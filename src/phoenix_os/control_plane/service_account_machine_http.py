from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from http import HTTPStatus
from types import MappingProxyType
from typing import Protocol
from urllib.parse import urlencode

from phoenix_os.control_plane.service_account_audit import (
    ControlPlaneServiceAccountAudit,
)
from phoenix_os.control_plane.service_account_authentication import (
    ControlPlaneServiceAccountAuthentication,
    ControlPlaneServiceAccountAuthenticationContext,
)
from phoenix_os.control_plane.service_account_authorization import (
    ControlPlaneServiceAccountAuthorization,
    ControlPlaneServiceAccountAuthorizer,
    ControlPlaneServiceAccountPermissionDeniedError,
)
from phoenix_os.control_plane.service_account_policy import (
    ControlPlaneServiceAccountApiContext,
    control_plane_service_account_api_context,
    control_plane_service_account_api_scope,
)
from phoenix_os.control_plane.service_account_replay import (
    ControlPlaneServiceAccountReplayRequest,
    ControlPlaneServiceAccountRequestNonce,
)

CONTROL_PLANE_SERVICE_ACCOUNT_MACHINE_PREFIX = "/v1/control-plane/machine/"

MAX_CONTROL_PLANE_SERVICE_ACCOUNT_MACHINE_ROUTES = 128

_MACHINE_CREDENTIAL_HEADERS = frozenset(
    {
        "authorization",
        "x-phoenix-request-nonce",
        "x-phoenix-request-timestamp",
    }
)

_BROWSER_ONLY_HEADERS = frozenset(
    {
        "cookie",
        "x-phoenix-csrf",
        "x-phoenix-step-up",
    }
)

_INTERNAL_HEADERS = _MACHINE_CREDENTIAL_HEADERS | _BROWSER_ONLY_HEADERS

ControlPlaneServiceAccountMachineResponse = tuple[
    HTTPStatus,
    Mapping[str, object],
    dict[str, str],
]


class ControlPlaneServiceAccountMachineAuthentication(Protocol):
    """Authenticate one replay-protected machine request."""

    async def authenticate(
        self,
        authorization: str | None,
        *,
        context: (ControlPlaneServiceAccountAuthenticationContext),
        request: ControlPlaneServiceAccountReplayRequest,
    ) -> ControlPlaneServiceAccountAuthentication | None: ...


class ControlPlaneServiceAccountMachinePolicy(Protocol):
    """Apply central deny-by-default authorization."""

    async def enforce(
        self,
        context: ControlPlaneServiceAccountApiContext,
        *,
        action: str,
        resource: str,
    ) -> object: ...


class ControlPlaneServiceAccountMachineHandler(Protocol):
    """Execute one explicitly allowlisted machine route."""

    async def __call__(
        self,
        context: ControlPlaneServiceAccountApiContext,
        request: ControlPlaneServiceAccountMachineRequest,
    ) -> ControlPlaneServiceAccountMachineResponse: ...


@dataclass(frozen=True, slots=True)
class ControlPlaneServiceAccountMachineRoute:
    """One exact machine-only HTTP route."""

    method: str
    path: str
    action: str
    resource: str
    handler: ControlPlaneServiceAccountMachineHandler = field(
        repr=False,
    )
    schema_version: int = 1

    def __post_init__(self) -> None:
        method = self.method.strip().upper()
        path = self.path.strip()
        action = self.action.strip()
        resource = self.resource.strip()

        if method not in {
            "GET",
            "POST",
        }:
            raise ValueError("machine route method must be GET or POST")

        if (
            not path.startswith(CONTROL_PLANE_SERVICE_ACCOUNT_MACHINE_PREFIX)
            or path.endswith("/")
            or "?" in path
            or "#" in path
            or path != self.path
        ):
            raise ValueError("machine route path must be an exact machine API path")

        if not action or action != self.action or not resource or resource != self.resource:
            raise ValueError("machine route authorization fields must be canonical")

        if not callable(self.handler):
            raise TypeError("machine route handler must be callable")

        if self.schema_version != 1:
            raise ValueError("unsupported machine route schema version")

        object.__setattr__(
            self,
            "method",
            method,
        )
        object.__setattr__(
            self,
            "path",
            path,
        )


@dataclass(frozen=True, slots=True)
class ControlPlaneServiceAccountMachineRequest:
    """Credential-free request passed to a machine handler."""

    method: str
    path: str
    target: str = field(
        repr=False,
    )
    query: Mapping[
        str,
        tuple[str, ...],
    ]
    headers: Mapping[
        str,
        tuple[str, ...],
    ] = field(
        repr=False,
    )
    body: bytes = field(
        repr=False,
    )
    schema_version: int = 1

    def __post_init__(self) -> None:
        if self.method not in {
            "GET",
            "POST",
        }:
            raise ValueError("machine request method is invalid")

        if not self.path.startswith(CONTROL_PLANE_SERVICE_ACCOUNT_MACHINE_PREFIX):
            raise ValueError("machine request path is invalid")

        if not self.target.startswith(self.path):
            raise ValueError("machine request target is inconsistent")

        if any(name in _INTERNAL_HEADERS for name in self.headers):
            raise ValueError("machine request exposes internal headers")

        if not isinstance(
            self.body,
            bytes,
        ):
            raise TypeError("machine request body must be bytes")

        if self.schema_version != 1:
            raise ValueError("unsupported machine request schema version")

        object.__setattr__(
            self,
            "query",
            MappingProxyType({name: tuple(values) for name, values in self.query.items()}),
        )

        object.__setattr__(
            self,
            "headers",
            MappingProxyType({name: tuple(values) for name, values in self.headers.items()}),
        )


class ControlPlaneServiceAccountMachineHttpAdapter:
    """Authenticate and authorize exact machine-only routes."""

    def __init__(
        self,
        *,
        authentication: (ControlPlaneServiceAccountMachineAuthentication),
        policy: ControlPlaneServiceAccountMachinePolicy,
        audit: ControlPlaneServiceAccountAudit,
        routes: tuple[
            ControlPlaneServiceAccountMachineRoute,
            ...,
        ],
        exact_authorizer: (ControlPlaneServiceAccountAuthorizer | None) = None,
    ) -> None:
        if not callable(
            getattr(
                authentication,
                "authenticate",
                None,
            )
        ):
            raise TypeError("machine HTTP requires authentication")

        if not callable(
            getattr(
                policy,
                "enforce",
                None,
            )
        ):
            raise TypeError("machine HTTP requires policy authorization")

        if not isinstance(
            audit,
            ControlPlaneServiceAccountAudit,
        ):
            raise TypeError("machine HTTP requires protected audit")

        if not routes:
            raise ValueError("machine HTTP requires at least one route")

        if len(routes) > (MAX_CONTROL_PLANE_SERVICE_ACCOUNT_MACHINE_ROUTES):
            raise ValueError("machine HTTP route capacity exceeded")

        authorizer = (
            ControlPlaneServiceAccountAuthorizer() if exact_authorizer is None else exact_authorizer
        )

        if not isinstance(
            authorizer,
            ControlPlaneServiceAccountAuthorizer,
        ):
            raise TypeError("machine HTTP exact authorizer has an invalid type")

        indexed: dict[
            tuple[str, str],
            ControlPlaneServiceAccountMachineRoute,
        ] = {}

        methods: dict[
            str,
            set[str],
        ] = {}

        for route in routes:
            if not isinstance(
                route,
                ControlPlaneServiceAccountMachineRoute,
            ):
                raise TypeError("machine HTTP routes have an invalid type")

            key = (
                route.method,
                route.path,
            )

            if key in indexed:
                raise ValueError("duplicate machine HTTP route")

            indexed[key] = route

            methods.setdefault(
                route.path,
                set(),
            ).add(route.method)

        self._authentication = authentication
        self._policy = policy
        self._audit = audit
        self._exact_authorizer = authorizer
        self._routes = indexed

        self._methods = {path: frozenset(values) for path, values in methods.items()}

    def handles(
        self,
        path: str,
    ) -> bool:
        """Return true only for an explicitly registered path."""

        return path in self._methods

    def allowed_methods(
        self,
        path: str,
    ) -> tuple[str, ...]:
        """Return deterministic methods for one known path."""

        return tuple(
            sorted(
                self._methods.get(
                    path,
                    frozenset(),
                )
            )
        )

    async def dispatch(
        self,
        *,
        context: (ControlPlaneServiceAccountAuthenticationContext),
        method: str,
        path: str,
        query: Mapping[
            str,
            tuple[str, ...],
        ],
        headers: Mapping[
            str,
            tuple[str, ...],
        ],
        body: bytes,
    ) -> ControlPlaneServiceAccountMachineResponse:
        normalized_method = method.strip().upper()

        route = self._routes.get(
            (
                normalized_method,
                path,
            )
        )

        if route is None:
            allowed = self.allowed_methods(path)

            if allowed:
                return (
                    HTTPStatus.METHOD_NOT_ALLOWED,
                    {
                        "error": "method_not_allowed",
                    },
                    {
                        "Allow": ", ".join(allowed),
                    },
                )

            return (
                HTTPStatus.NOT_FOUND,
                {
                    "error": "not_found",
                },
                {},
            )

        try:
            normalized_headers = _normalize_headers(headers)

            if any(normalized_headers.get(name) for name in _BROWSER_ONLY_HEADERS):
                return (
                    HTTPStatus.FORBIDDEN,
                    {
                        "error": "request_rejected",
                    },
                    {},
                )

            authorization = _required_header(
                normalized_headers,
                "authorization",
            )

            replay_request = ControlPlaneServiceAccountReplayRequest(
                nonce=ControlPlaneServiceAccountRequestNonce(
                    _required_header(
                        normalized_headers,
                        "x-phoenix-request-nonce",
                    )
                ),
                issued_at=_aware_datetime(
                    _required_header(
                        normalized_headers,
                        "x-phoenix-request-timestamp",
                    )
                ),
                method=route.method,
                target=_canonical_target(
                    route.path,
                    query,
                ),
                body_digest=hashlib.sha256(body).hexdigest(),
            )

        except (
            KeyError,
            TypeError,
            ValueError,
        ):
            await self._audit.authentication_rejected(context)

            return _unauthorized()

        try:
            authentication = await self._authentication.authenticate(
                authorization,
                context=context,
                request=replay_request,
            )
        except RuntimeError:
            return (
                HTTPStatus.SERVICE_UNAVAILABLE,
                {
                    "error": "machine_api_unavailable",
                },
                {},
            )

        if authentication is None:
            await self._audit.authentication_rejected(context)

            return _unauthorized()

        await self._audit.authentication_succeeded(
            authentication,
            context,
        )

        api_context = control_plane_service_account_api_context(
            authentication,
            correlation_id=_optional_header(
                normalized_headers,
                "x-phoenix-correlation-id",
            ),
        )

        exact = self._exact_authorizer.decide(
            authentication,
            action=route.action,
            resource=route.resource,
        )

        if not exact.allowed:
            await self._audit.authorization_decided(
                api_context,
                exact,
            )

            return (
                HTTPStatus.FORBIDDEN,
                {
                    "error": "forbidden",
                },
                {},
            )

        try:
            await self._policy.enforce(
                api_context,
                action=route.action,
                resource=route.resource,
            )
        except ControlPlaneServiceAccountPermissionDeniedError:
            await self._audit.authorization_decided(
                api_context,
                ControlPlaneServiceAccountAuthorization(
                    action=route.action,
                    resource=route.resource,
                    allowed=False,
                ),
            )

            return (
                HTTPStatus.FORBIDDEN,
                {
                    "error": "forbidden",
                },
                {},
            )
        except RuntimeError:
            return (
                HTTPStatus.SERVICE_UNAVAILABLE,
                {
                    "error": "machine_api_unavailable",
                },
                {},
            )

        await self._audit.authorization_decided(
            api_context,
            exact,
        )

        machine_request = ControlPlaneServiceAccountMachineRequest(
            method=route.method,
            path=route.path,
            target=replay_request.target,
            query=query,
            headers=_handler_headers(normalized_headers),
            body=body,
        )

        try:
            with control_plane_service_account_api_scope(api_context):
                return await route.handler(
                    api_context,
                    machine_request,
                )
        except (
            KeyError,
            TypeError,
            ValueError,
        ):
            return (
                HTTPStatus.BAD_REQUEST,
                {
                    "error": "invalid_machine_request",
                },
                {},
            )
        except RuntimeError:
            return (
                HTTPStatus.SERVICE_UNAVAILABLE,
                {
                    "error": "machine_api_unavailable",
                },
                {},
            )


def _normalize_headers(
    headers: Mapping[
        str,
        tuple[str, ...],
    ],
) -> dict[
    str,
    tuple[str, ...],
]:
    normalized: dict[
        str,
        list[str],
    ] = {}

    for raw_name, raw_values in headers.items():
        if not isinstance(
            raw_name,
            str,
        ):
            raise TypeError("HTTP header name must be str")

        name = raw_name.strip().lower()

        if not name or any(character.isspace() for character in name):
            raise ValueError("HTTP header name is invalid")

        for value in raw_values:
            if not isinstance(
                value,
                str,
            ):
                raise TypeError("HTTP header value must be str")

            normalized.setdefault(
                name,
                [],
            ).append(value)

    return {name: tuple(values) for name, values in normalized.items()}


def _required_header(
    headers: Mapping[
        str,
        tuple[str, ...],
    ],
    name: str,
) -> str:
    values = headers.get(
        name,
        (),
    )

    if len(values) != 1:
        raise ValueError(f"{name} must appear exactly once")

    value = values[0]

    if not value or value != value.strip():
        raise ValueError(f"{name} is invalid")

    return value


def _optional_header(
    headers: Mapping[
        str,
        tuple[str, ...],
    ],
    name: str,
) -> str | None:
    values = headers.get(
        name,
        (),
    )

    if not values:
        return None

    if len(values) != 1:
        raise ValueError(f"{name} must appear at most once")

    value = values[0]

    if not value or value != value.strip():
        raise ValueError(f"{name} is invalid")

    return value


def _aware_datetime(
    value: str,
) -> datetime:
    parsed = datetime.fromisoformat(value)

    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("machine request timestamp must be timezone-aware")

    return parsed


def _canonical_target(
    path: str,
    query: Mapping[
        str,
        tuple[str, ...],
    ],
) -> str:
    pairs: list[tuple[str, str],] = []

    for name, values in query.items():
        if not isinstance(
            name,
            str,
        ):
            raise TypeError("query name must be str")

        for value in values:
            if not isinstance(
                value,
                str,
            ):
                raise TypeError("query value must be str")

            pairs.append(
                (
                    name,
                    value,
                )
            )

    if not pairs:
        return path

    pairs.sort()

    return f"{path}?{urlencode(pairs)}"


def _handler_headers(
    headers: Mapping[
        str,
        tuple[str, ...],
    ],
) -> Mapping[
    str,
    tuple[str, ...],
]:
    return MappingProxyType(
        {name: tuple(values) for name, values in headers.items() if name not in _INTERNAL_HEADERS}
    )


def _unauthorized() -> ControlPlaneServiceAccountMachineResponse:
    return (
        HTTPStatus.UNAUTHORIZED,
        {
            "error": "unauthorized",
        },
        {
            "WWW-Authenticate": ('Bearer realm="phoenix-service-account"'),
        },
    )
