"""Durable-session HTTP administration for service accounts."""

from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import (
    datetime,
    timedelta,
)
from http import HTTPStatus
from typing import Protocol
from uuid import UUID

from phoenix_os.control_plane.auth import ControlPlanePrincipal
from phoenix_os.control_plane.csrf import ControlPlaneBrowserOrigin
from phoenix_os.control_plane.durable_session_access import (
    ControlPlaneDurableSessionAuthentication,
)
from phoenix_os.control_plane.errors import (
    ControlPlaneApiTokenCapacityError,
    ControlPlaneApiTokenConflictError,
    ControlPlaneApiTokenNotFoundError,
    ControlPlaneDurableSessionCsrfRejectedError,
    ControlPlaneServiceAccountAlreadyExistsError,
    ControlPlaneServiceAccountCapacityError,
    ControlPlaneServiceAccountConflictError,
    ControlPlaneServiceAccountLifecycleClosedError,
    ControlPlaneServiceAccountNotFoundError,
    ControlPlaneServiceAccountPersistenceError,
    ControlPlaneServiceAccountRepositoryClosedError,
    ControlPlaneStepUpRejectedError,
)
from phoenix_os.control_plane.service_account_admin import (
    ControlPlaneServiceAccountAdministration,
    ControlPlaneServiceAccountAdministrationPermissionDeniedError,
    api_token_grant_to_dict,
    api_token_view_page_to_dict,
    api_token_view_to_dict,
    service_account_view_page_to_dict,
    service_account_view_to_dict,
)
from phoenix_os.control_plane.service_account_contracts import (
    DEFAULT_CONTROL_PLANE_SERVICE_ACCOUNT_PAGE_SIZE,
    ControlPlaneApiTokenRestriction,
    ControlPlaneServiceAccountPageRequest,
)
from phoenix_os.control_plane.step_up import ControlPlaneStepUpAction

_SERVICE_ACCOUNTS_PATH = "/v1/control-plane/service-accounts"
_SERVICE_ACCOUNT_PREFIX = f"{_SERVICE_ACCOUNTS_PATH}/"
_API_TOKENS_PATH = "/v1/control-plane/api-tokens"
_API_TOKEN_PREFIX = f"{_API_TOKENS_PATH}/"


class ControlPlaneServiceAccountCsrfVerifier(Protocol):
    """Session-bound CSRF verification boundary."""

    async def verify_csrf(
        self,
        token_value: str | None,
        authentication: ControlPlaneDurableSessionAuthentication,
        *,
        supplied_origin: ControlPlaneBrowserOrigin,
        expected_origin: ControlPlaneBrowserOrigin,
    ) -> object: ...


class _ControlPlaneServiceAccountStepUpVerifier(Protocol):
    async def verify(
        self,
        token_value: str | None,
        session: ControlPlaneDurableSessionAuthentication,
        action: ControlPlaneStepUpAction,
    ) -> object: ...


class ControlPlaneServiceAccountHttpAdapter:
    """Expose Maintainer administration through durable cookie sessions."""

    def __init__(
        self,
        *,
        administration: ControlPlaneServiceAccountAdministration,
        boundary: ControlPlaneServiceAccountCsrfVerifier,
        step_up: _ControlPlaneServiceAccountStepUpVerifier,
    ) -> None:
        if not isinstance(
            administration,
            ControlPlaneServiceAccountAdministration,
        ):
            raise TypeError("service-account HTTP requires administration")

        if not callable(
            getattr(
                boundary,
                "verify_csrf",
                None,
            )
        ):
            raise TypeError("service-account HTTP requires a CSRF boundary")

        if not callable(
            getattr(
                step_up,
                "verify",
                None,
            )
        ):
            raise TypeError("service-account HTTP requires step-up verification")

        self._administration = administration
        self._boundary = boundary
        self._step_up = step_up

    @staticmethod
    def handles(
        path: str,
    ) -> bool:
        return (
            path == _SERVICE_ACCOUNTS_PATH
            or path.startswith(_SERVICE_ACCOUNT_PREFIX)
            or path.startswith(_API_TOKEN_PREFIX)
        )

    async def dispatch(
        self,
        *,
        authentication: ControlPlaneDurableSessionAuthentication,
        method: str,
        path: str,
        query: Mapping[str, tuple[str, ...]],
        headers: Mapping[str, tuple[str, ...]],
        body: bytes,
        server_origin: ControlPlaneBrowserOrigin,
    ) -> tuple[
        HTTPStatus,
        Mapping[str, object],
        dict[str, str],
    ]:
        principal = authentication.principal

        try:
            if method == "GET":
                return await self._dispatch_get(
                    principal=principal,
                    path=path,
                    query=query,
                    body=body,
                )

            if method != "POST":
                return (
                    HTTPStatus.METHOD_NOT_ALLOWED,
                    {
                        "error": "method_not_allowed",
                    },
                    {
                        "Allow": "GET, POST",
                    },
                )

            if query:
                return (
                    HTTPStatus.BAD_REQUEST,
                    {
                        "error": "invalid_request",
                    },
                    {},
                )

            await self._verify_csrf(
                authentication,
                headers,
                server_origin,
            )

            return await self._dispatch_post(
                authentication=authentication,
                headers=headers,
                principal=principal,
                path=path,
                document=_json_object(body),
            )

        except ControlPlaneServiceAccountAdministrationPermissionDeniedError:
            return (
                HTTPStatus.FORBIDDEN,
                {
                    "error": "forbidden",
                },
                {},
            )

        except (
            ControlPlaneDurableSessionCsrfRejectedError,
            ControlPlaneStepUpRejectedError,
        ):
            return (
                HTTPStatus.FORBIDDEN,
                {
                    "error": "request_rejected",
                },
                {},
            )

        except ControlPlaneApiTokenNotFoundError:
            return (
                HTTPStatus.NOT_FOUND,
                {
                    "error": "api_token_not_found",
                },
                {},
            )

        except ControlPlaneServiceAccountNotFoundError:
            return (
                HTTPStatus.NOT_FOUND,
                {
                    "error": "service_account_not_found",
                },
                {},
            )

        except ControlPlaneApiTokenConflictError:
            return (
                HTTPStatus.CONFLICT,
                {
                    "error": "api_token_conflict",
                },
                {},
            )

        except (
            ControlPlaneServiceAccountAlreadyExistsError,
            ControlPlaneServiceAccountConflictError,
        ):
            return (
                HTTPStatus.CONFLICT,
                {
                    "error": "service_account_conflict",
                },
                {},
            )

        except ControlPlaneApiTokenCapacityError:
            return (
                HTTPStatus.TOO_MANY_REQUESTS,
                {
                    "error": "api_token_capacity_exhausted",
                },
                {
                    "Retry-After": "1",
                },
            )

        except ControlPlaneServiceAccountCapacityError:
            return (
                HTTPStatus.TOO_MANY_REQUESTS,
                {
                    "error": ("service_account_capacity_exhausted"),
                },
                {
                    "Retry-After": "1",
                },
            )

        except (
            KeyError,
            TypeError,
            ValueError,
            UnicodeDecodeError,
            json.JSONDecodeError,
        ):
            return (
                HTTPStatus.BAD_REQUEST,
                {
                    "error": ("invalid_service_account_request"),
                },
                {},
            )

        except (
            ControlPlaneServiceAccountLifecycleClosedError,
            ControlPlaneServiceAccountPersistenceError,
            ControlPlaneServiceAccountRepositoryClosedError,
            RuntimeError,
        ):
            return (
                HTTPStatus.SERVICE_UNAVAILABLE,
                {
                    "error": "service_accounts_unavailable",
                },
                {},
            )

    async def _dispatch_get(
        self,
        *,
        principal: ControlPlanePrincipal,
        path: str,
        query: Mapping[str, tuple[str, ...]],
        body: bytes,
    ) -> tuple[
        HTTPStatus,
        Mapping[str, object],
        dict[str, str],
    ]:
        if body:
            return (
                HTTPStatus.BAD_REQUEST,
                {
                    "error": "invalid_request",
                },
                {},
            )

        request = _page_request(query)

        if path == _SERVICE_ACCOUNTS_PATH:
            account_page = await self._administration.list_accounts(
                principal,
                request,
            )

            return (
                HTTPStatus.OK,
                service_account_view_page_to_dict(account_page),
                {},
            )

        route = _service_account_route(path)

        if route is not None and route[1] == "tokens":
            token_page = await self._administration.list_tokens(
                principal,
                route[0],
                request,
            )

            return (
                HTTPStatus.OK,
                api_token_view_page_to_dict(token_page),
                {},
            )

        return (
            HTTPStatus.NOT_FOUND,
            {
                "error": "not_found",
            },
            {},
        )

    async def _dispatch_post(
        self,
        *,
        authentication: ControlPlaneDurableSessionAuthentication,
        headers: Mapping[str, tuple[str, ...]],
        principal: ControlPlanePrincipal,
        path: str,
        document: Mapping[str, object],
    ) -> tuple[
        HTTPStatus,
        Mapping[str, object],
        dict[str, str],
    ]:
        if path == _SERVICE_ACCOUNTS_PATH:
            _require_fields(
                document,
                required={
                    "name",
                    "display_name",
                },
            )

            view = await self._administration.create_account(
                principal,
                name=_string(
                    document,
                    "name",
                ),
                display_name=_string(
                    document,
                    "display_name",
                ),
            )

            return (
                HTTPStatus.CREATED,
                service_account_view_to_dict(view),
                {},
            )

        token_route = _api_token_route(path)

        if token_route is not None:
            token_id, action = token_route

            if action == "rotate":
                _require_fields(
                    document,
                    required={
                        "expected_revision",
                        "expires_at",
                    },
                    optional={
                        "label",
                        "scopes",
                        "resources",
                        "restriction",
                        "overlap_seconds",
                    },
                )

                await self._verify_step_up(
                    authentication,
                    headers,
                    ControlPlaneStepUpAction.ROTATE_API_TOKEN,
                )

                grant = await self._administration.rotate_token(
                    principal,
                    token_id,
                    expected_revision=_positive_integer(
                        document,
                        "expected_revision",
                    ),
                    expires_at=_aware_datetime(
                        document,
                        "expires_at",
                    ),
                    label=_optional_string(
                        document,
                        "label",
                    ),
                    scopes=_optional_string_set(
                        document,
                        "scopes",
                    ),
                    resources=_optional_string_set(
                        document,
                        "resources",
                    ),
                    restriction=_optional_restriction(document),
                    overlap=timedelta(
                        seconds=_optional_nonnegative_integer(
                            document,
                            "overlap_seconds",
                            0,
                        )
                    ),
                )

                return (
                    HTTPStatus.OK,
                    api_token_grant_to_dict(grant),
                    {
                        "Cache-Control": "no-store",
                    },
                )

            if action == "revoke":
                _require_fields(
                    document,
                    required={
                        "expected_revision",
                    },
                )

                await self._verify_step_up(
                    authentication,
                    headers,
                    ControlPlaneStepUpAction.REVOKE_API_TOKEN,
                )

                token_view = await self._administration.revoke_token(
                    principal,
                    token_id,
                    expected_revision=_positive_integer(
                        document,
                        "expected_revision",
                    ),
                )

                return (
                    HTTPStatus.OK,
                    api_token_view_to_dict(token_view),
                    {},
                )

            return (
                HTTPStatus.NOT_FOUND,
                {
                    "error": "not_found",
                },
                {},
            )

        route = _service_account_route(path)

        if route is None:
            return (
                HTTPStatus.NOT_FOUND,
                {
                    "error": "not_found",
                },
                {},
            )

        account_id, action = route

        if action == "tokens":
            return (
                HTTPStatus.METHOD_NOT_ALLOWED,
                {
                    "error": "method_not_allowed",
                },
                {
                    "Allow": "GET",
                },
            )

        if action == "update":
            _require_fields(
                document,
                required={
                    "expected_revision",
                },
                optional={
                    "name",
                    "display_name",
                },
            )

            view = await self._administration.update_account(
                principal,
                account_id,
                expected_revision=_positive_integer(
                    document,
                    "expected_revision",
                ),
                name=_optional_string(
                    document,
                    "name",
                ),
                display_name=_optional_string(
                    document,
                    "display_name",
                ),
            )

            return (
                HTTPStatus.OK,
                service_account_view_to_dict(view),
                {},
            )

        if action == "disable":
            _require_fields(
                document,
                required={
                    "expected_revision",
                },
            )

            view = await self._administration.disable_account(
                principal,
                account_id,
                expected_revision=_positive_integer(
                    document,
                    "expected_revision",
                ),
            )

            return (
                HTTPStatus.OK,
                service_account_view_to_dict(view),
                {},
            )

        if action == "enable":
            _require_fields(
                document,
                required={
                    "expected_revision",
                },
            )

            await self._verify_step_up(
                authentication,
                headers,
                ControlPlaneStepUpAction.ENABLE_SERVICE_ACCOUNT,
            )

            view = await self._administration.enable_account(
                principal,
                account_id,
                expected_revision=_positive_integer(
                    document,
                    "expected_revision",
                ),
            )

            return (
                HTTPStatus.OK,
                service_account_view_to_dict(view),
                {},
            )

        if action == "revoke":
            _require_fields(
                document,
                required={
                    "expected_revision",
                },
            )

            await self._verify_step_up(
                authentication,
                headers,
                ControlPlaneStepUpAction.REVOKE_SERVICE_ACCOUNT,
            )

            view = await self._administration.revoke_account(
                principal,
                account_id,
                expected_revision=_positive_integer(
                    document,
                    "expected_revision",
                ),
            )

            return (
                HTTPStatus.OK,
                service_account_view_to_dict(view),
                {},
            )

        if action == "issue-token":
            _require_fields(
                document,
                required={
                    "label",
                    "scopes",
                    "expires_at",
                },
                optional={
                    "resources",
                    "restriction",
                },
            )

            await self._verify_step_up(
                authentication,
                headers,
                ControlPlaneStepUpAction.ISSUE_API_TOKEN,
            )

            resources = (
                _string_set(
                    document,
                    "resources",
                )
                if "resources" in document
                else frozenset(
                    {
                        "*",
                    }
                )
            )

            grant = await self._administration.issue_token(
                principal,
                account_id,
                label=_string(
                    document,
                    "label",
                ),
                scopes=_string_set(
                    document,
                    "scopes",
                ),
                resources=resources,
                restriction=_optional_restriction(document),
                expires_at=_aware_datetime(
                    document,
                    "expires_at",
                ),
            )

            return (
                HTTPStatus.CREATED,
                api_token_grant_to_dict(grant),
                {
                    "Cache-Control": "no-store",
                },
            )

        return (
            HTTPStatus.NOT_FOUND,
            {
                "error": "not_found",
            },
            {},
        )

    async def _verify_csrf(
        self,
        authentication: ControlPlaneDurableSessionAuthentication,
        headers: Mapping[str, tuple[str, ...]],
        server_origin: ControlPlaneBrowserOrigin,
    ) -> None:
        try:
            supplied_origin = _exact_origin(
                headers,
                server_origin,
            )
        except ValueError as exception:
            raise ControlPlaneDurableSessionCsrfRejectedError(
                "service-account request origin rejected"
            ) from exception

        await self._boundary.verify_csrf(
            _one_optional_header(
                headers,
                "x-phoenix-csrf",
            ),
            authentication,
            supplied_origin=supplied_origin,
            expected_origin=server_origin,
        )

    async def _verify_step_up(
        self,
        authentication: ControlPlaneDurableSessionAuthentication,
        headers: Mapping[str, tuple[str, ...]],
        action: ControlPlaneStepUpAction,
    ) -> None:
        await self._step_up.verify(
            _one_optional_header(
                headers,
                "x-phoenix-step-up",
            ),
            authentication,
            action,
        )


def _service_account_route(
    path: str,
) -> tuple[UUID, str] | None:
    if not path.startswith(_SERVICE_ACCOUNT_PREFIX):
        return None

    parts = path[len(_SERVICE_ACCOUNT_PREFIX) :].split("/")

    if len(parts) != 2:
        return None

    if parts[1] not in {
        "tokens",
        "update",
        "disable",
        "enable",
        "revoke",
        "issue-token",
    }:
        return None

    return UUID(parts[0]), parts[1]


def _api_token_route(
    path: str,
) -> tuple[UUID, str] | None:
    if not path.startswith(_API_TOKEN_PREFIX):
        return None

    parts = path[len(_API_TOKEN_PREFIX) :].split("/")

    if len(parts) != 2 or parts[1] not in {
        "rotate",
        "revoke",
    }:
        return None

    return UUID(parts[0]), parts[1]


def _page_request(
    query: Mapping[str, tuple[str, ...]],
) -> ControlPlaneServiceAccountPageRequest:
    if set(query) - {
        "offset",
        "limit",
    }:
        raise ValueError("unsupported service-account pagination field")

    return ControlPlaneServiceAccountPageRequest(
        offset=_query_integer(
            query,
            "offset",
            0,
        ),
        limit=_query_integer(
            query,
            "limit",
            DEFAULT_CONTROL_PLANE_SERVICE_ACCOUNT_PAGE_SIZE,
        ),
    )


def _query_integer(
    query: Mapping[str, tuple[str, ...]],
    name: str,
    default: int,
) -> int:
    values = query.get(name)

    if values is None:
        return default

    if len(values) != 1 or not values[0] or not values[0].isascii() or not values[0].isdigit():
        raise ValueError("pagination value must be one unsigned integer")

    return int(values[0])


def _json_object(
    body: bytes,
) -> Mapping[str, object]:
    if not body:
        raise ValueError("service-account body is required")

    document = json.loads(body.decode("utf-8"))

    if not isinstance(
        document,
        dict,
    ):
        raise TypeError("service-account body must be an object")

    return document


def _require_fields(
    document: Mapping[str, object],
    *,
    required: set[str],
    optional: set[str] | None = None,
) -> None:
    allowed = required | (set() if optional is None else optional)

    if not required.issubset(document) or set(document) - allowed:
        raise ValueError("service-account request fields do not match route schema")


def _string(
    document: Mapping[str, object],
    name: str,
) -> str:
    value = document[name]

    if not isinstance(
        value,
        str,
    ):
        raise TypeError(f"{name} must be a string")

    return value


def _optional_string(
    document: Mapping[str, object],
    name: str,
) -> str | None:
    if name not in document:
        return None

    return _string(
        document,
        name,
    )


def _positive_integer(
    document: Mapping[str, object],
    name: str,
) -> int:
    value = document[name]

    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise TypeError(f"{name} must be a positive integer")

    return value


def _aware_datetime(
    document: Mapping[str, object],
    name: str,
) -> datetime:
    value = datetime.fromisoformat(
        _string(
            document,
            name,
        )
    )

    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name} must be timezone-aware")

    return value


def _string_set(
    document: Mapping[str, object],
    name: str,
) -> frozenset[str]:
    raw = document[name]

    if not isinstance(
        raw,
        list,
    ):
        raise TypeError(f"{name} must be an array of strings")

    values: list[str] = []

    for item in raw:
        if not isinstance(
            item,
            str,
        ):
            raise TypeError(f"{name} must be an array of strings")

        values.append(item)

    return frozenset(values)


def _optional_string_set(
    document: Mapping[str, object],
    name: str,
) -> frozenset[str] | None:
    if name not in document:
        return None

    return _string_set(
        document,
        name,
    )


def _optional_nonnegative_integer(
    document: Mapping[str, object],
    name: str,
    default: int,
) -> int:
    if name not in document:
        return default

    value = document[name]

    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise TypeError(f"{name} must be a nonnegative integer")

    return value


def _optional_restriction(
    document: Mapping[str, object],
) -> ControlPlaneApiTokenRestriction | None:
    if "restriction" not in document:
        return None

    raw = document["restriction"]

    if not isinstance(
        raw,
        dict,
    ):
        raise TypeError("restriction must be an object")

    if set(raw) - {
        "allowed_client_networks",
        "mutual_tls_certificate_sha256",
    }:
        raise ValueError("restriction contains unsupported fields")

    networks_raw = raw.get(
        "allowed_client_networks",
        [],
    )

    if not isinstance(
        networks_raw,
        list,
    ):
        raise TypeError("allowed_client_networks must be an array of strings")

    networks: list[str] = []

    for item in networks_raw:
        if not isinstance(
            item,
            str,
        ):
            raise TypeError("allowed_client_networks must be an array of strings")

        networks.append(item)

    fingerprint = raw.get("mutual_tls_certificate_sha256")

    if fingerprint is not None and not isinstance(
        fingerprint,
        str,
    ):
        raise TypeError("mutual_tls_certificate_sha256 must be a string or null")

    return ControlPlaneApiTokenRestriction(
        allowed_client_networks=tuple(networks),
        mutual_tls_certificate_sha256=(fingerprint),
    )


def _one_optional_header(
    headers: Mapping[str, tuple[str, ...]],
    name: str,
) -> str | None:
    values = headers.get(
        name,
        (),
    )

    if not values:
        return None

    if len(values) != 1 or not values[0]:
        raise ValueError(f"one {name} header is required")

    return values[0]


def _exact_origin(
    headers: Mapping[str, tuple[str, ...]],
    server_origin: ControlPlaneBrowserOrigin,
) -> ControlPlaneBrowserOrigin:
    origin = ControlPlaneBrowserOrigin(
        _one_optional_header(
            headers,
            "origin",
        )
        or ""
    )

    if origin != server_origin:
        raise ValueError("request origin does not match control plane")

    return origin
