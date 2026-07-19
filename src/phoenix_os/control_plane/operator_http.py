"""Strict loopback HTTP adapter for local operator sessions and management."""

from __future__ import annotations

import json
import secrets
from collections.abc import Mapping
from http import HTTPStatus
from uuid import UUID

from phoenix_os.control_plane.auth import ControlPlanePrincipal
from phoenix_os.control_plane.csrf import (
    ControlPlaneBrowserOrigin,
    ControlPlaneCsrfProtector,
    ControlPlaneCsrfToken,
)
from phoenix_os.control_plane.errors import (
    ControlPlaneCsrfRejectedError,
    ControlPlaneOperatorAccessRejectedError,
    ControlPlaneOperatorAlreadyExistsError,
    ControlPlaneOperatorCapacityError,
    ControlPlaneOperatorConflictError,
    ControlPlaneOperatorNotFoundError,
    ControlPlaneOperatorPermissionDeniedError,
    ControlPlaneOperatorStateError,
)
from phoenix_os.control_plane.operator_api import ControlPlaneOperatorApi
from phoenix_os.control_plane.operator_contracts import (
    ControlPlaneOperatorPageRequest,
    ControlPlaneOperatorRole,
    ControlPlaneOperatorToken,
)
from phoenix_os.control_plane.operator_sessions import ControlPlaneOperatorAccessService
from phoenix_os.control_plane.serialization import (
    operator_credential_grant_to_dict,
    operator_mutation_receipt_to_dict,
    operator_view_page_to_dict,
    operator_view_to_dict,
)

_OPERATOR_PREFIX = "/v1/control-plane/operators/"
_SESSION_PREFIX = "/v1/control-plane/operator-sessions/"


class ControlPlaneOperatorSessionAuthenticator:
    """Adapt temporary operator sessions to the control-plane transport boundary."""

    def __init__(self, access: ControlPlaneOperatorAccessService) -> None:
        self._access = access

    async def authenticate(self, authorization: str | None) -> ControlPlanePrincipal | None:
        evidence = await self._access.authenticate(authorization)
        return None if evidence is None else evidence.principal


class ControlPlaneOperatorHttpAdapter:
    """Expose only allowlisted operator and session operations."""

    def __init__(
        self,
        *,
        api: ControlPlaneOperatorApi,
        access: ControlPlaneOperatorAccessService,
        csrf: ControlPlaneCsrfProtector,
    ) -> None:
        self._api = api
        self._access = access
        self._csrf = csrf

    @staticmethod
    def handles_public(path: str) -> bool:
        return path == "/v1/control-plane/operator/login"

    @staticmethod
    def handles(path: str) -> bool:
        return (
            path
            in {
                "/v1/control-plane/operator/logout",
                "/v1/control-plane/operator/me",
                "/v1/control-plane/operators",
            }
            or path.startswith(_OPERATOR_PREFIX)
            or path.startswith(_SESSION_PREFIX)
        )

    async def dispatch_public(
        self,
        *,
        method: str,
        authorization: str | None,
        body: bytes,
        query: Mapping[str, tuple[str, ...]],
    ) -> tuple[HTTPStatus, Mapping[str, object], dict[str, str]]:
        if method != "POST" or body or query:
            return HTTPStatus.BAD_REQUEST, {"error": "invalid_request"}, {}
        try:
            grant = await self._access.login(authorization)
        except ControlPlaneOperatorAccessRejectedError:
            return (
                HTTPStatus.UNAUTHORIZED,
                {"error": "unauthorized"},
                {"WWW-Authenticate": 'Bearer realm="phoenix-control-plane"'},
            )
        return (
            HTTPStatus.OK,
            {
                "schema_version": grant.schema_version,
                "session_id": str(grant.session_id),
                "operator_id": str(grant.operator_id),
                "username": grant.username,
                "session_token": grant.token.value,
                "issued_at": grant.issued_at.isoformat(),
                "expires_at": grant.expires_at.isoformat(),
            },
            {"Cache-Control": "no-store"},
        )

    async def dispatch(
        self,
        *,
        principal: ControlPlanePrincipal,
        authorization: str | None,
        method: str,
        path: str,
        query: Mapping[str, tuple[str, ...]],
        headers: Mapping[str, tuple[str, ...]],
        body: bytes,
        server_origin: ControlPlaneBrowserOrigin,
    ) -> tuple[HTTPStatus, Mapping[str, object], dict[str, str]]:
        try:
            if path == "/v1/control-plane/operator/me":
                if method != "GET" or body or query:
                    return HTTPStatus.BAD_REQUEST, {"error": "invalid_request"}, {}
                return (
                    HTTPStatus.OK,
                    {
                        "schema_version": 1,
                        "username": principal.name,
                        "permissions": sorted(principal.permissions),
                    },
                    {},
                )

            if path == "/v1/control-plane/operator/logout":
                if method != "POST" or body or query:
                    return HTTPStatus.BAD_REQUEST, {"error": "invalid_request"}, {}
                return (
                    HTTPStatus.OK,
                    {"schema_version": 1, "logged_out": await self._access.logout(authorization)},
                    {"Cache-Control": "no-store"},
                )

            if path == "/v1/control-plane/operators" and method == "GET":
                if body:
                    return HTTPStatus.BAD_REQUEST, {"error": "invalid_request"}, {}
                page = _page_request(query)
                return (
                    HTTPStatus.OK,
                    operator_view_page_to_dict(await self._api.list_operators(principal, page)),
                    {},
                )

            if method != "POST" or query:
                return (
                    HTTPStatus.METHOD_NOT_ALLOWED,
                    {"error": "method_not_allowed"},
                    {"Allow": "GET, POST"},
                )
            self._verify_csrf(principal, headers, server_origin)
            document = _json_object(body)

            if path == "/v1/control-plane/operators":
                _require_fields(
                    document,
                    required={"username", "display_name", "role"},
                    optional={"additional_permissions", "token"},
                )
                token = _token(document.get("token"))
                grant = await self._api.create_operator(
                    principal,
                    username=_string(document, "username"),
                    display_name=_string(document, "display_name"),
                    role=ControlPlaneOperatorRole(_string(document, "role")),
                    token=token,
                    additional_permissions=_permissions(document.get("additional_permissions", [])),
                )
                return (
                    HTTPStatus.CREATED,
                    operator_credential_grant_to_dict(grant),
                    {"Cache-Control": "no-store"},
                )

            operator_route = _operator_route(path)
            if operator_route is not None:
                operator_id, action = operator_route
                expected_revision = _integer(document, "expected_revision")
                if action == "update":
                    _require_fields(
                        document,
                        required={
                            "expected_revision",
                            "display_name",
                            "role",
                        },
                        optional={"additional_permissions"},
                    )
                    view = await self._api.update_operator(
                        principal,
                        operator_id,
                        expected_revision=expected_revision,
                        display_name=_string(document, "display_name"),
                        role=ControlPlaneOperatorRole(_string(document, "role")),
                        additional_permissions=_permissions(
                            document.get("additional_permissions", [])
                        ),
                    )
                    return HTTPStatus.OK, operator_view_to_dict(view), {}
                _require_fields(
                    document,
                    required={"expected_revision"},
                    optional={"token"} if action == "rotate" else set(),
                )
                if action == "rotate":
                    grant = await self._api.rotate_credential(
                        principal,
                        operator_id,
                        _token(document.get("token")),
                        expected_revision=expected_revision,
                    )
                    return (
                        HTTPStatus.OK,
                        operator_credential_grant_to_dict(grant),
                        {"Cache-Control": "no-store"},
                    )
                if action == "disable":
                    receipt = await self._api.disable(
                        principal, operator_id, expected_revision=expected_revision
                    )
                elif action == "reactivate":
                    receipt = await self._api.reactivate(
                        principal, operator_id, expected_revision=expected_revision
                    )
                elif action == "revoke":
                    receipt = await self._api.revoke(
                        principal, operator_id, expected_revision=expected_revision
                    )
                else:
                    return HTTPStatus.NOT_FOUND, {"error": "not_found"}, {}
                return HTTPStatus.OK, operator_mutation_receipt_to_dict(receipt), {}

            session_id = _session_route(path)
            if session_id is not None:
                _require_fields(document, required=set())
                revoked = await self._api.revoke_session(principal, session_id)
                return HTTPStatus.OK, {"schema_version": 1, "revoked": revoked}, {}

            return HTTPStatus.NOT_FOUND, {"error": "not_found"}, {}
        except ControlPlaneOperatorPermissionDeniedError:
            return HTTPStatus.FORBIDDEN, {"error": "forbidden"}, {}
        except ControlPlaneCsrfRejectedError:
            return HTTPStatus.FORBIDDEN, {"error": "request_rejected"}, {}
        except ControlPlaneOperatorAlreadyExistsError:
            return HTTPStatus.CONFLICT, {"error": "operator_conflict"}, {}
        except ControlPlaneOperatorNotFoundError:
            return HTTPStatus.NOT_FOUND, {"error": "operator_not_found"}, {}
        except (ControlPlaneOperatorConflictError, ControlPlaneOperatorStateError):
            return HTTPStatus.CONFLICT, {"error": "operator_conflict"}, {}
        except ControlPlaneOperatorCapacityError:
            return (
                HTTPStatus.TOO_MANY_REQUESTS,
                {"error": "operator_capacity_exhausted"},
                {"Retry-After": "1"},
            )
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            return HTTPStatus.BAD_REQUEST, {"error": "invalid_operator_request"}, {}
        except RuntimeError:
            return HTTPStatus.SERVICE_UNAVAILABLE, {"error": "operators_unavailable"}, {}

    def _verify_csrf(
        self,
        principal: ControlPlanePrincipal,
        headers: Mapping[str, tuple[str, ...]],
        origin: ControlPlaneBrowserOrigin,
    ) -> None:
        try:
            supplied_origin = ControlPlaneBrowserOrigin(_one_header(headers, "origin"))
            token = ControlPlaneCsrfToken(_one_header(headers, "x-phoenix-csrf"))
        except ValueError as exception:
            raise ControlPlaneCsrfRejectedError(
                "operator request CSRF evidence is invalid"
            ) from exception
        if supplied_origin != origin:
            raise ControlPlaneCsrfRejectedError("request origin does not match control plane")
        self._csrf.verify(token, principal, origin)


def _operator_route(path: str) -> tuple[UUID, str] | None:
    if not path.startswith(_OPERATOR_PREFIX):
        return None
    parts = path[len(_OPERATOR_PREFIX) :].split("/")
    if len(parts) != 2 or parts[1] not in {"update", "rotate", "disable", "reactivate", "revoke"}:
        return None
    return UUID(parts[0]), parts[1]


def _session_route(path: str) -> UUID | None:
    if not path.startswith(_SESSION_PREFIX) or not path.endswith("/revoke"):
        return None
    value = path[len(_SESSION_PREFIX) : -len("/revoke")]
    if "/" in value or not value:
        return None
    return UUID(value)


def _page_request(query: Mapping[str, tuple[str, ...]]) -> ControlPlaneOperatorPageRequest:
    if set(query) - {"offset", "limit"}:
        raise ValueError("unsupported operator pagination field")
    return ControlPlaneOperatorPageRequest(
        offset=_query_integer(query, "offset", 0),
        limit=_query_integer(query, "limit", 50),
    )


def _query_integer(query: Mapping[str, tuple[str, ...]], name: str, default: int) -> int:
    values = query.get(name)
    if values is None:
        return default
    if len(values) != 1 or not values[0]:
        raise ValueError("pagination value must be singular")
    return int(values[0])


def _json_object(body: bytes) -> Mapping[str, object]:
    if not body:
        raise ValueError("operator body is required")
    document = json.loads(body.decode("utf-8"))
    if not isinstance(document, dict):
        raise TypeError("operator body must be an object")
    return document


def _require_fields(
    document: Mapping[str, object],
    *,
    required: set[str],
    optional: set[str] | None = None,
) -> None:
    allowed = required | (set() if optional is None else optional)
    if not required.issubset(document) or set(document) - allowed:
        raise ValueError("operator request fields do not match route schema")


def _string(document: Mapping[str, object], name: str) -> str:
    value = document[name]
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a string")
    return value


def _integer(document: Mapping[str, object], name: str) -> int:
    value = document[name]
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an integer")
    return value


def _permissions(value: object) -> frozenset[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise TypeError("additional_permissions must be an array of strings")
    return frozenset(value)


def _token(value: object) -> ControlPlaneOperatorToken:
    if value is None:
        return ControlPlaneOperatorToken(secrets.token_urlsafe(32))
    if not isinstance(value, str):
        raise TypeError("token must be a string")
    return ControlPlaneOperatorToken(value)


def _one_header(headers: Mapping[str, tuple[str, ...]], name: str) -> str:
    values = headers.get(name, ())
    if len(values) != 1 or not values[0]:
        raise ValueError(f"one {name} header is required")
    return values[0]
