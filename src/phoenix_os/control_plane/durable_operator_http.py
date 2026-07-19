"""Cookie-authenticated durable operator and session-management HTTP adapter."""

from __future__ import annotations

import json
import secrets
from collections.abc import Mapping
from http import HTTPStatus
from uuid import UUID

from phoenix_os.control_plane.csrf import ControlPlaneBrowserOrigin
from phoenix_os.control_plane.durable_session_access import (
    ControlPlaneDurableSessionAuthentication,
)
from phoenix_os.control_plane.durable_session_contracts import (
    DEFAULT_DURABLE_SESSION_PAGE_SIZE,
    ControlPlaneDurableSessionPageRequest,
    ControlPlaneDurableSessionStatus,
)
from phoenix_os.control_plane.durable_session_history import (
    ControlPlaneDurableSessionHistoryService,
)
from phoenix_os.control_plane.durable_session_http import (
    ControlPlaneDurableSessionHttpBoundary,
)
from phoenix_os.control_plane.errors import (
    ControlPlaneDurableSessionCsrfRejectedError,
    ControlPlaneDurableSessionHttpRejectedError,
    ControlPlaneOperatorAlreadyExistsError,
    ControlPlaneOperatorCapacityError,
    ControlPlaneOperatorConflictError,
    ControlPlaneOperatorNotFoundError,
    ControlPlaneOperatorPermissionDeniedError,
    ControlPlaneOperatorStateError,
    ControlPlaneStepUpRejectedError,
)
from phoenix_os.control_plane.operator_api import ControlPlaneOperatorApi
from phoenix_os.control_plane.operator_contracts import (
    ControlPlaneOperatorPageRequest,
    ControlPlaneOperatorRole,
    ControlPlaneOperatorToken,
)
from phoenix_os.control_plane.serialization import (
    durable_session_history_page_to_dict,
    operator_credential_grant_to_dict,
    operator_mutation_receipt_to_dict,
    operator_view_page_to_dict,
    operator_view_to_dict,
    step_up_grant_to_dict,
)
from phoenix_os.control_plane.step_up import (
    ControlPlaneOperatorStepUpService,
    ControlPlaneStepUpAction,
)

_OPERATOR_PREFIX = "/v1/control-plane/operators/"
_SESSION_PREFIX = "/v1/control-plane/operator-sessions/"


class ControlPlaneDurableOperatorHttpAdapter:
    """Expose durable cookie sessions, history, step-up, and operator management."""

    def __init__(
        self,
        *,
        api: ControlPlaneOperatorApi,
        boundary: ControlPlaneDurableSessionHttpBoundary,
        history: ControlPlaneDurableSessionHistoryService,
        step_up: ControlPlaneOperatorStepUpService,
    ) -> None:
        self._api = api
        self._boundary = boundary
        self._history = history
        self._step_up = step_up

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
                "/v1/control-plane/operator/step-up",
                "/v1/control-plane/operators",
                "/v1/control-plane/operator-sessions",
            }
            or path.startswith(_OPERATOR_PREFIX)
            or path.startswith(_SESSION_PREFIX)
        )

    async def dispatch_public(
        self,
        *,
        method: str,
        authorization: str | None,
        headers: Mapping[str, tuple[str, ...]],
        body: bytes,
        query: Mapping[str, tuple[str, ...]],
        server_origin: ControlPlaneBrowserOrigin,
    ) -> tuple[HTTPStatus, Mapping[str, object], dict[str, str]]:
        if method != "POST" or body or query:
            return HTTPStatus.BAD_REQUEST, {"error": "invalid_request"}, {}
        try:
            origin = _exact_origin(headers, server_origin)
            login = await self._boundary.login(authorization, origin=origin)
        except (ControlPlaneDurableSessionHttpRejectedError, ValueError):
            return (
                HTTPStatus.UNAUTHORIZED,
                {"error": "unauthorized"},
                {"WWW-Authenticate": 'Bearer realm="phoenix-control-plane"'},
            )
        authentication = login.authentication
        return (
            HTTPStatus.OK,
            {
                "schema_version": login.schema_version,
                "session_id": str(authentication.session_id),
                "operator_id": str(authentication.operator_id),
                "username": authentication.principal.name,
                "generation": authentication.generation,
                "issued_at": authentication.authenticated_at.isoformat(),
                "absolute_expires_at": authentication.absolute_expires_at.isoformat(),
                "idle_expires_at": authentication.idle_expires_at.isoformat(),
            },
            dict(login.response_headers),
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
    ) -> tuple[HTTPStatus, Mapping[str, object], dict[str, str]]:
        principal = authentication.principal
        try:
            if path == "/v1/control-plane/operator/me":
                if method != "GET" or body or query:
                    return HTTPStatus.BAD_REQUEST, {"error": "invalid_request"}, {}
                return (
                    HTTPStatus.OK,
                    {
                        "schema_version": 1,
                        "session_id": str(authentication.session_id),
                        "operator_id": str(authentication.operator_id),
                        "username": principal.name,
                        "generation": authentication.generation,
                        "permissions": sorted(principal.permissions),
                        "absolute_expires_at": authentication.absolute_expires_at.isoformat(),
                        "idle_expires_at": authentication.idle_expires_at.isoformat(),
                    },
                    {},
                )

            if path == "/v1/control-plane/operator/logout":
                if method != "POST" or body or query:
                    return HTTPStatus.BAD_REQUEST, {"error": "invalid_request"}, {}
                await self._verify_csrf(authentication, headers, server_origin)
                changed, response_headers = await self._boundary.logout(
                    _one_optional_header(headers, "cookie")
                )
                return (
                    HTTPStatus.OK,
                    {"schema_version": 1, "logged_out": changed},
                    dict(response_headers),
                )

            if path == "/v1/control-plane/operator/step-up":
                if method != "POST" or query:
                    return HTTPStatus.BAD_REQUEST, {"error": "invalid_request"}, {}
                await self._verify_csrf(authentication, headers, server_origin)
                document = _json_object(body)
                _require_fields(document, required={"action"})
                step_up_grant = await self._step_up.confirm(
                    authentication,
                    _one_optional_header(headers, "authorization"),
                    ControlPlaneStepUpAction(_string(document, "action")),
                )
                return (
                    HTTPStatus.OK,
                    step_up_grant_to_dict(step_up_grant),
                    {"Cache-Control": "no-store"},
                )

            if path == "/v1/control-plane/operator-sessions":
                if method != "GET" or body:
                    return (
                        HTTPStatus.METHOD_NOT_ALLOWED,
                        {"error": "method_not_allowed"},
                        {"Allow": "GET"},
                    )
                session_request = _session_page_request(query)
                session_page = await self._history.list_history(principal, session_request)
                return (
                    HTTPStatus.OK,
                    durable_session_history_page_to_dict(session_page),
                    {},
                )

            if path == "/v1/control-plane/operators" and method == "GET":
                if body:
                    return HTTPStatus.BAD_REQUEST, {"error": "invalid_request"}, {}
                operator_request = _operator_page_request(query)
                return (
                    HTTPStatus.OK,
                    operator_view_page_to_dict(
                        await self._api.list_operators(principal, operator_request)
                    ),
                    {},
                )

            if method != "POST" or query:
                return (
                    HTTPStatus.METHOD_NOT_ALLOWED,
                    {"error": "method_not_allowed"},
                    {"Allow": "GET, POST"},
                )
            await self._verify_csrf(authentication, headers, server_origin)
            document = _json_object(body)

            if path == "/v1/control-plane/operators":
                _require_fields(
                    document,
                    required={"username", "display_name", "role"},
                    optional={"additional_permissions", "token"},
                )
                role = ControlPlaneOperatorRole(_string(document, "role"))
                if role is ControlPlaneOperatorRole.MAINTAINER:
                    await self._verify_step_up(
                        authentication,
                        headers,
                        ControlPlaneStepUpAction.CREATE_MAINTAINER,
                    )
                credential_grant = await self._api.create_operator(
                    principal,
                    username=_string(document, "username"),
                    display_name=_string(document, "display_name"),
                    role=role,
                    token=_token(document.get("token")),
                    additional_permissions=_permissions(document.get("additional_permissions", [])),
                )
                return (
                    HTTPStatus.CREATED,
                    operator_credential_grant_to_dict(credential_grant),
                    {"Cache-Control": "no-store"},
                )

            operator_route = _operator_route(path)
            if operator_route is not None:
                operator_id, action = operator_route
                expected_revision = _integer(document, "expected_revision")
                if action == "update":
                    _require_fields(
                        document,
                        required={"expected_revision", "display_name", "role"},
                        optional={"additional_permissions"},
                    )
                    await self._verify_step_up(
                        authentication,
                        headers,
                        ControlPlaneStepUpAction.UPDATE_ACCESS,
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
                    await self._verify_step_up(
                        authentication,
                        headers,
                        ControlPlaneStepUpAction.ROTATE_CREDENTIAL,
                    )
                    credential_grant = await self._api.rotate_credential(
                        principal,
                        operator_id,
                        _token(document.get("token")),
                        expected_revision=expected_revision,
                    )
                    return (
                        HTTPStatus.OK,
                        operator_credential_grant_to_dict(credential_grant),
                        {"Cache-Control": "no-store"},
                    )
                if action == "disable":
                    receipt = await self._api.disable(
                        principal,
                        operator_id,
                        expected_revision=expected_revision,
                    )
                elif action == "reactivate":
                    receipt = await self._api.reactivate(
                        principal,
                        operator_id,
                        expected_revision=expected_revision,
                    )
                elif action == "revoke":
                    await self._verify_step_up(
                        authentication,
                        headers,
                        ControlPlaneStepUpAction.REVOKE_OPERATOR,
                    )
                    receipt = await self._api.revoke(
                        principal,
                        operator_id,
                        expected_revision=expected_revision,
                    )
                elif action == "revoke-sessions":
                    await self._verify_step_up(
                        authentication,
                        headers,
                        ControlPlaneStepUpAction.REVOKE_OPERATOR_SESSIONS,
                    )
                    revoked = await self._api.revoke_operator_sessions(principal, operator_id)
                    return (
                        HTTPStatus.OK,
                        {"schema_version": 1, "operator_id": str(operator_id), "revoked": revoked},
                        {},
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
        except (ControlPlaneDurableSessionCsrfRejectedError, ControlPlaneStepUpRejectedError):
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

    async def _verify_csrf(
        self,
        authentication: ControlPlaneDurableSessionAuthentication,
        headers: Mapping[str, tuple[str, ...]],
        server_origin: ControlPlaneBrowserOrigin,
    ) -> None:
        supplied_origin = _exact_origin(headers, server_origin)
        await self._boundary.verify_csrf(
            _one_optional_header(headers, "x-phoenix-csrf"),
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
            _one_optional_header(headers, "x-phoenix-step-up"),
            authentication,
            action,
        )


def _operator_route(path: str) -> tuple[UUID, str] | None:
    if not path.startswith(_OPERATOR_PREFIX):
        return None
    parts = path[len(_OPERATOR_PREFIX) :].split("/")
    if len(parts) != 2 or parts[1] not in {
        "update",
        "rotate",
        "disable",
        "reactivate",
        "revoke",
        "revoke-sessions",
    }:
        return None
    return UUID(parts[0]), parts[1]


def _session_route(path: str) -> UUID | None:
    if not path.startswith(_SESSION_PREFIX) or not path.endswith("/revoke"):
        return None
    value = path[len(_SESSION_PREFIX) : -len("/revoke")]
    if "/" in value or not value:
        return None
    return UUID(value)


def _operator_page_request(query: Mapping[str, tuple[str, ...]]) -> ControlPlaneOperatorPageRequest:
    if set(query) - {"offset", "limit"}:
        raise ValueError("unsupported operator pagination field")
    return ControlPlaneOperatorPageRequest(
        offset=_query_integer(query, "offset", 0),
        limit=_query_integer(query, "limit", 50),
    )


def _session_page_request(
    query: Mapping[str, tuple[str, ...]],
) -> ControlPlaneDurableSessionPageRequest:
    if set(query) - {"offset", "limit", "operator_id", "status"}:
        raise ValueError("unsupported durable session pagination field")
    operator_value = _query_text(query, "operator_id")
    status_value = _query_text(query, "status")
    return ControlPlaneDurableSessionPageRequest(
        offset=_query_integer(query, "offset", 0),
        limit=_query_integer(query, "limit", DEFAULT_DURABLE_SESSION_PAGE_SIZE),
        operator_id=None if operator_value is None else UUID(operator_value),
        status=None if status_value is None else ControlPlaneDurableSessionStatus(status_value),
    )


def _query_integer(query: Mapping[str, tuple[str, ...]], name: str, default: int) -> int:
    value = _query_text(query, name)
    return default if value is None else int(value)


def _query_text(query: Mapping[str, tuple[str, ...]], name: str) -> str | None:
    values = query.get(name)
    if values is None:
        return None
    if len(values) != 1 or not values[0]:
        raise ValueError("query value must be singular")
    return values[0]


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


def _one_optional_header(headers: Mapping[str, tuple[str, ...]], name: str) -> str | None:
    values = headers.get(name, ())
    if not values:
        return None
    if len(values) != 1 or not values[0]:
        raise ValueError(f"one {name} header is required")
    return values[0]


def _exact_origin(
    headers: Mapping[str, tuple[str, ...]],
    server_origin: ControlPlaneBrowserOrigin,
) -> ControlPlaneBrowserOrigin:
    origin = ControlPlaneBrowserOrigin(_one_optional_header(headers, "origin") or "")
    if origin != server_origin:
        raise ValueError("request origin does not match control plane")
    return origin
