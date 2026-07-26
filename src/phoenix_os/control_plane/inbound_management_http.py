"""Maintainer-only HTTP administration for secure inbound events."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta
from http import HTTPStatus
from typing import Protocol
from uuid import UUID

from phoenix_os.control_plane.auth import ControlPlanePrincipal
from phoenix_os.control_plane.csrf import ControlPlaneBrowserOrigin
from phoenix_os.control_plane.durable_session_access import (
    ControlPlaneDurableSessionAuthentication,
)
from phoenix_os.control_plane.errors import (
    ControlPlaneDurableSessionCsrfRejectedError,
    ControlPlaneStepUpRejectedError,
)
from phoenix_os.control_plane.step_up import ControlPlaneStepUpAction
from phoenix_os.inbound_events.contracts import (
    DEFAULT_INBOUND_PAGE_SIZE,
    InboundAuthenticationPolicy,
    InboundHmacPolicy,
    InboundPageRequest,
    InboundPublicationRetryPolicy,
    InboundServiceAccountPolicy,
)
from phoenix_os.inbound_events.errors import (
    InboundCorruptionError,
    InboundEventCapacityError,
    InboundEventConflictError,
    InboundEventNotFoundError,
    InboundEventRepositoryClosedError,
    InboundManagerAccessDeniedError,
    InboundManagerClosedError,
    InboundPersistenceError,
    InboundRecoveryClosedError,
    InboundRedriveNotEligibleError,
    InboundReplayCapacityError,
    InboundReplayRepositoryClosedError,
    InboundSchemaRegistrationError,
    InboundSourceAlreadyExistsError,
    InboundSourceCapacityError,
    InboundSourceConflictError,
    InboundSourceNotFoundError,
    InboundSourceRepositoryClosedError,
)
from phoenix_os.inbound_events.manager import (
    InboundManager,
    inbound_event_view_page_to_dict,
    inbound_event_view_to_dict,
    inbound_manager_snapshot_to_dict,
    inbound_receipt_view_to_dict,
    inbound_redrive_result_to_dict,
    inbound_source_view_page_to_dict,
    inbound_source_view_to_dict,
)
from phoenix_os.policy import PrincipalType, SecurityContext
from phoenix_os.secrets import SecretRef

INBOUND_MANAGEMENT_BASE_PATH = "/v1/control-plane/inbound"

_SOURCES_PATH = f"{INBOUND_MANAGEMENT_BASE_PATH}/sources"
_SOURCE_PREFIX = f"{_SOURCES_PATH}/"
_EVENTS_PATH = f"{INBOUND_MANAGEMENT_BASE_PATH}/events"
_EVENT_PREFIX = f"{_EVENTS_PATH}/"
_RECEIPT_PREFIX = f"{INBOUND_MANAGEMENT_BASE_PATH}/receipts/"
_HEALTH_PATH = f"{INBOUND_MANAGEMENT_BASE_PATH}/health"
_NO_STORE = {"Cache-Control": "no-store"}


class ControlPlaneInboundManagementCsrfVerifier(Protocol):
    """Durable-session CSRF verification boundary."""

    async def verify_csrf(
        self,
        token_value: str | None,
        authentication: ControlPlaneDurableSessionAuthentication,
        *,
        supplied_origin: ControlPlaneBrowserOrigin,
        expected_origin: ControlPlaneBrowserOrigin,
    ) -> object: ...


class _ControlPlaneInboundManagementStepUpVerifier(Protocol):
    async def verify(
        self,
        token_value: str | None,
        session: ControlPlaneDurableSessionAuthentication,
        action: ControlPlaneStepUpAction,
    ) -> object: ...


class ControlPlaneInboundManagementHttpAdapter:
    """Expose exact-permission inbound administration to Maintainer sessions."""

    def __init__(
        self,
        *,
        manager: InboundManager,
        boundary: ControlPlaneInboundManagementCsrfVerifier,
        step_up: _ControlPlaneInboundManagementStepUpVerifier,
    ) -> None:
        if not isinstance(manager, InboundManager):
            raise TypeError("inbound management HTTP requires InboundManager")
        if not callable(getattr(boundary, "verify_csrf", None)):
            raise TypeError("inbound management HTTP requires a CSRF boundary")
        if not callable(getattr(step_up, "verify", None)):
            raise TypeError("inbound management HTTP requires step-up verification")
        self._manager = manager
        self._boundary = boundary
        self._step_up = step_up

    @property
    def manager(self) -> InboundManager:
        return self._manager

    @staticmethod
    def handles(path: str) -> bool:
        return path == _HEALTH_PATH or path.startswith(f"{INBOUND_MANAGEMENT_BASE_PATH}/")

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
        context = _security_context(authentication.principal)
        try:
            if method == "GET":
                return await self._dispatch_get(
                    context=context,
                    path=path,
                    query=query,
                    body=body,
                )
            if method != "POST":
                return (
                    HTTPStatus.METHOD_NOT_ALLOWED,
                    {"error": "method_not_allowed"},
                    {"Allow": "GET, POST", **_NO_STORE},
                )
            if query:
                return (
                    HTTPStatus.BAD_REQUEST,
                    {"error": "invalid_request"},
                    dict(_NO_STORE),
                )
            await self._verify_csrf(authentication, headers, server_origin)
            return await self._dispatch_post(
                authentication=authentication,
                context=context,
                path=path,
                headers=headers,
                document=_json_object(body),
            )
        except InboundManagerAccessDeniedError:
            return HTTPStatus.FORBIDDEN, {"error": "forbidden"}, dict(_NO_STORE)
        except (
            ControlPlaneDurableSessionCsrfRejectedError,
            ControlPlaneStepUpRejectedError,
        ):
            return (
                HTTPStatus.FORBIDDEN,
                {"error": "request_rejected"},
                dict(_NO_STORE),
            )
        except InboundSourceNotFoundError:
            return (
                HTTPStatus.NOT_FOUND,
                {"error": "inbound_source_not_found"},
                dict(_NO_STORE),
            )
        except InboundEventNotFoundError:
            return (
                HTTPStatus.NOT_FOUND,
                {"error": "inbound_event_not_found"},
                dict(_NO_STORE),
            )
        except InboundRedriveNotEligibleError:
            return (
                HTTPStatus.CONFLICT,
                {"error": "inbound_redrive_rejected"},
                dict(_NO_STORE),
            )
        except (
            InboundSourceAlreadyExistsError,
            InboundSourceConflictError,
            InboundEventConflictError,
        ):
            return (
                HTTPStatus.CONFLICT,
                {"error": "inbound_conflict"},
                dict(_NO_STORE),
            )
        except InboundSchemaRegistrationError:
            return (
                HTTPStatus.UNPROCESSABLE_ENTITY,
                {"error": "inbound_schema_unavailable"},
                dict(_NO_STORE),
            )
        except (
            InboundSourceCapacityError,
            InboundEventCapacityError,
            InboundReplayCapacityError,
        ):
            return (
                HTTPStatus.TOO_MANY_REQUESTS,
                {"error": "inbound_capacity_exhausted"},
                {"Retry-After": "1", **_NO_STORE},
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
                {"error": "invalid_inbound_request"},
                dict(_NO_STORE),
            )
        except (
            InboundManagerClosedError,
            InboundRecoveryClosedError,
            InboundPersistenceError,
            InboundCorruptionError,
            InboundSourceRepositoryClosedError,
            InboundEventRepositoryClosedError,
            InboundReplayRepositoryClosedError,
            RuntimeError,
        ):
            return (
                HTTPStatus.SERVICE_UNAVAILABLE,
                {"error": "inbound_management_unavailable"},
                dict(_NO_STORE),
            )

    async def _dispatch_get(
        self,
        *,
        context: SecurityContext,
        path: str,
        query: Mapping[str, tuple[str, ...]],
        body: bytes,
    ) -> tuple[HTTPStatus, Mapping[str, object], dict[str, str]]:
        if body:
            return (
                HTTPStatus.BAD_REQUEST,
                {"error": "invalid_request"},
                dict(_NO_STORE),
            )

        if path == _SOURCES_PATH:
            source_page = await self._manager.list_sources(
                context,
                _page_request(query),
            )
            return (
                HTTPStatus.OK,
                inbound_source_view_page_to_dict(source_page),
                dict(_NO_STORE),
            )

        if path == _EVENTS_PATH:
            event_page = await self._manager.list_events(
                context,
                _page_request(query),
            )
            return (
                HTTPStatus.OK,
                inbound_event_view_page_to_dict(event_page),
                dict(_NO_STORE),
            )

        if path == _HEALTH_PATH:
            if query:
                raise ValueError("inbound health does not accept query fields")
            snapshot = await self._manager.snapshot(context)
            return (
                HTTPStatus.OK,
                inbound_manager_snapshot_to_dict(snapshot),
                dict(_NO_STORE),
            )

        if query:
            raise ValueError("inbound detail routes do not accept query fields")

        source_id = _detail_id(path, _SOURCE_PREFIX)
        if source_id is not None:
            source_view = await self._manager.get_source(
                source_id,
                context,
            )
            return (
                HTTPStatus.OK,
                inbound_source_view_to_dict(source_view),
                dict(_NO_STORE),
            )

        event_id = _detail_id(path, _EVENT_PREFIX)
        if event_id is not None:
            event_view = await self._manager.get_event(
                event_id,
                context,
            )
            return (
                HTTPStatus.OK,
                inbound_event_view_to_dict(event_view),
                dict(_NO_STORE),
            )

        receipt_id = _detail_id(path, _RECEIPT_PREFIX)
        if receipt_id is not None:
            receipt_view = await self._manager.get_receipt(
                receipt_id,
                context,
            )
            return (
                HTTPStatus.OK,
                inbound_receipt_view_to_dict(receipt_view),
                dict(_NO_STORE),
            )

        return HTTPStatus.NOT_FOUND, {"error": "not_found"}, dict(_NO_STORE)

    async def _dispatch_post(
        self,
        *,
        authentication: ControlPlaneDurableSessionAuthentication,
        context: SecurityContext,
        path: str,
        headers: Mapping[str, tuple[str, ...]],
        document: Mapping[str, object],
    ) -> tuple[HTTPStatus, Mapping[str, object], dict[str, str]]:
        if path == _SOURCES_PATH:
            _require_fields(
                document,
                required={
                    "name",
                    "display_name",
                    "authentication",
                    "event_types",
                },
                optional={
                    "max_body_bytes",
                    "max_header_bytes",
                    "timestamp_skew_seconds",
                    "replay_retention_seconds",
                    "max_concurrency",
                    "requests_per_minute",
                    "retry",
                },
            )
            await self._verify_step_up(
                authentication,
                headers,
                ControlPlaneStepUpAction.CREATE_INBOUND_SOURCE,
            )
            view = await self._manager.create_source(
                context,
                name=_string(document, "name"),
                display_name=_string(document, "display_name"),
                authentication=_authentication(document),
                event_types=_string_set(document, "event_types"),
                max_body_bytes=_optional_positive_integer(
                    document,
                    "max_body_bytes",
                    262_144,
                ),
                max_header_bytes=_optional_positive_integer(
                    document,
                    "max_header_bytes",
                    16_384,
                ),
                timestamp_skew=timedelta(
                    seconds=_optional_positive_number(
                        document,
                        "timestamp_skew_seconds",
                        300.0,
                    )
                ),
                replay_retention=timedelta(
                    seconds=_optional_positive_number(
                        document,
                        "replay_retention_seconds",
                        86_400.0,
                    )
                ),
                max_concurrency=_optional_positive_integer(
                    document,
                    "max_concurrency",
                    8,
                ),
                requests_per_minute=_optional_positive_integer(
                    document,
                    "requests_per_minute",
                    120,
                ),
                retry=_optional_retry(document),
            )
            return (
                HTTPStatus.CREATED,
                inbound_source_view_to_dict(view),
                dict(_NO_STORE),
            )

        source_route = _action_route(path, _SOURCE_PREFIX)
        if source_route is not None:
            source_id, action = source_route
            if action == "update":
                _require_fields(
                    document,
                    required={"expected_revision"},
                    optional={
                        "name",
                        "display_name",
                        "event_types",
                        "max_body_bytes",
                        "max_header_bytes",
                        "timestamp_skew_seconds",
                        "replay_retention_seconds",
                        "max_concurrency",
                        "requests_per_minute",
                        "retry",
                    },
                )
                await self._verify_step_up(
                    authentication,
                    headers,
                    ControlPlaneStepUpAction.UPDATE_INBOUND_SOURCE,
                )
                view = await self._manager.update_source(
                    source_id,
                    context,
                    expected_revision=_positive_integer(
                        document,
                        "expected_revision",
                    ),
                    name=_optional_string(document, "name"),
                    display_name=_optional_string(
                        document,
                        "display_name",
                    ),
                    event_types=_optional_string_set(
                        document,
                        "event_types",
                    ),
                    max_body_bytes=_optional_integer(
                        document,
                        "max_body_bytes",
                    ),
                    max_header_bytes=_optional_integer(
                        document,
                        "max_header_bytes",
                    ),
                    timestamp_skew=_optional_duration(
                        document,
                        "timestamp_skew_seconds",
                    ),
                    replay_retention=_optional_duration(
                        document,
                        "replay_retention_seconds",
                    ),
                    max_concurrency=_optional_integer(
                        document,
                        "max_concurrency",
                    ),
                    requests_per_minute=_optional_integer(
                        document,
                        "requests_per_minute",
                    ),
                    retry=_optional_retry(document),
                )
                return (
                    HTTPStatus.OK,
                    inbound_source_view_to_dict(view),
                    dict(_NO_STORE),
                )

            if action == "update-authentication":
                _require_fields(
                    document,
                    required={"expected_revision", "authentication"},
                )
                await self._verify_step_up(
                    authentication,
                    headers,
                    ControlPlaneStepUpAction.UPDATE_INBOUND_AUTHENTICATION,
                )
                view = await self._manager.update_authentication(
                    source_id,
                    context,
                    expected_revision=_positive_integer(
                        document,
                        "expected_revision",
                    ),
                    authentication=_authentication(document),
                )
                return (
                    HTTPStatus.OK,
                    inbound_source_view_to_dict(view),
                    dict(_NO_STORE),
                )

            if action == "disable":
                _revision_only(document)
                view = await self._manager.disable_source(
                    source_id,
                    context,
                    expected_revision=_positive_integer(
                        document,
                        "expected_revision",
                    ),
                )
                return (
                    HTTPStatus.OK,
                    inbound_source_view_to_dict(view),
                    dict(_NO_STORE),
                )

            if action == "enable":
                _revision_only(document)
                await self._verify_step_up(
                    authentication,
                    headers,
                    ControlPlaneStepUpAction.ENABLE_INBOUND_SOURCE,
                )
                view = await self._manager.enable_source(
                    source_id,
                    context,
                    expected_revision=_positive_integer(
                        document,
                        "expected_revision",
                    ),
                )
                return (
                    HTTPStatus.OK,
                    inbound_source_view_to_dict(view),
                    dict(_NO_STORE),
                )

            if action == "revoke":
                _revision_only(document)
                await self._verify_step_up(
                    authentication,
                    headers,
                    ControlPlaneStepUpAction.REVOKE_INBOUND_SOURCE,
                )
                view = await self._manager.revoke_source(
                    source_id,
                    context,
                    expected_revision=_positive_integer(
                        document,
                        "expected_revision",
                    ),
                )
                return (
                    HTTPStatus.OK,
                    inbound_source_view_to_dict(view),
                    dict(_NO_STORE),
                )

            if action == "rotate-hmac-key":
                _require_fields(
                    document,
                    required={
                        "expected_revision",
                        "secret_name",
                        "secret_namespace",
                        "secret_version",
                    },
                    optional={
                        "predecessor_valid_until",
                        "lease_ttl_seconds",
                    },
                )
                await self._verify_step_up(
                    authentication,
                    headers,
                    ControlPlaneStepUpAction.ROTATE_INBOUND_HMAC_KEY,
                )
                lease_seconds = _optional_number(
                    document,
                    "lease_ttl_seconds",
                )
                view = await self._manager.rotate_hmac_key(
                    source_id,
                    context,
                    expected_revision=_positive_integer(
                        document,
                        "expected_revision",
                    ),
                    secret_ref=SecretRef(
                        _string(document, "secret_name"),
                        _string(document, "secret_namespace"),
                        _positive_integer(document, "secret_version"),
                    ),
                    predecessor_valid_until=_optional_aware_datetime(
                        document,
                        "predecessor_valid_until",
                    ),
                    lease_ttl=(None if lease_seconds is None else timedelta(seconds=lease_seconds)),
                )
                return (
                    HTTPStatus.OK,
                    inbound_source_view_to_dict(view),
                    dict(_NO_STORE),
                )

        event_route = _action_route(path, _EVENT_PREFIX)
        if event_route is not None and event_route[1] == "redrive":
            _require_fields(
                document,
                required=set(),
                optional={"scheduled_at"},
            )
            await self._verify_step_up(
                authentication,
                headers,
                ControlPlaneStepUpAction.REDRIVE_INBOUND_EVENT,
            )
            result = await self._manager.redrive_event(
                event_route[0],
                context,
                scheduled_at=_optional_aware_datetime(
                    document,
                    "scheduled_at",
                ),
            )
            return (
                HTTPStatus.ACCEPTED,
                inbound_redrive_result_to_dict(result),
                dict(_NO_STORE),
            )

        return HTTPStatus.NOT_FOUND, {"error": "not_found"}, dict(_NO_STORE)

    async def _verify_csrf(
        self,
        authentication: ControlPlaneDurableSessionAuthentication,
        headers: Mapping[str, tuple[str, ...]],
        server_origin: ControlPlaneBrowserOrigin,
    ) -> None:
        try:
            supplied_origin = _exact_origin(headers, server_origin)
        except ValueError as exception:
            raise ControlPlaneDurableSessionCsrfRejectedError(
                "inbound management request origin rejected"
            ) from exception
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


def _security_context(principal: ControlPlanePrincipal) -> SecurityContext:
    return SecurityContext(
        principal=principal.name,
        principal_type=PrincipalType.USER,
        authenticated=True,
        permissions=principal.permissions,
    )


def _detail_id(path: str, prefix: str) -> UUID | None:
    if not path.startswith(prefix):
        return None
    suffix = path[len(prefix) :]
    if not suffix or "/" in suffix:
        return None
    return UUID(suffix)


def _action_route(path: str, prefix: str) -> tuple[UUID, str] | None:
    if not path.startswith(prefix):
        return None
    parts = path[len(prefix) :].split("/")
    if len(parts) != 2:
        return None
    allowed = {
        "update",
        "update-authentication",
        "disable",
        "enable",
        "revoke",
        "rotate-hmac-key",
        "redrive",
    }
    if parts[1] not in allowed:
        return None
    return UUID(parts[0]), parts[1]


def _page_request(
    query: Mapping[str, tuple[str, ...]],
) -> InboundPageRequest:
    if set(query) - {"offset", "limit"}:
        raise ValueError("unsupported inbound pagination field")
    return InboundPageRequest(
        offset=_query_integer(query, "offset", 0),
        limit=_query_integer(
            query,
            "limit",
            DEFAULT_INBOUND_PAGE_SIZE,
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


def _json_object(body: bytes) -> Mapping[str, object]:
    if not body:
        raise ValueError("inbound management body is required")
    document = json.loads(
        body.decode("utf-8"),
        object_pairs_hook=_strict_object,
        parse_constant=_reject_constant,
    )
    if not isinstance(document, dict):
        raise TypeError("inbound management body must be an object")
    return document


def _strict_object(
    pairs: Sequence[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(value: str) -> object:
    raise ValueError(f"unsupported JSON constant: {value}")


def _require_fields(
    document: Mapping[str, object],
    *,
    required: set[str],
    optional: set[str] | None = None,
) -> None:
    allowed = required | (set() if optional is None else optional)
    if not required.issubset(document) or set(document) - allowed:
        raise ValueError("inbound management fields do not match route schema")


def _revision_only(document: Mapping[str, object]) -> None:
    _require_fields(document, required={"expected_revision"})


def _string(document: Mapping[str, object], name: str) -> str:
    value = document[name]
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a string")
    return value


def _optional_string(
    document: Mapping[str, object],
    name: str,
) -> str | None:
    return None if name not in document else _string(document, name)


def _positive_integer(
    document: Mapping[str, object],
    name: str,
) -> int:
    value = document[name]
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise TypeError(f"{name} must be a positive integer")
    return value


def _optional_integer(
    document: Mapping[str, object],
    name: str,
) -> int | None:
    return None if name not in document else _positive_integer(document, name)


def _optional_positive_integer(
    document: Mapping[str, object],
    name: str,
    default: int,
) -> int:
    return default if name not in document else _positive_integer(document, name)


def _positive_number(
    document: Mapping[str, object],
    name: str,
) -> float:
    value = document[name]
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{name} must be a positive number")
    resolved = float(value)
    if resolved <= 0:
        raise ValueError(f"{name} must be a positive number")
    return resolved


def _optional_number(
    document: Mapping[str, object],
    name: str,
) -> float | None:
    return None if name not in document else _positive_number(document, name)


def _optional_positive_number(
    document: Mapping[str, object],
    name: str,
    default: float,
) -> float:
    return default if name not in document else _positive_number(document, name)


def _string_set(
    document: Mapping[str, object],
    name: str,
) -> frozenset[str]:
    raw = document[name]
    if not isinstance(raw, list):
        raise TypeError(f"{name} must be an array of strings")
    values: list[str] = []
    for item in raw:
        if not isinstance(item, str):
            raise TypeError(f"{name} must be an array of strings")
        values.append(item)
    return frozenset(values)


def _optional_string_set(
    document: Mapping[str, object],
    name: str,
) -> frozenset[str] | None:
    return None if name not in document else _string_set(document, name)


def _mapping(
    document: Mapping[str, object],
    name: str,
) -> Mapping[str, object]:
    value = document[name]
    if not isinstance(value, dict):
        raise TypeError(f"{name} must be an object")
    return value


def _authentication(
    document: Mapping[str, object],
) -> InboundAuthenticationPolicy:
    raw = _mapping(document, "authentication")
    mode = _string(raw, "mode")
    if mode == "hmac_sha256":
        _require_fields(
            raw,
            required={
                "mode",
                "secret_name",
                "secret_namespace",
                "secret_version",
            },
            optional={"lease_ttl_seconds"},
        )
        lease_seconds = _optional_positive_number(
            raw,
            "lease_ttl_seconds",
            30.0,
        )
        return InboundHmacPolicy(
            SecretRef(
                _string(raw, "secret_name"),
                _string(raw, "secret_namespace"),
                _positive_integer(raw, "secret_version"),
            ),
            lease_ttl=timedelta(seconds=lease_seconds),
        )
    if mode == "service_account":
        _require_fields(
            raw,
            required={"mode", "resource"},
            optional={"required_action"},
        )
        return InboundServiceAccountPolicy(
            resource=_string(raw, "resource"),
            required_action=(
                "inbound_event.submit"
                if "required_action" not in raw
                else _string(raw, "required_action")
            ),
        )
    raise ValueError("unsupported inbound authentication mode")


def _optional_retry(
    document: Mapping[str, object],
) -> InboundPublicationRetryPolicy | None:
    if "retry" not in document:
        return None
    raw = _mapping(document, "retry")
    _require_fields(
        raw,
        required=set(),
        optional={
            "max_attempts",
            "initial_delay_seconds",
            "multiplier",
            "max_delay_seconds",
        },
    )
    default = InboundPublicationRetryPolicy()
    return InboundPublicationRetryPolicy(
        max_attempts=(
            default.max_attempts
            if "max_attempts" not in raw
            else _positive_integer(raw, "max_attempts")
        ),
        initial_delay=timedelta(
            seconds=_optional_positive_number(
                raw,
                "initial_delay_seconds",
                default.initial_delay.total_seconds(),
            )
        ),
        multiplier=_optional_positive_number(
            raw,
            "multiplier",
            default.multiplier,
        ),
        max_delay=timedelta(
            seconds=_optional_positive_number(
                raw,
                "max_delay_seconds",
                default.max_delay.total_seconds(),
            )
        ),
    )


def _optional_duration(
    document: Mapping[str, object],
    name: str,
) -> timedelta | None:
    value = _optional_number(document, name)
    return None if value is None else timedelta(seconds=value)


def _optional_aware_datetime(
    document: Mapping[str, object],
    name: str,
) -> datetime | None:
    if name not in document:
        return None
    value = datetime.fromisoformat(_string(document, name))
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name} must be timezone-aware")
    return value


def _one_optional_header(
    headers: Mapping[str, tuple[str, ...]],
    name: str,
) -> str | None:
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
    origin = _one_optional_header(headers, "origin")
    if origin is None:
        raise ValueError("Origin is required")
    supplied = ControlPlaneBrowserOrigin(origin)
    if supplied != server_origin:
        raise ValueError("Origin does not match")
    return supplied
