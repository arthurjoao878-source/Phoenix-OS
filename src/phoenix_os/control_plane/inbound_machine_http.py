"""Scoped service-account administration for durable inbound events."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from datetime import timedelta
from http import HTTPStatus
from uuid import UUID

from phoenix_os.control_plane.inbound_management_http import (
    _authentication,
    _optional_aware_datetime,
    _optional_duration,
    _optional_integer,
    _optional_number,
    _optional_retry,
    _optional_string,
    _optional_string_set,
    _positive_integer,
    _require_fields,
    _string,
)
from phoenix_os.control_plane.service_account_authorization import (
    ControlPlaneServiceAccountAuthorizer,
    ControlPlaneServiceAccountPermissionDeniedError,
)
from phoenix_os.control_plane.service_account_machine_http import (
    ControlPlaneServiceAccountMachineRequest,
    ControlPlaneServiceAccountMachineResponse,
    ControlPlaneServiceAccountMachineRoute,
)
from phoenix_os.control_plane.service_account_policy import (
    ControlPlaneServiceAccountApiContext,
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
    INBOUND_EVENTS_READ_PERMISSION,
    INBOUND_RECEIPTS_READ_PERMISSION,
    INBOUND_SOURCES_AUTHENTICATION_PERMISSION,
    INBOUND_SOURCES_DISABLE_PERMISSION,
    INBOUND_SOURCES_ENABLE_PERMISSION,
    INBOUND_SOURCES_READ_PERMISSION,
    INBOUND_SOURCES_REVOKE_PERMISSION,
    INBOUND_SOURCES_ROTATE_PERMISSION,
    INBOUND_SOURCES_UPDATE_PERMISSION,
    InboundManager,
    inbound_event_view_to_dict,
    inbound_receipt_view_to_dict,
    inbound_redrive_result_to_dict,
    inbound_source_view_to_dict,
)
from phoenix_os.inbound_events.recovery import (
    INBOUND_REDRIVE_PERMISSION,
)
from phoenix_os.policy import PrincipalType, SecurityContext
from phoenix_os.secrets import SecretRef

CONTROL_PLANE_INBOUND_MACHINE_RESOURCE = "inbound-machine"
CONTROL_PLANE_INBOUND_MACHINE_BASE_PATH = "/v1/control-plane/machine/inbound"

_SOURCE = f"{CONTROL_PLANE_INBOUND_MACHINE_BASE_PATH}/source"
_SOURCE_UPDATE = f"{_SOURCE}/update"
_SOURCE_AUTHENTICATION = f"{_SOURCE}/update-authentication"
_SOURCE_DISABLE = f"{_SOURCE}/disable"
_SOURCE_ENABLE = f"{_SOURCE}/enable"
_SOURCE_REVOKE = f"{_SOURCE}/revoke"
_SOURCE_ROTATE = f"{_SOURCE}/rotate-hmac-key"
_EVENT = f"{CONTROL_PLANE_INBOUND_MACHINE_BASE_PATH}/event"
_EVENT_REDRIVE = f"{_EVENT}/redrive"
_RECEIPT = f"{CONTROL_PLANE_INBOUND_MACHINE_BASE_PATH}/receipt"
_NO_STORE = {"Cache-Control": "no-store"}

_ROUTE_SPECS = (
    ("GET", _SOURCE, INBOUND_SOURCES_READ_PERMISSION),
    ("POST", _SOURCE_UPDATE, INBOUND_SOURCES_UPDATE_PERMISSION),
    (
        "POST",
        _SOURCE_AUTHENTICATION,
        INBOUND_SOURCES_AUTHENTICATION_PERMISSION,
    ),
    ("POST", _SOURCE_DISABLE, INBOUND_SOURCES_DISABLE_PERMISSION),
    ("POST", _SOURCE_ENABLE, INBOUND_SOURCES_ENABLE_PERMISSION),
    ("POST", _SOURCE_REVOKE, INBOUND_SOURCES_REVOKE_PERMISSION),
    ("POST", _SOURCE_ROTATE, INBOUND_SOURCES_ROTATE_PERMISSION),
    ("GET", _EVENT, INBOUND_EVENTS_READ_PERMISSION),
    ("POST", _EVENT_REDRIVE, INBOUND_REDRIVE_PERMISSION),
    ("GET", _RECEIPT, INBOUND_RECEIPTS_READ_PERMISSION),
)


class ControlPlaneInboundMachineAdministration:
    """Expose concrete-resource inbound administration to machine identities."""

    def __init__(
        self,
        manager: InboundManager,
        *,
        exact_authorizer: ControlPlaneServiceAccountAuthorizer | None = None,
    ) -> None:
        if not isinstance(manager, InboundManager):
            raise TypeError("inbound machine administration requires InboundManager")
        authorizer = (
            ControlPlaneServiceAccountAuthorizer() if exact_authorizer is None else exact_authorizer
        )
        if not isinstance(
            authorizer,
            ControlPlaneServiceAccountAuthorizer,
        ):
            raise TypeError("inbound machine exact authorizer has an invalid type")
        self._manager = manager
        self._exact_authorizer = authorizer
        self._actions = {(method, path): action for method, path, action in _ROUTE_SPECS}
        self._routes = tuple(
            ControlPlaneServiceAccountMachineRoute(
                method=method,
                path=path,
                action=action,
                resource=CONTROL_PLANE_INBOUND_MACHINE_RESOURCE,
                handler=self._handle,
            )
            for method, path, action in _ROUTE_SPECS
        )

    @property
    def manager(self) -> InboundManager:
        return self._manager

    @property
    def routes(
        self,
    ) -> tuple[ControlPlaneServiceAccountMachineRoute, ...]:
        return self._routes

    async def _handle(
        self,
        context: ControlPlaneServiceAccountApiContext,
        request: ControlPlaneServiceAccountMachineRequest,
    ) -> ControlPlaneServiceAccountMachineResponse:
        try:
            action = self._actions[
                (
                    request.method,
                    request.path,
                )
            ]

            if request.path == _SOURCE:
                source_id = _required_query_uuid(
                    request,
                    "source_id",
                )
                resource = _source_resource(source_id)
                self._require_concrete(
                    context,
                    action=action,
                    resource=resource,
                )
                source_view = await self._manager.get_source(
                    source_id,
                    _manager_context(
                        context,
                        action,
                        resource,
                    ),
                )
                return (
                    HTTPStatus.OK,
                    inbound_source_view_to_dict(source_view),
                    dict(_NO_STORE),
                )

            if request.path == _EVENT:
                event_id = _required_query_uuid(
                    request,
                    "event_id",
                )
                resource = _event_resource(event_id)
                self._require_concrete(
                    context,
                    action=action,
                    resource=resource,
                )
                event_view = await self._manager.get_event(
                    event_id,
                    _manager_context(
                        context,
                        action,
                        resource,
                    ),
                )
                return (
                    HTTPStatus.OK,
                    inbound_event_view_to_dict(event_view),
                    dict(_NO_STORE),
                )

            if request.path == _RECEIPT:
                receipt_id = _required_query_uuid(
                    request,
                    "receipt_id",
                )
                resource = _receipt_resource(receipt_id)
                self._require_concrete(
                    context,
                    action=action,
                    resource=resource,
                )
                receipt_view = await self._manager.get_receipt(
                    receipt_id,
                    _manager_context(
                        context,
                        action,
                        resource,
                    ),
                )
                return (
                    HTTPStatus.OK,
                    inbound_receipt_view_to_dict(receipt_view),
                    dict(_NO_STORE),
                )

            document = _post_document(request)

            if request.path in {
                _SOURCE_UPDATE,
                _SOURCE_AUTHENTICATION,
                _SOURCE_DISABLE,
                _SOURCE_ENABLE,
                _SOURCE_REVOKE,
                _SOURCE_ROTATE,
            }:
                source_id = _uuid(document, "source_id")
                resource = _source_resource(source_id)
            elif request.path == _EVENT_REDRIVE:
                event_id = _uuid(document, "event_id")
                resource = _event_resource(event_id)
            else:
                raise ValueError("unknown inbound machine route")

            self._require_concrete(
                context,
                action=action,
                resource=resource,
            )
            manager_context = _manager_context(
                context,
                action,
                resource,
            )

            if request.path == _SOURCE_UPDATE:
                _require_fields(
                    document,
                    required={
                        "source_id",
                        "expected_revision",
                    },
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
                view = await self._manager.update_source(
                    source_id,
                    manager_context,
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

            if request.path == _SOURCE_AUTHENTICATION:
                _require_fields(
                    document,
                    required={
                        "source_id",
                        "expected_revision",
                        "authentication",
                    },
                )
                view = await self._manager.update_authentication(
                    source_id,
                    manager_context,
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

            if request.path in {
                _SOURCE_DISABLE,
                _SOURCE_ENABLE,
                _SOURCE_REVOKE,
            }:
                _require_fields(
                    document,
                    required={
                        "source_id",
                        "expected_revision",
                    },
                )
                expected_revision = _positive_integer(
                    document,
                    "expected_revision",
                )
                if request.path == _SOURCE_DISABLE:
                    view = await self._manager.disable_source(
                        source_id,
                        manager_context,
                        expected_revision=expected_revision,
                    )
                elif request.path == _SOURCE_ENABLE:
                    view = await self._manager.enable_source(
                        source_id,
                        manager_context,
                        expected_revision=expected_revision,
                    )
                else:
                    view = await self._manager.revoke_source(
                        source_id,
                        manager_context,
                        expected_revision=expected_revision,
                    )
                return (
                    HTTPStatus.OK,
                    inbound_source_view_to_dict(view),
                    dict(_NO_STORE),
                )

            if request.path == _SOURCE_ROTATE:
                _require_fields(
                    document,
                    required={
                        "source_id",
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
                lease_seconds = _optional_number(
                    document,
                    "lease_ttl_seconds",
                )
                view = await self._manager.rotate_hmac_key(
                    source_id,
                    manager_context,
                    expected_revision=_positive_integer(
                        document,
                        "expected_revision",
                    ),
                    secret_ref=SecretRef(
                        _string(document, "secret_name"),
                        _string(document, "secret_namespace"),
                        _positive_integer(
                            document,
                            "secret_version",
                        ),
                    ),
                    predecessor_valid_until=(
                        _optional_aware_datetime(
                            document,
                            "predecessor_valid_until",
                        )
                    ),
                    lease_ttl=(None if lease_seconds is None else timedelta(seconds=lease_seconds)),
                )
                return (
                    HTTPStatus.OK,
                    inbound_source_view_to_dict(view),
                    dict(_NO_STORE),
                )

            if request.path == _EVENT_REDRIVE:
                _require_fields(
                    document,
                    required={"event_id"},
                    optional={"scheduled_at"},
                )
                result = await self._manager.redrive_event(
                    event_id,
                    manager_context,
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

            raise ValueError("unknown inbound machine route")

        except (
            ControlPlaneServiceAccountPermissionDeniedError,
            InboundManagerAccessDeniedError,
        ):
            return (
                HTTPStatus.FORBIDDEN,
                {"error": "forbidden"},
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

    def _require_concrete(
        self,
        context: ControlPlaneServiceAccountApiContext,
        *,
        action: str,
        resource: str,
    ) -> None:
        self._exact_authorizer.require(
            context.authentication,
            action=action,
            resource=resource,
        )


def control_plane_inbound_machine_routes(
    manager: InboundManager,
    *,
    exact_authorizer: ControlPlaneServiceAccountAuthorizer | None = None,
) -> tuple[ControlPlaneServiceAccountMachineRoute, ...]:
    """Build the explicit concrete-resource inbound machine route set."""

    return ControlPlaneInboundMachineAdministration(
        manager,
        exact_authorizer=exact_authorizer,
    ).routes


def _manager_context(
    context: ControlPlaneServiceAccountApiContext,
    permission: str,
    resource: str,
) -> SecurityContext:
    security = context.security_context
    attributes = dict(security.attributes)
    attributes["resource"] = resource
    return SecurityContext(
        principal=context.principal_name,
        principal_type=PrincipalType.SERVICE,
        authenticated=True,
        roles=frozenset(),
        permissions=frozenset({permission}),
        scopes=context.scopes,
        attributes=attributes,
        correlation_id=context.correlation_id,
        causation_id=context.request_id,
        confirmed=False,
    )


def _required_query_uuid(
    request: ControlPlaneServiceAccountMachineRequest,
    name: str,
) -> UUID:
    if request.body:
        raise ValueError("inbound machine GET requests must not contain a body")
    if set(request.query) != {name}:
        raise ValueError("inbound machine GET requires one identifier query field")
    values = request.query[name]
    if len(values) != 1 or not values[0]:
        raise ValueError("inbound machine identifier must appear exactly once")
    return UUID(values[0])


def _post_document(
    request: ControlPlaneServiceAccountMachineRequest,
) -> Mapping[str, object]:
    if request.query:
        raise ValueError("inbound machine mutation does not accept query fields")
    values = request.headers.get("content-type", ())
    if len(values) != 1:
        raise ValueError("inbound machine content type is required")
    media_type = values[0].split(";", 1)[0].strip().lower()
    if media_type != "application/json":
        raise ValueError("inbound machine body must be JSON")
    if not request.body:
        raise ValueError("inbound machine body is required")
    document = json.loads(
        request.body.decode("utf-8"),
        object_pairs_hook=_strict_object,
        parse_constant=_reject_constant,
    )
    if not isinstance(document, dict):
        raise TypeError("inbound machine body must be an object")
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


def _uuid(
    document: Mapping[str, object],
    name: str,
) -> UUID:
    return UUID(_string(document, name))


def _source_resource(source_id: UUID) -> str:
    return f"inbound-source:{source_id}"


def _event_resource(event_id: UUID) -> str:
    return f"inbound-event:{event_id}"


def _receipt_resource(receipt_id: UUID) -> str:
    return f"inbound-receipt:{receipt_id}"
