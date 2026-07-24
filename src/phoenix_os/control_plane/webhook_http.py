"""Maintainer-only HTTP administration for durable webhooks."""

from __future__ import annotations

import json
from collections.abc import Mapping
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
from phoenix_os.policy import PrincipalType, SecurityContext
from phoenix_os.secrets import SecretRef
from phoenix_os.webhooks.contracts import (
    DEFAULT_WEBHOOK_PAGE_SIZE,
    WebhookEndpoint,
    WebhookPageRequest,
    WebhookRetryPolicy,
    WebhookSigningPolicy,
)
from phoenix_os.webhooks.errors import (
    WebhookDeliveryCapacityError,
    WebhookDeliveryConflictError,
    WebhookDeliveryNotFoundError,
    WebhookDeliveryRepositoryClosedError,
    WebhookManagerAccessDeniedError,
    WebhookManagerClosedError,
    WebhookPersistenceError,
    WebhookRecoveryClosedError,
    WebhookRedriveNotEligibleError,
    WebhookSubscriptionAlreadyExistsError,
    WebhookSubscriptionCapacityError,
    WebhookSubscriptionConflictError,
    WebhookSubscriptionNotFoundError,
    WebhookSubscriptionRepositoryClosedError,
)
from phoenix_os.webhooks.manager import (
    WebhookManager,
    webhook_delivery_view_page_to_dict,
    webhook_delivery_view_to_dict,
    webhook_manager_snapshot_to_dict,
    webhook_redrive_result_to_dict,
    webhook_subscription_view_page_to_dict,
    webhook_subscription_view_to_dict,
)

_WEBHOOKS_PATH = "/v1/control-plane/webhooks"
_SUBSCRIPTIONS_PATH = f"{_WEBHOOKS_PATH}/subscriptions"
_SUBSCRIPTION_PREFIX = f"{_SUBSCRIPTIONS_PATH}/"
_DELIVERIES_PATH = f"{_WEBHOOKS_PATH}/deliveries"
_DELIVERY_PREFIX = f"{_DELIVERIES_PATH}/"
_HEALTH_PATH = f"{_WEBHOOKS_PATH}/health"
_NO_STORE = {"Cache-Control": "no-store"}


class ControlPlaneWebhookCsrfVerifier(Protocol):
    """Durable-session CSRF verification boundary."""

    async def verify_csrf(
        self,
        token_value: str | None,
        authentication: ControlPlaneDurableSessionAuthentication,
        *,
        supplied_origin: ControlPlaneBrowserOrigin,
        expected_origin: ControlPlaneBrowserOrigin,
    ) -> object: ...


class _ControlPlaneWebhookStepUpVerifier(Protocol):
    async def verify(
        self,
        token_value: str | None,
        session: ControlPlaneDurableSessionAuthentication,
        action: ControlPlaneStepUpAction,
    ) -> object: ...


class ControlPlaneWebhookHttpAdapter:
    """Expose exact-permission webhook administration to durable Maintainer sessions."""

    def __init__(
        self,
        *,
        manager: WebhookManager,
        boundary: ControlPlaneWebhookCsrfVerifier,
        step_up: _ControlPlaneWebhookStepUpVerifier,
    ) -> None:
        if not isinstance(manager, WebhookManager):
            raise TypeError("webhook HTTP requires a WebhookManager")
        if not callable(getattr(boundary, "verify_csrf", None)):
            raise TypeError("webhook HTTP requires a CSRF boundary")
        if not callable(getattr(step_up, "verify", None)):
            raise TypeError("webhook HTTP requires step-up verification")
        self._manager = manager
        self._boundary = boundary
        self._step_up = step_up

    @property
    def manager(self) -> WebhookManager:
        return self._manager

    @staticmethod
    def handles(path: str) -> bool:
        return path == _HEALTH_PATH or path.startswith(f"{_WEBHOOKS_PATH}/")

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
                return HTTPStatus.BAD_REQUEST, {"error": "invalid_request"}, dict(_NO_STORE)
            await self._verify_csrf(authentication, headers, server_origin)
            return await self._dispatch_post(
                authentication=authentication,
                context=context,
                path=path,
                headers=headers,
                document=_json_object(body),
            )
        except WebhookManagerAccessDeniedError:
            return HTTPStatus.FORBIDDEN, {"error": "forbidden"}, dict(_NO_STORE)
        except (
            ControlPlaneDurableSessionCsrfRejectedError,
            ControlPlaneStepUpRejectedError,
        ):
            return HTTPStatus.FORBIDDEN, {"error": "request_rejected"}, dict(_NO_STORE)
        except WebhookSubscriptionNotFoundError:
            return (
                HTTPStatus.NOT_FOUND,
                {"error": "webhook_subscription_not_found"},
                dict(_NO_STORE),
            )
        except WebhookDeliveryNotFoundError:
            return (
                HTTPStatus.NOT_FOUND,
                {"error": "webhook_delivery_not_found"},
                dict(_NO_STORE),
            )
        except WebhookRedriveNotEligibleError as exception:
            return (
                HTTPStatus.CONFLICT,
                {
                    "error": "webhook_redrive_rejected",
                    "category": exception.category,
                },
                dict(_NO_STORE),
            )
        except (
            WebhookSubscriptionAlreadyExistsError,
            WebhookSubscriptionConflictError,
            WebhookDeliveryConflictError,
        ):
            return HTTPStatus.CONFLICT, {"error": "webhook_conflict"}, dict(_NO_STORE)
        except (
            WebhookSubscriptionCapacityError,
            WebhookDeliveryCapacityError,
        ):
            return (
                HTTPStatus.TOO_MANY_REQUESTS,
                {"error": "webhook_capacity_exhausted"},
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
                {"error": "invalid_webhook_request"},
                dict(_NO_STORE),
            )
        except (
            WebhookManagerClosedError,
            WebhookRecoveryClosedError,
            WebhookPersistenceError,
            WebhookSubscriptionRepositoryClosedError,
            WebhookDeliveryRepositoryClosedError,
            RuntimeError,
        ):
            return (
                HTTPStatus.SERVICE_UNAVAILABLE,
                {"error": "webhooks_unavailable"},
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
            return HTTPStatus.BAD_REQUEST, {"error": "invalid_request"}, dict(_NO_STORE)

        if path == _SUBSCRIPTIONS_PATH:
            subscription_page = await self._manager.list_subscriptions(
                context,
                _page_request(query),
            )
            return (
                HTTPStatus.OK,
                webhook_subscription_view_page_to_dict(subscription_page),
                dict(_NO_STORE),
            )

        if path == _DELIVERIES_PATH:
            delivery_page = await self._manager.list_deliveries(
                context,
                _page_request(query),
            )
            return (
                HTTPStatus.OK,
                webhook_delivery_view_page_to_dict(delivery_page),
                dict(_NO_STORE),
            )

        if path == _HEALTH_PATH:
            if query:
                raise ValueError("webhook health does not accept query fields")
            snapshot = await self._manager.snapshot(context)
            return HTTPStatus.OK, webhook_manager_snapshot_to_dict(snapshot), dict(_NO_STORE)

        if query:
            raise ValueError("webhook detail routes do not accept query fields")

        subscription_id = _detail_id(path, _SUBSCRIPTION_PREFIX)
        if subscription_id is not None:
            subscription_view = await self._manager.get_subscription(
                subscription_id,
                context,
            )
            return (
                HTTPStatus.OK,
                webhook_subscription_view_to_dict(subscription_view),
                dict(_NO_STORE),
            )

        delivery_id = _detail_id(path, _DELIVERY_PREFIX)
        if delivery_id is not None:
            delivery_view = await self._manager.get_delivery(
                delivery_id,
                context,
            )
            return (
                HTTPStatus.OK,
                webhook_delivery_view_to_dict(delivery_view),
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
        if path == _SUBSCRIPTIONS_PATH:
            _require_fields(
                document,
                required={
                    "name",
                    "display_name",
                    "event_types",
                    "endpoint",
                    "signing",
                    "egress_policy",
                },
                optional={"retry", "resource_filters"},
            )
            await self._verify_step_up(
                authentication,
                headers,
                ControlPlaneStepUpAction.CREATE_WEBHOOK_SUBSCRIPTION,
            )
            view = await self._manager.create_subscription(
                context,
                name=_string(document, "name"),
                display_name=_string(document, "display_name"),
                event_types=_string_set(document, "event_types"),
                endpoint=_endpoint(document),
                signing=_signing(document),
                egress_policy=_string(document, "egress_policy"),
                retry=_optional_retry(document),
                resource_filters=_optional_resource_filters(document),
            )
            return (
                HTTPStatus.CREATED,
                webhook_subscription_view_to_dict(view),
                dict(_NO_STORE),
            )

        subscription_route = _action_route(path, _SUBSCRIPTION_PREFIX)
        if subscription_route is not None:
            subscription_id, action = subscription_route
            if action == "update":
                _require_fields(
                    document,
                    required={"expected_revision"},
                    optional={
                        "name",
                        "display_name",
                        "event_types",
                        "endpoint",
                        "egress_policy",
                        "retry",
                        "resource_filters",
                    },
                )
                await self._verify_step_up(
                    authentication,
                    headers,
                    ControlPlaneStepUpAction.UPDATE_WEBHOOK_SUBSCRIPTION,
                )
                view = await self._manager.update_subscription(
                    subscription_id,
                    context,
                    expected_revision=_positive_integer(
                        document,
                        "expected_revision",
                    ),
                    name=_optional_string(document, "name"),
                    display_name=_optional_string(document, "display_name"),
                    event_types=_optional_string_set(document, "event_types"),
                    endpoint=_optional_endpoint(document),
                    egress_policy=_optional_string(document, "egress_policy"),
                    retry=_optional_retry(document),
                    resource_filters=_optional_resource_filters(document),
                )
                return (
                    HTTPStatus.OK,
                    webhook_subscription_view_to_dict(view),
                    dict(_NO_STORE),
                )

            if action == "disable":
                _revision_only(document)
                view = await self._manager.disable_subscription(
                    subscription_id,
                    context,
                    expected_revision=_positive_integer(
                        document,
                        "expected_revision",
                    ),
                )
                return (
                    HTTPStatus.OK,
                    webhook_subscription_view_to_dict(view),
                    dict(_NO_STORE),
                )

            if action == "enable":
                _revision_only(document)
                await self._verify_step_up(
                    authentication,
                    headers,
                    ControlPlaneStepUpAction.ENABLE_WEBHOOK_SUBSCRIPTION,
                )
                view = await self._manager.enable_subscription(
                    subscription_id,
                    context,
                    expected_revision=_positive_integer(
                        document,
                        "expected_revision",
                    ),
                )
                return (
                    HTTPStatus.OK,
                    webhook_subscription_view_to_dict(view),
                    dict(_NO_STORE),
                )

            if action == "revoke":
                _revision_only(document)
                await self._verify_step_up(
                    authentication,
                    headers,
                    ControlPlaneStepUpAction.REVOKE_WEBHOOK_SUBSCRIPTION,
                )
                view = await self._manager.revoke_subscription(
                    subscription_id,
                    context,
                    expected_revision=_positive_integer(
                        document,
                        "expected_revision",
                    ),
                )
                return (
                    HTTPStatus.OK,
                    webhook_subscription_view_to_dict(view),
                    dict(_NO_STORE),
                )

            if action == "rotate-signing-key":
                _require_fields(
                    document,
                    required={
                        "expected_revision",
                        "secret_name",
                        "secret_namespace",
                        "secret_version",
                    },
                    optional={"lease_ttl_seconds"},
                )
                await self._verify_step_up(
                    authentication,
                    headers,
                    ControlPlaneStepUpAction.ROTATE_WEBHOOK_SIGNING_KEY,
                )
                lease_seconds = _optional_positive_number(
                    document,
                    "lease_ttl_seconds",
                )
                view = await self._manager.rotate_signing_key(
                    subscription_id,
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
                    lease_ttl=(None if lease_seconds is None else timedelta(seconds=lease_seconds)),
                )
                return (
                    HTTPStatus.OK,
                    webhook_subscription_view_to_dict(view),
                    dict(_NO_STORE),
                )

        delivery_route = _action_route(path, _DELIVERY_PREFIX)
        if delivery_route is not None and delivery_route[1] == "redrive":
            _require_fields(
                document,
                required=set(),
                optional={"scheduled_at"},
            )
            await self._verify_step_up(
                authentication,
                headers,
                ControlPlaneStepUpAction.REDRIVE_WEBHOOK_DELIVERY,
            )
            result = await self._manager.redrive_delivery(
                delivery_route[0],
                context,
                scheduled_at=_optional_aware_datetime(document, "scheduled_at"),
            )
            return (
                HTTPStatus.ACCEPTED,
                webhook_redrive_result_to_dict(result),
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
                "webhook request origin rejected"
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
        "disable",
        "enable",
        "revoke",
        "rotate-signing-key",
        "redrive",
    }
    if parts[1] not in allowed:
        return None
    return UUID(parts[0]), parts[1]


def _page_request(query: Mapping[str, tuple[str, ...]]) -> WebhookPageRequest:
    if set(query) - {"offset", "limit"}:
        raise ValueError("unsupported webhook pagination field")
    return WebhookPageRequest(
        offset=_query_integer(query, "offset", 0),
        limit=_query_integer(query, "limit", DEFAULT_WEBHOOK_PAGE_SIZE),
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
        raise ValueError("webhook body is required")
    document = json.loads(body.decode("utf-8"))
    if not isinstance(document, dict):
        raise TypeError("webhook body must be an object")
    return document


def _require_fields(
    document: Mapping[str, object],
    *,
    required: set[str],
    optional: set[str] | None = None,
) -> None:
    allowed = required | (set() if optional is None else optional)
    if not required.issubset(document) or set(document) - allowed:
        raise ValueError("webhook request fields do not match route schema")


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


def _positive_integer(document: Mapping[str, object], name: str) -> int:
    value = document[name]
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise TypeError(f"{name} must be a positive integer")
    return value


def _positive_number(document: Mapping[str, object], name: str) -> float:
    value = document[name]
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{name} must be a positive number")
    resolved = float(value)
    if resolved <= 0:
        raise ValueError(f"{name} must be a positive number")
    return resolved


def _optional_positive_number(
    document: Mapping[str, object],
    name: str,
) -> float | None:
    return None if name not in document else _positive_number(document, name)


def _nonnegative_number(document: Mapping[str, object], name: str) -> float:
    value = document[name]
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{name} must be a nonnegative number")
    resolved = float(value)
    if resolved < 0:
        raise ValueError(f"{name} must be a nonnegative number")
    return resolved


def _string_set(document: Mapping[str, object], name: str) -> frozenset[str]:
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


def _mapping(document: Mapping[str, object], name: str) -> Mapping[str, object]:
    value = document[name]
    if not isinstance(value, dict):
        raise TypeError(f"{name} must be an object")
    return value


def _endpoint(document: Mapping[str, object]) -> WebhookEndpoint:
    raw = _mapping(document, "endpoint")
    _require_fields(raw, required={"url"}, optional={"allow_insecure_loopback"})
    allow_insecure = raw.get("allow_insecure_loopback", False)
    if type(allow_insecure) is not bool:
        raise TypeError("allow_insecure_loopback must be bool")
    return WebhookEndpoint(
        _string(raw, "url"),
        allow_insecure_loopback=allow_insecure,
    )


def _optional_endpoint(document: Mapping[str, object]) -> WebhookEndpoint | None:
    return None if "endpoint" not in document else _endpoint(document)


def _signing(document: Mapping[str, object]) -> WebhookSigningPolicy:
    raw = _mapping(document, "signing")
    _require_fields(
        raw,
        required={"secret_name", "secret_namespace", "secret_version"},
        optional={"lease_ttl_seconds"},
    )
    lease_seconds = (
        30.0 if "lease_ttl_seconds" not in raw else _positive_number(raw, "lease_ttl_seconds")
    )
    return WebhookSigningPolicy(
        SecretRef(
            _string(raw, "secret_name"),
            _string(raw, "secret_namespace"),
            _positive_integer(raw, "secret_version"),
        ),
        lease_ttl=timedelta(seconds=lease_seconds),
    )


def _optional_retry(document: Mapping[str, object]) -> WebhookRetryPolicy | None:
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
            "jitter_ratio",
        },
    )
    default = WebhookRetryPolicy()
    return WebhookRetryPolicy(
        max_attempts=(
            default.max_attempts
            if "max_attempts" not in raw
            else _positive_integer(raw, "max_attempts")
        ),
        initial_delay=timedelta(
            seconds=(
                default.initial_delay.total_seconds()
                if "initial_delay_seconds" not in raw
                else _positive_number(raw, "initial_delay_seconds")
            )
        ),
        multiplier=(
            default.multiplier if "multiplier" not in raw else _positive_number(raw, "multiplier")
        ),
        max_delay=timedelta(
            seconds=(
                default.max_delay.total_seconds()
                if "max_delay_seconds" not in raw
                else _positive_number(raw, "max_delay_seconds")
            )
        ),
        jitter_ratio=(
            default.jitter_ratio
            if "jitter_ratio" not in raw
            else _nonnegative_number(raw, "jitter_ratio")
        ),
    )


def _optional_resource_filters(
    document: Mapping[str, object],
) -> Mapping[str, Mapping[str, frozenset[str]]] | None:
    if "resource_filters" not in document:
        return None
    raw = _mapping(document, "resource_filters")
    result: dict[str, Mapping[str, frozenset[str]]] = {}
    for event_name, fields_value in raw.items():
        if not isinstance(event_name, str) or not isinstance(fields_value, dict):
            raise TypeError("resource_filters must map strings to objects")
        fields: dict[str, frozenset[str]] = {}
        for field_name, values in fields_value.items():
            if not isinstance(field_name, str) or not isinstance(values, list):
                raise TypeError("resource filter fields must map strings to arrays")
            normalized: list[str] = []
            for item in values:
                if not isinstance(item, str):
                    raise TypeError("resource filter values must be strings")
                normalized.append(item)
            fields[field_name] = frozenset(normalized)
        result[event_name] = fields
    return result


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
    origin = ControlPlaneBrowserOrigin(_one_optional_header(headers, "origin") or "")
    if origin != server_origin:
        raise ValueError("request origin does not match control plane")
    return origin
