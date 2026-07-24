"""Scoped service-account administration for durable webhooks."""

from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import timedelta
from http import HTTPStatus
from uuid import UUID

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
from phoenix_os.control_plane.webhook_http import (
    _endpoint,
    _optional_aware_datetime,
    _optional_endpoint,
    _optional_positive_number,
    _optional_resource_filters,
    _optional_retry,
    _optional_string,
    _optional_string_set,
    _page_request,
    _positive_integer,
    _require_fields,
    _signing,
    _string,
    _string_set,
)
from phoenix_os.policy import PrincipalType, SecurityContext
from phoenix_os.secrets import SecretRef
from phoenix_os.webhooks.errors import (
    PhoenixWebhookError,
    WebhookDeliveryCapacityError,
    WebhookDeliveryConflictError,
    WebhookDeliveryNotFoundError,
    WebhookDeliveryRepositoryClosedError,
    WebhookManagerAccessDeniedError,
    WebhookManagerClosedError,
    WebhookPersistenceError,
    WebhookRecoveryClosedError,
    WebhookRedriveAccessDeniedError,
    WebhookRedriveNotEligibleError,
    WebhookSubscriptionAlreadyExistsError,
    WebhookSubscriptionCapacityError,
    WebhookSubscriptionConflictError,
    WebhookSubscriptionNotFoundError,
    WebhookSubscriptionRepositoryClosedError,
)
from phoenix_os.webhooks.manager import (
    WEBHOOK_DELIVERIES_READ_PERMISSION,
    WEBHOOK_HEALTH_READ_PERMISSION,
    WEBHOOK_REDRIVE_PERMISSION,
    WEBHOOK_SUBSCRIPTIONS_CREATE_PERMISSION,
    WEBHOOK_SUBSCRIPTIONS_DISABLE_PERMISSION,
    WEBHOOK_SUBSCRIPTIONS_ENABLE_PERMISSION,
    WEBHOOK_SUBSCRIPTIONS_READ_PERMISSION,
    WEBHOOK_SUBSCRIPTIONS_REVOKE_PERMISSION,
    WEBHOOK_SUBSCRIPTIONS_ROTATE_PERMISSION,
    WEBHOOK_SUBSCRIPTIONS_UPDATE_PERMISSION,
    WebhookManager,
    webhook_delivery_view_page_to_dict,
    webhook_manager_snapshot_to_dict,
    webhook_redrive_result_to_dict,
    webhook_subscription_view_page_to_dict,
    webhook_subscription_view_to_dict,
)

CONTROL_PLANE_WEBHOOK_MACHINE_RESOURCE = "webhooks"
CONTROL_PLANE_WEBHOOK_MACHINE_BASE_PATH = "/v1/control-plane/machine/webhooks"

_HEALTH = f"{CONTROL_PLANE_WEBHOOK_MACHINE_BASE_PATH}/health"
_SUBSCRIPTIONS = f"{CONTROL_PLANE_WEBHOOK_MACHINE_BASE_PATH}/subscriptions"
_CREATE = f"{_SUBSCRIPTIONS}/create"
_UPDATE = f"{_SUBSCRIPTIONS}/update"
_DISABLE = f"{_SUBSCRIPTIONS}/disable"
_ENABLE = f"{_SUBSCRIPTIONS}/enable"
_REVOKE = f"{_SUBSCRIPTIONS}/revoke"
_ROTATE = f"{_SUBSCRIPTIONS}/rotate-signing-key"
_DELIVERIES = f"{CONTROL_PLANE_WEBHOOK_MACHINE_BASE_PATH}/deliveries"
_REDRIVE = f"{_DELIVERIES}/redrive"
_NO_STORE = {"Cache-Control": "no-store"}

_ROUTE_SPECS = (
    ("GET", _HEALTH, WEBHOOK_HEALTH_READ_PERMISSION),
    ("GET", _SUBSCRIPTIONS, WEBHOOK_SUBSCRIPTIONS_READ_PERMISSION),
    ("POST", _CREATE, WEBHOOK_SUBSCRIPTIONS_CREATE_PERMISSION),
    ("POST", _UPDATE, WEBHOOK_SUBSCRIPTIONS_UPDATE_PERMISSION),
    ("POST", _DISABLE, WEBHOOK_SUBSCRIPTIONS_DISABLE_PERMISSION),
    ("POST", _ENABLE, WEBHOOK_SUBSCRIPTIONS_ENABLE_PERMISSION),
    ("POST", _REVOKE, WEBHOOK_SUBSCRIPTIONS_REVOKE_PERMISSION),
    ("POST", _ROTATE, WEBHOOK_SUBSCRIPTIONS_ROTATE_PERMISSION),
    ("GET", _DELIVERIES, WEBHOOK_DELIVERIES_READ_PERMISSION),
    ("POST", _REDRIVE, WEBHOOK_REDRIVE_PERMISSION),
)


class ControlPlaneWebhookMachineAdministration:
    """Expose exact-scope webhook management through machine-only routes."""

    def __init__(
        self,
        manager: WebhookManager,
        *,
        exact_authorizer: ControlPlaneServiceAccountAuthorizer | None = None,
    ) -> None:
        if not isinstance(manager, WebhookManager):
            raise TypeError("webhook machine administration requires a WebhookManager")
        authorizer = (
            ControlPlaneServiceAccountAuthorizer() if exact_authorizer is None else exact_authorizer
        )
        if not isinstance(authorizer, ControlPlaneServiceAccountAuthorizer):
            raise TypeError("webhook machine exact authorizer has an invalid type")
        self._manager = manager
        self._exact_authorizer = authorizer
        self._actions = {(method, path): action for method, path, action in _ROUTE_SPECS}
        self._routes = tuple(
            ControlPlaneServiceAccountMachineRoute(
                method=method,
                path=path,
                action=action,
                resource=CONTROL_PLANE_WEBHOOK_MACHINE_RESOURCE,
                handler=self._handle,
            )
            for method, path, action in _ROUTE_SPECS
        )

    @property
    def manager(self) -> WebhookManager:
        return self._manager

    @property
    def routes(self) -> tuple[ControlPlaneServiceAccountMachineRoute, ...]:
        return self._routes

    async def _handle(
        self,
        context: ControlPlaneServiceAccountApiContext,
        request: ControlPlaneServiceAccountMachineRequest,
    ) -> ControlPlaneServiceAccountMachineResponse:
        try:
            action = self._actions[(request.method, request.path)]
            self._exact_authorizer.require(
                context.authentication,
                action=action,
                resource=CONTROL_PLANE_WEBHOOK_MACHINE_RESOURCE,
            )
            manager_context = _manager_context(context, action)

            if request.path == _HEALTH:
                _require_get(request, allow_query=False)
                snapshot = await self._manager.snapshot(manager_context)
                return (
                    HTTPStatus.OK,
                    webhook_manager_snapshot_to_dict(snapshot),
                    dict(_NO_STORE),
                )

            if request.path == _SUBSCRIPTIONS:
                _require_get(request, allow_query=True)
                subscription_page = await self._manager.list_subscriptions(
                    manager_context,
                    _page_request(request.query),
                )
                return (
                    HTTPStatus.OK,
                    webhook_subscription_view_page_to_dict(subscription_page),
                    dict(_NO_STORE),
                )

            if request.path == _DELIVERIES:
                _require_get(request, allow_query=True)
                delivery_page = await self._manager.list_deliveries(
                    manager_context,
                    _page_request(request.query),
                )
                return (
                    HTTPStatus.OK,
                    webhook_delivery_view_page_to_dict(delivery_page),
                    dict(_NO_STORE),
                )

            document = _post_document(request)

            if request.path == _CREATE:
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
                view = await self._manager.create_subscription(
                    manager_context,
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

            if request.path == _UPDATE:
                _require_fields(
                    document,
                    required={"subscription_id", "expected_revision"},
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
                view = await self._manager.update_subscription(
                    _uuid(document, "subscription_id"),
                    manager_context,
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

            if request.path in {_DISABLE, _ENABLE, _REVOKE}:
                _require_fields(
                    document,
                    required={"subscription_id", "expected_revision"},
                )
                subscription_id = _uuid(document, "subscription_id")
                expected_revision = _positive_integer(
                    document,
                    "expected_revision",
                )
                if request.path == _DISABLE:
                    view = await self._manager.disable_subscription(
                        subscription_id,
                        manager_context,
                        expected_revision=expected_revision,
                    )
                elif request.path == _ENABLE:
                    view = await self._manager.enable_subscription(
                        subscription_id,
                        manager_context,
                        expected_revision=expected_revision,
                    )
                else:
                    view = await self._manager.revoke_subscription(
                        subscription_id,
                        manager_context,
                        expected_revision=expected_revision,
                    )
                return (
                    HTTPStatus.OK,
                    webhook_subscription_view_to_dict(view),
                    dict(_NO_STORE),
                )

            if request.path == _ROTATE:
                _require_fields(
                    document,
                    required={
                        "subscription_id",
                        "expected_revision",
                        "secret_name",
                        "secret_namespace",
                        "secret_version",
                    },
                    optional={"lease_ttl_seconds"},
                )
                lease_seconds = _optional_positive_number(
                    document,
                    "lease_ttl_seconds",
                )
                view = await self._manager.rotate_signing_key(
                    _uuid(document, "subscription_id"),
                    manager_context,
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

            if request.path == _REDRIVE:
                _require_fields(
                    document,
                    required={"delivery_id"},
                    optional={"scheduled_at"},
                )
                result = await self._manager.redrive_delivery(
                    _uuid(document, "delivery_id"),
                    manager_context,
                    scheduled_at=_optional_aware_datetime(
                        document,
                        "scheduled_at",
                    ),
                )
                return (
                    HTTPStatus.ACCEPTED,
                    webhook_redrive_result_to_dict(result),
                    dict(_NO_STORE),
                )

            raise ValueError("unknown webhook machine route")

        except (
            ControlPlaneServiceAccountPermissionDeniedError,
            WebhookManagerAccessDeniedError,
            WebhookRedriveAccessDeniedError,
        ):
            return (
                HTTPStatus.FORBIDDEN,
                {"error": "forbidden"},
                dict(_NO_STORE),
            )
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
            return (
                HTTPStatus.CONFLICT,
                {"error": "webhook_conflict"},
                dict(_NO_STORE),
            )
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
            PhoenixWebhookError,
            RuntimeError,
        ):
            return (
                HTTPStatus.SERVICE_UNAVAILABLE,
                {"error": "webhooks_unavailable"},
                dict(_NO_STORE),
            )


def control_plane_webhook_machine_routes(
    manager: WebhookManager,
    *,
    exact_authorizer: ControlPlaneServiceAccountAuthorizer | None = None,
) -> tuple[ControlPlaneServiceAccountMachineRoute, ...]:
    """Build the concrete machine-only webhook route set."""

    return ControlPlaneWebhookMachineAdministration(
        manager,
        exact_authorizer=exact_authorizer,
    ).routes


def _manager_context(
    context: ControlPlaneServiceAccountApiContext,
    permission: str,
) -> SecurityContext:
    security = context.security_context
    return SecurityContext(
        principal=context.principal_name,
        principal_type=PrincipalType.SERVICE,
        authenticated=True,
        roles=frozenset(),
        permissions=frozenset({permission}),
        scopes=context.scopes,
        attributes=dict(security.attributes),
        correlation_id=context.correlation_id,
        causation_id=context.request_id,
        confirmed=False,
    )


def _require_get(
    request: ControlPlaneServiceAccountMachineRequest,
    *,
    allow_query: bool,
) -> None:
    if request.body:
        raise ValueError("webhook machine GET requests must not contain a body")
    if not allow_query and request.query:
        raise ValueError("webhook machine route does not accept query fields")


def _post_document(
    request: ControlPlaneServiceAccountMachineRequest,
) -> Mapping[str, object]:
    if request.query:
        raise ValueError("webhook machine mutation does not accept query fields")
    values = request.headers.get("content-type", ())
    if len(values) != 1:
        raise ValueError("webhook machine content type is required")
    media_type = values[0].split(";", 1)[0].strip().lower()
    if media_type != "application/json":
        raise ValueError("webhook machine body must be JSON")
    if not request.body:
        raise ValueError("webhook machine body is required")
    document = json.loads(request.body.decode("utf-8"))
    if not isinstance(document, dict):
        raise TypeError("webhook machine body must be an object")
    return document


def _uuid(
    document: Mapping[str, object],
    name: str,
) -> UUID:
    return UUID(_string(document, name))
