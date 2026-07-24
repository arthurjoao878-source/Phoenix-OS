from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from http import HTTPStatus
from typing import ClassVar
from uuid import UUID

import pytest

from phoenix_os.control_plane import (
    AdminTokenAuthenticator,
    ControlPlaneBrowserOrigin,
    ControlPlaneDurableSessionAuthentication,
    ControlPlaneDurableSessionCsrfRejectedError,
    ControlPlaneHttpServer,
    ControlPlanePrincipal,
    ControlPlaneStepUpRejectedError,
    ControlPlaneWebhookHttpAdapter,
)
from phoenix_os.control_plane.operator_contracts import ControlPlaneOperatorRole
from phoenix_os.control_plane.step_up import ControlPlaneStepUpAction
from phoenix_os.secrets import SecretRef
from phoenix_os.webhooks import (
    InMemoryWebhookDeliveryRepository,
    InMemoryWebhookSubscriptionRepository,
    WebhookAttempt,
    WebhookAttemptOutcome,
    WebhookDelivery,
    WebhookDeliveryRecovery,
    WebhookDeliveryStatus,
    WebhookEndpoint,
    WebhookManager,
    WebhookRetryPolicy,
    WebhookSigningPolicy,
    WebhookSubscription,
)

_NOW = datetime(2026, 7, 24, 12, 0, tzinfo=UTC)
_LATER = _NOW + timedelta(minutes=3)
_ORIGIN = ControlPlaneBrowserOrigin("http://127.0.0.1:9443")
_SUBSCRIPTION_ID = UUID("00000000-0000-4000-8000-000000001101")
_DELIVERY_ID = UUID("00000000-0000-4000-8000-000000002101")
_EVENT_ID = UUID("00000000-0000-4000-8000-000000003101")
_SESSION_ID = UUID("00000000-0000-4000-8000-000000004101")
_OPERATOR_ID = UUID("00000000-0000-4000-8000-000000005101")


class _Boundary:
    def __init__(self, *, reject: bool = False) -> None:
        self.reject = reject
        self.calls = 0

    async def verify_csrf(
        self,
        token_value: str | None,
        authentication: ControlPlaneDurableSessionAuthentication,
        *,
        supplied_origin: ControlPlaneBrowserOrigin,
        expected_origin: ControlPlaneBrowserOrigin,
    ) -> object:
        self.calls += 1
        if self.reject:
            raise ControlPlaneDurableSessionCsrfRejectedError("CSRF rejected")
        assert token_value == "csrf-value"
        assert authentication.session_id == _SESSION_ID
        assert supplied_origin == _ORIGIN
        assert expected_origin == _ORIGIN
        return object()


class _StepUp:
    calls: ClassVar[
        list[
            tuple[
                str | None,
                ControlPlaneDurableSessionAuthentication,
                ControlPlaneStepUpAction,
            ]
        ]
    ] = []

    def __init__(self, *, reject: bool = False) -> None:
        type(self).calls = []
        self.reject = reject

    async def verify(
        self,
        token_value: str | None,
        session: ControlPlaneDurableSessionAuthentication,
        action: ControlPlaneStepUpAction,
    ) -> object:
        type(self).calls.append((token_value, session, action))
        if self.reject:
            raise ControlPlaneStepUpRejectedError("step-up rejected")
        assert token_value == "step-up-value"
        return object()


def _last_step_up_action() -> ControlPlaneStepUpAction:
    return _StepUp.calls[-1][2]


def _principal(*, maintainer: bool = True) -> ControlPlanePrincipal:
    role = ControlPlaneOperatorRole.MAINTAINER if maintainer else ControlPlaneOperatorRole.OPERATOR
    return ControlPlanePrincipal(
        "maintainer" if maintainer else "operator",
        role.permissions,
    )


def _authentication(
    *,
    maintainer: bool = True,
) -> ControlPlaneDurableSessionAuthentication:
    return ControlPlaneDurableSessionAuthentication(
        session_id=_SESSION_ID,
        operator_id=_OPERATOR_ID,
        principal=_principal(maintainer=maintainer),
        generation=1,
        authenticated_at=_NOW,
        absolute_expires_at=_NOW + timedelta(hours=2),
        idle_expires_at=_NOW + timedelta(minutes=30),
    )


def _subscription() -> WebhookSubscription:
    return WebhookSubscription(
        id=_SUBSCRIPTION_ID,
        name="release.notifications",
        display_name="Release Notifications",
        event_types=frozenset({"jobs.completed"}),
        endpoint=WebhookEndpoint("https://hooks.example.com/private-path-token"),
        signing=WebhookSigningPolicy(
            SecretRef("must-not-leak", "integrations", 1),
        ),
        egress_policy="production.webhooks",
        created_at=_NOW,
        updated_at=_NOW,
        created_by="maintainer:test",
        retry=WebhookRetryPolicy(
            max_attempts=3,
            initial_delay=timedelta(seconds=5),
            max_delay=timedelta(minutes=1),
        ),
    )


def _dead_letter(subscription: WebhookSubscription) -> WebhookDelivery:
    body = b'{"payload":{"job_id":"job-1","token":"must-not-leak"}}'
    started = _NOW + timedelta(minutes=1)
    finished = _NOW + timedelta(minutes=2)
    attempt = WebhookAttempt(
        delivery_id=_DELIVERY_ID,
        number=1,
        scheduled_at=started,
        started_at=started,
        finished_at=finished,
        outcome=WebhookAttemptOutcome.RETRYABLE_FAILURE,
        retry_scheduled=False,
        error_category="timeout",
    )
    return WebhookDelivery(
        id=_DELIVERY_ID,
        subscription_id=subscription.id,
        event_type="jobs.completed",
        deduplication_key=hashlib.sha256(b"deduplication-http").hexdigest(),
        canonical_body=body,
        body_sha256=hashlib.sha256(body).hexdigest(),
        occurred_at=_NOW,
        created_at=_NOW,
        updated_at=finished,
        status=WebhookDeliveryStatus.DEAD_LETTER,
        source_event_id=_EVENT_ID,
        attempts=(attempt,),
        terminal_at=finished,
    )


async def _system(
    *,
    subscription: WebhookSubscription | None = None,
    delivery: WebhookDelivery | None = None,
    maintainer: bool = True,
    reject_csrf: bool = False,
    reject_step_up: bool = False,
) -> tuple[
    ControlPlaneWebhookHttpAdapter,
    _Boundary,
    _StepUp,
    ControlPlaneDurableSessionAuthentication,
]:
    subscriptions = InMemoryWebhookSubscriptionRepository()
    deliveries = InMemoryWebhookDeliveryRepository()
    if subscription is not None:
        await subscriptions.add(subscription)
    if delivery is not None:
        await deliveries.add(delivery)
    recovery = WebhookDeliveryRecovery(
        subscriptions=subscriptions,
        deliveries=deliveries,
        clock=lambda: _LATER,
    )
    manager = WebhookManager(
        subscriptions=subscriptions,
        deliveries=deliveries,
        recovery=recovery,
        clock=lambda: _LATER,
        subscription_id_factory=lambda: _SUBSCRIPTION_ID,
    )
    boundary = _Boundary(reject=reject_csrf)
    step_up = _StepUp(reject=reject_step_up)
    adapter = ControlPlaneWebhookHttpAdapter(
        manager=manager,
        boundary=boundary,
        step_up=step_up,
    )
    return adapter, boundary, step_up, _authentication(maintainer=maintainer)


def _headers(
    *,
    origin: str = "http://127.0.0.1:9443",
    step_up: bool = True,
) -> dict[str, tuple[str, ...]]:
    result: dict[str, tuple[str, ...]] = {
        "origin": (origin,),
        "x-phoenix-csrf": ("csrf-value",),
    }
    if step_up:
        result["x-phoenix-step-up"] = ("step-up-value",)
    return result


def _body(value: Mapping[str, object]) -> bytes:
    return json.dumps(dict(value)).encode("utf-8")


def _object_mapping(value: object) -> Mapping[str, object]:
    if not isinstance(value, dict):
        raise TypeError("expected an object mapping")
    return value


def _create_document() -> dict[str, object]:
    return {
        "name": "release.notifications",
        "display_name": "Release Notifications",
        "event_types": ["jobs.completed"],
        "endpoint": {
            "url": "https://hooks.example.com/private-path-token",
        },
        "signing": {
            "secret_name": "must-not-leak",
            "secret_namespace": "integrations",
            "secret_version": 1,
        },
        "egress_policy": "production.webhooks",
        "retry": {
            "max_attempts": 3,
            "initial_delay_seconds": 5,
            "max_delay_seconds": 60,
            "jitter_ratio": 0.1,
        },
    }


def test_adapter_handles_only_webhook_routes() -> None:
    assert ControlPlaneWebhookHttpAdapter.handles("/v1/control-plane/webhooks/subscriptions")
    assert ControlPlaneWebhookHttpAdapter.handles(
        f"/v1/control-plane/webhooks/deliveries/{_DELIVERY_ID}"
    )
    assert not ControlPlaneWebhookHttpAdapter.handles("/v1/control-plane/service-accounts")


def test_server_requires_durable_session_for_webhook_adapter() -> None:
    subscriptions = InMemoryWebhookSubscriptionRepository()
    deliveries = InMemoryWebhookDeliveryRepository()
    recovery = WebhookDeliveryRecovery(
        subscriptions=subscriptions,
        deliveries=deliveries,
        clock=lambda: _LATER,
    )
    adapter = ControlPlaneWebhookHttpAdapter(
        manager=WebhookManager(
            subscriptions=subscriptions,
            deliveries=deliveries,
            recovery=recovery,
            clock=lambda: _LATER,
        ),
        boundary=_Boundary(),
        step_up=_StepUp(),
    )

    with pytest.raises(ValueError, match="durable session"):
        ControlPlaneHttpServer(
            object(),  # type: ignore[arg-type]
            AdminTokenAuthenticator("A" * 32),
            webhook_http=adapter,
        )


@pytest.mark.asyncio
async def test_create_and_list_subscription_are_protected_and_redacted() -> None:
    adapter, boundary, _, authentication = await _system()

    status, payload, headers = await adapter.dispatch(
        authentication=authentication,
        method="POST",
        path="/v1/control-plane/webhooks/subscriptions",
        query={},
        headers=_headers(),
        body=_body(_create_document()),
        server_origin=_ORIGIN,
    )

    assert status is HTTPStatus.CREATED
    assert headers == {"Cache-Control": "no-store"}
    assert boundary.calls == 1
    assert _last_step_up_action() is ControlPlaneStepUpAction.CREATE_WEBHOOK_SUBSCRIPTION
    rendered = repr(payload)
    assert payload["id"] == str(_SUBSCRIPTION_ID)
    signing = _object_mapping(payload["signing"])
    assert signing["key_version"] == 1
    assert "private-path-token" not in rendered
    assert "must-not-leak" not in rendered
    assert "integrations" not in rendered

    status, page, headers = await adapter.dispatch(
        authentication=authentication,
        method="GET",
        path="/v1/control-plane/webhooks/subscriptions",
        query={},
        headers={},
        body=b"",
        server_origin=_ORIGIN,
    )

    assert status is HTTPStatus.OK
    assert headers == {"Cache-Control": "no-store"}
    page_info = _object_mapping(page["page"])
    assert page_info["total"] == 1


@pytest.mark.asyncio
async def test_get_update_disable_enable_rotate_and_revoke_subscription() -> None:
    adapter, _, _, authentication = await _system(subscription=_subscription())
    base = f"/v1/control-plane/webhooks/subscriptions/{_SUBSCRIPTION_ID}"

    status, payload, _ = await adapter.dispatch(
        authentication=authentication,
        method="GET",
        path=base,
        query={},
        headers={},
        body=b"",
        server_origin=_ORIGIN,
    )
    assert status is HTTPStatus.OK
    assert payload["revision"] == 1

    status, payload, _ = await adapter.dispatch(
        authentication=authentication,
        method="POST",
        path=f"{base}/update",
        query={},
        headers=_headers(),
        body=_body(
            {
                "expected_revision": 1,
                "display_name": "Updated",
            }
        ),
        server_origin=_ORIGIN,
    )
    assert status is HTTPStatus.OK
    assert payload["display_name"] == "Updated"
    assert payload["revision"] == 2
    assert _last_step_up_action() is ControlPlaneStepUpAction.UPDATE_WEBHOOK_SUBSCRIPTION

    status, payload, _ = await adapter.dispatch(
        authentication=authentication,
        method="POST",
        path=f"{base}/disable",
        query={},
        headers=_headers(step_up=False),
        body=_body({"expected_revision": 2}),
        server_origin=_ORIGIN,
    )
    assert status is HTTPStatus.OK
    assert payload["status"] == "disabled"

    status, payload, _ = await adapter.dispatch(
        authentication=authentication,
        method="POST",
        path=f"{base}/enable",
        query={},
        headers=_headers(),
        body=_body({"expected_revision": 3}),
        server_origin=_ORIGIN,
    )
    assert status is HTTPStatus.OK
    assert payload["status"] == "active"
    assert _last_step_up_action() is ControlPlaneStepUpAction.ENABLE_WEBHOOK_SUBSCRIPTION

    status, payload, _ = await adapter.dispatch(
        authentication=authentication,
        method="POST",
        path=f"{base}/rotate-signing-key",
        query={},
        headers=_headers(),
        body=_body(
            {
                "expected_revision": 4,
                "secret_name": "rotated-secret",
                "secret_namespace": "integrations",
                "secret_version": 2,
                "lease_ttl_seconds": 20,
            }
        ),
        server_origin=_ORIGIN,
    )
    assert status is HTTPStatus.OK
    signing = _object_mapping(payload["signing"])
    assert signing["key_version"] == 2
    assert _last_step_up_action() is ControlPlaneStepUpAction.ROTATE_WEBHOOK_SIGNING_KEY
    assert "rotated-secret" not in repr(payload)

    status, payload, _ = await adapter.dispatch(
        authentication=authentication,
        method="POST",
        path=f"{base}/revoke",
        query={},
        headers=_headers(),
        body=_body({"expected_revision": 5}),
        server_origin=_ORIGIN,
    )
    assert status is HTTPStatus.OK
    assert payload["status"] == "revoked"
    assert _last_step_up_action() is ControlPlaneStepUpAction.REVOKE_WEBHOOK_SUBSCRIPTION


@pytest.mark.asyncio
async def test_delivery_list_detail_and_redrive_never_return_body() -> None:
    subscription = _subscription()
    delivery = _dead_letter(subscription)
    adapter, _, _, authentication = await _system(
        subscription=subscription,
        delivery=delivery,
    )
    detail = f"/v1/control-plane/webhooks/deliveries/{delivery.id}"

    status, payload, _ = await adapter.dispatch(
        authentication=authentication,
        method="GET",
        path=detail,
        query={},
        headers={},
        body=b"",
        server_origin=_ORIGIN,
    )
    assert status is HTTPStatus.OK
    rendered = repr(payload)
    assert payload["status"] == "dead_letter"
    assert payload["redrive_eligible"] is True
    assert "must-not-leak" not in rendered
    assert delivery.body_sha256 not in rendered

    status, page, _ = await adapter.dispatch(
        authentication=authentication,
        method="GET",
        path="/v1/control-plane/webhooks/deliveries",
        query={"limit": ("10",)},
        headers={},
        body=b"",
        server_origin=_ORIGIN,
    )
    assert status is HTTPStatus.OK
    page_info = _object_mapping(page["page"])
    assert page_info["total"] == 1

    status, result, _ = await adapter.dispatch(
        authentication=authentication,
        method="POST",
        path=f"{detail}/redrive",
        query={},
        headers=_headers(),
        body=_body({}),
        server_origin=_ORIGIN,
    )
    assert status is HTTPStatus.ACCEPTED
    assert result["status"] == "retrying"
    assert _last_step_up_action() is ControlPlaneStepUpAction.REDRIVE_WEBHOOK_DELIVERY


@pytest.mark.asyncio
async def test_health_snapshot_requires_maintainer_permission() -> None:
    adapter, _, _, authentication = await _system(maintainer=False)

    status, payload, headers = await adapter.dispatch(
        authentication=authentication,
        method="GET",
        path="/v1/control-plane/webhooks/health",
        query={},
        headers={},
        body=b"",
        server_origin=_ORIGIN,
    )

    assert status is HTTPStatus.FORBIDDEN
    assert payload == {"error": "forbidden"}
    assert headers == {"Cache-Control": "no-store"}


@pytest.mark.asyncio
async def test_operator_cannot_create_subscription() -> None:
    adapter, _, _, authentication = await _system(maintainer=False)

    status, payload, _ = await adapter.dispatch(
        authentication=authentication,
        method="POST",
        path="/v1/control-plane/webhooks/subscriptions",
        query={},
        headers=_headers(),
        body=_body(_create_document()),
        server_origin=_ORIGIN,
    )

    assert status is HTTPStatus.FORBIDDEN
    assert payload == {"error": "forbidden"}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("reject_csrf", "reject_step_up"),
    (
        (True, False),
        (False, True),
    ),
)
async def test_csrf_and_step_up_fail_closed(
    reject_csrf: bool,
    reject_step_up: bool,
) -> None:
    adapter, _, _, authentication = await _system(
        reject_csrf=reject_csrf,
        reject_step_up=reject_step_up,
    )

    status, payload, _ = await adapter.dispatch(
        authentication=authentication,
        method="POST",
        path="/v1/control-plane/webhooks/subscriptions",
        query={},
        headers=_headers(),
        body=_body(_create_document()),
        server_origin=_ORIGIN,
    )

    assert status is HTTPStatus.FORBIDDEN
    assert payload == {"error": "request_rejected"}


@pytest.mark.asyncio
async def test_origin_mismatch_fails_closed() -> None:
    adapter, _, _, authentication = await _system()

    status, payload, _ = await adapter.dispatch(
        authentication=authentication,
        method="POST",
        path="/v1/control-plane/webhooks/subscriptions",
        query={},
        headers=_headers(origin="http://127.0.0.1:9555"),
        body=_body(_create_document()),
        server_origin=_ORIGIN,
    )

    assert status is HTTPStatus.FORBIDDEN
    assert payload == {"error": "request_rejected"}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "document",
    (
        {},
        {"name": "missing-fields"},
        {
            **_create_document(),
            "unsupported": True,
        },
        {
            **_create_document(),
            "event_types": "jobs.completed",
        },
        {
            **_create_document(),
            "endpoint": {
                "url": "http://example.com/unsafe",
            },
        },
    ),
)
async def test_invalid_create_documents_are_rejected(
    document: Mapping[str, object],
) -> None:
    adapter, _, _, authentication = await _system()

    status, payload, _ = await adapter.dispatch(
        authentication=authentication,
        method="POST",
        path="/v1/control-plane/webhooks/subscriptions",
        query={},
        headers=_headers(),
        body=_body(document),
        server_origin=_ORIGIN,
    )

    assert status is HTTPStatus.BAD_REQUEST
    assert payload == {"error": "invalid_webhook_request"}


@pytest.mark.asyncio
async def test_stale_revision_is_conflict() -> None:
    adapter, _, _, authentication = await _system(subscription=_subscription())

    status, payload, _ = await adapter.dispatch(
        authentication=authentication,
        method="POST",
        path=f"/v1/control-plane/webhooks/subscriptions/{_SUBSCRIPTION_ID}/disable",
        query={},
        headers=_headers(step_up=False),
        body=_body({"expected_revision": 2}),
        server_origin=_ORIGIN,
    )

    assert status is HTTPStatus.CONFLICT
    assert payload == {"error": "webhook_conflict"}


@pytest.mark.asyncio
async def test_unknown_routes_and_methods_are_bounded() -> None:
    adapter, _, _, authentication = await _system()

    status, payload, _ = await adapter.dispatch(
        authentication=authentication,
        method="GET",
        path="/v1/control-plane/webhooks/unknown",
        query={},
        headers={},
        body=b"",
        server_origin=_ORIGIN,
    )
    assert status is HTTPStatus.NOT_FOUND
    assert payload == {"error": "not_found"}

    status, payload, headers = await adapter.dispatch(
        authentication=authentication,
        method="DELETE",
        path="/v1/control-plane/webhooks/subscriptions",
        query={},
        headers={},
        body=b"",
        server_origin=_ORIGIN,
    )
    assert status is HTTPStatus.METHOD_NOT_ALLOWED
    assert payload == {"error": "method_not_allowed"}
    assert headers["Allow"] == "GET, POST"
