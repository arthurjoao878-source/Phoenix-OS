from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from http import HTTPStatus
from pathlib import Path
from uuid import UUID

import pytest

from phoenix_os.control_plane import (
    CONTROL_PLANE_WEBHOOK_MACHINE_BASE_PATH,
    CONTROL_PLANE_WEBHOOK_MACHINE_RESOURCE,
    ControlPlaneWebhookMachineAdministration,
    control_plane_webhook_machine_routes,
)
from phoenix_os.control_plane import (
    service_account_authentication as service_account_authentication_module,
)
from phoenix_os.control_plane.network_contracts import (
    ControlPlaneClientIdentitySource,
)
from phoenix_os.control_plane.service_account_audit import (
    ControlPlaneServiceAccountAudit,
    ControlPlaneServiceAccountAuditProtector,
)
from phoenix_os.control_plane.service_account_authentication import (
    ControlPlaneServiceAccountAuthentication,
    ControlPlaneServiceAccountAuthenticationContext,
)
from phoenix_os.control_plane.service_account_authorization import (
    ControlPlaneServiceAccountPermissionDeniedError,
)
from phoenix_os.control_plane.service_account_machine_http import (
    ControlPlaneServiceAccountMachineHttpAdapter,
)
from phoenix_os.control_plane.service_account_policy import (
    ControlPlaneServiceAccountApiContext,
)
from phoenix_os.control_plane.service_account_replay import (
    ControlPlaneServiceAccountReplayRequest,
)
from phoenix_os.secrets import SecretRef
from phoenix_os.webhooks import (
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
    InMemoryWebhookDeliveryRepository,
    InMemoryWebhookSubscriptionRepository,
    WebhookAttempt,
    WebhookAttemptOutcome,
    WebhookDelivery,
    WebhookDeliveryRecovery,
    WebhookDeliveryStatus,
    WebhookEndpoint,
    WebhookManager,
    WebhookSigningPolicy,
    WebhookSubscription,
    WebhookSubscriptionStatus,
)

_NOW = datetime(2026, 7, 24, 16, 0, tzinfo=UTC)
_LATER = _NOW + timedelta(minutes=5)
_ACCOUNT_ID = UUID("10000000-0000-4000-8000-000000000071")
_TOKEN_ID = UUID("20000000-0000-4000-8000-000000000071")
_SUBSCRIPTION_ID = UUID("30000000-0000-4000-8000-000000000071")
_DELIVERY_ID = UUID("40000000-0000-4000-8000-000000000071")
_EVENT_ID = UUID("50000000-0000-4000-8000-000000000071")
_RFC = (
    Path(__file__).resolve().parents[1]
    / "docs"
    / "rfcs"
    / "RFC-0024-durable-signed-webhooks-and-event-subscriptions.md"
)

_ALL_SCOPES = frozenset(
    {
        WEBHOOK_SUBSCRIPTIONS_READ_PERMISSION,
        WEBHOOK_SUBSCRIPTIONS_CREATE_PERMISSION,
        WEBHOOK_SUBSCRIPTIONS_UPDATE_PERMISSION,
        WEBHOOK_SUBSCRIPTIONS_DISABLE_PERMISSION,
        WEBHOOK_SUBSCRIPTIONS_ENABLE_PERMISSION,
        WEBHOOK_SUBSCRIPTIONS_REVOKE_PERMISSION,
        WEBHOOK_SUBSCRIPTIONS_ROTATE_PERMISSION,
        WEBHOOK_DELIVERIES_READ_PERMISSION,
        WEBHOOK_REDRIVE_PERMISSION,
        WEBHOOK_HEALTH_READ_PERMISSION,
    }
)


class _Authentication:
    def __init__(
        self,
        evidence: ControlPlaneServiceAccountAuthentication | None,
    ) -> None:
        self.evidence = evidence
        self.calls = 0

    async def authenticate(
        self,
        authorization: str | None,
        *,
        context: ControlPlaneServiceAccountAuthenticationContext,
        request: ControlPlaneServiceAccountReplayRequest,
    ) -> ControlPlaneServiceAccountAuthentication | None:
        del authorization, context, request
        self.calls += 1
        return self.evidence


class _Policy:
    def __init__(self, *, denied: bool = False) -> None:
        self.denied = denied
        self.calls: list[tuple[str, str]] = []

    async def enforce(
        self,
        context: ControlPlaneServiceAccountApiContext,
        *,
        action: str,
        resource: str,
    ) -> object:
        del context
        self.calls.append((action, resource))
        if self.denied:
            raise ControlPlaneServiceAccountPermissionDeniedError(
                "service-account authorization denied"
            )
        return object()


def _evidence(
    *,
    scopes: frozenset[str] = _ALL_SCOPES,
    resources: frozenset[str] = frozenset({CONTROL_PLANE_WEBHOOK_MACHINE_RESOURCE}),
) -> ControlPlaneServiceAccountAuthentication:
    return ControlPlaneServiceAccountAuthentication(
        service_account_id=_ACCOUNT_ID,
        token_id=_TOKEN_ID,
        account_name="webhook.bot",
        scopes=scopes,
        resources=resources,
        token_version=1,
        account_revision=1,
        token_revision=1,
        authenticated_at=_NOW,
        expires_at=_NOW + timedelta(hours=1),
    )


def _transport_context() -> ControlPlaneServiceAccountAuthenticationContext:
    return ControlPlaneServiceAccountAuthenticationContext(
        client_address="127.0.0.1",
        peer_address="127.0.0.1",
        identity_source=ControlPlaneClientIdentitySource.DIRECT,
        _authority=service_account_authentication_module._CONTEXT_AUTHORITY,
    )


def _subscription(
    *,
    status: WebhookSubscriptionStatus = WebhookSubscriptionStatus.ACTIVE,
    revision: int = 1,
    signing_version: int = 1,
) -> WebhookSubscription:
    disabled_at = _NOW if status is WebhookSubscriptionStatus.DISABLED else None
    revoked_at = _NOW if status is WebhookSubscriptionStatus.REVOKED else None
    return WebhookSubscription(
        id=_SUBSCRIPTION_ID,
        name="release.notifications",
        display_name="Release Notifications",
        event_types=frozenset({"jobs.completed"}),
        endpoint=WebhookEndpoint("https://hooks.example.com/private-path-token"),
        signing=WebhookSigningPolicy(SecretRef("must-not-leak", "integrations", signing_version)),
        egress_policy="production.webhooks",
        created_at=_NOW,
        updated_at=_NOW,
        created_by="maintainer:test",
        status=status,
        disabled_at=disabled_at,
        revoked_at=revoked_at,
        revision=revision,
    )


def _dead_letter(
    subscription: WebhookSubscription,
) -> WebhookDelivery:
    body = b'{"token":"must-not-leak"}'
    attempt = WebhookAttempt(
        delivery_id=_DELIVERY_ID,
        number=1,
        scheduled_at=_NOW,
        started_at=_NOW,
        finished_at=_NOW + timedelta(seconds=1),
        outcome=WebhookAttemptOutcome.RETRYABLE_FAILURE,
        retry_scheduled=False,
        error_category="timeout",
    )
    return WebhookDelivery(
        id=_DELIVERY_ID,
        subscription_id=subscription.id,
        event_type="jobs.completed",
        deduplication_key=hashlib.sha256(b"dedupe").hexdigest(),
        canonical_body=body,
        body_sha256=hashlib.sha256(body).hexdigest(),
        occurred_at=_NOW,
        created_at=_NOW,
        updated_at=_NOW + timedelta(seconds=1),
        status=WebhookDeliveryStatus.DEAD_LETTER,
        source_event_id=_EVENT_ID,
        attempts=(attempt,),
        terminal_at=_NOW + timedelta(seconds=1),
    )


async def _manager(
    *,
    subscription: WebhookSubscription | None = None,
    delivery: WebhookDelivery | None = None,
) -> tuple[
    InMemoryWebhookSubscriptionRepository,
    InMemoryWebhookDeliveryRepository,
    WebhookManager,
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
    return subscriptions, deliveries, manager


async def _system(
    *,
    evidence: ControlPlaneServiceAccountAuthentication | None = None,
    policy_denied: bool = False,
    subscription: WebhookSubscription | None = None,
    delivery: WebhookDelivery | None = None,
) -> tuple[
    InMemoryWebhookSubscriptionRepository,
    InMemoryWebhookDeliveryRepository,
    ControlPlaneServiceAccountMachineHttpAdapter,
    _Authentication,
    _Policy,
]:
    subscriptions, deliveries, manager = await _manager(
        subscription=subscription,
        delivery=delivery,
    )
    authentication = _Authentication(_evidence() if evidence is None else evidence)
    policy = _Policy(denied=policy_denied)
    audit = ControlPlaneServiceAccountAudit(
        None,
        ControlPlaneServiceAccountAuditProtector(b"a" * 32),
    )
    adapter = ControlPlaneServiceAccountMachineHttpAdapter(
        authentication=authentication,
        policy=policy,
        audit=audit,
        routes=control_plane_webhook_machine_routes(manager),
    )
    return subscriptions, deliveries, adapter, authentication, policy


def _headers() -> dict[str, tuple[str, ...]]:
    return {
        "authorization": ("Bearer phx_sa_" + "A" * 48,),
        "x-phoenix-request-nonce": ("N" * 32,),
        "x-phoenix-request-timestamp": (_NOW.isoformat(),),
        "content-type": ("application/json",),
    }


async def _dispatch(
    adapter: ControlPlaneServiceAccountMachineHttpAdapter,
    *,
    method: str,
    path: str,
    document: dict[str, object] | None = None,
    query: dict[str, tuple[str, ...]] | None = None,
    headers: dict[str, tuple[str, ...]] | None = None,
) -> tuple[HTTPStatus, dict[str, object], dict[str, str]]:
    body = (
        b""
        if document is None
        else json.dumps(
            document,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    )
    status, payload, response_headers = await adapter.dispatch(
        context=_transport_context(),
        method=method,
        path=path,
        query={} if query is None else query,
        headers=_headers() if headers is None else headers,
        body=body,
    )
    return status, dict(payload), response_headers


def test_machine_constants_are_canonical() -> None:
    assert CONTROL_PLANE_WEBHOOK_MACHINE_BASE_PATH == ("/v1/control-plane/machine/webhooks")
    assert CONTROL_PLANE_WEBHOOK_MACHINE_RESOURCE == "webhooks"


@pytest.mark.asyncio
async def test_route_set_contains_each_reviewed_action_once() -> None:
    _, _, manager = await _manager()
    administration = ControlPlaneWebhookMachineAdministration(manager)
    routes = administration.routes

    assert len(routes) == 10
    assert len({(route.method, route.path) for route in routes}) == 10
    assert {route.action for route in routes} == _ALL_SCOPES
    assert {route.resource for route in routes} == {CONTROL_PLANE_WEBHOOK_MACHINE_RESOURCE}
    assert all(
        route.path.startswith(f"{CONTROL_PLANE_WEBHOOK_MACHINE_BASE_PATH}/") for route in routes
    )


@pytest.mark.asyncio
async def test_health_and_subscription_reads_are_safe() -> None:
    subscription = _subscription()
    _, _, adapter, _, _ = await _system(subscription=subscription)

    health_status, health, health_headers = await _dispatch(
        adapter,
        method="GET",
        path=f"{CONTROL_PLANE_WEBHOOK_MACHINE_BASE_PATH}/health",
    )
    list_status, page, list_headers = await _dispatch(
        adapter,
        method="GET",
        path=(f"{CONTROL_PLANE_WEBHOOK_MACHINE_BASE_PATH}/subscriptions"),
        query={"limit": ("10",)},
    )

    rendered = repr((health, page))
    assert health_status is HTTPStatus.OK
    assert list_status is HTTPStatus.OK
    assert health_headers == {"Cache-Control": "no-store"}
    assert list_headers == {"Cache-Control": "no-store"}
    subscriptions_summary = health["subscriptions"]
    assert isinstance(subscriptions_summary, dict)
    assert subscriptions_summary["active"] == 1

    items = page["items"]
    assert isinstance(items, list)
    first_item = items[0]
    assert isinstance(first_item, dict)
    endpoint = first_item["endpoint"]
    assert isinstance(endpoint, dict)
    assert endpoint["host"] == "hooks.example.com"
    assert "private-path-token" not in rendered
    assert "must-not-leak" not in rendered
    assert "secret_name" not in rendered


@pytest.mark.asyncio
async def test_create_uses_machine_identity_and_safe_response() -> None:
    subscriptions, _, adapter, _, policy = await _system()
    status, payload, headers = await _dispatch(
        adapter,
        method="POST",
        path=(f"{CONTROL_PLANE_WEBHOOK_MACHINE_BASE_PATH}/subscriptions/create"),
        document={
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
        },
    )

    stored = await subscriptions.get(_SUBSCRIPTION_ID)
    assert status is HTTPStatus.CREATED
    assert headers == {"Cache-Control": "no-store"}
    assert stored is not None
    assert stored.created_by == "service-account:webhook.bot"
    signing = payload["signing"]
    assert isinstance(signing, dict)
    assert signing["key_version"] == 1
    assert "must-not-leak" not in repr(payload)
    assert policy.calls == [
        (
            WEBHOOK_SUBSCRIPTIONS_CREATE_PERMISSION,
            CONTROL_PLANE_WEBHOOK_MACHINE_RESOURCE,
        )
    ]


@pytest.mark.asyncio
async def test_update_disable_enable_and_revoke_lifecycle() -> None:
    subscription = _subscription()
    _, _, adapter, _, _ = await _system(subscription=subscription)
    base = CONTROL_PLANE_WEBHOOK_MACHINE_BASE_PATH

    update_status, updated, _ = await _dispatch(
        adapter,
        method="POST",
        path=f"{base}/subscriptions/update",
        document={
            "subscription_id": str(subscription.id),
            "expected_revision": 1,
            "display_name": "Updated Notifications",
        },
    )
    disable_status, disabled, _ = await _dispatch(
        adapter,
        method="POST",
        path=f"{base}/subscriptions/disable",
        document={
            "subscription_id": str(subscription.id),
            "expected_revision": 2,
        },
    )
    enable_status, enabled, _ = await _dispatch(
        adapter,
        method="POST",
        path=f"{base}/subscriptions/enable",
        document={
            "subscription_id": str(subscription.id),
            "expected_revision": 3,
        },
    )
    revoke_status, revoked, _ = await _dispatch(
        adapter,
        method="POST",
        path=f"{base}/subscriptions/revoke",
        document={
            "subscription_id": str(subscription.id),
            "expected_revision": 4,
        },
    )

    assert update_status is HTTPStatus.OK
    assert updated["display_name"] == "Updated Notifications"
    assert disable_status is HTTPStatus.OK
    assert disabled["status"] == "disabled"
    assert enable_status is HTTPStatus.OK
    assert enabled["status"] == "active"
    assert revoke_status is HTTPStatus.OK
    assert revoked["status"] == "revoked"
    assert revoked["revision"] == 5


@pytest.mark.asyncio
async def test_signing_rotation_never_returns_reference() -> None:
    subscription = _subscription()
    _, _, adapter, _, _ = await _system(subscription=subscription)
    status, payload, _ = await _dispatch(
        adapter,
        method="POST",
        path=(f"{CONTROL_PLANE_WEBHOOK_MACHINE_BASE_PATH}/subscriptions/rotate-signing-key"),
        document={
            "subscription_id": str(subscription.id),
            "expected_revision": 1,
            "secret_name": "new-secret",
            "secret_namespace": "integrations",
            "secret_version": 2,
            "lease_ttl_seconds": 45,
        },
    )

    signing = payload["signing"]
    assert isinstance(signing, dict)
    assert status is HTTPStatus.OK
    assert signing["key_version"] == 2
    assert "new-secret" not in repr(payload)
    assert "integrations" not in repr(payload)
    assert "secret_name" not in repr(payload)


@pytest.mark.asyncio
async def test_delivery_list_is_body_free_and_redrive_is_scoped() -> None:
    subscription = _subscription()
    delivery = _dead_letter(subscription)
    _, deliveries, adapter, _, policy = await _system(
        subscription=subscription,
        delivery=delivery,
    )
    base = CONTROL_PLANE_WEBHOOK_MACHINE_BASE_PATH

    list_status, page, _ = await _dispatch(
        adapter,
        method="GET",
        path=f"{base}/deliveries",
    )
    redrive_status, result, _ = await _dispatch(
        adapter,
        method="POST",
        path=f"{base}/deliveries/redrive",
        document={"delivery_id": str(delivery.id)},
    )

    stored = await deliveries.get(delivery.id)
    assert list_status is HTTPStatus.OK
    assert "must-not-leak" not in repr(page)
    assert "canonical_body" not in repr(page)
    assert "signature" not in repr(page)
    assert redrive_status is HTTPStatus.ACCEPTED
    assert result["status"] == "retrying"
    assert stored is not None
    assert stored.status is WebhookDeliveryStatus.RETRYING
    assert policy.calls[-1] == (
        WEBHOOK_REDRIVE_PERMISSION,
        CONTROL_PLANE_WEBHOOK_MACHINE_RESOURCE,
    )


@pytest.mark.asyncio
async def test_missing_scope_fails_before_policy_and_handler() -> None:
    evidence = _evidence(scopes=frozenset({WEBHOOK_HEALTH_READ_PERMISSION}))
    _, _, adapter, authentication, policy = await _system(evidence=evidence)
    status, payload, _ = await _dispatch(
        adapter,
        method="GET",
        path=(f"{CONTROL_PLANE_WEBHOOK_MACHINE_BASE_PATH}/subscriptions"),
    )

    assert status is HTTPStatus.FORBIDDEN
    assert payload == {"error": "forbidden"}
    assert authentication.calls == 1
    assert policy.calls == []


@pytest.mark.asyncio
async def test_missing_resource_fails_before_policy() -> None:
    evidence = _evidence(resources=frozenset({"jobs"}))
    _, _, adapter, _, policy = await _system(evidence=evidence)
    status, payload, _ = await _dispatch(
        adapter,
        method="GET",
        path=f"{CONTROL_PLANE_WEBHOOK_MACHINE_BASE_PATH}/health",
    )

    assert status is HTTPStatus.FORBIDDEN
    assert payload == {"error": "forbidden"}
    assert policy.calls == []


@pytest.mark.asyncio
async def test_central_policy_denial_is_generic() -> None:
    _, _, adapter, _, policy = await _system(policy_denied=True)
    status, payload, _ = await _dispatch(
        adapter,
        method="GET",
        path=f"{CONTROL_PLANE_WEBHOOK_MACHINE_BASE_PATH}/health",
    )

    assert status is HTTPStatus.FORBIDDEN
    assert payload == {"error": "forbidden"}
    assert policy.calls == [
        (
            WEBHOOK_HEALTH_READ_PERMISSION,
            CONTROL_PLANE_WEBHOOK_MACHINE_RESOURCE,
        )
    ]


@pytest.mark.asyncio
async def test_browser_credentials_are_rejected() -> None:
    _, _, adapter, authentication, _ = await _system()
    headers = _headers()
    headers["cookie"] = ("phoenix_session=browser",)
    status, payload, _ = await _dispatch(
        adapter,
        method="GET",
        path=f"{CONTROL_PLANE_WEBHOOK_MACHINE_BASE_PATH}/health",
        headers=headers,
    )

    assert status is HTTPStatus.FORBIDDEN
    assert payload == {"error": "request_rejected"}
    assert authentication.calls == 0


@pytest.mark.asyncio
async def test_mutation_requires_json_and_rejects_query() -> None:
    _, _, adapter, _, _ = await _system()
    path = f"{CONTROL_PLANE_WEBHOOK_MACHINE_BASE_PATH}/subscriptions/create"
    bad_headers = _headers()
    bad_headers["content-type"] = ("text/plain",)

    media_status, media_payload, _ = await _dispatch(
        adapter,
        method="POST",
        path=path,
        document={"unused": True},
        headers=bad_headers,
    )
    query_status, query_payload, _ = await _dispatch(
        adapter,
        method="POST",
        path=path,
        document={"unused": True},
        query={"limit": ("1",)},
    )

    assert media_status is HTTPStatus.BAD_REQUEST
    assert media_payload == {"error": "invalid_webhook_request"}
    assert query_status is HTTPStatus.BAD_REQUEST
    assert query_payload == {"error": "invalid_webhook_request"}


@pytest.mark.asyncio
async def test_stale_revision_and_not_found_are_safe() -> None:
    subscription = _subscription()
    _, _, adapter, _, _ = await _system(subscription=subscription)
    base = CONTROL_PLANE_WEBHOOK_MACHINE_BASE_PATH

    conflict_status, conflict_payload, _ = await _dispatch(
        adapter,
        method="POST",
        path=f"{base}/subscriptions/disable",
        document={
            "subscription_id": str(subscription.id),
            "expected_revision": 99,
        },
    )
    missing_status, missing_payload, _ = await _dispatch(
        adapter,
        method="POST",
        path=f"{base}/subscriptions/disable",
        document={
            "subscription_id": str(UUID(int=999)),
            "expected_revision": 1,
        },
    )

    assert conflict_status is HTTPStatus.CONFLICT
    assert conflict_payload == {"error": "webhook_conflict"}
    assert missing_status is HTTPStatus.NOT_FOUND
    assert missing_payload == {"error": "webhook_subscription_not_found"}


def test_rfc_marks_scoped_service_account_administration_complete() -> None:
    rfc = _RFC.read_text(encoding="utf-8")
    assert "- [x] Optional scoped service-account administration" in rfc
    assert "fixed machine-only routes" in rfc
