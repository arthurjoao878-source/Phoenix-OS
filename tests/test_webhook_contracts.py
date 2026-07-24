from __future__ import annotations

import math
from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
from types import MappingProxyType
from typing import Any, cast
from uuid import UUID

import pytest

from phoenix_os.secrets import SecretRef
from phoenix_os.webhooks import (
    MAX_WEBHOOK_PAGE_SIZE,
    MAX_WEBHOOK_RETRY_DELAY,
    MAX_WEBHOOK_SIGNING_LEASE_TTL,
    MAX_WEBHOOK_SUBSCRIPTION_CAPACITY,
    PhoenixWebhookError,
    WebhookAttemptOutcome,
    WebhookCorruptionError,
    WebhookDeliveryStatus,
    WebhookEgressPolicy,
    WebhookEndpoint,
    WebhookEventType,
    WebhookPageInfo,
    WebhookPageRequest,
    WebhookPayload,
    WebhookPersistenceError,
    WebhookRetryPolicy,
    WebhookSchemaError,
    WebhookSigningPolicy,
    WebhookSubscription,
    WebhookSubscriptionPage,
    WebhookSubscriptionRepositorySnapshot,
    WebhookSubscriptionStatus,
    normalize_webhook_resource_filters,
)


def test_subscription_status_exposes_delivery_eligibility() -> None:
    assert WebhookSubscriptionStatus.ACTIVE.deliverable is True
    assert WebhookSubscriptionStatus.DISABLED.deliverable is False
    assert WebhookSubscriptionStatus.REVOKED.deliverable is False


def test_delivery_status_exposes_terminal_and_schedulable_states() -> None:
    assert WebhookDeliveryStatus.PENDING.schedulable is True
    assert WebhookDeliveryStatus.RETRYING.schedulable is True
    assert WebhookDeliveryStatus.IN_FLIGHT.schedulable is False

    assert WebhookDeliveryStatus.SUCCEEDED.terminal is True
    assert WebhookDeliveryStatus.FAILED.terminal is True
    assert WebhookDeliveryStatus.DEAD_LETTER.terminal is True
    assert WebhookDeliveryStatus.CANCELLED.terminal is True
    assert WebhookDeliveryStatus.RETRYING.terminal is False


def test_attempt_outcome_exposes_success() -> None:
    assert WebhookAttemptOutcome.SUCCEEDED.succeeded is True
    assert WebhookAttemptOutcome.RETRYABLE_FAILURE.succeeded is False
    assert WebhookAttemptOutcome.TERMINAL_FAILURE.succeeded is False


def test_https_endpoint_is_canonicalized() -> None:
    endpoint = WebhookEndpoint("HTTPS://Example.COM:443/hooks")

    assert endpoint.url == "https://example.com/hooks"
    assert endpoint.scheme == "https"
    assert endpoint.host == "example.com"
    assert endpoint.port == 443
    assert endpoint.loopback_development is False


def test_https_endpoint_normalizes_ipv6_and_default_path() -> None:
    endpoint = WebhookEndpoint("https://[2001:0db8::1]")

    assert endpoint.url == "https://[2001:db8::1]/"
    assert endpoint.host == "2001:db8::1"


@pytest.mark.parametrize(
    "value",
    [
        "",
        " https://example.com/hooks",
        "ftp://example.com/hooks",
        "https://user@example.com/hooks",
        "https://example.com/hooks?token=secret",
        "https://example.com/hooks#fragment",
        "https://example.com:99999/hooks",
        "https://example.com\\hooks",
        "https://-example.com/hooks",
        "https://example..com/hooks",
        "https://example.com/\x00hooks",
    ],
)
def test_endpoint_rejects_ambiguous_or_sensitive_forms(value: str) -> None:
    with pytest.raises(ValueError):
        WebhookEndpoint(value)


def test_http_endpoint_requires_explicit_literal_loopback() -> None:
    with pytest.raises(ValueError, match="explicit loopback"):
        WebhookEndpoint("http://127.0.0.1/hooks")

    with pytest.raises(ValueError, match="literal loopback"):
        WebhookEndpoint(
            "http://localhost/hooks",
            allow_insecure_loopback=True,
        )

    with pytest.raises(ValueError, match="literal loopback"):
        WebhookEndpoint(
            "http://192.0.2.1/hooks",
            allow_insecure_loopback=True,
        )

    endpoint = WebhookEndpoint(
        "http://127.0.0.1:80/hooks",
        allow_insecure_loopback=True,
    )

    assert endpoint.url == "http://127.0.0.1/hooks"
    assert endpoint.port == 80
    assert endpoint.loopback_development is True


def test_https_endpoint_rejects_irrelevant_loopback_override() -> None:
    with pytest.raises(ValueError, match="valid only for HTTP"):
        WebhookEndpoint(
            "https://example.com/hooks",
            allow_insecure_loopback=True,
        )


def test_egress_policy_normalizes_name_ports_and_networks() -> None:
    policy = WebhookEgressPolicy(
        name=" Production.Webhooks ",
        allowed_ports=frozenset({443, 8443}),
        allowed_networks=(
            "2001:db8::/32",
            "203.0.113.0/24",
        ),
    )

    assert policy.name == "production.webhooks"
    assert policy.allowed_ports == frozenset({443, 8443})
    assert policy.allowed_networks == (
        "203.0.113.0/24",
        "2001:db8::/32",
    )


def test_egress_policy_rejects_invalid_ports_and_networks() -> None:
    with pytest.raises(TypeError, match="integers"):
        WebhookEgressPolicy(
            name="production.webhooks",
            allowed_ports=frozenset({True}),
        )

    with pytest.raises(ValueError, match="between 1 and 65535"):
        WebhookEgressPolicy(
            name="production.webhooks",
            allowed_ports=frozenset({0}),
        )

    with pytest.raises(ValueError, match="canonical CIDR"):
        WebhookEgressPolicy(
            name="production.webhooks",
            allowed_networks=("203.0.113.1/24",),
        )

    with pytest.raises(ValueError, match="port 80"):
        WebhookEgressPolicy(
            name="development.webhooks",
            allow_insecure_loopback=True,
        )


def test_signing_policy_requires_exact_secret_version() -> None:
    with pytest.raises(ValueError, match="exact version"):
        WebhookSigningPolicy(SecretRef("webhook-signing", "integrations"))

    policy = WebhookSigningPolicy(
        SecretRef("webhook-signing", "integrations", 3),
    )

    assert policy.key_version == 3


def test_signing_policy_bounds_lease_ttl() -> None:
    secret = SecretRef("webhook-signing", "integrations", 1)

    with pytest.raises(ValueError, match="positive"):
        WebhookSigningPolicy(secret, lease_ttl=timedelta(0))

    with pytest.raises(ValueError, match="maximum"):
        WebhookSigningPolicy(
            secret,
            lease_ttl=MAX_WEBHOOK_SIGNING_LEASE_TTL + timedelta(microseconds=1),
        )


def test_retry_policy_returns_bounded_base_delay() -> None:
    policy = WebhookRetryPolicy(
        max_attempts=5,
        initial_delay=timedelta(seconds=10),
        multiplier=3,
        max_delay=timedelta(seconds=60),
        jitter_ratio=0.25,
    )

    assert policy.base_delay_after(1) == timedelta(seconds=10)
    assert policy.base_delay_after(2) == timedelta(seconds=30)
    assert policy.base_delay_after(3) == timedelta(seconds=60)
    assert policy.base_delay_after(4) == timedelta(seconds=60)


def test_retry_policy_clamps_without_numeric_overflow() -> None:
    policy = WebhookRetryPolicy(
        max_attempts=20,
        initial_delay=MAX_WEBHOOK_RETRY_DELAY,
        multiplier=10,
        max_delay=MAX_WEBHOOK_RETRY_DELAY,
    )

    assert policy.base_delay_after(19) == MAX_WEBHOOK_RETRY_DELAY


@pytest.mark.parametrize(
    "factory",
    [
        lambda: WebhookRetryPolicy(max_attempts=0),
        lambda: WebhookRetryPolicy(max_attempts=21),
        lambda: WebhookRetryPolicy(initial_delay=timedelta(0)),
        lambda: WebhookRetryPolicy(max_delay=timedelta(days=2)),
        lambda: WebhookRetryPolicy(multiplier=0.5),
        lambda: WebhookRetryPolicy(multiplier=math.inf),
        lambda: WebhookRetryPolicy(jitter_ratio=-0.1),
        lambda: WebhookRetryPolicy(jitter_ratio=math.nan),
    ],
)
def test_retry_policy_rejects_invalid_bounds(
    factory: Callable[[], WebhookRetryPolicy],
) -> None:
    with pytest.raises(ValueError):
        factory()


def test_retry_policy_rejects_nonretryable_attempt_indexes() -> None:
    policy = WebhookRetryPolicy(max_attempts=3)

    with pytest.raises(ValueError, match="retryable attempt"):
        policy.base_delay_after(0)

    with pytest.raises(ValueError, match="retryable attempt"):
        policy.base_delay_after(3)


def test_event_type_normalizes_safe_fields() -> None:
    event_type = WebhookEventType(
        name=" Jobs.Completed ",
        schema_version=2,
        resource_filter_fields=frozenset({" Workflow_ID ", "job_id"}),
        max_payload_bytes=32_768,
    )

    assert event_type.name == "jobs.completed"
    assert event_type.schema_version == 2
    assert event_type.resource_filter_fields == frozenset({"workflow_id", "job_id"})
    assert event_type.supports_filters is True


def test_event_type_rejects_invalid_contracts() -> None:
    with pytest.raises(ValueError, match="event type"):
        WebhookEventType("jobs/completed")

    with pytest.raises(TypeError, match="frozenset"):
        WebhookEventType(
            "jobs.completed",
            resource_filter_fields=cast(Any, {"job_id"}),
        )

    with pytest.raises(ValueError, match="schema_version"):
        WebhookEventType("jobs.completed", schema_version=0)

    with pytest.raises(ValueError, match="max_payload_bytes"):
        WebhookEventType("jobs.completed", max_payload_bytes=0)


def test_payload_is_deeply_immutable_and_json_compatible() -> None:
    original = {
        "job": {
            "id": "job-1",
            "labels": ["release", "stable"],
        },
        "attempts": 2,
        "successful": True,
    }
    payload = WebhookPayload(WebhookEventType("jobs.completed"), original)

    original["attempts"] = 99
    nested = payload.data["job"]

    assert isinstance(payload.data, MappingProxyType)
    assert isinstance(nested, MappingProxyType)
    assert isinstance(nested, Mapping)
    assert payload.data["attempts"] == 2
    assert nested["labels"] == ("release", "stable")

    mutable_view = cast(Any, payload.data)
    with pytest.raises(TypeError):
        mutable_view["new"] = "value"


def test_payload_rejects_unsafe_json_values() -> None:
    event_type = WebhookEventType("jobs.completed")

    with pytest.raises(ValueError, match="non-finite"):
        WebhookPayload(event_type, {"value": math.inf})

    with pytest.raises(ValueError, match="unsupported"):
        WebhookPayload(event_type, {"value": object()})

    with pytest.raises(ValueError, match="keys must be strings"):
        WebhookPayload(event_type, cast(Any, {1: "value"}))


def test_resource_filters_are_normalized_and_deeply_frozen() -> None:
    filters = normalize_webhook_resource_filters(
        {
            " Jobs.Completed ": {
                " Workflow_ID ": frozenset({" release ", "nightly"}),
            }
        },
        event_types=frozenset({"jobs.completed"}),
    )

    assert isinstance(filters, MappingProxyType)
    assert filters["jobs.completed"]["workflow_id"] == frozenset({"release", "nightly"})


def test_resource_filters_reject_unsubscribed_or_ambiguous_values() -> None:
    with pytest.raises(ValueError, match="unsubscribed"):
        normalize_webhook_resource_filters(
            {"jobs.failed": {"job_id": frozenset({"job-1"})}},
            event_types=frozenset({"jobs.completed"}),
        )

    with pytest.raises(TypeError, match="frozenset"):
        normalize_webhook_resource_filters(
            cast(Any, {"jobs.completed": {"job_id": ["job-1"]}}),
            event_types=frozenset({"jobs.completed"}),
        )


def test_webhook_error_hierarchy_preserves_persistence_context() -> None:
    assert issubclass(WebhookPersistenceError, PhoenixWebhookError)
    assert issubclass(WebhookCorruptionError, WebhookPersistenceError)
    assert issubclass(WebhookSchemaError, WebhookCorruptionError)


_NOW = datetime(2026, 7, 22, 12, 0, tzinfo=UTC)
_SUBSCRIPTION_ID = UUID("00000000-0000-4000-8000-000000000024")


def _subscription(**changes: object) -> WebhookSubscription:
    values: dict[str, object] = {
        "id": _SUBSCRIPTION_ID,
        "name": "release.notifications",
        "display_name": "Release Notifications",
        "event_types": frozenset({"jobs.completed", "workflows.failed"}),
        "endpoint": WebhookEndpoint("https://hooks.example.com/phoenix"),
        "signing": WebhookSigningPolicy(SecretRef("release-webhook", "integrations", 2)),
        "egress_policy": "production.webhooks",
        "created_at": _NOW,
        "updated_at": _NOW,
        "created_by": "maintainer:arthur",
        "resource_filters": {"jobs.completed": {"job_id": frozenset({"job-1"})}},
    }
    values.update(changes)
    return WebhookSubscription(**cast(Any, values))


def test_subscription_normalizes_and_freezes_safe_metadata() -> None:
    subscription = _subscription(
        name=" Release.Notifications ",
        display_name=" Release Notifications ",
        event_types=frozenset({" Jobs.Completed ", "workflows.failed"}),
        egress_policy=" Production.Webhooks ",
        created_by=" maintainer:arthur ",
    )

    assert subscription.name == "release.notifications"
    assert subscription.display_name == "Release Notifications"
    assert subscription.event_types == frozenset({"jobs.completed", "workflows.failed"})
    assert subscription.egress_policy == "production.webhooks"
    assert subscription.created_by == "maintainer:arthur"
    assert isinstance(subscription.resource_filters, MappingProxyType)
    assert subscription.deliverable is True


def test_subscription_rejects_duplicate_normalized_event_types() -> None:
    with pytest.raises(ValueError, match="unique after normalization"):
        _subscription(event_types=frozenset({"Jobs.Completed", "jobs.completed"}))


def test_subscription_rejects_empty_or_non_frozen_event_types() -> None:
    with pytest.raises(ValueError, match="at least one"):
        _subscription(event_types=frozenset())

    with pytest.raises(TypeError, match="frozenset"):
        _subscription(event_types=cast(Any, {"jobs.completed"}))


def test_subscription_rejects_unsubscribed_resource_filters() -> None:
    with pytest.raises(ValueError, match="unsubscribed"):
        _subscription(resource_filters={"jobs.failed": {"job_id": frozenset({"job-1"})}})


def test_subscription_requires_aware_ordered_timestamps() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        _subscription(created_at=datetime(2026, 7, 22, 12, 0))

    with pytest.raises(ValueError, match="cannot precede"):
        _subscription(updated_at=_NOW - timedelta(seconds=1))


def test_disabled_subscription_requires_bounded_lifecycle_timestamp() -> None:
    disabled_at = _NOW + timedelta(minutes=1)
    subscription = _subscription(
        status=WebhookSubscriptionStatus.DISABLED,
        updated_at=disabled_at,
        disabled_at=disabled_at,
    )

    assert subscription.deliverable is False

    with pytest.raises(ValueError, match="requires only disabled_at"):
        _subscription(status=WebhookSubscriptionStatus.DISABLED)


def test_revoked_subscription_requires_revocation_timestamp() -> None:
    revoked_at = _NOW + timedelta(minutes=2)
    subscription = _subscription(
        status=WebhookSubscriptionStatus.REVOKED,
        updated_at=revoked_at,
        revoked_at=revoked_at,
    )

    assert subscription.status is WebhookSubscriptionStatus.REVOKED

    with pytest.raises(ValueError, match="requires revoked_at"):
        _subscription(status=WebhookSubscriptionStatus.REVOKED)


def test_active_subscription_rejects_inactive_timestamps() -> None:
    disabled_at = _NOW + timedelta(minutes=1)
    with pytest.raises(ValueError, match="inactive timestamps"):
        _subscription(updated_at=disabled_at, disabled_at=disabled_at)


def test_subscription_rejects_invalid_revision_and_schema() -> None:
    with pytest.raises(ValueError, match="revision"):
        _subscription(revision=0)

    with pytest.raises(ValueError, match="schema version"):
        _subscription(schema_version=2)


def test_webhook_page_request_enforces_bounds() -> None:
    assert WebhookPageRequest().offset == 0

    with pytest.raises(ValueError, match="offset"):
        WebhookPageRequest(offset=-1)

    with pytest.raises(ValueError, match="between 1"):
        WebhookPageRequest(limit=MAX_WEBHOOK_PAGE_SIZE + 1)


def test_webhook_page_info_builds_deterministic_next_offset() -> None:
    request = WebhookPageRequest(offset=10, limit=5)
    page = WebhookPageInfo.from_slice(request, returned=5, total=18)

    assert page.next_offset == 15

    terminal = WebhookPageInfo.from_slice(request, returned=3, total=13)
    assert terminal.next_offset is None


def test_webhook_page_info_rejects_inconsistent_metadata() -> None:
    with pytest.raises(ValueError, match="requires next_offset"):
        WebhookPageInfo(offset=0, limit=10, returned=5, total=6, next_offset=None)

    with pytest.raises(ValueError, match="inconsistent"):
        WebhookPageInfo(offset=0, limit=10, returned=5, total=6, next_offset=4)


def test_subscription_page_requires_unique_items() -> None:
    first = _subscription()
    page = WebhookPageInfo(offset=0, limit=10, returned=2, total=2, next_offset=None)

    with pytest.raises(ValueError, match="unique"):
        WebhookSubscriptionPage(items=(first, first), page=page)


def test_subscription_repository_snapshot_validates_counts() -> None:
    snapshot = WebhookSubscriptionRepositorySnapshot(
        closed=False,
        subscriptions=3,
        active=1,
        disabled=1,
        revoked=1,
        capacity=100,
    )

    assert snapshot.subscriptions == 3

    with pytest.raises(ValueError, match="inconsistent"):
        WebhookSubscriptionRepositorySnapshot(
            closed=False,
            subscriptions=3,
            active=3,
            disabled=1,
            revoked=0,
            capacity=100,
        )

    with pytest.raises(ValueError, match="outside bounds"):
        WebhookSubscriptionRepositorySnapshot(
            closed=False,
            subscriptions=0,
            active=0,
            disabled=0,
            revoked=0,
            capacity=MAX_WEBHOOK_SUBSCRIPTION_CAPACITY + 1,
        )
