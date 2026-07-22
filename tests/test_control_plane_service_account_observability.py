from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import cast
from uuid import UUID

import pytest

from phoenix_os.control_plane import (
    ControlPlaneClientIdentity,
    ControlPlaneNetworkRequestContext,
    ControlPlaneServiceAccountAudit,
    ControlPlaneServiceAccountAuditProtector,
    ControlPlaneServiceAccountAuthenticationThrottle,
    ControlPlaneServiceAccountHealth,
    ControlPlaneServiceAccountHealthSnapshot,
    ControlPlaneServiceAccountObservability,
    ControlPlaneServiceAccountReplayPolicy,
    ControlPlaneServiceAccountReplayProtector,
    ControlPlaneServiceAccountReplayRejectedError,
    ControlPlaneServiceAccountReplayRequest,
    ControlPlaneServiceAccountRequestNonce,
    ControlPlaneTlsPolicy,
    control_plane_service_account_authentication_context,
    control_plane_service_account_observability_to_dict,
)
from phoenix_os.control_plane.service_account_authentication import (
    ControlPlaneServiceAccountAuthentication,
    ControlPlaneServiceAccountAuthenticationContext,
)
from phoenix_os.control_plane.service_account_lifecycle import (
    ControlPlaneServiceAccountLifecycleService,
)
from phoenix_os.control_plane.service_account_memory import (
    InMemoryControlPlaneServiceAccountRepository,
)
from phoenix_os.events import EventBus

_NOW = datetime(
    2026,
    7,
    20,
    12,
    tzinfo=UTC,
)
_ACCOUNT_ID = UUID("10000000-0000-0000-0000-000000000001")
_TOKEN_ID = UUID("20000000-0000-0000-0000-000000000001")
_TOKEN_VALUE = "phx_sa_" + "S" * 48
_EMPTY_DIGEST = hashlib.sha256(b"").hexdigest()


class _ReplayClock:
    def __init__(self) -> None:
        self.value = _NOW

    def __call__(self) -> datetime:
        return self.value


class _Writer:
    def __init__(
        self,
        address: str,
    ) -> None:
        self.address = address

    def get_extra_info(
        self,
        name: str,
        default: object = None,
    ) -> object:
        if name == "peername":
            return (
                self.address,
                443,
            )

        return default


class _Events:
    def __init__(
        self,
        *,
        fail: bool = False,
    ) -> None:
        self.fail = fail
        self.records: list[dict[str, object]] = []

    async def emit(
        self,
        name: str,
        *,
        source: str,
        payload: Mapping[str, object],
        correlation_id: str | None = None,
        causation_id: UUID | None = None,
    ) -> object:
        if self.fail:
            raise RuntimeError("closed")

        self.records.append(
            {
                "name": name,
                "source": source,
                "payload": dict(payload),
                "correlation_id": correlation_id,
                "causation_id": causation_id,
            }
        )

        return object()


@dataclass(slots=True)
class _Stack:
    repository: InMemoryControlPlaneServiceAccountRepository
    lifecycle: ControlPlaneServiceAccountLifecycleService
    throttle: ControlPlaneServiceAccountAuthenticationThrottle
    replay: ControlPlaneServiceAccountReplayProtector
    audit: ControlPlaneServiceAccountAudit
    observability: ControlPlaneServiceAccountObservability
    events: _Events


def _transport(
    address: str = "8.8.8.8",
) -> ControlPlaneServiceAccountAuthenticationContext:
    network = ControlPlaneNetworkRequestContext(
        identity=ControlPlaneClientIdentity(
            address=address,
            peer_address=address,
        ),
        host="api.example.test",
        origin=None,
    )

    return control_plane_service_account_authentication_context(
        network,
        _Writer(address),
        tls_policy=ControlPlaneTlsPolicy(),
    )


def _authentication() -> ControlPlaneServiceAccountAuthentication:
    return ControlPlaneServiceAccountAuthentication(
        service_account_id=_ACCOUNT_ID,
        token_id=_TOKEN_ID,
        account_name="release.bot",
        scopes=frozenset(
            {
                "jobs.read",
            }
        ),
        resources=frozenset(
            {
                "job:*",
            }
        ),
        token_version=1,
        account_revision=1,
        token_revision=1,
        authenticated_at=_NOW,
        expires_at=_NOW + timedelta(hours=1),
    )


def _request(
    nonce: str,
) -> ControlPlaneServiceAccountReplayRequest:
    return ControlPlaneServiceAccountReplayRequest(
        nonce=ControlPlaneServiceAccountRequestNonce(nonce),
        issued_at=_NOW,
        method="POST",
        target="/v1/machine/jobs?limit=10",
        body_digest=_EMPTY_DIGEST,
    )


def _stack(
    *,
    fail_events: bool = False,
    replay_capacity: int = 100,
) -> _Stack:
    repository = InMemoryControlPlaneServiceAccountRepository()

    lifecycle = ControlPlaneServiceAccountLifecycleService(
        repository=repository,
        clock=lambda: _NOW,
        account_id_factory=lambda: _ACCOUNT_ID,
        token_id_factory=lambda: _TOKEN_ID,
        token_factory=lambda: _TOKEN_VALUE,
    )

    throttle = ControlPlaneServiceAccountAuthenticationThrottle()

    replay = ControlPlaneServiceAccountReplayProtector(
        b"R" * 32,
        ControlPlaneServiceAccountReplayPolicy(
            window=timedelta(minutes=5),
            future_skew=timedelta(seconds=30),
            capacity=replay_capacity,
        ),
        clock=_ReplayClock(),
    )

    events = _Events(fail=fail_events)

    audit = ControlPlaneServiceAccountAudit(
        cast(EventBus, events),
        ControlPlaneServiceAccountAuditProtector(b"A" * 32),
    )

    observability = ControlPlaneServiceAccountObservability(
        registry=repository,
        lifecycle=lifecycle,
        throttle=throttle,
        replay=replay,
        audit=audit,
    )

    return _Stack(
        repository=repository,
        lifecycle=lifecycle,
        throttle=throttle,
        replay=replay,
        audit=audit,
        observability=observability,
        events=events,
    )


@pytest.mark.asyncio
async def test_empty_open_stack_is_healthy() -> None:
    stack = _stack()

    snapshot = await stack.observability.snapshot()

    assert snapshot.health.status is (ControlPlaneServiceAccountHealth.HEALTHY)
    assert snapshot.health.registry_available
    assert snapshot.health.lifecycle_available
    assert snapshot.health.throttling_available
    assert snapshot.health.replay_protection_available
    assert snapshot.health.audit_delivery_healthy
    assert snapshot.health.capacity_protection_healthy

    assert snapshot.metrics.accounts == 0
    assert snapshot.metrics.tokens == 0
    assert snapshot.metrics.replay_attempts == 0
    assert snapshot.metrics.audit_emitted == 0


@pytest.mark.asyncio
async def test_snapshot_aggregates_only_safe_counters() -> None:
    stack = _stack()

    account = await stack.lifecycle.create_account(
        name="release.bot",
        display_name="Release Bot",
    )

    grant = await stack.lifecycle.issue_token(
        account.id,
        label="automation",
        scopes=frozenset(
            {
                "jobs.read",
            }
        ),
        expires_at=_NOW + timedelta(hours=1),
    )

    transport = _transport()
    authentication = _authentication()

    await stack.throttle.consume_client(transport)
    await stack.throttle.consume_account(account.id)

    await stack.replay.admit(
        authentication,
        _request("request-nonce-private"),
    )

    await stack.audit.authentication_succeeded(
        authentication,
        transport,
    )

    snapshot = await stack.observability.snapshot()
    serialized = control_plane_service_account_observability_to_dict(snapshot)

    metrics = snapshot.metrics

    assert metrics.accounts == 1
    assert metrics.active_accounts == 1
    assert metrics.tokens == 1
    assert metrics.active_tokens == 1
    assert metrics.accounts_created == 1
    assert metrics.tokens_issued == 1
    assert metrics.client_authentication_attempts == 1
    assert metrics.account_authentication_attempts == 1
    assert metrics.replay_attempts == 1
    assert metrics.replay_accepted == 1
    assert metrics.audit_emitted == 1

    rendered = repr(
        (
            snapshot,
            serialized,
        )
    )

    assert _TOKEN_VALUE not in rendered
    assert grant.metadata.token_digest not in rendered
    assert str(_ACCOUNT_ID) not in rendered
    assert str(_TOKEN_ID) not in rendered
    assert "release.bot" not in rendered
    assert "Release Bot" not in rendered
    assert "8.8.8.8" not in rendered
    assert "request-nonce-private" not in rendered
    assert "/v1/machine/jobs" not in rendered


@pytest.mark.asyncio
async def test_audit_delivery_failure_degrades_health() -> None:
    stack = _stack(fail_events=True)

    await stack.audit.authentication_rejected(_transport())

    snapshot = await stack.observability.snapshot()

    assert snapshot.health.status is (ControlPlaneServiceAccountHealth.DEGRADED)
    assert not snapshot.health.audit_delivery_healthy
    assert snapshot.metrics.audit_emitted == 0
    assert snapshot.metrics.audit_dropped == 1


@pytest.mark.asyncio
async def test_capacity_rejection_degrades_health() -> None:
    stack = _stack(replay_capacity=1)
    authentication = _authentication()

    await stack.replay.admit(
        authentication,
        _request("request-nonce-0001"),
    )

    with pytest.raises(
        ControlPlaneServiceAccountReplayRejectedError,
    ):
        await stack.replay.admit(
            authentication,
            _request("request-nonce-0002"),
        )

    snapshot = await stack.observability.snapshot()

    assert snapshot.health.status is (ControlPlaneServiceAccountHealth.DEGRADED)
    assert not (snapshot.health.capacity_protection_healthy)
    assert snapshot.metrics.replay_rejections == 1
    assert snapshot.metrics.tracked_replay_requests == 1


@pytest.mark.asyncio
async def test_partial_component_closure_is_degraded() -> None:
    stack = _stack()

    await stack.throttle.close()

    snapshot = await stack.observability.snapshot()

    assert snapshot.health.status is (ControlPlaneServiceAccountHealth.DEGRADED)
    assert not snapshot.health.throttling_available
    assert snapshot.health.registry_available


@pytest.mark.asyncio
async def test_all_owned_security_components_closed_is_stopped() -> None:
    stack = _stack()

    await stack.lifecycle.close()
    await stack.repository.close()
    await stack.throttle.close()
    await stack.replay.close()

    snapshot = await stack.observability.snapshot()

    assert snapshot.health.status is (ControlPlaneServiceAccountHealth.STOPPED)
    assert not snapshot.health.registry_available
    assert not snapshot.health.lifecycle_available
    assert not snapshot.health.throttling_available
    assert not snapshot.health.replay_protection_available


def test_health_snapshot_rejects_inconsistent_status() -> None:
    with pytest.raises(
        ValueError,
        match="does not match",
    ):
        ControlPlaneServiceAccountHealthSnapshot(
            status=(ControlPlaneServiceAccountHealth.HEALTHY),
            registry_available=False,
            lifecycle_available=True,
            throttling_available=True,
            replay_protection_available=True,
            audit_delivery_healthy=True,
            capacity_protection_healthy=True,
        )


@pytest.mark.asyncio
async def test_serializer_uses_exact_allowlisted_sections() -> None:
    stack = _stack()

    payload = control_plane_service_account_observability_to_dict(
        await stack.observability.snapshot()
    )

    assert set(payload) == {
        "schema_version",
        "health",
        "metrics",
    }

    health = cast(
        dict[str, object],
        payload["health"],
    )
    metrics = cast(
        dict[str, object],
        payload["metrics"],
    )

    assert set(health) == {
        "schema_version",
        "status",
        "registry_available",
        "lifecycle_available",
        "throttling_available",
        "replay_protection_available",
        "audit_delivery_healthy",
        "capacity_protection_healthy",
        "last_throttle_block",
        "last_replay_rejection",
        "last_audit_event",
    }

    assert "account_id" not in metrics
    assert "token_id" not in metrics
    assert "client_address" not in metrics
    assert "digest" not in metrics
    assert "nonce" not in metrics


def test_observability_exports_are_public() -> None:
    import phoenix_os.control_plane as control_plane

    assert (
        control_plane.ControlPlaneServiceAccountObservability
        is ControlPlaneServiceAccountObservability
    )
    assert control_plane.ControlPlaneServiceAccountHealth is ControlPlaneServiceAccountHealth
    assert (
        control_plane.control_plane_service_account_observability_to_dict
        is control_plane_service_account_observability_to_dict
    )
