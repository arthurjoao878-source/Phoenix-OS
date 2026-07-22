from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from phoenix_os.control_plane.service_account_audit import (
    ControlPlaneServiceAccountAuditEvent,
    ControlPlaneServiceAccountAuditSnapshot,
)
from phoenix_os.control_plane.service_account_contracts import (
    ControlPlaneServiceAccountRegistrySnapshot,
)
from phoenix_os.control_plane.service_account_lifecycle import (
    ControlPlaneServiceAccountLifecycleSnapshot,
)
from phoenix_os.control_plane.service_account_replay import (
    ControlPlaneServiceAccountReplayRejectionReason,
    ControlPlaneServiceAccountReplaySnapshot,
)
from phoenix_os.control_plane.service_account_throttling import (
    ControlPlaneServiceAccountThrottleBlockReason,
    ControlPlaneServiceAccountThrottleSnapshot,
)


class ControlPlaneServiceAccountHealth(StrEnum):
    """Coarse service-account subsystem health."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    STOPPED = "stopped"


@dataclass(frozen=True, slots=True)
class ControlPlaneServiceAccountMetricsSnapshot:
    """Identifier-free cumulative service-account metrics."""

    accounts: int
    active_accounts: int
    disabled_accounts: int
    revoked_accounts: int
    tokens: int
    active_tokens: int
    revoked_tokens: int
    expired_tokens: int

    accounts_created: int
    accounts_updated: int
    tokens_issued: int

    client_authentication_attempts: int
    account_authentication_attempts: int
    client_authentication_blocks: int
    account_authentication_blocks: int
    throttle_capacity_blocks: int
    tracked_clients: int
    tracked_accounts: int

    replay_attempts: int
    replay_accepted: int
    replay_rejections: int
    tracked_replay_requests: int

    audit_emitted: int
    audit_dropped: int

    schema_version: int = 1

    def __post_init__(self) -> None:
        counters = (
            self.accounts,
            self.active_accounts,
            self.disabled_accounts,
            self.revoked_accounts,
            self.tokens,
            self.active_tokens,
            self.revoked_tokens,
            self.expired_tokens,
            self.accounts_created,
            self.accounts_updated,
            self.tokens_issued,
            self.client_authentication_attempts,
            self.account_authentication_attempts,
            self.client_authentication_blocks,
            self.account_authentication_blocks,
            self.throttle_capacity_blocks,
            self.tracked_clients,
            self.tracked_accounts,
            self.replay_attempts,
            self.replay_accepted,
            self.replay_rejections,
            self.tracked_replay_requests,
            self.audit_emitted,
            self.audit_dropped,
        )

        if any(value < 0 for value in counters):
            raise ValueError("service-account metrics cannot be negative")

        if self.active_accounts + self.disabled_accounts + self.revoked_accounts != self.accounts:
            raise ValueError("service-account metric account totals are inconsistent")

        if self.active_tokens + self.revoked_tokens + self.expired_tokens != self.tokens:
            raise ValueError("service-account metric token totals are inconsistent")

        if self.replay_accepted + self.replay_rejections != self.replay_attempts:
            raise ValueError("service-account replay metric totals are inconsistent")

        if self.schema_version != 1:
            raise ValueError("unsupported service-account metrics snapshot schema version")


@dataclass(frozen=True, slots=True)
class ControlPlaneServiceAccountHealthSnapshot:
    """Safe coarse health and fixed diagnostic categories."""

    status: ControlPlaneServiceAccountHealth
    registry_available: bool
    lifecycle_available: bool
    throttling_available: bool
    replay_protection_available: bool
    audit_delivery_healthy: bool
    capacity_protection_healthy: bool

    last_throttle_block: ControlPlaneServiceAccountThrottleBlockReason | None = None
    last_replay_rejection: ControlPlaneServiceAccountReplayRejectionReason | None = None
    last_audit_event: ControlPlaneServiceAccountAuditEvent | None = None

    schema_version: int = 1

    def __post_init__(self) -> None:
        flags = (
            self.registry_available,
            self.lifecycle_available,
            self.throttling_available,
            self.replay_protection_available,
            self.audit_delivery_healthy,
            self.capacity_protection_healthy,
        )

        if any(not isinstance(value, bool) for value in flags):
            raise TypeError("service-account health flags must be bool")

        status = ControlPlaneServiceAccountHealth(self.status)

        throttle_block = (
            None
            if self.last_throttle_block is None
            else ControlPlaneServiceAccountThrottleBlockReason(self.last_throttle_block)
        )

        replay_rejection = (
            None
            if self.last_replay_rejection is None
            else ControlPlaneServiceAccountReplayRejectionReason(self.last_replay_rejection)
        )

        audit_event = (
            None
            if self.last_audit_event is None
            else ControlPlaneServiceAccountAuditEvent(self.last_audit_event)
        )

        expected = _derive_health(
            registry_available=self.registry_available,
            lifecycle_available=self.lifecycle_available,
            throttling_available=self.throttling_available,
            replay_protection_available=(self.replay_protection_available),
            audit_delivery_healthy=(self.audit_delivery_healthy),
            capacity_protection_healthy=(self.capacity_protection_healthy),
        )

        if status is not expected:
            raise ValueError("service-account health status does not match component state")

        if self.schema_version != 1:
            raise ValueError("unsupported service-account health snapshot schema version")

        object.__setattr__(
            self,
            "status",
            status,
        )
        object.__setattr__(
            self,
            "last_throttle_block",
            throttle_block,
        )
        object.__setattr__(
            self,
            "last_replay_rejection",
            replay_rejection,
        )
        object.__setattr__(
            self,
            "last_audit_event",
            audit_event,
        )


@dataclass(frozen=True, slots=True)
class ControlPlaneServiceAccountObservabilitySnapshot:
    """Safe combined health and metrics snapshot."""

    health: ControlPlaneServiceAccountHealthSnapshot
    metrics: ControlPlaneServiceAccountMetricsSnapshot
    schema_version: int = 1

    def __post_init__(self) -> None:
        if not isinstance(
            self.health,
            ControlPlaneServiceAccountHealthSnapshot,
        ):
            raise TypeError("service-account observability requires a health snapshot")

        if not isinstance(
            self.metrics,
            ControlPlaneServiceAccountMetricsSnapshot,
        ):
            raise TypeError("service-account observability requires a metrics snapshot")

        if self.schema_version != 1:
            raise ValueError("unsupported service-account observability snapshot schema version")


class _RegistrySnapshotSource(Protocol):
    async def snapshot(
        self,
    ) -> ControlPlaneServiceAccountRegistrySnapshot: ...


class _LifecycleSnapshotSource(Protocol):
    async def snapshot(
        self,
    ) -> ControlPlaneServiceAccountLifecycleSnapshot: ...


class _ThrottleSnapshotSource(Protocol):
    async def snapshot(
        self,
    ) -> ControlPlaneServiceAccountThrottleSnapshot: ...


class _ReplaySnapshotSource(Protocol):
    async def snapshot(
        self,
    ) -> ControlPlaneServiceAccountReplaySnapshot: ...


class _AuditSnapshotSource(Protocol):
    async def snapshot(
        self,
    ) -> ControlPlaneServiceAccountAuditSnapshot: ...


class ControlPlaneServiceAccountObservability:
    """Aggregate only reviewed service-account snapshots."""

    def __init__(
        self,
        *,
        registry: _RegistrySnapshotSource,
        lifecycle: _LifecycleSnapshotSource,
        throttle: _ThrottleSnapshotSource,
        replay: _ReplaySnapshotSource,
        audit: _AuditSnapshotSource,
    ) -> None:
        for source, label in (
            (
                registry,
                "registry",
            ),
            (
                lifecycle,
                "lifecycle",
            ),
            (
                throttle,
                "throttle",
            ),
            (
                replay,
                "replay",
            ),
            (
                audit,
                "audit",
            ),
        ):
            if not callable(
                getattr(
                    source,
                    "snapshot",
                    None,
                )
            ):
                raise TypeError(f"service-account observability {label} source is invalid")

        self._registry = registry
        self._lifecycle = lifecycle
        self._throttle = throttle
        self._replay = replay
        self._audit = audit

    async def snapshot(
        self,
    ) -> ControlPlaneServiceAccountObservabilitySnapshot:
        registry = await self._registry.snapshot()
        lifecycle = await self._lifecycle.snapshot()
        throttle = await self._throttle.snapshot()
        replay = await self._replay.snapshot()
        audit = await self._audit.snapshot()

        replay_rejections = (
            replay.replay_rejections
            + replay.nonce_reuse_rejections
            + replay.stale_rejections
            + replay.future_rejections
            + replay.capacity_rejections
        )

        metrics = ControlPlaneServiceAccountMetricsSnapshot(
            accounts=registry.accounts,
            active_accounts=registry.active_accounts,
            disabled_accounts=registry.disabled_accounts,
            revoked_accounts=registry.revoked_accounts,
            tokens=registry.tokens,
            active_tokens=registry.active_tokens,
            revoked_tokens=registry.revoked_tokens,
            expired_tokens=registry.expired_tokens,
            accounts_created=lifecycle.accounts_created,
            accounts_updated=lifecycle.accounts_updated,
            tokens_issued=lifecycle.tokens_issued,
            client_authentication_attempts=(throttle.client_attempts),
            account_authentication_attempts=(throttle.account_attempts),
            client_authentication_blocks=(throttle.client_blocks),
            account_authentication_blocks=(throttle.account_blocks),
            throttle_capacity_blocks=(throttle.capacity_blocks),
            tracked_clients=throttle.tracked_clients,
            tracked_accounts=throttle.tracked_accounts,
            replay_attempts=replay.attempts,
            replay_accepted=replay.accepted,
            replay_rejections=replay_rejections,
            tracked_replay_requests=(replay.tracked_requests),
            audit_emitted=audit.emitted,
            audit_dropped=audit.dropped,
        )

        capacity_healthy = throttle.capacity_blocks == 0 and replay.capacity_rejections == 0

        health = ControlPlaneServiceAccountHealthSnapshot(
            status=_derive_health(
                registry_available=not registry.closed,
                lifecycle_available=not lifecycle.closed,
                throttling_available=not throttle.closed,
                replay_protection_available=not replay.closed,
                audit_delivery_healthy=audit.dropped == 0,
                capacity_protection_healthy=(capacity_healthy),
            ),
            registry_available=not registry.closed,
            lifecycle_available=not lifecycle.closed,
            throttling_available=not throttle.closed,
            replay_protection_available=not replay.closed,
            audit_delivery_healthy=audit.dropped == 0,
            capacity_protection_healthy=capacity_healthy,
            last_throttle_block=throttle.last_block,
            last_replay_rejection=(replay.last_rejection),
            last_audit_event=audit.last_event,
        )

        return ControlPlaneServiceAccountObservabilitySnapshot(
            health=health,
            metrics=metrics,
        )


def control_plane_service_account_observability_to_dict(
    snapshot: ControlPlaneServiceAccountObservabilitySnapshot,
) -> dict[str, object]:
    """Serialize through an explicit identifier-free allowlist."""

    if not isinstance(
        snapshot,
        ControlPlaneServiceAccountObservabilitySnapshot,
    ):
        raise TypeError("service-account observability serializer requires a trusted snapshot")

    health = snapshot.health
    metrics = snapshot.metrics

    return {
        "schema_version": snapshot.schema_version,
        "health": {
            "schema_version": health.schema_version,
            "status": health.status.value,
            "registry_available": health.registry_available,
            "lifecycle_available": (health.lifecycle_available),
            "throttling_available": (health.throttling_available),
            "replay_protection_available": (health.replay_protection_available),
            "audit_delivery_healthy": (health.audit_delivery_healthy),
            "capacity_protection_healthy": (health.capacity_protection_healthy),
            "last_throttle_block": _optional_value(health.last_throttle_block),
            "last_replay_rejection": _optional_value(health.last_replay_rejection),
            "last_audit_event": _optional_value(health.last_audit_event),
        },
        "metrics": {
            "schema_version": metrics.schema_version,
            "accounts": metrics.accounts,
            "active_accounts": metrics.active_accounts,
            "disabled_accounts": metrics.disabled_accounts,
            "revoked_accounts": metrics.revoked_accounts,
            "tokens": metrics.tokens,
            "active_tokens": metrics.active_tokens,
            "revoked_tokens": metrics.revoked_tokens,
            "expired_tokens": metrics.expired_tokens,
            "accounts_created": metrics.accounts_created,
            "accounts_updated": metrics.accounts_updated,
            "tokens_issued": metrics.tokens_issued,
            "client_authentication_attempts": (metrics.client_authentication_attempts),
            "account_authentication_attempts": (metrics.account_authentication_attempts),
            "client_authentication_blocks": (metrics.client_authentication_blocks),
            "account_authentication_blocks": (metrics.account_authentication_blocks),
            "throttle_capacity_blocks": (metrics.throttle_capacity_blocks),
            "tracked_clients": metrics.tracked_clients,
            "tracked_accounts": metrics.tracked_accounts,
            "replay_attempts": metrics.replay_attempts,
            "replay_accepted": metrics.replay_accepted,
            "replay_rejections": metrics.replay_rejections,
            "tracked_replay_requests": (metrics.tracked_replay_requests),
            "audit_emitted": metrics.audit_emitted,
            "audit_dropped": metrics.audit_dropped,
        },
    }


def _derive_health(
    *,
    registry_available: bool,
    lifecycle_available: bool,
    throttling_available: bool,
    replay_protection_available: bool,
    audit_delivery_healthy: bool,
    capacity_protection_healthy: bool,
) -> ControlPlaneServiceAccountHealth:
    availability = (
        registry_available,
        lifecycle_available,
        throttling_available,
        replay_protection_available,
    )

    if not any(availability):
        return ControlPlaneServiceAccountHealth.STOPPED

    if not all(availability) or not audit_delivery_healthy or not capacity_protection_healthy:
        return ControlPlaneServiceAccountHealth.DEGRADED

    return ControlPlaneServiceAccountHealth.HEALTHY


def _optional_value(
    value: StrEnum | None,
) -> str | None:
    return None if value is None else value.value
