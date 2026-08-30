"""Internal reliability contracts for RFC-0037 durable-run hardening."""

from __future__ import annotations

from collections.abc import Awaitable
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Protocol, runtime_checkable

from phoenix_os.agent.durable_contracts import (
    DurableAgentRunId,
    DurableLease,
    DurableRunLimits,
)


class DurableMutationOutcome(StrEnum):
    """Internal classification of one durable mutation's proven commit outcome."""

    CONFIRMED_COMMITTED = "CONFIRMED_COMMITTED"
    CONFIRMED_NOT_COMMITTED = "CONFIRMED_NOT_COMMITTED"
    COMMIT_OUTCOME_UNKNOWN = "COMMIT_OUTCOME_UNKNOWN"


class ReliabilityFaultPoint(StrEnum):
    """Fixed Phoenix-owned deterministic fault points defined by RFC-0037."""

    CHECKPOINT_BEFORE_ENCODE = "checkpoint.before_encode"
    CHECKPOINT_AFTER_ENCODE = "checkpoint.after_encode"
    CHECKPOINT_BEFORE_STORE_MUTATION = "checkpoint.before_store_mutation"
    CHECKPOINT_AFTER_STORE_COMMIT_BEFORE_ACK = "checkpoint.after_store_commit_before_ack"
    CHECKPOINT_AFTER_ACK = "checkpoint.after_ack"

    LEASE_BEFORE_ACQUIRE = "lease.before_acquire"
    LEASE_AFTER_ACQUIRE = "lease.after_acquire"
    LEASE_BEFORE_RENEW = "lease.before_renew"
    LEASE_AFTER_RENEW = "lease.after_renew"

    RECOVERY_AFTER_CANDIDATE_READ = "recovery.after_candidate_read"
    RECOVERY_AFTER_LEASE_ACQUIRE = "recovery.after_lease_acquire"
    RECOVERY_AFTER_REREAD = "recovery.after_reread"
    RECOVERY_AFTER_LIVE_REVALIDATION = "recovery.after_live_revalidation"
    RECOVERY_BEFORE_TRANSITION = "recovery.before_transition"
    RECOVERY_AFTER_TRANSITION_COMMIT = "recovery.after_transition_commit"

    ATTEMPT_AFTER_PREPARED = "attempt.after_prepared"
    ATTEMPT_AFTER_STARTED = "attempt.after_started"
    ATTEMPT_AFTER_EXTERNAL_RETURN_BEFORE_TERMINAL_RECORD = (
        "attempt.after_external_return_before_terminal_record"
    )

    RECONCILE_BEFORE_MUTATION = "reconcile.before_mutation"
    RECONCILE_AFTER_MUTATION_COMMIT = "reconcile.after_mutation_commit"

    RETENTION_BEFORE_DELETE = "retention.before_delete"
    RETENTION_AFTER_DELETE_COMMIT = "retention.after_delete_commit"

    SHUTDOWN_AFTER_ADMISSION_STOP = "shutdown.after_admission_stop"


@runtime_checkable
class ReliabilityFaultInjector(Protocol):
    """Internal, content-free deterministic fault-injection seam."""

    def inject(self, point: ReliabilityFaultPoint, /) -> None:
        """Reach one fixed Phoenix-owned fault point."""


MAX_DURABLE_STORE_GENERATION = (1 << 63) - 1


class DurableStoreFreshnessCategory(StrEnum):
    """Content-free classification of durable-store restore freshness."""

    CURRENT = "current"
    ROLLBACK_DETECTED = "rollback-detected"
    STORE_IDENTITY_MISMATCH = "store-identity-mismatch"
    WITNESS_UNAVAILABLE = "witness-unavailable"


@dataclass(frozen=True, slots=True)
class DurableStoreFreshnessSnapshot:
    """Bounded restore-generation evidence safe for administration diagnostics."""

    category: DurableStoreFreshnessCategory
    store_generation: int | None
    witness_generation: int | None

    def __post_init__(self) -> None:
        if not isinstance(self.category, DurableStoreFreshnessCategory):
            raise TypeError("category must be DurableStoreFreshnessCategory")
        for label, value in (
            ("store_generation", self.store_generation),
            ("witness_generation", self.witness_generation),
        ):
            if value is None:
                continue
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"{label} must be an integer or None")
            if value < 0 or value > MAX_DURABLE_STORE_GENERATION:
                raise ValueError(f"{label} is outside supported bounds")

    @property
    def automatic_recovery_available(self) -> bool:
        return self.category is DurableStoreFreshnessCategory.CURRENT


@runtime_checkable
class DurableStoreFreshnessSource(Protocol):
    "Read bounded restore-freshness evidence without exposing store identity."

    def get_store_freshness(self) -> Awaitable[DurableStoreFreshnessSnapshot]: ...


@runtime_checkable
class DurableRecoveryAttemptStore(Protocol):
    """Persist bounded per-run recovery-attempt bookkeeping outside checkpoints."""

    @property
    def limits(self) -> DurableRunLimits: ...

    def claim_recovery_attempt(
        self,
        run_id: DurableAgentRunId,
        *,
        lease: DurableLease,
        now: datetime,
    ) -> Awaitable[int]: ...

    def get_recovery_attempt_count(
        self,
        run_id: DurableAgentRunId,
    ) -> Awaitable[int]: ...


class NoOpReliabilityFaultInjector:
    """Production-safe implementation that never injects a failure."""

    __slots__ = ()

    def inject(self, point: ReliabilityFaultPoint, /) -> None:
        if not isinstance(point, ReliabilityFaultPoint):
            raise TypeError("point must be ReliabilityFaultPoint")


NOOP_RELIABILITY_FAULT_INJECTOR = NoOpReliabilityFaultInjector()
