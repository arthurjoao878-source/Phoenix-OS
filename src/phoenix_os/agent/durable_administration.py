"""Least-privilege content-free administration for durable agent runs."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Protocol, runtime_checkable

from phoenix_os.agent.durable_authorization import durable_agent_run_resource
from phoenix_os.agent.durable_compatibility import (
    DurableCompatibilityCategory,
    DurableCompatibilityValidator,
)
from phoenix_os.agent.durable_contracts import (
    MAX_DURABLE_LIFETIME,
    CheckpointEnvelope,
    CheckpointPayloadProfile,
    DurableAgentRunId,
    DurableLease,
    DurableRunStatus,
    DurableRunStore,
)
from phoenix_os.agent.durable_lease import DurableLeaseManager
from phoenix_os.agent.durable_observer import (
    DurableRunObserver,
    DurableRunObserverSnapshot,
)
from phoenix_os.agent.durable_retention_worker import (
    DurableRetentionWorker,
    DurableRetentionWorkerSnapshot,
    DurableRetentionWorkerState,
)
from phoenix_os.agent.durable_worker import (
    DurableRecoveryWorker,
    DurableRecoveryWorkerSnapshot,
    DurableRecoveryWorkerState,
)
from phoenix_os.agent.errors import (
    AgentAdministrationAccessDeniedError,
    AgentServiceUnavailableError,
    AgentStateConflictError,
)
from phoenix_os.policy import PrincipalType, SecurityContext

AGENT_DURABLE_READ_ACTION = "agent.durable.read"
AGENT_DURABLE_HEALTH_READ_ACTION = "agent.durable.health.read"
DURABLE_ADMINISTRATION_HEALTH_RESOURCE = "durable-agent-runs:health"

MAX_DURABLE_ADMINISTRATION_AGE_SECONDS = int(MAX_DURABLE_LIFETIME.total_seconds())
MAX_DURABLE_ADMINISTRATION_COUNT = 2_147_483_647


def _require_bounded_count(value: int, *, label: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{label} must be an integer")
    if value < 0 or value > MAX_DURABLE_ADMINISTRATION_COUNT:
        raise ValueError(f"{label} is outside the administration bound")


def _bounded_count(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise AgentStateConflictError()
    return min(value, MAX_DURABLE_ADMINISTRATION_COUNT)


class DurablePauseCategory(StrEnum):
    """Safe pause classification without approval or continuation content."""

    NONE = "none"
    APPROVAL = "approval"
    OPERATOR = "operator"
    SHUTDOWN = "shutdown"


class DurableRetentionCategory(StrEnum):
    """Safe classification against the checkpoint retention deadline."""

    RETAINED = "retained"
    EXPIRED = "expired"


class DurableIndeterminateCategory(StrEnum):
    """Safe external-attempt uncertainty category."""

    NONE = "none"
    MODEL = "model"
    TOOL = "tool"


@dataclass(frozen=True, slots=True)
class DurableAdministrationConfiguration:
    """Explicit exposure controls for durable administration."""

    machine_administration_enabled: bool = False
    schema_version: int = 1

    def __post_init__(self) -> None:
        if type(self.machine_administration_enabled) is not bool:
            raise TypeError("machine_administration_enabled must be bool")
        if self.schema_version != 1:
            raise ValueError("unsupported durable administration configuration version")


@dataclass(frozen=True, slots=True)
class DurableRunAdministrationView:
    """RFC-0028 content-free state for one exact durable run."""

    run_id: DurableAgentRunId
    status: DurableRunStatus
    pause_category: DurablePauseCategory
    checkpoint_sequence: int
    age_seconds: int
    retention_category: DurableRetentionCategory
    payload_profile: CheckpointPayloadProfile
    lease_present: bool
    fencing_generation: int | None
    indeterminate_category: DurableIndeterminateCategory
    compatibility_category: DurableCompatibilityCategory
    schema_version: int = 1

    def __post_init__(self) -> None:
        if not isinstance(self.run_id, DurableAgentRunId):
            raise TypeError("run_id must be DurableAgentRunId")
        if not isinstance(self.status, DurableRunStatus):
            raise TypeError("status must be DurableRunStatus")
        if not isinstance(self.pause_category, DurablePauseCategory):
            raise TypeError("pause_category must be DurablePauseCategory")
        if not isinstance(self.retention_category, DurableRetentionCategory):
            raise TypeError("retention_category must be DurableRetentionCategory")
        if not isinstance(self.payload_profile, CheckpointPayloadProfile):
            raise TypeError("payload_profile must be CheckpointPayloadProfile")
        if not isinstance(self.indeterminate_category, DurableIndeterminateCategory):
            raise TypeError("indeterminate_category must be DurableIndeterminateCategory")
        if not isinstance(self.compatibility_category, DurableCompatibilityCategory):
            raise TypeError("compatibility_category must be DurableCompatibilityCategory")

        if isinstance(self.checkpoint_sequence, bool) or not isinstance(
            self.checkpoint_sequence,
            int,
        ):
            raise TypeError("checkpoint_sequence must be an integer")
        if self.checkpoint_sequence <= 0:
            raise ValueError("checkpoint_sequence must be positive")

        if isinstance(self.age_seconds, bool) or not isinstance(self.age_seconds, int):
            raise TypeError("age_seconds must be an integer")
        if self.age_seconds < 0 or self.age_seconds > MAX_DURABLE_ADMINISTRATION_AGE_SECONDS:
            raise ValueError("age_seconds is outside the administration bound")

        if type(self.lease_present) is not bool:
            raise TypeError("lease_present must be bool")
        if self.lease_present != (self.fencing_generation is not None):
            raise ValueError("lease presence and fencing generation are inconsistent")
        if self.fencing_generation is not None:
            if isinstance(self.fencing_generation, bool) or not isinstance(
                self.fencing_generation,
                int,
            ):
                raise TypeError("fencing_generation must be an integer or None")
            if self.fencing_generation <= 0:
                raise ValueError("fencing_generation must be positive")

        if self.schema_version != 1:
            raise ValueError("unsupported durable administration view version")


@dataclass(frozen=True, slots=True)
class DurableRecoveryAdministrationHealth:
    """Bounded recovery health without timestamps or run identifiers."""

    state: DurableRecoveryWorkerState
    active: int
    passes_started: int
    passes_completed: int
    passes_failed: int
    passes_timed_out: int
    passes_stopped: int
    candidates_admitted: int
    assessed: int
    conflicts: int
    failed: int
    forced_cancellations: int
    schema_version: int = 1

    def __post_init__(self) -> None:
        if not isinstance(self.state, DurableRecoveryWorkerState):
            raise TypeError("state must be DurableRecoveryWorkerState")
        for label, value in (
            ("active", self.active),
            ("passes_started", self.passes_started),
            ("passes_completed", self.passes_completed),
            ("passes_failed", self.passes_failed),
            ("passes_timed_out", self.passes_timed_out),
            ("passes_stopped", self.passes_stopped),
            ("candidates_admitted", self.candidates_admitted),
            ("assessed", self.assessed),
            ("conflicts", self.conflicts),
            ("failed", self.failed),
            ("forced_cancellations", self.forced_cancellations),
        ):
            _require_bounded_count(value, label=label)
        if self.schema_version != 1:
            raise ValueError("unsupported recovery administration health version")

    @property
    def degraded(self) -> bool:
        return (
            self.passes_failed > 0
            or self.passes_timed_out > 0
            or self.failed > 0
            or self.forced_cancellations > 0
        )


@dataclass(frozen=True, slots=True)
class DurableRetentionAdministrationHealth:
    """Bounded retention health without timestamps or run identifiers."""

    state: DurableRetentionWorkerState
    passes_started: int
    passes_completed: int
    passes_timed_out: int
    passes_failed: int
    passes_stopped: int
    schema_version: int = 1

    def __post_init__(self) -> None:
        if not isinstance(self.state, DurableRetentionWorkerState):
            raise TypeError("state must be DurableRetentionWorkerState")
        for label, value in (
            ("passes_started", self.passes_started),
            ("passes_completed", self.passes_completed),
            ("passes_timed_out", self.passes_timed_out),
            ("passes_failed", self.passes_failed),
            ("passes_stopped", self.passes_stopped),
        ):
            _require_bounded_count(value, label=label)
        if self.schema_version != 1:
            raise ValueError("unsupported retention administration health version")

    @property
    def degraded(self) -> bool:
        return self.passes_failed > 0 or self.passes_timed_out > 0


@dataclass(frozen=True, slots=True)
class DurableObserverAdministrationHealth:
    """Bounded observer health without correlation identifiers."""

    observations: int
    event_failures: int
    audit_failures: int
    observability_failures: int
    schema_version: int = 1

    def __post_init__(self) -> None:
        for label, value in (
            ("observations", self.observations),
            ("event_failures", self.event_failures),
            ("audit_failures", self.audit_failures),
            ("observability_failures", self.observability_failures),
        ):
            _require_bounded_count(value, label=label)
        if self.schema_version != 1:
            raise ValueError("unsupported observer administration health version")

    @property
    def degraded(self) -> bool:
        return self.event_failures > 0 or self.audit_failures > 0 or self.observability_failures > 0


@dataclass(frozen=True, slots=True)
class DurableAdministrationSnapshot:
    """Content-free durable storage and bounded subsystem health."""

    store_open: bool
    lease_manager_open: bool
    recovery: DurableRecoveryAdministrationHealth | None = None
    retention: DurableRetentionAdministrationHealth | None = None
    observer: DurableObserverAdministrationHealth | None = None
    schema_version: int = 1

    def __post_init__(self) -> None:
        if type(self.store_open) is not bool:
            raise TypeError("store_open must be bool")
        if type(self.lease_manager_open) is not bool:
            raise TypeError("lease_manager_open must be bool")
        if self.recovery is not None and not isinstance(
            self.recovery,
            DurableRecoveryAdministrationHealth,
        ):
            raise TypeError("recovery must be DurableRecoveryAdministrationHealth or None")
        if self.retention is not None and not isinstance(
            self.retention,
            DurableRetentionAdministrationHealth,
        ):
            raise TypeError("retention must be DurableRetentionAdministrationHealth or None")
        if self.observer is not None and not isinstance(
            self.observer,
            DurableObserverAdministrationHealth,
        ):
            raise TypeError("observer must be DurableObserverAdministrationHealth or None")
        if self.schema_version != 1:
            raise ValueError("unsupported durable administration snapshot version")

    @property
    def degraded(self) -> bool:
        return (
            not self.store_open
            or not self.lease_manager_open
            or (self.recovery is not None and self.recovery.degraded)
            or (self.retention is not None and self.retention.degraded)
            or (self.observer is not None and self.observer.degraded)
        )


@runtime_checkable
class DurableMachineAdministrationGuard(Protocol):
    """Trusted outer boundary for exact machine scope-and-resource authorization."""

    async def authorize(
        self,
        context: SecurityContext,
        *,
        action: str,
        resource: str,
    ) -> None: ...


class DurableRunAdministration:
    """Expose read-only durable run state without persisted content or authority."""

    def __init__(
        self,
        *,
        store: DurableRunStore,
        lease_manager: DurableLeaseManager,
        compatibility_validator: DurableCompatibilityValidator,
        configuration: DurableAdministrationConfiguration | None = None,
        recovery_worker: DurableRecoveryWorker | None = None,
        retention_worker: DurableRetentionWorker | None = None,
        observer: DurableRunObserver | None = None,
        machine_guard: DurableMachineAdministrationGuard | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not isinstance(store, DurableRunStore):
            raise TypeError("store must implement DurableRunStore")
        if not isinstance(lease_manager, DurableLeaseManager):
            raise TypeError("lease_manager must implement DurableLeaseManager")
        if not isinstance(compatibility_validator, DurableCompatibilityValidator):
            raise TypeError("compatibility_validator must implement DurableCompatibilityValidator")
        if recovery_worker is not None and not isinstance(
            recovery_worker,
            DurableRecoveryWorker,
        ):
            raise TypeError("recovery_worker must implement DurableRecoveryWorker")
        if retention_worker is not None and not isinstance(
            retention_worker,
            DurableRetentionWorker,
        ):
            raise TypeError("retention_worker must implement DurableRetentionWorker")
        if observer is not None and not isinstance(observer, DurableRunObserver):
            raise TypeError("observer must implement DurableRunObserver")
        if machine_guard is not None and not isinstance(
            machine_guard,
            DurableMachineAdministrationGuard,
        ):
            raise TypeError("machine_guard must implement DurableMachineAdministrationGuard")

        selected_configuration = (
            DurableAdministrationConfiguration() if configuration is None else configuration
        )
        if not isinstance(
            selected_configuration,
            DurableAdministrationConfiguration,
        ):
            raise TypeError("configuration must be DurableAdministrationConfiguration")
        if selected_configuration.machine_administration_enabled and machine_guard is None:
            raise ValueError("enabled machine administration requires a machine guard")

        selected_clock = (lambda: datetime.now(UTC)) if clock is None else clock
        if not callable(selected_clock):
            raise TypeError("clock must be callable")

        bound_lease_manager = getattr(store, "lease_manager", None)
        if bound_lease_manager is not None and bound_lease_manager is not lease_manager:
            raise ValueError("lease_manager must match the durable store lease manager")

        self._store = store
        self._lease_manager = lease_manager
        self._compatibility_validator = compatibility_validator
        self._configuration = selected_configuration
        self._recovery_worker = recovery_worker
        self._retention_worker = retention_worker
        self._observer = observer
        self._machine_guard = machine_guard
        self._clock: Callable[[], datetime] = selected_clock

    async def run(
        self,
        run_id: DurableAgentRunId,
        context: SecurityContext,
    ) -> DurableRunAdministrationView | None:
        """Return one exact content-free run view after read authorization."""

        if not isinstance(run_id, DurableAgentRunId):
            raise TypeError("run_id must be DurableAgentRunId")

        resource = durable_agent_run_resource(run_id)
        await self._authorize(
            context,
            action=AGENT_DURABLE_READ_ACTION,
            resource=resource,
        )

        now = self._now()
        try:
            checkpoint = await self._store.get_current(run_id)
            if checkpoint is None:
                return None
            if checkpoint.durable_run_id != run_id or now < checkpoint.created_at:
                raise AgentStateConflictError()

            compatibility = self._compatibility_validator.validate(checkpoint)
            lease = await self._lease_manager.get_current(run_id, now=now)
            return _run_view(
                checkpoint,
                lease=lease,
                compatibility_category=compatibility.category,
                now=now,
            )
        except AgentStateConflictError:
            raise
        except Exception:
            raise AgentServiceUnavailableError() from None

    async def snapshot(
        self,
        context: SecurityContext,
    ) -> DurableAdministrationSnapshot:
        """Return bounded storage, worker, and observer health only."""

        await self._authorize(
            context,
            action=AGENT_DURABLE_HEALTH_READ_ACTION,
            resource=DURABLE_ADMINISTRATION_HEALTH_RESOURCE,
        )

        try:
            recovery_snapshot = (
                None if self._recovery_worker is None else await self._recovery_worker.snapshot()
            )
            retention_snapshot = (
                None if self._retention_worker is None else await self._retention_worker.snapshot()
            )
            observer_snapshot = None if self._observer is None else await self._observer.snapshot()

            return DurableAdministrationSnapshot(
                store_open=not self._store.closed,
                lease_manager_open=not self._lease_manager.closed,
                recovery=(
                    None if recovery_snapshot is None else _recovery_health(recovery_snapshot)
                ),
                retention=(
                    None if retention_snapshot is None else _retention_health(retention_snapshot)
                ),
                observer=(
                    None if observer_snapshot is None else _observer_health(observer_snapshot)
                ),
            )
        except Exception:
            raise AgentServiceUnavailableError() from None

    async def _authorize(
        self,
        context: SecurityContext,
        *,
        action: str,
        resource: str,
    ) -> None:
        if not isinstance(context, SecurityContext):
            raise TypeError("context must be SecurityContext")
        if not context.authenticated:
            raise AgentAdministrationAccessDeniedError()

        if context.principal_type is PrincipalType.SERVICE:
            if (
                not self._configuration.machine_administration_enabled
                or self._machine_guard is None
                or action not in context.scopes
            ):
                raise AgentAdministrationAccessDeniedError()
            try:
                await self._machine_guard.authorize(
                    context,
                    action=action,
                    resource=resource,
                )
            except Exception:
                raise AgentAdministrationAccessDeniedError() from None
            return

        if context.principal_type is not PrincipalType.USER:
            raise AgentAdministrationAccessDeniedError()
        if action not in context.permissions and "*" not in context.permissions:
            raise AgentAdministrationAccessDeniedError()

    def _now(self) -> datetime:
        try:
            value = self._clock()
        except Exception:
            raise AgentServiceUnavailableError() from None
        if not isinstance(value, datetime):
            raise AgentServiceUnavailableError()
        if value.tzinfo is None or value.utcoffset() is None:
            raise AgentServiceUnavailableError()
        return value


def _run_view(
    checkpoint: CheckpointEnvelope,
    *,
    lease: DurableLease | None,
    compatibility_category: DurableCompatibilityCategory,
    now: datetime,
) -> DurableRunAdministrationView:
    return DurableRunAdministrationView(
        run_id=checkpoint.durable_run_id,
        status=checkpoint.status,
        pause_category=_pause_category(checkpoint.status),
        checkpoint_sequence=checkpoint.sequence.value,
        age_seconds=min(
            MAX_DURABLE_ADMINISTRATION_AGE_SECONDS,
            int((now - checkpoint.metadata.budget.started_at).total_seconds()),
        ),
        retention_category=(
            DurableRetentionCategory.EXPIRED
            if now >= checkpoint.metadata.retention_deadline
            else DurableRetentionCategory.RETAINED
        ),
        payload_profile=checkpoint.metadata.payload_profile,
        lease_present=lease is not None,
        fencing_generation=None if lease is None else lease.generation.value,
        indeterminate_category=_indeterminate_category(checkpoint.status),
        compatibility_category=compatibility_category,
    )


def _recovery_health(
    snapshot: DurableRecoveryWorkerSnapshot,
) -> DurableRecoveryAdministrationHealth:
    return DurableRecoveryAdministrationHealth(
        state=snapshot.state,
        active=_bounded_count(snapshot.active),
        passes_started=_bounded_count(snapshot.passes_started),
        passes_completed=_bounded_count(snapshot.passes_completed),
        passes_failed=_bounded_count(snapshot.passes_failed),
        passes_timed_out=_bounded_count(snapshot.passes_timed_out),
        passes_stopped=_bounded_count(snapshot.passes_stopped),
        candidates_admitted=_bounded_count(snapshot.candidates_admitted),
        assessed=_bounded_count(snapshot.assessed),
        conflicts=_bounded_count(snapshot.conflicts),
        failed=_bounded_count(snapshot.failed),
        forced_cancellations=_bounded_count(snapshot.forced_cancellations),
    )


def _retention_health(
    snapshot: DurableRetentionWorkerSnapshot,
) -> DurableRetentionAdministrationHealth:
    return DurableRetentionAdministrationHealth(
        state=snapshot.state,
        passes_started=_bounded_count(snapshot.passes_started),
        passes_completed=_bounded_count(snapshot.passes_completed),
        passes_timed_out=_bounded_count(snapshot.passes_timed_out),
        passes_failed=_bounded_count(snapshot.passes_failed),
        passes_stopped=_bounded_count(snapshot.passes_stopped),
    )


def _observer_health(
    snapshot: DurableRunObserverSnapshot,
) -> DurableObserverAdministrationHealth:
    return DurableObserverAdministrationHealth(
        observations=_bounded_count(snapshot.observations),
        event_failures=_bounded_count(snapshot.event_failures),
        audit_failures=_bounded_count(snapshot.audit_failures),
        observability_failures=_bounded_count(snapshot.observability_failures),
    )


def _pause_category(status: DurableRunStatus) -> DurablePauseCategory:
    if status is DurableRunStatus.PAUSED_APPROVAL:
        return DurablePauseCategory.APPROVAL
    if status is DurableRunStatus.PAUSED_OPERATOR:
        return DurablePauseCategory.OPERATOR
    if status is DurableRunStatus.PAUSED_SHUTDOWN:
        return DurablePauseCategory.SHUTDOWN
    return DurablePauseCategory.NONE


def _indeterminate_category(
    status: DurableRunStatus,
) -> DurableIndeterminateCategory:
    if status is DurableRunStatus.INDETERMINATE_MODEL:
        return DurableIndeterminateCategory.MODEL
    if status is DurableRunStatus.INDETERMINATE_TOOL:
        return DurableIndeterminateCategory.TOOL
    return DurableIndeterminateCategory.NONE
