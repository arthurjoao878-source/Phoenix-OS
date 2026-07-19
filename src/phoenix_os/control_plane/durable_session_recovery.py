"""Bounded recovery and lifecycle worker for overdue durable operator sessions."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum

from phoenix_os.control_plane.durable_session_contracts import (
    MAX_DURABLE_SESSION_PAGE_SIZE,
    ControlPlaneDurableSessionPageRequest,
    ControlPlaneDurableSessionRecord,
    ControlPlaneDurableSessionRepository,
    ControlPlaneDurableSessionStatus,
    ControlPlaneDurableSessionTerminationReason,
)
from phoenix_os.control_plane.errors import (
    ControlPlaneDurableSessionConflictError,
    ControlPlaneDurableSessionRecoveryWorkerStateError,
)
from phoenix_os.control_plane.operator_contracts import (
    ControlPlaneOperatorRecord,
    ControlPlaneOperatorRegistry,
    ControlPlaneOperatorStatus,
)

type ControlPlaneDurableSessionRecoveryClock = Callable[[], datetime]


def _utc_now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class ControlPlaneDurableSessionRecoveryBatch:
    """Safe counters and terminal records from one bounded recovery pass."""

    scanned: int
    eligible: int
    recovered: int
    healthy: int
    conflicts: int
    failures: int
    records: tuple[ControlPlaneDurableSessionRecord, ...] = ()

    def __post_init__(self) -> None:
        counters = (
            self.scanned,
            self.eligible,
            self.recovered,
            self.healthy,
            self.conflicts,
            self.failures,
        )
        if any(value < 0 for value in counters):
            raise ValueError("durable session recovery counters cannot be negative")
        if self.eligible > self.scanned or self.healthy > self.scanned:
            raise ValueError("durable session recovery counters exceed scanned count")
        if self.eligible + self.healthy != self.scanned:
            raise ValueError("durable session recovery decisions must equal scanned count")
        if self.recovered != len(self.records):
            raise ValueError("recovered durable session count must match records")
        if self.recovered + self.conflicts + self.failures != self.eligible:
            raise ValueError("durable session recovery outcomes must equal eligible count")
        if any(not record.status.terminal for record in self.records):
            raise ValueError("durable session recovery records must be terminal")


class ControlPlaneDurableSessionRecoveryService:
    """Reconcile persisted active sessions after downtime without plaintext credentials."""

    def __init__(
        self,
        *,
        repository: ControlPlaneDurableSessionRepository,
        registry: ControlPlaneOperatorRegistry,
        clock: ControlPlaneDurableSessionRecoveryClock = _utc_now,
    ) -> None:
        if not callable(clock):
            raise TypeError("durable session recovery clock must be callable")
        self._repository = repository
        self._registry = registry
        self._clock = clock

    async def recover(
        self,
        *,
        limit: int = 100,
        now: datetime | None = None,
    ) -> ControlPlaneDurableSessionRecoveryBatch:
        if limit <= 0 or limit > MAX_DURABLE_SESSION_PAGE_SIZE:
            raise ValueError(
                f"durable session recovery limit must be between 1 and "
                f"{MAX_DURABLE_SESSION_PAGE_SIZE}"
            )
        recovered_at = self._clock() if now is None else now
        _require_aware(recovered_at, "durable session recovery time")
        page = await self._repository.list_page(
            ControlPlaneDurableSessionPageRequest(
                limit=limit,
                status=ControlPlaneDurableSessionStatus.ACTIVE,
            )
        )
        recovered: list[ControlPlaneDurableSessionRecord] = []
        healthy = 0
        conflicts = 0
        failures = 0
        eligible = 0
        for record in reversed(page.items):
            try:
                operator = await self._registry.get(record.operator_id)
                reason = _recovery_reason(record, operator=operator, now=recovered_at)
            except asyncio.CancelledError:
                raise
            except Exception:
                eligible += 1
                failures += 1
                continue
            if reason is None:
                healthy += 1
                continue
            eligible += 1
            status = (
                ControlPlaneDurableSessionStatus.EXPIRED
                if reason.expiration
                else ControlPlaneDurableSessionStatus.REVOKED
            )
            try:
                updated = await self._repository.terminate(
                    record.id,
                    expected_revision=record.revision,
                    status=status,
                    reason=reason,
                    terminated_at=max(recovered_at, record.last_seen_at),
                )
            except asyncio.CancelledError:
                raise
            except ControlPlaneDurableSessionConflictError:
                conflicts += 1
            except Exception:
                failures += 1
            else:
                recovered.append(updated)
        return ControlPlaneDurableSessionRecoveryBatch(
            scanned=len(page.items),
            eligible=eligible,
            recovered=len(recovered),
            healthy=healthy,
            conflicts=conflicts,
            failures=failures,
            records=tuple(recovered),
        )


class ControlPlaneDurableSessionRecoveryWorkerState(StrEnum):
    CREATED = "created"
    RUNNING = "running"
    STOPPING = "stopping"
    STOPPED = "stopped"


@dataclass(frozen=True, slots=True)
class ControlPlaneDurableSessionRecoveryWorkerSnapshot:
    """Operational worker counters without tokens, digests, or exception text."""

    state: ControlPlaneDurableSessionRecoveryWorkerState
    worker: str
    ticks: int
    scanned: int
    recovered: int
    healthy: int
    conflicts: int
    failures: int
    last_tick_at: datetime | None = None
    last_error: str | None = None

    def __post_init__(self) -> None:
        worker = self.worker.strip()
        if not worker:
            raise ValueError("durable session recovery worker name must not be blank")
        if (
            min(
                self.ticks,
                self.scanned,
                self.recovered,
                self.healthy,
                self.conflicts,
                self.failures,
            )
            < 0
        ):
            raise ValueError("durable session recovery worker counters cannot be negative")
        if self.last_tick_at is not None:
            _require_aware(self.last_tick_at, "last_tick_at")
        error = None if self.last_error is None else self.last_error.strip() or None
        object.__setattr__(self, "state", ControlPlaneDurableSessionRecoveryWorkerState(self.state))
        object.__setattr__(self, "worker", worker)
        object.__setattr__(self, "last_error", error)


class ControlPlaneDurableSessionRecoveryWorker:
    """Run bounded durable session reconciliation under the Runtime lifecycle."""

    def __init__(
        self,
        service: ControlPlaneDurableSessionRecoveryService,
        *,
        poll_interval: float = 30.0,
        batch_size: int = 100,
        worker: str = "phoenix.control-plane.session-recovery",
        clock: ControlPlaneDurableSessionRecoveryClock = _utc_now,
    ) -> None:
        normalized_worker = worker.strip()
        if not normalized_worker:
            raise ValueError("durable session recovery worker name must not be blank")
        if poll_interval <= 0:
            raise ValueError("poll_interval must be positive")
        if batch_size <= 0 or batch_size > MAX_DURABLE_SESSION_PAGE_SIZE:
            raise ValueError(f"batch_size must be between 1 and {MAX_DURABLE_SESSION_PAGE_SIZE}")
        if not callable(clock):
            raise TypeError("durable session recovery worker clock must be callable")
        self._service = service
        self._poll_interval = poll_interval
        self._batch_size = batch_size
        self._worker = normalized_worker
        self._clock = clock
        self._state = ControlPlaneDurableSessionRecoveryWorkerState.CREATED
        self._ticks = 0
        self._scanned = 0
        self._recovered = 0
        self._healthy = 0
        self._conflicts = 0
        self._failures = 0
        self._last_tick_at: datetime | None = None
        self._last_error: str | None = None
        self._task: asyncio.Task[None] | None = None
        self._stop_requested = asyncio.Event()
        self._state_lock = asyncio.Lock()
        self._tick_lock = asyncio.Lock()

    @property
    def state(self) -> ControlPlaneDurableSessionRecoveryWorkerState:
        return self._state

    async def start(self, context: object) -> None:
        del context
        async with self._state_lock:
            if self._state is not ControlPlaneDurableSessionRecoveryWorkerState.CREATED:
                raise ControlPlaneDurableSessionRecoveryWorkerStateError(
                    f"cannot start durable session recovery worker from state {self._state.value}"
                )
            self._state = ControlPlaneDurableSessionRecoveryWorkerState.RUNNING
            self._task = asyncio.create_task(
                self._run_loop(),
                name=f"phoenix-durable-session-recovery:{self._worker}",
            )

    async def stop(self, context: object) -> None:
        del context
        async with self._state_lock:
            if self._state is ControlPlaneDurableSessionRecoveryWorkerState.STOPPED:
                return
            if self._state is ControlPlaneDurableSessionRecoveryWorkerState.CREATED:
                self._state = ControlPlaneDurableSessionRecoveryWorkerState.STOPPING
            elif self._state is ControlPlaneDurableSessionRecoveryWorkerState.RUNNING:
                self._state = ControlPlaneDurableSessionRecoveryWorkerState.STOPPING
                self._stop_requested.set()
            task = self._task
        if task is not None:
            await task
        async with self._state_lock:
            self._task = None
            self._state = ControlPlaneDurableSessionRecoveryWorkerState.STOPPED

    async def run_once(
        self,
        *,
        now: datetime | None = None,
    ) -> ControlPlaneDurableSessionRecoveryBatch:
        if self._state is not ControlPlaneDurableSessionRecoveryWorkerState.RUNNING:
            raise ControlPlaneDurableSessionRecoveryWorkerStateError(
                f"cannot run durable session recovery tick from state {self._state.value}"
            )
        tick_at = self._clock() if now is None else now
        _require_aware(tick_at, "durable session recovery tick")
        async with self._tick_lock:
            self._ticks += 1
            self._last_tick_at = tick_at
            try:
                batch = await self._service.recover(limit=self._batch_size, now=tick_at)
            except asyncio.CancelledError:
                raise
            except Exception as exception:
                self._failures += 1
                self._last_error = type(exception).__name__
                return ControlPlaneDurableSessionRecoveryBatch(0, 0, 0, 0, 0, 0)
            self._scanned += batch.scanned
            self._recovered += batch.recovered
            self._healthy += batch.healthy
            self._conflicts += batch.conflicts
            self._failures += batch.failures
            self._last_error = None
            return batch

    async def snapshot(self) -> ControlPlaneDurableSessionRecoveryWorkerSnapshot:
        async with self._state_lock:
            return ControlPlaneDurableSessionRecoveryWorkerSnapshot(
                state=self._state,
                worker=self._worker,
                ticks=self._ticks,
                scanned=self._scanned,
                recovered=self._recovered,
                healthy=self._healthy,
                conflicts=self._conflicts,
                failures=self._failures,
                last_tick_at=self._last_tick_at,
                last_error=self._last_error,
            )

    async def _run_loop(self) -> None:
        while not self._stop_requested.is_set():
            await self.run_once()
            try:
                await asyncio.wait_for(
                    self._stop_requested.wait(),
                    timeout=self._poll_interval,
                )
            except TimeoutError:
                pass


def _recovery_reason(
    record: ControlPlaneDurableSessionRecord,
    *,
    operator: ControlPlaneOperatorRecord | None,
    now: datetime,
) -> ControlPlaneDurableSessionTerminationReason | None:
    expiration = record.expiration_reason_at(now)
    if expiration is not None:
        return expiration
    if operator is None or operator.status is not ControlPlaneOperatorStatus.ACTIVE:
        return ControlPlaneDurableSessionTerminationReason.OPERATOR_INACTIVE
    if operator.token_version != record.operator_token_version:
        return ControlPlaneDurableSessionTerminationReason.CREDENTIAL_ROTATED
    if operator.revision != record.operator_revision or operator.username != record.username:
        return ControlPlaneDurableSessionTerminationReason.PERMISSIONS_CHANGED
    return None


def _require_aware(value: datetime, label: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")
