"""Bounded recovery probes and Runtime lifecycle worker for durable commands."""

from __future__ import annotations

import asyncio
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Protocol
from uuid import UUID

from phoenix_os.control_plane.commands import ControlPlaneCommandAction
from phoenix_os.control_plane.errors import (
    ControlPlaneCommandJournalConflictError,
    ControlPlaneCommandRecoveryWorkerStateError,
)
from phoenix_os.control_plane.journal_contracts import (
    MAX_COMMAND_JOURNAL_PAGE_SIZE,
    ControlPlaneCommandJournalPageRequest,
    ControlPlaneCommandJournalRecord,
    ControlPlaneCommandJournalRepository,
    ControlPlaneCommandJournalStatus,
)
from phoenix_os.jobs import JobRecord, JobStatus
from phoenix_os.workflows import WorkflowRecord, WorkflowStatus

type ControlPlaneCommandRecoveryClock = Callable[[], datetime]

_RESULT_CODE_PATTERN = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}\Z")


def _utc_now() -> datetime:
    return datetime.now(UTC)


class ControlPlaneCommandRecoveryDisposition(StrEnum):
    """Safe probe outcome for one interrupted durable command."""

    DEFERRED = "deferred"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class ControlPlaneCommandRecoveryDecision:
    """Payload-free recovery decision produced by a side-effect probe."""

    disposition: ControlPlaneCommandRecoveryDisposition
    result_code: str | None = None

    def __post_init__(self) -> None:
        disposition = ControlPlaneCommandRecoveryDisposition(self.disposition)
        result_code = None if self.result_code is None else self.result_code.strip().lower()
        if disposition is ControlPlaneCommandRecoveryDisposition.DEFERRED:
            if result_code is not None:
                raise ValueError("deferred recovery decision cannot contain a result code")
        elif result_code is None or _RESULT_CODE_PATTERN.fullmatch(result_code) is None:
            raise ValueError("terminal recovery decision requires a stable result code")
        object.__setattr__(self, "disposition", disposition)
        object.__setattr__(self, "result_code", result_code)

    @classmethod
    def deferred(cls) -> ControlPlaneCommandRecoveryDecision:
        return cls(ControlPlaneCommandRecoveryDisposition.DEFERRED)

    @classmethod
    def succeeded(cls, result_code: str) -> ControlPlaneCommandRecoveryDecision:
        return cls(ControlPlaneCommandRecoveryDisposition.SUCCEEDED, result_code)

    @classmethod
    def failed(cls, result_code: str) -> ControlPlaneCommandRecoveryDecision:
        return cls(ControlPlaneCommandRecoveryDisposition.FAILED, result_code)


class ControlPlaneCommandRecoveryProbe(Protocol):
    """Inspect external state without replaying a command payload."""

    def probe(
        self,
        record: ControlPlaneCommandJournalRecord,
    ) -> Awaitable[ControlPlaneCommandRecoveryDecision]: ...


class ControlPlaneCommandRecoveryJobSource(Protocol):
    def get(self, job_id: UUID) -> Awaitable[JobRecord | None]: ...


class ControlPlaneCommandRecoveryWorkflowSource(Protocol):
    def get(self, workflow_id: UUID) -> Awaitable[WorkflowRecord | None]: ...


class ControlPlaneCommandSideEffectProbe:
    """Reconcile deterministic job and workflow side effects without payload replay."""

    def __init__(
        self,
        *,
        jobs: ControlPlaneCommandRecoveryJobSource | None = None,
        workflows: ControlPlaneCommandRecoveryWorkflowSource | None = None,
    ) -> None:
        self._jobs = jobs
        self._workflows = workflows

    async def probe(
        self,
        record: ControlPlaneCommandJournalRecord,
    ) -> ControlPlaneCommandRecoveryDecision:
        if record.status.terminal:
            raise ValueError("terminal command journal records do not require recovery")
        try:
            if record.action is ControlPlaneCommandAction.CREATE_JOB:
                return await self._probe_created_job(record, "job.created")
            if record.action is ControlPlaneCommandAction.RETRY_DEAD_LETTER_JOB:
                return await self._probe_created_job(record, "job.retried")
            if record.action is ControlPlaneCommandAction.CANCEL_JOB:
                return await self._probe_cancelled_job(record)
            if record.action is ControlPlaneCommandAction.CANCEL_WORKFLOW:
                return await self._probe_cancelled_workflow(record)
        except asyncio.CancelledError:
            raise
        except Exception:
            return ControlPlaneCommandRecoveryDecision.deferred()
        return ControlPlaneCommandRecoveryDecision.failed("command.recovery-unsupported-action")

    async def _probe_created_job(
        self,
        record: ControlPlaneCommandJournalRecord,
        result_code: str,
    ) -> ControlPlaneCommandRecoveryDecision:
        if self._jobs is None:
            return ControlPlaneCommandRecoveryDecision.deferred()
        created = await self._jobs.get(record.command_id)
        if created is None:
            return ControlPlaneCommandRecoveryDecision.deferred()
        return ControlPlaneCommandRecoveryDecision.succeeded(result_code)

    async def _probe_cancelled_job(
        self,
        record: ControlPlaneCommandJournalRecord,
    ) -> ControlPlaneCommandRecoveryDecision:
        if self._jobs is None:
            return ControlPlaneCommandRecoveryDecision.deferred()
        job_id = _parse_target(record.target, "job")
        if job_id is None:
            return ControlPlaneCommandRecoveryDecision.failed("command.recovery-invalid-target")
        job = await self._jobs.get(job_id)
        if job is None:
            return ControlPlaneCommandRecoveryDecision.failed("job.not-found")
        if job.status is JobStatus.CANCELLED:
            return ControlPlaneCommandRecoveryDecision.succeeded("job.cancelled")
        if job.status.terminal:
            return ControlPlaneCommandRecoveryDecision.failed("job.not-cancellable")
        return ControlPlaneCommandRecoveryDecision.deferred()

    async def _probe_cancelled_workflow(
        self,
        record: ControlPlaneCommandJournalRecord,
    ) -> ControlPlaneCommandRecoveryDecision:
        if self._workflows is None:
            return ControlPlaneCommandRecoveryDecision.deferred()
        workflow_id = _parse_target(record.target, "workflow")
        if workflow_id is None:
            return ControlPlaneCommandRecoveryDecision.failed("command.recovery-invalid-target")
        workflow = await self._workflows.get(workflow_id)
        if workflow is None:
            return ControlPlaneCommandRecoveryDecision.failed("workflow.not-found")
        if workflow.status is WorkflowStatus.CANCELLED:
            return ControlPlaneCommandRecoveryDecision.succeeded("workflow.cancelled")
        if workflow.status.terminal:
            return ControlPlaneCommandRecoveryDecision.failed("workflow.not-cancellable")
        return ControlPlaneCommandRecoveryDecision.deferred()


@dataclass(frozen=True, slots=True)
class ControlPlaneCommandRecoveryBatch:
    """Non-sensitive counters from one bounded recovery pass."""

    scanned: int
    eligible: int
    recovered: int
    deferred: int
    conflicts: int
    failures: int
    records: tuple[ControlPlaneCommandJournalRecord, ...] = ()

    def __post_init__(self) -> None:
        counters = (
            self.scanned,
            self.eligible,
            self.recovered,
            self.deferred,
            self.conflicts,
            self.failures,
        )
        if any(value < 0 for value in counters):
            raise ValueError("recovery counters cannot be negative")
        if self.eligible > self.scanned:
            raise ValueError("eligible recovery count cannot exceed scanned count")
        if self.recovered != len(self.records):
            raise ValueError("recovered count must match returned records")
        if self.recovered + self.deferred + self.conflicts + self.failures != self.eligible:
            raise ValueError("recovery outcome counts must equal eligible count")
        if any(not record.status.terminal for record in self.records):
            raise ValueError("recovery batch records must be terminal")


class ControlPlaneCommandRecoveryService:
    """Perform one bounded, payload-free reconciliation pass."""

    def __init__(
        self,
        repository: ControlPlaneCommandJournalRepository,
        probe: ControlPlaneCommandRecoveryProbe,
        *,
        clock: ControlPlaneCommandRecoveryClock = _utc_now,
    ) -> None:
        if not callable(clock):
            raise TypeError("clock must be callable")
        self._repository = repository
        self._probe = probe
        self._clock = clock

    async def recover(
        self,
        *,
        limit: int = 100,
        now: datetime | None = None,
    ) -> ControlPlaneCommandRecoveryBatch:
        if limit <= 0 or limit > MAX_COMMAND_JOURNAL_PAGE_SIZE:
            raise ValueError(
                f"recovery limit must be between 1 and {MAX_COMMAND_JOURNAL_PAGE_SIZE}"
            )
        recovered_at = self._clock() if now is None else now
        if recovered_at.tzinfo is None:
            raise ValueError("recovery time must be timezone-aware")
        page = await self._repository.list_page(ControlPlaneCommandJournalPageRequest(limit=limit))
        eligible = tuple(record for record in reversed(page.items) if not record.status.terminal)
        recovered: list[ControlPlaneCommandJournalRecord] = []
        deferred = 0
        conflicts = 0
        failures = 0
        for record in eligible:
            try:
                decision = await self._probe.probe(record)
                if decision.disposition is ControlPlaneCommandRecoveryDisposition.DEFERRED:
                    deferred += 1
                    continue
                status = (
                    ControlPlaneCommandJournalStatus.SUCCEEDED
                    if decision.disposition is ControlPlaneCommandRecoveryDisposition.SUCCEEDED
                    else ControlPlaneCommandJournalStatus.FAILED
                )
                updated = await self._repository.transition(
                    record.command_id,
                    expected_revision=record.revision,
                    status=status,
                    updated_at=recovered_at,
                    result_code=decision.result_code,
                )
            except asyncio.CancelledError:
                raise
            except ControlPlaneCommandJournalConflictError:
                conflicts += 1
            except Exception:
                failures += 1
            else:
                recovered.append(updated)
        return ControlPlaneCommandRecoveryBatch(
            scanned=len(page.items),
            eligible=len(eligible),
            recovered=len(recovered),
            deferred=deferred,
            conflicts=conflicts,
            failures=failures,
            records=tuple(recovered),
        )


class ControlPlaneCommandRecoveryWorkerState(StrEnum):
    CREATED = "created"
    RUNNING = "running"
    STOPPING = "stopping"
    STOPPED = "stopped"


@dataclass(frozen=True, slots=True)
class ControlPlaneCommandRecoveryWorkerSnapshot:
    """Operational worker counters without command payloads or exception text."""

    state: ControlPlaneCommandRecoveryWorkerState
    worker: str
    ticks: int
    scanned: int
    recovered: int
    deferred: int
    conflicts: int
    failures: int
    last_tick_at: datetime | None = None
    last_error: str | None = None

    def __post_init__(self) -> None:
        worker = self.worker.strip()
        counters = (
            self.ticks,
            self.scanned,
            self.recovered,
            self.deferred,
            self.conflicts,
            self.failures,
        )
        if not worker:
            raise ValueError("recovery worker name must not be blank")
        if any(value < 0 for value in counters):
            raise ValueError("recovery worker counters cannot be negative")
        if self.last_tick_at is not None and self.last_tick_at.tzinfo is None:
            raise ValueError("last_tick_at must be timezone-aware")
        error = None if self.last_error is None else self.last_error.strip() or None
        object.__setattr__(self, "state", ControlPlaneCommandRecoveryWorkerState(self.state))
        object.__setattr__(self, "worker", worker)
        object.__setattr__(self, "last_error", error)


class ControlPlaneCommandRecoveryWorker:
    """Run bounded command recovery ticks under the Phoenix Runtime lifecycle."""

    def __init__(
        self,
        service: ControlPlaneCommandRecoveryService,
        *,
        poll_interval: float = 1.0,
        batch_size: int = 100,
        worker: str = "phoenix.control-plane.recovery",
        clock: ControlPlaneCommandRecoveryClock = _utc_now,
    ) -> None:
        normalized_worker = worker.strip()
        if not normalized_worker:
            raise ValueError("recovery worker name must not be blank")
        if poll_interval <= 0:
            raise ValueError("poll_interval must be positive")
        if batch_size <= 0 or batch_size > MAX_COMMAND_JOURNAL_PAGE_SIZE:
            raise ValueError(f"batch_size must be between 1 and {MAX_COMMAND_JOURNAL_PAGE_SIZE}")
        if not callable(clock):
            raise TypeError("clock must be callable")
        self._service = service
        self._poll_interval = poll_interval
        self._batch_size = batch_size
        self._worker = normalized_worker
        self._clock = clock
        self._state = ControlPlaneCommandRecoveryWorkerState.CREATED
        self._ticks = 0
        self._scanned = 0
        self._recovered = 0
        self._deferred = 0
        self._conflicts = 0
        self._failures = 0
        self._last_tick_at: datetime | None = None
        self._last_error: str | None = None
        self._task: asyncio.Task[None] | None = None
        self._stop_requested = asyncio.Event()
        self._state_lock = asyncio.Lock()
        self._tick_lock = asyncio.Lock()

    @property
    def state(self) -> ControlPlaneCommandRecoveryWorkerState:
        return self._state

    async def start(self, context: object) -> None:
        del context
        async with self._state_lock:
            if self._state is not ControlPlaneCommandRecoveryWorkerState.CREATED:
                raise ControlPlaneCommandRecoveryWorkerStateError(
                    f"cannot start command recovery worker from state {self._state.value}"
                )
            self._state = ControlPlaneCommandRecoveryWorkerState.RUNNING
            self._task = asyncio.create_task(
                self._run_loop(),
                name=f"phoenix-command-recovery:{self._worker}",
            )

    async def stop(self, context: object) -> None:
        del context
        async with self._state_lock:
            if self._state is ControlPlaneCommandRecoveryWorkerState.STOPPED:
                return
            if self._state is ControlPlaneCommandRecoveryWorkerState.CREATED:
                self._state = ControlPlaneCommandRecoveryWorkerState.STOPPING
            elif self._state is ControlPlaneCommandRecoveryWorkerState.RUNNING:
                self._state = ControlPlaneCommandRecoveryWorkerState.STOPPING
                self._stop_requested.set()
            task = self._task
        if task is not None:
            await task
        async with self._state_lock:
            self._task = None
            self._state = ControlPlaneCommandRecoveryWorkerState.STOPPED

    async def run_once(
        self,
        *,
        now: datetime | None = None,
    ) -> ControlPlaneCommandRecoveryBatch:
        if self._state is not ControlPlaneCommandRecoveryWorkerState.RUNNING:
            raise ControlPlaneCommandRecoveryWorkerStateError(
                f"cannot run command recovery tick from state {self._state.value}"
            )
        tick_at = self._clock() if now is None else now
        if tick_at.tzinfo is None:
            raise ValueError("now must be timezone-aware")
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
                return ControlPlaneCommandRecoveryBatch(0, 0, 0, 0, 0, 0)
            self._scanned += batch.scanned
            self._recovered += batch.recovered
            self._deferred += batch.deferred
            self._conflicts += batch.conflicts
            self._failures += batch.failures
            self._last_error = None
            return batch

    async def snapshot(self) -> ControlPlaneCommandRecoveryWorkerSnapshot:
        async with self._state_lock:
            return ControlPlaneCommandRecoveryWorkerSnapshot(
                state=self._state,
                worker=self._worker,
                ticks=self._ticks,
                scanned=self._scanned,
                recovered=self._recovered,
                deferred=self._deferred,
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


def _parse_target(value: str, prefix: str) -> UUID | None:
    expected = f"{prefix}:"
    if not value.startswith(expected):
        return None
    try:
        return UUID(value[len(expected) :])
    except ValueError:
        return None
