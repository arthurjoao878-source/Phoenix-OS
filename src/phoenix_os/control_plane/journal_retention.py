"""Deterministic terminal-only retention for the durable command journal."""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from uuid import UUID

from phoenix_os.control_plane.errors import (
    ControlPlaneCommandJournalConflictError,
    ControlPlaneCommandJournalNotFoundError,
    ControlPlaneCommandRetentionWorkerStateError,
)
from phoenix_os.control_plane.journal_contracts import (
    MAX_COMMAND_JOURNAL_CAPACITY,
    MAX_COMMAND_JOURNAL_PAGE_SIZE,
    ControlPlaneCommandJournalPageRequest,
    ControlPlaneCommandJournalRecord,
    ControlPlaneCommandJournalRepository,
    ControlPlaneCommandJournalStatus,
)
from phoenix_os.events import BusClosedError, EventBus

type ControlPlaneCommandRetentionClock = Callable[[], datetime]


def _utc_now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class ControlPlaneCommandRetentionPolicy:
    """Age/count retention bounds; non-terminal records are never candidates."""

    max_age: timedelta | None = timedelta(days=30)
    max_terminal_entries: int | None = 10_000
    batch_size: int = 100
    max_scan: int = MAX_COMMAND_JOURNAL_CAPACITY

    def __post_init__(self) -> None:
        if self.max_age is None and self.max_terminal_entries is None:
            raise ValueError("retention requires an age or count bound")
        if self.max_age is not None and self.max_age <= timedelta(0):
            raise ValueError("retention max_age must be positive")
        if self.max_terminal_entries is not None and self.max_terminal_entries < 0:
            raise ValueError("retention max_terminal_entries cannot be negative")
        if self.batch_size <= 0 or self.batch_size > MAX_COMMAND_JOURNAL_PAGE_SIZE:
            raise ValueError(
                f"retention batch_size must be between 1 and {MAX_COMMAND_JOURNAL_PAGE_SIZE}"
            )
        if self.max_scan <= 0 or self.max_scan > MAX_COMMAND_JOURNAL_CAPACITY:
            raise ValueError(
                f"retention max_scan must be between 1 and {MAX_COMMAND_JOURNAL_CAPACITY}"
            )


@dataclass(frozen=True, slots=True)
class ControlPlaneCommandRetentionCandidate:
    """Revision-bound deletion candidate without idempotency or fingerprint data."""

    command_id: UUID
    expected_revision: int
    completed_at: datetime
    status: ControlPlaneCommandJournalStatus

    def __post_init__(self) -> None:
        if self.expected_revision <= 0:
            raise ValueError("retention candidate revision must be positive")
        if self.completed_at.tzinfo is None:
            raise ValueError("retention candidate completed_at must be timezone-aware")
        status = ControlPlaneCommandJournalStatus(self.status)
        if not status.terminal:
            raise ValueError("retention candidate must be terminal")
        object.__setattr__(self, "status", status)


@dataclass(frozen=True, slots=True)
class ControlPlaneCommandRetentionPlan:
    """Deterministic bounded deletion plan calculated from one journal view."""

    generated_at: datetime
    scanned: int
    terminal: int
    candidates: tuple[ControlPlaneCommandRetentionCandidate, ...]
    schema_version: int = 1

    def __post_init__(self) -> None:
        if self.schema_version != 1:
            raise ValueError("unsupported command retention plan schema version")
        if self.generated_at.tzinfo is None:
            raise ValueError("retention plan generated_at must be timezone-aware")
        if self.scanned < 0 or self.terminal < 0 or self.terminal > self.scanned:
            raise ValueError("retention plan counters are inconsistent")
        if len(self.candidates) > MAX_COMMAND_JOURNAL_PAGE_SIZE:
            raise ValueError("retention plan exceeds the maximum batch size")
        identities = tuple(item.command_id for item in self.candidates)
        if len(identities) != len(set(identities)):
            raise ValueError("retention candidates must be unique")


@dataclass(frozen=True, slots=True)
class ControlPlaneCommandRetentionResult:
    """Safe retention result counters without command identities or storage details."""

    planned: int
    deleted: int
    conflicts: int
    failures: int
    completed_at: datetime
    schema_version: int = 1

    def __post_init__(self) -> None:
        if self.schema_version != 1:
            raise ValueError("unsupported command retention result schema version")
        if self.completed_at.tzinfo is None:
            raise ValueError("retention result completed_at must be timezone-aware")
        counters = (self.planned, self.deleted, self.conflicts, self.failures)
        if any(value < 0 for value in counters):
            raise ValueError("retention result counters cannot be negative")
        if self.deleted + self.conflicts + self.failures != self.planned:
            raise ValueError("retention result outcomes must equal planned candidates")


class ControlPlaneCommandRetentionService:
    """Plan and apply bounded terminal retention with safe audit events."""

    def __init__(
        self,
        repository: ControlPlaneCommandJournalRepository,
        *,
        events: EventBus | None = None,
        clock: ControlPlaneCommandRetentionClock = _utc_now,
    ) -> None:
        if not callable(clock):
            raise TypeError("retention clock must be callable")
        self._repository = repository
        self._events = events
        self._clock = clock

    async def plan(
        self,
        policy: ControlPlaneCommandRetentionPolicy,
        *,
        now: datetime | None = None,
    ) -> ControlPlaneCommandRetentionPlan:
        generated_at = self._now(now)
        records = await self._scan(policy.max_scan)
        terminal = tuple(item for item in records if item.status.terminal)
        ordered = tuple(
            sorted(
                terminal,
                key=lambda item: (
                    item.completed_at or item.updated_at,
                    item.command_id.hex,
                ),
            )
        )
        selected: dict[UUID, ControlPlaneCommandJournalRecord] = {}
        if policy.max_age is not None:
            cutoff = generated_at - policy.max_age
            for item in ordered:
                completed_at = item.completed_at
                if completed_at is not None and completed_at <= cutoff:
                    selected[item.command_id] = item
        if policy.max_terminal_entries is not None:
            excess = max(0, len(ordered) - policy.max_terminal_entries)
            for item in ordered[:excess]:
                selected[item.command_id] = item
        candidates = tuple(
            ControlPlaneCommandRetentionCandidate(
                command_id=item.command_id,
                expected_revision=item.revision,
                completed_at=item.completed_at or item.updated_at,
                status=item.status,
            )
            for item in sorted(
                selected.values(),
                key=lambda value: (
                    value.completed_at or value.updated_at,
                    value.command_id.hex,
                ),
            )[: policy.batch_size]
        )
        return ControlPlaneCommandRetentionPlan(
            generated_at=generated_at,
            scanned=len(records),
            terminal=len(terminal),
            candidates=candidates,
        )

    async def apply(
        self,
        plan: ControlPlaneCommandRetentionPlan,
        *,
        now: datetime | None = None,
    ) -> ControlPlaneCommandRetentionResult:
        completed_at = self._now(now)
        deleted = 0
        conflicts = 0
        failures = 0
        for candidate in plan.candidates:
            try:
                await self._repository.delete_terminal(
                    candidate.command_id,
                    expected_revision=candidate.expected_revision,
                )
            except (
                ControlPlaneCommandJournalConflictError,
                ControlPlaneCommandJournalNotFoundError,
            ):
                conflicts += 1
            except asyncio.CancelledError:
                raise
            except Exception:
                failures += 1
            else:
                deleted += 1
        result = ControlPlaneCommandRetentionResult(
            planned=len(plan.candidates),
            deleted=deleted,
            conflicts=conflicts,
            failures=failures,
            completed_at=completed_at,
        )
        await self._safe_emit(result)
        return result

    async def run(
        self,
        policy: ControlPlaneCommandRetentionPolicy,
        *,
        now: datetime | None = None,
    ) -> ControlPlaneCommandRetentionResult:
        plan = await self.plan(policy, now=now)
        return await self.apply(plan, now=now)

    async def _scan(self, maximum: int) -> tuple[ControlPlaneCommandJournalRecord, ...]:
        records: list[ControlPlaneCommandJournalRecord] = []
        offset = 0
        while len(records) < maximum:
            limit = min(MAX_COMMAND_JOURNAL_PAGE_SIZE, maximum - len(records))
            page = await self._repository.list_page(
                ControlPlaneCommandJournalPageRequest(offset=offset, limit=limit)
            )
            records.extend(page.items)
            if page.page.next_offset is None:
                break
            offset = page.page.next_offset
        return tuple(records)

    async def _safe_emit(self, result: ControlPlaneCommandRetentionResult) -> None:
        if self._events is None:
            return
        outcome = "succeeded" if result.failures == 0 else "failed"
        payload: Mapping[str, object] = {
            "action": "command-journal.retention",
            "actor": "phoenix.control-plane.retention",
            "conflicts": result.conflicts,
            "deleted": result.deleted,
            "failures": result.failures,
            "outcome": outcome,
            "planned": result.planned,
            "resource": "control-plane:command-journal",
            "status": outcome,
        }
        try:
            await self._events.emit(
                "control-plane.command.journal.retention-completed",
                source="phoenix.control-plane",
                payload=payload,
            )
        except (BusClosedError, RuntimeError):
            pass

    def _now(self, value: datetime | None) -> datetime:
        result = self._clock() if value is None else value
        if result.tzinfo is None:
            raise ValueError("retention time must be timezone-aware")
        return result


class ControlPlaneCommandRetentionWorkerState(StrEnum):
    """Lifecycle states for periodic terminal retention."""

    CREATED = "created"
    RUNNING = "running"
    STOPPING = "stopping"
    STOPPED = "stopped"


@dataclass(frozen=True, slots=True)
class ControlPlaneCommandRetentionWorkerSnapshot:
    """Safe retention worker counters without command identities."""

    state: ControlPlaneCommandRetentionWorkerState
    worker: str
    ticks: int
    planned: int
    deleted: int
    conflicts: int
    failures: int
    last_tick_at: datetime | None = None
    last_error: str | None = None

    def __post_init__(self) -> None:
        worker = self.worker.strip()
        counters = (self.ticks, self.planned, self.deleted, self.conflicts, self.failures)
        if not worker:
            raise ValueError("retention worker name must not be blank")
        if any(value < 0 for value in counters):
            raise ValueError("retention worker counters cannot be negative")
        if self.last_tick_at is not None and self.last_tick_at.tzinfo is None:
            raise ValueError("last_tick_at must be timezone-aware")
        error = None if self.last_error is None else self.last_error.strip() or None
        object.__setattr__(self, "state", ControlPlaneCommandRetentionWorkerState(self.state))
        object.__setattr__(self, "worker", worker)
        object.__setattr__(self, "last_error", error)


class ControlPlaneCommandRetentionWorker:
    """Run bounded terminal retention under the Phoenix Runtime lifecycle."""

    def __init__(
        self,
        service: ControlPlaneCommandRetentionService,
        policy: ControlPlaneCommandRetentionPolicy,
        *,
        poll_interval: float = 3600.0,
        worker: str = "phoenix.control-plane.retention",
        clock: ControlPlaneCommandRetentionClock = _utc_now,
    ) -> None:
        normalized_worker = worker.strip()
        if not normalized_worker:
            raise ValueError("retention worker name must not be blank")
        if poll_interval <= 0:
            raise ValueError("poll_interval must be positive")
        if not callable(clock):
            raise TypeError("clock must be callable")
        self._service = service
        self._policy = policy
        self._poll_interval = poll_interval
        self._worker = normalized_worker
        self._clock = clock
        self._state = ControlPlaneCommandRetentionWorkerState.CREATED
        self._ticks = 0
        self._planned = 0
        self._deleted = 0
        self._conflicts = 0
        self._failures = 0
        self._last_tick_at: datetime | None = None
        self._last_error: str | None = None
        self._task: asyncio.Task[None] | None = None
        self._stop_requested = asyncio.Event()
        self._state_lock = asyncio.Lock()
        self._tick_lock = asyncio.Lock()

    @property
    def state(self) -> ControlPlaneCommandRetentionWorkerState:
        return self._state

    async def start(self, context: object) -> None:
        del context
        async with self._state_lock:
            if self._state is not ControlPlaneCommandRetentionWorkerState.CREATED:
                raise ControlPlaneCommandRetentionWorkerStateError(
                    f"cannot start command retention worker from state {self._state.value}"
                )
            self._state = ControlPlaneCommandRetentionWorkerState.RUNNING
            self._task = asyncio.create_task(
                self._run_loop(),
                name=f"phoenix-command-retention:{self._worker}",
            )

    async def stop(self, context: object) -> None:
        del context
        async with self._state_lock:
            if self._state is ControlPlaneCommandRetentionWorkerState.STOPPED:
                return
            if self._state is ControlPlaneCommandRetentionWorkerState.CREATED:
                self._state = ControlPlaneCommandRetentionWorkerState.STOPPING
            elif self._state is ControlPlaneCommandRetentionWorkerState.RUNNING:
                self._state = ControlPlaneCommandRetentionWorkerState.STOPPING
                self._stop_requested.set()
            task = self._task
        if task is not None:
            await task
        async with self._state_lock:
            self._task = None
            self._state = ControlPlaneCommandRetentionWorkerState.STOPPED

    async def run_once(
        self,
        *,
        now: datetime | None = None,
    ) -> ControlPlaneCommandRetentionResult:
        if self._state is not ControlPlaneCommandRetentionWorkerState.RUNNING:
            raise ControlPlaneCommandRetentionWorkerStateError(
                f"cannot run command retention tick from state {self._state.value}"
            )
        tick_at = self._clock() if now is None else now
        if tick_at.tzinfo is None:
            raise ValueError("now must be timezone-aware")
        async with self._tick_lock:
            self._ticks += 1
            self._last_tick_at = tick_at
            try:
                result = await self._service.run(self._policy, now=tick_at)
            except asyncio.CancelledError:
                raise
            except Exception as exception:
                self._failures += 1
                self._last_error = type(exception).__name__
                return ControlPlaneCommandRetentionResult(
                    planned=0,
                    deleted=0,
                    conflicts=0,
                    failures=0,
                    completed_at=tick_at,
                )
            self._planned += result.planned
            self._deleted += result.deleted
            self._conflicts += result.conflicts
            self._failures += result.failures
            self._last_error = None
            return result

    async def snapshot(self) -> ControlPlaneCommandRetentionWorkerSnapshot:
        async with self._state_lock:
            return ControlPlaneCommandRetentionWorkerSnapshot(
                state=self._state,
                worker=self._worker,
                ticks=self._ticks,
                planned=self._planned,
                deleted=self._deleted,
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
                continue
