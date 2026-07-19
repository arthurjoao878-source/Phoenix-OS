"""Terminal-only retention for durable operator-session history."""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from uuid import UUID

from phoenix_os.control_plane.durable_session_contracts import (
    MAX_DURABLE_SESSION_CAPACITY,
    MAX_DURABLE_SESSION_PAGE_SIZE,
    ControlPlaneDurableSessionPageRequest,
    ControlPlaneDurableSessionRecord,
    ControlPlaneDurableSessionRepository,
    ControlPlaneDurableSessionStatus,
)
from phoenix_os.control_plane.errors import (
    ControlPlaneDurableSessionConflictError,
    ControlPlaneDurableSessionNotFoundError,
    ControlPlaneDurableSessionRetentionWorkerStateError,
)
from phoenix_os.events import BusClosedError, EventBus

type ControlPlaneDurableSessionRetentionClock = Callable[[], datetime]


def _utc_now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class ControlPlaneDurableSessionRetentionPolicy:
    """Bound terminal history by age and count without deleting active sessions."""

    max_age: timedelta | None = timedelta(days=7)
    max_terminal_entries: int | None = 10_000
    batch_size: int = 100
    max_scan: int = MAX_DURABLE_SESSION_CAPACITY

    def __post_init__(self) -> None:
        if self.max_age is None and self.max_terminal_entries is None:
            raise ValueError("durable session retention requires an age or count bound")
        if self.max_age is not None and self.max_age <= timedelta(0):
            raise ValueError("durable session retention max_age must be positive")
        if self.max_terminal_entries is not None and self.max_terminal_entries < 0:
            raise ValueError("durable session retention count cannot be negative")
        if self.batch_size <= 0 or self.batch_size > MAX_DURABLE_SESSION_PAGE_SIZE:
            raise ValueError("durable session retention batch size is outside supported bounds")
        if self.max_scan <= 0 or self.max_scan > MAX_DURABLE_SESSION_CAPACITY:
            raise ValueError("durable session retention scan bound is outside supported bounds")


@dataclass(frozen=True, slots=True)
class ControlPlaneDurableSessionRetentionCandidate:
    """Revision-bound standalone terminal deletion candidate."""

    session_id: UUID
    expected_revision: int
    terminated_at: datetime
    status: ControlPlaneDurableSessionStatus

    def __post_init__(self) -> None:
        if self.expected_revision <= 0:
            raise ValueError("durable session retention revision must be positive")
        if self.terminated_at.tzinfo is None:
            raise ValueError("durable session retention time must be timezone-aware")
        status = ControlPlaneDurableSessionStatus(self.status)
        if not status.terminal:
            raise ValueError("durable session retention candidate must be terminal")
        object.__setattr__(self, "status", status)


@dataclass(frozen=True, slots=True)
class ControlPlaneDurableSessionRetentionPlan:
    """Deterministic oldest-first deletion plan."""

    created_at: datetime
    scanned: int
    terminal: int
    protected_lineage: int
    candidates: tuple[ControlPlaneDurableSessionRetentionCandidate, ...]

    def __post_init__(self) -> None:
        if self.created_at.tzinfo is None:
            raise ValueError("durable session retention plan time must be timezone-aware")
        if min(self.scanned, self.terminal, self.protected_lineage) < 0:
            raise ValueError("durable session retention counters cannot be negative")
        if self.terminal > self.scanned or self.protected_lineage > self.terminal:
            raise ValueError("durable session retention counters are inconsistent")
        if len({item.session_id for item in self.candidates}) != len(self.candidates):
            raise ValueError("durable session retention candidates must be unique")


@dataclass(frozen=True, slots=True)
class ControlPlaneDurableSessionRetentionResult:
    """Credential-free retention result counters."""

    planned: int
    deleted: int
    conflicts: int
    failures: int
    protected_lineage: int
    completed_at: datetime

    def __post_init__(self) -> None:
        if (
            min(
                self.planned,
                self.deleted,
                self.conflicts,
                self.failures,
                self.protected_lineage,
            )
            < 0
        ):
            raise ValueError("durable session retention result counters cannot be negative")
        if self.deleted + self.conflicts + self.failures != self.planned:
            raise ValueError("durable session retention result counters are inconsistent")
        if self.completed_at.tzinfo is None:
            raise ValueError("durable session retention completion must be timezone-aware")


class ControlPlaneDurableSessionRetentionService:
    """Plan and apply bounded terminal retention with optimistic revisions."""

    def __init__(
        self,
        repository: ControlPlaneDurableSessionRepository,
        *,
        events: EventBus | None = None,
        clock: ControlPlaneDurableSessionRetentionClock = _utc_now,
    ) -> None:
        if not callable(clock):
            raise TypeError("durable session retention clock must be callable")
        self._repository = repository
        self._events = events
        self._clock = clock

    async def plan(
        self,
        policy: ControlPlaneDurableSessionRetentionPolicy,
        *,
        now: datetime | None = None,
    ) -> ControlPlaneDurableSessionRetentionPlan:
        created_at = self._now(now)
        records = await self._scan(policy.max_scan)
        terminal = [record for record in records if record.status.terminal]
        standalone = [
            record
            for record in terminal
            if record.predecessor_session_id is None and record.successor_session_id is None
        ]
        protected_lineage = len(terminal) - len(standalone)
        standalone.sort(key=_oldest_terminal_key)
        selected: dict[UUID, ControlPlaneDurableSessionRecord] = {}
        if policy.max_age is not None:
            cutoff = created_at - policy.max_age
            for record in standalone:
                assert record.terminated_at is not None
                if record.terminated_at <= cutoff:
                    selected[record.id] = record
        if policy.max_terminal_entries is not None:
            overflow = max(0, len(terminal) - policy.max_terminal_entries)
            for record in standalone:
                if overflow <= 0:
                    break
                if record.id not in selected:
                    selected[record.id] = record
                overflow -= 1
        ordered = sorted(selected.values(), key=_oldest_terminal_key)[: policy.batch_size]
        return ControlPlaneDurableSessionRetentionPlan(
            created_at=created_at,
            scanned=len(records),
            terminal=len(terminal),
            protected_lineage=protected_lineage,
            candidates=tuple(
                ControlPlaneDurableSessionRetentionCandidate(
                    session_id=record.id,
                    expected_revision=record.revision,
                    terminated_at=_required_terminated_at(record),
                    status=record.status,
                )
                for record in ordered
            ),
        )

    async def apply(
        self,
        plan: ControlPlaneDurableSessionRetentionPlan,
        *,
        now: datetime | None = None,
    ) -> ControlPlaneDurableSessionRetentionResult:
        completed_at = self._now(now)
        deleted = conflicts = failures = 0
        for candidate in plan.candidates:
            try:
                await self._repository.delete_terminal(
                    candidate.session_id,
                    expected_revision=candidate.expected_revision,
                )
            except (
                ControlPlaneDurableSessionConflictError,
                ControlPlaneDurableSessionNotFoundError,
            ):
                conflicts += 1
            except asyncio.CancelledError:
                raise
            except Exception:
                failures += 1
            else:
                deleted += 1
        result = ControlPlaneDurableSessionRetentionResult(
            planned=len(plan.candidates),
            deleted=deleted,
            conflicts=conflicts,
            failures=failures,
            protected_lineage=plan.protected_lineage,
            completed_at=completed_at,
        )
        await self._safe_emit(result)
        return result

    async def run(
        self,
        policy: ControlPlaneDurableSessionRetentionPolicy,
        *,
        now: datetime | None = None,
    ) -> ControlPlaneDurableSessionRetentionResult:
        plan = await self.plan(policy, now=now)
        return await self.apply(plan, now=now)

    async def _scan(self, maximum: int) -> tuple[ControlPlaneDurableSessionRecord, ...]:
        records: list[ControlPlaneDurableSessionRecord] = []
        offset = 0
        while len(records) < maximum:
            limit = min(MAX_DURABLE_SESSION_PAGE_SIZE, maximum - len(records))
            page = await self._repository.list_page(
                ControlPlaneDurableSessionPageRequest(offset=offset, limit=limit)
            )
            records.extend(page.items)
            if page.page.next_offset is None:
                break
            offset = page.page.next_offset
        return tuple(records)

    async def _safe_emit(self, result: ControlPlaneDurableSessionRetentionResult) -> None:
        if self._events is None:
            return
        outcome = "succeeded" if result.failures == 0 else "failed"
        payload: Mapping[str, object] = {
            "action": "operator-session.retention",
            "actor": "phoenix.control-plane.session-retention",
            "conflicts": result.conflicts,
            "deleted": result.deleted,
            "failures": result.failures,
            "outcome": outcome,
            "planned": result.planned,
            "protected_lineage": result.protected_lineage,
            "resource": "control-plane:operator-sessions",
            "status": outcome,
        }
        try:
            await self._events.emit(
                "control-plane.operator.session.retention-completed",
                source="phoenix.control-plane",
                payload=payload,
            )
        except (BusClosedError, RuntimeError):
            pass

    def _now(self, value: datetime | None) -> datetime:
        result = self._clock() if value is None else value
        if result.tzinfo is None:
            raise ValueError("durable session retention time must be timezone-aware")
        return result


class ControlPlaneDurableSessionRetentionWorkerState(StrEnum):
    CREATED = "created"
    RUNNING = "running"
    STOPPING = "stopping"
    STOPPED = "stopped"


@dataclass(frozen=True, slots=True)
class ControlPlaneDurableSessionRetentionWorkerSnapshot:
    state: ControlPlaneDurableSessionRetentionWorkerState
    ticks: int
    planned: int
    deleted: int
    conflicts: int
    failures: int
    protected_lineage: int
    last_tick_at: datetime | None = None
    last_error: str | None = None

    def __post_init__(self) -> None:
        if (
            min(
                self.ticks,
                self.planned,
                self.deleted,
                self.conflicts,
                self.failures,
                self.protected_lineage,
            )
            < 0
        ):
            raise ValueError("durable session retention worker counters cannot be negative")
        if self.last_tick_at is not None and self.last_tick_at.tzinfo is None:
            raise ValueError("durable session retention worker time must be timezone-aware")
        object.__setattr__(
            self, "state", ControlPlaneDurableSessionRetentionWorkerState(self.state)
        )
        object.__setattr__(
            self,
            "last_error",
            None if self.last_error is None else self.last_error.strip() or None,
        )


class ControlPlaneDurableSessionRetentionWorker:
    """Run bounded session retention under Runtime lifecycle ownership."""

    def __init__(
        self,
        service: ControlPlaneDurableSessionRetentionService,
        policy: ControlPlaneDurableSessionRetentionPolicy,
        *,
        poll_interval: float = 3600.0,
        clock: ControlPlaneDurableSessionRetentionClock = _utc_now,
    ) -> None:
        if poll_interval <= 0:
            raise ValueError("durable session retention poll interval must be positive")
        if not callable(clock):
            raise TypeError("durable session retention worker clock must be callable")
        self._service = service
        self._policy = policy
        self._poll_interval = poll_interval
        self._clock = clock
        self._state = ControlPlaneDurableSessionRetentionWorkerState.CREATED
        self._ticks = self._planned = self._deleted = 0
        self._conflicts = self._failures = self._protected_lineage = 0
        self._last_tick_at: datetime | None = None
        self._last_error: str | None = None
        self._task: asyncio.Task[None] | None = None
        self._stop_requested = asyncio.Event()
        self._state_lock = asyncio.Lock()
        self._tick_lock = asyncio.Lock()

    @property
    def state(self) -> ControlPlaneDurableSessionRetentionWorkerState:
        return self._state

    async def start(self, context: object = None) -> None:
        del context
        async with self._state_lock:
            if self._state is not ControlPlaneDurableSessionRetentionWorkerState.CREATED:
                raise ControlPlaneDurableSessionRetentionWorkerStateError(
                    f"cannot start durable session retention from {self._state.value}"
                )
            self._state = ControlPlaneDurableSessionRetentionWorkerState.RUNNING
            self._task = asyncio.create_task(
                self._run_loop(),
                name="phoenix-durable-session-retention",
            )

    async def stop(self, context: object = None) -> None:
        del context
        async with self._state_lock:
            if self._state is ControlPlaneDurableSessionRetentionWorkerState.STOPPED:
                return
            if self._state in {
                ControlPlaneDurableSessionRetentionWorkerState.CREATED,
                ControlPlaneDurableSessionRetentionWorkerState.RUNNING,
            }:
                self._state = ControlPlaneDurableSessionRetentionWorkerState.STOPPING
                self._stop_requested.set()
            task = self._task
        if task is not None:
            await task
        async with self._state_lock:
            self._task = None
            self._state = ControlPlaneDurableSessionRetentionWorkerState.STOPPED

    async def run_once(
        self,
        *,
        now: datetime | None = None,
    ) -> ControlPlaneDurableSessionRetentionResult:
        if self._state is not ControlPlaneDurableSessionRetentionWorkerState.RUNNING:
            raise ControlPlaneDurableSessionRetentionWorkerStateError(
                f"cannot run durable session retention from {self._state.value}"
            )
        tick_at = self._clock() if now is None else now
        if tick_at.tzinfo is None:
            raise ValueError("durable session retention tick must be timezone-aware")
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
                return ControlPlaneDurableSessionRetentionResult(
                    planned=0,
                    deleted=0,
                    conflicts=0,
                    failures=0,
                    protected_lineage=0,
                    completed_at=tick_at,
                )
            self._planned += result.planned
            self._deleted += result.deleted
            self._conflicts += result.conflicts
            self._failures += result.failures
            self._protected_lineage += result.protected_lineage
            self._last_error = None
            return result

    async def snapshot(self) -> ControlPlaneDurableSessionRetentionWorkerSnapshot:
        async with self._state_lock:
            return ControlPlaneDurableSessionRetentionWorkerSnapshot(
                state=self._state,
                ticks=self._ticks,
                planned=self._planned,
                deleted=self._deleted,
                conflicts=self._conflicts,
                failures=self._failures,
                protected_lineage=self._protected_lineage,
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


def _oldest_terminal_key(record: ControlPlaneDurableSessionRecord) -> tuple[datetime, str]:
    return _required_terminated_at(record), record.id.hex


def _required_terminated_at(record: ControlPlaneDurableSessionRecord) -> datetime:
    if record.terminated_at is None:
        raise ValueError("terminal durable session is missing terminated_at")
    return record.terminated_at
