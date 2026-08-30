import asyncio
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import cast
from uuid import UUID

import pytest

from phoenix_os.agent.contracts import AgentId
from phoenix_os.agent.durable_compatibility import (
    DurableCompatibilityAssessment,
    DurableCompatibilityCategory,
)
from phoenix_os.agent.durable_contracts import (
    CheckpointDigest,
    CheckpointEnvelope,
    CheckpointId,
    CheckpointSequence,
    DurableAgentRunId,
    DurableLease,
    DurableRunLimits,
    DurableRunStatus,
    DurableRunStore,
    DurableRunVersion,
    FencingGeneration,
    RecoveryDisposition,
    RecoveryPoint,
)
from phoenix_os.agent.durable_recovery import (
    DurableRecoveryAssessment,
    DurableRecoveryCoordinator,
)
from phoenix_os.agent.durable_reliability import DurableRecoveryAttemptStore
from phoenix_os.agent.durable_worker import (
    MAX_RECOVERY_WORKER_CANCELLATION_GRACE,
    MAX_RECOVERY_WORKER_CANDIDATES,
    MAX_RECOVERY_WORKER_CONCURRENCY,
    MAX_RECOVERY_WORKER_PAGE_SIZE,
    MAX_RECOVERY_WORKER_PASS_DURATION,
    MAX_RECOVERY_WORKER_SHUTDOWN_GRACE,
    BoundedDurableRecoveryWorker,
    DurableRecoveryWorker,
    DurableRecoveryWorkerConfiguration,
    DurableRecoveryWorkerReport,
    DurableRecoveryWorkerSnapshot,
    DurableRecoveryWorkerState,
)
from phoenix_os.agent.errors import AgentCodecError, AgentStateConflictError

NOW = datetime(2026, 7, 31, 22, tzinfo=UTC)
DIGEST = CheckpointDigest("a" * 64)
AGENT_ID = AgentId("assistant")


def _run_id(value: int) -> DurableAgentRunId:
    return DurableAgentRunId(UUID(int=value))


def _assessment(
    run_id: DurableAgentRunId,
    *,
    now: datetime = NOW,
) -> DurableRecoveryAssessment:
    return DurableRecoveryAssessment(
        run_id=run_id,
        checkpoint_id=CheckpointId(UUID(int=run_id.value.int + 10_000)),
        checkpoint_digest=DIGEST,
        sequence=CheckpointSequence(1),
        run_version=DurableRunVersion(1),
        status=DurableRunStatus.ACTIVE,
        point=RecoveryPoint.SAFE_BOUNDARY,
        disposition=RecoveryDisposition.RESUME,
        compatibility=DurableCompatibilityAssessment(
            agent_id=AGENT_ID,
            category=DurableCompatibilityCategory.EXACT,
        ),
        generation=FencingGeneration(1),
        assessed_at=now,
    )


class _FakeStore:
    def __init__(
        self,
        candidates: tuple[DurableAgentRunId, ...] = (),
        *,
        malformed_pages: list[object] | None = None,
        failure: Exception | None = None,
    ) -> None:
        self.closed = False
        self.candidates = candidates
        self.malformed_pages = [] if malformed_pages is None else malformed_pages
        self.failure = failure
        self.limits = DurableRunLimits()
        self.list_calls: list[tuple[int, DurableAgentRunId | None]] = []

    async def create(self, checkpoint: CheckpointEnvelope) -> None:
        raise AssertionError("create is outside the recovery worker boundary")

    async def get_current(
        self,
        run_id: DurableAgentRunId,
    ) -> CheckpointEnvelope | None:
        raise AssertionError("get_current is outside the recovery worker boundary")

    async def list_history(
        self,
        run_id: DurableAgentRunId,
        *,
        limit: int,
    ) -> tuple[CheckpointEnvelope, ...]:
        raise AssertionError("list_history is outside the recovery worker boundary")

    async def list_recovery_candidates(
        self,
        *,
        limit: int,
        after: DurableAgentRunId | None = None,
    ) -> tuple[DurableAgentRunId, ...]:
        self.list_calls.append((limit, after))
        if self.failure is not None:
            raise self.failure
        if self.malformed_pages:
            return cast(tuple[DurableAgentRunId, ...], self.malformed_pages.pop(0))
        values = tuple(run_id for run_id in self.candidates if after is None or run_id > after)
        return values[:limit]

    async def append(
        self,
        checkpoint: CheckpointEnvelope,
        *,
        expected_version: DurableRunVersion,
        lease: DurableLease,
        now: datetime,
    ) -> CheckpointEnvelope:
        raise AssertionError("append is outside the recovery worker boundary")

    async def claim_recovery_attempt(
        self,
        run_id: DurableAgentRunId,
        *,
        lease: DurableLease,
        now: datetime,
    ) -> int:
        raise AssertionError("claim is owned by the recovery coordinator")

    async def get_recovery_attempt_count(
        self,
        run_id: DurableAgentRunId,
    ) -> int:
        return 0

    async def close(self) -> None:
        self.closed = True


class _LegacyStore:
    def __init__(self, delegate: _FakeStore) -> None:
        self._delegate = delegate

    @property
    def closed(self) -> bool:
        return self._delegate.closed

    async def create(self, checkpoint: CheckpointEnvelope) -> None:
        await self._delegate.create(checkpoint)

    async def get_current(
        self,
        run_id: DurableAgentRunId,
    ) -> CheckpointEnvelope | None:
        return await self._delegate.get_current(run_id)

    async def list_history(
        self,
        run_id: DurableAgentRunId,
        *,
        limit: int,
    ) -> tuple[CheckpointEnvelope, ...]:
        return await self._delegate.list_history(run_id, limit=limit)

    async def list_recovery_candidates(
        self,
        *,
        limit: int,
        after: DurableAgentRunId | None = None,
    ) -> tuple[DurableAgentRunId, ...]:
        return await self._delegate.list_recovery_candidates(limit=limit, after=after)

    async def append(
        self,
        checkpoint: CheckpointEnvelope,
        *,
        expected_version: DurableRunVersion,
        lease: DurableLease,
        now: datetime,
    ) -> CheckpointEnvelope:
        return await self._delegate.append(
            checkpoint,
            expected_version=expected_version,
            lease=lease,
            now=now,
        )

    async def close(self) -> None:
        await self._delegate.close()


class _FakeCoordinator:
    def __init__(self) -> None:
        self._closed = False
        self.conflicts: set[DurableAgentRunId] = set()
        self.failures: set[DurableAgentRunId] = set()
        self.wrong_run_ids: set[DurableAgentRunId] = set()
        self.calls: list[tuple[DurableAgentRunId, str, datetime]] = []
        self.active = 0
        self.max_active = 0
        self.entered = asyncio.Event()
        self.release = asyncio.Event()
        self.block = False
        self.close_error: Exception | None = None

    @property
    def closed(self) -> bool:
        return self._closed

    async def assess_candidate(
        self,
        run_id: DurableAgentRunId,
        *,
        owner_id: str,
        now: datetime,
    ) -> DurableRecoveryAssessment:
        self.calls.append((run_id, owner_id, now))
        self.active += 1
        self.max_active = max(self.max_active, self.active)
        self.entered.set()
        try:
            if self.block:
                await self.release.wait()
            else:
                await asyncio.sleep(0)
            if run_id in self.conflicts:
                raise AgentStateConflictError()
            if run_id in self.failures:
                raise AgentCodecError("fake candidate failure")
            if run_id in self.wrong_run_ids:
                return _assessment(_run_id(run_id.value.int + 1_000), now=now)
            return _assessment(run_id, now=now)
        finally:
            self.active -= 1

    async def assess_page(
        self,
        *,
        owner_id: str,
        now: datetime,
        limit: int,
        after: DurableAgentRunId | None = None,
    ) -> tuple[DurableRecoveryAssessment, ...]:
        raise AssertionError("the worker admits candidates through the store")

    async def close(self) -> None:
        self._closed = True
        if self.close_error is not None:
            raise self.close_error


def _worker(
    candidates: tuple[DurableAgentRunId, ...] = (),
    *,
    configuration: DurableRecoveryWorkerConfiguration | None = None,
    coordinator: _FakeCoordinator | None = None,
    store: _FakeStore | None = None,
    clock: Callable[[], datetime] | None = None,
) -> tuple[BoundedDurableRecoveryWorker, _FakeStore, _FakeCoordinator]:
    selected_store = _FakeStore(candidates) if store is None else store
    selected_coordinator = _FakeCoordinator() if coordinator is None else coordinator
    selected_clock = (lambda: NOW) if clock is None else clock
    worker = BoundedDurableRecoveryWorker(
        store=selected_store,
        coordinator=selected_coordinator,
        configuration=configuration,
        clock=selected_clock,
    )
    return worker, selected_store, selected_coordinator


def test_default_configuration_is_finite_and_normalized() -> None:
    configuration = DurableRecoveryWorkerConfiguration(owner_id=" phoenix-recovery ")

    assert configuration.owner_id == "phoenix-recovery"
    assert configuration.page_size == 32
    assert configuration.max_candidates == 256
    assert configuration.concurrency == 4
    assert configuration.pass_timeout == timedelta(seconds=30)
    assert configuration.shutdown_grace == timedelta(seconds=5)
    assert configuration.cancellation_grace == timedelta(seconds=1)


@pytest.mark.parametrize("owner_id", ["", "Worker", "worker space", "a" * 129])
def test_configuration_rejects_invalid_owner_ids(owner_id: str) -> None:
    with pytest.raises(ValueError, match="owner_id"):
        DurableRecoveryWorkerConfiguration(owner_id=owner_id)


def test_configuration_rejects_non_string_owner_id() -> None:
    with pytest.raises(TypeError, match="owner_id"):
        DurableRecoveryWorkerConfiguration(owner_id=cast(str, object()))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("page_size", True),
        ("page_size", 0),
        ("page_size", MAX_RECOVERY_WORKER_PAGE_SIZE + 1),
        ("max_candidates", 0),
        ("max_candidates", MAX_RECOVERY_WORKER_CANDIDATES + 1),
        ("concurrency", 0),
        ("concurrency", MAX_RECOVERY_WORKER_CONCURRENCY + 1),
    ],
)
def test_configuration_rejects_invalid_integer_bounds(field: str, value: object) -> None:
    with pytest.raises((TypeError, ValueError)):
        if field == "page_size":
            DurableRecoveryWorkerConfiguration(page_size=cast(int, value))
        elif field == "max_candidates":
            DurableRecoveryWorkerConfiguration(max_candidates=cast(int, value))
        else:
            DurableRecoveryWorkerConfiguration(concurrency=cast(int, value))


def test_configuration_rejects_concurrency_larger_than_page_or_pass() -> None:
    with pytest.raises(ValueError, match="page_size"):
        DurableRecoveryWorkerConfiguration(page_size=2, concurrency=3)
    with pytest.raises(ValueError, match="max_candidates"):
        DurableRecoveryWorkerConfiguration(
            page_size=4,
            max_candidates=2,
            concurrency=3,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("pass_timeout", timedelta(0)),
        ("pass_timeout", MAX_RECOVERY_WORKER_PASS_DURATION + timedelta(seconds=1)),
        ("shutdown_grace", timedelta(0)),
        ("shutdown_grace", MAX_RECOVERY_WORKER_SHUTDOWN_GRACE + timedelta(seconds=1)),
        ("cancellation_grace", timedelta(0)),
        (
            "cancellation_grace",
            MAX_RECOVERY_WORKER_CANCELLATION_GRACE + timedelta(seconds=1),
        ),
    ],
)
def test_configuration_rejects_invalid_durations(field: str, value: timedelta) -> None:
    with pytest.raises(ValueError):
        if field == "pass_timeout":
            DurableRecoveryWorkerConfiguration(pass_timeout=value)
        elif field == "shutdown_grace":
            DurableRecoveryWorkerConfiguration(shutdown_grace=value)
        else:
            DurableRecoveryWorkerConfiguration(cancellation_grace=value)


def test_report_validates_order_counts_flags_and_time() -> None:
    first = _assessment(_run_id(1))
    second = _assessment(_run_id(2))
    report = DurableRecoveryWorkerReport(
        assessments=(first, second),
        admitted=4,
        conflicts=1,
        failed=1,
        pages=2,
        exhausted=True,
        timed_out=False,
        stopped=False,
        started_at=NOW,
        completed_at=NOW,
    )

    assert report.assessed == 2
    assert report.truncated is False

    with pytest.raises(ValueError, match="ordered"):
        replace(report, assessments=(second, first))
    with pytest.raises(ValueError, match="outcomes"):
        replace(report, admitted=3)
    with pytest.raises(ValueError, match="both"):
        replace(report, exhausted=False, timed_out=True, stopped=True)
    with pytest.raises(ValueError, match="interrupted"):
        replace(report, timed_out=True)
    with pytest.raises(ValueError, match="precede"):
        replace(report, completed_at=NOW - timedelta(seconds=1))


def test_snapshot_validates_cumulative_invariants() -> None:
    snapshot = DurableRecoveryWorkerSnapshot(
        state=DurableRecoveryWorkerState.RUNNING,
        active=1,
        passes_started=2,
        passes_completed=1,
        passes_failed=0,
        passes_timed_out=0,
        passes_stopped=0,
        candidates_admitted=3,
        assessed=2,
        conflicts=1,
        failed=0,
        forced_cancellations=0,
        last_started_at=NOW,
        last_completed_at=NOW,
    )

    assert snapshot.accepting
    with pytest.raises(ValueError, match="started passes"):
        replace(snapshot, passes_completed=3)
    with pytest.raises(ValueError, match="candidate outcomes"):
        replace(snapshot, assessed=4)


def test_worker_implements_protocol_and_rejects_invalid_dependencies() -> None:
    worker, store, coordinator = _worker()

    assert isinstance(worker, DurableRecoveryWorker)
    assert isinstance(store, DurableRunStore)
    assert isinstance(coordinator, DurableRecoveryCoordinator)

    with pytest.raises(TypeError, match="store"):
        BoundedDurableRecoveryWorker(
            store=cast(DurableRunStore, object()),
            coordinator=coordinator,
        )
    with pytest.raises(TypeError, match="coordinator"):
        BoundedDurableRecoveryWorker(
            store=store,
            coordinator=cast(DurableRecoveryCoordinator, object()),
        )
    with pytest.raises(TypeError, match="configuration"):
        BoundedDurableRecoveryWorker(
            store=store,
            coordinator=coordinator,
            configuration=cast(DurableRecoveryWorkerConfiguration, object()),
        )
    with pytest.raises(TypeError, match="clock"):
        BoundedDurableRecoveryWorker(
            store=store,
            coordinator=coordinator,
            clock=cast(Callable[[], datetime], 42),
        )


@pytest.mark.asyncio
async def test_start_is_idempotent_and_does_not_schedule_autonomous_work() -> None:
    worker, store, coordinator = _worker((_run_id(1),))

    assert worker.state is DurableRecoveryWorkerState.CREATED
    await worker.start()
    await worker.start()

    snapshot = await worker.snapshot()
    assert snapshot.state is DurableRecoveryWorkerState.RUNNING
    assert snapshot.passes_started == 0
    assert store.list_calls == []
    assert coordinator.calls == []


@pytest.mark.asyncio
async def test_run_requires_running_state_and_closed_worker_cannot_restart() -> None:
    worker, _store, _coordinator = _worker()

    with pytest.raises(RuntimeError, match="not running"):
        await worker.run_once()

    await worker.close()
    with pytest.raises(RuntimeError, match="restarted"):
        await worker.start()
    with pytest.raises(RuntimeError, match="not running"):
        await worker.run_once()


@pytest.mark.asyncio
async def test_empty_scan_is_exhausted_and_content_free() -> None:
    worker, store, coordinator = _worker()
    await worker.start()

    report = await worker.run_once()
    snapshot = await worker.snapshot()

    assert report.assessments == ()
    assert report.admitted == 0
    assert report.pages == 1
    assert report.exhausted
    assert not report.truncated
    assert store.list_calls == [(32, None)]
    assert coordinator.calls == []
    assert snapshot.passes_completed == 1
    assert snapshot.candidates_admitted == 0


@pytest.mark.asyncio
async def test_scan_pages_deterministically_and_preserves_order() -> None:
    candidates = tuple(_run_id(value) for value in range(1, 8))
    configuration = DurableRecoveryWorkerConfiguration(
        page_size=3,
        max_candidates=10,
        concurrency=2,
    )
    worker, store, coordinator = _worker(candidates, configuration=configuration)
    await worker.start()

    report = await worker.run_once()

    assert tuple(item.run_id for item in report.assessments) == candidates
    assert report.admitted == 7
    assert report.pages == 3
    assert report.exhausted
    assert [call[0] for call in store.list_calls] == [3, 3, 3]
    assert [call[1] for call in store.list_calls] == [None, _run_id(3), _run_id(6)]
    assert all(call[1] == "phoenix-recovery" for call in coordinator.calls)


@pytest.mark.asyncio
async def test_max_candidate_bound_truncates_without_unbounded_probe() -> None:
    candidates = tuple(_run_id(value) for value in range(1, 20))
    configuration = DurableRecoveryWorkerConfiguration(
        page_size=4,
        max_candidates=5,
        concurrency=2,
    )
    worker, store, _coordinator = _worker(candidates, configuration=configuration)
    await worker.start()

    report = await worker.run_once()

    assert report.admitted == 5
    assert report.assessed == 5
    assert report.truncated
    assert report.pages == 2
    assert store.list_calls == [(4, None), (1, _run_id(4))]


@pytest.mark.asyncio
async def test_candidate_concurrency_never_exceeds_configuration() -> None:
    candidates = tuple(_run_id(value) for value in range(1, 10))
    configuration = DurableRecoveryWorkerConfiguration(
        page_size=9,
        max_candidates=9,
        concurrency=3,
    )
    coordinator = _FakeCoordinator()
    worker, _store, coordinator = _worker(
        candidates,
        configuration=configuration,
        coordinator=coordinator,
    )
    await worker.start()

    report = await worker.run_once()

    assert report.assessed == 9
    assert coordinator.max_active == 3


@pytest.mark.asyncio
async def test_conflicts_and_candidate_failures_are_isolated() -> None:
    candidates = tuple(_run_id(value) for value in range(1, 6))
    coordinator = _FakeCoordinator()
    coordinator.conflicts.add(_run_id(2))
    coordinator.failures.add(_run_id(3))
    coordinator.wrong_run_ids.add(_run_id(4))
    worker, _store, _coordinator = _worker(candidates, coordinator=coordinator)
    await worker.start()

    report = await worker.run_once()
    snapshot = await worker.snapshot()

    assert tuple(item.run_id for item in report.assessments) == (_run_id(1), _run_id(5))
    assert report.conflicts == 1
    assert report.failed == 2
    assert snapshot.assessed == 2
    assert snapshot.conflicts == 1
    assert snapshot.failed == 2


@pytest.mark.asyncio
async def test_only_one_pass_can_run_at_a_time() -> None:
    coordinator = _FakeCoordinator()
    coordinator.block = True
    worker, _store, coordinator = _worker((_run_id(1),), coordinator=coordinator)
    await worker.start()

    active = asyncio.create_task(worker.run_once())
    await coordinator.entered.wait()
    with pytest.raises(AgentStateConflictError):
        await worker.run_once()

    coordinator.release.set()
    report = await active
    assert report.assessed == 1


@pytest.mark.asyncio
async def test_pass_timeout_cancels_inflight_assessments_and_reports_partial_admission() -> None:
    coordinator = _FakeCoordinator()
    coordinator.block = True
    configuration = DurableRecoveryWorkerConfiguration(
        page_size=2,
        max_candidates=2,
        concurrency=2,
        pass_timeout=timedelta(milliseconds=20),
    )
    worker, _store, coordinator = _worker(
        (_run_id(1), _run_id(2)),
        configuration=configuration,
        coordinator=coordinator,
    )
    await worker.start()

    report = await worker.run_once()
    snapshot = await worker.snapshot()

    assert report.timed_out
    assert not report.exhausted
    assert report.admitted == 2
    assert report.assessed == 0
    assert coordinator.active == 0
    assert snapshot.passes_timed_out == 1
    assert snapshot.active == 0


@pytest.mark.asyncio
async def test_close_from_created_is_finite_idempotent_and_closes_coordinator() -> None:
    worker, _store, coordinator = _worker()

    await worker.close()
    await worker.close()

    assert worker.state is DurableRecoveryWorkerState.CLOSED
    assert coordinator.closed
    assert (await worker.snapshot()).accepting is False


@pytest.mark.asyncio
async def test_close_requests_stop_and_drains_between_candidate_batches() -> None:
    candidates = tuple(_run_id(value) for value in range(1, 5))
    coordinator = _FakeCoordinator()
    coordinator.block = True
    configuration = DurableRecoveryWorkerConfiguration(
        page_size=4,
        max_candidates=4,
        concurrency=1,
        shutdown_grace=timedelta(seconds=1),
    )
    worker, _store, coordinator = _worker(
        candidates,
        configuration=configuration,
        coordinator=coordinator,
    )
    await worker.start()

    pass_task = asyncio.create_task(worker.run_once())
    await coordinator.entered.wait()
    close_task = asyncio.create_task(worker.close())
    await asyncio.sleep(0)
    assert worker.state is DurableRecoveryWorkerState.CLOSING

    coordinator.release.set()
    report = await pass_task
    await close_task

    assert report.stopped
    assert report.admitted == 4
    assert report.assessed == 1
    snapshot = await worker.snapshot()
    assert snapshot.state is DurableRecoveryWorkerState.CLOSED
    assert len(coordinator.calls) == 1


@pytest.mark.asyncio
async def test_close_force_cancels_a_stuck_pass_after_grace() -> None:
    coordinator = _FakeCoordinator()
    coordinator.block = True
    configuration = DurableRecoveryWorkerConfiguration(
        page_size=1,
        max_candidates=1,
        concurrency=1,
        pass_timeout=timedelta(seconds=5),
        shutdown_grace=timedelta(milliseconds=10),
        cancellation_grace=timedelta(milliseconds=20),
    )
    worker, _store, coordinator = _worker(
        (_run_id(1),),
        configuration=configuration,
        coordinator=coordinator,
    )
    await worker.start()

    pass_task = asyncio.create_task(worker.run_once())
    await coordinator.entered.wait()
    await worker.close()

    with pytest.raises(asyncio.CancelledError):
        await pass_task
    snapshot = await worker.snapshot()
    assert snapshot.forced_cancellations == 1
    assert snapshot.passes_stopped == 1
    assert snapshot.active == 0
    assert snapshot.state is DurableRecoveryWorkerState.CLOSED


@pytest.mark.asyncio
async def test_concurrent_close_callers_wait_for_the_same_transition() -> None:
    worker, _store, coordinator = _worker()
    await worker.start()

    await asyncio.gather(worker.close(), worker.close(), worker.close())

    assert worker.state is DurableRecoveryWorkerState.CLOSED
    assert coordinator.closed


@pytest.mark.asyncio
async def test_coordinator_close_failure_still_leaves_worker_closed() -> None:
    coordinator = _FakeCoordinator()
    coordinator.close_error = RuntimeError("close failed")
    worker, _store, _coordinator = _worker(coordinator=coordinator)
    await worker.start()

    with pytest.raises(RuntimeError, match="close failed"):
        await worker.close()

    assert worker.state is DurableRecoveryWorkerState.CLOSED


@pytest.mark.asyncio
async def test_store_page_failure_fails_pass_and_clears_active_lifecycle() -> None:
    store = _FakeStore(failure=AgentCodecError("store failed"))
    worker, _store, _coordinator = _worker(store=store)
    await worker.start()

    with pytest.raises(AgentCodecError, match="store failed"):
        await worker.run_once()

    snapshot = await worker.snapshot()
    assert snapshot.passes_started == 1
    assert snapshot.passes_failed == 1
    assert snapshot.active == 0

    store.failure = None
    report = await worker.run_once()
    assert report.exhausted


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "page",
    [
        [_run_id(1)],
        (_run_id(1), _run_id(1)),
        (_run_id(2), _run_id(1)),
        (cast(DurableAgentRunId, object()),),
    ],
)
async def test_malformed_candidate_pages_fail_closed(page: object) -> None:
    store = _FakeStore(malformed_pages=[page])
    worker, _store, _coordinator = _worker(store=store)
    await worker.start()

    with pytest.raises((TypeError, AgentCodecError)):
        await worker.run_once()

    assert (await worker.snapshot()).passes_failed == 1


@pytest.mark.asyncio
async def test_page_larger_than_requested_limit_fails_closed() -> None:
    configuration = DurableRecoveryWorkerConfiguration(
        page_size=1,
        max_candidates=1,
        concurrency=1,
    )
    store = _FakeStore(malformed_pages=[(_run_id(1), _run_id(2))])
    worker, _store, _coordinator = _worker(
        store=store,
        configuration=configuration,
    )
    await worker.start()

    with pytest.raises(AgentCodecError, match="requested limit"):
        await worker.run_once()


@pytest.mark.asyncio
async def test_cursor_rollback_on_later_page_fails_closed() -> None:
    configuration = DurableRecoveryWorkerConfiguration(
        page_size=1,
        max_candidates=2,
        concurrency=1,
    )
    store = _FakeStore(malformed_pages=[(_run_id(2),), (_run_id(1),)])
    worker, _store, _coordinator = _worker(
        store=store,
        configuration=configuration,
    )
    await worker.start()

    with pytest.raises(AgentCodecError, match="strictly ordered"):
        await worker.run_once()


@pytest.mark.asyncio
async def test_invalid_or_rollback_clock_fails_closed() -> None:
    invalid_worker, _store, _coordinator = _worker(clock=lambda: NOW.replace(tzinfo=None))
    await invalid_worker.start()
    with pytest.raises(ValueError, match="timezone-aware"):
        await invalid_worker.run_once()

    values = iter((NOW, NOW - timedelta(seconds=1)))
    rollback_worker, _store, _coordinator = _worker(clock=lambda: next(values))
    await rollback_worker.start()
    with pytest.raises(ValueError, match="precede"):
        await rollback_worker.run_once()
    assert (await rollback_worker.snapshot()).passes_failed == 1


@pytest.mark.asyncio
async def test_worker_uses_fresh_clock_and_exact_owner_for_each_candidate() -> None:
    times = iter(
        (
            NOW,
            NOW + timedelta(seconds=1),
            NOW + timedelta(seconds=2),
            NOW + timedelta(seconds=3),
        )
    )
    configuration = DurableRecoveryWorkerConfiguration(owner_id="startup-worker")
    worker, _store, coordinator = _worker(
        (_run_id(1), _run_id(2)),
        configuration=configuration,
        clock=lambda: next(times),
    )
    await worker.start()

    report = await worker.run_once()

    assert report.started_at == NOW
    assert report.completed_at == NOW + timedelta(seconds=3)
    assert [call[1] for call in coordinator.calls] == ["startup-worker", "startup-worker"]
    assert [call[2] for call in coordinator.calls] == [
        NOW + timedelta(seconds=1),
        NOW + timedelta(seconds=2),
    ]


@pytest.mark.asyncio
async def test_worker_without_persistent_attempt_store_fails_closed_before_enumeration() -> None:
    backing = _FakeStore((_run_id(1),))
    legacy = _LegacyStore(backing)
    coordinator = _FakeCoordinator()

    assert isinstance(backing, DurableRecoveryAttemptStore)
    assert isinstance(legacy, DurableRunStore)
    assert not isinstance(legacy, DurableRecoveryAttemptStore)

    worker = BoundedDurableRecoveryWorker(
        store=legacy,
        coordinator=coordinator,
        clock=lambda: NOW,
    )
    await worker.start()

    with pytest.raises(AgentStateConflictError):
        await worker.run_once()

    assert backing.list_calls == []
    assert coordinator.calls == []
    snapshot = await worker.snapshot()
    assert snapshot.passes_started == 0
    assert snapshot.candidates_admitted == 0
