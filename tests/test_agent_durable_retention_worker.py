from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import cast
from uuid import UUID

import pytest

from phoenix_os.agent.durable_contracts import (
    CheckpointDigest,
    CheckpointEnvelope,
    DurableAgentRunId,
    DurableLease,
    DurableRunStatus,
    DurableRunTombstone,
    DurableRunVersion,
    FencingGeneration,
    RetentionPolicy,
)
from phoenix_os.agent.durable_lease import (
    DurableLeaseManager,
    InMemoryDurableLeaseManager,
)
from phoenix_os.agent.durable_memory import InMemoryDurableRunStore
from phoenix_os.agent.durable_retention_worker import (
    MAX_RETENTION_WORKER_CANDIDATES,
    MAX_RETENTION_WORKER_PAGE_SIZE,
    MAX_RETENTION_WORKER_PASS_DURATION,
    BoundedDurableRetentionWorker,
    DurableRetentionWorker,
    DurableRetentionWorkerConfiguration,
    DurableRetentionWorkerReport,
    DurableRetentionWorkerState,
)
from phoenix_os.agent.errors import (
    AgentCodecError,
    AgentStateConflictError,
)


def test_retention_worker_configuration_has_finite_defaults() -> None:
    configuration = DurableRetentionWorkerConfiguration()

    assert configuration.owner_id == "phoenix-retention"

    assert 0 < configuration.page_size <= MAX_RETENTION_WORKER_PAGE_SIZE

    assert 0 < configuration.max_candidates <= MAX_RETENTION_WORKER_CANDIDATES

    assert timedelta(0) < configuration.pass_timeout <= MAX_RETENTION_WORKER_PASS_DURATION


@pytest.mark.parametrize(
    ("field", "value", "error_type"),
    [
        ("page_size", 0, ValueError),
        ("page_size", True, TypeError),
        (
            "page_size",
            MAX_RETENTION_WORKER_PAGE_SIZE + 1,
            ValueError,
        ),
        ("max_candidates", 0, ValueError),
        ("max_candidates", True, TypeError),
        (
            "max_candidates",
            MAX_RETENTION_WORKER_CANDIDATES + 1,
            ValueError,
        ),
        ("pass_timeout", timedelta(0), ValueError),
        (
            "pass_timeout",
            MAX_RETENTION_WORKER_PASS_DURATION + timedelta(microseconds=1),
            ValueError,
        ),
    ],
)
def test_retention_worker_configuration_rejects_unbounded_values(
    field: str,
    value: object,
    error_type: type[Exception],
) -> None:
    arguments: dict[str, object] = {
        field: value,
    }

    with pytest.raises(error_type):
        DurableRetentionWorkerConfiguration(
            **arguments,  # type: ignore[arg-type]
        )


class _StructurallyValidRetentionWorker:
    @property
    def state(self) -> DurableRetentionWorkerState:
        return DurableRetentionWorkerState.CREATED

    async def start(self) -> None:
        return None

    async def run_once(self) -> object:
        return object()

    async def snapshot(self) -> object:
        return object()

    async def close(self) -> None:
        return None


def test_retention_worker_protocol_is_runtime_checkable() -> None:
    candidate = _StructurallyValidRetentionWorker()

    assert isinstance(candidate, DurableRetentionWorker)


def test_bounded_retention_worker_exposes_finite_lifecycle() -> None:
    assert hasattr(BoundedDurableRetentionWorker, "start")
    assert hasattr(BoundedDurableRetentionWorker, "run_once")
    assert hasattr(BoundedDurableRetentionWorker, "snapshot")
    assert hasattr(BoundedDurableRetentionWorker, "close")

    assert DurableRetentionWorkerState.CREATED.value == "created"
    assert DurableRetentionWorkerState.RUNNING.value == "running"
    assert DurableRetentionWorkerState.CLOSING.value == "closing"
    assert DurableRetentionWorkerState.CLOSED.value == "closed"


RETENTION_POLICY = RetentionPolicy(
    payload_retention=timedelta(seconds=10),
    metadata_retention=timedelta(seconds=20),
    tombstone_retention=timedelta(seconds=30),
)

NOW = datetime(2026, 8, 2, 12, tzinfo=UTC)


def test_retention_worker_requires_explicit_retention_dependencies() -> None:
    store = InMemoryDurableRunStore()

    worker = BoundedDurableRetentionWorker(
        store=store,
        lease_manager=store.lease_manager,
        policy=RETENTION_POLICY,
        clock=lambda: NOW,
    )

    assert isinstance(worker, DurableRetentionWorker)
    assert worker.store is store
    assert worker.lease_manager is store.lease_manager
    assert worker.policy == RETENTION_POLICY
    assert worker.state is DurableRetentionWorkerState.CREATED


def test_retention_worker_rejects_store_without_retention_capability() -> None:
    class _NotARetentionStore:
        pass

    leases = InMemoryDurableLeaseManager()

    with pytest.raises(
        TypeError,
        match="DurableRetentionStore",
    ):
        BoundedDurableRetentionWorker(
            store=_NotARetentionStore(),  # type: ignore[arg-type]
            lease_manager=leases,
            policy=RETENTION_POLICY,
            clock=lambda: NOW,
        )


def test_retention_worker_rejects_mismatched_lease_manager() -> None:
    store = InMemoryDurableRunStore()
    other_leases = InMemoryDurableLeaseManager()

    with pytest.raises(
        ValueError,
        match="must match",
    ):
        BoundedDurableRetentionWorker(
            store=store,
            lease_manager=other_leases,
            policy=RETENTION_POLICY,
            clock=lambda: NOW,
        )


def test_retention_worker_rejects_invalid_policy_type() -> None:
    store = InMemoryDurableRunStore()

    with pytest.raises(
        TypeError,
        match="RetentionPolicy",
    ):
        BoundedDurableRetentionWorker(
            store=store,
            lease_manager=store.lease_manager,
            policy=object(),  # type: ignore[arg-type]
            clock=lambda: NOW,
        )


class _RecordingRetentionStore(InMemoryDurableRunStore):
    def __init__(self) -> None:
        super().__init__()
        self.cleanup_candidate_calls: list[
            tuple[
                RetentionPolicy,
                datetime,
                int,
                DurableAgentRunId | None,
            ]
        ] = []

    async def list_cleanup_candidates(
        self,
        *,
        policy: RetentionPolicy,
        now: datetime,
        limit: int,
        after: DurableAgentRunId | None = None,
    ) -> tuple[DurableAgentRunId, ...]:
        self.cleanup_candidate_calls.append(
            (
                policy,
                now,
                limit,
                after,
            )
        )
        return ()

    async def delete_expired_protected_payloads(
        self,
        run_id: DurableAgentRunId,
        *,
        policy: RetentionPolicy,
        lease: DurableLease,
        now: datetime,
    ) -> bool:
        del run_id, policy, lease, now
        return False


@pytest.mark.asyncio
async def test_retention_run_once_scans_one_bounded_candidate_page() -> None:
    store = _RecordingRetentionStore()

    configuration = DurableRetentionWorkerConfiguration(
        page_size=7,
        max_candidates=21,
    )

    worker = BoundedDurableRetentionWorker(
        store=store,
        lease_manager=store.lease_manager,
        policy=RETENTION_POLICY,
        configuration=configuration,
        clock=lambda: NOW,
    )

    await worker.start()
    await worker.run_once()

    assert store.cleanup_candidate_calls == [
        (
            RETENTION_POLICY,
            NOW,
            7,
            None,
        )
    ]

    snapshot = await worker.snapshot()

    assert snapshot.passes_started == 1
    assert snapshot.passes_completed == 1

    await worker.close()
    await store.close()


class _PagedRecordingRetentionStore(_RecordingRetentionStore):
    def __init__(
        self,
        pages: tuple[
            tuple[DurableAgentRunId, ...],
            ...,
        ],
    ) -> None:
        super().__init__()
        self._pages = pages

    async def list_cleanup_candidates(
        self,
        *,
        policy: RetentionPolicy,
        now: datetime,
        limit: int,
        after: DurableAgentRunId | None = None,
    ) -> tuple[DurableAgentRunId, ...]:
        self.cleanup_candidate_calls.append(
            (
                policy,
                now,
                limit,
                after,
            )
        )

        page_index = len(self.cleanup_candidate_calls) - 1

        if page_index >= len(self._pages):
            return ()

        return self._pages[page_index]


@pytest.mark.asyncio
async def test_retention_run_once_pages_until_max_candidate_bound() -> None:
    run_ids = tuple(DurableAgentRunId(UUID(int=value)) for value in range(1, 6))

    store = _PagedRecordingRetentionStore(
        (
            run_ids[:2],
            run_ids[2:4],
            run_ids[4:],
        )
    )

    configuration = DurableRetentionWorkerConfiguration(
        page_size=2,
        max_candidates=5,
    )

    worker = BoundedDurableRetentionWorker(
        store=store,
        lease_manager=store.lease_manager,
        policy=RETENTION_POLICY,
        configuration=configuration,
        clock=lambda: NOW,
    )

    await worker.start()
    await worker.run_once()

    assert store.cleanup_candidate_calls == [
        (
            RETENTION_POLICY,
            NOW,
            2,
            None,
        ),
        (
            RETENTION_POLICY,
            NOW,
            2,
            run_ids[1],
        ),
        (
            RETENTION_POLICY,
            NOW,
            1,
            run_ids[3],
        ),
    ]

    snapshot = await worker.snapshot()

    assert snapshot.passes_started == 1
    assert snapshot.passes_completed == 1

    await worker.close()
    await store.close()


class _RecordingRetentionLeaseManager(InMemoryDurableLeaseManager):
    def __init__(self) -> None:
        super().__init__()
        self.acquire_calls: list[
            tuple[
                DurableAgentRunId,
                str,
                datetime,
            ]
        ] = []
        self.release_calls: list[
            tuple[
                DurableLease,
                datetime,
            ]
        ] = []

    async def acquire(
        self,
        run_id: DurableAgentRunId,
        *,
        owner_id: str,
        now: datetime,
    ) -> DurableLease:
        self.acquire_calls.append(
            (
                run_id,
                owner_id,
                now,
            )
        )

        return await super().acquire(
            run_id,
            owner_id=owner_id,
            now=now,
        )

    async def release(
        self,
        lease: DurableLease,
        *,
        now: datetime,
    ) -> None:
        self.release_calls.append(
            (
                lease,
                now,
            )
        )

        await super().release(
            lease,
            now=now,
        )


class _SingleCandidateRetentionStore(InMemoryDurableRunStore):
    def __init__(
        self,
        *,
        lease_manager: _RecordingRetentionLeaseManager,
        run_id: DurableAgentRunId,
    ) -> None:
        super().__init__(
            lease_manager=lease_manager,
        )
        self._candidate_run_id = run_id
        self.cleanup_candidate_calls = 0

    async def list_cleanup_candidates(
        self,
        *,
        policy: RetentionPolicy,
        now: datetime,
        limit: int,
        after: DurableAgentRunId | None = None,
    ) -> tuple[DurableAgentRunId, ...]:
        del policy, now

        self.cleanup_candidate_calls += 1

        if after is not None:
            return ()

        if limit < 1:
            return ()

        return (self._candidate_run_id,)

    async def delete_expired_protected_payloads(
        self,
        run_id: DurableAgentRunId,
        *,
        policy: RetentionPolicy,
        lease: DurableLease,
        now: datetime,
    ) -> bool:
        del run_id, policy, lease, now
        return False


@pytest.mark.asyncio
async def test_retention_run_once_acquires_and_releases_cleanup_lease() -> None:
    run_id = DurableAgentRunId(UUID(int=101))

    leases = _RecordingRetentionLeaseManager()

    store = _SingleCandidateRetentionStore(
        lease_manager=leases,
        run_id=run_id,
    )

    configuration = DurableRetentionWorkerConfiguration(
        owner_id="phoenix-retention-test",
        page_size=2,
        max_candidates=2,
    )

    worker = BoundedDurableRetentionWorker(
        store=store,
        lease_manager=leases,
        policy=RETENTION_POLICY,
        configuration=configuration,
        clock=lambda: NOW,
    )

    await worker.start()
    await worker.run_once()

    assert leases.acquire_calls == [
        (
            run_id,
            "phoenix-retention-test",
            NOW,
        )
    ]

    assert len(leases.release_calls) == 1

    released_lease, released_at = leases.release_calls[0]

    assert released_lease.run_id == run_id
    assert released_lease.owner_id == ("phoenix-retention-test")
    assert released_at == NOW

    assert (
        await leases.get_current(
            run_id,
            now=NOW,
        )
        is None
    )

    await worker.close()
    await store.close()


class _PayloadCleanupRetentionStore(_SingleCandidateRetentionStore):
    def __init__(
        self,
        *,
        lease_manager: _RecordingRetentionLeaseManager,
        run_id: DurableAgentRunId,
    ) -> None:
        super().__init__(
            lease_manager=lease_manager,
            run_id=run_id,
        )

        self.payload_cleanup_calls: list[
            tuple[
                DurableAgentRunId,
                RetentionPolicy,
                DurableLease,
                datetime,
            ]
        ] = []

    async def delete_expired_protected_payloads(
        self,
        run_id: DurableAgentRunId,
        *,
        policy: RetentionPolicy,
        lease: DurableLease,
        now: datetime,
    ) -> bool:
        self.payload_cleanup_calls.append(
            (
                run_id,
                policy,
                lease,
                now,
            )
        )

        return True


@pytest.mark.asyncio
async def test_retention_run_once_deletes_due_payload_under_cleanup_lease() -> None:
    run_id = DurableAgentRunId(UUID(int=102))

    leases = _RecordingRetentionLeaseManager()

    store = _PayloadCleanupRetentionStore(
        lease_manager=leases,
        run_id=run_id,
    )

    configuration = DurableRetentionWorkerConfiguration(
        owner_id="phoenix-retention-payload-test",
        page_size=2,
        max_candidates=2,
    )

    worker = BoundedDurableRetentionWorker(
        store=store,
        lease_manager=leases,
        policy=RETENTION_POLICY,
        configuration=configuration,
        clock=lambda: NOW,
    )

    await worker.start()
    await worker.run_once()

    assert len(store.payload_cleanup_calls) == 1

    (
        cleaned_run_id,
        cleaned_policy,
        cleanup_lease,
        cleaned_at,
    ) = store.payload_cleanup_calls[0]

    assert cleaned_run_id == run_id
    assert cleaned_policy == RETENTION_POLICY
    assert cleanup_lease.run_id == run_id
    assert cleanup_lease.owner_id == ("phoenix-retention-payload-test")
    assert cleaned_at == NOW

    assert len(leases.release_calls) == 1

    released_lease, released_at = leases.release_calls[0]

    assert released_lease == cleanup_lease
    assert released_at == NOW

    assert (
        await leases.get_current(
            run_id,
            now=NOW,
        )
        is None
    )

    await worker.close()
    await store.close()


class _MetadataDueRetentionStore(_PayloadCleanupRetentionStore):
    def __init__(
        self,
        *,
        lease_manager: _RecordingRetentionLeaseManager,
        run_id: DurableAgentRunId,
    ) -> None:
        super().__init__(
            lease_manager=lease_manager,
            run_id=run_id,
        )

        self.events: list[str] = []

        self.tombstone_calls: list[
            tuple[
                DurableAgentRunId,
                RetentionPolicy,
                DurableLease,
                datetime,
            ]
        ] = []

        self._terminal_checkpoint = cast(
            CheckpointEnvelope,
            SimpleNamespace(
                status=DurableRunStatus.COMPLETED,
                created_at=(NOW - RETENTION_POLICY.metadata_retention),
            ),
        )

    async def get_current(
        self,
        run_id: DurableAgentRunId,
    ) -> CheckpointEnvelope | None:
        if run_id != self._candidate_run_id:
            return None

        return self._terminal_checkpoint

    async def delete_expired_protected_payloads(
        self,
        run_id: DurableAgentRunId,
        *,
        policy: RetentionPolicy,
        lease: DurableLease,
        now: datetime,
    ) -> bool:
        self.events.append("payload")

        return await super().delete_expired_protected_payloads(
            run_id,
            policy=policy,
            lease=lease,
            now=now,
        )

    async def tombstone_terminal_run(
        self,
        run_id: DurableAgentRunId,
        *,
        policy: RetentionPolicy,
        lease: DurableLease,
        now: datetime,
    ) -> DurableRunTombstone:
        self.events.append("tombstone")

        self.tombstone_calls.append(
            (
                run_id,
                policy,
                lease,
                now,
            )
        )

        return cast(
            DurableRunTombstone,
            SimpleNamespace(),
        )


@pytest.mark.asyncio
async def test_retention_run_once_tombstones_metadata_due_terminal_run() -> None:
    run_id = DurableAgentRunId(UUID(int=103))

    leases = _RecordingRetentionLeaseManager()

    store = _MetadataDueRetentionStore(
        lease_manager=leases,
        run_id=run_id,
    )

    configuration = DurableRetentionWorkerConfiguration(
        owner_id="phoenix-retention-tombstone-test",
        page_size=2,
        max_candidates=2,
    )

    worker = BoundedDurableRetentionWorker(
        store=store,
        lease_manager=leases,
        policy=RETENTION_POLICY,
        configuration=configuration,
        clock=lambda: NOW,
    )

    await worker.start()
    await worker.run_once()

    assert store.events == [
        "payload",
        "tombstone",
    ]

    assert len(store.payload_cleanup_calls) == 1
    assert len(store.tombstone_calls) == 1

    (
        _,
        _,
        payload_lease,
        payload_at,
    ) = store.payload_cleanup_calls[0]

    (
        tombstoned_run_id,
        tombstoned_policy,
        tombstone_lease,
        tombstoned_at,
    ) = store.tombstone_calls[0]

    assert tombstoned_run_id == run_id
    assert tombstoned_policy == RETENTION_POLICY

    assert tombstone_lease == payload_lease
    assert tombstone_lease.run_id == run_id
    assert tombstone_lease.owner_id == ("phoenix-retention-tombstone-test")

    assert payload_at == NOW
    assert tombstoned_at == NOW

    assert len(leases.release_calls) == 1

    released_lease, released_at = leases.release_calls[0]

    assert released_lease == tombstone_lease
    assert released_at == NOW

    assert (
        await leases.get_current(
            run_id,
            now=NOW,
        )
        is None
    )

    await worker.close()
    await store.close()


class _ExpiredTombstoneRetentionStore(_PayloadCleanupRetentionStore):
    def __init__(
        self,
        *,
        lease_manager: _RecordingRetentionLeaseManager,
        run_id: DurableAgentRunId,
    ) -> None:
        super().__init__(
            lease_manager=lease_manager,
            run_id=run_id,
        )

        self.purge_calls: list[
            tuple[
                DurableAgentRunId,
                DurableLease,
                datetime,
            ]
        ] = []

        self._expired_tombstone = DurableRunTombstone(
            run_id=run_id,
            terminal_status=DurableRunStatus.COMPLETED,
            terminal_version=DurableRunVersion(1),
            final_checkpoint_digest=CheckpointDigest("f" * 64),
            deletion_generation=FencingGeneration(1),
            terminal_at=(NOW - RETENTION_POLICY.tombstone_retention),
            retain_until=NOW,
        )

    async def get_tombstone(
        self,
        run_id: DurableAgentRunId,
    ) -> DurableRunTombstone | None:
        if run_id != self._candidate_run_id:
            return None

        return self._expired_tombstone

    async def purge_expired_tombstone(
        self,
        run_id: DurableAgentRunId,
        *,
        lease: DurableLease,
        now: datetime,
    ) -> bool:
        self.purge_calls.append(
            (
                run_id,
                lease,
                now,
            )
        )

        return True


@pytest.mark.asyncio
async def test_retention_run_once_purges_expired_tombstone_under_cleanup_lease() -> None:
    run_id = DurableAgentRunId(UUID(int=104))

    leases = _RecordingRetentionLeaseManager()

    store = _ExpiredTombstoneRetentionStore(
        lease_manager=leases,
        run_id=run_id,
    )

    configuration = DurableRetentionWorkerConfiguration(
        owner_id="phoenix-retention-purge-test",
        page_size=2,
        max_candidates=2,
    )

    worker = BoundedDurableRetentionWorker(
        store=store,
        lease_manager=leases,
        policy=RETENTION_POLICY,
        configuration=configuration,
        clock=lambda: NOW,
    )

    await worker.start()
    await worker.run_once()

    assert store.payload_cleanup_calls == []
    assert len(store.purge_calls) == 1

    (
        purged_run_id,
        purge_lease,
        purged_at,
    ) = store.purge_calls[0]

    assert purged_run_id == run_id
    assert purge_lease.run_id == run_id
    assert purge_lease.owner_id == ("phoenix-retention-purge-test")
    assert purged_at == NOW

    assert len(leases.release_calls) == 1

    released_lease, released_at = leases.release_calls[0]

    assert released_lease == purge_lease
    assert released_at == NOW

    assert (
        await leases.get_current(
            run_id,
            now=NOW,
        )
        is None
    )

    await worker.close()
    await store.close()


class _FirstAcquireConflictLeaseManager(_RecordingRetentionLeaseManager):
    def __init__(
        self,
        *,
        conflict_run_id: DurableAgentRunId,
    ) -> None:
        super().__init__()
        self._conflict_run_id = conflict_run_id

    async def acquire(
        self,
        run_id: DurableAgentRunId,
        *,
        owner_id: str,
        now: datetime,
    ) -> DurableLease:
        if run_id == self._conflict_run_id:
            self.acquire_calls.append(
                (
                    run_id,
                    owner_id,
                    now,
                )
            )
            raise AgentStateConflictError()

        return await super().acquire(
            run_id,
            owner_id=owner_id,
            now=now,
        )


class _TwoCandidateRetentionStore(InMemoryDurableRunStore):
    def __init__(
        self,
        *,
        lease_manager: DurableLeaseManager,
        run_ids: tuple[
            DurableAgentRunId,
            DurableAgentRunId,
        ],
    ) -> None:
        super().__init__(
            lease_manager=lease_manager,
        )
        self._candidate_run_ids = run_ids

    async def list_cleanup_candidates(
        self,
        *,
        policy: RetentionPolicy,
        now: datetime,
        limit: int,
        after: DurableAgentRunId | None = None,
    ) -> tuple[DurableAgentRunId, ...]:
        del policy, now

        if after is not None:
            return ()

        return self._candidate_run_ids[:limit]

    async def delete_expired_protected_payloads(
        self,
        run_id: DurableAgentRunId,
        *,
        policy: RetentionPolicy,
        lease: DurableLease,
        now: datetime,
    ) -> bool:
        del run_id, policy, lease, now
        return False


@pytest.mark.asyncio
async def test_retention_run_once_continues_after_cleanup_lease_race() -> None:
    first_run_id = DurableAgentRunId(UUID(int=105))
    second_run_id = DurableAgentRunId(UUID(int=106))

    leases = _FirstAcquireConflictLeaseManager(
        conflict_run_id=first_run_id,
    )

    store = _TwoCandidateRetentionStore(
        lease_manager=leases,
        run_ids=(
            first_run_id,
            second_run_id,
        ),
    )

    configuration = DurableRetentionWorkerConfiguration(
        owner_id="phoenix-retention-race-test",
        page_size=2,
        max_candidates=2,
    )

    worker = BoundedDurableRetentionWorker(
        store=store,
        lease_manager=leases,
        policy=RETENTION_POLICY,
        configuration=configuration,
        clock=lambda: NOW,
    )

    await worker.start()
    await worker.run_once()

    assert [call[0] for call in leases.acquire_calls] == [
        first_run_id,
        second_run_id,
    ]

    assert len(leases.release_calls) == 1

    released_lease, released_at = leases.release_calls[0]

    assert released_lease.run_id == second_run_id
    assert released_at == NOW

    assert (
        await leases.get_current(
            second_run_id,
            now=NOW,
        )
        is None
    )

    snapshot = await worker.snapshot()

    assert snapshot.passes_started == 1
    assert snapshot.passes_completed == 1

    await worker.close()
    await store.close()


class _BlockingFirstScanRetentionStore(_RecordingRetentionStore):
    def __init__(self) -> None:
        super().__init__()
        self.first_scan_entered = asyncio.Event()
        self.release_first_scan = asyncio.Event()
        self.scan_count = 0

    async def list_cleanup_candidates(
        self,
        *,
        policy: RetentionPolicy,
        now: datetime,
        limit: int,
        after: DurableAgentRunId | None = None,
    ) -> tuple[DurableAgentRunId, ...]:
        self.cleanup_candidate_calls.append(
            (
                policy,
                now,
                limit,
                after,
            )
        )

        self.scan_count += 1

        if self.scan_count == 1:
            self.first_scan_entered.set()
            await self.release_first_scan.wait()

        return ()


@pytest.mark.asyncio
async def test_retention_worker_rejects_concurrent_passes() -> None:
    store = _BlockingFirstScanRetentionStore()

    worker = BoundedDurableRetentionWorker(
        store=store,
        lease_manager=store.lease_manager,
        policy=RETENTION_POLICY,
        clock=lambda: NOW,
    )

    await worker.start()

    first_pass = asyncio.create_task(worker.run_once())

    await asyncio.wait_for(
        store.first_scan_entered.wait(),
        timeout=1.0,
    )

    try:
        with pytest.raises(AgentStateConflictError):
            await worker.run_once()
    finally:
        store.release_first_scan.set()
        await first_pass

    assert store.scan_count == 1

    snapshot = await worker.snapshot()

    assert snapshot.passes_started == 1
    assert snapshot.passes_completed == 1

    await worker.close()
    await store.close()


class _NeverCompletingRetentionScanStore(_RecordingRetentionStore):
    def __init__(self) -> None:
        super().__init__()
        self.scan_entered = asyncio.Event()
        self.release_scan = asyncio.Event()

    async def list_cleanup_candidates(
        self,
        *,
        policy: RetentionPolicy,
        now: datetime,
        limit: int,
        after: DurableAgentRunId | None = None,
    ) -> tuple[DurableAgentRunId, ...]:
        self.cleanup_candidate_calls.append(
            (
                policy,
                now,
                limit,
                after,
            )
        )

        self.scan_entered.set()
        await self.release_scan.wait()
        return ()


@pytest.mark.asyncio
async def test_retention_worker_enforces_pass_timeout() -> None:
    store = _NeverCompletingRetentionScanStore()

    configuration = DurableRetentionWorkerConfiguration(
        pass_timeout=timedelta(milliseconds=20),
    )

    worker = BoundedDurableRetentionWorker(
        store=store,
        lease_manager=store.lease_manager,
        policy=RETENTION_POLICY,
        configuration=configuration,
        clock=lambda: NOW,
    )

    await worker.start()

    try:
        await asyncio.wait_for(
            worker.run_once(),
            timeout=0.25,
        )
    finally:
        store.release_scan.set()

    assert store.scan_entered.is_set()

    snapshot = await worker.snapshot()

    assert snapshot.passes_started == 1
    assert snapshot.passes_completed == 0
    assert snapshot.passes_timed_out == 1

    await worker.close()
    await store.close()


@pytest.mark.asyncio
async def test_retention_run_once_returns_content_free_report() -> None:
    store = _RecordingRetentionStore()

    worker = BoundedDurableRetentionWorker(
        store=store,
        lease_manager=store.lease_manager,
        policy=RETENTION_POLICY,
        clock=lambda: NOW,
    )

    await worker.start()

    try:
        report = await worker.run_once()

        assert report.admitted == 0
        assert report.payloads_deleted == 0
        assert report.tombstoned == 0
        assert report.purged == 0
        assert report.conflicts == 0
        assert report.failed == 0
        assert report.pages == 1
        assert report.exhausted is True
        assert report.timed_out is False
        assert report.started_at == NOW
        assert report.completed_at == NOW
    finally:
        await worker.close()
        await store.close()


class _FirstCandidateFailureRetentionStore(InMemoryDurableRunStore):
    def __init__(
        self,
        *,
        lease_manager: DurableLeaseManager,
        run_ids: tuple[
            DurableAgentRunId,
            DurableAgentRunId,
        ],
    ) -> None:
        super().__init__(
            lease_manager=lease_manager,
        )
        self._candidate_run_ids = run_ids
        self.payload_attempts: list[DurableAgentRunId] = []

    async def list_cleanup_candidates(
        self,
        *,
        policy: RetentionPolicy,
        now: datetime,
        limit: int,
        after: DurableAgentRunId | None = None,
    ) -> tuple[DurableAgentRunId, ...]:
        del policy, now

        if after is not None:
            return ()

        return self._candidate_run_ids[:limit]

    async def delete_expired_protected_payloads(
        self,
        run_id: DurableAgentRunId,
        *,
        policy: RetentionPolicy,
        lease: DurableLease,
        now: datetime,
    ) -> bool:
        del policy, lease, now

        self.payload_attempts.append(run_id)

        if run_id == self._candidate_run_ids[0]:
            raise RuntimeError("synthetic retention candidate failure")

        return False


@pytest.mark.asyncio
async def test_retention_run_once_isolates_unexpected_candidate_failure() -> None:
    first_run_id = DurableAgentRunId(UUID(int=107))
    second_run_id = DurableAgentRunId(UUID(int=108))

    leases = _RecordingRetentionLeaseManager()

    store = _FirstCandidateFailureRetentionStore(
        lease_manager=leases,
        run_ids=(
            first_run_id,
            second_run_id,
        ),
    )

    configuration = DurableRetentionWorkerConfiguration(
        owner_id="phoenix-retention-failure-test",
        page_size=2,
        max_candidates=2,
    )

    worker = BoundedDurableRetentionWorker(
        store=store,
        lease_manager=leases,
        policy=RETENTION_POLICY,
        configuration=configuration,
        clock=lambda: NOW,
    )

    await worker.start()

    try:
        report = await worker.run_once()

        assert report.admitted == 2
        assert report.failed == 1
        assert report.conflicts == 0
        assert report.timed_out is False

        assert store.payload_attempts == [
            first_run_id,
            second_run_id,
        ]

        assert [call[0] for call in leases.acquire_calls] == [
            first_run_id,
            second_run_id,
        ]

        assert [call[0].run_id for call in leases.release_calls] == [
            first_run_id,
            second_run_id,
        ]
    finally:
        await worker.close()
        await store.close()


class _FirstCandidateMutationConflictRetentionStore(InMemoryDurableRunStore):
    def __init__(
        self,
        *,
        lease_manager: DurableLeaseManager,
        run_ids: tuple[
            DurableAgentRunId,
            DurableAgentRunId,
        ],
    ) -> None:
        super().__init__(
            lease_manager=lease_manager,
        )
        self._candidate_run_ids = run_ids
        self.payload_attempts: list[DurableAgentRunId] = []

    async def list_cleanup_candidates(
        self,
        *,
        policy: RetentionPolicy,
        now: datetime,
        limit: int,
        after: DurableAgentRunId | None = None,
    ) -> tuple[DurableAgentRunId, ...]:
        del policy, now

        if after is not None:
            return ()

        return self._candidate_run_ids[:limit]

    async def delete_expired_protected_payloads(
        self,
        run_id: DurableAgentRunId,
        *,
        policy: RetentionPolicy,
        lease: DurableLease,
        now: datetime,
    ) -> bool:
        del policy, lease, now

        self.payload_attempts.append(run_id)

        if run_id == self._candidate_run_ids[0]:
            raise AgentStateConflictError()

        return False


@pytest.mark.asyncio
async def test_retention_run_once_classifies_mutation_fencing_conflict() -> None:
    first_run_id = DurableAgentRunId(UUID(int=109))
    second_run_id = DurableAgentRunId(UUID(int=110))

    leases = _RecordingRetentionLeaseManager()

    store = _FirstCandidateMutationConflictRetentionStore(
        lease_manager=leases,
        run_ids=(
            first_run_id,
            second_run_id,
        ),
    )

    configuration = DurableRetentionWorkerConfiguration(
        owner_id="phoenix-retention-mutation-conflict-test",
        page_size=2,
        max_candidates=2,
    )

    worker = BoundedDurableRetentionWorker(
        store=store,
        lease_manager=leases,
        policy=RETENTION_POLICY,
        configuration=configuration,
        clock=lambda: NOW,
    )

    await worker.start()

    try:
        report = await worker.run_once()

        assert report.admitted == 2
        assert report.conflicts == 1
        assert report.failed == 0
        assert report.timed_out is False

        assert store.payload_attempts == [
            first_run_id,
            second_run_id,
        ]

        assert [call[0] for call in leases.acquire_calls] == [
            first_run_id,
            second_run_id,
        ]

        assert [call[0].run_id for call in leases.release_calls] == [
            first_run_id,
            second_run_id,
        ]
    finally:
        await worker.close()
        await store.close()


class _FirstReleaseConflictLeaseManager(_RecordingRetentionLeaseManager):
    def __init__(
        self,
        *,
        conflict_run_id: DurableAgentRunId,
    ) -> None:
        super().__init__()
        self._conflict_run_id = conflict_run_id

    async def release(
        self,
        lease: DurableLease,
        *,
        now: datetime,
    ) -> None:
        await super().release(
            lease,
            now=now,
        )

        if lease.run_id == self._conflict_run_id:
            raise AgentStateConflictError()


@pytest.mark.asyncio
async def test_retention_run_once_isolates_release_fencing_conflict() -> None:
    first_run_id = DurableAgentRunId(UUID(int=111))
    second_run_id = DurableAgentRunId(UUID(int=112))

    leases = _FirstReleaseConflictLeaseManager(
        conflict_run_id=first_run_id,
    )

    store = _TwoCandidateRetentionStore(
        lease_manager=leases,
        run_ids=(
            first_run_id,
            second_run_id,
        ),
    )

    configuration = DurableRetentionWorkerConfiguration(
        owner_id="phoenix-retention-release-conflict-test",
        page_size=2,
        max_candidates=2,
    )

    worker = BoundedDurableRetentionWorker(
        store=store,
        lease_manager=leases,
        policy=RETENTION_POLICY,
        configuration=configuration,
        clock=lambda: NOW,
    )

    await worker.start()

    try:
        report = await worker.run_once()

        assert report.admitted == 2
        assert report.conflicts == 1
        assert report.failed == 0
        assert report.timed_out is False

        assert [call[0] for call in leases.acquire_calls] == [
            first_run_id,
            second_run_id,
        ]

        assert [call[0].run_id for call in leases.release_calls] == [
            first_run_id,
            second_run_id,
        ]
    finally:
        await worker.close()
        await store.close()


class _FirstReleaseFailureLeaseManager(_RecordingRetentionLeaseManager):
    def __init__(
        self,
        *,
        failure_run_id: DurableAgentRunId,
    ) -> None:
        super().__init__()
        self._failure_run_id = failure_run_id

    async def release(
        self,
        lease: DurableLease,
        *,
        now: datetime,
    ) -> None:
        await super().release(
            lease,
            now=now,
        )

        if lease.run_id == self._failure_run_id:
            raise RuntimeError("synthetic retention release failure")


@pytest.mark.asyncio
async def test_retention_run_once_isolates_unexpected_release_failure() -> None:
    first_run_id = DurableAgentRunId(UUID(int=113))
    second_run_id = DurableAgentRunId(UUID(int=114))

    leases = _FirstReleaseFailureLeaseManager(
        failure_run_id=first_run_id,
    )

    store = _TwoCandidateRetentionStore(
        lease_manager=leases,
        run_ids=(
            first_run_id,
            second_run_id,
        ),
    )

    configuration = DurableRetentionWorkerConfiguration(
        owner_id="phoenix-retention-release-failure-test",
        page_size=2,
        max_candidates=2,
    )

    worker = BoundedDurableRetentionWorker(
        store=store,
        lease_manager=leases,
        policy=RETENTION_POLICY,
        configuration=configuration,
        clock=lambda: NOW,
    )

    await worker.start()

    try:
        report = await worker.run_once()

        assert report.admitted == 2
        assert report.conflicts == 0
        assert report.failed == 1
        assert report.timed_out is False

        assert [call[0] for call in leases.acquire_calls] == [
            first_run_id,
            second_run_id,
        ]

        assert [call[0].run_id for call in leases.release_calls] == [
            first_run_id,
            second_run_id,
        ]
    finally:
        await worker.close()
        await store.close()


@pytest.mark.asyncio
async def test_retention_worker_start_does_not_run_cleanup_autonomously() -> None:
    store = _RecordingRetentionStore()

    worker = BoundedDurableRetentionWorker(
        store=store,
        lease_manager=store.lease_manager,
        policy=RETENTION_POLICY,
        clock=lambda: NOW,
    )

    await worker.start()

    try:
        await asyncio.sleep(0)
        await asyncio.sleep(0)

        assert store.cleanup_candidate_calls == []

        snapshot = await worker.snapshot()

        assert snapshot.state is DurableRetentionWorkerState.RUNNING
        assert snapshot.passes_started == 0
        assert snapshot.passes_completed == 0
        assert snapshot.passes_timed_out == 0
        assert snapshot.last_started_at is None
        assert snapshot.last_completed_at is None
    finally:
        await worker.close()
        await store.close()


@pytest.mark.asyncio
async def test_retention_worker_close_drains_active_pass_before_closing() -> None:
    store = _BlockingFirstScanRetentionStore()

    worker = BoundedDurableRetentionWorker(
        store=store,
        lease_manager=store.lease_manager,
        policy=RETENTION_POLICY,
        clock=lambda: NOW,
    )

    await worker.start()

    active_pass = asyncio.create_task(worker.run_once())

    await asyncio.wait_for(
        store.first_scan_entered.wait(),
        timeout=1.0,
    )

    close_task = asyncio.create_task(worker.close())

    await asyncio.sleep(0)

    store.release_first_scan.set()

    try:
        report = await asyncio.wait_for(
            active_pass,
            timeout=1.0,
        )

        await asyncio.wait_for(
            close_task,
            timeout=1.0,
        )

        assert report.admitted == 0
        assert report.failed == 0
        assert report.conflicts == 0
        assert report.timed_out is False
        assert report.exhausted is True

        snapshot = await worker.snapshot()

        assert snapshot.state is DurableRetentionWorkerState.CLOSED
        assert snapshot.passes_started == 1
        assert snapshot.passes_completed == 1
        assert snapshot.passes_timed_out == 0
    finally:
        store.release_first_scan.set()

        if not active_pass.done():
            active_pass.cancel()

            try:
                await active_pass
            except asyncio.CancelledError:
                pass

        if not close_task.done():
            await close_task

        await worker.close()
        await store.close()


@pytest.mark.asyncio
async def test_retention_worker_concurrent_close_waits_until_closed() -> None:
    store = _BlockingFirstScanRetentionStore()

    worker = BoundedDurableRetentionWorker(
        store=store,
        lease_manager=store.lease_manager,
        policy=RETENTION_POLICY,
        clock=lambda: NOW,
    )

    await worker.start()

    active_pass = asyncio.create_task(worker.run_once())

    await asyncio.wait_for(
        store.first_scan_entered.wait(),
        timeout=1.0,
    )

    first_close = asyncio.create_task(worker.close())

    await asyncio.sleep(0)

    second_close = asyncio.create_task(worker.close())

    await asyncio.sleep(0)

    try:
        assert first_close.done() is False
        assert second_close.done() is False

        snapshot = await worker.snapshot()

        assert snapshot.state is DurableRetentionWorkerState.CLOSING

        store.release_first_scan.set()

        report = await asyncio.wait_for(
            active_pass,
            timeout=1.0,
        )

        await asyncio.wait_for(
            first_close,
            timeout=1.0,
        )

        await asyncio.wait_for(
            second_close,
            timeout=1.0,
        )

        assert report.exhausted is True

        snapshot = await worker.snapshot()

        assert snapshot.state is DurableRetentionWorkerState.CLOSED
        assert snapshot.passes_started == 1
        assert snapshot.passes_completed == 1
    finally:
        store.release_first_scan.set()

        await asyncio.gather(
            active_pass,
            first_close,
            second_close,
            return_exceptions=True,
        )

        await worker.close()
        await store.close()


def test_retention_worker_configuration_bounds_shutdown_grace() -> None:
    configuration = DurableRetentionWorkerConfiguration(
        shutdown_grace=timedelta(seconds=5),
        cancellation_grace=timedelta(seconds=1),
    )

    assert configuration.shutdown_grace == timedelta(seconds=5)
    assert configuration.cancellation_grace == timedelta(seconds=1)

    with pytest.raises(ValueError):
        DurableRetentionWorkerConfiguration(
            shutdown_grace=timedelta(0),
        )

    with pytest.raises(ValueError):
        DurableRetentionWorkerConfiguration(
            shutdown_grace=timedelta(seconds=61),
        )

    with pytest.raises(ValueError):
        DurableRetentionWorkerConfiguration(
            cancellation_grace=timedelta(0),
        )

    with pytest.raises(ValueError):
        DurableRetentionWorkerConfiguration(
            cancellation_grace=timedelta(seconds=31),
        )


@pytest.mark.asyncio
async def test_retention_worker_close_cancels_active_pass_after_shutdown_grace() -> None:
    store = _BlockingFirstScanRetentionStore()

    configuration = DurableRetentionWorkerConfiguration(
        pass_timeout=timedelta(seconds=30),
        shutdown_grace=timedelta(milliseconds=10),
        cancellation_grace=timedelta(milliseconds=100),
    )

    worker = BoundedDurableRetentionWorker(
        store=store,
        lease_manager=store.lease_manager,
        policy=RETENTION_POLICY,
        configuration=configuration,
        clock=lambda: NOW,
    )

    await worker.start()

    active_pass = asyncio.create_task(worker.run_once())

    await asyncio.wait_for(
        store.first_scan_entered.wait(),
        timeout=1.0,
    )

    close_task = asyncio.create_task(worker.close())

    try:
        await asyncio.sleep(0.05)

        assert close_task.done() is True

        await close_task

        with pytest.raises(asyncio.CancelledError):
            await active_pass

        snapshot = await worker.snapshot()

        assert snapshot.state is DurableRetentionWorkerState.CLOSED
    finally:
        store.release_first_scan.set()

        await asyncio.gather(
            active_pass,
            close_task,
            return_exceptions=True,
        )

        await worker.close()
        await store.close()


class _StubbornRetentionScanStore(_RecordingRetentionStore):
    def __init__(self) -> None:
        super().__init__()
        self.scan_entered = asyncio.Event()
        self.cancellation_seen = asyncio.Event()
        self.release_scan = asyncio.Event()

    async def list_cleanup_candidates(
        self,
        *,
        policy: RetentionPolicy,
        now: datetime,
        limit: int,
        after: DurableAgentRunId | None = None,
    ) -> tuple[DurableAgentRunId, ...]:
        self.cleanup_candidate_calls.append(
            (
                policy,
                now,
                limit,
                after,
            )
        )

        self.scan_entered.set()

        try:
            await self.release_scan.wait()
        except asyncio.CancelledError:
            self.cancellation_seen.set()
            await self.release_scan.wait()

        return ()


@pytest.mark.asyncio
async def test_retention_worker_close_is_finite_when_active_pass_ignores_cancellation() -> None:
    store = _StubbornRetentionScanStore()

    configuration = DurableRetentionWorkerConfiguration(
        pass_timeout=timedelta(seconds=30),
        shutdown_grace=timedelta(milliseconds=10),
        cancellation_grace=timedelta(milliseconds=20),
    )

    worker = BoundedDurableRetentionWorker(
        store=store,
        lease_manager=store.lease_manager,
        policy=RETENTION_POLICY,
        configuration=configuration,
        clock=lambda: NOW,
    )

    await worker.start()

    active_pass = asyncio.create_task(worker.run_once())

    await asyncio.wait_for(
        store.scan_entered.wait(),
        timeout=1.0,
    )

    close_task = asyncio.create_task(worker.close())

    try:
        await asyncio.wait_for(
            store.cancellation_seen.wait(),
            timeout=1.0,
        )

        await asyncio.wait_for(
            close_task,
            timeout=0.25,
        )

        assert active_pass.done() is False

        snapshot = await worker.snapshot()

        assert snapshot.state is DurableRetentionWorkerState.CLOSED

        await asyncio.wait_for(
            worker.close(),
            timeout=0.25,
        )
    finally:
        store.release_scan.set()

        await asyncio.gather(
            active_pass,
            return_exceptions=True,
        )

        await worker.close()
        await store.close()


class _StubbornFailingRetentionScanStore(_RecordingRetentionStore):
    def __init__(self) -> None:
        super().__init__()
        self.scan_entered = asyncio.Event()
        self.cancellation_seen = asyncio.Event()
        self.release_scan = asyncio.Event()

    async def list_cleanup_candidates(
        self,
        *,
        policy: RetentionPolicy,
        now: datetime,
        limit: int,
        after: DurableAgentRunId | None = None,
    ) -> tuple[DurableAgentRunId, ...]:
        self.cleanup_candidate_calls.append(
            (
                policy,
                now,
                limit,
                after,
            )
        )

        self.scan_entered.set()

        try:
            await self.release_scan.wait()
        except asyncio.CancelledError:
            self.cancellation_seen.set()
            await self.release_scan.wait()

        raise RuntimeError("synthetic late stubborn retention failure")


@pytest.mark.asyncio
async def test_retention_worker_consumes_late_stubborn_pass_failure() -> None:
    store = _StubbornFailingRetentionScanStore()

    configuration = DurableRetentionWorkerConfiguration(
        pass_timeout=timedelta(seconds=30),
        shutdown_grace=timedelta(milliseconds=10),
        cancellation_grace=timedelta(milliseconds=20),
    )

    worker = BoundedDurableRetentionWorker(
        store=store,
        lease_manager=store.lease_manager,
        policy=RETENTION_POLICY,
        configuration=configuration,
        clock=lambda: NOW,
    )

    await worker.start()

    active_pass = asyncio.create_task(worker.run_once())

    await asyncio.wait_for(
        store.scan_entered.wait(),
        timeout=1.0,
    )

    try:
        await asyncio.wait_for(
            worker.close(),
            timeout=0.25,
        )

        assert store.cancellation_seen.is_set()
        assert active_pass.done() is False

        snapshot = await worker.snapshot()

        assert snapshot.state is DurableRetentionWorkerState.CLOSED

        store.release_scan.set()

        done, pending = await asyncio.wait(
            {active_pass},
            timeout=0.25,
        )

        assert pending == set()
        assert done == {active_pass}
        assert active_pass.cancelled() is False

        await asyncio.sleep(0)

        assert active_pass._log_traceback is False
    finally:
        store.release_scan.set()

        await asyncio.gather(
            active_pass,
            return_exceptions=True,
        )

        await worker.close()
        await store.close()


@pytest.mark.parametrize(
    "page",
    (
        (
            DurableAgentRunId(UUID(int=201)),
            DurableAgentRunId(UUID(int=201)),
        ),
        (
            DurableAgentRunId(UUID(int=202)),
            DurableAgentRunId(UUID(int=201)),
        ),
    ),
)
@pytest.mark.asyncio
async def test_retention_run_once_rejects_non_strict_candidate_page(
    page: tuple[
        DurableAgentRunId,
        DurableAgentRunId,
    ],
) -> None:
    store = _PagedRecordingRetentionStore(
        pages=(page,),
    )

    configuration = DurableRetentionWorkerConfiguration(
        page_size=2,
        max_candidates=2,
    )

    worker = BoundedDurableRetentionWorker(
        store=store,
        lease_manager=store.lease_manager,
        policy=RETENTION_POLICY,
        configuration=configuration,
        clock=lambda: NOW,
    )

    await worker.start()

    try:
        with pytest.raises(AgentCodecError):
            await worker.run_once()
    finally:
        await worker.close()
        await store.close()


class _MalformedCleanupPageRetentionStore(_RecordingRetentionStore):
    def __init__(
        self,
        page: object,
    ) -> None:
        super().__init__()
        self._page = page

    async def list_cleanup_candidates(
        self,
        *,
        policy: RetentionPolicy,
        now: datetime,
        limit: int,
        after: DurableAgentRunId | None = None,
    ) -> tuple[DurableAgentRunId, ...]:
        self.cleanup_candidate_calls.append(
            (
                policy,
                now,
                limit,
                after,
            )
        )

        return self._page  # type: ignore[return-value]


@pytest.mark.parametrize(
    ("page", "expected_exception"),
    (
        (
            [
                DurableAgentRunId(UUID(int=301)),
            ],
            TypeError,
        ),
        (
            ("not-a-durable-run-id",),
            AgentCodecError,
        ),
        (
            (
                DurableAgentRunId(UUID(int=301)),
                DurableAgentRunId(UUID(int=302)),
                DurableAgentRunId(UUID(int=303)),
            ),
            AgentCodecError,
        ),
    ),
)
@pytest.mark.asyncio
async def test_retention_run_once_rejects_malformed_candidate_page(
    page: object,
    expected_exception: type[Exception],
) -> None:
    store = _MalformedCleanupPageRetentionStore(
        page,
    )

    configuration = DurableRetentionWorkerConfiguration(
        page_size=2,
        max_candidates=2,
    )

    worker = BoundedDurableRetentionWorker(
        store=store,
        lease_manager=store.lease_manager,
        policy=RETENTION_POLICY,
        configuration=configuration,
        clock=lambda: NOW,
    )

    await worker.start()

    try:
        with pytest.raises(expected_exception):
            await worker.run_once()
    finally:
        await worker.close()
        await store.close()


@pytest.mark.asyncio
async def test_retention_run_once_rejects_candidate_page_that_does_not_advance_after_cursor() -> (
    None
):
    first_run_id = DurableAgentRunId(UUID(int=311))
    second_run_id = DurableAgentRunId(UUID(int=312))
    third_run_id = DurableAgentRunId(UUID(int=313))

    store = _PagedRecordingRetentionStore(
        pages=(
            (
                first_run_id,
                second_run_id,
            ),
            (
                second_run_id,
                third_run_id,
            ),
        ),
    )

    configuration = DurableRetentionWorkerConfiguration(
        page_size=2,
        max_candidates=4,
    )

    worker = BoundedDurableRetentionWorker(
        store=store,
        lease_manager=store.lease_manager,
        policy=RETENTION_POLICY,
        configuration=configuration,
        clock=lambda: NOW,
    )

    await worker.start()

    try:
        with pytest.raises(AgentCodecError):
            await worker.run_once()

        assert len(store.cleanup_candidate_calls) == 2

        assert store.cleanup_candidate_calls[1][3] == second_run_id
    finally:
        await worker.close()
        await store.close()


@pytest.mark.asyncio
async def test_retention_worker_snapshot_accounts_pass_level_failure() -> None:
    run_id = DurableAgentRunId(UUID(int=321))

    store = _PagedRecordingRetentionStore(
        pages=(
            (
                run_id,
                run_id,
            ),
        ),
    )

    worker = BoundedDurableRetentionWorker(
        store=store,
        lease_manager=store.lease_manager,
        policy=RETENTION_POLICY,
        clock=lambda: NOW,
    )

    await worker.start()

    try:
        with pytest.raises(AgentCodecError):
            await worker.run_once()

        snapshot = await worker.snapshot()

        assert snapshot.passes_started == 1
        assert snapshot.passes_completed == 0
        assert snapshot.passes_timed_out == 0
        assert snapshot.passes_failed == 1
    finally:
        await worker.close()
        await store.close()


class _CancellableRetentionScanStore(_RecordingRetentionStore):
    def __init__(self) -> None:
        super().__init__()
        self.scan_entered = asyncio.Event()
        self.release_scan = asyncio.Event()

    async def list_cleanup_candidates(
        self,
        *,
        policy: RetentionPolicy,
        now: datetime,
        limit: int,
        after: DurableAgentRunId | None = None,
    ) -> tuple[DurableAgentRunId, ...]:
        self.cleanup_candidate_calls.append(
            (
                policy,
                now,
                limit,
                after,
            )
        )

        self.scan_entered.set()
        await self.release_scan.wait()

        return ()


@pytest.mark.asyncio
async def test_retention_worker_snapshot_accounts_cancelled_pass_as_stopped() -> None:
    store = _CancellableRetentionScanStore()

    configuration = DurableRetentionWorkerConfiguration(
        pass_timeout=timedelta(seconds=30),
        shutdown_grace=timedelta(milliseconds=10),
        cancellation_grace=timedelta(milliseconds=50),
    )

    worker = BoundedDurableRetentionWorker(
        store=store,
        lease_manager=store.lease_manager,
        policy=RETENTION_POLICY,
        configuration=configuration,
        clock=lambda: NOW,
    )

    await worker.start()

    active_pass = asyncio.create_task(worker.run_once())

    await asyncio.wait_for(
        store.scan_entered.wait(),
        timeout=1.0,
    )

    try:
        await asyncio.wait_for(
            asyncio.gather(
                worker.close(),
                return_exceptions=True,
            ),
            timeout=0.25,
        )

        await asyncio.gather(
            active_pass,
            return_exceptions=True,
        )

        snapshot = await worker.snapshot()

        assert snapshot.state is DurableRetentionWorkerState.CLOSED
        assert snapshot.passes_started == 1
        assert snapshot.passes_completed == 0
        assert snapshot.passes_timed_out == 0
        assert snapshot.passes_failed == 0
        assert snapshot.passes_stopped == 1
    finally:
        store.release_scan.set()

        await asyncio.gather(
            active_pass,
            return_exceptions=True,
        )

        await worker.close()
        await store.close()


class _CooperativeStopRetentionStore(_RecordingRetentionStore):
    def __init__(
        self,
        run_ids: tuple[
            DurableAgentRunId,
            DurableAgentRunId,
        ],
    ) -> None:
        super().__init__()
        self._run_ids = run_ids
        self.first_candidate_entered = asyncio.Event()
        self.release_first_candidate = asyncio.Event()
        self.payload_attempts: list[DurableAgentRunId] = []

    async def list_cleanup_candidates(
        self,
        *,
        policy: RetentionPolicy,
        now: datetime,
        limit: int,
        after: DurableAgentRunId | None = None,
    ) -> tuple[DurableAgentRunId, ...]:
        self.cleanup_candidate_calls.append(
            (
                policy,
                now,
                limit,
                after,
            )
        )

        if after is not None:
            return ()

        return self._run_ids

    async def delete_expired_protected_payloads(
        self,
        run_id: DurableAgentRunId,
        *,
        policy: RetentionPolicy,
        lease: DurableLease,
        now: datetime,
    ) -> bool:
        del policy, lease, now

        self.payload_attempts.append(run_id)

        if run_id == self._run_ids[0]:
            self.first_candidate_entered.set()

            await self.release_first_candidate.wait()

        return False


@pytest.mark.asyncio
async def test_retention_worker_close_stops_cooperatively_between_candidates() -> None:
    first_run_id = DurableAgentRunId(UUID(int=401))
    second_run_id = DurableAgentRunId(UUID(int=402))

    store = _CooperativeStopRetentionStore(
        (
            first_run_id,
            second_run_id,
        )
    )

    configuration = DurableRetentionWorkerConfiguration(
        page_size=2,
        max_candidates=2,
        pass_timeout=timedelta(seconds=30),
        shutdown_grace=timedelta(seconds=1),
        cancellation_grace=timedelta(milliseconds=50),
    )

    worker = BoundedDurableRetentionWorker(
        store=store,
        lease_manager=store.lease_manager,
        policy=RETENTION_POLICY,
        configuration=configuration,
        clock=lambda: NOW,
    )

    await worker.start()

    active_pass = asyncio.create_task(worker.run_once())

    await asyncio.wait_for(
        store.first_candidate_entered.wait(),
        timeout=1.0,
    )

    close_task = asyncio.create_task(worker.close())

    for _ in range(100):
        if worker.state is DurableRetentionWorkerState.CLOSING:
            break

        await asyncio.sleep(0)

    assert worker.state is DurableRetentionWorkerState.CLOSING

    store.release_first_candidate.set()

    try:
        await asyncio.wait_for(
            close_task,
            timeout=1.0,
        )

        await asyncio.wait_for(
            active_pass,
            timeout=1.0,
        )

        assert store.payload_attempts == [
            first_run_id,
        ]
    finally:
        store.release_first_candidate.set()

        await asyncio.gather(
            active_pass,
            close_task,
            return_exceptions=True,
        )

        await worker.close()
        await store.close()


class _CooperativePageStopRetentionStore(_RecordingRetentionStore):
    def __init__(
        self,
        first_run_id: DurableAgentRunId,
        second_run_id: DurableAgentRunId,
    ) -> None:
        super().__init__()
        self._first_run_id = first_run_id
        self._second_run_id = second_run_id
        self.first_candidate_entered = asyncio.Event()
        self.release_first_candidate = asyncio.Event()

    async def list_cleanup_candidates(
        self,
        *,
        policy: RetentionPolicy,
        now: datetime,
        limit: int,
        after: DurableAgentRunId | None = None,
    ) -> tuple[DurableAgentRunId, ...]:
        self.cleanup_candidate_calls.append(
            (
                policy,
                now,
                limit,
                after,
            )
        )

        if after is None:
            return (self._first_run_id,)

        return (self._second_run_id,)

    async def delete_expired_protected_payloads(
        self,
        run_id: DurableAgentRunId,
        *,
        policy: RetentionPolicy,
        lease: DurableLease,
        now: datetime,
    ) -> bool:
        del policy, lease, now

        if run_id == self._first_run_id:
            self.first_candidate_entered.set()

            await self.release_first_candidate.wait()

        return False


@pytest.mark.asyncio
async def test_retention_worker_close_stops_cooperatively_before_next_page() -> None:
    first_run_id = DurableAgentRunId(UUID(int=411))
    second_run_id = DurableAgentRunId(UUID(int=412))

    store = _CooperativePageStopRetentionStore(
        first_run_id,
        second_run_id,
    )

    configuration = DurableRetentionWorkerConfiguration(
        page_size=1,
        max_candidates=2,
        pass_timeout=timedelta(seconds=30),
        shutdown_grace=timedelta(seconds=1),
        cancellation_grace=timedelta(milliseconds=50),
    )

    worker = BoundedDurableRetentionWorker(
        store=store,
        lease_manager=store.lease_manager,
        policy=RETENTION_POLICY,
        configuration=configuration,
        clock=lambda: NOW,
    )

    await worker.start()

    active_pass = asyncio.create_task(worker.run_once())

    await asyncio.wait_for(
        store.first_candidate_entered.wait(),
        timeout=1.0,
    )

    close_task = asyncio.create_task(worker.close())

    for _ in range(100):
        if worker.state is DurableRetentionWorkerState.CLOSING:
            break

        await asyncio.sleep(0)

    assert worker.state is DurableRetentionWorkerState.CLOSING

    store.release_first_candidate.set()

    try:
        await asyncio.wait_for(
            close_task,
            timeout=1.0,
        )

        await asyncio.wait_for(
            active_pass,
            timeout=1.0,
        )

        assert store.cleanup_candidate_calls == [
            (
                RETENTION_POLICY,
                NOW,
                1,
                None,
            )
        ]
    finally:
        store.release_first_candidate.set()

        await asyncio.gather(
            active_pass,
            close_task,
            return_exceptions=True,
        )

        await worker.close()
        await store.close()


@pytest.mark.asyncio
async def test_retention_worker_accounts_cooperative_shutdown_as_stopped() -> None:
    first_run_id = DurableAgentRunId(UUID(int=421))
    second_run_id = DurableAgentRunId(UUID(int=422))

    store = _CooperativeStopRetentionStore(
        (
            first_run_id,
            second_run_id,
        )
    )

    configuration = DurableRetentionWorkerConfiguration(
        page_size=2,
        max_candidates=2,
        pass_timeout=timedelta(seconds=30),
        shutdown_grace=timedelta(seconds=1),
        cancellation_grace=timedelta(milliseconds=50),
    )

    worker = BoundedDurableRetentionWorker(
        store=store,
        lease_manager=store.lease_manager,
        policy=RETENTION_POLICY,
        configuration=configuration,
        clock=lambda: NOW,
    )

    await worker.start()

    active_pass = asyncio.create_task(worker.run_once())

    await asyncio.wait_for(
        store.first_candidate_entered.wait(),
        timeout=1.0,
    )

    close_task = asyncio.create_task(worker.close())

    for _ in range(100):
        if worker.state is DurableRetentionWorkerState.CLOSING:
            break

        await asyncio.sleep(0)

    assert worker.state is DurableRetentionWorkerState.CLOSING

    store.release_first_candidate.set()

    try:
        report = await asyncio.wait_for(
            active_pass,
            timeout=1.0,
        )

        await asyncio.wait_for(
            close_task,
            timeout=1.0,
        )

        assert report.stopped is True
        assert report.timed_out is False
        assert report.exhausted is False

        snapshot = await worker.snapshot()

        assert snapshot.state is DurableRetentionWorkerState.CLOSED
        assert snapshot.passes_started == 1
        assert snapshot.passes_completed == 0
        assert snapshot.passes_timed_out == 0
        assert snapshot.passes_failed == 0
        assert snapshot.passes_stopped == 1
    finally:
        store.release_first_candidate.set()

        await asyncio.gather(
            active_pass,
            close_task,
            return_exceptions=True,
        )

        await worker.close()
        await store.close()


class _TimeoutWhileHoldingLeaseRetentionStore(_RecordingRetentionStore):
    def __init__(
        self,
        run_id: DurableAgentRunId,
    ) -> None:
        super().__init__()
        self._run_id = run_id
        self.candidate_entered = asyncio.Event()
        self.release_candidate = asyncio.Event()

    async def list_cleanup_candidates(
        self,
        *,
        policy: RetentionPolicy,
        now: datetime,
        limit: int,
        after: DurableAgentRunId | None = None,
    ) -> tuple[DurableAgentRunId, ...]:
        self.cleanup_candidate_calls.append(
            (
                policy,
                now,
                limit,
                after,
            )
        )

        if after is not None:
            return ()

        return (self._run_id,)

    async def delete_expired_protected_payloads(
        self,
        run_id: DurableAgentRunId,
        *,
        policy: RetentionPolicy,
        lease: DurableLease,
        now: datetime,
    ) -> bool:
        del policy, lease, now

        assert run_id == self._run_id

        self.candidate_entered.set()

        await self.release_candidate.wait()

        return False


@pytest.mark.asyncio
async def test_retention_worker_timeout_releases_candidate_lease() -> None:
    run_id = DurableAgentRunId(UUID(int=431))

    store = _TimeoutWhileHoldingLeaseRetentionStore(
        run_id,
    )

    configuration = DurableRetentionWorkerConfiguration(
        page_size=1,
        max_candidates=1,
        pass_timeout=timedelta(milliseconds=20),
    )

    worker = BoundedDurableRetentionWorker(
        store=store,
        lease_manager=store.lease_manager,
        policy=RETENTION_POLICY,
        configuration=configuration,
        clock=lambda: NOW,
    )

    await worker.start()

    try:
        report = await asyncio.wait_for(
            worker.run_once(),
            timeout=0.25,
        )

        assert store.candidate_entered.is_set()
        assert report.timed_out is True

        current_lease = await store.lease_manager.get_current(
            run_id,
            now=NOW,
        )

        assert current_lease is None

        snapshot = await worker.snapshot()

        assert snapshot.passes_started == 1
        assert snapshot.passes_completed == 0
        assert snapshot.passes_timed_out == 1
        assert snapshot.passes_failed == 0
        assert snapshot.passes_stopped == 0
    finally:
        store.release_candidate.set()

        await worker.close()
        await store.close()


@pytest.mark.asyncio
async def test_retention_worker_close_cancellation_releases_candidate_lease() -> None:
    run_id = DurableAgentRunId(UUID(int=432))

    store = _TimeoutWhileHoldingLeaseRetentionStore(
        run_id,
    )

    configuration = DurableRetentionWorkerConfiguration(
        page_size=1,
        max_candidates=1,
        pass_timeout=timedelta(seconds=30),
        shutdown_grace=timedelta(milliseconds=10),
        cancellation_grace=timedelta(milliseconds=100),
    )

    worker = BoundedDurableRetentionWorker(
        store=store,
        lease_manager=store.lease_manager,
        policy=RETENTION_POLICY,
        configuration=configuration,
        clock=lambda: NOW,
    )

    await worker.start()

    active_pass = asyncio.create_task(worker.run_once())

    await asyncio.wait_for(
        store.candidate_entered.wait(),
        timeout=1.0,
    )

    close_task = asyncio.create_task(worker.close())

    try:
        await asyncio.wait_for(
            close_task,
            timeout=0.25,
        )

        with pytest.raises(asyncio.CancelledError):
            await active_pass

        current_lease = await store.lease_manager.get_current(
            run_id,
            now=NOW,
        )

        assert current_lease is None

        snapshot = await worker.snapshot()

        assert snapshot.state is DurableRetentionWorkerState.CLOSED
        assert snapshot.passes_started == 1
        assert snapshot.passes_completed == 0
        assert snapshot.passes_timed_out == 0
        assert snapshot.passes_failed == 0
        assert snapshot.passes_stopped == 1
    finally:
        store.release_candidate.set()

        await asyncio.gather(
            active_pass,
            close_task,
            return_exceptions=True,
        )

        await worker.close()
        await store.close()


class _CancellationGraceFailureRetentionStore(_RecordingRetentionStore):
    def __init__(self) -> None:
        super().__init__()
        self.scan_entered = asyncio.Event()

    async def list_cleanup_candidates(
        self,
        *,
        policy: RetentionPolicy,
        now: datetime,
        limit: int,
        after: DurableAgentRunId | None = None,
    ) -> tuple[DurableAgentRunId, ...]:
        self.cleanup_candidate_calls.append(
            (
                policy,
                now,
                limit,
                after,
            )
        )

        self.scan_entered.set()

        try:
            await asyncio.Future()
        except asyncio.CancelledError:
            raise RuntimeError("synthetic cancellation-grace failure") from None


@pytest.mark.asyncio
async def test_retention_worker_consumes_failure_completed_during_cancellation_grace() -> None:
    store = _CancellationGraceFailureRetentionStore()

    configuration = DurableRetentionWorkerConfiguration(
        pass_timeout=timedelta(seconds=30),
        shutdown_grace=timedelta(milliseconds=10),
        cancellation_grace=timedelta(milliseconds=100),
    )

    worker = BoundedDurableRetentionWorker(
        store=store,
        lease_manager=store.lease_manager,
        policy=RETENTION_POLICY,
        configuration=configuration,
        clock=lambda: NOW,
    )

    await worker.start()

    active_pass = asyncio.create_task(worker.run_once())

    await asyncio.wait_for(
        store.scan_entered.wait(),
        timeout=1.0,
    )

    try:
        await asyncio.wait_for(
            worker.close(),
            timeout=0.25,
        )

        assert active_pass.done() is True

        assert active_pass._log_traceback is False

        snapshot = await worker.snapshot()

        assert snapshot.state is DurableRetentionWorkerState.CLOSED
        assert snapshot.passes_started == 1
        assert snapshot.passes_completed == 0
        assert snapshot.passes_timed_out == 0
        assert snapshot.passes_failed == 1
        assert snapshot.passes_stopped == 0
    finally:
        await asyncio.gather(
            active_pass,
            return_exceptions=True,
        )

        await worker.close()
        await store.close()


@pytest.mark.asyncio
async def test_retention_worker_consumes_late_failure_when_close_itself_is_cancelled() -> None:
    store = _StubbornFailingRetentionScanStore()

    configuration = DurableRetentionWorkerConfiguration(
        pass_timeout=timedelta(seconds=30),
        shutdown_grace=timedelta(seconds=30),
        cancellation_grace=timedelta(milliseconds=50),
    )

    worker = BoundedDurableRetentionWorker(
        store=store,
        lease_manager=store.lease_manager,
        policy=RETENTION_POLICY,
        configuration=configuration,
        clock=lambda: NOW,
    )

    await worker.start()

    active_pass = asyncio.create_task(worker.run_once())

    await asyncio.wait_for(
        store.scan_entered.wait(),
        timeout=1.0,
    )

    close_task = asyncio.create_task(worker.close())

    for _ in range(100):
        if worker.state is DurableRetentionWorkerState.CLOSING:
            break

        await asyncio.sleep(0)

    assert worker.state is DurableRetentionWorkerState.CLOSING

    close_task.cancel()

    try:
        with pytest.raises(asyncio.CancelledError):
            await close_task

        await asyncio.wait_for(
            store.cancellation_seen.wait(),
            timeout=1.0,
        )

        assert active_pass.done() is False

        store.release_scan.set()

        for _ in range(100):
            if active_pass.done():
                break

            await asyncio.sleep(0)

        assert active_pass.done() is True

        # Task done callbacks run on a subsequent event-loop turn.
        # Let _consume_task retrieve the late exception.
        await asyncio.sleep(0)

        assert active_pass._log_traceback is False

        snapshot = await worker.snapshot()

        assert snapshot.state is DurableRetentionWorkerState.CLOSED
        assert snapshot.passes_started == 1
        assert snapshot.passes_completed == 0
        assert snapshot.passes_timed_out == 0
        assert snapshot.passes_failed == 1
        assert snapshot.passes_stopped == 0
    finally:
        store.release_scan.set()

        await asyncio.gather(
            active_pass,
            close_task,
            return_exceptions=True,
        )

        await worker.close()
        await store.close()


@pytest.mark.parametrize(
    ("exhausted", "timed_out", "stopped"),
    [
        (True, True, False),
        (True, False, True),
        (False, True, True),
        (True, True, True),
    ],
)
def test_retention_worker_report_rejects_multiple_terminal_outcomes(
    exhausted: bool,
    timed_out: bool,
    stopped: bool,
) -> None:
    with pytest.raises(
        ValueError,
        match="terminal outcomes are mutually exclusive",
    ):
        DurableRetentionWorkerReport(
            admitted=0,
            payloads_deleted=0,
            tombstoned=0,
            purged=0,
            conflicts=0,
            failed=0,
            pages=0,
            exhausted=exhausted,
            timed_out=timed_out,
            stopped=stopped,
            started_at=NOW,
            completed_at=NOW,
        )
