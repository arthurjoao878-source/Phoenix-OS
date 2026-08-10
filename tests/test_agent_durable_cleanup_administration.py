from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import pytest

from phoenix_os.agent import (
    AGENT_DURABLE_CLEANUP_ACTION,
    DURABLE_ADMINISTRATION_CLEANUP_RESOURCE,
    AgentAdministrationAccessDeniedError,
    AgentServiceUnavailableError,
    AgentStateConflictError,
    DurableCleanupAdministration,
    DurableCleanupAdministrationBounds,
    DurableCleanupAdministrationWorker,
    DurableRetentionWorkerConfiguration,
    DurableRetentionWorkerReport,
    RetentionPolicy,
)
from phoenix_os.audit import (
    AuditEvent,
    AuditLedger,
    AuditOutcome,
    AuditQuery,
    AuditRecord,
    InMemoryAuditStore,
)
from phoenix_os.policy import PrincipalType, SecurityContext

NOW = datetime(2026, 8, 9, 22, tzinfo=UTC)
SECRET = "never-leak-cleanup-worker-error"

POLICY = RetentionPolicy(
    payload_retention=timedelta(days=7),
    metadata_retention=timedelta(days=30),
    tombstone_retention=timedelta(days=90),
)
CONFIGURATION = DurableRetentionWorkerConfiguration(
    owner_id="phoenix-retention-admin-test",
    page_size=32,
    max_candidates=16,
    pass_timeout=timedelta(seconds=30),
)
REPORT = DurableRetentionWorkerReport(
    admitted=3,
    payloads_deleted=1,
    tombstoned=1,
    purged=1,
    conflicts=0,
    failed=0,
    pages=2,
    exhausted=True,
    timed_out=False,
    stopped=False,
    started_at=NOW,
    completed_at=NOW + timedelta(seconds=1),
)


class _Worker:
    def __init__(
        self,
        *,
        policy: RetentionPolicy = POLICY,
        configuration: DurableRetentionWorkerConfiguration = CONFIGURATION,
        report: DurableRetentionWorkerReport = REPORT,
        error: Exception | None = None,
    ) -> None:
        self._policy = policy
        self._configuration = configuration
        self._report = report
        self._error = error
        self.calls = 0

    @property
    def policy(self) -> RetentionPolicy:
        return self._policy

    @property
    def configuration(self) -> DurableRetentionWorkerConfiguration:
        return self._configuration

    async def run_once(self) -> DurableRetentionWorkerReport:
        self.calls += 1
        if self._error is not None:
            raise self._error
        return self._report


class _FailingAuditStore(InMemoryAuditStore):
    async def append(
        self,
        event: AuditEvent,
        *,
        recorded_at: datetime,
    ) -> AuditRecord:
        del event, recorded_at
        raise RuntimeError(SECRET)


class _SecondAppendFailsAuditStore(InMemoryAuditStore):
    def __init__(self) -> None:
        super().__init__()
        self.append_calls = 0

    async def append(
        self,
        event: AuditEvent,
        *,
        recorded_at: datetime,
    ) -> AuditRecord:
        self.append_calls += 1
        if self.append_calls == 2:
            raise RuntimeError(SECRET)
        return await super().append(event, recorded_at=recorded_at)


class _SecondAppendCancelledAuditStore(InMemoryAuditStore):
    def __init__(self) -> None:
        super().__init__()
        self.append_calls = 0

    async def append(
        self,
        event: AuditEvent,
        *,
        recorded_at: datetime,
    ) -> AuditRecord:
        self.append_calls += 1
        if self.append_calls == 2:
            raise asyncio.CancelledError()
        return await super().append(event, recorded_at=recorded_at)


class _ExplodingBoundsWorker(_Worker):
    @property
    def policy(self) -> RetentionPolicy:
        raise RuntimeError(SECRET)


class _BlockingWorker(_Worker):
    def __init__(self) -> None:
        super().__init__()
        self.started = asyncio.Event()
        self.release = asyncio.Event()

    async def run_once(self) -> DurableRetentionWorkerReport:
        self.calls += 1
        self.started.set()
        await self.release.wait()
        return self._report


def _context(
    *,
    permissions: frozenset[str] = frozenset({AGENT_DURABLE_CLEANUP_ACTION}),
    principal_type: PrincipalType = PrincipalType.USER,
    authenticated: bool = True,
) -> SecurityContext:
    return SecurityContext(
        principal="operator:maintainer",
        principal_type=principal_type,
        authenticated=authenticated,
        permissions=permissions,
        scopes=frozenset({AGENT_DURABLE_CLEANUP_ACTION}),
        correlation_id="durable-cleanup-administration-test",
    )


def _bounds(
    **overrides: int,
) -> DurableCleanupAdministrationBounds:
    values = {
        "page_size": 32,
        "max_candidates": 16,
        "pass_timeout_microseconds": 30_000_000,
        "payload_retention_microseconds": 7 * 86_400_000_000,
        "metadata_retention_microseconds": 30 * 86_400_000_000,
        "tombstone_retention_microseconds": 90 * 86_400_000_000,
    }
    values.update(overrides)
    return DurableCleanupAdministrationBounds(**values)


def test_cleanup_administration_worker_protocol_is_structural() -> None:
    assert isinstance(_Worker(), DurableCleanupAdministrationWorker)


def test_cleanup_bounds_are_derived_from_server_worker_configuration() -> None:
    worker = _Worker()
    administration = DurableCleanupAdministration(
        worker=worker,
        audit=AuditLedger(),
    )

    bounds = administration.bounds(_context())

    assert bounds == _bounds()
    assert bounds.page_size > bounds.max_candidates
    assert not hasattr(bounds, "owner_id")
    assert not hasattr(bounds, "lease")
    assert not hasattr(bounds, "generation")
    assert not hasattr(bounds, "payload")


def test_cleanup_bounds_sanitize_server_worker_failures() -> None:
    administration = DurableCleanupAdministration(
        worker=_ExplodingBoundsWorker(),
        audit=AuditLedger(),
    )

    with pytest.raises(AgentServiceUnavailableError) as captured:
        administration.bounds(_context())

    assert SECRET not in repr(captured.value)


@pytest.mark.parametrize(
    "context",
    [
        _context(permissions=frozenset()),
        _context(permissions=frozenset({"*"})),
        _context(principal_type=PrincipalType.SERVICE),
        _context(authenticated=False),
    ],
)
def test_cleanup_bounds_require_exact_authenticated_human_permission(
    context: SecurityContext,
) -> None:
    administration = DurableCleanupAdministration(
        worker=_Worker(),
        audit=AuditLedger(),
    )

    with pytest.raises(AgentAdministrationAccessDeniedError):
        administration.bounds(context)


@pytest.mark.asyncio
async def test_cleanup_run_rejects_unauthorized_context_before_audit_or_mutation() -> None:
    for context in (
        _context(permissions=frozenset()),
        _context(permissions=frozenset({"*"})),
        _context(principal_type=PrincipalType.SERVICE),
        _context(authenticated=False),
    ):
        worker = _Worker()
        store = InMemoryAuditStore()
        administration = DurableCleanupAdministration(
            worker=worker,
            audit=AuditLedger(store),
        )

        with pytest.raises(AgentAdministrationAccessDeniedError):
            await administration.run(
                context,
                expected_bounds=_bounds(),
                requested_at=NOW,
            )

        assert worker.calls == 0
        assert await store.read(AuditQuery(limit=10)) == ()


@pytest.mark.asyncio
async def test_cleanup_run_requires_expected_server_bounds_before_audit_or_mutation() -> None:
    worker = _Worker()
    store = InMemoryAuditStore()
    administration = DurableCleanupAdministration(
        worker=worker,
        audit=AuditLedger(store),
    )

    with pytest.raises(AgentStateConflictError):
        await administration.run(
            _context(),
            expected_bounds=_bounds(max_candidates=15),
            requested_at=NOW,
        )

    assert worker.calls == 0
    assert await store.read(AuditQuery(limit=10)) == ()


@pytest.mark.asyncio
async def test_cleanup_run_fails_closed_when_required_pre_mutation_audit_fails() -> None:
    worker = _Worker()
    administration = DurableCleanupAdministration(
        worker=worker,
        audit=AuditLedger(_FailingAuditStore()),
    )

    with pytest.raises(AgentServiceUnavailableError) as captured:
        await administration.run(
            _context(),
            expected_bounds=_bounds(),
            requested_at=NOW,
        )

    assert worker.calls == 0
    assert SECRET not in repr(captured.value)


@pytest.mark.asyncio
async def test_cleanup_run_records_safe_request_and_outcome_and_returns_report() -> None:
    worker = _Worker()
    store = InMemoryAuditStore()
    administration = DurableCleanupAdministration(
        worker=worker,
        audit=AuditLedger(store),
    )

    report = await administration.run(
        _context(),
        expected_bounds=_bounds(),
        requested_at=NOW,
    )

    assert report is REPORT
    assert worker.calls == 1

    records = await store.read(AuditQuery(limit=10))
    assert [record.event.name for record in records] == [
        "agent.durable.cleanup.requested",
        "agent.durable.cleanup.outcome",
    ]

    requested = records[0].event
    assert requested.action == AGENT_DURABLE_CLEANUP_ACTION
    assert requested.resource == DURABLE_ADMINISTRATION_CLEANUP_RESOURCE
    assert requested.outcome is AuditOutcome.UNKNOWN
    assert requested.details == {
        "bounds_schema_version": 1,
        "max_candidates": 16,
        "metadata_retention_microseconds": 30 * 86_400_000_000,
        "page_size": 32,
        "pass_timeout_microseconds": 30_000_000,
        "payload_retention_microseconds": 7 * 86_400_000_000,
        "requested_at": NOW.isoformat(),
        "tombstone_retention_microseconds": 90 * 86_400_000_000,
    }

    outcome = records[1].event
    assert outcome.action == AGENT_DURABLE_CLEANUP_ACTION
    assert outcome.resource == DURABLE_ADMINISTRATION_CLEANUP_RESOURCE
    assert outcome.outcome is AuditOutcome.SUCCEEDED
    assert outcome.details == {
        "admitted": 3,
        "conflicts": 0,
        "exhausted": True,
        "failed": 0,
        "pages": 2,
        "payloads_deleted": 1,
        "purged": 1,
        "stopped": False,
        "timed_out": False,
        "tombstoned": 1,
    }

    serialized = repr(records)
    assert SECRET not in serialized
    assert "phoenix-retention-admin-test" not in serialized


@pytest.mark.asyncio
async def test_cleanup_run_does_not_turn_post_mutation_audit_failure_into_retry_signal() -> None:
    worker = _Worker()
    store = _SecondAppendFailsAuditStore()
    administration = DurableCleanupAdministration(
        worker=worker,
        audit=AuditLedger(store),
    )

    report = await administration.run(
        _context(),
        expected_bounds=_bounds(),
        requested_at=NOW,
    )

    assert report is REPORT
    assert worker.calls == 1
    assert store.append_calls == 2
    records = await store.read(AuditQuery(limit=10))
    assert [record.event.name for record in records] == [
        "agent.durable.cleanup.requested",
    ]


@pytest.mark.asyncio
async def test_cleanup_run_suppresses_post_commit_audit_cancellation_retry_signal() -> None:
    worker = _Worker()
    store = _SecondAppendCancelledAuditStore()
    administration = DurableCleanupAdministration(
        worker=worker,
        audit=AuditLedger(store),
    )

    report = await administration.run(
        _context(),
        expected_bounds=_bounds(),
        requested_at=NOW,
    )

    assert report is REPORT
    assert worker.calls == 1
    assert store.append_calls == 2
    records = await store.read(AuditQuery(limit=10))
    assert [record.event.name for record in records] == [
        "agent.durable.cleanup.requested",
    ]


@pytest.mark.asyncio
async def test_cleanup_run_sanitizes_worker_failures_after_required_request_audit() -> None:
    worker = _Worker(error=RuntimeError(SECRET))
    store = InMemoryAuditStore()
    administration = DurableCleanupAdministration(
        worker=worker,
        audit=AuditLedger(store),
    )

    with pytest.raises(AgentServiceUnavailableError) as captured:
        await administration.run(
            _context(),
            expected_bounds=_bounds(),
            requested_at=NOW,
        )

    assert worker.calls == 1
    assert SECRET not in repr(captured.value)
    records = await store.read(AuditQuery(limit=10))
    assert [record.event.name for record in records] == [
        "agent.durable.cleanup.requested",
    ]


@pytest.mark.asyncio
async def test_cleanup_run_preserves_worker_conflict_without_leaking_content() -> None:
    worker = _Worker(error=AgentStateConflictError())
    store = InMemoryAuditStore()
    administration = DurableCleanupAdministration(
        worker=worker,
        audit=AuditLedger(store),
    )

    with pytest.raises(AgentStateConflictError):
        await administration.run(
            _context(),
            expected_bounds=_bounds(),
            requested_at=NOW,
        )

    assert worker.calls == 1
    records = await store.read(AuditQuery(limit=10))
    assert [record.event.name for record in records] == [
        "agent.durable.cleanup.requested",
    ]


@pytest.mark.asyncio
async def test_cleanup_close_stops_admission_and_drains_active_pass() -> None:
    worker = _BlockingWorker()
    administration = DurableCleanupAdministration(
        worker=worker,
        audit=AuditLedger(),
    )

    active = asyncio.create_task(
        administration.run(
            _context(),
            expected_bounds=_bounds(),
            requested_at=NOW,
        )
    )
    await worker.started.wait()

    closing = asyncio.create_task(administration.close())
    await asyncio.sleep(0)
    assert administration.closed
    assert not closing.done()

    rejected = asyncio.create_task(
        administration.run(
            _context(),
            expected_bounds=_bounds(),
            requested_at=NOW,
        )
    )
    await asyncio.sleep(0)
    assert not rejected.done()

    worker.release.set()

    assert await active is REPORT
    await closing
    with pytest.raises(AgentServiceUnavailableError):
        await rejected

    assert worker.calls == 1
    with pytest.raises(AgentServiceUnavailableError):
        administration.bounds(_context())


@pytest.mark.asyncio
async def test_cleanup_close_drains_even_when_caller_is_cancelled() -> None:
    worker = _BlockingWorker()
    administration = DurableCleanupAdministration(
        worker=worker,
        audit=AuditLedger(),
    )

    active = asyncio.create_task(
        administration.run(
            _context(),
            expected_bounds=_bounds(),
            requested_at=NOW,
        )
    )
    await worker.started.wait()

    closing = asyncio.create_task(administration.close())
    await asyncio.sleep(0)
    closing.cancel()
    await asyncio.sleep(0)

    assert administration.closed
    assert not closing.done()

    worker.release.set()
    assert await active is REPORT

    with pytest.raises(asyncio.CancelledError):
        await closing

    with pytest.raises(AgentServiceUnavailableError):
        await administration.run(
            _context(),
            expected_bounds=_bounds(),
            requested_at=NOW,
        )
    assert worker.calls == 1
