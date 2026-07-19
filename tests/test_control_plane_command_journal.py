from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest

from phoenix_os.control_plane import (
    MAX_COMMAND_JOURNAL_CAPACITY,
    ControlPlaneCommandAction,
    ControlPlaneCommandIntent,
    ControlPlaneCommandJournalAlreadyExistsError,
    ControlPlaneCommandJournalCapacityError,
    ControlPlaneCommandJournalConflictError,
    ControlPlaneCommandJournalNotFoundError,
    ControlPlaneCommandJournalPage,
    ControlPlaneCommandJournalPageInfo,
    ControlPlaneCommandJournalPageRequest,
    ControlPlaneCommandJournalRecord,
    ControlPlaneCommandJournalRepositoryClosedError,
    ControlPlaneCommandJournalSnapshot,
    ControlPlaneCommandJournalStatus,
    IdempotencyKey,
    InMemoryControlPlaneCommandJournalRepository,
    command_payload_digest,
)

_NOW = datetime(2026, 7, 19, 3, 0, tzinfo=UTC)
_DIGEST = "a" * 64
_FINGERPRINT = "b" * 64


def _intent(
    *,
    key: str = "journal-key-0001",
    target: str = "job:daily-report",
    requested_at: datetime = _NOW,
    command_id: UUID | None = None,
) -> ControlPlaneCommandIntent:
    return ControlPlaneCommandIntent(
        action=ControlPlaneCommandAction.CREATE_JOB,
        target=target,
        idempotency_key=IdempotencyKey(key),
        payload_digest=command_payload_digest(b'{"capability":"report"}'),
        requested_at=requested_at,
        id=command_id or uuid4(),
    )


def _record(
    *,
    command_id: UUID | None = None,
    idempotency_digest: str = _DIGEST,
    fingerprint: str = _FINGERPRINT,
    requested_at: datetime = _NOW,
    status: ControlPlaneCommandJournalStatus = ControlPlaneCommandJournalStatus.PENDING,
    updated_at: datetime | None = None,
    completed_at: datetime | None = None,
    result_code: str | None = None,
    revision: int = 1,
) -> ControlPlaneCommandJournalRecord:
    return ControlPlaneCommandJournalRecord(
        command_id=command_id or uuid4(),
        action=ControlPlaneCommandAction.CREATE_JOB,
        target=" job:daily-report ",
        principal=" phoenix.dashboard ",
        idempotency_digest=idempotency_digest,
        fingerprint=fingerprint,
        status=status,
        requested_at=requested_at,
        updated_at=updated_at or requested_at,
        completed_at=completed_at,
        result_code=result_code,
        revision=revision,
    )


@pytest.mark.parametrize(
    ("status", "terminal"),
    [
        (ControlPlaneCommandJournalStatus.PENDING, False),
        (ControlPlaneCommandJournalStatus.EXECUTING, False),
        (ControlPlaneCommandJournalStatus.SUCCEEDED, True),
        (ControlPlaneCommandJournalStatus.REJECTED, True),
        (ControlPlaneCommandJournalStatus.FAILED, True),
    ],
)
def test_command_journal_status_terminal(
    status: ControlPlaneCommandJournalStatus,
    terminal: bool,
) -> None:
    assert status.terminal is terminal


def test_command_journal_record_from_intent_omits_plaintext_key() -> None:
    intent = _intent(key="journal-secret-key")

    record = ControlPlaneCommandJournalRecord.from_intent(
        intent,
        principal=" dashboard.operator ",
    )

    assert record.command_id == intent.id
    assert record.action is intent.action
    assert record.target == intent.target
    assert record.principal == "dashboard.operator"
    assert record.idempotency_digest == intent.idempotency_key.digest.hex()
    assert record.fingerprint == intent.fingerprint
    assert record.status is ControlPlaneCommandJournalStatus.PENDING
    assert "journal-secret-key" not in repr(record)
    assert record.idempotency_digest not in repr(record)
    assert record.fingerprint not in repr(record)


def test_command_journal_record_normalizes_fields() -> None:
    record = _record(idempotency_digest="A" * 64, fingerprint="B" * 64)

    assert record.target == "job:daily-report"
    assert record.principal == "phoenix.dashboard"
    assert record.idempotency_digest == _DIGEST
    assert record.fingerprint == _FINGERPRINT


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("target", " ", "target"),
        ("target", "job\x00bad", "control characters"),
        ("target", "x" * 257, "target"),
        ("principal", " ", "principal"),
        ("principal", "operator\nroot", "control characters"),
        ("principal", "x" * 129, "principal"),
    ],
)
def test_command_journal_record_rejects_invalid_text(
    field: str,
    value: str,
    message: str,
) -> None:
    values: dict[str, object] = {
        "command_id": uuid4(),
        "action": ControlPlaneCommandAction.CREATE_JOB,
        "target": "job:daily-report",
        "principal": "phoenix.dashboard",
        "idempotency_digest": _DIGEST,
        "fingerprint": _FINGERPRINT,
        "status": ControlPlaneCommandJournalStatus.PENDING,
        "requested_at": _NOW,
        "updated_at": _NOW,
    }
    values[field] = value

    with pytest.raises(ValueError, match=message):
        ControlPlaneCommandJournalRecord(**values)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("idempotency_digest", "a" * 63),
        ("idempotency_digest", "g" * 64),
        ("fingerprint", "b" * 65),
        ("fingerprint", "-" * 64),
    ],
)
def test_command_journal_record_rejects_invalid_digests(field: str, value: str) -> None:
    if field == "idempotency_digest":
        with pytest.raises(ValueError, match="idempotency digest"):
            _record(idempotency_digest=value)
    else:
        with pytest.raises(ValueError, match="fingerprint"):
            _record(fingerprint=value)


@pytest.mark.parametrize("schema_version", [0, 2])
def test_command_journal_record_rejects_unknown_schema(schema_version: int) -> None:
    with pytest.raises(ValueError, match="schema version"):
        replace(_record(), schema_version=schema_version)


@pytest.mark.parametrize("revision", [-1, 0])
def test_command_journal_record_requires_positive_revision(revision: int) -> None:
    with pytest.raises(ValueError, match="revision"):
        _record(revision=revision)


def test_command_journal_record_requires_aware_times() -> None:
    naive = datetime(2026, 7, 19, 3, 0)

    with pytest.raises(ValueError, match="requested_at"):
        _record(requested_at=naive)

    with pytest.raises(ValueError, match="updated_at"):
        _record(updated_at=naive)


def test_command_journal_record_rejects_time_travel() -> None:
    with pytest.raises(ValueError, match="updated_at cannot precede"):
        _record(updated_at=_NOW - timedelta(seconds=1))

    with pytest.raises(ValueError, match="completed_at cannot precede"):
        _record(
            status=ControlPlaneCommandJournalStatus.SUCCEEDED,
            updated_at=_NOW + timedelta(seconds=2),
            completed_at=_NOW + timedelta(seconds=1),
            result_code="job.created",
        )


@pytest.mark.parametrize(
    "status",
    [
        ControlPlaneCommandJournalStatus.PENDING,
        ControlPlaneCommandJournalStatus.EXECUTING,
    ],
)
def test_non_terminal_record_rejects_completion_data(
    status: ControlPlaneCommandJournalStatus,
) -> None:
    with pytest.raises(ValueError, match="non-terminal"):
        _record(status=status, completed_at=_NOW, result_code="job.created")


@pytest.mark.parametrize(
    "status",
    [
        ControlPlaneCommandJournalStatus.SUCCEEDED,
        ControlPlaneCommandJournalStatus.REJECTED,
        ControlPlaneCommandJournalStatus.FAILED,
    ],
)
def test_terminal_record_requires_completion_data(
    status: ControlPlaneCommandJournalStatus,
) -> None:
    with pytest.raises(ValueError, match="terminal"):
        _record(status=status)


def test_terminal_record_normalizes_result_code() -> None:
    record = _record(
        status=ControlPlaneCommandJournalStatus.SUCCEEDED,
        completed_at=_NOW,
        result_code=" JOB.CREATED ",
    )

    assert record.result_code == "job.created"


def test_terminal_record_rejects_invalid_result_code() -> None:
    with pytest.raises(ValueError, match="result code"):
        _record(
            status=ControlPlaneCommandJournalStatus.FAILED,
            completed_at=_NOW,
            result_code="internal error details",
        )


@pytest.mark.parametrize(
    ("offset", "limit"),
    [(-1, 10), (0, 0), (0, 201)],
)
def test_command_journal_page_request_rejects_invalid_bounds(offset: int, limit: int) -> None:
    with pytest.raises(ValueError):
        ControlPlaneCommandJournalPageRequest(offset=offset, limit=limit)


def test_command_journal_page_info_builds_next_offset() -> None:
    request = ControlPlaneCommandJournalPageRequest(offset=10, limit=5)

    page = ControlPlaneCommandJournalPageInfo.from_slice(request, returned=5, total=20)

    assert page.next_offset == 15


def test_command_journal_page_info_ends_at_total() -> None:
    request = ControlPlaneCommandJournalPageRequest(offset=10, limit=5)

    page = ControlPlaneCommandJournalPageInfo.from_slice(request, returned=2, total=12)

    assert page.next_offset is None


@pytest.mark.parametrize(
    "page",
    [
        ControlPlaneCommandJournalPageInfo(0, 10, 0, 0, None),
        ControlPlaneCommandJournalPageInfo(0, 10, 1, 1, None),
    ],
)
def test_command_journal_page_accepts_consistent_items(
    page: ControlPlaneCommandJournalPageInfo,
) -> None:
    items = () if page.returned == 0 else (_record(),)

    result = ControlPlaneCommandJournalPage(items=items, page=page)

    assert len(result.items) == page.returned


def test_command_journal_page_rejects_duplicate_items() -> None:
    record = _record()
    page = ControlPlaneCommandJournalPageInfo(0, 2, 2, 2, None)

    with pytest.raises(ValueError, match="unique"):
        ControlPlaneCommandJournalPage(items=(record, record), page=page)


def test_command_journal_snapshot_validates_totals() -> None:
    snapshot = ControlPlaneCommandJournalSnapshot(
        closed=False,
        entries=5,
        pending=1,
        executing=1,
        succeeded=1,
        rejected=1,
        failed=1,
        capacity=10,
    )

    assert snapshot.entries == 5


def test_command_journal_snapshot_rejects_inconsistent_totals() -> None:
    with pytest.raises(ValueError, match="status counts"):
        ControlPlaneCommandJournalSnapshot(
            closed=False,
            entries=2,
            pending=1,
            executing=0,
            succeeded=0,
            rejected=0,
            failed=0,
            capacity=10,
        )


@pytest.mark.parametrize("capacity", [0, -1, MAX_COMMAND_JOURNAL_CAPACITY + 1])
def test_memory_command_journal_rejects_invalid_capacity(capacity: int) -> None:
    with pytest.raises(ValueError, match="capacity"):
        InMemoryControlPlaneCommandJournalRepository(capacity=capacity)


async def test_memory_command_journal_adds_and_reads_record() -> None:
    repository = InMemoryControlPlaneCommandJournalRepository()
    record = _record()

    await repository.add(record)

    assert await repository.get(record.command_id) == record
    assert await repository.get_by_idempotency_digest(record.idempotency_digest) == record


async def test_memory_command_journal_normalizes_digest_lookup() -> None:
    repository = InMemoryControlPlaneCommandJournalRepository()
    record = _record()
    await repository.add(record)

    assert await repository.get_by_idempotency_digest("A" * 64) == record


async def test_memory_command_journal_rejects_invalid_digest_lookup() -> None:
    repository = InMemoryControlPlaneCommandJournalRepository()

    with pytest.raises(ValueError, match="SHA-256"):
        await repository.get_by_idempotency_digest("not-a-digest")


async def test_memory_command_journal_rejects_duplicate_command_id() -> None:
    repository = InMemoryControlPlaneCommandJournalRepository()
    command_id = uuid4()
    await repository.add(_record(command_id=command_id))

    with pytest.raises(ControlPlaneCommandJournalAlreadyExistsError):
        await repository.add(
            _record(
                command_id=command_id,
                idempotency_digest="c" * 64,
                fingerprint="d" * 64,
            )
        )


async def test_memory_command_journal_rejects_duplicate_idempotency_digest() -> None:
    repository = InMemoryControlPlaneCommandJournalRepository()
    await repository.add(_record())

    with pytest.raises(ControlPlaneCommandJournalAlreadyExistsError):
        await repository.add(_record(fingerprint="c" * 64))


async def test_memory_command_journal_enforces_capacity() -> None:
    repository = InMemoryControlPlaneCommandJournalRepository(capacity=1)
    await repository.add(_record())

    with pytest.raises(ControlPlaneCommandJournalCapacityError):
        await repository.add(_record(idempotency_digest="c" * 64, fingerprint="d" * 64))


async def test_memory_command_journal_concurrent_duplicate_add_is_atomic() -> None:
    repository = InMemoryControlPlaneCommandJournalRepository()
    record = _record()

    results = await asyncio.gather(
        repository.add(record),
        repository.add(record),
        return_exceptions=True,
    )

    assert sum(result is None for result in results) == 1
    assert (
        sum(isinstance(result, ControlPlaneCommandJournalAlreadyExistsError) for result in results)
        == 1
    )


async def test_memory_command_journal_lists_newest_first_with_pagination() -> None:
    repository = InMemoryControlPlaneCommandJournalRepository()
    older = _record(command_id=UUID(int=1), requested_at=_NOW)
    newer = _record(
        command_id=UUID(int=2),
        idempotency_digest="c" * 64,
        fingerprint="d" * 64,
        requested_at=_NOW + timedelta(seconds=1),
    )
    await repository.add(older)
    await repository.add(newer)

    first = await repository.list_page(ControlPlaneCommandJournalPageRequest(limit=1))
    second = await repository.list_page(ControlPlaneCommandJournalPageRequest(offset=1, limit=1))

    assert first.items == (newer,)
    assert first.page.next_offset == 1
    assert second.items == (older,)
    assert second.page.next_offset is None


async def test_memory_command_journal_transitions_to_executing() -> None:
    repository = InMemoryControlPlaneCommandJournalRepository()
    record = _record()
    await repository.add(record)

    updated = await repository.transition(
        record.command_id,
        expected_revision=1,
        status=ControlPlaneCommandJournalStatus.EXECUTING,
        updated_at=_NOW + timedelta(seconds=1),
    )

    assert updated.status is ControlPlaneCommandJournalStatus.EXECUTING
    assert updated.revision == 2
    assert updated.completed_at is None
    assert updated.result_code is None


@pytest.mark.parametrize(
    ("status", "result_code"),
    [
        (ControlPlaneCommandJournalStatus.SUCCEEDED, "job.created"),
        (ControlPlaneCommandJournalStatus.REJECTED, "command.denied"),
        (ControlPlaneCommandJournalStatus.FAILED, "command.failed"),
    ],
)
async def test_memory_command_journal_allows_pending_terminal_reconciliation(
    status: ControlPlaneCommandJournalStatus,
    result_code: str,
) -> None:
    repository = InMemoryControlPlaneCommandJournalRepository()
    record = _record()
    await repository.add(record)
    finished_at = _NOW + timedelta(seconds=1)

    updated = await repository.transition(
        record.command_id,
        expected_revision=1,
        status=status,
        updated_at=finished_at,
        result_code=result_code,
    )

    assert updated.status is status
    assert updated.completed_at == finished_at
    assert updated.result_code == result_code


@pytest.mark.parametrize(
    "status",
    [
        ControlPlaneCommandJournalStatus.SUCCEEDED,
        ControlPlaneCommandJournalStatus.REJECTED,
        ControlPlaneCommandJournalStatus.FAILED,
    ],
)
async def test_memory_command_journal_allows_executing_terminal_transition(
    status: ControlPlaneCommandJournalStatus,
) -> None:
    repository = InMemoryControlPlaneCommandJournalRepository()
    record = _record()
    await repository.add(record)
    executing = await repository.transition(
        record.command_id,
        expected_revision=1,
        status=ControlPlaneCommandJournalStatus.EXECUTING,
        updated_at=_NOW + timedelta(seconds=1),
    )

    terminal = await repository.transition(
        record.command_id,
        expected_revision=executing.revision,
        status=status,
        updated_at=_NOW + timedelta(seconds=2),
        result_code="command.finished",
    )

    assert terminal.status is status
    assert terminal.revision == 3


async def test_memory_command_journal_rejects_stale_revision() -> None:
    repository = InMemoryControlPlaneCommandJournalRepository()
    record = _record()
    await repository.add(record)

    with pytest.raises(ControlPlaneCommandJournalConflictError, match="revision"):
        await repository.transition(
            record.command_id,
            expected_revision=2,
            status=ControlPlaneCommandJournalStatus.EXECUTING,
            updated_at=_NOW,
        )


async def test_memory_command_journal_rejects_missing_record_transition() -> None:
    repository = InMemoryControlPlaneCommandJournalRepository()

    with pytest.raises(ControlPlaneCommandJournalNotFoundError):
        await repository.transition(
            uuid4(),
            expected_revision=1,
            status=ControlPlaneCommandJournalStatus.EXECUTING,
            updated_at=_NOW,
        )


async def test_memory_command_journal_rejects_terminal_replacement() -> None:
    repository = InMemoryControlPlaneCommandJournalRepository()
    record = _record()
    await repository.add(record)
    terminal = await repository.transition(
        record.command_id,
        expected_revision=1,
        status=ControlPlaneCommandJournalStatus.SUCCEEDED,
        updated_at=_NOW + timedelta(seconds=1),
        result_code="job.created",
    )

    with pytest.raises(ControlPlaneCommandJournalConflictError, match="transition"):
        await repository.transition(
            record.command_id,
            expected_revision=terminal.revision,
            status=ControlPlaneCommandJournalStatus.FAILED,
            updated_at=_NOW + timedelta(seconds=2),
            result_code="command.failed",
        )


async def test_memory_command_journal_rejects_backwards_update_time() -> None:
    repository = InMemoryControlPlaneCommandJournalRepository()
    record = _record()
    await repository.add(record)
    executing = await repository.transition(
        record.command_id,
        expected_revision=1,
        status=ControlPlaneCommandJournalStatus.EXECUTING,
        updated_at=_NOW + timedelta(seconds=2),
    )

    with pytest.raises(ControlPlaneCommandJournalConflictError, match="backwards"):
        await repository.transition(
            record.command_id,
            expected_revision=executing.revision,
            status=ControlPlaneCommandJournalStatus.FAILED,
            updated_at=_NOW + timedelta(seconds=1),
            result_code="command.failed",
        )


async def test_memory_command_journal_requires_transition_result_code() -> None:
    repository = InMemoryControlPlaneCommandJournalRepository()
    record = _record()
    await repository.add(record)

    with pytest.raises(ValueError, match="terminal"):
        await repository.transition(
            record.command_id,
            expected_revision=1,
            status=ControlPlaneCommandJournalStatus.SUCCEEDED,
            updated_at=_NOW + timedelta(seconds=1),
        )


async def test_memory_command_journal_snapshot_counts_states() -> None:
    repository = InMemoryControlPlaneCommandJournalRepository(capacity=10)
    pending = _record()
    executing = _record(idempotency_digest="c" * 64, fingerprint="d" * 64)
    failed = _record(idempotency_digest="e" * 64, fingerprint="f" * 64)
    for record in (pending, executing, failed):
        await repository.add(record)
    await repository.transition(
        executing.command_id,
        expected_revision=1,
        status=ControlPlaneCommandJournalStatus.EXECUTING,
        updated_at=_NOW,
    )
    await repository.transition(
        failed.command_id,
        expected_revision=1,
        status=ControlPlaneCommandJournalStatus.FAILED,
        updated_at=_NOW,
        result_code="command.failed",
    )

    snapshot = await repository.snapshot()

    assert snapshot.entries == 3
    assert snapshot.pending == 1
    assert snapshot.executing == 1
    assert snapshot.failed == 1
    assert snapshot.succeeded == 0
    assert snapshot.rejected == 0
    assert snapshot.capacity == 10


async def test_memory_command_journal_close_clears_records_and_reports_closed() -> None:
    repository = InMemoryControlPlaneCommandJournalRepository()
    await repository.add(_record())

    await repository.close()
    snapshot = await repository.snapshot()

    assert repository.closed is True
    assert snapshot.closed is True
    assert snapshot.entries == 0


async def test_memory_command_journal_rejects_operations_after_close() -> None:
    repository = InMemoryControlPlaneCommandJournalRepository()
    await repository.close()

    with pytest.raises(ControlPlaneCommandJournalRepositoryClosedError):
        await repository.add(_record())
    with pytest.raises(ControlPlaneCommandJournalRepositoryClosedError):
        await repository.get(uuid4())
    with pytest.raises(ControlPlaneCommandJournalRepositoryClosedError):
        await repository.list_page()
