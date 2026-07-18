from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from phoenix_os import (
    Identity,
    InMemorySessionRepository,
    MemoryStateStore,
    Session,
    SessionRecord,
    SessionRepositoryClosedError,
    SessionStatus,
    StateSessionRepository,
)


def make_record(subject: str = "arthur", digest: str = "a" * 64) -> SessionRecord:
    now = datetime.now(UTC)
    session = Session(
        uuid4(),
        Identity(subject, roles=frozenset({"user"}), attributes={"tenant": "phoenix"}),
        now,
        now + timedelta(hours=1),
        now,
        idle_expires_at=now + timedelta(minutes=30),
        idle_ttl=timedelta(minutes=30),
        metadata={"device": "desktop"},
    )
    return SessionRecord(session, digest)


@pytest.mark.asyncio
async def test_in_memory_repository_round_trip_and_indexes() -> None:
    repository = InMemorySessionRepository()
    first = make_record("arthur", "a" * 64)
    second = make_record("arthur", "b" * 64)
    await repository.save(second)
    await repository.save(first)

    assert await repository.get(first.session.id) == first
    assert await repository.find_by_digest(first.token_digest) == first
    assert await repository.find_by_digest("f" * 64) is None
    assert {record.token_digest for record in await repository.list_for_subject("arthur")} == {
        first.token_digest,
        second.token_digest,
    }
    assert len(await repository.list_all()) == 2


@pytest.mark.asyncio
async def test_in_memory_repository_updates_digest_index() -> None:
    repository = InMemorySessionRepository()
    record = make_record(digest="a" * 64)
    await repository.save(record)
    changed = replace(record, token_digest="b" * 64)
    await repository.save(changed)
    assert await repository.find_by_digest("a" * 64) is None
    assert await repository.find_by_digest("b" * 64) == changed


@pytest.mark.asyncio
async def test_in_memory_repository_rejects_digest_collision() -> None:
    repository = InMemorySessionRepository()
    await repository.save(make_record("arthur", "a" * 64))
    with pytest.raises(ValueError, match="collision"):
        await repository.save(make_record("nova", "a" * 64))


@pytest.mark.asyncio
async def test_in_memory_repository_close_rejects_use() -> None:
    repository = InMemorySessionRepository()
    await repository.close()
    assert repository.closed
    with pytest.raises(SessionRepositoryClosedError):
        await repository.list_all()


@pytest.mark.asyncio
async def test_state_repository_round_trip_and_update() -> None:
    store = MemoryStateStore()
    repository = StateSessionRepository(store)
    record = make_record(digest="c" * 64)
    await repository.save(record)

    loaded = await repository.get(record.session.id)
    assert loaded == record
    assert await repository.find_by_digest(record.token_digest) == record

    revoked = replace(
        record,
        session=replace(
            record.session,
            status=SessionStatus.REVOKED,
            revoked_at=datetime.now(UTC),
            revocation_reason="logout",
        ),
    )
    await repository.save(revoked)
    assert await repository.get(record.session.id) == revoked


@pytest.mark.asyncio
async def test_state_repository_lists_by_subject() -> None:
    store = MemoryStateStore()
    repository = StateSessionRepository(store)
    first = make_record("arthur", "d" * 64)
    second = make_record("nova", "e" * 64)
    await repository.save(first)
    await repository.save(second)
    assert await repository.list_for_subject("arthur") == (first,)
    assert len(await repository.list_all()) == 2


@pytest.mark.asyncio
async def test_state_repository_borrows_store_lifecycle() -> None:
    store = MemoryStateStore()
    repository = StateSessionRepository(store)
    await repository.close()
    assert repository.closed
    assert not store.closed
    with pytest.raises(SessionRepositoryClosedError):
        await repository.list_all()
