from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from phoenix_os.agent import (
    AgentCodecError,
    AgentId,
    AgentLimitExceededError,
    AgentServiceUnavailableError,
    AgentStateConflictError,
    ArtifactDeleteRequest,
    ArtifactDigest,
    ArtifactId,
    ArtifactListRequest,
    ArtifactLogicalPath,
    ArtifactOriginKind,
    ArtifactProvenance,
    ArtifactReadRequest,
    ArtifactRecord,
    ArtifactVersion,
    ArtifactWriteRequest,
    InMemoryWorkspaceBackingAdapter,
    InMemoryWorkspaceStore,
    StateStoreWorkspaceStore,
    WorkspaceLimits,
    WorkspaceNamespace,
    WorkspaceRetentionPolicy,
    WorkspaceScope,
    agent_workspace_scope,
    artifact_content_digest,
)
from phoenix_os.agent.workspace_backing import WorkspaceBackingKey
from phoenix_os.state import MemoryStateStore, StateKey, StateOperationContext
from phoenix_os.state.errors import StateTransactionError
from phoenix_os.state.memory import MemoryStateTransaction

_NOW = datetime(2026, 8, 12, 12, tzinfo=UTC)


class FakeClock:
    def __init__(self, now: datetime = _NOW) -> None:
        self.now = now

    def __call__(self) -> datetime:
        return self.now

    def advance(self, delta: timedelta) -> None:
        self.now += delta


def _scope(scope_id: str = "researcher") -> WorkspaceScope:
    return agent_workspace_scope(
        namespace=WorkspaceNamespace("default"),
        agent_id=AgentId(scope_id),
    )


def _artifact_id(value: int = 1) -> ArtifactId:
    return ArtifactId(UUID(int=value))


def _write(
    content: bytes,
    *,
    artifact_id: ArtifactId | None = None,
    logical_path: str = "reports/result.txt",
    expected_version: ArtifactVersion | None = None,
    scope: WorkspaceScope | None = None,
    created_at: datetime = _NOW,
) -> ArtifactWriteRequest:
    digest = artifact_content_digest(content)
    return ArtifactWriteRequest(
        scope=_scope() if scope is None else scope,
        artifact_id=_artifact_id() if artifact_id is None else artifact_id,
        logical_path=ArtifactLogicalPath(logical_path),
        content=content,
        provenance=ArtifactProvenance(
            origin=ArtifactOriginKind.AGENT_REQUEST,
            content_digest=digest,
            created_at=created_at,
            source_agent_id=AgentId("researcher"),
            attributes={"source": "test"},
        ),
        metadata={"kind": "report"},
        expected_version=expected_version,
        created_at=created_at,
    )


def _read(
    artifact_id: ArtifactId | None = None,
    *,
    scope: WorkspaceScope | None = None,
) -> ArtifactReadRequest:
    return ArtifactReadRequest(
        scope=_scope() if scope is None else scope,
        artifact_id=_artifact_id() if artifact_id is None else artifact_id,
        created_at=_NOW,
    )


class _InspectableBacking(InMemoryWorkspaceBackingAdapter):
    @property
    def keys(self) -> tuple[WorkspaceBackingKey, ...]:
        return tuple(self._objects)

    def corrupt(self, key: WorkspaceBackingKey, content: bytes) -> None:
        self._objects[key] = content


class _RetainingBacking(_InspectableBacking):
    async def delete(self, key: WorkspaceBackingKey) -> None:
        self._ensure_open()
        if not isinstance(key, WorkspaceBackingKey):
            raise TypeError("key must be WorkspaceBackingKey")


class _BlockingBacking(_InspectableBacking):
    def __init__(self) -> None:
        super().__init__()
        self.written = asyncio.Event()
        self.release = asyncio.Event()

    async def write(
        self,
        key: WorkspaceBackingKey,
        content: bytes,
        *,
        expected_digest: ArtifactDigest,
    ) -> None:
        await super().write(
            key,
            content,
            expected_digest=expected_digest,
        )
        self.written.set()
        await self.release.wait()


class _ReadFailingBacking(_InspectableBacking):
    def __init__(self) -> None:
        super().__init__()
        self.fail_reads = False

    async def read(
        self,
        key: WorkspaceBackingKey,
        *,
        expected_digest: ArtifactDigest,
    ) -> bytes:
        if self.fail_reads:
            raise AgentCodecError("injected backing read failure")
        return await super().read(key, expected_digest=expected_digest)


class _ControlledCommitStateStore(MemoryStateStore):
    def __init__(self, *, clock: FakeClock) -> None:
        super().__init__(clock=clock)
        self.fail_commits = True

    def transaction(
        self,
        *,
        context: StateOperationContext | None = None,
    ) -> MemoryStateTransaction:
        self._ensure_open()
        return _ControlledCommitTransaction(self, context=context)


class _ControlledCommitTransaction(MemoryStateTransaction):
    def __init__(
        self,
        store: _ControlledCommitStateStore,
        *,
        context: StateOperationContext | None,
    ) -> None:
        super().__init__(store, context=context)
        self._controlled_store = store

    async def commit(self) -> None:
        if self._controlled_store.fail_commits:
            raise StateTransactionError("injected authoritative commit failure")
        await super().commit()


class _PostCommitBlockingStateStore(MemoryStateStore):
    def __init__(self, *, clock: FakeClock) -> None:
        super().__init__(clock=clock)
        self.committed = asyncio.Event()
        self.release = asyncio.Event()

    def transaction(
        self,
        *,
        context: StateOperationContext | None = None,
    ) -> MemoryStateTransaction:
        self._ensure_open()
        return _PostCommitBlockingTransaction(self, context=context)


class _PostCommitBlockingTransaction(MemoryStateTransaction):
    def __init__(
        self,
        store: _PostCommitBlockingStateStore,
        *,
        context: StateOperationContext | None,
    ) -> None:
        super().__init__(store, context=context)
        self._controlled_store = store

    async def commit(self) -> None:
        await super().commit()
        self._controlled_store.committed.set()
        await self._controlled_store.release.wait()


async def _replace_record_document(
    state: MemoryStateStore,
    **updates: object,
) -> None:
    stored_records = await state.list(namespace="agent-workspace", prefix="record.")
    assert len(stored_records) == 1
    stored = stored_records[0]
    assert isinstance(stored.value, dict)
    document = dict(stored.value)
    document.update(updates)
    await state.put(
        StateKey(stored.key.namespace, stored.key.name, dict),
        document,
        expected_version=stored.version,
    )


async def _assert_read_and_list_fail_closed(
    store: StateStoreWorkspaceStore,
    record: ArtifactRecord,
) -> None:
    with pytest.raises(AgentCodecError, match="authoritative metadata"):
        await store.read(_read(record.artifact_id, scope=record.scope))
    with pytest.raises(AgentCodecError, match="authoritative metadata"):
        await store.list(ArtifactListRequest(scope=record.scope, created_at=_NOW))


@pytest.mark.asyncio
async def test_create_read_list_update_and_delete() -> None:
    clock = FakeClock()
    store = InMemoryWorkspaceStore(clock=clock)
    created = await store.write(_write(b"first version"))

    assert isinstance(created, ArtifactRecord)
    assert not hasattr(created, "content")
    loaded = await store.read(_read(created.artifact_id))
    assert loaded is not None
    assert loaded.record == created
    assert loaded.content == b"first version"

    listing = await store.list(
        ArtifactListRequest(
            scope=created.scope,
            prefix=ArtifactLogicalPath("reports"),
            max_results=4,
            created_at=clock(),
        )
    )
    assert listing.artifacts == (created,)
    assert listing.records == (created,)
    assert listing.truncated is False

    clock.advance(timedelta(seconds=1))
    updated = await store.write(
        _write(
            b"second version",
            artifact_id=created.artifact_id,
            logical_path="reports/final.txt",
            expected_version=created.version,
            created_at=clock(),
        )
    )
    assert updated.version == created.version.next()
    assert updated.created_at == created.created_at
    loaded = await store.read(_read(created.artifact_id))
    assert loaded is not None and loaded.content == b"second version"

    clock.advance(timedelta(seconds=1))
    await store.delete(
        ArtifactDeleteRequest(
            scope=created.scope,
            artifact_id=created.artifact_id,
            expected_version=updated.version,
            created_at=clock(),
        )
    )
    assert await store.read(_read(created.artifact_id)) is None
    assert (
        await store.list(ArtifactListRequest(scope=created.scope, created_at=clock()))
    ).artifacts == ()


@pytest.mark.asyncio
async def test_optimistic_stale_write_and_delete_are_rejected() -> None:
    clock = FakeClock()
    store = InMemoryWorkspaceStore(clock=clock)
    created = await store.write(_write(b"base"))
    clock.advance(timedelta(seconds=1))
    updated = await store.write(
        _write(
            b"updated",
            artifact_id=created.artifact_id,
            expected_version=created.version,
            created_at=clock(),
        )
    )

    with pytest.raises(AgentStateConflictError):
        await store.write(
            _write(
                b"stale",
                artifact_id=created.artifact_id,
                expected_version=created.version,
                created_at=clock(),
            )
        )
    with pytest.raises(AgentStateConflictError):
        await store.delete(
            ArtifactDeleteRequest(
                scope=created.scope,
                artifact_id=created.artifact_id,
                expected_version=created.version,
                created_at=clock(),
            )
        )

    loaded = await store.read(_read(created.artifact_id))
    assert loaded is not None and loaded.record == updated


@pytest.mark.asyncio
async def test_canonical_logical_path_collision_is_rejected() -> None:
    store = InMemoryWorkspaceStore(clock=FakeClock())
    await store.write(
        _write(
            b"first",
            artifact_id=_artifact_id(1),
            logical_path="Reports/R\u00e9sum\u00e9.TXT",
        )
    )

    with pytest.raises(AgentStateConflictError):
        await store.write(
            _write(
                b"second",
                artifact_id=_artifact_id(2),
                logical_path="reports/re\u0301sume\u0301.txt",
            )
        )


@pytest.mark.asyncio
async def test_per_artifact_byte_quota_is_enforced() -> None:
    store = InMemoryWorkspaceStore(
        limits=WorkspaceLimits(max_artifact_bytes=4, max_total_bytes_per_scope=8),
        clock=FakeClock(),
    )

    with pytest.raises(AgentLimitExceededError):
        await store.write(_write(b"12345"))


@pytest.mark.asyncio
async def test_artifact_count_quota_is_enforced() -> None:
    store = InMemoryWorkspaceStore(
        limits=WorkspaceLimits(
            max_artifacts_per_scope=1,
            max_artifact_id_history_per_scope=2,
        ),
        clock=FakeClock(),
    )
    await store.write(_write(b"one", artifact_id=_artifact_id(1), logical_path="one.txt"))

    with pytest.raises(AgentLimitExceededError):
        await store.write(_write(b"two", artifact_id=_artifact_id(2), logical_path="two.txt"))


@pytest.mark.asyncio
async def test_total_scope_byte_quota_accounts_for_updates() -> None:
    clock = FakeClock()
    store = InMemoryWorkspaceStore(
        limits=WorkspaceLimits(max_artifact_bytes=8, max_total_bytes_per_scope=8),
        clock=clock,
    )
    first = await store.write(_write(b"1234", artifact_id=_artifact_id(1), logical_path="one.txt"))
    await store.write(_write(b"5678", artifact_id=_artifact_id(2), logical_path="two.txt"))

    clock.advance(timedelta(seconds=1))
    with pytest.raises(AgentLimitExceededError):
        await store.write(
            _write(
                b"12345",
                artifact_id=first.artifact_id,
                logical_path="one.txt",
                expected_version=first.version,
                created_at=clock(),
            )
        )


@pytest.mark.asyncio
async def test_concurrent_quota_race_has_one_winner() -> None:
    limits = WorkspaceLimits(
        max_artifacts_per_scope=1,
        max_artifact_id_history_per_scope=2,
    )
    store = InMemoryWorkspaceStore(limits=limits, clock=FakeClock())

    results = await asyncio.gather(
        store.write(_write(b"left", artifact_id=_artifact_id(1), logical_path="left.txt")),
        store.write(_write(b"right", artifact_id=_artifact_id(2), logical_path="right.txt")),
        return_exceptions=True,
    )

    assert len([item for item in results if isinstance(item, ArtifactRecord)]) == 1
    assert len([item for item in results if isinstance(item, AgentLimitExceededError)]) == 1


@pytest.mark.asyncio
async def test_concurrent_canonical_path_collision_has_one_winner() -> None:
    store = InMemoryWorkspaceStore(clock=FakeClock())

    results = await asyncio.gather(
        store.write(_write(b"left", artifact_id=_artifact_id(1), logical_path="SAME.txt")),
        store.write(_write(b"right", artifact_id=_artifact_id(2), logical_path="same.TXT")),
        return_exceptions=True,
    )

    assert len([item for item in results if isinstance(item, ArtifactRecord)]) == 1
    assert len([item for item in results if isinstance(item, AgentStateConflictError)]) == 1


@pytest.mark.asyncio
async def test_backing_digest_mismatch_fails_closed_without_leaking_bytes() -> None:
    clock = FakeClock()
    state = MemoryStateStore(clock=clock)
    backing = _InspectableBacking()
    store = StateStoreWorkspaceStore(state, backing, clock=clock)
    created = await store.write(_write(b"private original bytes"))
    key = backing.keys[0]
    backing.corrupt(key, b"substituted native path C:/private")

    with pytest.raises(AgentCodecError) as captured:
        await store.read(_read(created.artifact_id))
    message = str(captured.value)
    assert "private original bytes" not in message
    assert "C:/private" not in message


@pytest.mark.asyncio
async def test_persisted_future_updated_at_fails_closed_on_read_and_list() -> None:
    clock = FakeClock()
    state = MemoryStateStore(clock=clock)
    backing = _InspectableBacking()
    store = StateStoreWorkspaceStore(state, backing, clock=clock)
    created = await store.write(_write(b"trusted bytes"))
    future = clock() + timedelta(seconds=1)
    await _replace_record_document(
        state,
        updated_at=future.isoformat(),
        expires_at=(future + store.limits.retention.artifact_ttl).isoformat(),
    )

    await _assert_read_and_list_fail_closed(store, created)


@pytest.mark.asyncio
async def test_persisted_expiry_above_current_retention_fails_closed() -> None:
    clock = FakeClock()
    state = MemoryStateStore(clock=clock)
    backing = _InspectableBacking()
    original = StateStoreWorkspaceStore(state, backing, clock=clock)
    created = await original.write(_write(b"trusted bytes"))
    strict_limits = WorkspaceLimits(
        retention=WorkspaceRetentionPolicy(
            artifact_ttl=timedelta(days=1),
            tombstone_retention=timedelta(days=90),
        )
    )
    hardened = StateStoreWorkspaceStore(
        state,
        backing,
        limits=strict_limits,
        clock=clock,
    )

    await _assert_read_and_list_fail_closed(hardened, created)


@pytest.mark.asyncio
async def test_persisted_byte_length_above_current_limit_fails_closed() -> None:
    clock = FakeClock()
    state = MemoryStateStore(clock=clock)
    backing = _InspectableBacking()
    original = StateStoreWorkspaceStore(state, backing, clock=clock)
    created = await original.write(_write(b"12345"))
    hardened = StateStoreWorkspaceStore(
        state,
        backing,
        limits=WorkspaceLimits(max_artifact_bytes=4, max_total_bytes_per_scope=4),
        clock=clock,
    )

    await _assert_read_and_list_fail_closed(hardened, created)


@pytest.mark.asyncio
async def test_persisted_path_above_current_logical_path_limit_fails_closed() -> None:
    clock = FakeClock()
    state = MemoryStateStore(clock=clock)
    backing = _InspectableBacking()
    original = StateStoreWorkspaceStore(state, backing, clock=clock)
    created = await original.write(_write(b"trusted", logical_path="docs/long-name.txt"))
    hardened = StateStoreWorkspaceStore(
        state,
        backing,
        limits=WorkspaceLimits(max_logical_path_bytes=8),
        clock=clock,
    )
    await _assert_read_and_list_fail_closed(hardened, created)

    segment_hardened = StateStoreWorkspaceStore(
        state,
        backing,
        limits=WorkspaceLimits(max_logical_path_segments=1),
        clock=clock,
    )
    await _assert_read_and_list_fail_closed(segment_hardened, created)


@pytest.mark.asyncio
async def test_persisted_tombstone_above_current_retention_fails_closed() -> None:
    clock = FakeClock()
    state = MemoryStateStore(clock=clock)
    backing = _InspectableBacking()
    original = StateStoreWorkspaceStore(state, backing, clock=clock)
    created = await original.write(_write(b"delete me"))
    await original.delete(
        ArtifactDeleteRequest(
            scope=created.scope,
            artifact_id=created.artifact_id,
            expected_version=created.version,
            created_at=clock(),
        )
    )
    hardened = StateStoreWorkspaceStore(
        state,
        backing,
        limits=WorkspaceLimits(
            retention=WorkspaceRetentionPolicy(
                artifact_ttl=timedelta(days=30),
                tombstone_retention=timedelta(days=1),
            )
        ),
        clock=clock,
    )

    await _assert_read_and_list_fail_closed(hardened, created)


@pytest.mark.asyncio
async def test_content_free_list_does_not_read_backing_bytes() -> None:
    clock = FakeClock()
    state = MemoryStateStore(clock=clock)
    backing = _ReadFailingBacking()
    store = StateStoreWorkspaceStore(state, backing, clock=clock)
    created = await store.write(_write(b"listed without payload I/O"))
    backing.fail_reads = True

    listing = await store.list(ArtifactListRequest(scope=created.scope, created_at=clock()))
    assert listing.artifacts == (created,)
    with pytest.raises(AgentCodecError, match="backing"):
        await store.read(_read(created.artifact_id))


@pytest.mark.asyncio
async def test_expired_artifact_is_absent_from_read_and_list() -> None:
    clock = FakeClock()
    limits = WorkspaceLimits(
        retention=WorkspaceRetentionPolicy(
            artifact_ttl=timedelta(seconds=10),
            tombstone_retention=timedelta(seconds=30),
        )
    )
    store = InMemoryWorkspaceStore(limits=limits, clock=clock)
    created = await store.write(_write(b"short lived"))

    clock.advance(timedelta(seconds=11))
    assert await store.read(_read(created.artifact_id)) is None
    assert (
        await store.list(ArtifactListRequest(scope=created.scope, created_at=clock()))
    ).artifacts == ()


@pytest.mark.asyncio
async def test_deleted_artifact_id_cannot_be_reused_after_tombstone_expiry() -> None:
    clock = FakeClock()
    limits = WorkspaceLimits(
        retention=WorkspaceRetentionPolicy(
            artifact_ttl=timedelta(seconds=10),
            tombstone_retention=timedelta(seconds=20),
        )
    )
    store = InMemoryWorkspaceStore(limits=limits, clock=clock)
    created = await store.write(_write(b"delete me"))
    await store.delete(
        ArtifactDeleteRequest(
            scope=created.scope,
            artifact_id=created.artifact_id,
            expected_version=created.version,
            created_at=clock(),
        )
    )
    clock.advance(timedelta(seconds=21))

    with pytest.raises(AgentStateConflictError):
        await store.write(
            _write(
                b"resurrection",
                artifact_id=created.artifact_id,
                created_at=clock(),
            )
        )


@pytest.mark.asyncio
async def test_bounded_anti_reuse_ledger_fails_closed_at_capacity() -> None:
    clock = FakeClock()
    limits = WorkspaceLimits(
        max_artifacts_per_scope=1,
        max_artifact_id_history_per_scope=2,
        retention=WorkspaceRetentionPolicy(
            artifact_ttl=timedelta(seconds=5),
            tombstone_retention=timedelta(seconds=5),
        ),
    )
    store = InMemoryWorkspaceStore(limits=limits, clock=clock)

    for value in (1, 2):
        created = await store.write(
            _write(
                f"version-{value}".encode(),
                artifact_id=_artifact_id(value),
                logical_path=f"{value}.txt",
                created_at=clock(),
            )
        )
        await store.delete(
            ArtifactDeleteRequest(
                scope=created.scope,
                artifact_id=created.artifact_id,
                expected_version=created.version,
                created_at=clock(),
            )
        )
        clock.advance(timedelta(seconds=6))

    with pytest.raises(AgentLimitExceededError):
        await store.write(
            _write(
                b"third identity",
                artifact_id=_artifact_id(3),
                logical_path="three.txt",
                created_at=clock(),
            )
        )


@pytest.mark.asyncio
async def test_close_and_dependency_unavailable_fail_closed() -> None:
    clock = FakeClock()
    state = MemoryStateStore(clock=clock)
    backing = InMemoryWorkspaceBackingAdapter()
    store = StateStoreWorkspaceStore(state, backing, clock=clock)
    await store.close()

    assert store.closed
    assert not state.closed
    assert not backing.closed
    with pytest.raises(AgentServiceUnavailableError):
        await store.read(_read())

    second = StateStoreWorkspaceStore(state, backing, clock=clock)
    await backing.close()
    with pytest.raises(AgentServiceUnavailableError):
        await second.write(_write(b"unavailable"))


@pytest.mark.asyncio
async def test_failed_authoritative_commit_leaves_no_visible_or_backing_bytes() -> None:
    clock = FakeClock()
    state = _ControlledCommitStateStore(clock=clock)
    backing = _InspectableBacking()
    store = StateStoreWorkspaceStore(state, backing, clock=clock)

    with pytest.raises(AgentCodecError):
        await store.write(_write(b"must never become authoritative"))

    assert backing.keys == ()
    assert await state.list(namespace="agent-workspace") == ()
    state.fail_commits = False
    assert await store.read(_read()) is None


@pytest.mark.asyncio
async def test_cancelled_write_rolls_back_metadata_and_published_backing() -> None:
    clock = FakeClock()
    state = MemoryStateStore(clock=clock)
    backing = _BlockingBacking()
    store = StateStoreWorkspaceStore(state, backing, clock=clock)

    task = asyncio.create_task(store.write(_write(b"cancel before commit")))
    await backing.written.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert backing.keys == ()
    assert await state.list(namespace="agent-workspace") == ()


@pytest.mark.asyncio
async def test_cancellation_after_authoritative_commit_returns_committed_success() -> None:
    clock = FakeClock()
    state = _PostCommitBlockingStateStore(clock=clock)
    backing = _InspectableBacking()
    store = StateStoreWorkspaceStore(state, backing, clock=clock)

    task = asyncio.create_task(store.write(_write(b"committed before cancellation")))
    await state.committed.wait()
    task.cancel()
    created = await task

    assert isinstance(created, ArtifactRecord)
    state.release.set()
    loaded = await store.read(_read(created.artifact_id))
    assert loaded is not None
    assert loaded.record == created
    assert loaded.content == b"committed before cancellation"


@pytest.mark.asyncio
async def test_old_backing_version_never_becomes_authoritative_again() -> None:
    clock = FakeClock()
    state = MemoryStateStore(clock=clock)
    backing = _RetainingBacking()
    store = StateStoreWorkspaceStore(state, backing, clock=clock)
    created = await store.write(_write(b"old bytes"))

    clock.advance(timedelta(seconds=1))
    updated = await store.write(
        _write(
            b"new bytes",
            artifact_id=created.artifact_id,
            expected_version=created.version,
            created_at=clock(),
        )
    )
    assert len(backing.keys) == 2

    loaded = await store.read(_read(created.artifact_id))
    assert loaded is not None
    assert loaded.record == updated
    assert loaded.content == b"new bytes"

    await store.delete(
        ArtifactDeleteRequest(
            scope=created.scope,
            artifact_id=created.artifact_id,
            expected_version=updated.version,
            created_at=clock(),
        )
    )
    assert len(backing.keys) == 2
    assert await store.read(_read(created.artifact_id)) is None
