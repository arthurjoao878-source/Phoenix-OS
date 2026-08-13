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
    AgentWorkspaceRuntimeConfiguration,
    AgentWorkspaceRuntimeOwner,
    ArtifactDeleteRequest,
    ArtifactDigest,
    ArtifactId,
    ArtifactLogicalPath,
    ArtifactOriginKind,
    ArtifactProvenance,
    ArtifactReadRequest,
    ArtifactWriteRequest,
    InMemoryWorkspaceBackingAdapter,
    StateStoreWorkspaceStore,
    WorkspaceLimits,
    WorkspaceNamespace,
    WorkspaceRecoverySnapshot,
    WorkspaceRetentionPolicy,
    WorkspaceScope,
    agent_workspace_scope,
    artifact_content_digest,
)
from phoenix_os.agent.workspace_backing import WorkspaceBackingKey
from phoenix_os.runtime import RuntimeContext
from phoenix_os.state import MemoryStateStore, StateKey

_NOW = datetime(2026, 8, 13, 4, tzinfo=UTC)
_NAMESPACE = WorkspaceNamespace("artifacts")


class _Clock:
    def __init__(self) -> None:
        self.value = _NOW

    def __call__(self) -> datetime:
        return self.value

    def advance(self, duration: timedelta) -> None:
        self.value += duration


class _InspectableBacking(InMemoryWorkspaceBackingAdapter):
    @property
    def keys(self) -> tuple[WorkspaceBackingKey, ...]:
        return tuple(self._objects)

    def corrupt(self, key: WorkspaceBackingKey, content: bytes) -> None:
        self._objects[key] = content


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
            raise AgentCodecError("injected secret C:/private https://evil.invalid")
        return await super().read(key, expected_digest=expected_digest)


def _scope(agent: str = "assistant") -> WorkspaceScope:
    return agent_workspace_scope(
        namespace=_NAMESPACE,
        agent_id=AgentId(agent),
    )


def _artifact_id(value: int) -> ArtifactId:
    return ArtifactId(UUID(int=value))


def _write(
    *,
    scope: WorkspaceScope,
    artifact_id: ArtifactId,
    content: bytes,
    path: str,
    created_at: datetime = _NOW,
) -> ArtifactWriteRequest:
    digest = artifact_content_digest(content)
    return ArtifactWriteRequest(
        scope=scope,
        artifact_id=artifact_id,
        logical_path=ArtifactLogicalPath(path),
        content=content,
        provenance=ArtifactProvenance(
            origin=ArtifactOriginKind.USER_INPUT,
            content_digest=digest,
            created_at=created_at,
            source_agent_id=AgentId("assistant"),
        ),
        created_at=created_at,
    )


def _store(
    clock: _Clock,
    *,
    limits: WorkspaceLimits | None = None,
    backing: InMemoryWorkspaceBackingAdapter | None = None,
) -> tuple[StateStoreWorkspaceStore, MemoryStateStore, InMemoryWorkspaceBackingAdapter]:
    state = MemoryStateStore(clock=clock)
    resolved_backing = _InspectableBacking() if backing is None else backing
    resolved_limits = WorkspaceLimits() if limits is None else limits
    return (
        StateStoreWorkspaceStore(
            state,
            resolved_backing,
            limits=resolved_limits,
            clock=clock,
        ),
        state,
        resolved_backing,
    )


async def _replace_record_document(
    state: MemoryStateStore,
    artifact_id: ArtifactId,
    **updates: object,
) -> None:
    stored_records = await state.list(namespace="agent-workspace", prefix="record.")
    selected = None
    for stored in stored_records:
        if isinstance(stored.value, dict) and stored.value.get("artifact_id") == str(artifact_id):
            selected = stored
            break
    assert selected is not None
    assert isinstance(selected.value, dict)
    document = dict(selected.value)
    document.update(updates)
    await state.put(
        StateKey(selected.key.namespace, selected.key.name, dict),
        document,
        expected_version=selected.version,
    )


@pytest.mark.asyncio
async def test_recovery_validates_live_backing_and_returns_content_free_counters() -> None:
    clock = _Clock()
    store, _state, _backing = _store(clock)
    scope = _scope()
    await store.write(
        _write(
            scope=scope,
            artifact_id=_artifact_id(1),
            content=b"first",
            path="notes/first.txt",
        )
    )
    await store.write(
        _write(
            scope=scope,
            artifact_id=_artifact_id(2),
            content=b"second",
            path="notes/second.txt",
        )
    )

    snapshot = await store.recover(
        namespace=_NAMESPACE,
        max_scopes=8,
        max_records=32,
    )

    assert snapshot == WorkspaceRecoverySnapshot(
        namespace=_NAMESPACE,
        scopes=1,
        records=2,
        active_artifacts=2,
        active_bytes=11,
        expired_artifacts=0,
        tombstones=0,
        created_at=_NOW,
    )
    assert not hasattr(snapshot, "content")
    assert not hasattr(snapshot, "logical_path")
    assert not hasattr(snapshot, "metadata")


@pytest.mark.asyncio
async def test_recovery_fails_closed_on_missing_or_digest_mismatched_live_backing() -> None:
    clock = _Clock()
    store, _state, backing = _store(clock)
    assert isinstance(backing, _InspectableBacking)
    await store.write(
        _write(
            scope=_scope(),
            artifact_id=_artifact_id(1),
            content=b"authoritative bytes",
            path="notes/live.txt",
        )
    )
    key = backing.keys[0]
    backing.corrupt(key, b"secret C:/private https://evil.invalid")

    with pytest.raises(AgentCodecError) as failure:
        await store.recover(namespace=_NAMESPACE, max_scopes=8, max_records=32)

    error = str(failure.value)
    assert "secret" not in error
    assert "C:/" not in error
    assert "https://" not in error

    backing._objects.pop(key)
    with pytest.raises(AgentCodecError):
        await store.recover(namespace=_NAMESPACE, max_scopes=8, max_records=32)


@pytest.mark.asyncio
async def test_recovery_rejects_record_without_identity_ledger() -> None:
    clock = _Clock()
    store, state, _backing = _store(clock)
    await store.write(
        _write(
            scope=_scope(),
            artifact_id=_artifact_id(1),
            content=b"data",
            path="notes/data.txt",
        )
    )
    ledgers = await state.list(namespace="agent-workspace", prefix="ledger.")
    assert len(ledgers) == 1
    await state.delete(
        ledgers[0].key,
        expected_version=ledgers[0].version,
    )

    with pytest.raises(AgentCodecError, match="identity ledger"):
        await store.recover(namespace=_NAMESPACE, max_scopes=8, max_records=32)


@pytest.mark.asyncio
async def test_recovery_rejects_scope_substitution_and_aggregate_path_collision() -> None:
    clock = _Clock()
    store, state, _backing = _store(clock)
    scope = _scope()
    first_id = _artifact_id(1)
    second_id = _artifact_id(2)
    await store.write(
        _write(
            scope=scope,
            artifact_id=first_id,
            content=b"first",
            path="notes/first.txt",
        )
    )
    await store.write(
        _write(
            scope=scope,
            artifact_id=second_id,
            content=b"second",
            path="notes/second.txt",
        )
    )

    await _replace_record_document(
        state,
        second_id,
        logical_path="notes/first.txt",
    )
    with pytest.raises(AgentCodecError, match="authoritative metadata"):
        await store.recover(namespace=_NAMESPACE, max_scopes=8, max_records=32)

    await _replace_record_document(
        state,
        second_id,
        logical_path="notes/second.txt",
        scope_id="other-agent",
    )
    with pytest.raises(AgentCodecError, match="authoritative metadata"):
        await store.recover(namespace=_NAMESPACE, max_scopes=8, max_records=32)


@pytest.mark.asyncio
async def test_expired_artifact_is_never_recovered_or_backing_read() -> None:
    clock = _Clock()
    limits = WorkspaceLimits(
        retention=WorkspaceRetentionPolicy(
            artifact_ttl=timedelta(seconds=1),
            tombstone_retention=timedelta(seconds=10),
        )
    )
    backing = _ReadFailingBacking()
    store, _state, _resolved = _store(clock, limits=limits, backing=backing)
    artifact_id = _artifact_id(1)
    await store.write(
        _write(
            scope=_scope(),
            artifact_id=artifact_id,
            content=b"short lived",
            path="notes/expired.txt",
        )
    )

    clock.advance(timedelta(seconds=2))
    backing.fail_reads = True
    snapshot = await store.recover(
        namespace=_NAMESPACE,
        max_scopes=8,
        max_records=32,
    )

    assert snapshot.active_artifacts == 0
    assert snapshot.expired_artifacts == 1
    assert (
        await store.read(
            ArtifactReadRequest(
                scope=_scope(),
                artifact_id=artifact_id,
                created_at=clock(),
            )
        )
        is None
    )


@pytest.mark.asyncio
async def test_tombstone_is_counted_but_never_resurrected() -> None:
    clock = _Clock()
    store, _state, _backing = _store(clock)
    scope = _scope()
    artifact_id = _artifact_id(1)
    record = await store.write(
        _write(
            scope=scope,
            artifact_id=artifact_id,
            content=b"delete me",
            path="notes/deleted.txt",
        )
    )
    await store.delete(
        ArtifactDeleteRequest(
            scope=scope,
            artifact_id=artifact_id,
            expected_version=record.version,
            created_at=clock(),
        )
    )

    snapshot = await store.recover(
        namespace=_NAMESPACE,
        max_scopes=8,
        max_records=32,
    )

    assert snapshot.tombstones == 1
    assert snapshot.active_artifacts == 0
    assert (
        await store.read(
            ArtifactReadRequest(
                scope=scope,
                artifact_id=artifact_id,
                created_at=clock(),
            )
        )
        is None
    )


@pytest.mark.asyncio
async def test_recovery_scope_and_record_limits_fail_closed_without_truncation() -> None:
    clock = _Clock()
    store, _state, _backing = _store(clock)
    for index, agent in enumerate(("a", "b"), start=1):
        await store.write(
            _write(
                scope=_scope(agent),
                artifact_id=_artifact_id(index),
                content=b"x",
                path=f"notes/{agent}.txt",
            )
        )

    with pytest.raises(AgentLimitExceededError):
        await store.recover(namespace=_NAMESPACE, max_scopes=1, max_records=32)
    with pytest.raises(AgentLimitExceededError):
        await store.recover(namespace=_NAMESPACE, max_scopes=8, max_records=1)


@pytest.mark.asyncio
async def test_runtime_owner_recovery_precedes_running_and_closes_on_failure() -> None:
    clock = _Clock()
    limits = WorkspaceLimits()
    backing = _InspectableBacking()
    store, _state, _resolved = _store(clock, limits=limits, backing=backing)
    await store.write(
        _write(
            scope=_scope(),
            artifact_id=_artifact_id(1),
            content=b"live",
            path="notes/live.txt",
        )
    )
    backing.corrupt(backing.keys[0], b"corrupt")

    owner = AgentWorkspaceRuntimeOwner(
        configuration=AgentWorkspaceRuntimeConfiguration(
            namespace=_NAMESPACE,
            limits=limits,
        ),
        store=store,
    )

    with pytest.raises(AgentCodecError):
        await owner.start(RuntimeContext(services={}))

    assert owner.running is False
    assert owner.closed is True
    assert store.closed is True
    assert owner.last_recovery is None


@pytest.mark.asyncio
async def test_runtime_owner_success_is_idempotent_and_stop_closes_store() -> None:
    clock = _Clock()
    limits = WorkspaceLimits()
    store, _state, _backing = _store(clock, limits=limits)
    await store.write(
        _write(
            scope=_scope(),
            artifact_id=_artifact_id(1),
            content=b"live",
            path="notes/live.txt",
        )
    )
    owner = AgentWorkspaceRuntimeOwner(
        configuration=AgentWorkspaceRuntimeConfiguration(
            namespace=_NAMESPACE,
            limits=limits,
            max_scopes_per_recovery=8,
            max_records_per_recovery=32,
        ),
        store=store,
    )
    context = RuntimeContext(services={})

    await owner.start(context)
    first = owner.last_recovery
    await owner.start(context)

    assert owner.running is True
    assert first is not None
    assert owner.last_recovery is first

    await owner.stop(context)
    assert owner.closed is True
    assert owner.running is False
    assert store.closed is True


@pytest.mark.asyncio
async def test_runtime_owner_timeout_is_safe_and_fail_closed() -> None:
    class _SlowStore:
        def __init__(self, limits: WorkspaceLimits) -> None:
            self._limits = limits
            self._closed = False

        @property
        def closed(self) -> bool:
            return self._closed

        @property
        def limits(self) -> WorkspaceLimits:
            return self._limits

        async def recover(
            self,
            *,
            namespace: WorkspaceNamespace,
            max_scopes: int,
            max_records: int,
        ) -> WorkspaceRecoverySnapshot:
            del namespace, max_scopes, max_records
            await asyncio.sleep(3600)
            raise AssertionError("unreachable")

        async def close(self) -> None:
            self._closed = True

    limits = WorkspaceLimits()
    store = _SlowStore(limits)
    owner = AgentWorkspaceRuntimeOwner(
        configuration=AgentWorkspaceRuntimeConfiguration(
            namespace=_NAMESPACE,
            limits=limits,
            operation_timeout=timedelta(milliseconds=1),
        ),
        store=store,
    )

    with pytest.raises(AgentServiceUnavailableError):
        await owner.start(RuntimeContext(services={}))

    assert owner.closed is True
    assert store.closed is True


def test_runtime_configuration_requires_exact_bounded_values_and_matching_limits() -> None:
    limits = WorkspaceLimits()
    with pytest.raises(ValueError, match="operation_timeout"):
        AgentWorkspaceRuntimeConfiguration(
            namespace=_NAMESPACE,
            operation_timeout=timedelta(0),
        )
    with pytest.raises(ValueError, match="max_scopes"):
        AgentWorkspaceRuntimeConfiguration(
            namespace=_NAMESPACE,
            max_scopes_per_recovery=0,
        )
    with pytest.raises(ValueError, match="max_records"):
        AgentWorkspaceRuntimeConfiguration(
            namespace=_NAMESPACE,
            max_records_per_recovery=0,
        )

    store = StateStoreWorkspaceStore(
        MemoryStateStore(),
        InMemoryWorkspaceBackingAdapter(),
        limits=WorkspaceLimits(max_artifact_bytes=8),
    )
    with pytest.raises(ValueError, match="limits must match"):
        AgentWorkspaceRuntimeOwner(
            configuration=AgentWorkspaceRuntimeConfiguration(
                namespace=_NAMESPACE,
                limits=limits,
            ),
            store=store,
        )


@pytest.mark.asyncio
async def test_recovery_propagates_cancellation_even_after_read_transaction_commit() -> None:
    class _CancelAfterCommitStateStore(MemoryStateStore):
        def bounded_read_transaction(self) -> object:  # type: ignore[override]
            inner = super().bounded_read_transaction()

            class _Transaction:
                @property
                def state(self) -> object:
                    return inner.state

                async def __aenter__(self) -> object:
                    await inner.__aenter__()
                    return self

                async def list_bounded(
                    self,
                    *,
                    namespace: str | None = None,
                    prefix: str | None = None,
                    limit: int,
                ) -> object:
                    return await inner.list_bounded(
                        namespace=namespace,
                        prefix=prefix,
                        limit=limit,
                    )

                async def commit(self) -> None:
                    await inner.commit()
                    raise asyncio.CancelledError

                async def rollback(self) -> None:
                    await inner.rollback()

            return _Transaction()

    clock = _Clock()
    state = _CancelAfterCommitStateStore(clock=clock)
    backing = InMemoryWorkspaceBackingAdapter()
    store = StateStoreWorkspaceStore(state, backing, clock=clock)

    with pytest.raises(asyncio.CancelledError):
        await store.recover(
            namespace=_NAMESPACE,
            max_scopes=8,
            max_records=32,
        )


@pytest.mark.asyncio
async def test_runtime_owner_timeout_cannot_be_bypassed_by_cancel_suppression() -> None:
    class _CancellationSuppressingStore:
        def __init__(self, limits: WorkspaceLimits) -> None:
            self._limits = limits
            self._closed = False

        @property
        def closed(self) -> bool:
            return self._closed

        @property
        def limits(self) -> WorkspaceLimits:
            return self._limits

        async def recover(
            self,
            *,
            namespace: WorkspaceNamespace,
            max_scopes: int,
            max_records: int,
        ) -> WorkspaceRecoverySnapshot:
            del max_scopes, max_records
            try:
                await asyncio.Future()
            except asyncio.CancelledError:
                return WorkspaceRecoverySnapshot(
                    namespace=namespace,
                    scopes=0,
                    records=0,
                    active_artifacts=0,
                    active_bytes=0,
                    expired_artifacts=0,
                    tombstones=0,
                    created_at=_NOW,
                )
            raise AssertionError("unreachable")

        async def close(self) -> None:
            self._closed = True

    limits = WorkspaceLimits()
    store = _CancellationSuppressingStore(limits)
    owner = AgentWorkspaceRuntimeOwner(
        configuration=AgentWorkspaceRuntimeConfiguration(
            namespace=_NAMESPACE,
            limits=limits,
            operation_timeout=timedelta(milliseconds=1),
        ),
        store=store,
    )

    with pytest.raises(AgentServiceUnavailableError):
        await owner.start(RuntimeContext(services={}))

    assert owner.running is False
    assert owner.closed is True
    assert store.closed is True


@pytest.mark.asyncio
async def test_runtime_owner_rejects_forged_recovery_evidence_before_admission() -> None:
    class _ForgedStore:
        def __init__(self, limits: WorkspaceLimits) -> None:
            self._limits = limits
            self._closed = False

        @property
        def closed(self) -> bool:
            return self._closed

        @property
        def limits(self) -> WorkspaceLimits:
            return self._limits

        async def recover(
            self,
            *,
            namespace: WorkspaceNamespace,
            max_scopes: int,
            max_records: int,
        ) -> WorkspaceRecoverySnapshot:
            del namespace, max_scopes, max_records
            return WorkspaceRecoverySnapshot(
                namespace=WorkspaceNamespace("forged"),
                scopes=0,
                records=0,
                active_artifacts=0,
                active_bytes=0,
                expired_artifacts=0,
                tombstones=0,
                created_at=_NOW,
            )

        async def close(self) -> None:
            self._closed = True

    limits = WorkspaceLimits()
    store = _ForgedStore(limits)
    owner = AgentWorkspaceRuntimeOwner(
        configuration=AgentWorkspaceRuntimeConfiguration(
            namespace=_NAMESPACE,
            limits=limits,
        ),
        store=store,
    )

    with pytest.raises(AgentCodecError, match="recovery evidence"):
        await owner.start(RuntimeContext(services={}))

    assert owner.running is False
    assert owner.closed is True
    assert store.closed is True
    assert owner.last_recovery is None


@pytest.mark.asyncio
async def test_recovery_requires_bounded_state_enumeration_capability() -> None:
    class _UnboundedStateStore:
        closed = False

        def transaction(self) -> object:
            return object()

    store = StateStoreWorkspaceStore(
        _UnboundedStateStore(),  # type: ignore[arg-type]
        InMemoryWorkspaceBackingAdapter(),
    )

    with pytest.raises(AgentServiceUnavailableError):
        await store.recover(
            namespace=_NAMESPACE,
            max_scopes=8,
            max_records=32,
        )


@pytest.mark.asyncio
async def test_recovery_fails_closed_if_read_commit_raises_after_commit() -> None:
    class _FailAfterCommitStateStore(MemoryStateStore):
        def bounded_read_transaction(self) -> object:  # type: ignore[override]
            inner = super().bounded_read_transaction()

            class _Transaction:
                @property
                def state(self) -> object:
                    return inner.state

                async def __aenter__(self) -> object:
                    await inner.__aenter__()
                    return self

                async def list_bounded(
                    self,
                    *,
                    namespace: str | None = None,
                    prefix: str | None = None,
                    limit: int,
                ) -> object:
                    return await inner.list_bounded(
                        namespace=namespace,
                        prefix=prefix,
                        limit=limit,
                    )

                async def commit(self) -> None:
                    await inner.commit()
                    raise RuntimeError("secret C:/private https://evil.invalid")

                async def rollback(self) -> None:
                    await inner.rollback()

            return _Transaction()

    clock = _Clock()
    state = _FailAfterCommitStateStore(clock=clock)
    store = StateStoreWorkspaceStore(
        state,
        InMemoryWorkspaceBackingAdapter(),
        clock=clock,
    )

    with pytest.raises(AgentServiceUnavailableError) as failure:
        await store.recover(
            namespace=_NAMESPACE,
            max_scopes=8,
            max_records=32,
        )

    error = str(failure.value)
    assert "secret" not in error
    assert "C:/" not in error
    assert "https://" not in error


@pytest.mark.asyncio
async def test_memory_recovery_scan_yields_to_cancellation_and_releases_lock() -> None:
    clock = _Clock()
    state = MemoryStateStore(clock=clock)
    for index in range(256):
        await state.put(
            StateKey("unrelated", f"item.{index}", dict),
            {"index": index},
        )

    store = StateStoreWorkspaceStore(
        state,
        InMemoryWorkspaceBackingAdapter(),
        clock=clock,
    )
    recovery = asyncio.create_task(
        store.recover(
            namespace=_NAMESPACE,
            max_scopes=8,
            max_records=32,
        )
    )
    await asyncio.sleep(0)
    assert recovery.done() is False

    recovery.cancel()
    with pytest.raises(asyncio.CancelledError):
        await recovery

    await asyncio.wait_for(
        state.put(
            StateKey("unrelated", "after-cancel", dict),
            {"ok": True},
        ),
        timeout=1.0,
    )
