from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import cast
from uuid import UUID

import pytest

from phoenix_os.agent import (
    AgentCodecError,
    AgentId,
    AgentLimitExceededError,
    AgentServiceUnavailableError,
    AgentWorkspaceRuntimeConfiguration,
    AgentWorkspaceRuntimeOwner,
    ArtifactId,
    ArtifactLogicalPath,
    ArtifactOriginKind,
    ArtifactProvenance,
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
from phoenix_os.state import MemoryStateStore

_NOW = datetime(2026, 8, 13, 22, tzinfo=UTC)
_NAMESPACE = WorkspaceNamespace("cleanup")
_FOREIGN_NAMESPACE = WorkspaceNamespace("foreign")


class _Clock:
    def __init__(self) -> None:
        self.now = _NOW

    def __call__(self) -> datetime:
        return self.now

    def advance(self, delta: timedelta) -> None:
        self.now += delta


def _scope(namespace: WorkspaceNamespace, agent: str) -> WorkspaceScope:
    return agent_workspace_scope(
        namespace=namespace,
        agent_id=AgentId(agent),
    )


def _request(
    *,
    scope: WorkspaceScope,
    artifact_id: ArtifactId,
    content: bytes,
    created_at: datetime,
) -> ArtifactWriteRequest:
    digest = artifact_content_digest(content)
    return ArtifactWriteRequest(
        scope=scope,
        artifact_id=artifact_id,
        logical_path=ArtifactLogicalPath(f"results/{artifact_id.value.hex}.txt"),
        content=content,
        provenance=ArtifactProvenance(
            origin=ArtifactOriginKind.OPERATOR,
            content_digest=digest,
            created_at=created_at,
        ),
        created_at=created_at,
    )


async def _backing_key_for_namespace(
    state: MemoryStateStore,
    namespace: WorkspaceNamespace,
) -> WorkspaceBackingKey:
    records = await state.list(namespace="agent-workspace", prefix="record.")
    for stored in records:
        if not isinstance(stored.value, dict):
            continue
        document = cast(dict[str, object], stored.value)
        if document.get("namespace") != namespace.value:
            continue
        raw = document.get("backing_key")
        if isinstance(raw, str):
            return WorkspaceBackingKey(raw)
    raise AssertionError("backing key not found")


@pytest.mark.asyncio
async def test_cleanup_is_cursor_bounded_and_tombstones_only_target_namespace() -> None:
    clock = _Clock()
    limits = WorkspaceLimits(
        retention=WorkspaceRetentionPolicy(
            artifact_ttl=timedelta(seconds=1),
            tombstone_retention=timedelta(seconds=30),
        )
    )
    state = MemoryStateStore(clock=clock)
    backing = InMemoryWorkspaceBackingAdapter()
    store = StateStoreWorkspaceStore(state, backing, limits=limits, clock=clock)

    target_id = ArtifactId(UUID("b0000000-0000-0000-0000-000000000001"))
    foreign_id = ArtifactId(UUID("b0000000-0000-0000-0000-000000000002"))
    await store.write(
        _request(
            scope=_scope(_NAMESPACE, "target"),
            artifact_id=target_id,
            content=b"target expired bytes",
            created_at=clock.now,
        )
    )
    await store.write(
        _request(
            scope=_scope(_FOREIGN_NAMESPACE, "foreign"),
            artifact_id=foreign_id,
            content=b"foreign expired bytes",
            created_at=clock.now,
        )
    )

    target_backing = await _backing_key_for_namespace(state, _NAMESPACE)
    foreign_backing = await _backing_key_for_namespace(state, _FOREIGN_NAMESPACE)
    assert await backing.exists(target_backing) is True
    assert await backing.exists(foreign_backing) is True

    clock.advance(timedelta(seconds=2))

    cursor: str | None = None
    scanned_total = 0
    cleaned_total = 0
    for _ in range(4):
        cursor, scanned, cleaned = await store.cleanup_expired_batch(
            namespace=_NAMESPACE,
            after=cursor,
            max_records=1,
        )
        scanned_total += scanned
        cleaned_total += cleaned
        if cursor is None:
            break
    else:
        raise AssertionError("cleanup cursor did not terminate")

    assert scanned_total == 2
    assert cleaned_total == 1
    assert await backing.exists(target_backing) is False
    assert await backing.exists(foreign_backing) is True

    target = await store.recover(
        namespace=_NAMESPACE,
        max_scopes=8,
        max_records=32,
    )
    foreign = await store.recover(
        namespace=_FOREIGN_NAMESPACE,
        max_scopes=8,
        max_records=32,
    )
    assert target.records == 1
    assert target.tombstones == 1
    assert target.expired_artifacts == 0
    assert foreign.records == 1
    assert foreign.tombstones == 0
    assert foreign.expired_artifacts == 1


@pytest.mark.asyncio
async def test_cleanup_requires_deterministic_paged_state_capability() -> None:
    class _RecoveryOnlyStateStore(MemoryStateStore):
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

                async def rollback(self) -> None:
                    await inner.rollback()

            return _Transaction()

    clock = _Clock()
    store = StateStoreWorkspaceStore(
        _RecoveryOnlyStateStore(clock=clock),
        InMemoryWorkspaceBackingAdapter(),
        clock=clock,
    )

    with pytest.raises(AgentServiceUnavailableError):
        await store.cleanup_expired_batch(
            namespace=_NAMESPACE,
            after=None,
            max_records=8,
        )


@pytest.mark.asyncio
async def test_runtime_cleanup_cursor_progresses_one_bounded_page_per_cycle() -> None:
    clock = _Clock()
    limits = WorkspaceLimits(
        retention=WorkspaceRetentionPolicy(
            artifact_ttl=timedelta(seconds=1),
            tombstone_retention=timedelta(seconds=30),
        )
    )
    state = MemoryStateStore(clock=clock)
    backing = InMemoryWorkspaceBackingAdapter()
    store = StateStoreWorkspaceStore(state, backing, limits=limits, clock=clock)

    for index in range(2):
        await store.write(
            _request(
                scope=_scope(_NAMESPACE, f"agent-{index}"),
                artifact_id=ArtifactId(UUID(f"b0000000-0000-0000-0000-{index + 10:012d}")),
                content=f"expired-{index}".encode(),
                created_at=clock.now,
            )
        )

    clock.advance(timedelta(seconds=2))
    owner = AgentWorkspaceRuntimeOwner(
        configuration=AgentWorkspaceRuntimeConfiguration(
            namespace=_NAMESPACE,
            limits=limits,
            max_scopes_per_recovery=8,
            max_records_per_recovery=32,
            max_cleanup_records_per_cycle=1,
        ),
        store=store,
    )
    await owner.start(RuntimeContext(services={}))

    cleaned = 0
    for _ in range(4):
        cleaned += await owner.cleanup_once()
        snapshot = await store.recover(
            namespace=_NAMESPACE,
            max_scopes=8,
            max_records=32,
        )
        if snapshot.tombstones == 2:
            break

    assert cleaned == 2
    snapshot = await store.recover(
        namespace=_NAMESPACE,
        max_scopes=8,
        max_records=32,
    )
    assert snapshot.tombstones == 2
    assert snapshot.expired_artifacts == 0


@pytest.mark.asyncio
async def test_runtime_cleanup_timeout_cannot_be_bypassed_by_cancel_suppression() -> None:
    class _SlowMaintenanceStore:
        def __init__(self) -> None:
            self._limits = WorkspaceLimits()
            self._closed = False
            self.cancelled = asyncio.Event()
            self.release = asyncio.Event()

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

        async def cleanup_expired_batch(
            self,
            *,
            namespace: WorkspaceNamespace,
            after: str | None,
            max_records: int,
        ) -> tuple[str | None, int, int]:
            del namespace, after, max_records
            try:
                await asyncio.Future()
            except asyncio.CancelledError:
                self.cancelled.set()
                await self.release.wait()
                return None, 0, 0
            raise AssertionError("unreachable")

        async def close(self) -> None:
            self._closed = True

    store = _SlowMaintenanceStore()
    owner = AgentWorkspaceRuntimeOwner(
        configuration=AgentWorkspaceRuntimeConfiguration(
            namespace=_NAMESPACE,
            limits=store.limits,
            operation_timeout=timedelta(milliseconds=1),
        ),
        store=store,
    )
    await owner.start(RuntimeContext(services={}))

    with pytest.raises(AgentServiceUnavailableError):
        await owner.cleanup_once()

    await asyncio.wait_for(store.cancelled.wait(), timeout=0.2)
    assert owner.running is True
    store.release.set()
    await asyncio.sleep(0)
    await owner.close()


@pytest.mark.asyncio
async def test_runtime_cleanup_rejects_forged_progress_evidence() -> None:
    class _ForgedMaintenanceStore:
        def __init__(self) -> None:
            self._limits = WorkspaceLimits()
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

        async def cleanup_expired_batch(
            self,
            *,
            namespace: WorkspaceNamespace,
            after: str | None,
            max_records: int,
        ) -> tuple[str | None, int, int]:
            del namespace, after
            return None, max_records, max_records + 1

        async def close(self) -> None:
            self._closed = True

    store = _ForgedMaintenanceStore()
    owner = AgentWorkspaceRuntimeOwner(
        configuration=AgentWorkspaceRuntimeConfiguration(
            namespace=_NAMESPACE,
            limits=store.limits,
            max_cleanup_records_per_cycle=8,
        ),
        store=store,
    )
    await owner.start(RuntimeContext(services={}))

    with pytest.raises(AgentCodecError, match="cleanup evidence"):
        await owner.cleanup_once()

    assert owner.running is True
    await owner.close()


def test_runtime_cleanup_configuration_is_strictly_bounded() -> None:
    with pytest.raises(ValueError, match="max_cleanup_records_per_cycle"):
        AgentWorkspaceRuntimeConfiguration(
            namespace=_NAMESPACE,
            max_cleanup_records_per_cycle=0,
        )
    with pytest.raises(ValueError, match="max_cleanup_records_per_cycle"):
        AgentWorkspaceRuntimeConfiguration(
            namespace=_NAMESPACE,
            max_cleanup_records_per_cycle=4_097,
        )


@pytest.mark.asyncio
async def test_runtime_cleanup_rejects_non_advancing_cursor_evidence() -> None:
    class _NonAdvancingMaintenanceStore:
        def __init__(self) -> None:
            self._limits = WorkspaceLimits()
            self._closed = False
            self.calls = 0

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

        async def cleanup_expired_batch(
            self,
            *,
            namespace: WorkspaceNamespace,
            after: str | None,
            max_records: int,
        ) -> tuple[str | None, int, int]:
            del namespace, after
            self.calls += 1
            return "agent-workspace:record.ffffffff", max_records, 0

        async def close(self) -> None:
            self._closed = True

    store = _NonAdvancingMaintenanceStore()
    owner = AgentWorkspaceRuntimeOwner(
        configuration=AgentWorkspaceRuntimeConfiguration(
            namespace=_NAMESPACE,
            limits=store.limits,
            max_cleanup_records_per_cycle=1,
        ),
        store=store,
    )
    await owner.start(RuntimeContext(services={}))

    assert await owner.cleanup_once() == 0
    with pytest.raises(AgentCodecError, match="cleanup evidence"):
        await owner.cleanup_once()

    assert store.calls == 2
    assert owner.running is True
    await owner.close()


@pytest.mark.asyncio
async def test_cleanup_rejects_provider_over_return_before_processing() -> None:
    class _OverReturningStateStore(MemoryStateStore):
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

                async def list_bounded_page(
                    self,
                    *,
                    namespace: str | None = None,
                    prefix: str | None = None,
                    after: str | None = None,
                    limit: int,
                ) -> object:
                    del namespace, prefix, after, limit
                    return (object(), object())

                async def commit(self) -> None:
                    await inner.commit()

                async def rollback(self) -> None:
                    await inner.rollback()

            return _Transaction()

    store = StateStoreWorkspaceStore(
        _OverReturningStateStore(),
        InMemoryWorkspaceBackingAdapter(),
    )

    with pytest.raises(AgentLimitExceededError):
        await store.cleanup_expired_batch(
            namespace=_NAMESPACE,
            after=None,
            max_records=1,
        )


@pytest.mark.asyncio
async def test_runtime_cleanup_timeout_keeps_concurrency_bounded() -> None:
    class _CancellationSuppressingMaintenanceStore:
        def __init__(self) -> None:
            self._limits = WorkspaceLimits()
            self._closed = False
            self.started = 0
            self.cancelled = asyncio.Event()
            self.release = asyncio.Event()

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

        async def cleanup_expired_batch(
            self,
            *,
            namespace: WorkspaceNamespace,
            after: str | None,
            max_records: int,
        ) -> tuple[str | None, int, int]:
            del namespace, after, max_records
            self.started += 1
            try:
                await asyncio.Future()
            except asyncio.CancelledError:
                self.cancelled.set()
                await self.release.wait()
                return None, 0, 0
            raise AssertionError("unreachable")

        async def close(self) -> None:
            self._closed = True

    store = _CancellationSuppressingMaintenanceStore()
    owner = AgentWorkspaceRuntimeOwner(
        configuration=AgentWorkspaceRuntimeConfiguration(
            namespace=_NAMESPACE,
            limits=store.limits,
            operation_timeout=timedelta(milliseconds=1),
        ),
        store=store,
    )
    await owner.start(RuntimeContext(services={}))

    with pytest.raises(AgentServiceUnavailableError):
        await owner.cleanup_once()
    await asyncio.wait_for(store.cancelled.wait(), timeout=0.2)

    with pytest.raises(AgentServiceUnavailableError):
        await owner.cleanup_once()
    assert store.started == 1

    store.release.set()
    await asyncio.sleep(0)
    await owner.close()
