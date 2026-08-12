from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import pytest

from phoenix_os.agent import (
    AgentMemoryAdministration,
    AgentMemoryRuntimeConfiguration,
    AgentMemoryRuntimeOwner,
    AgentMemoryService,
    AgentServiceUnavailableError,
    ContentFreeMemoryObserver,
    InMemoryDerivedMemoryIndex,
    MemoryDeleteRequest,
    MemoryEmbeddingProvider,
    MemoryLimits,
    MemoryNamespace,
    MemoryOriginKind,
    MemoryProvenance,
    MemoryReadRequest,
    MemoryRecord,
    MemoryRecordVersion,
    MemoryRetrievalCandidate,
    MemoryRuntimeOperation,
    MemoryScope,
    MemoryScopeId,
    MemoryScopeKind,
    MemorySearchRequest,
    MemoryWriteRequest,
    SemanticMemoryRetrievalAdapter,
    StateStoreMemoryStore,
    memory_content_digest,
)
from phoenix_os.events import Event, EventBus
from phoenix_os.policy import PrincipalType, SecurityContext
from phoenix_os.runtime import RuntimeContext
from phoenix_os.state import MemoryStateStore

_NOW = datetime(2026, 8, 12, 5, tzinfo=UTC)


class _Clock:
    def __init__(self) -> None:
        self.now = _NOW

    def __call__(self) -> datetime:
        return self.now


class _EmbeddingProvider:
    provider_id = "test-semantic"
    dimension = 3

    def __init__(self) -> None:
        self.inputs: list[str] = []

    async def embed(self, text: str) -> tuple[float, float, float]:
        self.inputs.append(text)
        folded = text.casefold()
        if "blue" in folded:
            return (1.0, 0.0, 0.0)
        if "red" in folded:
            return (0.0, 1.0, 0.0)
        return (0.0, 0.0, 1.0)


class _HangingEmbeddingProvider:
    provider_id = "hanging-semantic"
    dimension = 3

    async def embed(self, text: str) -> tuple[float, float, float]:
        del text
        await asyncio.Event().wait()
        raise AssertionError("unreachable")


class _HangingScopeStore(StateStoreMemoryStore):
    async def list_scopes(self, *, limit: int) -> tuple[MemoryScope, ...]:
        del limit
        await asyncio.Event().wait()
        raise AssertionError("unreachable")


class _CancellationResistantScopeStore(StateStoreMemoryStore):
    def __init__(self, state_store: MemoryStateStore, *, clock: _Clock) -> None:
        super().__init__(state_store, clock=clock)
        self.calls = 0
        self.entered = asyncio.Event()
        self.release = asyncio.Event()

    async def list_scopes(self, *, limit: int) -> tuple[MemoryScope, ...]:
        del limit
        self.calls += 1
        if self.calls == 1:
            return ()
        self.entered.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            await self.release.wait()
        return ()


class _AllowMemoryAuthorizer:
    def __init__(self) -> None:
        self.admin_calls = 0

    async def authorize_search(
        self,
        request: MemorySearchRequest,
        context: SecurityContext,
    ) -> None:
        assert context.authenticated

    async def authorize_read(
        self,
        request: MemoryReadRequest,
        context: SecurityContext,
    ) -> None:
        assert context.authenticated

    async def authorize_write(
        self,
        request: MemoryWriteRequest,
        context: SecurityContext,
    ) -> None:
        assert context.authenticated

    async def authorize_delete(
        self,
        request: MemoryDeleteRequest,
        context: SecurityContext,
    ) -> None:
        assert context.authenticated

    async def authorize_admin(
        self,
        scope: MemoryScope,
        context: SecurityContext,
        *,
        created_at: datetime | None = None,
    ) -> None:
        assert context.authenticated
        self.admin_calls += 1


def _context() -> SecurityContext:
    return SecurityContext(
        principal="service:assistant",
        principal_type=PrincipalType.SERVICE,
        authenticated=True,
    )


def _scope() -> MemoryScope:
    return MemoryScope(
        namespace=MemoryNamespace("runtime-memory"),
        kind=MemoryScopeKind.AGENT,
        scope_id=MemoryScopeId("assistant"),
    )


def _write(
    content: str,
    *,
    expected_version: MemoryRecordVersion | None = None,
) -> MemoryWriteRequest:
    digest = memory_content_digest(content)
    return MemoryWriteRequest(
        scope=_scope(),
        content=content,
        provenance=MemoryProvenance(
            origin=MemoryOriginKind.USER_INPUT,
            content_digest=digest,
            created_at=_NOW,
        ),
        expected_version=expected_version,
        created_at=_NOW,
    )


def _candidate(record: MemoryRecord) -> MemoryRetrievalCandidate:
    return MemoryRetrievalCandidate(
        scope=record.scope,
        memory_id=record.memory_id,
        version=record.version,
        content_digest=record.content_digest,
        score=0.0,
    )


@pytest.mark.asyncio
async def test_semantic_index_candidate_is_revalidated_after_source_delete() -> None:
    clock = _Clock()
    store = StateStoreMemoryStore(MemoryStateStore(clock=clock), clock=clock)
    record = await store.write(_write("blue invoice"))
    provider = _EmbeddingProvider()
    index = InMemoryDerivedMemoryIndex(dimension=provider.dimension)
    await index.upsert(_candidate(record), await provider.embed(record.content or ""))
    service = AgentMemoryService(
        store=store,
        authorizer=_AllowMemoryAuthorizer(),
        retrieval=SemanticMemoryRetrievalAdapter(provider=provider, index=index),
        clock=clock,
    )

    before = await service.search(
        MemorySearchRequest(scope=_scope(), query="blue", created_at=_NOW),
        _context(),
    )
    assert [hit.memory_id for hit in before.hits] == [record.memory_id]

    await store.delete(
        MemoryDeleteRequest(
            scope=record.scope,
            memory_id=record.memory_id,
            expected_version=record.version,
            created_at=_NOW,
        )
    )
    after = await service.search(
        MemorySearchRequest(scope=_scope(), query="blue", created_at=_NOW),
        _context(),
    )

    assert after.hits == ()
    assert index.entry_count == 1


@pytest.mark.asyncio
async def test_semantic_index_cannot_return_expired_authoritative_record() -> None:
    clock = _Clock()
    limits = MemoryLimits()
    store = StateStoreMemoryStore(
        MemoryStateStore(clock=clock),
        limits=limits,
        clock=clock,
    )
    record = await store.write(_write("blue expiry"))
    provider = _EmbeddingProvider()
    index = InMemoryDerivedMemoryIndex(dimension=provider.dimension)
    await index.upsert(_candidate(record), await provider.embed(record.content or ""))
    service = AgentMemoryService(
        store=store,
        authorizer=_AllowMemoryAuthorizer(),
        retrieval=SemanticMemoryRetrievalAdapter(provider=provider, index=index),
        limits=limits,
        clock=clock,
    )

    clock.now = _NOW + limits.retention.record_ttl + timedelta(seconds=1)
    result = await service.search(
        MemorySearchRequest(
            scope=_scope(),
            query="blue",
            created_at=clock.now,
        ),
        _context(),
    )

    assert result.hits == ()


@pytest.mark.asyncio
async def test_restart_recovery_rebuilds_only_authoritative_active_records() -> None:
    clock = _Clock()
    backing = MemoryStateStore(clock=clock)
    provider = _EmbeddingProvider()
    configuration = AgentMemoryRuntimeConfiguration(
        namespace=MemoryNamespace("runtime-memory"),
        semantic_enabled=True,
        maintenance_interval=timedelta(hours=1),
    )
    observer = ContentFreeMemoryObserver()

    store_one = StateStoreMemoryStore(backing, clock=clock)
    record = await store_one.write(_write("blue survives restart"))
    index_one = InMemoryDerivedMemoryIndex(dimension=provider.dimension)
    owner_one = AgentMemoryRuntimeOwner(
        configuration=configuration,
        store=store_one,
        observer=observer,
        provider=provider,
        index=index_one,
        clock=clock,
    )
    await owner_one.start(RuntimeContext(services={}))
    assert await index_one.count_scope(_scope()) == 1
    await owner_one.close()
    assert not backing.closed

    store_two = StateStoreMemoryStore(backing, clock=clock)
    index_two = InMemoryDerivedMemoryIndex(dimension=provider.dimension)
    owner_two = AgentMemoryRuntimeOwner(
        configuration=configuration,
        store=store_two,
        observer=observer,
        provider=provider,
        index=index_two,
        clock=clock,
    )
    await owner_two.start(RuntimeContext(services={}))
    assert await index_two.count_scope(_scope()) == 1

    await store_two.delete(
        MemoryDeleteRequest(
            scope=record.scope,
            memory_id=record.memory_id,
            expected_version=record.version,
            created_at=clock.now,
        )
    )
    await owner_two.close()

    store_three = StateStoreMemoryStore(backing, clock=clock)
    index_three = InMemoryDerivedMemoryIndex(dimension=provider.dimension)
    owner_three = AgentMemoryRuntimeOwner(
        configuration=configuration,
        store=store_three,
        observer=observer,
        provider=provider,
        index=index_three,
        clock=clock,
    )
    await owner_three.start(RuntimeContext(services={}))
    assert await index_three.count_scope(_scope()) == 0
    await owner_three.close()
    await backing.close()


@pytest.mark.asyncio
async def test_store_lists_scopes_without_exposing_content_in_physical_identity() -> None:
    clock = _Clock()
    store = StateStoreMemoryStore(MemoryStateStore(clock=clock), clock=clock)
    await store.write(_write("blue scope discovery"))

    scopes = await store.list_scopes(limit=4)

    assert scopes == (_scope(),)


@pytest.mark.asyncio
async def test_content_free_observer_and_administration_never_emit_memory_text() -> None:
    clock = _Clock()
    events = EventBus()
    captured: list[Event] = []

    async def capture(event: Event) -> None:
        captured.append(event)

    await events.subscribe("agent.memory.operation", capture)
    store = StateStoreMemoryStore(MemoryStateStore(clock=clock), clock=clock)
    secret = "TOP_SECRET_MEMORY_TEXT blue"
    record = await store.write(_write(secret))
    provider = _EmbeddingProvider()
    index = InMemoryDerivedMemoryIndex(dimension=provider.dimension)
    observer = ContentFreeMemoryObserver(events)
    configuration = AgentMemoryRuntimeConfiguration(
        namespace=MemoryNamespace("runtime-memory"),
        semantic_enabled=True,
        maintenance_interval=timedelta(hours=1),
    )
    owner = AgentMemoryRuntimeOwner(
        configuration=configuration,
        store=store,
        observer=observer,
        provider=provider,
        index=index,
        clock=clock,
    )
    assert await owner.index_record(record)
    assert secret not in repr(index._entries)

    authorizer = _AllowMemoryAuthorizer()
    administration = AgentMemoryAdministration(
        authorizer=authorizer,
        store=store,
        observer=observer,
        index=index,
        clock=clock,
    )
    snapshot = await administration.snapshot(_scope(), _context())

    assert authorizer.admin_calls == 1
    assert snapshot.active_records == 1
    assert snapshot.indexed_records == 1
    assert secret not in repr(snapshot)
    assert secret not in repr(captured)
    assert all("query" not in repr(event.payload).lower() for event in captured)
    assert all("embedding" not in repr(event.payload).lower() for event in captured)
    assert any(
        event.payload.get("operation") == MemoryRuntimeOperation.ADMIN.value for event in captured
    )
    await owner.close()
    await events.close()


def test_semantic_provider_boundary_is_structural_and_bounded() -> None:
    provider = _EmbeddingProvider()
    assert isinstance(provider, MemoryEmbeddingProvider)

    with pytest.raises(ValueError, match="dimension"):
        InMemoryDerivedMemoryIndex(dimension=4_097)


@pytest.mark.asyncio
async def test_semantic_embedding_provider_is_deadline_bounded() -> None:
    provider = _HangingEmbeddingProvider()
    index = InMemoryDerivedMemoryIndex(dimension=provider.dimension)
    adapter = SemanticMemoryRetrievalAdapter(
        provider=provider,
        index=index,
        operation_timeout=timedelta(milliseconds=20),
    )

    with pytest.raises(AgentServiceUnavailableError):
        await adapter.search(
            MemorySearchRequest(
                scope=_scope(),
                query="deadline",
                created_at=_NOW,
            )
        )

    await index.close()


@pytest.mark.asyncio
async def test_runtime_recovery_is_deadline_bounded_and_startup_cleans_up() -> None:
    clock = _Clock()
    store = _HangingScopeStore(MemoryStateStore(clock=clock), clock=clock)
    provider = _EmbeddingProvider()
    index = InMemoryDerivedMemoryIndex(dimension=provider.dimension)
    owner = AgentMemoryRuntimeOwner(
        configuration=AgentMemoryRuntimeConfiguration(
            namespace=MemoryNamespace("runtime-memory"),
            semantic_enabled=True,
            operation_timeout=timedelta(milliseconds=20),
        ),
        store=store,
        observer=ContentFreeMemoryObserver(),
        provider=provider,
        index=index,
        clock=clock,
    )

    with pytest.raises(AgentServiceUnavailableError):
        await owner.start(RuntimeContext(services={}))

    assert owner.closed
    assert store.closed
    assert index.closed


@pytest.mark.asyncio
async def test_runtime_shutdown_does_not_wait_forever_for_maintenance() -> None:
    clock = _Clock()
    store = _CancellationResistantScopeStore(
        MemoryStateStore(clock=clock),
        clock=clock,
    )
    owner = AgentMemoryRuntimeOwner(
        configuration=AgentMemoryRuntimeConfiguration(
            namespace=MemoryNamespace("runtime-memory"),
            maintenance_interval=timedelta(milliseconds=1),
            operation_timeout=timedelta(milliseconds=20),
        ),
        store=store,
        observer=ContentFreeMemoryObserver(),
        clock=clock,
    )

    await owner.start(RuntimeContext(services={}))
    await asyncio.wait_for(store.entered.wait(), timeout=1.0)
    await asyncio.wait_for(owner.close(), timeout=0.25)

    assert owner.closed
    store.release.set()
    await asyncio.sleep(0)


def test_runtime_maintenance_bounds_are_strict() -> None:
    with pytest.raises(ValueError, match="max_scopes_per_cycle"):
        AgentMemoryRuntimeConfiguration(
            namespace=MemoryNamespace("runtime-memory"),
            max_scopes_per_cycle=1_025,
        )

    with pytest.raises(ValueError, match="max_records_per_scope_cycle"):
        AgentMemoryRuntimeConfiguration(
            namespace=MemoryNamespace("runtime-memory"),
            max_records_per_scope_cycle=4_097,
        )

    with pytest.raises(ValueError, match="operation_timeout"):
        AgentMemoryRuntimeConfiguration(
            namespace=MemoryNamespace("runtime-memory"),
            operation_timeout=timedelta(0),
        )
