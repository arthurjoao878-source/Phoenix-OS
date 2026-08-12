from __future__ import annotations

from datetime import UTC, datetime
from math import inf, nan
from uuid import UUID

import pytest

from phoenix_os.agent import (
    MEMORY_CONTEXT_TRUST_LABEL,
    AgentLimitExceededError,
    AgentMemoryService,
    DeterministicLexicalMemoryRetrievalAdapter,
    InMemoryAgentMemoryStore,
    MemoryContextBlock,
    MemoryDeleteRequest,
    MemoryId,
    MemoryLimits,
    MemoryNamespace,
    MemoryOriginKind,
    MemoryProvenance,
    MemoryReadRequest,
    MemoryRecord,
    MemoryRecordVersion,
    MemoryRetrievalCandidate,
    MemoryScope,
    MemoryScopeId,
    MemoryScopeKind,
    MemorySearchRequest,
    MemoryWriteRequest,
    memory_content_digest,
    memory_context_messages,
)
from phoenix_os.policy import PrincipalType, SecurityContext

_NOW = datetime(2026, 8, 12, 4, tzinfo=UTC)


def _context() -> SecurityContext:
    return SecurityContext(
        principal="service:assistant",
        principal_type=PrincipalType.SERVICE,
        authenticated=True,
    )


def _scope(value: str = "assistant") -> MemoryScope:
    return MemoryScope(
        namespace=MemoryNamespace("memory"),
        kind=MemoryScopeKind.AGENT,
        scope_id=MemoryScopeId(value),
    )


def _memory_id(value: int) -> MemoryId:
    return MemoryId(UUID(int=value))


def _write(
    content: str,
    *,
    scope: MemoryScope | None = None,
    memory_id: MemoryId | None = None,
) -> MemoryWriteRequest:
    digest = memory_content_digest(content)
    return MemoryWriteRequest(
        scope=_scope() if scope is None else scope,
        memory_id=_memory_id(1) if memory_id is None else memory_id,
        content=content,
        provenance=MemoryProvenance(
            origin=MemoryOriginKind.USER_INPUT,
            content_digest=digest,
            created_at=_NOW,
            attributes={"source": "test"},
        ),
        metadata={"kind": "note"},
        created_at=_NOW,
    )


class _AllowMemoryAuthorizer:
    def __init__(self) -> None:
        self.search_calls = 0
        self.read_calls = 0
        self.write_calls = 0
        self.delete_calls = 0

    async def authorize_search(
        self,
        request: MemorySearchRequest,
        context: SecurityContext,
    ) -> None:
        assert context.authenticated
        self.search_calls += 1

    async def authorize_read(
        self,
        request: MemoryReadRequest,
        context: SecurityContext,
    ) -> None:
        assert context.authenticated
        self.read_calls += 1

    async def authorize_write(
        self,
        request: MemoryWriteRequest,
        context: SecurityContext,
    ) -> None:
        assert context.authenticated
        self.write_calls += 1

    async def authorize_delete(
        self,
        request: MemoryDeleteRequest,
        context: SecurityContext,
    ) -> None:
        assert context.authenticated
        self.delete_calls += 1

    async def authorize_admin(
        self,
        scope: MemoryScope,
        context: SecurityContext,
        *,
        created_at: datetime | None = None,
    ) -> None:
        assert context.authenticated


class _StaticAdapter:
    adapter_id = "static-memory-candidates"

    def __init__(self, candidates: tuple[MemoryRetrievalCandidate, ...]) -> None:
        self.candidates = candidates
        self.calls = 0

    async def search(
        self,
        request: MemorySearchRequest,
    ) -> tuple[MemoryRetrievalCandidate, ...]:
        self.calls += 1
        return self.candidates


def _candidate(
    record: MemoryRecord,
    *,
    score: float = 1.0,
    scope: MemoryScope | None = None,
    version: MemoryRecordVersion | None = None,
    digest: str | None = None,
) -> MemoryRetrievalCandidate:
    return MemoryRetrievalCandidate(
        scope=record.scope if scope is None else scope,
        memory_id=record.memory_id,
        version=record.version if version is None else version,
        content_digest=record.content_digest if digest is None else digest,
        score=score,
    )


@pytest.mark.asyncio
async def test_deterministic_lexical_adapter_returns_matching_candidates() -> None:
    store = InMemoryAgentMemoryStore(clock=lambda: _NOW)
    blue = await store.write(_write("blue folder", memory_id=_memory_id(1)))
    await store.write(_write("red folder", memory_id=_memory_id(2)))
    adapter = DeterministicLexicalMemoryRetrievalAdapter(store)

    candidates = await adapter.search(
        MemorySearchRequest(
            scope=_scope(),
            query="blue",
            created_at=_NOW,
        )
    )

    assert [candidate.memory_id for candidate in candidates] == [blue.memory_id]
    assert candidates[0].score > 0


@pytest.mark.asyncio
async def test_service_authorizes_search_once_and_returns_authoritative_hit() -> None:
    store = InMemoryAgentMemoryStore(clock=lambda: _NOW)
    record = await store.write(_write("blue folder"))
    authorizer = _AllowMemoryAuthorizer()
    adapter = _StaticAdapter((_candidate(record, score=3.0),))
    service = AgentMemoryService(
        store=store,
        authorizer=authorizer,
        retrieval=adapter,
        clock=lambda: _NOW,
    )

    result = await service.search(
        MemorySearchRequest(scope=_scope(), query="blue", created_at=_NOW),
        _context(),
    )

    assert authorizer.search_calls == 1
    assert adapter.calls == 1
    assert len(result.hits) == 1
    assert result.hits[0].record == record
    assert result.hits[0].score == 3.0


@pytest.mark.asyncio
async def test_cross_scope_candidate_is_rejected_before_disclosure() -> None:
    store = InMemoryAgentMemoryStore(clock=lambda: _NOW)
    record = await store.write(_write("isolated"))
    foreign = _scope("foreign")
    service = AgentMemoryService(
        store=store,
        authorizer=_AllowMemoryAuthorizer(),
        retrieval=_StaticAdapter((_candidate(record, scope=foreign),)),
        clock=lambda: _NOW,
    )

    result = await service.search(
        MemorySearchRequest(scope=_scope(), query="isolated", created_at=_NOW),
        _context(),
    )

    assert result.hits == ()


@pytest.mark.asyncio
async def test_stale_version_candidate_cannot_resurrect_record() -> None:
    store = InMemoryAgentMemoryStore(clock=lambda: _NOW)
    record = await store.write(_write("versioned"))
    service = AgentMemoryService(
        store=store,
        authorizer=_AllowMemoryAuthorizer(),
        retrieval=_StaticAdapter((_candidate(record, version=record.version.next()),)),
        clock=lambda: _NOW,
    )

    result = await service.search(
        MemorySearchRequest(scope=_scope(), query="versioned", created_at=_NOW),
        _context(),
    )

    assert result.hits == ()


@pytest.mark.asyncio
async def test_wrong_digest_candidate_is_rejected() -> None:
    store = InMemoryAgentMemoryStore(clock=lambda: _NOW)
    record = await store.write(_write("digest"))
    service = AgentMemoryService(
        store=store,
        authorizer=_AllowMemoryAuthorizer(),
        retrieval=_StaticAdapter((_candidate(record, digest="sha256:" + "f" * 64),)),
        clock=lambda: _NOW,
    )

    result = await service.search(
        MemorySearchRequest(scope=_scope(), query="digest", created_at=_NOW),
        _context(),
    )

    assert result.hits == ()


@pytest.mark.asyncio
async def test_deleted_candidate_is_absent_after_authoritative_revalidation() -> None:
    store = InMemoryAgentMemoryStore(clock=lambda: _NOW)
    record = await store.write(_write("deleted"))
    candidate = _candidate(record)
    await store.delete(
        MemoryDeleteRequest(
            scope=record.scope,
            memory_id=record.memory_id,
            expected_version=record.version,
            created_at=_NOW,
        )
    )
    service = AgentMemoryService(
        store=store,
        authorizer=_AllowMemoryAuthorizer(),
        retrieval=_StaticAdapter((candidate,)),
        clock=lambda: _NOW,
    )

    result = await service.search(
        MemorySearchRequest(scope=_scope(), query="deleted", created_at=_NOW),
        _context(),
    )

    assert result.hits == ()


@pytest.mark.asyncio
async def test_equal_scores_use_phoenix_owned_memory_id_tie_break() -> None:
    store = InMemoryAgentMemoryStore(clock=lambda: _NOW)
    first = await store.write(_write("same", memory_id=_memory_id(1)))
    second = await store.write(_write("same", memory_id=_memory_id(2)))
    service = AgentMemoryService(
        store=store,
        authorizer=_AllowMemoryAuthorizer(),
        retrieval=_StaticAdapter(
            (
                _candidate(second, score=5.0),
                _candidate(first, score=5.0),
            )
        ),
        clock=lambda: _NOW,
    )

    result = await service.search(
        MemorySearchRequest(scope=_scope(), query="same", created_at=_NOW),
        _context(),
    )

    assert [hit.memory_id for hit in result.hits] == [_memory_id(1), _memory_id(2)]


@pytest.mark.asyncio
async def test_search_result_count_and_bytes_are_bounded() -> None:
    limits = MemoryLimits(
        max_search_results=1,
        max_context_items=1,
        max_search_result_bytes=4,
        max_context_bytes=4,
        max_record_bytes=4,
        max_total_bytes_per_scope=32,
    )
    store = InMemoryAgentMemoryStore(limits=limits, clock=lambda: _NOW)
    first = await store.write(_write("1234", memory_id=_memory_id(1)))
    second = await store.write(_write("5678", memory_id=_memory_id(2)))
    service = AgentMemoryService(
        store=store,
        authorizer=_AllowMemoryAuthorizer(),
        retrieval=_StaticAdapter((_candidate(first), _candidate(second))),
        limits=limits,
        clock=lambda: _NOW,
    )

    with pytest.raises(AgentLimitExceededError):
        await service.search(
            MemorySearchRequest(
                scope=_scope(),
                query="1",
                max_results=2,
                max_bytes=4,
                created_at=_NOW,
            ),
            _context(),
        )


@pytest.mark.parametrize("score", (nan, inf, -inf, 1_000_001.0))
def test_candidate_scores_must_be_finite_and_bounded(score: float) -> None:
    with pytest.raises(ValueError, match="ranking score"):
        MemoryRetrievalCandidate(
            scope=_scope(),
            memory_id=_memory_id(1),
            version=MemoryRecordVersion(),
            content_digest="sha256:" + "a" * 64,
            score=score,
        )


@pytest.mark.asyncio
async def test_context_block_preserves_provenance_and_renders_user_data() -> None:
    store = InMemoryAgentMemoryStore(clock=lambda: _NOW)
    record = await store.write(_write("remember blue"))
    service = AgentMemoryService(
        store=store,
        authorizer=_AllowMemoryAuthorizer(),
        retrieval=_StaticAdapter((_candidate(record),)),
        clock=lambda: _NOW,
    )
    result = await service.search(
        MemorySearchRequest(scope=_scope(), query="blue", created_at=_NOW),
        _context(),
    )

    block = service.assemble_context(result)

    assert isinstance(block, MemoryContextBlock)
    assert block.trust_label == MEMORY_CONTEXT_TRUST_LABEL
    assert block.hits[0].record.provenance == record.provenance
    messages = memory_context_messages(block)
    assert len(messages) == 1
    assert messages[0].role.value == "user"
    assert messages[0].metadata["trust"] == MEMORY_CONTEXT_TRUST_LABEL
    assert "UNTRUSTED_RETRIEVED_MEMORY" in messages[0].content
    assert "remember blue" in messages[0].content


@pytest.mark.asyncio
async def test_service_direct_operations_use_independent_authorization() -> None:
    store = InMemoryAgentMemoryStore(clock=lambda: _NOW)
    authorizer = _AllowMemoryAuthorizer()
    adapter = DeterministicLexicalMemoryRetrievalAdapter(store)
    service = AgentMemoryService(
        store=store,
        authorizer=authorizer,
        retrieval=adapter,
        clock=lambda: _NOW,
    )
    write = _write("direct")
    created = await service.write(write, _context())
    loaded = await service.read(
        MemoryReadRequest(
            scope=created.scope,
            memory_id=created.memory_id,
            created_at=_NOW,
        ),
        _context(),
    )
    await service.delete(
        MemoryDeleteRequest(
            scope=created.scope,
            memory_id=created.memory_id,
            expected_version=created.version,
            created_at=_NOW,
        ),
        _context(),
    )

    assert loaded == created
    assert authorizer.write_calls == 1
    assert authorizer.read_calls == 1
    assert authorizer.delete_calls == 1
