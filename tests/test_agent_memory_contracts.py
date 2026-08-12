from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta
from types import MappingProxyType
from uuid import UUID

import pytest

from phoenix_os.agent import (
    MAX_MEMORY_CONTEXT_ITEMS,
    MAX_MEMORY_NAMESPACE_LENGTH,
    MAX_MEMORY_QUERY_BYTES,
    MAX_MEMORY_RECORD_BYTES,
    MAX_MEMORY_RECORDS_PER_SCOPE,
    MAX_MEMORY_RETENTION,
    MAX_MEMORY_SCOPE_TOTAL_BYTES,
    MAX_MEMORY_SEARCH_RESULTS,
    MAX_MEMORY_TOMBSTONE_RETENTION,
    AgentId,
    AgentRunId,
    MemoryDeleteRequest,
    MemoryId,
    MemoryLimits,
    MemoryNamespace,
    MemoryOriginKind,
    MemoryProvenance,
    MemoryReadRequest,
    MemoryRecordStatus,
    MemoryRecordVersion,
    MemoryRetentionPolicy,
    MemoryScope,
    MemoryScopeId,
    MemoryScopeKind,
    MemorySearchRequest,
    MemoryWriteRequest,
    memory_content_digest,
)

_NOW = datetime(2026, 8, 11, 23, tzinfo=UTC)
_MEMORY_ID = MemoryId(UUID("10000000-0000-0000-0000-000000000030"))


def _scope() -> MemoryScope:
    return MemoryScope(
        namespace=MemoryNamespace("Default"),
        kind=MemoryScopeKind.AGENT,
        scope_id=MemoryScopeId("Researcher"),
    )


def _provenance(content: str = "remember this") -> MemoryProvenance:
    return MemoryProvenance(
        origin=MemoryOriginKind.AGENT_REQUEST,
        content_digest=memory_content_digest(content),
        created_at=_NOW,
        source_run_id=AgentRunId(UUID("20000000-0000-0000-0000-000000000030")),
        source_agent_id=AgentId("researcher"),
        attributes={"channel": "explicit"},
    )


def test_memory_identifiers_and_scope_are_immutable_and_normalized() -> None:
    namespace = MemoryNamespace(" Default ")
    scope_id = MemoryScopeId(" Researcher ")
    scope = MemoryScope(namespace, MemoryScopeKind.AGENT, scope_id)

    assert str(namespace) == "default"
    assert str(scope_id) == "researcher"
    assert scope.kind is MemoryScopeKind.AGENT
    assert str(_MEMORY_ID) == "10000000-0000-0000-0000-000000000030"
    with pytest.raises(FrozenInstanceError):
        scope.scope_id = MemoryScopeId("other")  # type: ignore[misc]


@pytest.mark.parametrize(
    "value",
    (
        "",
        "bad/name",
        "bad:scope",
        "x" * (MAX_MEMORY_NAMESPACE_LENGTH + 1),
    ),
)
def test_memory_namespace_rejects_unsafe_values(value: str) -> None:
    with pytest.raises(ValueError):
        MemoryNamespace(value)


@pytest.mark.parametrize("value", ("", "bad/scope", "bad:scope", "contains space"))
def test_memory_scope_id_rejects_resource_injection(value: str) -> None:
    with pytest.raises(ValueError):
        MemoryScopeId(value)


def test_memory_scope_kinds_and_statuses_are_finite() -> None:
    assert tuple(item.value for item in MemoryScopeKind) == ("run", "agent", "principal")
    assert tuple(item.value for item in MemoryRecordStatus) == ("active", "tombstoned")


def test_record_version_is_positive_monotonic_and_bounded() -> None:
    version = MemoryRecordVersion()
    assert version.value == 1
    assert version.next() == MemoryRecordVersion(2)

    with pytest.raises(ValueError):
        MemoryRecordVersion(0)
    with pytest.raises(TypeError):
        MemoryRecordVersion(True)


def test_retention_policy_is_explicit_and_finite() -> None:
    policy = MemoryRetentionPolicy(
        record_ttl=timedelta(days=7),
        tombstone_retention=timedelta(days=30),
    )
    assert policy.record_ttl == timedelta(days=7)
    assert policy.tombstone_retention == timedelta(days=30)

    with pytest.raises(ValueError):
        MemoryRetentionPolicy(record_ttl=timedelta(0))
    with pytest.raises(ValueError):
        MemoryRetentionPolicy(record_ttl=MAX_MEMORY_RETENTION + timedelta(seconds=1))
    with pytest.raises(ValueError):
        MemoryRetentionPolicy(
            tombstone_retention=MAX_MEMORY_TOMBSTONE_RETENTION + timedelta(seconds=1)
        )


def test_memory_limits_are_finite_and_relationally_safe() -> None:
    limits = MemoryLimits()
    assert limits.max_record_bytes <= MAX_MEMORY_RECORD_BYTES
    assert limits.max_records_per_scope <= MAX_MEMORY_RECORDS_PER_SCOPE
    assert limits.max_total_bytes_per_scope <= MAX_MEMORY_SCOPE_TOTAL_BYTES
    assert limits.max_query_bytes <= MAX_MEMORY_QUERY_BYTES
    assert limits.max_search_results <= MAX_MEMORY_SEARCH_RESULTS
    assert limits.max_context_items <= MAX_MEMORY_CONTEXT_ITEMS

    with pytest.raises(ValueError):
        MemoryLimits(max_record_bytes=1024, max_total_bytes_per_scope=512)
    with pytest.raises(ValueError):
        MemoryLimits(max_search_results=4, max_context_items=5)


def test_provenance_is_bounded_content_free_origin_metadata() -> None:
    provenance = _provenance()

    assert provenance.origin is MemoryOriginKind.AGENT_REQUEST
    assert provenance.content_digest.startswith("sha256:")
    assert provenance.source_agent_id == AgentId("researcher")
    assert provenance.attributes == {"channel": "explicit"}
    assert isinstance(provenance.attributes, MappingProxyType)

    with pytest.raises(ValueError):
        MemoryProvenance(
            origin=MemoryOriginKind.AGENT_REQUEST,
            content_digest="not-a-digest",
            created_at=_NOW,
        )


def test_memory_write_is_explicit_preserves_content_and_freezes_metadata() -> None:
    content = "  remember exact whitespace  "
    request = MemoryWriteRequest(
        scope=_scope(),
        memory_id=_MEMORY_ID,
        content=content,
        provenance=_provenance(content),
        metadata={"kind": "note"},
        created_at=_NOW,
    )

    assert request.content == content
    assert request.metadata == {"kind": "note"}
    assert isinstance(request.metadata, MappingProxyType)
    assert request.expected_version is None

    with pytest.raises(ValueError):
        MemoryWriteRequest(
            scope=_scope(),
            memory_id=_MEMORY_ID,
            content="different",
            provenance=_provenance("original"),
            created_at=_NOW,
        )


def test_memory_write_rejects_blank_or_oversized_content() -> None:
    with pytest.raises(ValueError):
        MemoryWriteRequest(
            scope=_scope(),
            memory_id=_MEMORY_ID,
            content="   ",
            provenance=_provenance("x"),
            created_at=_NOW,
        )

    oversized = "x" * (MAX_MEMORY_RECORD_BYTES + 1)
    with pytest.raises(ValueError):
        memory_content_digest(oversized)


def test_direct_read_and_delete_bind_exact_record_and_version() -> None:
    scope = _scope()
    read = MemoryReadRequest(scope=scope, memory_id=_MEMORY_ID, created_at=_NOW)
    delete = MemoryDeleteRequest(
        scope=scope,
        memory_id=_MEMORY_ID,
        expected_version=MemoryRecordVersion(7),
        created_at=_NOW,
    )

    assert read.memory_id == _MEMORY_ID
    assert delete.memory_id == _MEMORY_ID
    assert delete.expected_version == MemoryRecordVersion(7)


def test_search_request_is_trimmed_and_globally_bounded() -> None:
    request = MemorySearchRequest(
        scope=_scope(),
        query="  project phoenix  ",
        max_results=8,
        max_bytes=4096,
        created_at=_NOW,
    )
    assert request.query == "project phoenix"
    assert request.max_results == 8
    assert request.max_bytes == 4096

    with pytest.raises(ValueError):
        MemorySearchRequest(
            scope=_scope(),
            query="x" * (MAX_MEMORY_QUERY_BYTES + 1),
            created_at=_NOW,
        )
    with pytest.raises(ValueError):
        MemorySearchRequest(
            scope=_scope(),
            query="query",
            max_results=MAX_MEMORY_SEARCH_RESULTS + 1,
            created_at=_NOW,
        )


def test_request_timestamps_must_be_timezone_aware() -> None:
    naive = datetime(2026, 8, 11, 23)

    with pytest.raises(ValueError):
        MemoryReadRequest(scope=_scope(), memory_id=_MEMORY_ID, created_at=naive)
