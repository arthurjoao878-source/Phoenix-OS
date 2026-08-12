"""Immutable bounded contracts for secure Phoenix agent memory."""

from __future__ import annotations

import hashlib
import math
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from types import MappingProxyType
from uuid import UUID, uuid4

from phoenix_os.agent.contracts import AgentId, AgentRunId

MAX_MEMORY_NAMESPACE_LENGTH = 128
MAX_MEMORY_SCOPE_ID_LENGTH = 192
MAX_MEMORY_RECORD_BYTES = 1_048_576
MAX_MEMORY_METADATA_ITEMS = 64
MAX_MEMORY_METADATA_KEY_LENGTH = 128
MAX_MEMORY_METADATA_VALUE_LENGTH = 1_024
MAX_MEMORY_PROVENANCE_ITEMS = 32
MAX_MEMORY_SOURCE_VERSION_LENGTH = 128
MAX_MEMORY_RECORDS_PER_SCOPE = 100_000
MAX_MEMORY_SCOPE_TOTAL_BYTES = 1_073_741_824
MAX_MEMORY_QUERY_BYTES = 65_536
MAX_MEMORY_SEARCH_RESULTS = 256
MAX_MEMORY_SEARCH_RESULT_BYTES = 4_194_304
MAX_MEMORY_CONTEXT_ITEMS = 128
MAX_MEMORY_CONTEXT_BYTES = 4_194_304
MAX_MEMORY_RETENTION = timedelta(days=3650)
MAX_MEMORY_TOMBSTONE_RETENTION = timedelta(days=3650)
MAX_MEMORY_RANKING_SCORE = 1_000_000.0
MEMORY_CONTEXT_TRUST_LABEL = "untrusted_retrieved_memory"

_MEMORY_NAMESPACE_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,127})$")
_MEMORY_SCOPE_ID_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,191})$")
_MEMORY_DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")


def _positive_int(value: int, *, label: str, maximum: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{label} must be an integer")
    if value <= 0:
        raise ValueError(f"{label} must be greater than zero")
    if value > maximum:
        raise ValueError(f"{label} exceeds the global maximum")


def _memory_ranking_score(value: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError("memory ranking score must be numeric")
    normalized = float(value)
    if not math.isfinite(normalized):
        raise ValueError("memory ranking score must be finite")
    if abs(normalized) > MAX_MEMORY_RANKING_SCORE:
        raise ValueError("memory ranking score exceeds the maximum")
    return normalized


def _positive_duration(value: timedelta, *, label: str, maximum: timedelta) -> None:
    if not isinstance(value, timedelta):
        raise TypeError(f"{label} must be a timedelta")
    if value <= timedelta(0):
        raise ValueError(f"{label} must be greater than zero")
    if value > maximum:
        raise ValueError(f"{label} exceeds the global maximum")


def _aware(value: datetime, *, label: str) -> None:
    if not isinstance(value, datetime):
        raise TypeError(f"{label} must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")


def _bounded_text(
    value: str,
    *,
    label: str,
    maximum_chars: int,
    allow_blank: bool = False,
) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{label} must be a string")
    normalized = value if allow_blank else value.strip()
    if not allow_blank and not normalized:
        raise ValueError(f"{label} must not be blank")
    if len(normalized) > maximum_chars:
        raise ValueError(f"{label} exceeds the maximum length")
    return normalized


def _bounded_utf8_text(
    value: str,
    *,
    label: str,
    maximum_bytes: int,
    allow_blank: bool = False,
) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{label} must be a string")
    normalized = value
    if not allow_blank and not normalized.strip():
        raise ValueError(f"{label} must not be blank")
    if len(normalized.encode("utf-8")) > maximum_bytes:
        raise ValueError(f"{label} exceeds the maximum byte size")
    return normalized


def _freeze_text_mapping(
    value: Mapping[str, str],
    *,
    label: str,
    maximum_items: int,
) -> Mapping[str, str]:
    if not isinstance(value, Mapping):
        raise TypeError(f"{label} must be a mapping")
    if len(value) > maximum_items:
        raise ValueError(f"{label} exceeds the maximum item count")
    frozen: dict[str, str] = {}
    for key, item in value.items():
        normalized_key = _bounded_text(
            key,
            label=f"{label} key",
            maximum_chars=MAX_MEMORY_METADATA_KEY_LENGTH,
        )
        normalized_value = _bounded_text(
            item,
            label=f"{label} value",
            maximum_chars=MAX_MEMORY_METADATA_VALUE_LENGTH,
            allow_blank=True,
        )
        if normalized_key in frozen:
            raise ValueError(f"{label} contains duplicate normalized keys")
        frozen[normalized_key] = normalized_value
    return MappingProxyType(frozen)


def memory_content_digest(content: str) -> str:
    """Return a content-free digest for one globally bounded memory value."""

    normalized = _bounded_utf8_text(
        content,
        label="memory content",
        maximum_bytes=MAX_MEMORY_RECORD_BYTES,
    )
    return "sha256:" + hashlib.sha256(normalized.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True, order=True)
class MemoryNamespace:
    """Stable server-owned namespace for one memory policy domain."""

    value: str

    def __post_init__(self) -> None:
        if not isinstance(self.value, str):
            raise TypeError("memory namespace must be a string")
        normalized = self.value.strip().lower()
        if _MEMORY_NAMESPACE_PATTERN.fullmatch(normalized) is None:
            raise ValueError("memory namespace is invalid")
        object.__setattr__(self, "value", normalized)

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True, order=True)
class MemoryScopeId:
    """Stable content-free identity inside one Phoenix-owned scope kind."""

    value: str

    def __post_init__(self) -> None:
        if not isinstance(self.value, str):
            raise TypeError("memory scope id must be a string")
        normalized = self.value.strip().lower()
        if _MEMORY_SCOPE_ID_PATTERN.fullmatch(normalized) is None:
            raise ValueError("memory scope id is invalid")
        object.__setattr__(self, "value", normalized)

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True, order=True)
class MemoryId:
    """Stable Phoenix-owned identity for one logical memory record."""

    value: UUID = field(default_factory=uuid4)

    def __post_init__(self) -> None:
        if not isinstance(self.value, UUID):
            raise TypeError("memory id must be UUID")

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True, order=True)
class MemoryRecordVersion:
    """Positive optimistic-concurrency version for one logical memory record."""

    value: int = 1

    def __post_init__(self) -> None:
        _positive_int(self.value, label="memory record version", maximum=2**63 - 1)

    def __int__(self) -> int:
        return self.value

    def next(self) -> MemoryRecordVersion:
        return MemoryRecordVersion(self.value + 1)


class MemoryScopeKind(StrEnum):
    RUN = "run"
    AGENT = "agent"
    PRINCIPAL = "principal"


class MemoryRecordStatus(StrEnum):
    ACTIVE = "active"
    TOMBSTONED = "tombstoned"


class MemoryOriginKind(StrEnum):
    USER_INPUT = "user_input"
    AGENT_REQUEST = "agent_request"
    TOOL_RESULT = "tool_result"
    DELEGATED_RESULT = "delegated_result"
    OPERATOR = "operator"
    IMPORT = "import"
    SYSTEM = "system"


@dataclass(frozen=True, slots=True, order=True)
class MemoryScope:
    """Exact Phoenix-owned visibility boundary for one memory operation."""

    namespace: MemoryNamespace
    kind: MemoryScopeKind
    scope_id: MemoryScopeId

    def __post_init__(self) -> None:
        if not isinstance(self.namespace, MemoryNamespace):
            raise TypeError("namespace must be MemoryNamespace")
        if not isinstance(self.kind, MemoryScopeKind):
            raise TypeError("kind must be MemoryScopeKind")
        if not isinstance(self.scope_id, MemoryScopeId):
            raise TypeError("scope_id must be MemoryScopeId")


@dataclass(frozen=True, slots=True)
class MemoryProvenance:
    """Bounded immutable origin facts; provenance never grants authority."""

    origin: MemoryOriginKind
    content_digest: str
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    source_version: str | None = None
    source_run_id: AgentRunId | None = None
    source_agent_id: AgentId | None = None
    source_principal_id: MemoryScopeId | None = None
    attributes: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.origin, MemoryOriginKind):
            raise TypeError("origin must be MemoryOriginKind")
        if not isinstance(self.content_digest, str):
            raise TypeError("content_digest must be a string")
        if _MEMORY_DIGEST_PATTERN.fullmatch(self.content_digest) is None:
            raise ValueError("content_digest must be a canonical sha256 digest")
        _aware(self.created_at, label="created_at")
        if self.source_version is not None:
            object.__setattr__(
                self,
                "source_version",
                _bounded_text(
                    self.source_version,
                    label="source_version",
                    maximum_chars=MAX_MEMORY_SOURCE_VERSION_LENGTH,
                ),
            )
        if self.source_run_id is not None and not isinstance(self.source_run_id, AgentRunId):
            raise TypeError("source_run_id must be AgentRunId")
        if self.source_agent_id is not None and not isinstance(self.source_agent_id, AgentId):
            raise TypeError("source_agent_id must be AgentId")
        if self.source_principal_id is not None and not isinstance(
            self.source_principal_id, MemoryScopeId
        ):
            raise TypeError("source_principal_id must be MemoryScopeId")
        object.__setattr__(
            self,
            "attributes",
            _freeze_text_mapping(
                self.attributes,
                label="provenance attributes",
                maximum_items=MAX_MEMORY_PROVENANCE_ITEMS,
            ),
        )


@dataclass(frozen=True, slots=True)
class MemoryRetentionPolicy:
    """Finite TTL and tombstone-retention policy for one memory domain."""

    record_ttl: timedelta = timedelta(days=30)
    tombstone_retention: timedelta = timedelta(days=90)

    def __post_init__(self) -> None:
        _positive_duration(
            self.record_ttl,
            label="record_ttl",
            maximum=MAX_MEMORY_RETENTION,
        )
        _positive_duration(
            self.tombstone_retention,
            label="tombstone_retention",
            maximum=MAX_MEMORY_TOMBSTONE_RETENTION,
        )


@dataclass(frozen=True, slots=True)
class MemoryLimits:
    """Finite limits for one configured memory namespace/scope."""

    max_record_bytes: int = 65_536
    max_records_per_scope: int = 10_000
    max_total_bytes_per_scope: int = 67_108_864
    max_query_bytes: int = 16_384
    max_search_results: int = 32
    max_search_result_bytes: int = 1_048_576
    max_context_items: int = 32
    max_context_bytes: int = 1_048_576
    retention: MemoryRetentionPolicy = field(default_factory=MemoryRetentionPolicy)

    def __post_init__(self) -> None:
        limits = (
            ("max_record_bytes", self.max_record_bytes, MAX_MEMORY_RECORD_BYTES),
            (
                "max_records_per_scope",
                self.max_records_per_scope,
                MAX_MEMORY_RECORDS_PER_SCOPE,
            ),
            (
                "max_total_bytes_per_scope",
                self.max_total_bytes_per_scope,
                MAX_MEMORY_SCOPE_TOTAL_BYTES,
            ),
            ("max_query_bytes", self.max_query_bytes, MAX_MEMORY_QUERY_BYTES),
            ("max_search_results", self.max_search_results, MAX_MEMORY_SEARCH_RESULTS),
            (
                "max_search_result_bytes",
                self.max_search_result_bytes,
                MAX_MEMORY_SEARCH_RESULT_BYTES,
            ),
            ("max_context_items", self.max_context_items, MAX_MEMORY_CONTEXT_ITEMS),
            ("max_context_bytes", self.max_context_bytes, MAX_MEMORY_CONTEXT_BYTES),
        )
        for label, value, maximum in limits:
            _positive_int(value, label=label, maximum=maximum)
        if not isinstance(self.retention, MemoryRetentionPolicy):
            raise TypeError("retention must be MemoryRetentionPolicy")
        if self.max_record_bytes > self.max_total_bytes_per_scope:
            raise ValueError("max_record_bytes cannot exceed max_total_bytes_per_scope")
        if self.max_context_items > self.max_search_results:
            raise ValueError("max_context_items cannot exceed max_search_results")


@dataclass(frozen=True, slots=True)
class MemoryRecord:
    """Authoritative immutable version of one logical memory record or tombstone."""

    scope: MemoryScope
    memory_id: MemoryId
    version: MemoryRecordVersion
    status: MemoryRecordStatus
    content_digest: str
    created_at: datetime
    updated_at: datetime
    expires_at: datetime
    content: str | None = None
    provenance: MemoryProvenance | None = None
    metadata: Mapping[str, str] = field(default_factory=dict)
    deleted_at: datetime | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.scope, MemoryScope):
            raise TypeError("scope must be MemoryScope")
        if not isinstance(self.memory_id, MemoryId):
            raise TypeError("memory_id must be MemoryId")
        if not isinstance(self.version, MemoryRecordVersion):
            raise TypeError("version must be MemoryRecordVersion")
        if not isinstance(self.status, MemoryRecordStatus):
            raise TypeError("status must be MemoryRecordStatus")
        if not isinstance(self.content_digest, str):
            raise TypeError("content_digest must be a string")
        if _MEMORY_DIGEST_PATTERN.fullmatch(self.content_digest) is None:
            raise ValueError("content_digest must be a canonical sha256 digest")

        _aware(self.created_at, label="created_at")
        _aware(self.updated_at, label="updated_at")
        _aware(self.expires_at, label="expires_at")
        if self.updated_at < self.created_at:
            raise ValueError("updated_at cannot precede created_at")
        if self.expires_at <= self.updated_at:
            raise ValueError("expires_at must follow updated_at")

        frozen_metadata = _freeze_text_mapping(
            self.metadata,
            label="memory metadata",
            maximum_items=MAX_MEMORY_METADATA_ITEMS,
        )
        object.__setattr__(self, "metadata", frozen_metadata)

        if self.status is MemoryRecordStatus.ACTIVE:
            if self.content is None:
                raise ValueError("active memory record requires content")
            content = _bounded_utf8_text(
                self.content,
                label="memory content",
                maximum_bytes=MAX_MEMORY_RECORD_BYTES,
            )
            object.__setattr__(self, "content", content)
            if memory_content_digest(content) != self.content_digest:
                raise ValueError("content_digest does not match memory content")
            if not isinstance(self.provenance, MemoryProvenance):
                raise TypeError("active memory record requires MemoryProvenance")
            if self.provenance.content_digest != self.content_digest:
                raise ValueError("provenance content digest does not match memory content")
            if self.deleted_at is not None:
                raise ValueError("active memory record cannot have deleted_at")
            return

        if self.content is not None:
            raise ValueError("tombstoned memory record cannot retain content")
        if self.provenance is not None:
            raise ValueError("tombstoned memory record cannot retain provenance")
        if self.metadata:
            raise ValueError("tombstoned memory record cannot retain metadata")
        if self.deleted_at is None:
            raise ValueError("tombstoned memory record requires deleted_at")
        _aware(self.deleted_at, label="deleted_at")
        if self.deleted_at != self.updated_at:
            raise ValueError("tombstone deleted_at must equal updated_at")
        if self.expires_at <= self.deleted_at:
            raise ValueError("tombstone expiry must follow deletion")

    @property
    def content_bytes(self) -> int:
        """Return persisted content bytes without exposing content."""

        return 0 if self.content is None else len(self.content.encode("utf-8"))

    def expired(self, *, now: datetime) -> bool:
        """Return whether this version is outside its authoritative retention window."""

        _aware(now, label="now")
        return now >= self.expires_at


@dataclass(frozen=True, slots=True)
class MemoryWriteRequest:
    """One explicit bounded write proposal against an exact memory record."""

    scope: MemoryScope
    content: str
    provenance: MemoryProvenance
    memory_id: MemoryId = field(default_factory=MemoryId)
    metadata: Mapping[str, str] = field(default_factory=dict)
    expected_version: MemoryRecordVersion | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        if not isinstance(self.scope, MemoryScope):
            raise TypeError("scope must be MemoryScope")
        if not isinstance(self.memory_id, MemoryId):
            raise TypeError("memory_id must be MemoryId")
        content = _bounded_utf8_text(
            self.content,
            label="memory content",
            maximum_bytes=MAX_MEMORY_RECORD_BYTES,
        )
        object.__setattr__(self, "content", content)
        if not isinstance(self.provenance, MemoryProvenance):
            raise TypeError("provenance must be MemoryProvenance")
        if self.provenance.content_digest != memory_content_digest(content):
            raise ValueError("provenance content digest does not match memory content")
        if self.expected_version is not None and not isinstance(
            self.expected_version, MemoryRecordVersion
        ):
            raise TypeError("expected_version must be MemoryRecordVersion")
        _aware(self.created_at, label="created_at")
        object.__setattr__(
            self,
            "metadata",
            _freeze_text_mapping(
                self.metadata,
                label="memory metadata",
                maximum_items=MAX_MEMORY_METADATA_ITEMS,
            ),
        )


@dataclass(frozen=True, slots=True)
class MemoryReadRequest:
    """One exact direct memory-record read request."""

    scope: MemoryScope
    memory_id: MemoryId
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        if not isinstance(self.scope, MemoryScope):
            raise TypeError("scope must be MemoryScope")
        if not isinstance(self.memory_id, MemoryId):
            raise TypeError("memory_id must be MemoryId")
        _aware(self.created_at, label="created_at")


@dataclass(frozen=True, slots=True)
class MemorySearchRequest:
    """One bounded search request inside an exact memory scope."""

    scope: MemoryScope
    query: str
    max_results: int = 16
    max_bytes: int = 262_144
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        if not isinstance(self.scope, MemoryScope):
            raise TypeError("scope must be MemoryScope")
        query = _bounded_utf8_text(
            self.query.strip(),
            label="memory search query",
            maximum_bytes=MAX_MEMORY_QUERY_BYTES,
        )
        object.__setattr__(self, "query", query)
        _positive_int(
            self.max_results,
            label="max_results",
            maximum=MAX_MEMORY_SEARCH_RESULTS,
        )
        _positive_int(
            self.max_bytes,
            label="max_bytes",
            maximum=MAX_MEMORY_SEARCH_RESULT_BYTES,
        )
        _aware(self.created_at, label="created_at")


@dataclass(frozen=True, slots=True)
class MemoryRetrievalCandidate:
    """Untrusted provider-neutral candidate identity returned by one retrieval adapter."""

    scope: MemoryScope
    memory_id: MemoryId
    version: MemoryRecordVersion
    content_digest: str
    score: float

    def __post_init__(self) -> None:
        if not isinstance(self.scope, MemoryScope):
            raise TypeError("scope must be MemoryScope")
        if not isinstance(self.memory_id, MemoryId):
            raise TypeError("memory_id must be MemoryId")
        if not isinstance(self.version, MemoryRecordVersion):
            raise TypeError("version must be MemoryRecordVersion")
        if not isinstance(self.content_digest, str):
            raise TypeError("content_digest must be a string")
        if _MEMORY_DIGEST_PATTERN.fullmatch(self.content_digest) is None:
            raise ValueError("content_digest must be a canonical sha256 digest")
        object.__setattr__(self, "score", _memory_ranking_score(self.score))


@dataclass(frozen=True, slots=True)
class MemorySearchHit:
    """One authoritative active record paired with validated untrusted ranking metadata."""

    record: MemoryRecord
    score: float

    def __post_init__(self) -> None:
        if not isinstance(self.record, MemoryRecord):
            raise TypeError("record must be MemoryRecord")
        if self.record.status is not MemoryRecordStatus.ACTIVE:
            raise ValueError("memory search hits require active records")
        object.__setattr__(self, "score", _memory_ranking_score(self.score))

    @property
    def scope(self) -> MemoryScope:
        return self.record.scope

    @property
    def memory_id(self) -> MemoryId:
        return self.record.memory_id

    @property
    def version(self) -> MemoryRecordVersion:
        return self.record.version

    @property
    def content_digest(self) -> str:
        return self.record.content_digest

    @property
    def content_bytes(self) -> int:
        return self.record.content_bytes


@dataclass(frozen=True, slots=True)
class MemorySearchResult:
    """Bounded deterministic authoritative disclosure for one exact memory scope."""

    scope: MemoryScope
    hits: Sequence[MemorySearchHit]
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        if not isinstance(self.scope, MemoryScope):
            raise TypeError("scope must be MemoryScope")
        normalized = tuple(self.hits)
        if len(normalized) > MAX_MEMORY_SEARCH_RESULTS:
            raise ValueError("memory search result exceeds the maximum hit count")
        if any(not isinstance(hit, MemorySearchHit) for hit in normalized):
            raise TypeError("hits must contain MemorySearchHit values")
        if any(hit.scope != self.scope for hit in normalized):
            raise ValueError("memory search result contains a mismatched scope")
        memory_ids = [hit.memory_id for hit in normalized]
        if len(memory_ids) != len(set(memory_ids)):
            raise ValueError("memory search result contains duplicate records")
        if sum(hit.content_bytes for hit in normalized) > MAX_MEMORY_SEARCH_RESULT_BYTES:
            raise ValueError("memory search result exceeds the maximum content bytes")
        _aware(self.created_at, label="created_at")
        object.__setattr__(
            self,
            "hits",
            tuple(
                sorted(
                    normalized,
                    key=lambda hit: (-hit.score, hit.memory_id.value.int),
                )
            ),
        )

    @property
    def content_bytes(self) -> int:
        return sum(hit.content_bytes for hit in self.hits)


@dataclass(frozen=True, slots=True)
class MemoryContextBlock:
    """Bounded provenance-preserving memory data that is never policy or authority."""

    scope: MemoryScope
    hits: Sequence[MemorySearchHit]
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        if not isinstance(self.scope, MemoryScope):
            raise TypeError("scope must be MemoryScope")
        normalized = tuple(self.hits)
        if not normalized:
            raise ValueError("memory context block requires at least one hit")
        if len(normalized) > MAX_MEMORY_CONTEXT_ITEMS:
            raise ValueError("memory context block exceeds the maximum item count")
        if any(not isinstance(hit, MemorySearchHit) for hit in normalized):
            raise TypeError("hits must contain MemorySearchHit values")
        if any(hit.scope != self.scope for hit in normalized):
            raise ValueError("memory context block contains a mismatched scope")
        memory_ids = [hit.memory_id for hit in normalized]
        if len(memory_ids) != len(set(memory_ids)):
            raise ValueError("memory context block contains duplicate records")
        if sum(hit.content_bytes for hit in normalized) > MAX_MEMORY_CONTEXT_BYTES:
            raise ValueError("memory context block exceeds the maximum content bytes")
        _aware(self.created_at, label="created_at")
        object.__setattr__(
            self,
            "hits",
            tuple(
                sorted(
                    normalized,
                    key=lambda hit: (-hit.score, hit.memory_id.value.int),
                )
            ),
        )

    @property
    def trust_label(self) -> str:
        return MEMORY_CONTEXT_TRUST_LABEL

    @property
    def content_bytes(self) -> int:
        return sum(hit.content_bytes for hit in self.hits)


@dataclass(frozen=True, slots=True)
class MemoryDeleteRequest:
    """One optimistic exact-record delete request."""

    scope: MemoryScope
    memory_id: MemoryId
    expected_version: MemoryRecordVersion
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        if not isinstance(self.scope, MemoryScope):
            raise TypeError("scope must be MemoryScope")
        if not isinstance(self.memory_id, MemoryId):
            raise TypeError("memory_id must be MemoryId")
        if not isinstance(self.expected_version, MemoryRecordVersion):
            raise TypeError("expected_version must be MemoryRecordVersion")
        _aware(self.created_at, label="created_at")
