"""Immutable bounded contracts for secure Phoenix agent workspaces."""

from __future__ import annotations

import hashlib
import re
import unicodedata
from collections.abc import Awaitable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from types import MappingProxyType
from typing import Protocol, runtime_checkable
from uuid import UUID, uuid4

from phoenix_os.agent.contracts import AgentId, AgentRunId

MAX_WORKSPACE_NAMESPACE_LENGTH = 128
MAX_WORKSPACE_SCOPE_ID_LENGTH = 192
MAX_WORKSPACE_LOGICAL_PATH_BYTES = 1_024
MAX_WORKSPACE_LOGICAL_PATH_SEGMENTS = 64
MAX_WORKSPACE_LOGICAL_PATH_SEGMENT_BYTES = 255
MAX_WORKSPACE_ARTIFACT_BYTES = 67_108_864
MAX_WORKSPACE_METADATA_ITEMS = 64
MAX_WORKSPACE_METADATA_KEY_LENGTH = 128
MAX_WORKSPACE_METADATA_VALUE_LENGTH = 1_024
MAX_WORKSPACE_MEDIA_TYPE_LENGTH = 255
MAX_WORKSPACE_PROVENANCE_ITEMS = 32
MAX_WORKSPACE_SOURCE_VERSION_LENGTH = 128
MAX_WORKSPACE_TRANSFER_ADAPTER_ID_LENGTH = 128
MAX_WORKSPACE_TRANSFER_REFERENCE_LENGTH = 512
MAX_WORKSPACE_ARTIFACTS_PER_SCOPE = 100_000
MAX_WORKSPACE_ARTIFACT_ID_HISTORY_PER_SCOPE = 100_000
MAX_WORKSPACE_SCOPE_TOTAL_BYTES = 10_737_418_240
MAX_WORKSPACE_LIST_RESULTS = 256
MAX_WORKSPACE_RETENTION = timedelta(days=3650)
MAX_WORKSPACE_TOMBSTONE_RETENTION = timedelta(days=3650)

_WORKSPACE_NAMESPACE_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,127})$")
_WORKSPACE_SCOPE_ID_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,191})$")
_ARTIFACT_DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
_MEDIA_TYPE_PATTERN = re.compile(
    r"^[a-z0-9][a-z0-9!#$&^_.+-]{0,126}/[a-z0-9][a-z0-9!#$&^_.+-]{0,126}$"
)
_WORKSPACE_TRANSFER_ADAPTER_ID_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,127})$")
_WORKSPACE_TRANSFER_REFERENCE_PATTERN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,511})$")
_WINDOWS_RESERVED_STEMS = frozenset(
    {"con", "prn", "aux", "nul"}
    | {f"com{index}" for index in range(1, 10)}
    | {f"lpt{index}" for index in range(1, 10)}
)


def _positive_int(value: int, *, label: str, maximum: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{label} must be an integer")
    if value <= 0:
        raise ValueError(f"{label} must be greater than zero")
    if value > maximum:
        raise ValueError(f"{label} exceeds the global maximum")


def _non_negative_int(value: int, *, label: str, maximum: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{label} must be an integer")
    if value < 0:
        raise ValueError(f"{label} cannot be negative")
    if value > maximum:
        raise ValueError(f"{label} exceeds the global maximum")


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


def _bounded_bytes(value: bytes, *, label: str, maximum_bytes: int) -> bytes:
    if not isinstance(value, bytes):
        raise TypeError(f"{label} must be bytes")
    if len(value) > maximum_bytes:
        raise ValueError(f"{label} exceeds the maximum byte size")
    return value


def _bounded_utf8_text(
    value: str,
    *,
    label: str,
    maximum_bytes: int,
) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{label} must be a string")
    if not value:
        raise ValueError(f"{label} must not be blank")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exception:
        raise ValueError(f"{label} is not valid Unicode") from exception
    if len(encoded) > maximum_bytes:
        raise ValueError(f"{label} exceeds the maximum byte size")
    return value


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
            maximum_chars=MAX_WORKSPACE_METADATA_KEY_LENGTH,
        )
        normalized_value = _bounded_text(
            item,
            label=f"{label} value",
            maximum_chars=MAX_WORKSPACE_METADATA_VALUE_LENGTH,
            allow_blank=True,
        )
        if normalized_key in frozen:
            raise ValueError(f"{label} contains duplicate normalized keys")
        frozen[normalized_key] = normalized_value
    return MappingProxyType(frozen)


def _canonical_logical_path(value: str) -> str:
    if not isinstance(value, str):
        raise TypeError("artifact logical path must be a string")
    if not value:
        raise ValueError("artifact logical path must not be blank")
    if "\\" in value:
        raise ValueError("artifact logical path must use portable forward separators")
    if value.startswith("/"):
        raise ValueError("artifact logical path must be relative")
    if "\x00" in value:
        raise ValueError("artifact logical path must not contain NUL")

    normalized = unicodedata.normalize("NFC", value)
    normalized = unicodedata.normalize("NFC", normalized.casefold())
    encoded = normalized.encode("utf-8")
    if len(encoded) > MAX_WORKSPACE_LOGICAL_PATH_BYTES:
        raise ValueError("artifact logical path exceeds the maximum byte size")

    segments = normalized.split("/")
    if len(segments) > MAX_WORKSPACE_LOGICAL_PATH_SEGMENTS:
        raise ValueError("artifact logical path exceeds the maximum segment count")

    for segment in segments:
        if not segment or segment in {".", ".."}:
            raise ValueError("artifact logical path contains an unsafe segment")
        if segment != segment.strip() or segment.endswith("."):
            raise ValueError("artifact logical path contains an ambiguous segment")
        if ":" in segment:
            raise ValueError("artifact logical path contains a reserved separator")
        if any(unicodedata.category(character).startswith("C") for character in segment):
            raise ValueError("artifact logical path contains a control or reserved character")
        if len(segment.encode("utf-8")) > MAX_WORKSPACE_LOGICAL_PATH_SEGMENT_BYTES:
            raise ValueError("artifact logical path segment exceeds the maximum byte size")
        stem = segment.split(".", 1)[0]
        if stem in _WINDOWS_RESERVED_STEMS:
            raise ValueError("artifact logical path contains a platform-reserved name")

    return normalized


@dataclass(frozen=True, slots=True, order=True)
class WorkspaceNamespace:
    """Stable server-owned namespace for one workspace policy domain."""

    value: str

    def __post_init__(self) -> None:
        if not isinstance(self.value, str):
            raise TypeError("workspace namespace must be a string")
        normalized = self.value.strip().lower()
        if _WORKSPACE_NAMESPACE_PATTERN.fullmatch(normalized) is None:
            raise ValueError("workspace namespace is invalid")
        object.__setattr__(self, "value", normalized)

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True, order=True)
class WorkspaceScopeId:
    """Stable content-free identity inside one Phoenix-owned scope kind."""

    value: str

    def __post_init__(self) -> None:
        if not isinstance(self.value, str):
            raise TypeError("workspace scope id must be a string")
        normalized = self.value.strip().lower()
        if _WORKSPACE_SCOPE_ID_PATTERN.fullmatch(normalized) is None:
            raise ValueError("workspace scope id is invalid")
        object.__setattr__(self, "value", normalized)

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True, order=True)
class WorkspaceId:
    """Stable Phoenix-owned identity for one configured workspace."""

    value: UUID = field(default_factory=uuid4)

    def __post_init__(self) -> None:
        if not isinstance(self.value, UUID):
            raise TypeError("workspace id must be UUID")

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True, order=True)
class ArtifactId:
    """Stable Phoenix-owned identity for one logical artifact."""

    value: UUID = field(default_factory=uuid4)

    def __post_init__(self) -> None:
        if not isinstance(self.value, UUID):
            raise TypeError("artifact id must be UUID")

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True, order=True)
class ArtifactVersion:
    """Positive optimistic-concurrency version for one logical artifact."""

    value: int = 1

    def __post_init__(self) -> None:
        _positive_int(self.value, label="artifact version", maximum=2**63 - 1)

    def __int__(self) -> int:
        return self.value

    def next(self) -> ArtifactVersion:
        return ArtifactVersion(self.value + 1)


@dataclass(frozen=True, slots=True, order=True)
class ArtifactDigest:
    """Canonical content digest for one authoritative artifact version."""

    value: str

    def __post_init__(self) -> None:
        if not isinstance(self.value, str):
            raise TypeError("artifact digest must be a string")
        if _ARTIFACT_DIGEST_PATTERN.fullmatch(self.value) is None:
            raise ValueError("artifact digest must be a canonical sha256 digest")

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True, order=True)
class ArtifactLogicalPath:
    """Canonical portable Phoenix logical path; never a native host path."""

    value: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "value", _canonical_logical_path(self.value))

    def __str__(self) -> str:
        return self.value

    @property
    def segments(self) -> tuple[str, ...]:
        return tuple(self.value.split("/"))


@dataclass(frozen=True, slots=True, order=True)
class ArtifactMediaType:
    """Bounded descriptive media type that never grants executable trust."""

    value: str = "application/octet-stream"

    def __post_init__(self) -> None:
        if not isinstance(self.value, str):
            raise TypeError("artifact media type must be a string")
        normalized = self.value.strip().lower()
        if len(normalized) > MAX_WORKSPACE_MEDIA_TYPE_LENGTH:
            raise ValueError("artifact media type exceeds the maximum length")
        if _MEDIA_TYPE_PATTERN.fullmatch(normalized) is None:
            raise ValueError("artifact media type is invalid")
        object.__setattr__(self, "value", normalized)

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True, order=True)
class WorkspaceTransferAdapterId:
    """Stable server-owned identity for one configured transfer adapter."""

    value: str

    def __post_init__(self) -> None:
        if not isinstance(self.value, str):
            raise TypeError("workspace transfer adapter id must be a string")
        normalized = self.value.strip().lower()
        if _WORKSPACE_TRANSFER_ADAPTER_ID_PATTERN.fullmatch(normalized) is None:
            raise ValueError("workspace transfer adapter id is invalid")
        object.__setattr__(self, "value", normalized)

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True, order=True)
class WorkspaceTransferReference:
    """Opaque adapter-local data reference carrying no authority.

    It cannot select an adapter, credential, network permission, host root, URL,
    native path, Phoenix scope, policy, or approval.
    """

    value: str

    def __post_init__(self) -> None:
        if not isinstance(self.value, str):
            raise TypeError("workspace transfer reference must be a string")
        if _WORKSPACE_TRANSFER_REFERENCE_PATTERN.fullmatch(self.value) is None:
            raise ValueError("workspace transfer reference is invalid")

    def __str__(self) -> str:
        return self.value


class WorkspaceScopeKind(StrEnum):
    RUN = "run"
    AGENT = "agent"
    PRINCIPAL = "principal"


class ArtifactStatus(StrEnum):
    ACTIVE = "active"
    TOMBSTONED = "tombstoned"


class ArtifactOriginKind(StrEnum):
    USER_INPUT = "user_input"
    AGENT_REQUEST = "agent_request"
    TOOL_RESULT = "tool_result"
    DELEGATED_RESULT = "delegated_result"
    OPERATOR = "operator"
    IMPORT = "import"
    SYSTEM = "system"


class ArtifactTransferDirection(StrEnum):
    IMPORT = "import"
    EXPORT = "export"


@dataclass(frozen=True, slots=True, order=True)
class WorkspaceScope:
    """Exact Phoenix-owned visibility boundary for one workspace operation."""

    namespace: WorkspaceNamespace
    kind: WorkspaceScopeKind
    scope_id: WorkspaceScopeId

    def __post_init__(self) -> None:
        if not isinstance(self.namespace, WorkspaceNamespace):
            raise TypeError("namespace must be WorkspaceNamespace")
        if not isinstance(self.kind, WorkspaceScopeKind):
            raise TypeError("kind must be WorkspaceScopeKind")
        if not isinstance(self.scope_id, WorkspaceScopeId):
            raise TypeError("scope_id must be WorkspaceScopeId")


def artifact_content_digest(content: bytes) -> ArtifactDigest:
    """Return a canonical digest for globally bounded immutable artifact bytes."""

    normalized = _bounded_bytes(
        content,
        label="artifact content",
        maximum_bytes=MAX_WORKSPACE_ARTIFACT_BYTES,
    )
    return ArtifactDigest("sha256:" + hashlib.sha256(normalized).hexdigest())


def canonical_artifact_path_digest(path: ArtifactLogicalPath) -> str:
    """Return a stable content-free digest for one canonical logical path."""

    if not isinstance(path, ArtifactLogicalPath):
        raise TypeError("path must be ArtifactLogicalPath")
    return "sha256:" + hashlib.sha256(path.value.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class ArtifactProvenance:
    """Bounded immutable origin facts; provenance never grants authority."""

    origin: ArtifactOriginKind
    content_digest: ArtifactDigest
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    source_version: str | None = None
    source_run_id: AgentRunId | None = None
    source_agent_id: AgentId | None = None
    source_principal_id: WorkspaceScopeId | None = None
    attributes: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.origin, ArtifactOriginKind):
            raise TypeError("origin must be ArtifactOriginKind")
        if not isinstance(self.content_digest, ArtifactDigest):
            raise TypeError("content_digest must be ArtifactDigest")
        _aware(self.created_at, label="created_at")
        if self.source_version is not None:
            object.__setattr__(
                self,
                "source_version",
                _bounded_text(
                    self.source_version,
                    label="source_version",
                    maximum_chars=MAX_WORKSPACE_SOURCE_VERSION_LENGTH,
                ),
            )
        if self.source_run_id is not None and not isinstance(self.source_run_id, AgentRunId):
            raise TypeError("source_run_id must be AgentRunId")
        if self.source_agent_id is not None and not isinstance(self.source_agent_id, AgentId):
            raise TypeError("source_agent_id must be AgentId")
        if self.source_principal_id is not None and not isinstance(
            self.source_principal_id, WorkspaceScopeId
        ):
            raise TypeError("source_principal_id must be WorkspaceScopeId")
        object.__setattr__(
            self,
            "attributes",
            _freeze_text_mapping(
                self.attributes,
                label="provenance attributes",
                maximum_items=MAX_WORKSPACE_PROVENANCE_ITEMS,
            ),
        )


@dataclass(frozen=True, slots=True)
class WorkspaceRetentionPolicy:
    """Finite artifact TTL and tombstone-retention policy."""

    artifact_ttl: timedelta = timedelta(days=30)
    tombstone_retention: timedelta = timedelta(days=90)

    def __post_init__(self) -> None:
        _positive_duration(
            self.artifact_ttl,
            label="artifact_ttl",
            maximum=MAX_WORKSPACE_RETENTION,
        )
        _positive_duration(
            self.tombstone_retention,
            label="tombstone_retention",
            maximum=MAX_WORKSPACE_TOMBSTONE_RETENTION,
        )


@dataclass(frozen=True, slots=True)
class WorkspaceLimits:
    """Finite limits for one configured workspace namespace/scope."""

    max_artifact_bytes: int = 16_777_216
    max_artifacts_per_scope: int = 10_000
    max_artifact_id_history_per_scope: int = 100_000
    max_total_bytes_per_scope: int = 1_073_741_824
    max_logical_path_bytes: int = 512
    max_logical_path_segments: int = 32
    max_list_results: int = 100
    retention: WorkspaceRetentionPolicy = field(default_factory=WorkspaceRetentionPolicy)

    def __post_init__(self) -> None:
        limits = (
            ("max_artifact_bytes", self.max_artifact_bytes, MAX_WORKSPACE_ARTIFACT_BYTES),
            (
                "max_artifacts_per_scope",
                self.max_artifacts_per_scope,
                MAX_WORKSPACE_ARTIFACTS_PER_SCOPE,
            ),
            (
                "max_artifact_id_history_per_scope",
                self.max_artifact_id_history_per_scope,
                MAX_WORKSPACE_ARTIFACT_ID_HISTORY_PER_SCOPE,
            ),
            (
                "max_total_bytes_per_scope",
                self.max_total_bytes_per_scope,
                MAX_WORKSPACE_SCOPE_TOTAL_BYTES,
            ),
            (
                "max_logical_path_bytes",
                self.max_logical_path_bytes,
                MAX_WORKSPACE_LOGICAL_PATH_BYTES,
            ),
            (
                "max_logical_path_segments",
                self.max_logical_path_segments,
                MAX_WORKSPACE_LOGICAL_PATH_SEGMENTS,
            ),
            ("max_list_results", self.max_list_results, MAX_WORKSPACE_LIST_RESULTS),
        )
        for label, value, maximum in limits:
            _positive_int(value, label=label, maximum=maximum)
        if self.max_artifact_bytes > self.max_total_bytes_per_scope:
            raise ValueError("max_artifact_bytes cannot exceed max_total_bytes_per_scope")
        if self.max_artifact_id_history_per_scope < self.max_artifacts_per_scope:
            raise ValueError(
                "max_artifact_id_history_per_scope cannot be less than max_artifacts_per_scope"
            )
        if not isinstance(self.retention, WorkspaceRetentionPolicy):
            raise TypeError("retention must be WorkspaceRetentionPolicy")


@dataclass(frozen=True, slots=True)
class ArtifactRecord:
    """Content-free authoritative metadata for one artifact version or tombstone."""

    scope: WorkspaceScope
    artifact_id: ArtifactId
    version: ArtifactVersion
    status: ArtifactStatus
    content_digest: ArtifactDigest
    byte_length: int
    created_at: datetime
    updated_at: datetime
    expires_at: datetime
    logical_path: ArtifactLogicalPath | None = None
    media_type: ArtifactMediaType | None = None
    provenance: ArtifactProvenance | None = None
    metadata: Mapping[str, str] = field(default_factory=dict)
    deleted_at: datetime | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.scope, WorkspaceScope):
            raise TypeError("scope must be WorkspaceScope")
        if not isinstance(self.artifact_id, ArtifactId):
            raise TypeError("artifact_id must be ArtifactId")
        if not isinstance(self.version, ArtifactVersion):
            raise TypeError("version must be ArtifactVersion")
        if not isinstance(self.status, ArtifactStatus):
            raise TypeError("status must be ArtifactStatus")
        if not isinstance(self.content_digest, ArtifactDigest):
            raise TypeError("content_digest must be ArtifactDigest")
        _non_negative_int(
            self.byte_length,
            label="artifact byte_length",
            maximum=MAX_WORKSPACE_ARTIFACT_BYTES,
        )
        _aware(self.created_at, label="created_at")
        _aware(self.updated_at, label="updated_at")
        _aware(self.expires_at, label="expires_at")
        if self.updated_at < self.created_at:
            raise ValueError("updated_at cannot precede created_at")
        if self.expires_at <= self.updated_at:
            raise ValueError("expires_at must follow updated_at")
        retention_duration = self.expires_at - self.updated_at
        maximum_retention = (
            MAX_WORKSPACE_RETENTION
            if self.status is ArtifactStatus.ACTIVE
            else MAX_WORKSPACE_TOMBSTONE_RETENTION
        )
        if retention_duration > maximum_retention:
            raise ValueError("artifact record retention exceeds the global maximum")
        object.__setattr__(
            self,
            "metadata",
            _freeze_text_mapping(
                self.metadata,
                label="artifact metadata",
                maximum_items=MAX_WORKSPACE_METADATA_ITEMS,
            ),
        )

        if self.status is ArtifactStatus.ACTIVE:
            if not isinstance(self.logical_path, ArtifactLogicalPath):
                raise TypeError("active artifact record requires ArtifactLogicalPath")
            if not isinstance(self.media_type, ArtifactMediaType):
                raise TypeError("active artifact record requires ArtifactMediaType")
            if not isinstance(self.provenance, ArtifactProvenance):
                raise TypeError("active artifact record requires ArtifactProvenance")
            if self.provenance.content_digest != self.content_digest:
                raise ValueError("provenance content digest does not match artifact digest")
            if self.provenance.created_at > self.updated_at:
                raise ValueError("provenance created_at cannot follow artifact updated_at")
            if self.deleted_at is not None:
                raise ValueError("active artifact record cannot have deleted_at")
            return

        if self.logical_path is not None:
            raise ValueError("tombstoned artifact record cannot retain logical_path")
        if self.byte_length != 0:
            raise ValueError("tombstoned artifact record cannot retain byte length")
        if self.media_type is not None:
            raise ValueError("tombstoned artifact record cannot retain media_type")
        if self.provenance is not None:
            raise ValueError("tombstoned artifact record cannot retain provenance")
        if self.metadata:
            raise ValueError("tombstoned artifact record cannot retain metadata")
        if self.deleted_at is None:
            raise ValueError("tombstoned artifact record requires deleted_at")
        _aware(self.deleted_at, label="deleted_at")
        if self.deleted_at != self.updated_at:
            raise ValueError("tombstone deleted_at must equal updated_at")

    def expired(self, *, now: datetime) -> bool:
        """Return whether this logical version is outside its retention window."""

        _aware(now, label="now")
        return now >= self.expires_at


@dataclass(frozen=True, slots=True)
class ArtifactReadResult:
    """Validated immutable bytes paired with their content-free authoritative record."""

    record: ArtifactRecord
    content: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.record, ArtifactRecord):
            raise TypeError("record must be ArtifactRecord")
        if self.record.status is not ArtifactStatus.ACTIVE:
            raise ValueError("artifact read result requires an active record")
        content = _bounded_bytes(
            self.content,
            label="artifact content",
            maximum_bytes=MAX_WORKSPACE_ARTIFACT_BYTES,
        )
        if len(content) != self.record.byte_length:
            raise ValueError("artifact content byte length does not match record")
        if artifact_content_digest(content) != self.record.content_digest:
            raise ValueError("artifact content digest does not match record")
        object.__setattr__(self, "content", content)


@dataclass(frozen=True, slots=True)
class ArtifactListResult:
    """Bounded deterministic content-free listing for one exact workspace scope."""

    scope: WorkspaceScope
    artifacts: Sequence[ArtifactRecord]
    truncated: bool = False
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        if not isinstance(self.scope, WorkspaceScope):
            raise TypeError("scope must be WorkspaceScope")
        normalized = tuple(self.artifacts)
        if len(normalized) > MAX_WORKSPACE_LIST_RESULTS:
            raise ValueError("artifact list result exceeds the maximum artifact count")
        if any(not isinstance(record, ArtifactRecord) for record in normalized):
            raise TypeError("artifacts must contain ArtifactRecord values")
        if any(record.scope != self.scope for record in normalized):
            raise ValueError("artifact list result contains a mismatched scope")
        if any(record.status is not ArtifactStatus.ACTIVE for record in normalized):
            raise ValueError("artifact list result contains a non-active artifact")
        artifact_ids = [record.artifact_id for record in normalized]
        if len(artifact_ids) != len(set(artifact_ids)):
            raise ValueError("artifact list result contains duplicate artifacts")
        if not isinstance(self.truncated, bool):
            raise TypeError("truncated must be bool")
        _aware(self.created_at, label="created_at")
        object.__setattr__(
            self,
            "artifacts",
            tuple(
                sorted(
                    normalized,
                    key=lambda record: (
                        record.logical_path.value if record.logical_path is not None else "",
                        record.artifact_id.value.int,
                    ),
                )
            ),
        )

    @property
    def records(self) -> tuple[ArtifactRecord, ...]:
        """Return the artifact records using the generic record-listing vocabulary."""

        return tuple(self.artifacts)


@dataclass(frozen=True, slots=True)
class ArtifactListRequest:
    """One bounded listing request inside an exact workspace scope."""

    scope: WorkspaceScope
    prefix: ArtifactLogicalPath | None = None
    max_results: int = 100
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        if not isinstance(self.scope, WorkspaceScope):
            raise TypeError("scope must be WorkspaceScope")
        if self.prefix is not None and not isinstance(self.prefix, ArtifactLogicalPath):
            raise TypeError("prefix must be ArtifactLogicalPath")
        _positive_int(
            self.max_results,
            label="max_results",
            maximum=MAX_WORKSPACE_LIST_RESULTS,
        )
        _aware(self.created_at, label="created_at")


@dataclass(frozen=True, slots=True)
class ArtifactReadRequest:
    """One exact direct artifact read request."""

    scope: WorkspaceScope
    artifact_id: ArtifactId
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        if not isinstance(self.scope, WorkspaceScope):
            raise TypeError("scope must be WorkspaceScope")
        if not isinstance(self.artifact_id, ArtifactId):
            raise TypeError("artifact_id must be ArtifactId")
        _aware(self.created_at, label="created_at")


@dataclass(frozen=True, slots=True)
class ArtifactWriteRequest:
    """One explicit bounded write proposal against an exact artifact."""

    scope: WorkspaceScope
    logical_path: ArtifactLogicalPath
    content: bytes
    provenance: ArtifactProvenance
    artifact_id: ArtifactId = field(default_factory=ArtifactId)
    media_type: ArtifactMediaType = field(default_factory=ArtifactMediaType)
    metadata: Mapping[str, str] = field(default_factory=dict)
    expected_version: ArtifactVersion | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        if not isinstance(self.scope, WorkspaceScope):
            raise TypeError("scope must be WorkspaceScope")
        if not isinstance(self.logical_path, ArtifactLogicalPath):
            raise TypeError("logical_path must be ArtifactLogicalPath")
        if not isinstance(self.artifact_id, ArtifactId):
            raise TypeError("artifact_id must be ArtifactId")
        content = _bounded_bytes(
            self.content,
            label="artifact content",
            maximum_bytes=MAX_WORKSPACE_ARTIFACT_BYTES,
        )
        object.__setattr__(self, "content", content)
        if not isinstance(self.provenance, ArtifactProvenance):
            raise TypeError("provenance must be ArtifactProvenance")
        if self.provenance.content_digest != artifact_content_digest(content):
            raise ValueError("provenance content digest does not match artifact content")
        if not isinstance(self.media_type, ArtifactMediaType):
            raise TypeError("media_type must be ArtifactMediaType")
        if self.expected_version is not None and not isinstance(
            self.expected_version, ArtifactVersion
        ):
            raise TypeError("expected_version must be ArtifactVersion")
        _aware(self.created_at, label="created_at")
        object.__setattr__(
            self,
            "metadata",
            _freeze_text_mapping(
                self.metadata,
                label="artifact metadata",
                maximum_items=MAX_WORKSPACE_METADATA_ITEMS,
            ),
        )


@dataclass(frozen=True, slots=True)
class ArtifactDeleteRequest:
    """One optimistic exact-artifact delete request."""

    scope: WorkspaceScope
    artifact_id: ArtifactId
    expected_version: ArtifactVersion
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        if not isinstance(self.scope, WorkspaceScope):
            raise TypeError("scope must be WorkspaceScope")
        if not isinstance(self.artifact_id, ArtifactId):
            raise TypeError("artifact_id must be ArtifactId")
        if not isinstance(self.expected_version, ArtifactVersion):
            raise TypeError("expected_version must be ArtifactVersion")
        _aware(self.created_at, label="created_at")


@dataclass(frozen=True, slots=True)
class ArtifactImportRequest:
    """One independently authorized import through a server-owned adapter."""

    scope: WorkspaceScope
    artifact_id: ArtifactId
    source_reference: WorkspaceTransferReference
    expected_version: ArtifactVersion | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        if not isinstance(self.scope, WorkspaceScope):
            raise TypeError("scope must be WorkspaceScope")
        if not isinstance(self.artifact_id, ArtifactId):
            raise TypeError("artifact_id must be ArtifactId")
        if not isinstance(self.source_reference, WorkspaceTransferReference):
            raise TypeError("source_reference must be WorkspaceTransferReference")
        if self.expected_version is not None and not isinstance(
            self.expected_version, ArtifactVersion
        ):
            raise TypeError("expected_version must be ArtifactVersion")
        _aware(self.created_at, label="created_at")


@dataclass(frozen=True, slots=True)
class ArtifactExportRequest:
    """One version-bound export within a server-owned destination configuration."""

    scope: WorkspaceScope
    artifact_id: ArtifactId
    expected_version: ArtifactVersion
    destination_reference: WorkspaceTransferReference
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        if not isinstance(self.scope, WorkspaceScope):
            raise TypeError("scope must be WorkspaceScope")
        if not isinstance(self.artifact_id, ArtifactId):
            raise TypeError("artifact_id must be ArtifactId")
        if not isinstance(self.expected_version, ArtifactVersion):
            raise TypeError("expected_version must be ArtifactVersion")
        if not isinstance(self.destination_reference, WorkspaceTransferReference):
            raise TypeError("destination_reference must be WorkspaceTransferReference")
        _aware(self.created_at, label="created_at")


@dataclass(frozen=True, slots=True)
class WorkspaceImportResult:
    """Globally bounded untrusted data returned by a configured import adapter."""

    content: bytes
    logical_path: str
    media_type: str = "application/octet-stream"
    metadata: Mapping[str, str] = field(default_factory=dict)
    external_digest: str | None = None
    source_version: str | None = None
    transfer_reference: WorkspaceTransferReference | None = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "content",
            _bounded_bytes(
                self.content,
                label="imported content",
                maximum_bytes=MAX_WORKSPACE_ARTIFACT_BYTES,
            ),
        )
        object.__setattr__(
            self,
            "logical_path",
            _bounded_utf8_text(
                self.logical_path,
                label="imported logical path",
                maximum_bytes=MAX_WORKSPACE_LOGICAL_PATH_BYTES,
            ),
        )
        object.__setattr__(
            self,
            "media_type",
            _bounded_text(
                self.media_type,
                label="imported media type",
                maximum_chars=MAX_WORKSPACE_MEDIA_TYPE_LENGTH,
            ),
        )
        object.__setattr__(
            self,
            "metadata",
            _freeze_text_mapping(
                self.metadata,
                label="imported metadata",
                maximum_items=MAX_WORKSPACE_METADATA_ITEMS,
            ),
        )
        if self.external_digest is not None:
            object.__setattr__(
                self,
                "external_digest",
                _bounded_text(
                    self.external_digest,
                    label="external digest",
                    maximum_chars=len("sha256:") + 64,
                ),
            )
        if self.source_version is not None:
            object.__setattr__(
                self,
                "source_version",
                _bounded_text(
                    self.source_version,
                    label="import source version",
                    maximum_chars=MAX_WORKSPACE_SOURCE_VERSION_LENGTH,
                ),
            )
        if self.transfer_reference is not None and not isinstance(
            self.transfer_reference, WorkspaceTransferReference
        ):
            raise TypeError("transfer_reference must be WorkspaceTransferReference")


@dataclass(frozen=True, slots=True)
class WorkspaceExportPayload:
    """Bounded exact artifact version disclosed to one configured export adapter."""

    scope: WorkspaceScope
    artifact_id: ArtifactId
    version: ArtifactVersion
    logical_path: ArtifactLogicalPath
    media_type: ArtifactMediaType
    content_digest: ArtifactDigest
    content: bytes
    destination_reference: WorkspaceTransferReference

    def __post_init__(self) -> None:
        if not isinstance(self.scope, WorkspaceScope):
            raise TypeError("scope must be WorkspaceScope")
        if not isinstance(self.artifact_id, ArtifactId):
            raise TypeError("artifact_id must be ArtifactId")
        if not isinstance(self.version, ArtifactVersion):
            raise TypeError("version must be ArtifactVersion")
        if not isinstance(self.logical_path, ArtifactLogicalPath):
            raise TypeError("logical_path must be ArtifactLogicalPath")
        if not isinstance(self.media_type, ArtifactMediaType):
            raise TypeError("media_type must be ArtifactMediaType")
        if not isinstance(self.content_digest, ArtifactDigest):
            raise TypeError("content_digest must be ArtifactDigest")
        content = _bounded_bytes(
            self.content,
            label="exported content",
            maximum_bytes=MAX_WORKSPACE_ARTIFACT_BYTES,
        )
        if artifact_content_digest(content) != self.content_digest:
            raise ValueError("exported content digest does not match authoritative digest")
        object.__setattr__(self, "content", content)
        if not isinstance(self.destination_reference, WorkspaceTransferReference):
            raise TypeError("destination_reference must be WorkspaceTransferReference")

    @property
    def byte_length(self) -> int:
        return len(self.content)


@dataclass(frozen=True, slots=True)
class WorkspaceExportResult:
    """Bounded content-free completion evidence returned by an export adapter."""

    transfer_reference: WorkspaceTransferReference | None = None

    def __post_init__(self) -> None:
        if self.transfer_reference is not None and not isinstance(
            self.transfer_reference, WorkspaceTransferReference
        ):
            raise TypeError("transfer_reference must be WorkspaceTransferReference")


@dataclass(frozen=True, slots=True)
class ArtifactTransferReceipt:
    """Content-free descriptive evidence for one completed transfer."""

    direction: ArtifactTransferDirection
    scope: WorkspaceScope
    artifact_id: ArtifactId
    version: ArtifactVersion
    content_digest: ArtifactDigest
    byte_length: int
    adapter_id: WorkspaceTransferAdapterId
    completed_at: datetime
    transfer_reference: WorkspaceTransferReference | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.direction, ArtifactTransferDirection):
            raise TypeError("direction must be ArtifactTransferDirection")
        if not isinstance(self.scope, WorkspaceScope):
            raise TypeError("scope must be WorkspaceScope")
        if not isinstance(self.artifact_id, ArtifactId):
            raise TypeError("artifact_id must be ArtifactId")
        if not isinstance(self.version, ArtifactVersion):
            raise TypeError("version must be ArtifactVersion")
        if not isinstance(self.content_digest, ArtifactDigest):
            raise TypeError("content_digest must be ArtifactDigest")
        _non_negative_int(
            self.byte_length,
            label="transferred byte_length",
            maximum=MAX_WORKSPACE_ARTIFACT_BYTES,
        )
        if not isinstance(self.adapter_id, WorkspaceTransferAdapterId):
            raise TypeError("adapter_id must be WorkspaceTransferAdapterId")
        _aware(self.completed_at, label="completed_at")
        if self.transfer_reference is not None and not isinstance(
            self.transfer_reference, WorkspaceTransferReference
        ):
            raise TypeError("transfer_reference must be WorkspaceTransferReference")


@runtime_checkable
class WorkspaceStore(Protocol):
    """Authoritative provider-neutral boundary for workspace metadata and bytes."""

    @property
    def closed(self) -> bool: ...

    @property
    def limits(self) -> WorkspaceLimits: ...

    def write(self, request: ArtifactWriteRequest) -> Awaitable[ArtifactRecord]: ...

    def read(self, request: ArtifactReadRequest) -> Awaitable[ArtifactReadResult | None]: ...

    def list(self, request: ArtifactListRequest) -> Awaitable[ArtifactListResult]: ...

    def delete(self, request: ArtifactDeleteRequest) -> Awaitable[None]: ...

    def close(self) -> Awaitable[None]: ...
