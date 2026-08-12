from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta
from types import MappingProxyType
from unicodedata import normalize
from uuid import UUID

import pytest

from phoenix_os.agent import (
    MAX_WORKSPACE_ARTIFACT_BYTES,
    MAX_WORKSPACE_ARTIFACTS_PER_SCOPE,
    MAX_WORKSPACE_LIST_RESULTS,
    MAX_WORKSPACE_LOGICAL_PATH_BYTES,
    MAX_WORKSPACE_LOGICAL_PATH_SEGMENT_BYTES,
    MAX_WORKSPACE_LOGICAL_PATH_SEGMENTS,
    MAX_WORKSPACE_RETENTION,
    MAX_WORKSPACE_SCOPE_TOTAL_BYTES,
    MAX_WORKSPACE_TOMBSTONE_RETENTION,
    AgentId,
    AgentRunId,
    ArtifactDeleteRequest,
    ArtifactDigest,
    ArtifactId,
    ArtifactListRequest,
    ArtifactLogicalPath,
    ArtifactMediaType,
    ArtifactOriginKind,
    ArtifactProvenance,
    ArtifactReadRequest,
    ArtifactRecord,
    ArtifactStatus,
    ArtifactVersion,
    ArtifactWriteRequest,
    WorkspaceId,
    WorkspaceLimits,
    WorkspaceNamespace,
    WorkspaceRetentionPolicy,
    WorkspaceScope,
    WorkspaceScopeId,
    WorkspaceScopeKind,
    artifact_content_digest,
    canonical_artifact_path_digest,
)

_NOW = datetime(2026, 8, 12, 5, 30, tzinfo=UTC)
_ARTIFACT_ID = ArtifactId(UUID("10000000-0000-0000-0000-000000000031"))


def _scope() -> WorkspaceScope:
    return WorkspaceScope(
        namespace=WorkspaceNamespace("Default"),
        kind=WorkspaceScopeKind.AGENT,
        scope_id=WorkspaceScopeId("Researcher"),
    )


def _provenance(content: bytes = b"artifact bytes") -> ArtifactProvenance:
    return ArtifactProvenance(
        origin=ArtifactOriginKind.AGENT_REQUEST,
        content_digest=artifact_content_digest(content),
        created_at=_NOW,
        source_run_id=AgentRunId(UUID("20000000-0000-0000-0000-000000000031")),
        source_agent_id=AgentId("researcher"),
        attributes={"channel": "explicit"},
    )


def test_workspace_identifiers_and_scope_are_immutable_and_normalized() -> None:
    workspace_id = WorkspaceId(UUID("30000000-0000-0000-0000-000000000031"))
    namespace = WorkspaceNamespace(" Default ")
    scope_id = WorkspaceScopeId(" Researcher ")
    scope = WorkspaceScope(namespace, WorkspaceScopeKind.AGENT, scope_id)

    assert str(workspace_id) == "30000000-0000-0000-0000-000000000031"
    assert str(namespace) == "default"
    assert str(scope_id) == "researcher"
    assert scope.kind is WorkspaceScopeKind.AGENT
    assert str(_ARTIFACT_ID) == "10000000-0000-0000-0000-000000000031"
    with pytest.raises(FrozenInstanceError):
        scope.scope_id = WorkspaceScopeId("other")  # type: ignore[misc]


@pytest.mark.parametrize(
    "value",
    (
        "",
        "bad/name",
        "bad:scope",
        "contains space",
        "x" * 129,
    ),
)
def test_workspace_namespace_rejects_unsafe_resource_values(value: str) -> None:
    with pytest.raises(ValueError):
        WorkspaceNamespace(value)


@pytest.mark.parametrize("value", ("", "bad/scope", "bad:scope", "contains space"))
def test_workspace_scope_id_rejects_resource_injection(value: str) -> None:
    with pytest.raises(ValueError):
        WorkspaceScopeId(value)


def test_workspace_scope_kinds_and_artifact_statuses_are_finite() -> None:
    assert tuple(item.value for item in WorkspaceScopeKind) == ("run", "agent", "principal")
    assert tuple(item.value for item in ArtifactStatus) == ("active", "tombstoned")


def test_artifact_version_is_positive_monotonic_and_bounded() -> None:
    version = ArtifactVersion()
    assert version.value == 1
    assert version.next() == ArtifactVersion(2)

    with pytest.raises(ValueError):
        ArtifactVersion(0)
    with pytest.raises(TypeError):
        ArtifactVersion(True)


def test_logical_path_is_portable_unicode_normalized_and_case_canonical() -> None:
    composed = ArtifactLogicalPath("Docs/Résumé.TXT")
    decomposed = ArtifactLogicalPath("docs/" + normalize("NFD", "résumé.txt"))

    assert composed == decomposed
    assert str(composed) == "docs/résumé.txt"
    assert composed.segments == ("docs", "résumé.txt")
    assert canonical_artifact_path_digest(composed) == canonical_artifact_path_digest(decomposed)


@pytest.mark.parametrize(
    "value",
    (
        "../secret.txt",
        "folder/../secret.txt",
        "/etc/passwd",
        "C:/Windows/system.ini",
        "//server/share/file.txt",
        r"folder\file.txt",
        "folder//file.txt",
        "folder/./file.txt",
        "nul.txt",
        "COM1",
        "folder/trailing.",
        "folder/trailing ",
        "folder/a:b.txt",
        "folder/\x00file.txt",
        r"\\?\C:\Windows\system.ini",
    ),
)
def test_logical_path_rejects_host_escape_alias_and_device_forms(value: str) -> None:
    with pytest.raises(ValueError):
        ArtifactLogicalPath(value)


def test_logical_path_global_bounds_are_strict() -> None:
    with pytest.raises(ValueError):
        ArtifactLogicalPath("x" * (MAX_WORKSPACE_LOGICAL_PATH_SEGMENT_BYTES + 1))
    with pytest.raises(ValueError):
        ArtifactLogicalPath("/".join(["x"] * (MAX_WORKSPACE_LOGICAL_PATH_SEGMENTS + 1)))
    with pytest.raises(ValueError):
        ArtifactLogicalPath("a/" + "b" * (MAX_WORKSPACE_LOGICAL_PATH_BYTES + 1))


def test_artifact_digest_and_media_type_are_canonical_and_bounded() -> None:
    digest = artifact_content_digest(b"artifact bytes")
    media_type = ArtifactMediaType(" Text/Plain ")

    assert isinstance(digest, ArtifactDigest)
    assert str(digest).startswith("sha256:")
    assert str(media_type) == "text/plain"

    with pytest.raises(ValueError):
        ArtifactDigest("not-a-digest")
    with pytest.raises(ValueError):
        ArtifactMediaType("text/plain; charset=utf-8")
    with pytest.raises(TypeError):
        artifact_content_digest(bytearray(b"mutable"))  # type: ignore[arg-type]


def test_artifact_content_digest_rejects_global_oversize() -> None:
    with pytest.raises(ValueError):
        artifact_content_digest(b"x" * (MAX_WORKSPACE_ARTIFACT_BYTES + 1))


def test_workspace_retention_and_limits_are_finite_and_relationally_safe() -> None:
    retention = WorkspaceRetentionPolicy(
        artifact_ttl=timedelta(days=7),
        tombstone_retention=timedelta(days=30),
    )
    limits = WorkspaceLimits(retention=retention)

    assert limits.max_artifact_bytes <= MAX_WORKSPACE_ARTIFACT_BYTES
    assert limits.max_artifacts_per_scope <= MAX_WORKSPACE_ARTIFACTS_PER_SCOPE
    assert limits.max_total_bytes_per_scope <= MAX_WORKSPACE_SCOPE_TOTAL_BYTES
    assert limits.max_list_results <= MAX_WORKSPACE_LIST_RESULTS

    with pytest.raises(ValueError):
        WorkspaceRetentionPolicy(artifact_ttl=timedelta(0))
    with pytest.raises(ValueError):
        WorkspaceRetentionPolicy(artifact_ttl=MAX_WORKSPACE_RETENTION + timedelta(seconds=1))
    with pytest.raises(ValueError):
        WorkspaceRetentionPolicy(
            tombstone_retention=MAX_WORKSPACE_TOMBSTONE_RETENTION + timedelta(seconds=1)
        )
    with pytest.raises(ValueError):
        WorkspaceLimits(max_artifact_bytes=1024, max_total_bytes_per_scope=512)


def test_artifact_record_retention_is_globally_bounded_by_status() -> None:
    content = b"artifact bytes"
    digest = artifact_content_digest(content)

    with pytest.raises(ValueError, match="global maximum"):
        ArtifactRecord(
            scope=_scope(),
            artifact_id=_ARTIFACT_ID,
            version=ArtifactVersion(),
            status=ArtifactStatus.ACTIVE,
            content_digest=digest,
            byte_length=len(content),
            created_at=_NOW,
            updated_at=_NOW,
            expires_at=_NOW + MAX_WORKSPACE_RETENTION + timedelta(seconds=1),
            logical_path=ArtifactLogicalPath("reports/result.txt"),
            media_type=ArtifactMediaType("text/plain"),
            provenance=_provenance(content),
        )

    with pytest.raises(ValueError, match="global maximum"):
        ArtifactRecord(
            scope=_scope(),
            artifact_id=_ARTIFACT_ID,
            status=ArtifactStatus.TOMBSTONED,
            version=ArtifactVersion(2),
            content_digest=digest,
            byte_length=0,
            created_at=_NOW,
            updated_at=_NOW,
            expires_at=_NOW + MAX_WORKSPACE_TOMBSTONE_RETENTION + timedelta(seconds=1),
            deleted_at=_NOW,
        )


def test_provenance_is_immutable_bounded_origin_metadata() -> None:
    provenance = _provenance()

    assert provenance.origin is ArtifactOriginKind.AGENT_REQUEST
    assert provenance.source_agent_id == AgentId("researcher")
    assert provenance.attributes == {"channel": "explicit"}
    assert isinstance(provenance.attributes, MappingProxyType)

    with pytest.raises(TypeError):
        ArtifactProvenance(
            origin=ArtifactOriginKind.AGENT_REQUEST,
            content_digest="not-a-digest",  # type: ignore[arg-type]
            created_at=_NOW,
        )


def test_artifact_write_is_explicit_binary_safe_and_freezes_metadata() -> None:
    content = b"\x00\x01exact bytes\xff"
    request = ArtifactWriteRequest(
        scope=_scope(),
        artifact_id=_ARTIFACT_ID,
        logical_path=ArtifactLogicalPath("Outputs/Result.BIN"),
        content=content,
        provenance=_provenance(content),
        media_type=ArtifactMediaType("application/octet-stream"),
        metadata={"kind": "result"},
        created_at=_NOW,
    )

    assert request.content == content
    assert str(request.logical_path) == "outputs/result.bin"
    assert request.metadata == {"kind": "result"}
    assert isinstance(request.metadata, MappingProxyType)
    assert request.expected_version is None

    with pytest.raises(ValueError):
        ArtifactWriteRequest(
            scope=_scope(),
            artifact_id=_ARTIFACT_ID,
            logical_path=ArtifactLogicalPath("outputs/result.bin"),
            content=b"different",
            provenance=_provenance(b"original"),
            created_at=_NOW,
        )


def test_list_read_and_delete_requests_bind_exact_scope_artifact_and_version() -> None:
    scope = _scope()
    listing = ArtifactListRequest(
        scope=scope,
        prefix=ArtifactLogicalPath("Reports"),
        max_results=8,
        created_at=_NOW,
    )
    read = ArtifactReadRequest(scope=scope, artifact_id=_ARTIFACT_ID, created_at=_NOW)
    delete = ArtifactDeleteRequest(
        scope=scope,
        artifact_id=_ARTIFACT_ID,
        expected_version=ArtifactVersion(7),
        created_at=_NOW,
    )

    assert str(listing.prefix) == "reports"
    assert listing.max_results == 8
    assert read.artifact_id == _ARTIFACT_ID
    assert delete.expected_version == ArtifactVersion(7)

    with pytest.raises(ValueError):
        ArtifactListRequest(
            scope=scope,
            max_results=MAX_WORKSPACE_LIST_RESULTS + 1,
            created_at=_NOW,
        )


def test_workspace_request_timestamps_must_be_timezone_aware() -> None:
    naive = datetime(2026, 8, 12, 5, 30)

    with pytest.raises(ValueError):
        ArtifactReadRequest(scope=_scope(), artifact_id=_ARTIFACT_ID, created_at=naive)
