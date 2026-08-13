from dataclasses import FrozenInstanceError
from datetime import UTC, datetime
from types import MappingProxyType
from uuid import UUID

import pytest

from phoenix_os.agent import (
    AgentId,
    ArtifactExportRequest,
    ArtifactId,
    ArtifactImportRequest,
    ArtifactLogicalPath,
    ArtifactMediaType,
    ArtifactTransferDirection,
    ArtifactTransferReceipt,
    ArtifactVersion,
    WorkspaceExportPayload,
    WorkspaceExportResult,
    WorkspaceImportResult,
    WorkspaceNamespace,
    WorkspaceScope,
    WorkspaceTransferAdapter,
    WorkspaceTransferAdapterId,
    WorkspaceTransferReference,
    agent_workspace_scope,
    artifact_content_digest,
)

_NOW = datetime(2026, 8, 12, 15, tzinfo=UTC)
_ARTIFACT_ID = ArtifactId(UUID("90000000-0000-0000-0000-000000000031"))


def _scope() -> WorkspaceScope:
    return agent_workspace_scope(
        namespace=WorkspaceNamespace("default"),
        agent_id=AgentId("researcher"),
    )


class _Adapter:
    adapter_id = WorkspaceTransferAdapterId("reviewed-transfer")
    closed = False

    async def import_artifact(
        self,
        source_reference: WorkspaceTransferReference,
        *,
        max_bytes: int,
    ) -> WorkspaceImportResult:
        assert max_bytes > 0
        return WorkspaceImportResult(
            content=b"imported",
            logical_path="reports/import.txt",
        )

    async def export_artifact(
        self,
        payload: WorkspaceExportPayload,
    ) -> WorkspaceExportResult:
        return WorkspaceExportResult()


def test_transfer_requests_are_immutable_exact_and_path_free() -> None:
    source = WorkspaceTransferReference("source-object-42")
    destination = WorkspaceTransferReference("destination-slot-7")
    imported = ArtifactImportRequest(
        scope=_scope(),
        artifact_id=_ARTIFACT_ID,
        source_reference=source,
        created_at=_NOW,
    )
    exported = ArtifactExportRequest(
        scope=_scope(),
        artifact_id=_ARTIFACT_ID,
        expected_version=ArtifactVersion(3),
        destination_reference=destination,
        created_at=_NOW,
    )

    assert imported.source_reference == source
    assert exported.destination_reference == destination
    assert exported.expected_version == ArtifactVersion(3)
    with pytest.raises(FrozenInstanceError):
        imported.artifact_id = ArtifactId()  # type: ignore[misc]

    for unsafe in (
        "C:/private/export.bin",
        r"C:\private\export.bin",
        "/var/private/export.bin",
        "https://provider.invalid/object",
        "../escape",
        "agent:researcher",
        "principal:owner",
        "credential:token",
        "policy:grant",
        "approval:reusable",
        "scope/run-42",
    ):
        with pytest.raises(ValueError):
            WorkspaceTransferReference(unsafe)
    with pytest.raises(ValueError):
        WorkspaceTransferReference("x" * 513)
    with pytest.raises(ValueError):
        WorkspaceTransferAdapterId("x" * 129)
    with pytest.raises(ValueError):
        ArtifactImportRequest(
            scope=_scope(),
            artifact_id=_ARTIFACT_ID,
            source_reference=source,
            created_at=datetime(2026, 8, 12, 15),
        )
    assert not hasattr(exported, "adapter_id")
    assert not hasattr(exported, "credential")
    assert not hasattr(exported, "host_root")


def test_transfer_results_and_receipts_are_bounded_immutable_and_content_free() -> None:
    content = b"provider-neutral bytes"
    digest = artifact_content_digest(content)
    imported = WorkspaceImportResult(
        content=content,
        logical_path="reports/result.txt",
        media_type="text/plain",
        metadata={"kind": "report"},
        external_digest=str(digest),
        source_version="etag-4",
        transfer_reference=WorkspaceTransferReference("provider-receipt-4"),
    )
    receipt = ArtifactTransferReceipt(
        direction=ArtifactTransferDirection.IMPORT,
        scope=_scope(),
        artifact_id=_ARTIFACT_ID,
        version=ArtifactVersion(),
        content_digest=digest,
        byte_length=len(content),
        adapter_id=WorkspaceTransferAdapterId("reviewed-transfer"),
        completed_at=_NOW,
        transfer_reference=WorkspaceTransferReference("provider-receipt-4"),
    )

    assert imported.metadata == {"kind": "report"}
    assert isinstance(imported.metadata, MappingProxyType)
    assert not hasattr(receipt, "content")
    assert not hasattr(receipt, "logical_path")
    assert content.decode() not in repr(receipt)
    with pytest.raises(FrozenInstanceError):
        receipt.byte_length = 0  # type: ignore[misc]


def test_export_payload_binds_exact_content_digest_and_destination_reference() -> None:
    content = b"exact export bytes"
    payload = WorkspaceExportPayload(
        scope=_scope(),
        artifact_id=_ARTIFACT_ID,
        version=ArtifactVersion(2),
        logical_path=ArtifactLogicalPath("reports/result.txt"),
        media_type=ArtifactMediaType("text/plain"),
        content_digest=artifact_content_digest(content),
        content=content,
        destination_reference=WorkspaceTransferReference("reviewed-destination"),
    )

    assert payload.byte_length == len(content)
    assert payload.destination_reference == WorkspaceTransferReference("reviewed-destination")
    with pytest.raises(ValueError, match="digest"):
        WorkspaceExportPayload(
            scope=payload.scope,
            artifact_id=payload.artifact_id,
            version=payload.version,
            logical_path=payload.logical_path,
            media_type=payload.media_type,
            content_digest=artifact_content_digest(b"substituted"),
            content=content,
            destination_reference=payload.destination_reference,
        )


def test_transfer_adapter_is_structural_and_server_owned() -> None:
    adapter = _Adapter()

    assert isinstance(adapter, WorkspaceTransferAdapter)
    assert adapter.adapter_id == WorkspaceTransferAdapterId("reviewed-transfer")
