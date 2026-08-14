"""Authorized service boundary for secure Phoenix workspace operations."""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime

from phoenix_os.agent.errors import (
    AgentCodecError,
    AgentLimitExceededError,
    AgentServiceUnavailableError,
    AgentStateConflictError,
)
from phoenix_os.agent.workspace_authorization import WorkspaceAuthorizer
from phoenix_os.agent.workspace_contracts import (
    ArtifactDeleteRequest,
    ArtifactDigest,
    ArtifactExportRequest,
    ArtifactImportRequest,
    ArtifactListRequest,
    ArtifactListResult,
    ArtifactLogicalPath,
    ArtifactMediaType,
    ArtifactOriginKind,
    ArtifactProvenance,
    ArtifactReadRequest,
    ArtifactReadResult,
    ArtifactRecord,
    ArtifactStatus,
    ArtifactTransferDirection,
    ArtifactTransferReceipt,
    ArtifactWriteRequest,
    WorkspaceExportPayload,
    WorkspaceExportResult,
    WorkspaceImportResult,
    WorkspaceLimits,
    WorkspaceStore,
    WorkspaceTransferAdapterId,
    WorkspaceTransferReference,
    artifact_content_digest,
)
from phoenix_os.agent.workspace_transfer import WorkspaceTransferAdapter
from phoenix_os.policy import SecurityContext

type Clock = Callable[[], datetime]


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _require_aware(value: datetime, *, label: str) -> None:
    if not isinstance(value, datetime):
        raise TypeError(f"{label} must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")


class AgentWorkspaceService:
    """Authorize every workspace operation before touching data dependencies."""

    def __init__(
        self,
        *,
        store: WorkspaceStore,
        authorizer: WorkspaceAuthorizer,
        transfer_adapter: WorkspaceTransferAdapter | None = None,
        limits: WorkspaceLimits | None = None,
        clock: Clock = _utc_now,
    ) -> None:
        if not isinstance(store, WorkspaceStore):
            raise TypeError("store must implement WorkspaceStore")
        if not isinstance(authorizer, WorkspaceAuthorizer):
            raise TypeError("authorizer must implement WorkspaceAuthorizer")
        if transfer_adapter is not None and not isinstance(
            transfer_adapter, WorkspaceTransferAdapter
        ):
            raise TypeError("transfer_adapter must implement WorkspaceTransferAdapter")
        if limits is not None and not isinstance(limits, WorkspaceLimits):
            raise TypeError("limits must be WorkspaceLimits or None")
        configured_limits = store.limits if limits is None else limits
        if not isinstance(configured_limits, WorkspaceLimits):
            raise TypeError("store limits must be WorkspaceLimits")
        if configured_limits != store.limits:
            raise ValueError("service limits must match authoritative store limits")
        if not callable(clock):
            raise TypeError("clock must be callable")
        self._store = store
        self._authorizer = authorizer
        self._transfer_adapter = transfer_adapter
        self._limits = configured_limits
        self._clock = clock
        self._closed = False

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def limits(self) -> WorkspaceLimits:
        return self._limits

    async def list(
        self,
        request: ArtifactListRequest,
        context: SecurityContext,
    ) -> ArtifactListResult:
        self._require_request_context(request, ArtifactListRequest, context)
        self._ensure_open()
        await self._authorizer.authorize_list(request, context)
        return await self._store.list(request)

    async def read(
        self,
        request: ArtifactReadRequest,
        context: SecurityContext,
    ) -> ArtifactReadResult | None:
        self._require_request_context(request, ArtifactReadRequest, context)
        self._ensure_open()
        await self._authorizer.authorize_read(request, context)
        return await self._store.read(request)

    async def write(
        self,
        request: ArtifactWriteRequest,
        context: SecurityContext,
    ) -> ArtifactRecord:
        self._require_request_context(request, ArtifactWriteRequest, context)
        self._ensure_open()
        await self._authorizer.authorize_write(request, context)
        return await self._store.write(request)

    async def delete(
        self,
        request: ArtifactDeleteRequest,
        context: SecurityContext,
    ) -> None:
        self._require_request_context(request, ArtifactDeleteRequest, context)
        self._ensure_open()
        await self._authorizer.authorize_delete(request, context)
        await self._store.delete(request)

    async def import_artifact(
        self,
        request: ArtifactImportRequest,
        context: SecurityContext,
    ) -> ArtifactTransferReceipt:
        self._require_request_context(request, ArtifactImportRequest, context)
        self._ensure_open()
        self._require_not_future(request.created_at)

        # Import is its own authority. The source cannot be touched before the
        # first exact policy decision and this path intentionally bypasses write().
        await self._authorizer.authorize_import(
            request.scope,
            request.artifact_id,
            context,
            created_at=request.created_at,
        )
        adapter, adapter_id = self._require_transfer_adapter()
        imported = await self._call_import_adapter(
            adapter,
            request.source_reference,
            max_bytes=self._limits.max_artifact_bytes,
        )
        validated = self._validated_import_result(imported)

        mutation_time = self._now()
        await self._authorizer.authorize_import(
            request.scope,
            request.artifact_id,
            context,
            created_at=mutation_time,
        )
        # Runtime shutdown may close this boundary while a cancellation-suppressing
        # source adapter is still returning. Never begin an authoritative mutation
        # after the service has been closed.
        self._ensure_open()
        write_request = ArtifactWriteRequest(
            scope=request.scope,
            artifact_id=request.artifact_id,
            logical_path=validated.logical_path,
            content=validated.content,
            media_type=validated.media_type,
            metadata=validated.metadata,
            provenance=ArtifactProvenance(
                origin=ArtifactOriginKind.IMPORT,
                content_digest=validated.content_digest,
                created_at=mutation_time,
                source_version=validated.source_version,
                attributes={"transfer_adapter_id": adapter_id.value},
            ),
            expected_version=request.expected_version,
            created_at=mutation_time,
        )
        record = await self._store.write(write_request)
        self._require_exact_written_record(record, write_request)
        # WorkspaceStore.write owns the authoritative cancellation boundary. No
        # await occurs after it returns a committed record.
        return ArtifactTransferReceipt(
            direction=ArtifactTransferDirection.IMPORT,
            scope=record.scope,
            artifact_id=record.artifact_id,
            version=record.version,
            content_digest=record.content_digest,
            byte_length=record.byte_length,
            adapter_id=adapter_id,
            completed_at=record.updated_at,
            transfer_reference=validated.transfer_reference,
        )

    async def export_artifact(
        self,
        request: ArtifactExportRequest,
        context: SecurityContext,
    ) -> ArtifactTransferReceipt:
        self._require_request_context(request, ArtifactExportRequest, context)
        self._ensure_open()
        self._require_not_future(request.created_at)

        # Export authority permits this one transfer but never exposes read() as
        # a public capability. Denial occurs before the store or adapter is used.
        await self._authorizer.authorize_export(
            request.scope,
            request.artifact_id,
            context,
            created_at=request.created_at,
        )
        adapter, adapter_id = self._require_transfer_adapter()
        loaded = await self._store.read(
            ArtifactReadRequest(
                scope=request.scope,
                artifact_id=request.artifact_id,
                created_at=request.created_at,
            )
        )
        if loaded is None:
            raise AgentStateConflictError()
        initial_record, initial_content = self._require_exact_read_result(loaded, request)
        if initial_record.version != request.expected_version:
            raise AgentStateConflictError()

        side_effect_time = self._now()
        await self._authorizer.authorize_export(
            request.scope,
            request.artifact_id,
            context,
            created_at=side_effect_time,
        )
        admission_time = self._now()
        admitted = await self._store.read(
            ArtifactReadRequest(
                scope=request.scope,
                artifact_id=request.artifact_id,
                created_at=admission_time,
            )
        )
        if admitted is None:
            raise AgentStateConflictError()
        record, content = self._require_exact_read_result(admitted, request)
        if record.version != request.expected_version:
            raise AgentStateConflictError()
        if (
            record.version != initial_record.version
            or record.content_digest != initial_record.content_digest
            or record.byte_length != initial_record.byte_length
            or content != initial_content
        ):
            raise AgentStateConflictError()

        # This second authoritative read is the export admission point. It occurs
        # after fresh authorization and no await separates its result from entry
        # into the adapter. No StateStore transaction spans provider I/O.
        # The second authoritative read is complete. Re-check the service
        # boundary immediately before admitting the external export side effect so
        # Runtime shutdown cannot start a new transfer after admission closes.
        self._ensure_open()
        assert record.logical_path is not None
        assert record.media_type is not None
        exported = await self._call_export_adapter(
            adapter,
            WorkspaceExportPayload(
                scope=record.scope,
                artifact_id=record.artifact_id,
                version=record.version,
                logical_path=record.logical_path,
                media_type=record.media_type,
                content_digest=record.content_digest,
                content=content,
                destination_reference=request.destination_reference,
            ),
        )
        # A malformed post-side-effect result is a server-owned adapter contract
        # failure. Fail closed and never retry it automatically in this service.
        transfer_reference = self._validated_export_result(exported)
        # A compliant adapter propagates cancellation only before its side effect
        # commits and returns completion after commit. There is no await between a
        # successful adapter result and this content-free receipt.
        return ArtifactTransferReceipt(
            direction=ArtifactTransferDirection.EXPORT,
            scope=record.scope,
            artifact_id=record.artifact_id,
            version=record.version,
            content_digest=record.content_digest,
            byte_length=record.byte_length,
            adapter_id=adapter_id,
            completed_at=self._now(),
            transfer_reference=transfer_reference,
        )

    async def close(self) -> None:
        """Close only this boundary; dependency ownership remains server-side."""

        self._closed = True

    @staticmethod
    def _require_request_context(
        request: object,
        request_type: type[object],
        context: SecurityContext,
    ) -> None:
        if not isinstance(request, request_type):
            raise TypeError(f"request must be {request_type.__name__}")
        if not isinstance(context, SecurityContext):
            raise TypeError("context must be SecurityContext")

    def _require_not_future(self, created_at: datetime) -> None:
        if created_at > self._now():
            raise AgentStateConflictError()

    def _now(self) -> datetime:
        value = self._clock()
        _require_aware(value, label="clock result")
        return value

    def _ensure_open(self) -> None:
        if self._closed:
            raise AgentServiceUnavailableError()

    def _require_transfer_adapter(
        self,
    ) -> tuple[WorkspaceTransferAdapter, WorkspaceTransferAdapterId]:
        adapter = self._transfer_adapter
        if adapter is None:
            raise AgentServiceUnavailableError()
        try:
            closed = adapter.closed
        except Exception:
            raise AgentServiceUnavailableError() from None
        if not isinstance(closed, bool):
            raise AgentCodecError("workspace transfer adapter is invalid")
        if closed:
            raise AgentServiceUnavailableError()
        try:
            configured_id = adapter.adapter_id
        except Exception:
            raise AgentServiceUnavailableError() from None
        try:
            if not isinstance(configured_id, WorkspaceTransferAdapterId):
                raise TypeError
            adapter_id = WorkspaceTransferAdapterId(configured_id.value)
        except Exception:
            raise AgentCodecError("workspace transfer adapter is invalid") from None
        return adapter, adapter_id

    @staticmethod
    async def _call_import_adapter(
        adapter: WorkspaceTransferAdapter,
        source_reference: WorkspaceTransferReference,
        *,
        max_bytes: int,
    ) -> WorkspaceImportResult:
        try:
            return await adapter.import_artifact(
                source_reference,
                max_bytes=max_bytes,
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            raise AgentServiceUnavailableError() from None

    @staticmethod
    async def _call_export_adapter(
        adapter: WorkspaceTransferAdapter,
        payload: WorkspaceExportPayload,
    ) -> WorkspaceExportResult:
        try:
            return await adapter.export_artifact(payload)
        except asyncio.CancelledError:
            raise
        except Exception:
            raise AgentServiceUnavailableError() from None

    def _validated_import_result(
        self,
        result: WorkspaceImportResult,
    ) -> _ValidatedImport:
        if not isinstance(result, WorkspaceImportResult):
            raise AgentCodecError("workspace import result is invalid")

        # Copy every provider-controlled property into exact Phoenix-owned base
        # values before interpreting it. Even an AgentCodecError raised by a
        # malicious getter is untrusted here and must be replaced, not preserved.
        try:
            external_digest = result.external_digest
            source_version = result.source_version
            revalidated = WorkspaceImportResult(
                content=bytes(result.content),
                logical_path=str(result.logical_path),
                media_type=str(result.media_type),
                metadata=dict(result.metadata),
                external_digest=(None if external_digest is None else str(external_digest)),
                source_version=(None if source_version is None else str(source_version)),
                transfer_reference=_copy_transfer_reference(result.transfer_reference),
            )
        except Exception:
            raise AgentCodecError("workspace import result is invalid") from None

        # From this point onward all data belongs to exact Phoenix contracts. A
        # valid but divergent external digest gets its distinct safe error only
        # after the untrusted boundary has been crossed.
        try:
            content = bytes(revalidated.content)
            digest = artifact_content_digest(content)
            claimed_digest = (
                None
                if revalidated.external_digest is None
                else ArtifactDigest(revalidated.external_digest)
            )
            logical_path = ArtifactLogicalPath(revalidated.logical_path)
            media_type = ArtifactMediaType(revalidated.media_type)
            metadata = dict(revalidated.metadata)
            source_version = revalidated.source_version
            transfer_reference = _copy_transfer_reference(revalidated.transfer_reference)
        except Exception:
            raise AgentCodecError("workspace import result is invalid") from None
        if claimed_digest is not None and claimed_digest != digest:
            raise AgentCodecError("workspace import digest is invalid")
        if len(content) > self._limits.max_artifact_bytes:
            raise AgentLimitExceededError()
        if (
            len(logical_path.value.encode("utf-8")) > self._limits.max_logical_path_bytes
            or len(logical_path.segments) > self._limits.max_logical_path_segments
        ):
            raise AgentLimitExceededError()
        return _ValidatedImport(
            content=content,
            logical_path=logical_path,
            media_type=media_type,
            metadata=metadata,
            content_digest=digest,
            source_version=source_version,
            transfer_reference=transfer_reference,
        )

    @staticmethod
    def _validated_export_result(
        result: WorkspaceExportResult,
    ) -> WorkspaceTransferReference | None:
        if not isinstance(result, WorkspaceExportResult):
            raise AgentCodecError("workspace export result is invalid")
        try:
            revalidated = WorkspaceExportResult(transfer_reference=result.transfer_reference)
            return _copy_transfer_reference(revalidated.transfer_reference)
        except Exception:
            raise AgentCodecError("workspace export result is invalid") from None

    @staticmethod
    def _require_exact_written_record(
        record: ArtifactRecord,
        request: ArtifactWriteRequest,
    ) -> None:
        if (
            not isinstance(record, ArtifactRecord)
            or record.status is not ArtifactStatus.ACTIVE
            or record.scope != request.scope
            or record.artifact_id != request.artifact_id
            or record.logical_path != request.logical_path
            or record.content_digest != request.provenance.content_digest
            or record.byte_length != len(request.content)
        ):
            raise AgentCodecError("workspace authoritative result is invalid")

    def _require_exact_read_result(
        self,
        result: ArtifactReadResult,
        request: ArtifactExportRequest,
    ) -> tuple[ArtifactRecord, bytes]:
        if not isinstance(result, ArtifactReadResult):
            raise AgentCodecError("workspace authoritative result is invalid")
        record = result.record
        content = result.content
        if (
            record.status is not ArtifactStatus.ACTIVE
            or record.scope != request.scope
            or record.artifact_id != request.artifact_id
            or record.byte_length != len(content)
            or record.byte_length > self._limits.max_artifact_bytes
            or artifact_content_digest(content) != record.content_digest
        ):
            raise AgentCodecError("workspace authoritative result is invalid")
        return record, content


@dataclass(frozen=True, slots=True)
class _ValidatedImport:
    content: bytes
    logical_path: ArtifactLogicalPath
    media_type: ArtifactMediaType
    metadata: Mapping[str, str]
    content_digest: ArtifactDigest
    source_version: str | None
    transfer_reference: WorkspaceTransferReference | None


def _copy_transfer_reference(
    value: WorkspaceTransferReference | None,
) -> WorkspaceTransferReference | None:
    if value is None:
        return None
    if not isinstance(value, WorkspaceTransferReference):
        raise TypeError
    return WorkspaceTransferReference(value.value)
