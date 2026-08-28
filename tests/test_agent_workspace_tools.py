from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from phoenix_os.agent.contracts import (
    AgentId,
    AgentJsonInput,
    AgentRunId,
    AgentStepId,
    ToolCallId,
    ToolEffect,
    ToolId,
    ToolInvocationRequest,
    ToolResultStatus,
    freeze_agent_json_object,
)
from phoenix_os.agent.errors import ToolExecutionError
from phoenix_os.agent.registry import ToolRegistry
from phoenix_os.agent.tools import (
    ToolFinalAdmissionContext,
    ToolFinalAdmissionValidator,
    ToolResourceResolutionContext,
)
from phoenix_os.agent.workspace_agent_tools import (
    WorkspaceAgentToolBinding,
    WorkspaceToolAdapter,
    workspace_tool_binding_id,
    workspace_tool_descriptor,
    workspace_tool_resolver,
)
from phoenix_os.agent.workspace_authorization import (
    WORKSPACE_DELETE_ACTION,
    WORKSPACE_EXPORT_ACTION,
    WORKSPACE_IMPORT_ACTION,
    WORKSPACE_LIST_ACTION,
    WORKSPACE_READ_ACTION,
    WORKSPACE_WRITE_ACTION,
    agent_workspace_scope,
    principal_workspace_scope,
    workspace_scope_resource,
)
from phoenix_os.agent.workspace_contracts import (
    ArtifactDeleteRequest,
    ArtifactExportRequest,
    ArtifactImportRequest,
    ArtifactListRequest,
    ArtifactListResult,
    ArtifactLogicalPath,
    ArtifactMediaType,
    ArtifactOriginKind,
    ArtifactReadRequest,
    ArtifactReadResult,
    ArtifactRecord,
    ArtifactStatus,
    ArtifactTransferDirection,
    ArtifactTransferReceipt,
    ArtifactVersion,
    ArtifactWriteRequest,
    WorkspaceLimits,
    WorkspaceNamespace,
    WorkspaceScopeKind,
    WorkspaceTransferAdapterId,
    WorkspaceTransferReference,
    artifact_content_digest,
)
from phoenix_os.agent.workspace_service import AgentWorkspaceService
from phoenix_os.policy import PrincipalType, SecurityContext

_NOW = datetime(2026, 8, 27, 12, 0, tzinfo=UTC)
_AGENT_ID = AgentId("research-agent")
_NAMESPACE = WorkspaceNamespace("integrated-workspace")
_CONTEXT = SecurityContext(
    principal="alice",
    principal_type=PrincipalType.USER,
    authenticated=True,
)


class _WorkspaceService(AgentWorkspaceService):
    def __init__(self) -> None:
        self._test_limits = WorkspaceLimits()
        self.list_request: ArtifactListRequest | None = None
        self.read_request: ArtifactReadRequest | None = None
        self.write_request: ArtifactWriteRequest | None = None
        self.delete_request: ArtifactDeleteRequest | None = None
        self.import_request: ArtifactImportRequest | None = None
        self.export_request: ArtifactExportRequest | None = None
        self.context: SecurityContext | None = None

    @property
    def limits(self) -> WorkspaceLimits:
        return self._test_limits

    async def list(
        self,
        request: ArtifactListRequest,
        context: SecurityContext,
        *,
        final_admission: ToolFinalAdmissionValidator | None = None,
    ) -> ArtifactListResult:
        if final_admission is not None:
            await final_admission()
        self.list_request = request
        self.context = context
        return ArtifactListResult(
            scope=request.scope,
            artifacts=(),
            created_at=request.created_at,
        )

    async def read(
        self,
        request: ArtifactReadRequest,
        context: SecurityContext,
        *,
        final_admission: ToolFinalAdmissionValidator | None = None,
    ) -> ArtifactReadResult | None:
        if final_admission is not None:
            await final_admission()
        self.read_request = request
        self.context = context
        return None

    async def write(
        self,
        request: ArtifactWriteRequest,
        context: SecurityContext,
        *,
        final_admission: ToolFinalAdmissionValidator | None = None,
    ) -> ArtifactRecord:
        del final_admission
        self.write_request = request
        self.context = context
        version = (
            request.expected_version.next()
            if request.expected_version is not None
            else ArtifactVersion(1)
        )
        return ArtifactRecord(
            scope=request.scope,
            artifact_id=request.artifact_id,
            version=version,
            status=ArtifactStatus.ACTIVE,
            content_digest=request.provenance.content_digest,
            byte_length=len(request.content),
            created_at=request.created_at,
            updated_at=request.created_at,
            expires_at=request.created_at + timedelta(days=1),
            logical_path=request.logical_path,
            media_type=request.media_type,
            provenance=request.provenance,
        )

    async def delete(
        self,
        request: ArtifactDeleteRequest,
        context: SecurityContext,
        *,
        final_admission: ToolFinalAdmissionValidator | None = None,
    ) -> None:
        del final_admission
        self.delete_request = request
        self.context = context

    async def import_artifact(
        self,
        request: ArtifactImportRequest,
        context: SecurityContext,
        *,
        final_admission: ToolFinalAdmissionValidator | None = None,
    ) -> ArtifactTransferReceipt:
        del final_admission
        self.import_request = request
        self.context = context
        return ArtifactTransferReceipt(
            direction=ArtifactTransferDirection.IMPORT,
            scope=request.scope,
            artifact_id=request.artifact_id,
            version=(
                request.expected_version.next()
                if request.expected_version is not None
                else ArtifactVersion(1)
            ),
            content_digest=artifact_content_digest(b"imported"),
            byte_length=len(b"imported"),
            adapter_id=WorkspaceTransferAdapterId("test-transfer"),
            completed_at=request.created_at,
            transfer_reference=request.source_reference,
        )

    async def export_artifact(
        self,
        request: ArtifactExportRequest,
        context: SecurityContext,
        *,
        final_admission: ToolFinalAdmissionValidator | None = None,
    ) -> ArtifactTransferReceipt:
        del final_admission
        self.export_request = request
        self.context = context
        return ArtifactTransferReceipt(
            direction=ArtifactTransferDirection.EXPORT,
            scope=request.scope,
            artifact_id=request.artifact_id,
            version=request.expected_version,
            content_digest=artifact_content_digest(b"exported"),
            byte_length=len(b"exported"),
            adapter_id=WorkspaceTransferAdapterId("test-transfer"),
            completed_at=request.created_at,
            transfer_reference=request.destination_reference,
        )


def _binding(
    action: str,
    *,
    scope_kind: WorkspaceScopeKind = WorkspaceScopeKind.AGENT,
) -> WorkspaceAgentToolBinding:
    return WorkspaceAgentToolBinding(
        agent_id=_AGENT_ID,
        tool_id=ToolId(f"integrated.{action}"),
        namespace=_NAMESPACE,
        scope_kind=scope_kind,
        action=action,
    )


def _request(
    binding: WorkspaceAgentToolBinding,
    arguments: dict[str, AgentJsonInput],
) -> ToolInvocationRequest:
    run_id = AgentRunId(UUID(int=11))
    step_id = AgentStepId(UUID(int=12))
    validated = freeze_agent_json_object(arguments)
    resource = workspace_tool_resolver(binding).resolve_resource_with_context(
        validated,
        ToolResourceResolutionContext(
            agent_id=_AGENT_ID,
            run_id=run_id,
            step_id=step_id,
        ),
    )
    return ToolInvocationRequest(
        agent_id=_AGENT_ID,
        run_id=run_id,
        step_id=step_id,
        call_id=ToolCallId(UUID(int=13)),
        tool_id=binding.tool_id,
        arguments=arguments,
        resolved_resource=resource,
        created_at=_NOW,
        deadline=_NOW + timedelta(minutes=1),
    )


def test_workspace_binding_descriptor_and_resolver_keep_agent_scope_server_owned() -> None:
    binding = _binding(WORKSPACE_LIST_ACTION)
    descriptor = workspace_tool_descriptor(binding, WorkspaceLimits())
    run_id = AgentRunId(UUID(int=11))
    step_id = AgentStepId(UUID(int=12))

    service = _WorkspaceService()
    registry = ToolRegistry()
    registry.register_tool(
        descriptor,
        resolver=workspace_tool_resolver(binding),
        adapter=WorkspaceToolAdapter(service, binding),
    )
    resource = registry.admit_tool_call(
        binding.tool_id,
        {},
        resolution_context=ToolResourceResolutionContext(
            agent_id=_AGENT_ID,
            run_id=run_id,
            step_id=step_id,
        ),
    ).resolved_resource

    assert descriptor.effect is ToolEffect.READ_ONLY
    assert binding.binding_id == workspace_tool_binding_id(
        _NAMESPACE,
        WorkspaceScopeKind.AGENT,
    )
    assert resource == workspace_scope_resource(
        agent_workspace_scope(namespace=_NAMESPACE, agent_id=_AGENT_ID)
    )


@pytest.mark.asyncio
async def test_workspace_principal_scope_is_derived_only_from_security_context() -> None:
    service = _WorkspaceService()
    binding = _binding(
        WORKSPACE_LIST_ACTION,
        scope_kind=WorkspaceScopeKind.PRINCIPAL,
    )
    request = _request(binding, {})

    result = await WorkspaceToolAdapter(service, binding).invoke_with_context(
        request,
        _CONTEXT,
    )

    assert result.status is ToolResultStatus.SUCCEEDED
    assert result.output == {"artifacts": ()}
    assert service.list_request is not None
    assert service.list_request.scope == principal_workspace_scope(
        namespace=_NAMESPACE,
        context=_CONTEXT,
    )
    assert request.resolved_resource == (f"agent-workspace:{_NAMESPACE}/scope:principal:current")


@pytest.mark.asyncio
async def test_workspace_write_derives_provenance_and_preserves_exact_artifact() -> None:
    service = _WorkspaceService()
    binding = _binding(WORKSPACE_WRITE_ACTION, scope_kind=WorkspaceScopeKind.RUN)
    artifact_id = str(UUID(int=14))
    content = b"reviewed artifact"
    request = _request(
        binding,
        {
            "artifact_id": artifact_id,
            "logical_path": "reports/result.txt",
            "content_base64": base64.b64encode(content).decode("ascii"),
            "media_type": "text/plain",
        },
    )

    result = await WorkspaceToolAdapter(service, binding).invoke_with_context(
        request,
        _CONTEXT,
    )

    assert result.status is ToolResultStatus.SUCCEEDED
    assert service.write_request is not None
    written = service.write_request
    assert str(written.artifact_id) == artifact_id
    assert written.scope.kind is WorkspaceScopeKind.RUN
    assert written.scope.scope_id.value == str(request.run_id)
    assert written.logical_path == ArtifactLogicalPath("reports/result.txt")
    assert written.content == content
    assert written.media_type == ArtifactMediaType("text/plain")
    assert written.provenance.origin is ArtifactOriginKind.AGENT_REQUEST
    assert written.provenance.source_run_id == request.run_id
    assert written.provenance.source_agent_id == _AGENT_ID
    assert result.output is not None
    assert result.output["artifact_id"] == artifact_id


@pytest.mark.asyncio
async def test_workspace_read_uses_exact_artifact_version_and_returns_not_found() -> None:
    service = _WorkspaceService()
    binding = _binding(WORKSPACE_READ_ACTION)
    artifact_id = str(UUID(int=15))
    request = _request(
        binding,
        {
            "artifact_id": artifact_id,
            "expected_version": 7,
        },
    )

    result = await WorkspaceToolAdapter(service, binding).invoke_with_context(
        request,
        _CONTEXT,
    )

    assert result.output == {"found": False}
    assert service.read_request is not None
    assert str(service.read_request.artifact_id) == artifact_id
    assert service.read_request.expected_version == ArtifactVersion(7)


@pytest.mark.asyncio
async def test_workspace_delete_keeps_exact_artifact_version_binding() -> None:
    service = _WorkspaceService()
    binding = _binding(WORKSPACE_DELETE_ACTION)
    artifact_id = str(UUID(int=17))
    request = _request(
        binding,
        {
            "artifact_id": artifact_id,
            "expected_version": 9,
        },
    )

    result = await WorkspaceToolAdapter(service, binding).invoke_with_context(
        request,
        _CONTEXT,
    )

    assert result.output == {"deleted": True}
    assert service.delete_request is not None
    assert str(service.delete_request.artifact_id) == artifact_id
    assert service.delete_request.expected_version == ArtifactVersion(9)


@pytest.mark.asyncio
async def test_workspace_import_and_export_keep_opaque_references_inside_service_boundary() -> None:
    service = _WorkspaceService()
    artifact_id = str(UUID(int=16))

    import_binding = _binding(WORKSPACE_IMPORT_ACTION)
    imported = await WorkspaceToolAdapter(service, import_binding).invoke_with_context(
        _request(
            import_binding,
            {
                "artifact_id": artifact_id,
                "source_reference": "source-item-1",
            },
        ),
        _CONTEXT,
    )
    assert imported.output is not None
    assert imported.output["direction"] == ArtifactTransferDirection.IMPORT.value
    assert service.import_request is not None
    assert service.import_request.source_reference == WorkspaceTransferReference("source-item-1")

    export_binding = _binding(WORKSPACE_EXPORT_ACTION)
    exported = await WorkspaceToolAdapter(service, export_binding).invoke_with_context(
        _request(
            export_binding,
            {
                "artifact_id": artifact_id,
                "expected_version": 3,
                "destination_reference": "destination-item-1",
            },
        ),
        _CONTEXT,
    )
    assert exported.output is not None
    assert exported.output["direction"] == ArtifactTransferDirection.EXPORT.value
    assert service.export_request is not None
    assert service.export_request.destination_reference == WorkspaceTransferReference(
        "destination-item-1"
    )


@pytest.mark.asyncio
async def test_workspace_adapter_rejects_substituted_upstream_resource() -> None:
    service = _WorkspaceService()
    binding = _binding(WORKSPACE_LIST_ACTION)
    request = _request(binding, {})
    substituted = ToolInvocationRequest(
        agent_id=request.agent_id,
        run_id=request.run_id,
        step_id=request.step_id,
        call_id=request.call_id,
        tool_id=request.tool_id,
        arguments=request.arguments,
        resolved_resource="agent-workspace:other/scope:agent:research-agent",
        created_at=request.created_at,
        deadline=request.deadline,
    )

    with pytest.raises(ToolExecutionError):
        await WorkspaceToolAdapter(service, binding).invoke_with_context(
            substituted,
            _CONTEXT,
        )


class _FinalAdmissionWorkspaceService(_WorkspaceService):
    def __init__(self) -> None:
        super().__init__()
        self.final_details: list[ToolFinalAdmissionContext | None] = []

    async def write(
        self,
        request: ArtifactWriteRequest,
        context: SecurityContext,
        *,
        final_admission: ToolFinalAdmissionValidator | None = None,
    ) -> ArtifactRecord:
        if final_admission is not None:
            details = ToolFinalAdmissionContext(mutation_bytes=len(request.content))
            self.final_details.append(details)
            await final_admission(details)
        return await super().write(request, context)


@pytest.mark.asyncio
async def test_workspace_tool_forwards_final_admission_to_effect_boundary() -> None:
    service = _FinalAdmissionWorkspaceService()
    binding = _binding(WORKSPACE_WRITE_ACTION, scope_kind=WorkspaceScopeKind.RUN)
    content = b"bounded final-admission bytes"
    request = _request(
        binding,
        {
            "artifact_id": str(UUID(int=101)),
            "logical_path": "reports/final.txt",
            "content_base64": base64.b64encode(content).decode("ascii"),
            "media_type": "text/plain",
        },
    )
    seen: list[ToolFinalAdmissionContext | None] = []

    async def final_admission(
        details: ToolFinalAdmissionContext | None = None,
    ) -> None:
        seen.append(details)

    result = await WorkspaceToolAdapter(
        service,
        binding,
    ).invoke_with_context_and_final_admission(
        request,
        _CONTEXT,
        final_admission,
    )

    assert result.status is ToolResultStatus.SUCCEEDED
    expected = ToolFinalAdmissionContext(mutation_bytes=len(content))
    assert seen == [expected]
    assert service.final_details == [expected]
