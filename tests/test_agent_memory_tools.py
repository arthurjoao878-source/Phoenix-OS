from __future__ import annotations

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
from phoenix_os.agent.memory_agent_tools import (
    MemoryAgentToolBinding,
    MemoryToolAdapter,
    memory_tool_binding_id,
    memory_tool_descriptor,
    memory_tool_resolver,
)
from phoenix_os.agent.memory_authorization import (
    MEMORY_DELETE_ACTION,
    MEMORY_READ_ACTION,
    MEMORY_SEARCH_ACTION,
    MEMORY_WRITE_ACTION,
    agent_memory_scope,
    memory_scope_resource,
    principal_memory_scope,
)
from phoenix_os.agent.memory_contracts import (
    MemoryDeleteRequest,
    MemoryLimits,
    MemoryNamespace,
    MemoryOriginKind,
    MemoryReadRequest,
    MemoryRecord,
    MemoryRecordIncarnation,
    MemoryRecordStatus,
    MemoryRecordVersion,
    MemoryScopeKind,
    MemorySearchRequest,
    MemorySearchResult,
    MemoryWriteRequest,
)
from phoenix_os.agent.memory_retrieval import (
    AgentMemoryService,
    MemoryFinalAdmissionValidator,
)
from phoenix_os.agent.registry import ToolRegistry
from phoenix_os.agent.tools import ToolResourceResolutionContext
from phoenix_os.policy import PrincipalType, SecurityContext

_NOW = datetime(2026, 8, 27, 12, 0, tzinfo=UTC)
_AGENT_ID = AgentId("research-agent")
_NAMESPACE = MemoryNamespace("integrated-memory")
_CONTEXT = SecurityContext(
    principal="alice",
    principal_type=PrincipalType.USER,
    authenticated=True,
)


class _MemoryService(AgentMemoryService):
    def __init__(self) -> None:
        self._test_limits = MemoryLimits()
        self.search_request: MemorySearchRequest | None = None
        self.read_request: MemoryReadRequest | None = None
        self.write_request: MemoryWriteRequest | None = None
        self.delete_request: MemoryDeleteRequest | None = None
        self.context: SecurityContext | None = None

    @property
    def limits(self) -> MemoryLimits:
        return self._test_limits

    async def search(
        self,
        request: MemorySearchRequest,
        context: SecurityContext,
        *,
        final_admission: MemoryFinalAdmissionValidator | None = None,
    ) -> MemorySearchResult:
        if final_admission is not None:
            await final_admission()
        self.search_request = request
        self.context = context
        return MemorySearchResult(scope=request.scope, hits=(), created_at=request.created_at)

    async def read(
        self,
        request: MemoryReadRequest,
        context: SecurityContext,
        *,
        final_admission: MemoryFinalAdmissionValidator | None = None,
    ) -> MemoryRecord | None:
        if final_admission is not None:
            await final_admission()
        self.read_request = request
        self.context = context
        return None

    async def write(
        self,
        request: MemoryWriteRequest,
        context: SecurityContext,
        *,
        final_admission: MemoryFinalAdmissionValidator | None = None,
    ) -> MemoryRecord:
        if final_admission is not None:
            await final_admission()
        self.write_request = request
        self.context = context
        incarnation = request.expected_incarnation or MemoryRecordIncarnation(UUID(int=8))
        version = (
            request.expected_version.next()
            if request.expected_version is not None
            else MemoryRecordVersion(1)
        )
        return MemoryRecord(
            scope=request.scope,
            memory_id=request.memory_id,
            incarnation=incarnation,
            version=version,
            status=MemoryRecordStatus.ACTIVE,
            content_digest=request.provenance.content_digest,
            created_at=request.created_at,
            updated_at=request.created_at,
            expires_at=request.created_at + timedelta(days=1),
            content=request.content,
            provenance=request.provenance,
        )

    async def delete(
        self,
        request: MemoryDeleteRequest,
        context: SecurityContext,
        *,
        final_admission: MemoryFinalAdmissionValidator | None = None,
    ) -> None:
        if final_admission is not None:
            await final_admission()
        self.delete_request = request
        self.context = context


def _binding(
    action: str,
    *,
    scope_kind: MemoryScopeKind = MemoryScopeKind.AGENT,
) -> MemoryAgentToolBinding:
    return MemoryAgentToolBinding(
        agent_id=_AGENT_ID,
        tool_id=ToolId(f"integrated.{action}"),
        namespace=_NAMESPACE,
        scope_kind=scope_kind,
        action=action,
    )


def _request(
    binding: MemoryAgentToolBinding,
    arguments: dict[str, AgentJsonInput],
) -> ToolInvocationRequest:
    run_id = AgentRunId(UUID(int=1))
    step_id = AgentStepId(UUID(int=2))
    resolver = memory_tool_resolver(binding)
    validated = freeze_agent_json_object(arguments)
    resource = resolver.resolve_resource_with_context(
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
        call_id=ToolCallId(UUID(int=3)),
        tool_id=binding.tool_id,
        arguments=arguments,
        resolved_resource=resource,
        created_at=_NOW,
        deadline=_NOW + timedelta(minutes=1),
    )


def test_memory_binding_descriptor_and_resolver_keep_agent_scope_server_owned() -> None:
    binding = _binding(MEMORY_SEARCH_ACTION)
    descriptor = memory_tool_descriptor(binding, MemoryLimits())
    run_id = AgentRunId(UUID(int=1))
    step_id = AgentStepId(UUID(int=2))

    service = _MemoryService()
    registry = ToolRegistry()
    registry.register_tool(
        descriptor,
        resolver=memory_tool_resolver(binding),
        adapter=MemoryToolAdapter(service, binding),
    )
    resource = registry.admit_tool_call(
        binding.tool_id,
        {"query": "supplier"},
        resolution_context=ToolResourceResolutionContext(
            agent_id=_AGENT_ID,
            run_id=run_id,
            step_id=step_id,
        ),
    ).resolved_resource

    assert descriptor.effect is ToolEffect.READ_ONLY
    assert descriptor.tool_id == binding.tool_id
    assert binding.binding_id == memory_tool_binding_id(
        _NAMESPACE,
        MemoryScopeKind.AGENT,
    )
    assert resource == memory_scope_resource(
        agent_memory_scope(namespace=_NAMESPACE, agent_id=_AGENT_ID)
    )


@pytest.mark.asyncio
async def test_memory_principal_scope_is_derived_only_from_security_context() -> None:
    service = _MemoryService()
    binding = _binding(
        MEMORY_SEARCH_ACTION,
        scope_kind=MemoryScopeKind.PRINCIPAL,
    )
    request = _request(binding, {"query": "supplier"})

    result = await MemoryToolAdapter(service, binding).invoke_with_context(
        request,
        _CONTEXT,
    )

    assert result.status is ToolResultStatus.SUCCEEDED
    assert result.output == {"records": ()}
    assert service.search_request is not None
    assert service.search_request.scope == principal_memory_scope(
        namespace=_NAMESPACE,
        context=_CONTEXT,
    )
    assert request.resolved_resource == (f"agent-memory:{_NAMESPACE}/scope:principal:current")


@pytest.mark.asyncio
async def test_memory_write_derives_provenance_and_preserves_exact_record_identity() -> None:
    service = _MemoryService()
    binding = _binding(MEMORY_WRITE_ACTION, scope_kind=MemoryScopeKind.RUN)
    memory_id = str(UUID(int=4))
    request = _request(
        binding,
        {
            "memory_id": memory_id,
            "content": "reviewed memory",
        },
    )

    result = await MemoryToolAdapter(service, binding).invoke_with_context(
        request,
        _CONTEXT,
    )

    assert result.status is ToolResultStatus.SUCCEEDED
    assert service.write_request is not None
    written = service.write_request
    assert str(written.memory_id) == memory_id
    assert written.scope.kind is MemoryScopeKind.RUN
    assert written.scope.scope_id.value == str(request.run_id)
    assert written.provenance.origin is MemoryOriginKind.AGENT_REQUEST
    assert written.provenance.source_run_id == request.run_id
    assert written.provenance.source_agent_id == _AGENT_ID
    assert result.output is not None
    assert result.output["memory_id"] == memory_id


@pytest.mark.asyncio
async def test_memory_read_and_delete_keep_exact_version_incarnation_binding() -> None:
    service = _MemoryService()
    memory_id = str(UUID(int=5))
    incarnation = str(UUID(int=6))

    read_binding = _binding(MEMORY_READ_ACTION)
    read = await MemoryToolAdapter(service, read_binding).invoke_with_context(
        _request(
            read_binding,
            {
                "memory_id": memory_id,
                "expected_version": 7,
                "expected_incarnation": incarnation,
            },
        ),
        _CONTEXT,
    )
    assert read.output == {"found": False}
    assert service.read_request is not None
    assert service.read_request.expected_version == MemoryRecordVersion(7)
    assert service.read_request.expected_incarnation == MemoryRecordIncarnation(UUID(incarnation))

    delete_binding = _binding(MEMORY_DELETE_ACTION)
    deleted = await MemoryToolAdapter(service, delete_binding).invoke_with_context(
        _request(
            delete_binding,
            {
                "memory_id": memory_id,
                "expected_version": 7,
                "expected_incarnation": incarnation,
            },
        ),
        _CONTEXT,
    )
    assert deleted.output == {"deleted": True}
    assert service.delete_request is not None
    assert service.delete_request.expected_version == MemoryRecordVersion(7)
    assert service.delete_request.expected_incarnation == MemoryRecordIncarnation(UUID(incarnation))


@pytest.mark.asyncio
async def test_memory_adapter_rejects_substituted_upstream_resource() -> None:
    service = _MemoryService()
    binding = _binding(MEMORY_SEARCH_ACTION)
    request = _request(binding, {"query": "supplier"})
    substituted = ToolInvocationRequest(
        agent_id=request.agent_id,
        run_id=request.run_id,
        step_id=request.step_id,
        call_id=request.call_id,
        tool_id=request.tool_id,
        arguments=request.arguments,
        resolved_resource="agent-memory:other/scope:agent:research-agent",
        created_at=request.created_at,
        deadline=request.deadline,
    )

    with pytest.raises(ToolExecutionError):
        await MemoryToolAdapter(service, binding).invoke_with_context(
            substituted,
            _CONTEXT,
        )
