from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from phoenix_os.agent.contracts import (
    AgentId,
    AgentRunId,
    AgentStepId,
    ToolCallId,
    ToolId,
    ToolInvocationRequest,
)
from phoenix_os.agent.errors import AgentAuthorizationRejectedError
from phoenix_os.agent.memory_agent_tools import (
    MemoryAgentToolBinding,
    MemoryToolAdapter,
    memory_tool_resolver,
)
from phoenix_os.agent.memory_authorization import (
    MEMORY_WRITE_ACTION,
    agent_memory_scope,
)
from phoenix_os.agent.memory_contracts import (
    MemoryDeleteRequest,
    MemoryNamespace,
    MemoryReadRequest,
    MemoryScope,
    MemoryScopeKind,
    MemorySearchRequest,
    MemoryWriteRequest,
)
from phoenix_os.agent.memory_retrieval import (
    AgentMemoryService,
    DeterministicLexicalMemoryRetrievalAdapter,
)
from phoenix_os.agent.memory_store import InMemoryAgentMemoryStore
from phoenix_os.agent.tools import ToolResourceResolutionContext
from phoenix_os.host_automation.agent_control_tools import (
    HOST_CLIPBOARD_WRITE_TOOL_ID,
    HostClipboardReadToolAdapter,
    HostClipboardWriteToolAdapter,
    HostEpochBoundToolAdapter,
)
from phoenix_os.host_automation.authorization import (
    PolicyEngineHostAutomationAuthorizer,
    host_clipboard_resource,
)
from phoenix_os.host_automation.contracts import (
    HostAutomationLimits,
    HostClipboardReadRequest,
    HostId,
)
from phoenix_os.host_automation.fake import DeterministicHostAutomationAdapter
from phoenix_os.host_automation.service import HostAutomationService
from phoenix_os.policy import (
    PolicyEffect,
    PolicyEngine,
    PolicyRule,
    PrincipalType,
    SecurityContext,
)

_NOW = datetime(2026, 8, 27, 21, tzinfo=UTC)


class _AllowMemoryAuthorizer:
    def __init__(self) -> None:
        self.write_calls = 0

    async def authorize_search(
        self,
        request: MemorySearchRequest,
        context: SecurityContext,
    ) -> None:
        del request
        assert context.authenticated

    async def authorize_read(
        self,
        request: MemoryReadRequest,
        context: SecurityContext,
    ) -> None:
        del request
        assert context.authenticated

    async def authorize_write(
        self,
        request: MemoryWriteRequest,
        context: SecurityContext,
    ) -> None:
        del request
        assert context.authenticated
        self.write_calls += 1

    async def authorize_delete(
        self,
        request: MemoryDeleteRequest,
        context: SecurityContext,
    ) -> None:
        del request
        assert context.authenticated

    async def authorize_admin(
        self,
        scope: MemoryScope,
        context: SecurityContext,
        *,
        created_at: datetime | None = None,
    ) -> None:
        del scope, created_at
        assert context.authenticated


def _context() -> SecurityContext:
    return SecurityContext(
        principal="service:assistant",
        principal_type=PrincipalType.SERVICE,
        authenticated=True,
    )


@pytest.mark.asyncio
async def test_memory_final_admission_runs_after_authorization_before_store_effect() -> None:
    store = InMemoryAgentMemoryStore(clock=lambda: _NOW)
    authorizer = _AllowMemoryAuthorizer()
    service = AgentMemoryService(
        store=store,
        authorizer=authorizer,
        retrieval=DeterministicLexicalMemoryRetrievalAdapter(store),
        clock=lambda: _NOW,
    )
    agent_id = AgentId("assistant")
    run_id = AgentRunId(UUID(int=401))
    step_id = AgentStepId(UUID(int=402))
    binding = MemoryAgentToolBinding(
        agent_id=agent_id,
        tool_id=ToolId("memory.write"),
        namespace=MemoryNamespace("integrated"),
        scope_kind=MemoryScopeKind.AGENT,
        action=MEMORY_WRITE_ACTION,
    )
    arguments = {
        "memory_id": str(UUID(int=403)),
        "content": "reviewed memory",
    }
    resource = memory_tool_resolver(binding).resolve_resource_with_context(
        arguments,
        ToolResourceResolutionContext(
            agent_id=agent_id,
            run_id=run_id,
            step_id=step_id,
        ),
    )
    request = ToolInvocationRequest(
        agent_id=agent_id,
        run_id=run_id,
        step_id=step_id,
        call_id=ToolCallId(UUID(int=404)),
        tool_id=binding.tool_id,
        arguments=arguments,
        resolved_resource=resource,
        created_at=_NOW,
        deadline=_NOW + timedelta(minutes=1),
    )
    callback_calls = 0

    async def deny_final_admission() -> None:
        nonlocal callback_calls
        callback_calls += 1
        assert authorizer.write_calls == 1
        raise AgentAuthorizationRejectedError()

    with pytest.raises(AgentAuthorizationRejectedError):
        await MemoryToolAdapter(
            service,
            binding,
        ).invoke_with_context_and_final_admission(
            request,
            _context(),
            deny_final_admission,
        )

    assert callback_calls == 1
    scope = agent_memory_scope(namespace=binding.namespace, agent_id=agent_id)
    assert await store.list_scope(scope, limit=1) == ()


@pytest.mark.asyncio
async def test_host_final_admission_runs_after_host_auth_before_native_effect() -> None:
    host_id = HostId("integrated-host")
    limits = HostAutomationLimits(operation_timeout=timedelta(seconds=30))
    native = DeterministicHostAutomationAdapter(
        host_id=host_id,
        limits=limits,
        clipboard_text="original",
    )
    service = HostAutomationService(
        adapter=native,
        authorizer=PolicyEngineHostAutomationAuthorizer(
            PolicyEngine((PolicyRule("allow", PolicyEffect.ALLOW),))
        ),
    )
    adapter = HostClipboardWriteToolAdapter(
        service,
        host_id=host_id,
        limits=limits,
    )
    read_adapter = HostClipboardReadToolAdapter(
        service,
        host_id=host_id,
        limits=limits,
    )
    assert service.host_epoch == native.host_epoch
    assert adapter.host_epoch == native.host_epoch
    assert read_adapter.host_epoch == native.host_epoch
    assert isinstance(adapter, HostEpochBoundToolAdapter)
    assert isinstance(read_adapter, HostEpochBoundToolAdapter)
    request = ToolInvocationRequest(
        agent_id=AgentId("assistant"),
        run_id=AgentRunId(UUID(int=411)),
        step_id=AgentStepId(UUID(int=412)),
        call_id=ToolCallId(UUID(int=413)),
        tool_id=HOST_CLIPBOARD_WRITE_TOOL_ID,
        arguments={"text": "blocked"},
        resolved_resource=host_clipboard_resource(host_id),
        created_at=_NOW,
        deadline=_NOW + timedelta(minutes=1),
    )
    callback_calls = 0

    async def deny_final_admission() -> None:
        nonlocal callback_calls
        callback_calls += 1
        raise AgentAuthorizationRejectedError()

    with pytest.raises(AgentAuthorizationRejectedError):
        await adapter.invoke_with_context_and_final_admission(
            request,
            _context(),
            deny_final_admission,
        )

    assert callback_calls == 1
    read = await service.read_clipboard(
        HostClipboardReadRequest(host_id=host_id, created_at=_NOW),
        _context(),
    )
    assert read.text == "original"


@pytest.mark.asyncio
async def test_memory_write_persists_final_admission_lineage_attributes() -> None:
    from phoenix_os.agent.memory_contracts import (
        MemoryId,
        MemoryOriginKind,
        MemoryProvenance,
        memory_content_digest,
    )
    from phoenix_os.agent.tools import ToolFinalAdmissionGrant

    store = InMemoryAgentMemoryStore(clock=lambda: _NOW)
    service = AgentMemoryService(
        store=store,
        authorizer=_AllowMemoryAuthorizer(),
        retrieval=DeterministicLexicalMemoryRetrievalAdapter(store),
        clock=lambda: _NOW,
    )
    scope = agent_memory_scope(
        namespace=MemoryNamespace("integrated"),
        agent_id=AgentId("assistant"),
    )
    content = "persisted reviewed memory"
    request = MemoryWriteRequest(
        scope=scope,
        memory_id=MemoryId(UUID(int=421)),
        content=content,
        provenance=MemoryProvenance(
            origin=MemoryOriginKind.AGENT_REQUEST,
            content_digest=memory_content_digest(content),
            attributes={"tool_id": "memory.write"},
            created_at=_NOW,
        ),
        created_at=_NOW,
    )

    async def final_admission() -> ToolFinalAdmissionGrant:
        return ToolFinalAdmissionGrant(
            provenance_attributes={
                "rfc0036.provenance.00": "opaque-lineage",
            }
        )

    record = await service.write(
        request,
        _context(),
        final_admission=final_admission,
    )

    assert record.provenance is not None
    assert record.provenance.attributes["tool_id"] == "memory.write"
    assert record.provenance.attributes["rfc0036.provenance.00"] == "opaque-lineage"


@pytest.mark.asyncio
async def test_memory_read_reports_persisted_lineage_only_after_authorized_read() -> None:
    from phoenix_os.agent.memory_contracts import (
        MemoryId,
        MemoryOriginKind,
        MemoryProvenance,
        MemoryReadRequest,
        memory_content_digest,
    )
    from phoenix_os.agent.tools import ToolFinalAdmissionContext
    from phoenix_os.integrated_agent.contracts import (
        IntegratedDataProvenance,
        IntegratedDataProvenanceAtom,
        IntegratedDataSourceKind,
    )
    from phoenix_os.integrated_agent.data_flow import (
        integrated_provenance_to_persistence_attributes,
    )

    store = InMemoryAgentMemoryStore(clock=lambda: _NOW)
    service = AgentMemoryService(
        store=store,
        authorizer=_AllowMemoryAuthorizer(),
        retrieval=DeterministicLexicalMemoryRetrievalAdapter(store),
        clock=lambda: _NOW,
    )
    scope = agent_memory_scope(
        namespace=MemoryNamespace("integrated"),
        agent_id=AgentId("assistant"),
    )
    memory_id = MemoryId(UUID(int=451))
    content = "persisted lineage read"
    persisted = IntegratedDataProvenance(
        (
            IntegratedDataProvenanceAtom(
                source_kind=IntegratedDataSourceKind.NETWORK,
                source_binding="network:profile/research/generation:3/operation:fetch",
                freshness_bindings=("profile-generation:3",),
            ),
        )
    )
    attributes = {
        "tool_id": "memory.write",
        **dict(integrated_provenance_to_persistence_attributes(persisted)),
    }
    written = await service.write(
        MemoryWriteRequest(
            scope=scope,
            memory_id=memory_id,
            content=content,
            provenance=MemoryProvenance(
                origin=MemoryOriginKind.AGENT_REQUEST,
                content_digest=memory_content_digest(content),
                attributes=attributes,
                created_at=_NOW,
            ),
            created_at=_NOW,
        ),
        _context(),
    )
    assert written.provenance is not None

    captured: ToolFinalAdmissionContext | None = None

    async def final_admission(
        details: ToolFinalAdmissionContext | None = None,
    ) -> None:
        nonlocal captured
        captured = details

    loaded = await service.read(
        MemoryReadRequest(
            scope=scope,
            memory_id=memory_id,
            created_at=_NOW,
        ),
        _context(),
        final_admission=final_admission,
    )

    assert loaded == written
    assert captured is not None
    assert captured.source_provenance_attributes == (written.provenance.attributes,)
