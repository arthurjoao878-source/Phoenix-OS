from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from phoenix_os.agent import (
    MEMORY_WRITE_ACTION,
    AgentId,
    AgentLoop,
    AgentMemoryService,
    AgentMessage,
    AgentMessageRole,
    AgentRunRequest,
    AgentRunStatus,
    BoundedAgentExecutor,
    DeterministicFinalTurn,
    DeterministicLexicalMemoryRetrievalAdapter,
    DeterministicModelTurnAdapter,
    DeterministicToolTurn,
    InMemoryAgentMemoryStore,
    InMemoryToolApprovalService,
    MemoryId,
    MemoryNamespace,
    MemoryOriginKind,
    MemoryProvenance,
    MemoryWriteRequest,
    PolicyEngineAgentRunAuthorizer,
    PolicyEngineMemoryAuthorizer,
    PolicyEngineToolAuthorizer,
    StaticToolResourceResolver,
    ToolApprovalChallenge,
    ToolApprovalEvidence,
    ToolDescriptor,
    ToolEffect,
    ToolExecutionError,
    ToolId,
    ToolInputSchema,
    ToolInvocationRequest,
    ToolInvocationResult,
    ToolOutputSchema,
    ToolRegistry,
    ToolResultStatus,
    ToolSchema,
    ToolSchemaType,
    agent_memory_scope,
    agent_run_resource,
    memory_content_digest,
    memory_record_resource,
)
from phoenix_os.agent.admission import AgentAdmissionController
from phoenix_os.agent.authorization import AgentRunAuthorityBinding
from phoenix_os.agent.configuration import AgentServiceConfiguration, AgentToolConfiguration
from phoenix_os.agent.contracts import AgentRunId, AgentRunResult, AgentStepId
from phoenix_os.agent.coordination import AgentDelegationCoordinator
from phoenix_os.agent.coordination_authorization import (
    AGENT_DELEGATE_ACTION,
    PolicyEngineDelegationAuthorizer,
    agent_delegation_resource,
)
from phoenix_os.agent.coordination_contracts import (
    CoordinationNamespace,
    DelegationBudget,
    DelegationDepth,
    DelegationId,
    DelegationLimits,
    DelegationLineage,
    DelegationLineageEntry,
    DelegationRequest,
)
from phoenix_os.agent.coordination_registry import (
    AgentDelegationRegistry,
    DelegableAgentDescriptor,
)
from phoenix_os.agent.coordination_results import ChildResultStatus
from phoenix_os.agent.coordination_runtime import (
    AgentCoordinationConfiguration,
    AgentCoordinationRuntime,
)
from phoenix_os.agent.durable_authorization import (
    AGENT_RESUME_ACTION,
    PolicyEngineDurableResumeAuthorizer,
    durable_agent_run_resource,
)
from phoenix_os.agent.durable_codec import seal_checkpoint_envelope
from phoenix_os.agent.durable_contracts import (
    CheckpointDigest,
    CheckpointEnvelope,
    CheckpointId,
    CheckpointMetadata,
    CheckpointNextOperation,
    CheckpointPayloadProfile,
    CheckpointSchemaVersion,
    CheckpointSequence,
    CompatibilityDigests,
    DurableAgentRunId,
    DurableLease,
    DurableRunStatus,
    DurableRunVersion,
    ResumeReason,
    ResumeRequest,
)
from phoenix_os.agent.durable_lease import InMemoryDurableLeaseManager
from phoenix_os.agent.errors import AgentAuthorizationRejectedError, AgentServiceUnavailableError
from phoenix_os.agent.service import AgentService
from phoenix_os.agent.state import AgentBudgetSnapshot, AgentCancellationToken
from phoenix_os.agent.workspace_authorization import (
    WORKSPACE_EXPORT_ACTION,
    WORKSPACE_WRITE_ACTION,
    PolicyEngineWorkspaceAuthorizer,
    agent_workspace_scope,
    workspace_artifact_resource,
)
from phoenix_os.agent.workspace_backing import InMemoryWorkspaceBackingAdapter
from phoenix_os.agent.workspace_contracts import (
    ArtifactExportRequest,
    ArtifactId,
    ArtifactLogicalPath,
    ArtifactOriginKind,
    ArtifactProvenance,
    ArtifactReadRequest,
    ArtifactRecord,
    ArtifactTransferReceipt,
    ArtifactWriteRequest,
    WorkspaceExportPayload,
    WorkspaceExportResult,
    WorkspaceImportResult,
    WorkspaceLimits,
    WorkspaceNamespace,
    WorkspaceTransferAdapterId,
    WorkspaceTransferReference,
    artifact_content_digest,
)
from phoenix_os.agent.workspace_service import AgentWorkspaceService
from phoenix_os.agent.workspace_store import StateStoreWorkspaceStore
from phoenix_os.events import EventBus
from phoenix_os.host_automation import (
    HOST_APPLICATION_LAUNCH_ACTION,
    HOST_APPLICATION_LAUNCH_TOOL_ID,
    HOST_CLIPBOARD_WRITE_ACTION,
    HOST_PROCESS_LIST_ACTION,
    HOST_PROCESS_LIST_TOOL_ID,
    DeterministicHostAutomationAdapter,
    HostApplicationId,
    HostApplicationLaunchRequest,
    HostApplicationLaunchResult,
    HostApplicationLaunchToolAdapter,
    HostAutomationLimits,
    HostAutomationService,
    HostClipboardReadRequest,
    HostClipboardWriteRequest,
    HostClipboardWriteResult,
    HostId,
    HostProcessListRequest,
    HostProcessListResult,
    HostProcessListToolAdapter,
    PolicyEngineHostAutomationAuthorizer,
    host_application_launch_tool_descriptor,
    host_application_launch_tool_resolver,
    host_application_resource,
    host_clipboard_resource,
    host_process_collection_resource,
    host_process_list_tool_descriptor,
    host_process_list_tool_resolver,
)
from phoenix_os.inference import InferenceRequest, ModelId, ModelProviderId
from phoenix_os.policy import (
    PolicyEffect,
    PolicyEngine,
    PolicyRule,
    PrincipalType,
    SecurityContext,
)
from phoenix_os.runtime import RuntimeContext
from phoenix_os.state import MemoryStateStore

_NOW = datetime(2026, 8, 21, 18, tzinfo=UTC)
_AGENT_ID = AgentId("assistant")
_HOST_ID = HostId("desktop")
_APP_ID = HostApplicationId("editor")
_REQUESTER = "service:requester"
_INTERNAL_HOST = "service:host-internal"
_APPROVER = "service:approver"

_MEMORY_NAMESPACE = MemoryNamespace("composition")
_MEMORY_SCOPE = agent_memory_scope(namespace=_MEMORY_NAMESPACE, agent_id=_AGENT_ID)
_MEMORY_ID = MemoryId(UUID("50000000-0000-0000-0000-000000000033"))
_MEMORY_WRITE_TOOL_ID = ToolId(MEMORY_WRITE_ACTION)
_MEMORY_RESOURCE = memory_record_resource(_MEMORY_SCOPE, _MEMORY_ID)
_MEMORY_CONTENT = "composition memory write"
_MEMORY_TOOL_RESOLVER_ID = "memory-write-composition-resource"
_MEMORY_TOOL_ADAPTER_ID = "memory-write-composition"

_WORKSPACE_NAMESPACE = WorkspaceNamespace("composition")
_WORKSPACE_SCOPE = agent_workspace_scope(namespace=_WORKSPACE_NAMESPACE, agent_id=_AGENT_ID)
_WORKSPACE_ARTIFACT_ID = ArtifactId(UUID("60000000-0000-0000-0000-000000000033"))
_WORKSPACE_WRITE_TOOL_ID = ToolId(WORKSPACE_WRITE_ACTION)
_WORKSPACE_RESOURCE = workspace_artifact_resource(_WORKSPACE_SCOPE, _WORKSPACE_ARTIFACT_ID)
_WORKSPACE_CONTENT = "composition workspace write"
_WORKSPACE_LOGICAL_PATH = ArtifactLogicalPath("composition/result.txt")
_WORKSPACE_TOOL_RESOLVER_ID = "workspace-write-composition-resource"
_WORKSPACE_TOOL_ADAPTER_ID = "workspace-write-composition"

_WORKSPACE_HOST_CONTENT = (
    "credential:host-admin|principal=service:host-internal|policy:allow|host.clipboard.write"
)
_WORKSPACE_HOST_BYTES = _WORKSPACE_HOST_CONTENT.encode("utf-8")
_WORKSPACE_HOST_DESTINATION = WorkspaceTransferReference("clipboard-transfer-slot")
_WORKSPACE_HOST_ADAPTER_ID = WorkspaceTransferAdapterId("workspace-host-composition")


_PARENT_AGENT_ID = AgentId("parent")
_CHILD_AGENT_ID = AgentId("child")
_INTERNAL_CHILD = "service:child-internal"
_COORDINATION_NAMESPACE = CoordinationNamespace("composition")
_PARENT_RUN_ID = AgentRunId(UUID("70000000-0000-0000-0000-000000000033"))
_DELEGATION_ID = DelegationId(UUID("71000000-0000-0000-0000-000000000033"))
_CHILD_TOOL_ID = ToolId("composition.child.read")
_CHILD_TOOL_RESOURCE = "composition:child-tool"
_CHILD_TOOL_RESOLVER_ID = "child-composition-resource"
_CHILD_TOOL_ADAPTER_ID = "child-composition"
_CHILD_TOOL_VALUE = "child composition value"

_DURABLE_RUN_ID = DurableAgentRunId(UUID("72000000-0000-0000-0000-000000000033"))
_DURABLE_AGENT_RUN_ID = AgentRunId(UUID("73000000-0000-0000-0000-000000000033"))
_DURABLE_CHECKPOINT_ID = CheckpointId(UUID("74000000-0000-0000-0000-000000000033"))
_DURABLE_STEP_ID = AgentStepId(UUID("75000000-0000-0000-0000-000000000033"))
_DURABLE_RESUME_ACTOR = "resume-operator"
_DURABLE_LEASE_OWNER = "resume-worker"


def _context(principal: str = _REQUESTER) -> SecurityContext:
    return SecurityContext(
        principal=principal,
        principal_type=PrincipalType.SERVICE,
        authenticated=True,
    )


def _request() -> AgentRunRequest:
    return AgentRunRequest(
        agent_id=_AGENT_ID,
        provider_id=ModelProviderId("local"),
        model_id=ModelId("chat"),
        messages=(AgentMessage(AgentMessageRole.USER, "list processes"),),
        created_at=_NOW,
        deadline=_NOW + timedelta(minutes=2),
    )


def _limits() -> HostAutomationLimits:
    return HostAutomationLimits(
        max_process_results=4,
        max_window_results=4,
        max_process_label_chars=256,
        max_window_title_chars=512,
        operation_timeout=timedelta(seconds=30),
    )


def _allow_rule(
    rule_id: str,
    *,
    action: str,
    resource: str,
    principal: str,
) -> PolicyRule:
    return PolicyRule(
        rule_id=rule_id,
        effect=PolicyEffect.ALLOW,
        actions=frozenset({action}),
        resources=frozenset({resource}),
        principals=frozenset({principal}),
        authenticated=True,
    )


def _run_policy(principal: str) -> PolicyEngine:
    return PolicyEngine(
        (
            _allow_rule(
                "allow-agent-run",
                action="agent.run",
                resource=agent_run_resource(_AGENT_ID),
                principal=principal,
            ),
        )
    )


def _tool_policy(principal: str) -> PolicyEngine:
    host_resource = host_process_collection_resource(_HOST_ID)
    return PolicyEngine(
        (
            _allow_rule(
                "allow-tool-invoke",
                action="tool.invoke",
                resource=f"tool:{HOST_PROCESS_LIST_TOOL_ID}/{host_resource}",
                principal=principal,
            ),
        )
    )


def _host_policy(principal: str) -> PolicyEngine:
    return PolicyEngine(
        (
            _allow_rule(
                "allow-host-process-list",
                action=HOST_PROCESS_LIST_ACTION,
                resource=host_process_collection_resource(_HOST_ID),
                principal=principal,
            ),
        )
    )


def _launch_tool_policy(principal: str) -> PolicyEngine:
    resource = host_application_resource(_HOST_ID, _APP_ID)
    return PolicyEngine(
        (
            _allow_rule(
                "allow-launch-tool-invoke",
                action="tool.invoke",
                resource=f"tool:{HOST_APPLICATION_LAUNCH_TOOL_ID}/{resource}",
                principal=principal,
            ),
        )
    )


def _launch_host_policy(principal: str) -> PolicyEngine:
    return PolicyEngine(
        (
            _allow_rule(
                "allow-host-application-launch",
                action=HOST_APPLICATION_LAUNCH_ACTION,
                resource=host_application_resource(_HOST_ID, _APP_ID),
                principal=principal,
            ),
        )
    )


def _memory_write_tool_policy(principal: str) -> PolicyEngine:
    return PolicyEngine(
        (
            _allow_rule(
                "allow-memory-write-tool-invoke",
                action="tool.invoke",
                resource=f"tool:{_MEMORY_WRITE_TOOL_ID}/{_MEMORY_RESOURCE}",
                principal=principal,
            ),
        )
    )


def _memory_write_policy(principal: str) -> PolicyEngine:
    return PolicyEngine(
        (
            _allow_rule(
                "allow-memory-write",
                action=MEMORY_WRITE_ACTION,
                resource=_MEMORY_RESOURCE,
                principal=principal,
            ),
        )
    )


def _workspace_write_tool_policy(principal: str) -> PolicyEngine:
    return PolicyEngine(
        (
            _allow_rule(
                "allow-workspace-write-tool-invoke",
                action="tool.invoke",
                resource=f"tool:{_WORKSPACE_WRITE_TOOL_ID}/{_WORKSPACE_RESOURCE}",
                principal=principal,
            ),
        )
    )


def _workspace_write_policy(principal: str) -> PolicyEngine:
    return PolicyEngine(
        (
            _allow_rule(
                "allow-workspace-write",
                action=WORKSPACE_WRITE_ACTION,
                resource=_WORKSPACE_RESOURCE,
                principal=principal,
            ),
        )
    )


def _workspace_export_policy(principal: str) -> PolicyEngine:
    return PolicyEngine(
        (
            _allow_rule(
                "allow-workspace-export",
                action=WORKSPACE_EXPORT_ACTION,
                resource=_WORKSPACE_RESOURCE,
                principal=principal,
            ),
        )
    )


def _host_clipboard_write_policy(principal: str) -> PolicyEngine:
    return PolicyEngine(
        (
            _allow_rule(
                "allow-host-clipboard-write",
                action=HOST_CLIPBOARD_WRITE_ACTION,
                resource=host_clipboard_resource(_HOST_ID),
                principal=principal,
            ),
        )
    )


def _delegation_policy(principal: str) -> PolicyEngine:
    return PolicyEngine(
        (
            _allow_rule(
                "allow-agent-delegate",
                action=AGENT_DELEGATE_ACTION,
                resource=agent_delegation_resource(
                    namespace=_COORDINATION_NAMESPACE,
                    parent_agent_id=_PARENT_AGENT_ID,
                    child_agent_id=_CHILD_AGENT_ID,
                ),
                principal=principal,
            ),
        )
    )


def _child_run_policy(principal: str) -> PolicyEngine:
    return PolicyEngine(
        (
            _allow_rule(
                "allow-child-agent-run",
                action="agent.run",
                resource=agent_run_resource(_CHILD_AGENT_ID),
                principal=principal,
            ),
        )
    )


def _child_tool_policy(principal: str) -> PolicyEngine:
    return PolicyEngine(
        (
            _allow_rule(
                "allow-child-tool-invoke",
                action="tool.invoke",
                resource=f"tool:{_CHILD_TOOL_ID}/{_CHILD_TOOL_RESOURCE}",
                principal=principal,
            ),
        )
    )


def _delegation_limits() -> DelegationLimits:
    return DelegationLimits(
        max_depth=1,
        max_fan_out=2,
        max_total_children=4,
        max_concurrent_children=2,
        max_queue_depth=2,
        max_input_bytes=16_384,
        max_result_bytes=65_536,
        max_result_depth=8,
        child_timeout=timedelta(minutes=5),
    )


def _delegation_budget() -> DelegationBudget:
    return DelegationBudget(
        max_model_turns=2,
        max_tool_calls=1,
        max_input_tokens=4_096,
        max_output_tokens=2_048,
        max_prompt_bytes=8_192,
        max_result_bytes=16_384,
        duration=timedelta(minutes=2),
    )


def _delegation_root_budget() -> DelegationBudget:
    child = _delegation_budget()
    return DelegationBudget(
        max_model_turns=child.max_model_turns * 4,
        max_tool_calls=child.max_tool_calls * 4,
        max_input_tokens=child.max_input_tokens * 4,
        max_output_tokens=child.max_output_tokens * 4,
        max_prompt_bytes=child.max_prompt_bytes * 4,
        max_result_bytes=child.max_result_bytes * 4,
        duration=child.duration * 4,
    )


def _delegation_request() -> DelegationRequest:
    limits = _delegation_limits()
    return DelegationRequest(
        parent_agent_id=_PARENT_AGENT_ID,
        parent_run_id=_PARENT_RUN_ID,
        child_agent_id=_CHILD_AGENT_ID,
        namespace=_COORDINATION_NAMESPACE,
        lineage=DelegationLineage((DelegationLineageEntry(_PARENT_AGENT_ID, _PARENT_RUN_ID),)),
        input={"task": "invoke the bounded child composition tool"},
        budget=_delegation_budget(),
        limits=limits,
        delegation_id=_DELEGATION_ID,
        created_at=_NOW,
        deadline=_NOW + timedelta(minutes=2),
    )


def _memory_write_tool_descriptor() -> ToolDescriptor:
    input_schema = ToolSchema(
        kind=ToolSchemaType.OBJECT,
        properties={
            "content": ToolSchema(
                kind=ToolSchemaType.STRING,
                min_length=1,
                max_length=512,
            )
        },
        required=frozenset({"content"}),
    )
    output_schema = ToolSchema(
        kind=ToolSchemaType.OBJECT,
        properties={"stored": ToolSchema(kind=ToolSchemaType.BOOLEAN)},
        required=frozenset({"stored"}),
    )
    return ToolDescriptor(
        tool_id=_MEMORY_WRITE_TOOL_ID,
        name="Write one composition-test memory",
        description=(
            "Write one bounded value to one server-owned memory record for "
            "authority-composition conformance."
        ),
        input_schema=ToolInputSchema(input_schema),
        output_schema=ToolOutputSchema(output_schema),
        effect=ToolEffect.REVERSIBLE_WRITE,
        approval_may_be_required=True,
        max_input_bytes=1_024,
        max_output_bytes=64,
        timeout=timedelta(seconds=10),
        resolver_id=_MEMORY_TOOL_RESOLVER_ID,
        adapter_id=_MEMORY_TOOL_ADAPTER_ID,
    )


def _workspace_write_tool_descriptor() -> ToolDescriptor:
    input_schema = ToolSchema(
        kind=ToolSchemaType.OBJECT,
        properties={
            "content": ToolSchema(
                kind=ToolSchemaType.STRING,
                min_length=1,
                max_length=512,
            )
        },
        required=frozenset({"content"}),
    )
    output_schema = ToolSchema(
        kind=ToolSchemaType.OBJECT,
        properties={"stored": ToolSchema(kind=ToolSchemaType.BOOLEAN)},
        required=frozenset({"stored"}),
    )
    return ToolDescriptor(
        tool_id=_WORKSPACE_WRITE_TOOL_ID,
        name="Write one composition-test workspace artifact",
        description=(
            "Write one bounded value to one server-owned workspace artifact for "
            "authority-composition conformance."
        ),
        input_schema=ToolInputSchema(input_schema),
        output_schema=ToolOutputSchema(output_schema),
        effect=ToolEffect.REVERSIBLE_WRITE,
        approval_may_be_required=True,
        max_input_bytes=1_024,
        max_output_bytes=64,
        timeout=timedelta(seconds=10),
        resolver_id=_WORKSPACE_TOOL_RESOLVER_ID,
        adapter_id=_WORKSPACE_TOOL_ADAPTER_ID,
    )


def _child_tool_descriptor() -> ToolDescriptor:
    schema = ToolSchema(
        kind=ToolSchemaType.OBJECT,
        properties={
            "value": ToolSchema(
                kind=ToolSchemaType.STRING,
                min_length=1,
                max_length=128,
            )
        },
        required=frozenset({"value"}),
    )
    return ToolDescriptor(
        tool_id=_CHILD_TOOL_ID,
        name="Read one child composition value",
        description=(
            "Return one bounded deterministic value for parent-child-tool "
            "authority-composition conformance."
        ),
        input_schema=ToolInputSchema(schema),
        output_schema=ToolOutputSchema(schema),
        effect=ToolEffect.READ_ONLY,
        approval_may_be_required=False,
        max_input_bytes=512,
        max_output_bytes=512,
        timeout=timedelta(seconds=10),
        resolver_id=_CHILD_TOOL_RESOLVER_ID,
        adapter_id=_CHILD_TOOL_ADAPTER_ID,
    )


class _AllowModelAuthorizer:
    async def authorize(
        self,
        request: InferenceRequest,
        context: SecurityContext,
    ) -> None:
        assert isinstance(request, InferenceRequest)
        assert context.authenticated


class _ImmediateApprovalResolver:
    def __init__(
        self,
        service: InMemoryToolApprovalService,
        approver: SecurityContext,
    ) -> None:
        self.service = service
        self.approver = approver
        self.challenges: list[ToolApprovalChallenge] = []

    async def resolve(self, challenge: ToolApprovalChallenge) -> ToolApprovalEvidence:
        self.challenges.append(challenge)
        return await self.service.approve(challenge.approval_id, self.approver)


class _RecordingRunAuthorizer(PolicyEngineAgentRunAuthorizer):
    def __init__(self, policy: PolicyEngine) -> None:
        super().__init__(policy)
        self.requests: list[AgentRunRequest] = []
        self.contexts: list[SecurityContext] = []

    async def authorize(
        self,
        request: AgentRunRequest,
        context: SecurityContext,
    ) -> None:
        self.requests.append(request)
        self.contexts.append(context)
        await super().authorize(request, context)


class _RecordingToolAuthorizer(PolicyEngineToolAuthorizer):
    def __init__(self, policy: PolicyEngine) -> None:
        super().__init__(policy)
        self.requests: list[ToolInvocationRequest] = []
        self.contexts: list[SecurityContext] = []

    async def authorize(
        self,
        request: ToolInvocationRequest,
        descriptor: ToolDescriptor,
        context: SecurityContext,
    ) -> None:
        self.requests.append(request)
        self.contexts.append(context)
        await super().authorize(request, descriptor, context)


class _RecordingMemoryAuthorizer(PolicyEngineMemoryAuthorizer):
    def __init__(self, policy: PolicyEngine) -> None:
        super().__init__(policy)
        self.write_requests: list[MemoryWriteRequest] = []
        self.write_contexts: list[SecurityContext] = []

    async def authorize_write(
        self,
        request: MemoryWriteRequest,
        context: SecurityContext,
    ) -> None:
        self.write_requests.append(request)
        self.write_contexts.append(context)
        await super().authorize_write(request, context)


class _RecordingWorkspaceAuthorizer(PolicyEngineWorkspaceAuthorizer):
    def __init__(self, policy: PolicyEngine) -> None:
        super().__init__(policy)
        self.write_requests: list[ArtifactWriteRequest] = []
        self.write_contexts: list[SecurityContext] = []
        self.export_requests: list[ArtifactExportRequest] = []
        self.export_contexts: list[SecurityContext] = []

    async def authorize_write(
        self,
        request: ArtifactWriteRequest,
        context: SecurityContext,
    ) -> None:
        self.write_requests.append(request)
        self.write_contexts.append(context)
        await super().authorize_write(request, context)

    async def authorize_export(
        self,
        request: ArtifactExportRequest,
        context: SecurityContext,
    ) -> None:
        self.export_requests.append(request)
        self.export_contexts.append(context)
        await super().authorize_export(request, context)


class _RecordingDelegationAuthorizer(PolicyEngineDelegationAuthorizer):
    def __init__(self, policy: PolicyEngine) -> None:
        super().__init__(policy)
        self.requests: list[DelegationRequest] = []
        self.descriptors: list[DelegableAgentDescriptor] = []
        self.contexts: list[SecurityContext] = []

    async def authorize(
        self,
        request: DelegationRequest,
        descriptor: DelegableAgentDescriptor,
        context: SecurityContext,
    ) -> None:
        self.requests.append(request)
        self.descriptors.append(descriptor)
        self.contexts.append(context)
        await super().authorize(request, descriptor, context)


class _ChildCompositionToolAdapter:
    adapter_id = _CHILD_TOOL_ADAPTER_ID
    tool_id = _CHILD_TOOL_ID

    def __init__(self) -> None:
        self.requests: list[ToolInvocationRequest] = []
        self.contexts: list[SecurityContext] = []
        self.calls = 0

    async def invoke(self, request: ToolInvocationRequest) -> ToolInvocationResult:
        del request
        raise ToolExecutionError()

    async def invoke_with_context(
        self,
        request: ToolInvocationRequest,
        context: SecurityContext,
    ) -> ToolInvocationResult:
        if not isinstance(request, ToolInvocationRequest):
            raise TypeError("request must be ToolInvocationRequest")
        if not isinstance(context, SecurityContext):
            raise TypeError("context must be SecurityContext")
        if (
            request.tool_id != _CHILD_TOOL_ID
            or request.resolved_resource != _CHILD_TOOL_RESOURCE
            or request.agent_id != _CHILD_AGENT_ID
            or frozenset(request.arguments) != frozenset({"value"})
            or request.arguments.get("value") != _CHILD_TOOL_VALUE
        ):
            raise ToolExecutionError()

        self.requests.append(request)
        self.contexts.append(context)
        self.calls += 1
        return ToolInvocationResult(
            run_id=request.run_id,
            step_id=request.step_id,
            call_id=request.call_id,
            tool_id=request.tool_id,
            status=ToolResultStatus.SUCCEEDED,
            output={"value": _CHILD_TOOL_VALUE},
            started_at=request.created_at,
            completed_at=request.created_at,
        )


class _RecordingChildAgentService(AgentService):
    def __init__(
        self,
        runtime: AgentLoop,
        registry: ToolRegistry,
        admission: AgentAdmissionController,
        configuration: AgentServiceConfiguration,
        *,
        events: EventBus,
        model_adapter: DeterministicModelTurnAdapter,
        tool_adapters: tuple[_ChildCompositionToolAdapter, ...],
    ) -> None:
        super().__init__(
            runtime,
            registry,
            admission,
            configuration,
            events=events,
            model_adapter=model_adapter,
            tool_adapters=tool_adapters,
        )
        self.run_requests: list[AgentRunRequest] = []
        self.run_contexts: list[SecurityContext] = []

    async def run(
        self,
        request: AgentRunRequest,
        context: SecurityContext,
        *,
        cancellation: AgentCancellationToken | None = None,
        _authority_binding: AgentRunAuthorityBinding | None = None,
    ) -> AgentRunResult:
        self.run_requests.append(request)
        self.run_contexts.append(context)
        return await super().run(
            request,
            context,
            cancellation=cancellation,
            _authority_binding=_authority_binding,
        )


class _MemoryWriteCompositionAdapter:
    adapter_id = _MEMORY_TOOL_ADAPTER_ID
    tool_id = _MEMORY_WRITE_TOOL_ID

    def __init__(self, service: AgentMemoryService) -> None:
        if not isinstance(service, AgentMemoryService):
            raise TypeError("service must be AgentMemoryService")
        self._service = service
        self.requests: list[ToolInvocationRequest] = []
        self.contexts: list[SecurityContext] = []

    async def invoke(self, request: ToolInvocationRequest) -> ToolInvocationResult:
        del request
        raise ToolExecutionError()

    async def invoke_with_context(
        self,
        request: ToolInvocationRequest,
        context: SecurityContext,
    ) -> ToolInvocationResult:
        if not isinstance(request, ToolInvocationRequest):
            raise TypeError("request must be ToolInvocationRequest")
        if not isinstance(context, SecurityContext):
            raise TypeError("context must be SecurityContext")
        if (
            request.tool_id != self.tool_id
            or request.resolved_resource != _MEMORY_RESOURCE
            or request.agent_id is None
            or frozenset(request.arguments) != frozenset({"content"})
        ):
            raise ToolExecutionError()

        content = request.arguments.get("content")
        if not isinstance(content, str) or not content.strip():
            raise ToolExecutionError()

        self.requests.append(request)
        self.contexts.append(context)

        digest = memory_content_digest(content)
        memory_request = MemoryWriteRequest(
            scope=_MEMORY_SCOPE,
            memory_id=_MEMORY_ID,
            content=content,
            provenance=MemoryProvenance(
                origin=MemoryOriginKind.AGENT_REQUEST,
                content_digest=digest,
                created_at=request.created_at,
                source_run_id=request.run_id,
                source_agent_id=request.agent_id,
            ),
            created_at=request.created_at,
        )
        record = await self._service.write(memory_request, context)
        if (
            record.scope != _MEMORY_SCOPE
            or record.memory_id != _MEMORY_ID
            or record.content_digest != digest
        ):
            raise ToolExecutionError()

        return ToolInvocationResult(
            run_id=request.run_id,
            step_id=request.step_id,
            call_id=request.call_id,
            tool_id=request.tool_id,
            status=ToolResultStatus.SUCCEEDED,
            output={"stored": True},
            started_at=request.created_at,
            completed_at=request.created_at,
        )


class _CountingWorkspaceStore(StateStoreWorkspaceStore):
    def __init__(self) -> None:
        limits = WorkspaceLimits()
        super().__init__(
            MemoryStateStore(clock=lambda: _NOW),
            InMemoryWorkspaceBackingAdapter(),
            limits=limits,
            clock=lambda: _NOW,
            owns_state_store=True,
            owns_backing=True,
        )
        self.write_calls = 0

    async def write(self, request: ArtifactWriteRequest) -> ArtifactRecord:
        self.write_calls += 1
        return await super().write(request)


class _WorkspaceWriteCompositionAdapter:
    adapter_id = _WORKSPACE_TOOL_ADAPTER_ID
    tool_id = _WORKSPACE_WRITE_TOOL_ID

    def __init__(self, service: AgentWorkspaceService) -> None:
        if not isinstance(service, AgentWorkspaceService):
            raise TypeError("service must be AgentWorkspaceService")
        self._service = service
        self.requests: list[ToolInvocationRequest] = []
        self.contexts: list[SecurityContext] = []

    async def invoke(self, request: ToolInvocationRequest) -> ToolInvocationResult:
        del request
        raise ToolExecutionError()

    async def invoke_with_context(
        self,
        request: ToolInvocationRequest,
        context: SecurityContext,
    ) -> ToolInvocationResult:
        if not isinstance(request, ToolInvocationRequest):
            raise TypeError("request must be ToolInvocationRequest")
        if not isinstance(context, SecurityContext):
            raise TypeError("context must be SecurityContext")
        if (
            request.tool_id != self.tool_id
            or request.resolved_resource != _WORKSPACE_RESOURCE
            or request.agent_id != _AGENT_ID
            or frozenset(request.arguments) != frozenset({"content"})
        ):
            raise ToolExecutionError()

        content_value = request.arguments.get("content")
        if not isinstance(content_value, str) or not content_value.strip():
            raise ToolExecutionError()
        try:
            content = content_value.encode("utf-8", errors="strict")
        except UnicodeEncodeError as exception:
            raise ToolExecutionError() from exception

        self.requests.append(request)
        self.contexts.append(context)

        digest = artifact_content_digest(content)
        workspace_request = ArtifactWriteRequest(
            scope=_WORKSPACE_SCOPE,
            artifact_id=_WORKSPACE_ARTIFACT_ID,
            logical_path=_WORKSPACE_LOGICAL_PATH,
            content=content,
            provenance=ArtifactProvenance(
                origin=ArtifactOriginKind.AGENT_REQUEST,
                content_digest=digest,
                created_at=request.created_at,
                source_run_id=request.run_id,
                source_agent_id=request.agent_id,
            ),
            created_at=request.created_at,
        )
        record = await self._service.write(workspace_request, context)
        if (
            record.scope != _WORKSPACE_SCOPE
            or record.artifact_id != _WORKSPACE_ARTIFACT_ID
            or record.logical_path != _WORKSPACE_LOGICAL_PATH
            or record.content_digest != digest
        ):
            raise ToolExecutionError()

        return ToolInvocationResult(
            run_id=request.run_id,
            step_id=request.step_id,
            call_id=request.call_id,
            tool_id=request.tool_id,
            status=ToolResultStatus.SUCCEEDED,
            output={"stored": True},
            started_at=request.created_at,
            completed_at=request.created_at,
        )


class _RecordingHostAuthorizer(PolicyEngineHostAutomationAuthorizer):
    def __init__(self, policy: PolicyEngine) -> None:
        super().__init__(policy)
        self.process_list_contexts: list[SecurityContext] = []
        self.application_launch_contexts: list[SecurityContext] = []
        self.clipboard_write_requests: list[HostClipboardWriteRequest] = []
        self.clipboard_write_contexts: list[SecurityContext] = []

    async def authorize_process_list(
        self,
        request: HostProcessListRequest,
        context: SecurityContext,
    ) -> None:
        self.process_list_contexts.append(context)
        await super().authorize_process_list(request, context)

    async def authorize_application_launch(
        self,
        request: HostApplicationLaunchRequest,
        context: SecurityContext,
    ) -> None:
        self.application_launch_contexts.append(context)
        await super().authorize_application_launch(request, context)

    async def authorize_clipboard_write(
        self,
        request: HostClipboardWriteRequest,
        context: SecurityContext,
    ) -> None:
        self.clipboard_write_requests.append(request)
        self.clipboard_write_contexts.append(context)
        await super().authorize_clipboard_write(request, context)


class _CountingHostAdapter(DeterministicHostAutomationAdapter):
    def __init__(self, limits: HostAutomationLimits) -> None:
        super().__init__(
            host_id=_HOST_ID,
            limits=limits,
            applications=(_APP_ID,),
        )
        self.process_list_calls = 0
        self.application_launch_calls = 0
        self.clipboard_write_calls = 0

    async def list_processes(
        self,
        request: HostProcessListRequest,
    ) -> HostProcessListResult:
        self.process_list_calls += 1
        return await super().list_processes(request)

    async def launch_application(
        self,
        request: HostApplicationLaunchRequest,
    ) -> HostApplicationLaunchResult:
        self.application_launch_calls += 1
        return await super().launch_application(request)

    async def write_clipboard(
        self,
        request: HostClipboardWriteRequest,
    ) -> HostClipboardWriteResult:
        self.clipboard_write_calls += 1
        return await super().write_clipboard(request)


class _WorkspaceToHostTransferAdapter:
    adapter_id = _WORKSPACE_HOST_ADAPTER_ID

    def __init__(
        self,
        service: HostAutomationService,
        requester_context: SecurityContext,
    ) -> None:
        if not isinstance(service, HostAutomationService):
            raise TypeError("service must be HostAutomationService")
        if not isinstance(requester_context, SecurityContext):
            raise TypeError("requester_context must be SecurityContext")
        self._service = service
        self._requester_context = requester_context
        self._closed = False
        self.export_calls = 0
        self.export_payloads: list[WorkspaceExportPayload] = []
        self.host_requests: list[HostClipboardWriteRequest] = []
        self.host_results: list[HostClipboardWriteResult] = []

    @property
    def closed(self) -> bool:
        return self._closed

    async def import_artifact(
        self,
        source_reference: WorkspaceTransferReference,
        *,
        max_bytes: int,
    ) -> WorkspaceImportResult:
        del source_reference, max_bytes
        raise AssertionError("import is outside workspace-to-host composition")

    async def export_artifact(
        self,
        payload: WorkspaceExportPayload,
    ) -> WorkspaceExportResult:
        if not isinstance(payload, WorkspaceExportPayload):
            raise TypeError("payload must be WorkspaceExportPayload")
        if (
            payload.scope != _WORKSPACE_SCOPE
            or payload.artifact_id != _WORKSPACE_ARTIFACT_ID
            or payload.logical_path != _WORKSPACE_LOGICAL_PATH
            or payload.content != _WORKSPACE_HOST_BYTES
            or payload.content_digest != artifact_content_digest(_WORKSPACE_HOST_BYTES)
            or payload.destination_reference != _WORKSPACE_HOST_DESTINATION
        ):
            raise AssertionError("unexpected workspace export payload")

        self.export_calls += 1
        self.export_payloads.append(payload)

        text = payload.content.decode("utf-8", errors="strict")
        host_request = HostClipboardWriteRequest(
            host_id=_HOST_ID,
            text=text,
            created_at=_NOW,
        )
        self.host_requests.append(host_request)
        result = await self._service.write_clipboard(
            host_request,
            self._requester_context,
        )
        self.host_results.append(result)
        return WorkspaceExportResult(
            transfer_reference=payload.destination_reference,
        )


class _WorkspaceHostIndirectPath:
    def __init__(
        self,
        *,
        service: AgentWorkspaceService,
        workspace_authorizer: _RecordingWorkspaceAuthorizer,
        transfer_adapter: _WorkspaceToHostTransferAdapter,
        host_authorizer: _RecordingHostAuthorizer,
        host_adapter: _CountingHostAdapter,
        export_request: ArtifactExportRequest,
        requester_context: SecurityContext,
    ) -> None:
        self.service = service
        self.workspace_authorizer = workspace_authorizer
        self.transfer_adapter = transfer_adapter
        self.host_authorizer = host_authorizer
        self.host_adapter = host_adapter
        self.export_request = export_request
        self.requester_context = requester_context

    async def run(
        self,
        context: SecurityContext,
    ) -> ArtifactTransferReceipt:
        if context is not self.requester_context:
            raise AssertionError("workspace-to-host path must preserve requester context identity")
        return await self.service.export_artifact(self.export_request, context)


async def _workspace_host_indirect_path(
    *,
    workspace_policy: PolicyEngine,
    host_policy: PolicyEngine,
    context: SecurityContext,
) -> _WorkspaceHostIndirectPath:
    store = _CountingWorkspaceStore()
    digest = artifact_content_digest(_WORKSPACE_HOST_BYTES)
    record = await store.write(
        ArtifactWriteRequest(
            scope=_WORKSPACE_SCOPE,
            artifact_id=_WORKSPACE_ARTIFACT_ID,
            logical_path=_WORKSPACE_LOGICAL_PATH,
            content=_WORKSPACE_HOST_BYTES,
            provenance=ArtifactProvenance(
                origin=ArtifactOriginKind.AGENT_REQUEST,
                content_digest=digest,
                created_at=_NOW,
                source_agent_id=_AGENT_ID,
            ),
            created_at=_NOW,
        )
    )

    host_authorizer = _RecordingHostAuthorizer(host_policy)
    host_adapter = _CountingHostAdapter(_limits())
    host_service = HostAutomationService(
        adapter=host_adapter,
        authorizer=host_authorizer,
    )

    transfer_adapter = _WorkspaceToHostTransferAdapter(
        host_service,
        context,
    )
    workspace_authorizer = _RecordingWorkspaceAuthorizer(workspace_policy)
    workspace_service = AgentWorkspaceService(
        store=store,
        authorizer=workspace_authorizer,
        transfer_adapter=transfer_adapter,
        clock=lambda: _NOW,
    )
    export_request = ArtifactExportRequest(
        scope=_WORKSPACE_SCOPE,
        artifact_id=_WORKSPACE_ARTIFACT_ID,
        expected_version=record.version,
        destination_reference=_WORKSPACE_HOST_DESTINATION,
        created_at=_NOW,
    )

    return _WorkspaceHostIndirectPath(
        service=workspace_service,
        workspace_authorizer=workspace_authorizer,
        transfer_adapter=transfer_adapter,
        host_authorizer=host_authorizer,
        host_adapter=host_adapter,
        export_request=export_request,
        requester_context=context,
    )


def _memory_write_composition_path(
    *,
    run_policy: PolicyEngine,
    tool_policy: PolicyEngine,
    memory_policy: PolicyEngine,
) -> tuple[
    AgentLoop,
    _RecordingRunAuthorizer,
    _RecordingToolAuthorizer,
    _RecordingMemoryAuthorizer,
    _MemoryWriteCompositionAdapter,
    InMemoryAgentMemoryStore,
    InMemoryToolApprovalService,
    _ImmediateApprovalResolver,
]:
    store = InMemoryAgentMemoryStore(clock=lambda: _NOW)
    memory_authorizer = _RecordingMemoryAuthorizer(memory_policy)
    memory_service = AgentMemoryService(
        store=store,
        authorizer=memory_authorizer,
        retrieval=DeterministicLexicalMemoryRetrievalAdapter(store),
        clock=lambda: _NOW,
    )
    memory_adapter = _MemoryWriteCompositionAdapter(memory_service)

    registry = ToolRegistry()
    registry.register_tool(
        _memory_write_tool_descriptor(),
        resolver=StaticToolResourceResolver(
            _MEMORY_TOOL_RESOLVER_ID,
            _MEMORY_RESOURCE,
        ),
        adapter=memory_adapter,
    )

    approval_service = InMemoryToolApprovalService(clock=lambda: _NOW)
    approval_resolver = _ImmediateApprovalResolver(
        approval_service,
        _context(_APPROVER),
    )
    run_authorizer = _RecordingRunAuthorizer(run_policy)
    tool_authorizer = _RecordingToolAuthorizer(tool_policy)
    loop = AgentLoop(
        run_authorizer=run_authorizer,
        model_authorizer=_AllowModelAuthorizer(),
        tool_authorizer=tool_authorizer,
        model_adapter=DeterministicModelTurnAdapter(
            (
                DeterministicToolTurn(
                    _MEMORY_WRITE_TOOL_ID,
                    {"content": _MEMORY_CONTENT},
                ),
                DeterministicFinalTurn("complete"),
            )
        ),
        registry=registry,
        executor=BoundedAgentExecutor(clock=lambda: _NOW),
        approval_service=approval_service,
        approval_resolver=approval_resolver,
        clock=lambda: _NOW,
    )
    return (
        loop,
        run_authorizer,
        tool_authorizer,
        memory_authorizer,
        memory_adapter,
        store,
        approval_service,
        approval_resolver,
    )


def _workspace_write_composition_path(
    *,
    run_policy: PolicyEngine,
    tool_policy: PolicyEngine,
    workspace_policy: PolicyEngine,
) -> tuple[
    AgentLoop,
    _RecordingRunAuthorizer,
    _RecordingToolAuthorizer,
    _RecordingWorkspaceAuthorizer,
    _WorkspaceWriteCompositionAdapter,
    _CountingWorkspaceStore,
    InMemoryToolApprovalService,
    _ImmediateApprovalResolver,
]:
    store = _CountingWorkspaceStore()
    workspace_authorizer = _RecordingWorkspaceAuthorizer(workspace_policy)
    workspace_service = AgentWorkspaceService(
        store=store,
        authorizer=workspace_authorizer,
        clock=lambda: _NOW,
    )
    workspace_adapter = _WorkspaceWriteCompositionAdapter(workspace_service)

    registry = ToolRegistry()
    registry.register_tool(
        _workspace_write_tool_descriptor(),
        resolver=StaticToolResourceResolver(
            _WORKSPACE_TOOL_RESOLVER_ID,
            _WORKSPACE_RESOURCE,
        ),
        adapter=workspace_adapter,
    )

    approval_service = InMemoryToolApprovalService(clock=lambda: _NOW)
    approval_resolver = _ImmediateApprovalResolver(
        approval_service,
        _context(_APPROVER),
    )
    run_authorizer = _RecordingRunAuthorizer(run_policy)
    tool_authorizer = _RecordingToolAuthorizer(tool_policy)
    loop = AgentLoop(
        run_authorizer=run_authorizer,
        model_authorizer=_AllowModelAuthorizer(),
        tool_authorizer=tool_authorizer,
        model_adapter=DeterministicModelTurnAdapter(
            (
                DeterministicToolTurn(
                    _WORKSPACE_WRITE_TOOL_ID,
                    {"content": _WORKSPACE_CONTENT},
                ),
                DeterministicFinalTurn("complete"),
            )
        ),
        registry=registry,
        executor=BoundedAgentExecutor(clock=lambda: _NOW),
        approval_service=approval_service,
        approval_resolver=approval_resolver,
        clock=lambda: _NOW,
    )
    return (
        loop,
        run_authorizer,
        tool_authorizer,
        workspace_authorizer,
        workspace_adapter,
        store,
        approval_service,
        approval_resolver,
    )


async def _parent_child_tool_composition_path(
    *,
    delegation_policy: PolicyEngine,
    child_run_policy: PolicyEngine,
    child_tool_policy: PolicyEngine,
) -> tuple[
    AgentCoordinationRuntime,
    _RecordingDelegationAuthorizer,
    _RecordingChildAgentService,
    _RecordingRunAuthorizer,
    _RecordingToolAuthorizer,
    _ChildCompositionToolAdapter,
]:
    descriptor = _child_tool_descriptor()
    child_configuration = AgentServiceConfiguration(
        agent_id=_CHILD_AGENT_ID,
        provider_id=ModelProviderId("local"),
        model_id=ModelId("chat"),
        tools=(AgentToolConfiguration(descriptor),),
    )

    child_registry = ToolRegistry()
    child_adapter = _ChildCompositionToolAdapter()
    child_registry.register_tool(
        descriptor,
        resolver=StaticToolResourceResolver(
            _CHILD_TOOL_RESOLVER_ID,
            _CHILD_TOOL_RESOURCE,
        ),
        adapter=child_adapter,
    )

    child_run_authorizer = _RecordingRunAuthorizer(child_run_policy)
    child_tool_authorizer = _RecordingToolAuthorizer(child_tool_policy)
    child_admission = AgentAdmissionController(child_configuration.limits)
    child_model_adapter = DeterministicModelTurnAdapter(
        (
            DeterministicToolTurn(
                _CHILD_TOOL_ID,
                {"value": _CHILD_TOOL_VALUE},
            ),
            DeterministicFinalTurn("child complete"),
        )
    )
    child_loop = AgentLoop(
        run_authorizer=child_run_authorizer,
        model_authorizer=_AllowModelAuthorizer(),
        tool_authorizer=child_tool_authorizer,
        model_adapter=child_model_adapter,
        registry=child_registry,
        executor=BoundedAgentExecutor(clock=lambda: _NOW),
        admission=child_admission,
        clock=lambda: _NOW,
    )
    child_service = _RecordingChildAgentService(
        child_loop,
        child_registry,
        child_admission,
        child_configuration,
        events=EventBus(),
        model_adapter=child_model_adapter,
        tool_adapters=(child_adapter,),
    )

    limits = _delegation_limits()
    delegation_registry = AgentDelegationRegistry()
    delegation_registry.register_agent(
        DelegableAgentDescriptor(
            configuration=child_configuration,
            namespace=_COORDINATION_NAMESPACE,
            allowed_parent_agents=(_PARENT_AGENT_ID,),
            compatibility_digest="sha256:" + "5" * 64,
            allow_inbound=True,
            allow_nested_delegation=False,
            max_accepted_depth=DelegationDepth(1),
            delegation_limits=limits,
        )
    )
    delegation_authorizer = _RecordingDelegationAuthorizer(delegation_policy)
    coordinator = AgentDelegationCoordinator(
        delegation_registry,
        delegation_authorizer,
        limits=limits,
        root_budget_limit=_delegation_root_budget(),
        clock=lambda: _NOW,
    )
    runtime = AgentCoordinationRuntime(
        coordinator,
        AgentCoordinationConfiguration(
            namespace=_COORDINATION_NAMESPACE,
            limits=limits,
            root_budget_limit=_delegation_root_budget(),
            shutdown_grace=timedelta(seconds=1),
            cancellation_grace=timedelta(seconds=1),
        ),
        {_CHILD_AGENT_ID: child_service},
        clock=lambda: _NOW,
    )

    runtime_context = RuntimeContext(services={})
    await child_service.start(runtime_context)
    await runtime.start(runtime_context)
    return (
        runtime,
        delegation_authorizer,
        child_service,
        child_run_authorizer,
        child_tool_authorizer,
        child_adapter,
    )


def _composition_path(
    *,
    run_policy: PolicyEngine,
    tool_policy: PolicyEngine,
    host_policy: PolicyEngine,
) -> tuple[
    AgentLoop,
    _RecordingRunAuthorizer,
    _RecordingToolAuthorizer,
    _RecordingHostAuthorizer,
    _CountingHostAdapter,
]:
    limits = _limits()
    native = _CountingHostAdapter(limits)
    host_authorizer = _RecordingHostAuthorizer(host_policy)
    service = HostAutomationService(
        adapter=native,
        authorizer=host_authorizer,
    )

    registry = ToolRegistry()
    registry.register_tool(
        host_process_list_tool_descriptor(limits),
        resolver=host_process_list_tool_resolver(_HOST_ID),
        adapter=HostProcessListToolAdapter(
            service,
            host_id=_HOST_ID,
            limits=limits,
        ),
    )

    run_authorizer = _RecordingRunAuthorizer(run_policy)
    tool_authorizer = _RecordingToolAuthorizer(tool_policy)
    loop = AgentLoop(
        run_authorizer=run_authorizer,
        model_authorizer=_AllowModelAuthorizer(),
        tool_authorizer=tool_authorizer,
        model_adapter=DeterministicModelTurnAdapter(
            (
                DeterministicToolTurn(
                    HOST_PROCESS_LIST_TOOL_ID,
                    {"limit": 1},
                ),
                DeterministicFinalTurn("complete"),
            )
        ),
        registry=registry,
        executor=BoundedAgentExecutor(clock=lambda: _NOW),
        clock=lambda: _NOW,
    )
    return loop, run_authorizer, tool_authorizer, host_authorizer, native


def _effectful_composition_path(
    *,
    run_policy: PolicyEngine,
    tool_policy: PolicyEngine,
    host_policy: PolicyEngine,
) -> tuple[
    AgentLoop,
    _RecordingRunAuthorizer,
    _RecordingToolAuthorizer,
    _RecordingHostAuthorizer,
    _CountingHostAdapter,
    InMemoryToolApprovalService,
    _ImmediateApprovalResolver,
]:
    limits = _limits()
    native = _CountingHostAdapter(limits)
    host_authorizer = _RecordingHostAuthorizer(host_policy)
    service = HostAutomationService(
        adapter=native,
        authorizer=host_authorizer,
    )

    registry = ToolRegistry()
    registry.register_tool(
        host_application_launch_tool_descriptor(limits),
        resolver=host_application_launch_tool_resolver(_HOST_ID, (_APP_ID,)),
        adapter=HostApplicationLaunchToolAdapter(
            service,
            host_id=_HOST_ID,
            limits=limits,
            applications=(_APP_ID,),
        ),
    )

    approval_service = InMemoryToolApprovalService(clock=lambda: _NOW)
    approval_resolver = _ImmediateApprovalResolver(
        approval_service,
        _context(_APPROVER),
    )
    run_authorizer = _RecordingRunAuthorizer(run_policy)
    tool_authorizer = _RecordingToolAuthorizer(tool_policy)
    loop = AgentLoop(
        run_authorizer=run_authorizer,
        model_authorizer=_AllowModelAuthorizer(),
        tool_authorizer=tool_authorizer,
        model_adapter=DeterministicModelTurnAdapter(
            (
                DeterministicToolTurn(
                    HOST_APPLICATION_LAUNCH_TOOL_ID,
                    {"application_id": str(_APP_ID)},
                ),
                DeterministicFinalTurn("complete"),
            )
        ),
        registry=registry,
        executor=BoundedAgentExecutor(clock=lambda: _NOW),
        approval_service=approval_service,
        approval_resolver=approval_resolver,
        clock=lambda: _NOW,
    )
    return (
        loop,
        run_authorizer,
        tool_authorizer,
        host_authorizer,
        native,
        approval_service,
        approval_resolver,
    )


@pytest.mark.asyncio
async def test_agent_tool_host_path_cannot_bypass_agent_run_boundary() -> None:
    context = _context()
    request = _request()
    run_policy = _run_policy(_INTERNAL_HOST)
    tool_policy = _tool_policy(_REQUESTER)
    host_policy = _host_policy(_REQUESTER)
    loop, run_authorizer, tool_authorizer, host_authorizer, native = _composition_path(
        run_policy=run_policy,
        tool_policy=tool_policy,
        host_policy=host_policy,
    )

    result = await loop.run(request, context)

    assert result.status is AgentRunStatus.FAILED
    assert result.error_code == "authorization_rejected"
    assert run_authorizer.contexts == [context]
    assert run_authorizer.contexts[0] is context
    assert tool_authorizer.contexts == []
    assert host_authorizer.process_list_contexts == []
    assert native.process_list_calls == 0

    run_snapshot = await run_policy.snapshot()
    tool_snapshot = await tool_policy.snapshot()
    host_snapshot = await host_policy.snapshot()
    assert (run_snapshot.allowed, run_snapshot.denied) == (0, 1)
    assert (tool_snapshot.allowed, tool_snapshot.denied) == (0, 0)
    assert (host_snapshot.allowed, host_snapshot.denied) == (0, 0)


@pytest.mark.asyncio
async def test_agent_tool_host_path_cannot_bypass_tool_boundary() -> None:
    context = _context()
    request = _request()
    run_policy = _run_policy(_REQUESTER)
    tool_policy = _tool_policy(_INTERNAL_HOST)
    host_policy = _host_policy(_REQUESTER)
    loop, run_authorizer, tool_authorizer, host_authorizer, native = _composition_path(
        run_policy=run_policy,
        tool_policy=tool_policy,
        host_policy=host_policy,
    )

    result = await loop.run(request, context)

    assert result.status is AgentRunStatus.FAILED
    assert result.error_code == "authorization_rejected"
    assert run_authorizer.contexts == [context, context]
    assert all(item is context for item in run_authorizer.contexts)
    assert tool_authorizer.contexts == [context]
    assert tool_authorizer.contexts[0] is context
    assert host_authorizer.process_list_contexts == []
    assert native.process_list_calls == 0

    run_snapshot = await run_policy.snapshot()
    tool_snapshot = await tool_policy.snapshot()
    host_snapshot = await host_policy.snapshot()
    assert (run_snapshot.allowed, run_snapshot.denied) == (2, 0)
    assert (tool_snapshot.allowed, tool_snapshot.denied) == (0, 1)
    assert (host_snapshot.allowed, host_snapshot.denied) == (0, 0)


@pytest.mark.asyncio
async def test_agent_tool_host_path_does_not_substitute_stronger_internal_identity() -> None:
    context = _context()
    request = _request()
    run_policy = _run_policy(_REQUESTER)
    tool_policy = _tool_policy(_REQUESTER)
    host_policy = _host_policy(_INTERNAL_HOST)
    loop, run_authorizer, tool_authorizer, host_authorizer, native = _composition_path(
        run_policy=run_policy,
        tool_policy=tool_policy,
        host_policy=host_policy,
    )

    result = await loop.run(request, context)

    assert result.status is AgentRunStatus.FAILED
    assert result.error_code == "tool_failed"
    assert run_authorizer.contexts == [context, context]
    assert all(item is context for item in run_authorizer.contexts)
    assert len(tool_authorizer.contexts) == 2
    assert all(item is context for item in tool_authorizer.contexts)
    assert host_authorizer.process_list_contexts == [context]
    assert host_authorizer.process_list_contexts[0] is context
    assert host_authorizer.process_list_contexts[0].principal == _REQUESTER
    assert host_authorizer.process_list_contexts[0].principal != _INTERNAL_HOST
    assert native.process_list_calls == 0

    run_snapshot = await run_policy.snapshot()
    tool_snapshot = await tool_policy.snapshot()
    host_snapshot = await host_policy.snapshot()
    assert (run_snapshot.allowed, run_snapshot.denied) == (2, 0)
    assert (tool_snapshot.allowed, tool_snapshot.denied) == (2, 0)
    assert (host_snapshot.allowed, host_snapshot.denied) == (0, 1)


@pytest.mark.asyncio
async def test_agent_tool_host_path_requires_full_intersection_and_preserves_subject() -> None:
    context = _context()
    request = _request()
    run_policy = _run_policy(_REQUESTER)
    tool_policy = _tool_policy(_REQUESTER)
    host_policy = _host_policy(_REQUESTER)
    loop, run_authorizer, tool_authorizer, host_authorizer, native = _composition_path(
        run_policy=run_policy,
        tool_policy=tool_policy,
        host_policy=host_policy,
    )

    result = await loop.run(request, context)

    assert result.status is AgentRunStatus.COMPLETED
    assert result.final_output == "complete"
    assert run_authorizer.requests == [request, request]
    assert run_authorizer.requests[0] is run_authorizer.requests[1]
    assert run_authorizer.contexts == [context, context]
    assert all(item is context for item in run_authorizer.contexts)
    assert run_authorizer.contexts[0] is context

    assert len(tool_authorizer.requests) == 2
    assert tool_authorizer.requests[0] is tool_authorizer.requests[1]
    assert tool_authorizer.requests[0].agent_id == request.agent_id
    assert tool_authorizer.requests[0].run_id == request.run_id
    assert len(tool_authorizer.contexts) == 2
    assert all(item is context for item in tool_authorizer.contexts)

    assert host_authorizer.process_list_contexts == [context]
    assert host_authorizer.process_list_contexts[0] is context
    assert native.process_list_calls == 1

    run_snapshot = await run_policy.snapshot()
    tool_snapshot = await tool_policy.snapshot()
    host_snapshot = await host_policy.snapshot()
    assert (run_snapshot.allowed, run_snapshot.denied) == (2, 0)
    assert (tool_snapshot.allowed, tool_snapshot.denied) == (2, 0)
    assert (host_snapshot.allowed, host_snapshot.denied) == (1, 0)


@pytest.mark.asyncio
async def test_effectful_agent_tool_host_approval_cannot_replace_requester_subject() -> None:
    context = _context()
    request = _request()
    run_policy = _run_policy(_REQUESTER)
    tool_policy = _launch_tool_policy(_REQUESTER)
    host_policy = _launch_host_policy(_APPROVER)
    (
        loop,
        run_authorizer,
        tool_authorizer,
        host_authorizer,
        native,
        approval_service,
        approval_resolver,
    ) = _effectful_composition_path(
        run_policy=run_policy,
        tool_policy=tool_policy,
        host_policy=host_policy,
    )

    result = await loop.run(request, context)

    assert result.status is AgentRunStatus.FAILED
    assert result.error_code == "tool_failed"
    assert run_authorizer.contexts == [context, context]
    assert all(item is context for item in run_authorizer.contexts)
    assert len(tool_authorizer.contexts) == 2
    assert all(item is context for item in tool_authorizer.contexts)
    assert len(approval_resolver.challenges) == 1
    assert approval_resolver.approver.principal == _APPROVER
    assert host_authorizer.application_launch_contexts == [context]
    assert host_authorizer.application_launch_contexts[0] is context
    assert host_authorizer.application_launch_contexts[0].principal == _REQUESTER
    assert host_authorizer.application_launch_contexts[0].principal != _APPROVER
    assert native.application_launch_calls == 0

    approval_snapshot = await approval_service.snapshot()
    assert approval_snapshot.consumed == 1
    assert approval_snapshot.pending == 0

    run_snapshot = await run_policy.snapshot()
    tool_snapshot = await tool_policy.snapshot()
    host_snapshot = await host_policy.snapshot()
    assert (run_snapshot.allowed, run_snapshot.denied) == (2, 0)
    assert (tool_snapshot.allowed, tool_snapshot.denied) == (2, 0)
    assert (host_snapshot.allowed, host_snapshot.denied) == (0, 1)


@pytest.mark.asyncio
async def test_effectful_agent_tool_host_requires_approval_and_full_intersection() -> None:
    context = _context()
    request = _request()
    run_policy = _run_policy(_REQUESTER)
    tool_policy = _launch_tool_policy(_REQUESTER)
    host_policy = _launch_host_policy(_REQUESTER)
    (
        loop,
        run_authorizer,
        tool_authorizer,
        host_authorizer,
        native,
        approval_service,
        approval_resolver,
    ) = _effectful_composition_path(
        run_policy=run_policy,
        tool_policy=tool_policy,
        host_policy=host_policy,
    )

    result = await loop.run(request, context)

    assert result.status is AgentRunStatus.COMPLETED
    assert result.final_output == "complete"
    assert run_authorizer.contexts == [context, context]
    assert all(item is context for item in run_authorizer.contexts)
    assert len(tool_authorizer.requests) == 2
    assert tool_authorizer.requests[0] is tool_authorizer.requests[1]
    assert tool_authorizer.requests[0].agent_id == request.agent_id
    assert tool_authorizer.requests[0].run_id == request.run_id
    assert all(item is context for item in tool_authorizer.contexts)
    assert len(approval_resolver.challenges) == 1
    assert approval_resolver.approver.principal == _APPROVER
    assert host_authorizer.application_launch_contexts == [context]
    assert host_authorizer.application_launch_contexts[0] is context
    assert host_authorizer.application_launch_contexts[0].principal == _REQUESTER
    assert host_authorizer.application_launch_contexts[0].principal != _APPROVER
    assert native.application_launch_calls == 1

    approval_snapshot = await approval_service.snapshot()
    assert approval_snapshot.consumed == 1
    assert approval_snapshot.pending == 0

    run_snapshot = await run_policy.snapshot()
    tool_snapshot = await tool_policy.snapshot()
    host_snapshot = await host_policy.snapshot()
    assert (run_snapshot.allowed, run_snapshot.denied) == (2, 0)
    assert (tool_snapshot.allowed, tool_snapshot.denied) == (2, 0)
    assert (host_snapshot.allowed, host_snapshot.denied) == (1, 0)


@pytest.mark.asyncio
async def test_agent_tool_memory_path_cannot_bypass_agent_run_boundary() -> None:
    context = _context()
    request = _request()
    run_policy = _run_policy(_APPROVER)
    tool_policy = _memory_write_tool_policy(_REQUESTER)
    memory_policy = _memory_write_policy(_REQUESTER)
    (
        loop,
        run_authorizer,
        tool_authorizer,
        memory_authorizer,
        memory_adapter,
        store,
        approval_service,
        approval_resolver,
    ) = _memory_write_composition_path(
        run_policy=run_policy,
        tool_policy=tool_policy,
        memory_policy=memory_policy,
    )

    result = await loop.run(request, context)

    assert result.status is AgentRunStatus.FAILED
    assert result.error_code == "authorization_rejected"
    assert run_authorizer.contexts == [context]
    assert tool_authorizer.contexts == []
    assert memory_authorizer.write_contexts == []
    assert memory_adapter.contexts == []
    assert approval_resolver.challenges == []
    assert await store.list_scope(_MEMORY_SCOPE) == ()

    approval_snapshot = await approval_service.snapshot()
    assert approval_snapshot.consumed == 0
    assert approval_snapshot.pending == 0

    run_snapshot = await run_policy.snapshot()
    tool_snapshot = await tool_policy.snapshot()
    memory_snapshot = await memory_policy.snapshot()
    assert (run_snapshot.allowed, run_snapshot.denied) == (0, 1)
    assert (tool_snapshot.allowed, tool_snapshot.denied) == (0, 0)
    assert (memory_snapshot.allowed, memory_snapshot.denied) == (0, 0)


@pytest.mark.asyncio
async def test_agent_tool_memory_path_cannot_bypass_tool_boundary() -> None:
    context = _context()
    request = _request()
    run_policy = _run_policy(_REQUESTER)
    tool_policy = _memory_write_tool_policy(_APPROVER)
    memory_policy = _memory_write_policy(_REQUESTER)
    (
        loop,
        run_authorizer,
        tool_authorizer,
        memory_authorizer,
        memory_adapter,
        store,
        approval_service,
        approval_resolver,
    ) = _memory_write_composition_path(
        run_policy=run_policy,
        tool_policy=tool_policy,
        memory_policy=memory_policy,
    )

    result = await loop.run(request, context)

    assert result.status is AgentRunStatus.FAILED
    assert result.error_code == "authorization_rejected"
    assert run_authorizer.contexts == [context, context]
    assert all(item is context for item in run_authorizer.contexts)
    assert tool_authorizer.contexts == [context]
    assert tool_authorizer.contexts[0] is context
    assert memory_authorizer.write_contexts == []
    assert memory_adapter.contexts == []
    assert approval_resolver.challenges == []
    assert await store.list_scope(_MEMORY_SCOPE) == ()

    approval_snapshot = await approval_service.snapshot()
    assert approval_snapshot.consumed == 0
    assert approval_snapshot.pending == 0

    run_snapshot = await run_policy.snapshot()
    tool_snapshot = await tool_policy.snapshot()
    memory_snapshot = await memory_policy.snapshot()
    assert (run_snapshot.allowed, run_snapshot.denied) == (2, 0)
    assert (tool_snapshot.allowed, tool_snapshot.denied) == (0, 1)
    assert (memory_snapshot.allowed, memory_snapshot.denied) == (0, 0)


@pytest.mark.asyncio
async def test_agent_tool_memory_approval_cannot_replace_requester_subject() -> None:
    context = _context()
    request = _request()
    run_policy = _run_policy(_REQUESTER)
    tool_policy = _memory_write_tool_policy(_REQUESTER)
    memory_policy = _memory_write_policy(_APPROVER)
    (
        loop,
        run_authorizer,
        tool_authorizer,
        memory_authorizer,
        memory_adapter,
        store,
        approval_service,
        approval_resolver,
    ) = _memory_write_composition_path(
        run_policy=run_policy,
        tool_policy=tool_policy,
        memory_policy=memory_policy,
    )

    result = await loop.run(request, context)

    assert result.status is AgentRunStatus.FAILED
    assert result.error_code == "tool_failed"
    assert run_authorizer.contexts == [context, context]
    assert all(item is context for item in run_authorizer.contexts)
    assert len(tool_authorizer.contexts) == 2
    assert all(item is context for item in tool_authorizer.contexts)
    assert len(approval_resolver.challenges) == 1
    assert approval_resolver.approver.principal == _APPROVER

    assert memory_adapter.contexts == [context]
    assert memory_adapter.contexts[0] is context
    assert memory_authorizer.write_contexts == [context]
    assert memory_authorizer.write_contexts[0] is context
    assert memory_authorizer.write_contexts[0].principal == _REQUESTER
    assert memory_authorizer.write_contexts[0].principal != _APPROVER
    assert await store.list_scope(_MEMORY_SCOPE) == ()

    approval_snapshot = await approval_service.snapshot()
    assert approval_snapshot.consumed == 1
    assert approval_snapshot.pending == 0

    run_snapshot = await run_policy.snapshot()
    tool_snapshot = await tool_policy.snapshot()
    memory_snapshot = await memory_policy.snapshot()
    assert (run_snapshot.allowed, run_snapshot.denied) == (2, 0)
    assert (tool_snapshot.allowed, tool_snapshot.denied) == (2, 0)
    assert (memory_snapshot.allowed, memory_snapshot.denied) == (0, 1)


@pytest.mark.asyncio
async def test_agent_tool_memory_requires_full_intersection_and_preserves_subject() -> None:
    context = _context()
    request = _request()
    run_policy = _run_policy(_REQUESTER)
    tool_policy = _memory_write_tool_policy(_REQUESTER)
    memory_policy = _memory_write_policy(_REQUESTER)
    (
        loop,
        run_authorizer,
        tool_authorizer,
        memory_authorizer,
        memory_adapter,
        store,
        approval_service,
        approval_resolver,
    ) = _memory_write_composition_path(
        run_policy=run_policy,
        tool_policy=tool_policy,
        memory_policy=memory_policy,
    )

    result = await loop.run(request, context)

    assert result.status is AgentRunStatus.COMPLETED
    assert result.final_output == "complete"
    assert run_authorizer.contexts == [context, context]
    assert all(item is context for item in run_authorizer.contexts)

    assert len(tool_authorizer.requests) == 2
    assert tool_authorizer.requests[0] is tool_authorizer.requests[1]
    assert tool_authorizer.requests[0].agent_id == request.agent_id
    assert tool_authorizer.requests[0].run_id == request.run_id
    assert all(item is context for item in tool_authorizer.contexts)

    assert len(approval_resolver.challenges) == 1
    assert approval_resolver.approver.principal == _APPROVER

    assert len(memory_adapter.requests) == 1
    assert memory_adapter.requests[0] is tool_authorizer.requests[0]
    assert memory_adapter.contexts == [context]
    assert memory_adapter.contexts[0] is context
    assert memory_authorizer.write_contexts == [context]
    assert memory_authorizer.write_contexts[0] is context
    assert memory_authorizer.write_contexts[0].principal == _REQUESTER
    assert memory_authorizer.write_contexts[0].principal != _APPROVER

    records = await store.list_scope(_MEMORY_SCOPE)
    assert len(records) == 1
    record = records[0]
    assert record.memory_id == _MEMORY_ID
    assert record.content == _MEMORY_CONTENT
    assert record.content_digest == memory_content_digest(_MEMORY_CONTENT)
    assert record.provenance is not None
    assert record.provenance.origin is MemoryOriginKind.AGENT_REQUEST
    assert record.provenance.source_run_id == request.run_id
    assert record.provenance.source_agent_id == request.agent_id

    approval_snapshot = await approval_service.snapshot()
    assert approval_snapshot.consumed == 1
    assert approval_snapshot.pending == 0

    run_snapshot = await run_policy.snapshot()
    tool_snapshot = await tool_policy.snapshot()
    memory_snapshot = await memory_policy.snapshot()
    assert (run_snapshot.allowed, run_snapshot.denied) == (2, 0)
    assert (tool_snapshot.allowed, tool_snapshot.denied) == (2, 0)
    assert (memory_snapshot.allowed, memory_snapshot.denied) == (1, 0)


@pytest.mark.asyncio
async def test_agent_tool_workspace_path_cannot_bypass_agent_run_boundary() -> None:
    context = _context()
    request = _request()
    run_policy = _run_policy(_APPROVER)
    tool_policy = _workspace_write_tool_policy(_REQUESTER)
    workspace_policy = _workspace_write_policy(_REQUESTER)
    (
        loop,
        run_authorizer,
        tool_authorizer,
        workspace_authorizer,
        workspace_adapter,
        store,
        approval_service,
        approval_resolver,
    ) = _workspace_write_composition_path(
        run_policy=run_policy,
        tool_policy=tool_policy,
        workspace_policy=workspace_policy,
    )

    result = await loop.run(request, context)

    assert result.status is AgentRunStatus.FAILED
    assert result.error_code == "authorization_rejected"
    assert run_authorizer.contexts == [context]
    assert tool_authorizer.contexts == []
    assert workspace_authorizer.write_contexts == []
    assert workspace_adapter.contexts == []
    assert approval_resolver.challenges == []
    assert store.write_calls == 0
    assert (
        await store.read(
            ArtifactReadRequest(
                scope=_WORKSPACE_SCOPE,
                artifact_id=_WORKSPACE_ARTIFACT_ID,
                created_at=_NOW,
            )
        )
        is None
    )

    approval_snapshot = await approval_service.snapshot()
    assert approval_snapshot.consumed == 0
    assert approval_snapshot.pending == 0

    run_snapshot = await run_policy.snapshot()
    tool_snapshot = await tool_policy.snapshot()
    workspace_snapshot = await workspace_policy.snapshot()
    assert (run_snapshot.allowed, run_snapshot.denied) == (0, 1)
    assert (tool_snapshot.allowed, tool_snapshot.denied) == (0, 0)
    assert (workspace_snapshot.allowed, workspace_snapshot.denied) == (0, 0)


@pytest.mark.asyncio
async def test_agent_tool_workspace_path_cannot_bypass_tool_boundary() -> None:
    context = _context()
    request = _request()
    run_policy = _run_policy(_REQUESTER)
    tool_policy = _workspace_write_tool_policy(_APPROVER)
    workspace_policy = _workspace_write_policy(_REQUESTER)
    (
        loop,
        run_authorizer,
        tool_authorizer,
        workspace_authorizer,
        workspace_adapter,
        store,
        approval_service,
        approval_resolver,
    ) = _workspace_write_composition_path(
        run_policy=run_policy,
        tool_policy=tool_policy,
        workspace_policy=workspace_policy,
    )

    result = await loop.run(request, context)

    assert result.status is AgentRunStatus.FAILED
    assert result.error_code == "authorization_rejected"
    assert run_authorizer.contexts == [context, context]
    assert all(item is context for item in run_authorizer.contexts)
    assert tool_authorizer.contexts == [context]
    assert tool_authorizer.contexts[0] is context
    assert workspace_authorizer.write_contexts == []
    assert workspace_adapter.contexts == []
    assert approval_resolver.challenges == []
    assert store.write_calls == 0
    assert (
        await store.read(
            ArtifactReadRequest(
                scope=_WORKSPACE_SCOPE,
                artifact_id=_WORKSPACE_ARTIFACT_ID,
                created_at=_NOW,
            )
        )
        is None
    )

    approval_snapshot = await approval_service.snapshot()
    assert approval_snapshot.consumed == 0
    assert approval_snapshot.pending == 0

    run_snapshot = await run_policy.snapshot()
    tool_snapshot = await tool_policy.snapshot()
    workspace_snapshot = await workspace_policy.snapshot()
    assert (run_snapshot.allowed, run_snapshot.denied) == (2, 0)
    assert (tool_snapshot.allowed, tool_snapshot.denied) == (0, 1)
    assert (workspace_snapshot.allowed, workspace_snapshot.denied) == (0, 0)


@pytest.mark.asyncio
async def test_agent_tool_workspace_approval_cannot_replace_requester_subject() -> None:
    context = _context()
    request = _request()
    run_policy = _run_policy(_REQUESTER)
    tool_policy = _workspace_write_tool_policy(_REQUESTER)
    workspace_policy = _workspace_write_policy(_APPROVER)
    (
        loop,
        run_authorizer,
        tool_authorizer,
        workspace_authorizer,
        workspace_adapter,
        store,
        approval_service,
        approval_resolver,
    ) = _workspace_write_composition_path(
        run_policy=run_policy,
        tool_policy=tool_policy,
        workspace_policy=workspace_policy,
    )

    result = await loop.run(request, context)

    assert result.status is AgentRunStatus.FAILED
    assert result.error_code == "tool_failed"
    assert run_authorizer.contexts == [context, context]
    assert all(item is context for item in run_authorizer.contexts)
    assert len(tool_authorizer.contexts) == 2
    assert all(item is context for item in tool_authorizer.contexts)
    assert len(approval_resolver.challenges) == 1
    assert approval_resolver.approver.principal == _APPROVER

    assert workspace_adapter.contexts == [context]
    assert workspace_adapter.contexts[0] is context
    assert workspace_authorizer.write_contexts == [context]
    assert workspace_authorizer.write_contexts[0] is context
    assert workspace_authorizer.write_contexts[0].principal == _REQUESTER
    assert workspace_authorizer.write_contexts[0].principal != _APPROVER
    assert store.write_calls == 0
    assert (
        await store.read(
            ArtifactReadRequest(
                scope=_WORKSPACE_SCOPE,
                artifact_id=_WORKSPACE_ARTIFACT_ID,
                created_at=_NOW,
            )
        )
        is None
    )

    approval_snapshot = await approval_service.snapshot()
    assert approval_snapshot.consumed == 1
    assert approval_snapshot.pending == 0

    run_snapshot = await run_policy.snapshot()
    tool_snapshot = await tool_policy.snapshot()
    workspace_snapshot = await workspace_policy.snapshot()
    assert (run_snapshot.allowed, run_snapshot.denied) == (2, 0)
    assert (tool_snapshot.allowed, tool_snapshot.denied) == (2, 0)
    assert (workspace_snapshot.allowed, workspace_snapshot.denied) == (0, 1)


@pytest.mark.asyncio
async def test_agent_tool_workspace_requires_full_intersection_and_preserves_subject() -> None:
    context = _context()
    request = _request()
    run_policy = _run_policy(_REQUESTER)
    tool_policy = _workspace_write_tool_policy(_REQUESTER)
    workspace_policy = _workspace_write_policy(_REQUESTER)
    (
        loop,
        run_authorizer,
        tool_authorizer,
        workspace_authorizer,
        workspace_adapter,
        store,
        approval_service,
        approval_resolver,
    ) = _workspace_write_composition_path(
        run_policy=run_policy,
        tool_policy=tool_policy,
        workspace_policy=workspace_policy,
    )

    result = await loop.run(request, context)

    assert result.status is AgentRunStatus.COMPLETED
    assert result.final_output == "complete"
    assert run_authorizer.contexts == [context, context]
    assert all(item is context for item in run_authorizer.contexts)

    assert len(tool_authorizer.requests) == 2
    assert tool_authorizer.requests[0] is tool_authorizer.requests[1]
    assert tool_authorizer.requests[0].agent_id == request.agent_id
    assert tool_authorizer.requests[0].run_id == request.run_id
    assert all(item is context for item in tool_authorizer.contexts)

    assert len(approval_resolver.challenges) == 1
    assert approval_resolver.approver.principal == _APPROVER

    assert len(workspace_adapter.requests) == 1
    assert workspace_adapter.requests[0] is tool_authorizer.requests[0]
    assert workspace_adapter.contexts == [context]
    assert workspace_adapter.contexts[0] is context
    assert workspace_authorizer.write_contexts == [context]
    assert workspace_authorizer.write_contexts[0] is context
    assert workspace_authorizer.write_contexts[0].principal == _REQUESTER
    assert workspace_authorizer.write_contexts[0].principal != _APPROVER

    assert len(workspace_authorizer.write_requests) == 1
    write_request = workspace_authorizer.write_requests[0]
    assert write_request.scope == _WORKSPACE_SCOPE
    assert write_request.artifact_id == _WORKSPACE_ARTIFACT_ID
    assert write_request.logical_path == _WORKSPACE_LOGICAL_PATH
    assert write_request.content == _WORKSPACE_CONTENT.encode("utf-8")
    assert write_request.provenance.origin is ArtifactOriginKind.AGENT_REQUEST
    assert write_request.provenance.content_digest == artifact_content_digest(write_request.content)
    assert write_request.provenance.source_run_id == request.run_id
    assert write_request.provenance.source_agent_id == request.agent_id

    assert store.write_calls == 1
    stored = await store.read(
        ArtifactReadRequest(
            scope=_WORKSPACE_SCOPE,
            artifact_id=_WORKSPACE_ARTIFACT_ID,
            created_at=_NOW,
        )
    )
    assert stored is not None
    assert stored.content == _WORKSPACE_CONTENT.encode("utf-8")
    record = stored.record
    assert record.scope == _WORKSPACE_SCOPE
    assert record.artifact_id == _WORKSPACE_ARTIFACT_ID
    assert record.logical_path == _WORKSPACE_LOGICAL_PATH
    assert record.content_digest == artifact_content_digest(stored.content)
    assert record.provenance is not None
    assert record.provenance.origin is ArtifactOriginKind.AGENT_REQUEST
    assert record.provenance.source_run_id == request.run_id
    assert record.provenance.source_agent_id == request.agent_id

    approval_snapshot = await approval_service.snapshot()
    assert approval_snapshot.consumed == 1
    assert approval_snapshot.pending == 0

    run_snapshot = await run_policy.snapshot()
    tool_snapshot = await tool_policy.snapshot()
    workspace_snapshot = await workspace_policy.snapshot()
    assert (run_snapshot.allowed, run_snapshot.denied) == (2, 0)
    assert (tool_snapshot.allowed, tool_snapshot.denied) == (2, 0)
    assert (workspace_snapshot.allowed, workspace_snapshot.denied) == (1, 0)


@pytest.mark.asyncio
async def test_parent_child_tool_path_cannot_bypass_delegation_boundary() -> None:
    context = _context()
    delegation_policy = _delegation_policy(_INTERNAL_CHILD)
    child_run_policy = _child_run_policy(_REQUESTER)
    child_tool_policy = _child_tool_policy(_REQUESTER)
    (
        runtime,
        delegation_authorizer,
        child_service,
        child_run_authorizer,
        child_tool_authorizer,
        child_adapter,
    ) = await _parent_child_tool_composition_path(
        delegation_policy=delegation_policy,
        child_run_policy=child_run_policy,
        child_tool_policy=child_tool_policy,
    )

    with pytest.raises(AgentAuthorizationRejectedError):
        await runtime.delegate_and_run(_delegation_request(), context)

    assert delegation_authorizer.contexts == [context]
    assert delegation_authorizer.contexts[0] is context
    assert child_service.run_contexts == []
    assert child_run_authorizer.contexts == []
    assert child_tool_authorizer.contexts == []
    assert child_adapter.contexts == []
    assert child_adapter.calls == 0

    delegation_snapshot = await delegation_policy.snapshot()
    run_snapshot = await child_run_policy.snapshot()
    tool_snapshot = await child_tool_policy.snapshot()
    assert (delegation_snapshot.allowed, delegation_snapshot.denied) == (0, 1)
    assert (run_snapshot.allowed, run_snapshot.denied) == (0, 0)
    assert (tool_snapshot.allowed, tool_snapshot.denied) == (0, 0)


@pytest.mark.asyncio
async def test_parent_child_tool_path_cannot_bypass_child_run_boundary() -> None:
    context = _context()
    delegation_policy = _delegation_policy(_REQUESTER)
    child_run_policy = _child_run_policy(_INTERNAL_CHILD)
    child_tool_policy = _child_tool_policy(_REQUESTER)
    (
        runtime,
        delegation_authorizer,
        child_service,
        child_run_authorizer,
        child_tool_authorizer,
        child_adapter,
    ) = await _parent_child_tool_composition_path(
        delegation_policy=delegation_policy,
        child_run_policy=child_run_policy,
        child_tool_policy=child_tool_policy,
    )

    result = await runtime.delegate_and_run(_delegation_request(), context)

    assert result.status is ChildResultStatus.FAILED
    assert result.error_code == "authorization_rejected"
    assert delegation_authorizer.contexts == [context]
    assert child_service.run_contexts == [context]
    assert child_service.run_contexts[0] is context
    assert child_run_authorizer.contexts == [context]
    assert child_run_authorizer.contexts[0] is context
    assert child_tool_authorizer.contexts == []
    assert child_adapter.contexts == []
    assert child_adapter.calls == 0

    delegation_snapshot = await delegation_policy.snapshot()
    run_snapshot = await child_run_policy.snapshot()
    tool_snapshot = await child_tool_policy.snapshot()
    assert (delegation_snapshot.allowed, delegation_snapshot.denied) == (1, 0)
    assert (run_snapshot.allowed, run_snapshot.denied) == (0, 1)
    assert (tool_snapshot.allowed, tool_snapshot.denied) == (0, 0)


@pytest.mark.asyncio
async def test_parent_child_tool_path_cannot_bypass_child_tool_boundary() -> None:
    context = _context()
    delegation_policy = _delegation_policy(_REQUESTER)
    child_run_policy = _child_run_policy(_REQUESTER)
    child_tool_policy = _child_tool_policy(_INTERNAL_CHILD)
    (
        runtime,
        delegation_authorizer,
        child_service,
        child_run_authorizer,
        child_tool_authorizer,
        child_adapter,
    ) = await _parent_child_tool_composition_path(
        delegation_policy=delegation_policy,
        child_run_policy=child_run_policy,
        child_tool_policy=child_tool_policy,
    )

    result = await runtime.delegate_and_run(_delegation_request(), context)

    assert result.status is ChildResultStatus.FAILED
    assert result.error_code == "authorization_rejected"
    assert delegation_authorizer.contexts == [context]
    assert child_service.run_contexts == [context]
    assert child_run_authorizer.contexts == [context, context]
    assert all(item is context for item in child_run_authorizer.contexts)
    assert child_tool_authorizer.contexts == [context]
    assert child_tool_authorizer.contexts[0] is context
    assert child_adapter.contexts == []
    assert child_adapter.calls == 0

    delegation_snapshot = await delegation_policy.snapshot()
    run_snapshot = await child_run_policy.snapshot()
    tool_snapshot = await child_tool_policy.snapshot()
    assert (delegation_snapshot.allowed, delegation_snapshot.denied) == (1, 0)
    assert (run_snapshot.allowed, run_snapshot.denied) == (2, 0)
    assert (tool_snapshot.allowed, tool_snapshot.denied) == (0, 1)


@pytest.mark.asyncio
async def test_parent_child_tool_requires_full_intersection_and_preserves_subject() -> None:
    context = _context()
    delegation_policy = _delegation_policy(_REQUESTER)
    child_run_policy = _child_run_policy(_REQUESTER)
    child_tool_policy = _child_tool_policy(_REQUESTER)
    (
        runtime,
        delegation_authorizer,
        child_service,
        child_run_authorizer,
        child_tool_authorizer,
        child_adapter,
    ) = await _parent_child_tool_composition_path(
        delegation_policy=delegation_policy,
        child_run_policy=child_run_policy,
        child_tool_policy=child_tool_policy,
    )

    result = await runtime.delegate_and_run(_delegation_request(), context)

    assert result.status is ChildResultStatus.SUCCEEDED
    assert result.error_code is None
    assert result.output == {"final_output": "child complete"}

    assert delegation_authorizer.contexts == [context]
    assert delegation_authorizer.contexts[0] is context
    assert child_service.run_contexts == [context]
    assert child_service.run_contexts[0] is context
    assert child_run_authorizer.contexts == [context, context]
    assert all(item is context for item in child_run_authorizer.contexts)
    assert child_tool_authorizer.contexts == [context, context]
    assert all(item is context for item in child_tool_authorizer.contexts)
    assert child_adapter.contexts == [context]
    assert child_adapter.contexts[0] is context
    assert child_adapter.calls == 1

    assert len(child_service.run_requests) == 1
    child_request = child_service.run_requests[0]
    assert child_request.agent_id == _CHILD_AGENT_ID
    assert child_request.run_id == result.child_run_id

    assert len(child_adapter.requests) == 1
    tool_request = child_adapter.requests[0]
    assert tool_request.agent_id == _CHILD_AGENT_ID
    assert tool_request.run_id == result.child_run_id
    assert tool_request.resolved_resource == _CHILD_TOOL_RESOURCE
    assert tool_request.arguments == {"value": _CHILD_TOOL_VALUE}

    delegation_snapshot = await delegation_policy.snapshot()
    run_snapshot = await child_run_policy.snapshot()
    tool_snapshot = await child_tool_policy.snapshot()
    assert (delegation_snapshot.allowed, delegation_snapshot.denied) == (1, 0)
    assert (run_snapshot.allowed, run_snapshot.denied) == (2, 0)
    assert (tool_snapshot.allowed, tool_snapshot.denied) == (2, 0)


def _durable_resume_context(principal: str = _REQUESTER) -> SecurityContext:
    return SecurityContext(
        principal=principal,
        principal_type=PrincipalType.SERVICE,
        authenticated=True,
        attributes={"durable_actor_id": _DURABLE_RESUME_ACTOR},
    )


def _durable_digest(character: str) -> CheckpointDigest:
    return CheckpointDigest(character * 64)


def _durable_resume_checkpoint() -> CheckpointEnvelope:
    created_at = _NOW - timedelta(minutes=1)
    return seal_checkpoint_envelope(
        CheckpointEnvelope(
            schema_version=CheckpointSchemaVersion(),
            durable_run_id=_DURABLE_RUN_ID,
            checkpoint_id=_DURABLE_CHECKPOINT_ID,
            sequence=CheckpointSequence(1),
            previous_digest=None,
            run_version=DurableRunVersion(1),
            status=DurableRunStatus.PAUSED_SHUTDOWN,
            agent_run_id=_DURABLE_AGENT_RUN_ID,
            step_id=_DURABLE_STEP_ID,
            metadata=CheckpointMetadata(
                agent_id=_CHILD_AGENT_ID,
                actor_id="origin-worker",
                next_operation=CheckpointNextOperation.MODEL_TURN,
                budget=AgentBudgetSnapshot(
                    steps=1,
                    model_turns=0,
                    tool_calls=0,
                    model_output_bytes=0,
                    tool_result_bytes=0,
                    input_tokens=8,
                    output_tokens=0,
                    started_at=created_at,
                    deadline=_NOW + timedelta(minutes=2),
                ),
                compatibility=CompatibilityDigests(
                    configuration=_durable_digest("a"),
                    tool_registry=_durable_digest("b"),
                    model_provider=_durable_digest("c"),
                    checkpoint_codec=_durable_digest("d"),
                ),
                payload_profile=CheckpointPayloadProfile.METADATA_ONLY,
                retention_deadline=_NOW + timedelta(days=1),
                active_attempt=None,
                metadata={"tenant": "composition"},
            ),
            created_at=created_at,
            digest=_durable_digest("0"),
        )
    )


def _durable_resume_policy(principal: str) -> PolicyEngine:
    return PolicyEngine(
        (
            _allow_rule(
                "allow-durable-agent-resume",
                action=AGENT_RESUME_ACTION,
                resource=durable_agent_run_resource(_DURABLE_RUN_ID),
                principal=principal,
            ),
        )
    )


def _durable_resumed_agent_request(checkpoint: CheckpointEnvelope) -> AgentRunRequest:
    return AgentRunRequest(
        agent_id=checkpoint.metadata.agent_id,
        provider_id=ModelProviderId("local"),
        model_id=ModelId("chat"),
        messages=(
            AgentMessage(
                AgentMessageRole.USER,
                "resume and invoke the bounded child composition tool",
            ),
        ),
        run_id=checkpoint.agent_run_id,
        created_at=_NOW,
        deadline=_NOW + timedelta(minutes=2),
    )


class _RecordingDurableResumeAuthorizer(PolicyEngineDurableResumeAuthorizer):
    def __init__(self, policy: PolicyEngine, lease_manager: InMemoryDurableLeaseManager) -> None:
        super().__init__(policy, lease_manager, clock=lambda: _NOW)
        self.requests: list[ResumeRequest] = []
        self.checkpoints: list[CheckpointEnvelope] = []
        self.leases: list[DurableLease] = []
        self.contexts: list[SecurityContext] = []

    async def authorize(
        self,
        request: ResumeRequest,
        checkpoint: CheckpointEnvelope,
        lease: DurableLease,
        context: SecurityContext,
    ) -> None:
        self.requests.append(request)
        self.checkpoints.append(checkpoint)
        self.leases.append(lease)
        self.contexts.append(context)
        await super().authorize(request, checkpoint, lease, context)


class _DurableResumeAgentToolPath:
    def __init__(
        self,
        *,
        resume_authorizer: _RecordingDurableResumeAuthorizer,
        service: _RecordingChildAgentService,
        run_authorizer: _RecordingRunAuthorizer,
        tool_authorizer: _RecordingToolAuthorizer,
        adapter: _ChildCompositionToolAdapter,
        checkpoint: CheckpointEnvelope,
        lease: DurableLease,
        resume_request: ResumeRequest,
        agent_request: AgentRunRequest,
        lease_manager: InMemoryDurableLeaseManager,
    ) -> None:
        self.resume_authorizer = resume_authorizer
        self.service = service
        self.run_authorizer = run_authorizer
        self.tool_authorizer = tool_authorizer
        self.adapter = adapter
        self.checkpoint = checkpoint
        self.lease = lease
        self.resume_request = resume_request
        self.agent_request = agent_request
        self.lease_manager = lease_manager

    async def run(self, context: SecurityContext) -> AgentRunResult:
        await self.resume_authorizer.authorize(
            self.resume_request,
            self.checkpoint,
            self.lease,
            context,
        )
        return await self.service.run(self.agent_request, context)


async def _durable_resume_agent_tool_path(
    *,
    resume_policy: PolicyEngine,
    run_policy: PolicyEngine,
    tool_policy: PolicyEngine,
) -> _DurableResumeAgentToolPath:
    checkpoint = _durable_resume_checkpoint()
    lease_manager = InMemoryDurableLeaseManager()
    lease = await lease_manager.acquire(
        checkpoint.durable_run_id,
        owner_id=_DURABLE_LEASE_OWNER,
        now=_NOW,
    )
    resume_request = ResumeRequest(
        run_id=checkpoint.durable_run_id,
        actor_id=_DURABLE_RESUME_ACTOR,
        reason=ResumeReason.OPERATOR_REQUEST,
        expected_version=checkpoint.run_version,
        generation=lease.generation,
        requested_at=_NOW,
    )
    resume_authorizer = _RecordingDurableResumeAuthorizer(resume_policy, lease_manager)

    descriptor = _child_tool_descriptor()
    configuration = AgentServiceConfiguration(
        agent_id=checkpoint.metadata.agent_id,
        provider_id=ModelProviderId("local"),
        model_id=ModelId("chat"),
        tools=(AgentToolConfiguration(descriptor),),
    )
    registry = ToolRegistry()
    adapter = _ChildCompositionToolAdapter()
    registry.register_tool(
        descriptor,
        resolver=StaticToolResourceResolver(_CHILD_TOOL_RESOLVER_ID, _CHILD_TOOL_RESOURCE),
        adapter=adapter,
    )

    run_authorizer = _RecordingRunAuthorizer(run_policy)
    tool_authorizer = _RecordingToolAuthorizer(tool_policy)
    admission = AgentAdmissionController(configuration.limits)
    model_adapter = DeterministicModelTurnAdapter(
        (
            DeterministicToolTurn(_CHILD_TOOL_ID, {"value": _CHILD_TOOL_VALUE}),
            DeterministicFinalTurn("durable child complete"),
        )
    )
    loop = AgentLoop(
        run_authorizer=run_authorizer,
        model_authorizer=_AllowModelAuthorizer(),
        tool_authorizer=tool_authorizer,
        model_adapter=model_adapter,
        registry=registry,
        executor=BoundedAgentExecutor(clock=lambda: _NOW),
        admission=admission,
        clock=lambda: _NOW,
    )
    service = _RecordingChildAgentService(
        loop,
        registry,
        admission,
        configuration,
        events=EventBus(),
        model_adapter=model_adapter,
        tool_adapters=(adapter,),
    )
    await service.start(RuntimeContext(services={}))

    return _DurableResumeAgentToolPath(
        resume_authorizer=resume_authorizer,
        service=service,
        run_authorizer=run_authorizer,
        tool_authorizer=tool_authorizer,
        adapter=adapter,
        checkpoint=checkpoint,
        lease=lease,
        resume_request=resume_request,
        agent_request=_durable_resumed_agent_request(checkpoint),
        lease_manager=lease_manager,
    )


@pytest.mark.asyncio
async def test_durable_resume_agent_tool_path_cannot_bypass_resume_boundary() -> None:
    context = _durable_resume_context()
    resume_policy = _durable_resume_policy(_INTERNAL_CHILD)
    run_policy = _child_run_policy(_REQUESTER)
    tool_policy = _child_tool_policy(_REQUESTER)
    path = await _durable_resume_agent_tool_path(
        resume_policy=resume_policy,
        run_policy=run_policy,
        tool_policy=tool_policy,
    )

    with pytest.raises(AgentAuthorizationRejectedError):
        await path.run(context)

    assert path.resume_authorizer.contexts == [context]
    assert path.resume_authorizer.contexts[0] is context
    assert path.service.run_contexts == []
    assert path.run_authorizer.contexts == []
    assert path.tool_authorizer.contexts == []
    assert path.adapter.contexts == []
    assert path.adapter.calls == 0

    resume_snapshot = await resume_policy.snapshot()
    run_snapshot = await run_policy.snapshot()
    tool_snapshot = await tool_policy.snapshot()
    assert (resume_snapshot.allowed, resume_snapshot.denied) == (0, 1)
    assert (run_snapshot.allowed, run_snapshot.denied) == (0, 0)
    assert (tool_snapshot.allowed, tool_snapshot.denied) == (0, 0)


@pytest.mark.asyncio
async def test_durable_resume_agent_tool_path_cannot_bypass_agent_run_boundary() -> None:
    context = _durable_resume_context()
    resume_policy = _durable_resume_policy(_REQUESTER)
    run_policy = _child_run_policy(_INTERNAL_CHILD)
    tool_policy = _child_tool_policy(_REQUESTER)
    path = await _durable_resume_agent_tool_path(
        resume_policy=resume_policy,
        run_policy=run_policy,
        tool_policy=tool_policy,
    )

    result = await path.run(context)

    assert result.status is AgentRunStatus.FAILED
    assert result.error_code == "authorization_rejected"
    assert path.resume_authorizer.contexts == [context]
    assert path.service.run_contexts == [context]
    assert path.service.run_contexts[0] is context
    assert path.run_authorizer.contexts == [context]
    assert path.run_authorizer.contexts[0] is context
    assert path.tool_authorizer.contexts == []
    assert path.adapter.contexts == []
    assert path.adapter.calls == 0

    resume_snapshot = await resume_policy.snapshot()
    run_snapshot = await run_policy.snapshot()
    tool_snapshot = await tool_policy.snapshot()
    assert (resume_snapshot.allowed, resume_snapshot.denied) == (1, 0)
    assert (run_snapshot.allowed, run_snapshot.denied) == (0, 1)
    assert (tool_snapshot.allowed, tool_snapshot.denied) == (0, 0)


@pytest.mark.asyncio
async def test_durable_resume_agent_tool_path_cannot_bypass_tool_boundary() -> None:
    context = _durable_resume_context()
    resume_policy = _durable_resume_policy(_REQUESTER)
    run_policy = _child_run_policy(_REQUESTER)
    tool_policy = _child_tool_policy(_INTERNAL_CHILD)
    path = await _durable_resume_agent_tool_path(
        resume_policy=resume_policy,
        run_policy=run_policy,
        tool_policy=tool_policy,
    )

    result = await path.run(context)

    assert result.status is AgentRunStatus.FAILED
    assert result.error_code == "authorization_rejected"
    assert path.resume_authorizer.contexts == [context]
    assert path.service.run_contexts == [context]
    assert path.run_authorizer.contexts == [context, context]
    assert all(item is context for item in path.run_authorizer.contexts)
    assert path.tool_authorizer.contexts == [context]
    assert path.tool_authorizer.contexts[0] is context
    assert path.adapter.contexts == []
    assert path.adapter.calls == 0

    resume_snapshot = await resume_policy.snapshot()
    run_snapshot = await run_policy.snapshot()
    tool_snapshot = await tool_policy.snapshot()
    assert (resume_snapshot.allowed, resume_snapshot.denied) == (1, 0)
    assert (run_snapshot.allowed, run_snapshot.denied) == (2, 0)
    assert (tool_snapshot.allowed, tool_snapshot.denied) == (0, 1)


@pytest.mark.asyncio
async def test_durable_resume_agent_tool_requires_full_intersection_and_preserves_subject() -> None:
    context = _durable_resume_context()
    resume_policy = _durable_resume_policy(_REQUESTER)
    run_policy = _child_run_policy(_REQUESTER)
    tool_policy = _child_tool_policy(_REQUESTER)
    path = await _durable_resume_agent_tool_path(
        resume_policy=resume_policy,
        run_policy=run_policy,
        tool_policy=tool_policy,
    )

    result = await path.run(context)

    assert result.status is AgentRunStatus.COMPLETED
    assert result.error_code is None
    assert result.final_output == "durable child complete"

    assert path.resume_authorizer.requests == [path.resume_request]
    assert path.resume_authorizer.checkpoints == [path.checkpoint]
    assert path.resume_authorizer.checkpoints[0] is path.checkpoint
    assert path.resume_authorizer.leases == [path.lease]
    assert path.resume_authorizer.leases[0] is path.lease
    assert path.resume_authorizer.contexts == [context]
    assert path.resume_authorizer.contexts[0] is context

    assert path.service.run_requests == [path.agent_request]
    assert path.service.run_contexts == [context]
    assert path.service.run_contexts[0] is context
    assert path.agent_request.agent_id == path.checkpoint.metadata.agent_id
    assert path.agent_request.run_id == path.checkpoint.agent_run_id

    assert path.run_authorizer.requests == [path.agent_request, path.agent_request]
    assert path.run_authorizer.requests[0] is path.run_authorizer.requests[1]
    assert path.run_authorizer.contexts == [context, context]
    assert all(item is context for item in path.run_authorizer.contexts)

    assert len(path.tool_authorizer.requests) == 2
    assert path.tool_authorizer.requests[0] is path.tool_authorizer.requests[1]
    assert path.tool_authorizer.contexts == [context, context]
    assert all(item is context for item in path.tool_authorizer.contexts)

    assert path.adapter.calls == 1
    assert path.adapter.contexts == [context]
    assert path.adapter.contexts[0] is context
    assert len(path.adapter.requests) == 1
    tool_request = path.adapter.requests[0]
    assert tool_request.agent_id == path.checkpoint.metadata.agent_id
    assert tool_request.run_id == path.checkpoint.agent_run_id
    assert tool_request.resolved_resource == _CHILD_TOOL_RESOURCE
    assert tool_request.arguments == {"value": _CHILD_TOOL_VALUE}

    resume_snapshot = await resume_policy.snapshot()
    run_snapshot = await run_policy.snapshot()
    tool_snapshot = await tool_policy.snapshot()
    assert (resume_snapshot.allowed, resume_snapshot.denied) == (1, 0)
    assert (run_snapshot.allowed, run_snapshot.denied) == (2, 0)
    assert (tool_snapshot.allowed, tool_snapshot.denied) == (2, 0)


@pytest.mark.asyncio
async def test_workspace_host_indirect_path_cannot_bypass_workspace_export_boundary() -> None:
    context = _context()
    workspace_policy = _workspace_export_policy(_INTERNAL_HOST)
    host_policy = _host_clipboard_write_policy(_REQUESTER)
    path = await _workspace_host_indirect_path(
        workspace_policy=workspace_policy,
        host_policy=host_policy,
        context=context,
    )

    with pytest.raises(AgentAuthorizationRejectedError):
        await path.run(context)

    assert path.workspace_authorizer.export_contexts == [context]
    assert path.workspace_authorizer.export_contexts[0] is context
    assert path.transfer_adapter.export_calls == 0
    assert path.transfer_adapter.export_payloads == []
    assert path.host_authorizer.clipboard_write_contexts == []
    assert path.host_adapter.clipboard_write_calls == 0

    workspace_snapshot = await workspace_policy.snapshot()
    host_snapshot = await host_policy.snapshot()
    assert (workspace_snapshot.allowed, workspace_snapshot.denied) == (0, 1)
    assert (host_snapshot.allowed, host_snapshot.denied) == (0, 0)


@pytest.mark.asyncio
async def test_workspace_data_cannot_amplify_into_indirect_host_authority() -> None:
    context = _context()
    workspace_policy = _workspace_export_policy(_REQUESTER)
    host_policy = _host_clipboard_write_policy(_INTERNAL_HOST)
    path = await _workspace_host_indirect_path(
        workspace_policy=workspace_policy,
        host_policy=host_policy,
        context=context,
    )

    with pytest.raises(AgentServiceUnavailableError):
        await path.run(context)

    assert path.workspace_authorizer.export_contexts == [context, context]
    assert all(item is context for item in path.workspace_authorizer.export_contexts)
    assert path.transfer_adapter.export_calls == 1
    assert len(path.transfer_adapter.export_payloads) == 1

    payload = path.transfer_adapter.export_payloads[0]
    assert payload.content == _WORKSPACE_HOST_BYTES
    assert payload.content_digest == artifact_content_digest(_WORKSPACE_HOST_BYTES)
    assert payload.destination_reference == _WORKSPACE_HOST_DESTINATION
    assert _INTERNAL_HOST in payload.content.decode("utf-8")
    for forbidden_attribute in (
        "context",
        "principal",
        "credential",
        "policy",
        "host_root",
        "approval",
    ):
        assert not hasattr(payload, forbidden_attribute)

    assert len(path.transfer_adapter.host_requests) == 1
    assert path.transfer_adapter.host_requests[0].text == _WORKSPACE_HOST_CONTENT
    assert path.host_authorizer.clipboard_write_contexts == [context]
    assert path.host_authorizer.clipboard_write_contexts[0] is context
    assert path.host_adapter.clipboard_write_calls == 0
    assert path.transfer_adapter.host_results == []

    workspace_snapshot = await workspace_policy.snapshot()
    host_snapshot = await host_policy.snapshot()
    assert (workspace_snapshot.allowed, workspace_snapshot.denied) == (2, 0)
    assert (host_snapshot.allowed, host_snapshot.denied) == (0, 1)


@pytest.mark.asyncio
async def test_workspace_host_indirect_path_requires_full_intersection_and_preserves_subject() -> (
    None
):
    context = _context()
    workspace_policy = _workspace_export_policy(_REQUESTER)
    host_policy = _host_clipboard_write_policy(_REQUESTER)
    path = await _workspace_host_indirect_path(
        workspace_policy=workspace_policy,
        host_policy=host_policy,
        context=context,
    )

    receipt = await path.run(context)

    assert path.workspace_authorizer.export_contexts == [context, context]
    assert all(item is context for item in path.workspace_authorizer.export_contexts)
    assert len(path.workspace_authorizer.export_requests) == 2
    assert path.workspace_authorizer.export_requests[0] == path.export_request
    assert path.workspace_authorizer.export_requests[1] == path.export_request

    assert path.transfer_adapter.export_calls == 1
    assert len(path.transfer_adapter.export_payloads) == 1
    payload = path.transfer_adapter.export_payloads[0]
    assert payload.content == _WORKSPACE_HOST_BYTES
    assert payload.content_digest == artifact_content_digest(_WORKSPACE_HOST_BYTES)
    assert payload.destination_reference == _WORKSPACE_HOST_DESTINATION

    assert len(path.transfer_adapter.host_requests) == 1
    host_request = path.transfer_adapter.host_requests[0]
    assert host_request.host_id == _HOST_ID
    assert host_request.text == _WORKSPACE_HOST_CONTENT

    assert path.host_authorizer.clipboard_write_contexts == [context]
    assert path.host_authorizer.clipboard_write_contexts[0] is context
    assert path.host_authorizer.clipboard_write_requests == [host_request]
    assert path.host_adapter.clipboard_write_calls == 1

    assert len(path.transfer_adapter.host_results) == 1
    host_result = path.transfer_adapter.host_results[0]
    assert host_result.host_id == _HOST_ID
    assert host_result.request_id == host_request.request_id
    assert host_result.written_characters == len(_WORKSPACE_HOST_CONTENT)
    assert host_result.written_bytes == len(_WORKSPACE_HOST_BYTES)

    clipboard = await path.host_adapter.read_clipboard(
        HostClipboardReadRequest(
            host_id=_HOST_ID,
            created_at=_NOW,
        )
    )
    assert clipboard.text == _WORKSPACE_HOST_CONTENT

    assert receipt.scope == _WORKSPACE_SCOPE
    assert receipt.artifact_id == _WORKSPACE_ARTIFACT_ID
    assert receipt.content_digest == artifact_content_digest(_WORKSPACE_HOST_BYTES)
    assert receipt.byte_length == len(_WORKSPACE_HOST_BYTES)
    assert receipt.adapter_id == _WORKSPACE_HOST_ADAPTER_ID
    assert receipt.transfer_reference == _WORKSPACE_HOST_DESTINATION

    workspace_snapshot = await workspace_policy.snapshot()
    host_snapshot = await host_policy.snapshot()
    assert (workspace_snapshot.allowed, workspace_snapshot.denied) == (2, 0)
    assert (host_snapshot.allowed, host_snapshot.denied) == (1, 0)


def test_tool_to_network_path_is_reviewed_without_authority_union() -> None:
    from phoenix_os.authority import (
        BUILTIN_AUTHORITY_CATALOG,
        AuthorityEffect,
        AuthorityFreshnessBinding,
        AuthorityIntent,
        AuthorityPathObservation,
    )

    intent = AuthorityIntent(
        action="network.http.request",
        canonical_resource="network-egress:composition/generation:3/operation:read",
        parameter_digest="sha256:" + "c" * 64,
        freshness_bindings=(
            AuthorityFreshnessBinding(
                "network.profile.generation",
                "composition:3",
            ),
        ),
    )
    observation = AuthorityPathObservation(
        intent=intent,
        boundaries=("tool.invoke", "network.http.request"),
        effect=AuthorityEffect.ALLOWED,
    )

    BUILTIN_AUTHORITY_CATALOG.validate_observation(observation)
    assert ("tool.invoke", "network.http.request") in (
        BUILTIN_AUTHORITY_CATALOG.mediated_transitions
    )
