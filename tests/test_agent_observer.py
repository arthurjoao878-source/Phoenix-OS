from datetime import UTC, datetime, timedelta

import pytest

from phoenix_os.agent import (
    AgentId,
    AgentMessage,
    AgentMessageRole,
    AgentRunRequest,
    AgentServiceConfiguration,
    AgentToolConfiguration,
    DeterministicFinalTurn,
    DeterministicModelTurnAdapter,
    DeterministicReadOnlyTool,
    DeterministicSideEffectTool,
    DeterministicToolTurn,
    InMemoryToolApprovalService,
    StaticToolResourceResolver,
    ToolApprovalChallenge,
    ToolApprovalEvidence,
    ToolDescriptor,
    ToolEffect,
    ToolId,
    ToolInputSchema,
    ToolOutputSchema,
    ToolSchema,
    ToolSchemaType,
    agent_run_resource,
    create_agent_runtime_stack,
)
from phoenix_os.audit import AuditLedger, AuditQuery, InMemoryAuditStore
from phoenix_os.events import Event, EventBus
from phoenix_os.inference import ModelId, ModelProviderId, inference_model_resource
from phoenix_os.observability import InMemorySink, ObservabilityHub
from phoenix_os.policy import PolicyEffect, PolicyEngine, PolicyRule, PrincipalType, SecurityContext
from phoenix_os.runtime import RuntimeContext


def _schema() -> ToolSchema:
    return ToolSchema(
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


def _descriptor(*, effect: ToolEffect = ToolEffect.READ_ONLY) -> ToolDescriptor:
    schema = _schema()
    return ToolDescriptor(
        tool_id=ToolId("lookup"),
        name="Lookup",
        description="One reviewed deterministic lookup.",
        input_schema=ToolInputSchema(schema),
        output_schema=ToolOutputSchema(schema),
        effect=effect,
        approval_may_be_required=effect is not ToolEffect.READ_ONLY,
        max_input_bytes=4_096,
        max_output_bytes=4_096,
        timeout=timedelta(seconds=5),
        resolver_id="lookup.resolver",
        adapter_id="lookup.adapter",
    )


def _configuration(descriptor: ToolDescriptor) -> AgentServiceConfiguration:
    return AgentServiceConfiguration(
        agent_id=AgentId("nova"),
        provider_id=ModelProviderId("deterministic"),
        model_id=ModelId("chat"),
        tools=(AgentToolConfiguration(descriptor),),
    )


def _context() -> SecurityContext:
    return SecurityContext(
        principal="service:assistant",
        principal_type=PrincipalType.SERVICE,
        authenticated=True,
        correlation_id="corr-agent-observer",
    )


def _policy(configuration: AgentServiceConfiguration) -> PolicyEngine:
    return PolicyEngine(
        (
            PolicyRule(
                rule_id="allow.agent.run",
                effect=PolicyEffect.ALLOW,
                actions=frozenset({"agent.run"}),
                resources=frozenset({agent_run_resource(configuration.agent_id)}),
                principals=frozenset({"service:assistant"}),
                authenticated=True,
            ),
            PolicyRule(
                rule_id="allow.agent.model",
                effect=PolicyEffect.ALLOW,
                actions=frozenset({"model.infer"}),
                resources=frozenset(
                    {
                        inference_model_resource(
                            configuration.provider_id,
                            configuration.model_id,
                        )
                    }
                ),
                principals=frozenset({"service:assistant"}),
                authenticated=True,
            ),
            PolicyRule(
                rule_id="allow.agent.tool",
                effect=PolicyEffect.ALLOW,
                actions=frozenset({"tool.invoke"}),
                resources=frozenset({"tool:lookup/record:fixed"}),
                principals=frozenset({"service:assistant"}),
                authenticated=True,
            ),
        )
    )


class _ImmediateApprovalResolver:
    def __init__(
        self,
        service: InMemoryToolApprovalService,
        approver: SecurityContext,
    ) -> None:
        self._service = service
        self._approver = approver

    async def resolve(self, challenge: ToolApprovalChallenge) -> ToolApprovalEvidence:
        return await self._service.approve(challenge.approval_id, self._approver)


@pytest.mark.asyncio
async def test_internal_agent_operations_emit_content_free_fixed_signals() -> None:
    prompt = "TOP-SECRET-PROMPT-4D"
    argument = "TOP-SECRET-ARGUMENT-4D"
    tool_output = "TOP-SECRET-TOOL-RESULT-4D"
    final_output = "TOP-SECRET-FINAL-RESULT-4D"
    descriptor = _descriptor()
    configuration = _configuration(descriptor)
    events = EventBus()
    captured: list[Event] = []

    async def capture(event: Event) -> None:
        if event.name.startswith("agent."):
            captured.append(event)

    await events.subscribe("*", capture)
    store = InMemoryAuditStore()
    audit = AuditLedger(store)
    sink = InMemorySink(capacity=500)
    observability = ObservabilityHub((sink,))
    stack = create_agent_runtime_stack(
        configuration=configuration,
        model_adapter=DeterministicModelTurnAdapter(
            (
                DeterministicToolTurn(descriptor.tool_id, {"value": argument}),
                DeterministicFinalTurn(final_output),
            )
        ),
        tool_resolvers=(StaticToolResourceResolver(descriptor.resolver_id, "record:fixed"),),
        tool_adapters=(
            DeterministicReadOnlyTool(
                descriptor.tool_id,
                {"value": tool_output},
                adapter_id=descriptor.adapter_id,
            ),
        ),
        policy=_policy(configuration),
        events=events,
        audit=audit,
        observability=observability,
    )
    now = datetime.now(UTC)
    request = AgentRunRequest(
        agent_id=configuration.agent_id,
        provider_id=configuration.provider_id,
        model_id=configuration.model_id,
        messages=(AgentMessage(AgentMessageRole.USER, prompt),),
        limits=configuration.limits,
        created_at=now,
        deadline=now + timedelta(minutes=1),
    )

    await stack.service.start(RuntimeContext(services={}))
    result = await stack.service.run(request, _context())

    assert result.final_output == final_output
    names = {event.name for event in captured}
    assert {
        "agent.tool.registered",
        "agent.authorization.run.succeeded",
        "agent.admission.run.succeeded",
        "agent.authorization.model.succeeded",
        "agent.model.turn.started",
        "agent.model.turn.succeeded",
        "agent.proposal.validation.succeeded",
        "agent.authorization.tool.succeeded",
        "agent.tool.invocation.started",
        "agent.tool.invocation.succeeded",
    } <= names
    assert all(event.payload == {} for event in captured)

    records = await store.read(AuditQuery(limit=1000))
    observations = (await sink.snapshot()).records
    serialized = repr((captured, records, observations))
    for secret in (prompt, argument, tool_output, final_output):
        assert secret not in serialized
    assert "sha256:" in serialized
    assert "resource_category" in serialized
    assert str(request.run_id) in serialized

    await stack.service.stop(RuntimeContext(services={}))


@pytest.mark.asyncio
async def test_approval_operations_emit_requested_approved_and_consumed() -> None:
    descriptor = _descriptor(effect=ToolEffect.EXTERNAL_COMMUNICATION)
    configuration = _configuration(descriptor)
    events = EventBus()
    captured: list[Event] = []

    async def capture(event: Event) -> None:
        if event.name.startswith("agent.approval."):
            captured.append(event)

    await events.subscribe("*", capture)
    approvals = InMemoryToolApprovalService()
    resolver = _ImmediateApprovalResolver(approvals, _context())
    stack = create_agent_runtime_stack(
        configuration=configuration,
        model_adapter=DeterministicModelTurnAdapter(
            (
                DeterministicToolTurn(descriptor.tool_id, {"value": "send"}),
                DeterministicFinalTurn("done"),
            )
        ),
        tool_resolvers=(StaticToolResourceResolver(descriptor.resolver_id, "record:fixed"),),
        tool_adapters=(
            DeterministicSideEffectTool(
                descriptor.tool_id,
                {"value": "sent"},
                adapter_id=descriptor.adapter_id,
            ),
        ),
        policy=_policy(configuration),
        events=events,
        approval_service=approvals,
        approval_resolver=resolver,
    )
    now = datetime.now(UTC)
    request = AgentRunRequest(
        agent_id=configuration.agent_id,
        provider_id=configuration.provider_id,
        model_id=configuration.model_id,
        messages=(AgentMessage(AgentMessageRole.USER, "send it"),),
        limits=configuration.limits,
        created_at=now,
        deadline=now + timedelta(minutes=1),
    )

    await stack.service.start(RuntimeContext(services={}))
    result = await stack.service.run(request, _context())

    assert result.final_output == "done"
    assert [event.name for event in captured] == [
        "agent.approval.requested",
        "agent.approval.approved",
        "agent.approval.consumed",
    ]
    assert all(event.payload == {} for event in captured)
    assert all("argument_digest" in event.metadata for event in captured)

    await stack.service.stop(RuntimeContext(services={}))
