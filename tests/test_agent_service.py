import asyncio
from datetime import UTC, datetime, timedelta

import pytest

from phoenix_os.agent import (
    AgentId,
    AgentLimits,
    AgentMessage,
    AgentMessageRole,
    AgentModelTurnRequest,
    AgentModelTurnResult,
    AgentRunRequest,
    AgentRunStatus,
    AgentServiceConfiguration,
    AgentServiceState,
    AgentToolConfiguration,
    DeterministicFinalTurn,
    DeterministicModelTurnAdapter,
    DeterministicReadOnlyTool,
    StaticToolResourceResolver,
    ToolDescriptor,
    ToolEffect,
    ToolId,
    ToolInputSchema,
    ToolInvocationRequest,
    ToolInvocationResult,
    ToolOutputSchema,
    ToolSchema,
    ToolSchemaType,
    agent_run_resource,
    create_agent_runtime_stack,
)
from phoenix_os.agent.authorization import AgentRunAuthorityBinding
from phoenix_os.audit import AuditLedger, AuditQuery, InMemoryAuditStore
from phoenix_os.events import Event, EventBus
from phoenix_os.inference import ModelId, ModelProviderId, inference_model_resource
from phoenix_os.observability import InMemorySink, ObservabilityHub
from phoenix_os.policy import PolicyEffect, PolicyEngine, PolicyRule, PrincipalType, SecurityContext
from phoenix_os.runtime import RuntimeContext


def _context() -> SecurityContext:
    return SecurityContext(
        principal="service:assistant",
        principal_type=PrincipalType.SERVICE,
        authenticated=True,
        correlation_id="corr-agent",
    )


def _runtime_context() -> RuntimeContext:
    return RuntimeContext(services={})


def _configuration(*, limits: AgentLimits | None = None) -> AgentServiceConfiguration:
    return AgentServiceConfiguration(
        agent_id=AgentId("nova"),
        provider_id=ModelProviderId("deterministic"),
        model_id=ModelId("chat"),
        limits=AgentLimits() if limits is None else limits,
    )


def _request(configuration: AgentServiceConfiguration, *, prompt: str = "hello") -> AgentRunRequest:
    now = datetime.now(UTC)
    return AgentRunRequest(
        agent_id=configuration.agent_id,
        provider_id=configuration.provider_id,
        model_id=configuration.model_id,
        messages=(AgentMessage(AgentMessageRole.USER, prompt),),
        limits=configuration.limits,
        created_at=now,
        deadline=now + min(configuration.limits.total_duration, timedelta(minutes=1)),
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
        )
    )


class BlockingModelAdapter:
    adapter_id = "blocking-agent-model"

    def __init__(self) -> None:
        self.started = asyncio.Event()
        self.cancelled = asyncio.Event()
        self.closed = False

    async def complete_turn(self, request: AgentModelTurnRequest) -> AgentModelTurnResult:
        del request
        self.started.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            self.cancelled.set()
            raise
        raise AssertionError("unreachable")

    async def aclose(self) -> None:
        self.closed = True


@pytest.mark.asyncio
async def test_agent_service_lifecycle_health_and_content_free_signals() -> None:
    prompt = "TOP-SECRET-AGENT-PROMPT-4187"
    response = "TOP-SECRET-AGENT-RESULT-9241"
    configuration = _configuration()
    events = EventBus()
    captured: list[Event] = []

    async def capture(event: Event) -> None:
        if event.name.startswith("agent."):
            captured.append(event)

    await events.subscribe("*", capture)
    store = InMemoryAuditStore()
    audit = AuditLedger(store)
    sink = InMemorySink(capacity=100)
    observability = ObservabilityHub((sink,))
    stack = create_agent_runtime_stack(
        configuration=configuration,
        model_adapter=DeterministicModelTurnAdapter((DeterministicFinalTurn(response),)),
        tool_resolvers=(),
        tool_adapters=(),
        policy=_policy(configuration),
        events=events,
        audit=audit,
        observability=observability,
    )

    created = await stack.service.snapshot()
    assert created.state is AgentServiceState.CREATED
    assert created.accepting is False

    await stack.service.start(_runtime_context())
    result = await stack.service.run(_request(configuration, prompt=prompt), _context())
    running = await stack.service.snapshot()

    assert result.status is AgentRunStatus.COMPLETED
    assert result.final_output == response
    assert running.state is AgentServiceState.RUNNING
    assert running.started == 1
    assert running.completed == 1
    assert running.active == 0
    assert all(event.payload == {} for event in captured)

    records = await store.read(AuditQuery(limit=1000))
    observations = (await sink.snapshot()).records
    serialized = repr((captured, records, observations, running))
    assert prompt not in serialized
    assert response not in serialized
    assert str(result.run_id) in serialized
    assert str(configuration.agent_id) in serialized

    await stack.service.stop(_runtime_context())
    stopped = await stack.service.snapshot()
    assert stopped.state is AgentServiceState.STOPPED
    assert stopped.accepting is False


@pytest.mark.asyncio
async def test_agent_service_propagates_bound_agent_run_authority_to_loop() -> None:
    configuration = _configuration()
    parameter_digest = "sha256:" + ("6" * 64)
    binding = AgentRunAuthorityBinding(
        parameter_digest=parameter_digest,
        attributes=(
            ("integrated_profile_generation", "7"),
            ("integrated_profile_id", "integrated-research"),
            ("integrated_task_digest", "sha256:" + ("5" * 64)),
        ),
    )
    policy = PolicyEngine(
        (
            PolicyRule(
                rule_id="allow.bound.agent.run",
                effect=PolicyEffect.ALLOW,
                actions=frozenset({"agent.run"}),
                resources=frozenset({agent_run_resource(configuration.agent_id)}),
                principals=frozenset({"service:assistant"}),
                authenticated=True,
                attribute_equals={
                    "authority_parameter_digest": parameter_digest,
                    "integrated_profile_generation": "7",
                    "integrated_profile_id": "integrated-research",
                    "integrated_task_digest": "sha256:" + ("5" * 64),
                },
            ),
            PolicyRule(
                rule_id="allow.bound.agent.model",
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
        )
    )
    stack = create_agent_runtime_stack(
        configuration=configuration,
        model_adapter=DeterministicModelTurnAdapter((DeterministicFinalTurn("done"),)),
        tool_resolvers=(),
        tool_adapters=(),
        policy=policy,
        events=EventBus(),
    )
    await stack.service.start(_runtime_context())

    result = await stack.service.run(
        _request(configuration),
        _context(),
        _authority_binding=binding,
    )

    assert result.status is AgentRunStatus.COMPLETED
    assert result.final_output == "done"
    await stack.service.stop(_runtime_context())


@pytest.mark.asyncio
async def test_agent_shutdown_rejects_new_work_and_cancels_active_run_within_bounds() -> None:
    limits = AgentLimits(
        cancellation_grace=timedelta(milliseconds=50),
        shutdown_grace=timedelta(milliseconds=100),
    )
    configuration = _configuration(limits=limits)
    adapter = BlockingModelAdapter()
    stack = create_agent_runtime_stack(
        configuration=configuration,
        model_adapter=adapter,
        tool_resolvers=(),
        tool_adapters=(),
        policy=_policy(configuration),
        events=EventBus(),
    )
    await stack.service.start(_runtime_context())
    invocation = asyncio.create_task(stack.service.run(_request(configuration), _context()))

    await asyncio.wait_for(adapter.started.wait(), timeout=1)
    await stack.service.stop(_runtime_context())
    result = await asyncio.wait_for(invocation, timeout=1)

    assert result.status is AgentRunStatus.CANCELLED
    assert adapter.cancelled.is_set()
    assert adapter.closed is True
    snapshot = await stack.service.snapshot()
    assert snapshot.state is AgentServiceState.STOPPED
    assert snapshot.cancelled == 1
    assert snapshot.active == 0


def _tool_schema() -> ToolSchema:
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


def _descriptor(tool_id: str) -> ToolDescriptor:
    return ToolDescriptor(
        tool_id=ToolId(tool_id),
        name=f"Tool {tool_id}",
        description="One reviewed close-order test tool.",
        input_schema=ToolInputSchema(_tool_schema()),
        output_schema=ToolOutputSchema(_tool_schema()),
        effect=ToolEffect.READ_ONLY,
        approval_may_be_required=False,
        max_input_bytes=4_096,
        max_output_bytes=4_096,
        timeout=timedelta(seconds=5),
        resolver_id=f"{tool_id}.resolver",
        adapter_id=f"{tool_id}.adapter",
    )


class ClosingToolAdapter:
    def __init__(self, descriptor: ToolDescriptor, closed: list[str]) -> None:
        self._delegate = DeterministicReadOnlyTool(
            descriptor.tool_id,
            {"value": "ok"},
            adapter_id=descriptor.adapter_id,
        )
        self._closed = closed

    @property
    def adapter_id(self) -> str:
        return self._delegate.adapter_id

    @property
    def tool_id(self) -> ToolId:
        return self._delegate.tool_id

    async def invoke(self, request: ToolInvocationRequest) -> ToolInvocationResult:
        return await self._delegate.invoke(request)

    async def aclose(self) -> None:
        self._closed.append(str(self.tool_id))


class ClosingModelAdapter:
    adapter_id = "closing-model"

    def __init__(self, closed: list[str]) -> None:
        self._delegate = DeterministicModelTurnAdapter((DeterministicFinalTurn("done"),))
        self._closed = closed

    async def complete_turn(self, request: AgentModelTurnRequest) -> AgentModelTurnResult:
        return await self._delegate.complete_turn(request)

    async def aclose(self) -> None:
        self._closed.append("model")


@pytest.mark.asyncio
async def test_agent_shutdown_closes_tool_adapters_in_reverse_composition_order() -> None:
    first = _descriptor("first")
    second = _descriptor("second")
    configuration = AgentServiceConfiguration(
        agent_id=AgentId("nova"),
        provider_id=ModelProviderId("deterministic"),
        model_id=ModelId("chat"),
        tools=(AgentToolConfiguration(first), AgentToolConfiguration(second)),
    )
    closed: list[str] = []
    stack = create_agent_runtime_stack(
        configuration=configuration,
        model_adapter=ClosingModelAdapter(closed),
        tool_resolvers=(
            StaticToolResourceResolver(first.resolver_id, "first/resource"),
            StaticToolResourceResolver(second.resolver_id, "second/resource"),
        ),
        tool_adapters=(
            ClosingToolAdapter(first, closed),
            ClosingToolAdapter(second, closed),
        ),
        policy=_policy(configuration),
        events=EventBus(),
    )

    await stack.service.start(_runtime_context())
    await stack.service.stop(_runtime_context())

    assert closed == ["second", "first", "model"]


class StubbornClosingModelAdapter:
    adapter_id = "stubborn-closing-model"

    def __init__(self) -> None:
        self._delegate = DeterministicModelTurnAdapter((DeterministicFinalTurn("done"),))
        self.close_started = asyncio.Event()
        self.release = asyncio.Event()

    async def complete_turn(self, request: AgentModelTurnRequest) -> AgentModelTurnResult:
        return await self._delegate.complete_turn(request)

    async def aclose(self) -> None:
        self.close_started.set()
        while not self.release.is_set():
            try:
                await self.release.wait()
            except asyncio.CancelledError:
                continue


@pytest.mark.asyncio
async def test_agent_shutdown_bounds_stubborn_adapter_close_and_finishes_state() -> None:
    limits = AgentLimits(
        cancellation_grace=timedelta(milliseconds=20),
        shutdown_grace=timedelta(milliseconds=20),
    )
    configuration = _configuration(limits=limits)
    adapter = StubbornClosingModelAdapter()
    stack = create_agent_runtime_stack(
        configuration=configuration,
        model_adapter=adapter,
        tool_resolvers=(),
        tool_adapters=(),
        policy=_policy(configuration),
        events=EventBus(),
    )
    await stack.service.start(_runtime_context())

    with pytest.raises(TimeoutError, match="shutdown close timed out"):
        await asyncio.wait_for(stack.service.stop(_runtime_context()), timeout=1)

    assert adapter.close_started.is_set()
    snapshot = await stack.service.snapshot()
    assert snapshot.state is AgentServiceState.STOPPED
    assert stack.registry.closed

    adapter.release.set()
    await asyncio.sleep(0)
