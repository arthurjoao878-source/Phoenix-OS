from datetime import UTC, datetime, timedelta

import pytest

from phoenix_os.agent import (
    AgentCancellationToken,
    AgentCoordinationConfiguration,
    AgentId,
    AgentLimits,
    AgentRunId,
    AgentRunRequest,
    AgentRunResult,
    AgentRunStatus,
    AgentServiceConfiguration,
    CoordinationNamespace,
    DelegableAgentDescriptor,
    DelegationBudget,
    DelegationDepth,
    DelegationId,
    DelegationLimits,
    DelegationStatus,
    DurableAgentCoordinationRuntimeStack,
    DurableDelegationRecord,
    DurableDelegationRecoveryState,
    DurableDelegationVersion,
    InMemoryDurableDelegationStore,
    create_durable_agent_coordination_runtime_stack,
)
from phoenix_os.inference import ModelId, ModelProviderId
from phoenix_os.policy import PolicyEngine, SecurityContext
from phoenix_os.runtime import RuntimeContext

_NOW = datetime(2026, 8, 11, 1, tzinfo=UTC)


class _StubChildService:
    def __init__(self, configuration: AgentServiceConfiguration) -> None:
        self._configuration = configuration

    @property
    def configuration(self) -> AgentServiceConfiguration:
        return self._configuration

    async def run(
        self,
        request: AgentRunRequest,
        context: SecurityContext,
        *,
        cancellation: AgentCancellationToken | None = None,
    ) -> AgentRunResult:
        del context, cancellation
        return AgentRunResult(
            run_id=request.run_id,
            status=AgentRunStatus.COMPLETED,
            model_turns=1,
            tool_calls=0,
            final_output="ok",
            started_at=_NOW,
            completed_at=_NOW,
        )


def _limits() -> DelegationLimits:
    return DelegationLimits(
        max_depth=2,
        max_fan_out=2,
        max_total_children=4,
        max_concurrent_children=2,
        max_queue_depth=4,
        max_input_bytes=4096,
        max_result_bytes=65_536,
        max_result_depth=8,
        child_timeout=timedelta(minutes=5),
    )


def _budget() -> DelegationBudget:
    return DelegationBudget(
        max_model_turns=4,
        max_tool_calls=2,
        max_input_tokens=16_384,
        max_output_tokens=8192,
        max_prompt_bytes=32_768,
        max_result_bytes=131_072,
        duration=timedelta(minutes=5),
    )


def _configuration() -> AgentCoordinationConfiguration:
    return AgentCoordinationConfiguration(
        namespace=CoordinationNamespace("default"),
        limits=_limits(),
        root_budget_limit=_budget(),
    )


def _child_configuration() -> AgentServiceConfiguration:
    return AgentServiceConfiguration(
        agent_id=AgentId("child"),
        provider_id=ModelProviderId("local"),
        model_id=ModelId("chat"),
        limits=AgentLimits(total_duration=timedelta(minutes=20)),
    )


def _descriptor(configuration: AgentServiceConfiguration) -> DelegableAgentDescriptor:
    return DelegableAgentDescriptor(
        configuration=configuration,
        namespace=CoordinationNamespace("default"),
        allowed_parent_agents=(AgentId("parent"),),
        compatibility_digest="sha256:" + "a" * 64,
        max_accepted_depth=DelegationDepth(2),
        allow_nested_delegation=True,
    )


def _recoverable_record() -> DurableDelegationRecord:
    return DurableDelegationRecord(
        delegation_id=DelegationId(),
        namespace=CoordinationNamespace("default"),
        parent_agent_id=AgentId("parent"),
        parent_run_id=AgentRunId(),
        root_run_id=AgentRunId(),
        child_agent_id=AgentId("child"),
        child_run_id=AgentRunId(),
        depth=DelegationDepth(1),
        budget=DelegationBudget(
            max_model_turns=2,
            max_tool_calls=1,
            max_input_tokens=4096,
            max_output_tokens=2048,
            max_prompt_bytes=8192,
            max_result_bytes=16_384,
            duration=timedelta(minutes=2),
        ),
        status=DelegationStatus.ADMITTED,
        request_digest="sha256:" + "1" * 64,
        compatibility_digest="sha256:" + "a" * 64,
        version=DurableDelegationVersion(),
        recovery_state=DurableDelegationRecoveryState.CLEAN,
        created_at=_NOW,
        updated_at=_NOW,
        deadline=_NOW + timedelta(days=1),
    )


@pytest.mark.asyncio
async def test_durable_composition_recovers_before_runtime_accepts_work() -> None:
    child_configuration = _child_configuration()
    service = _StubChildService(child_configuration)
    descriptor = _descriptor(child_configuration)
    store = InMemoryDurableDelegationStore()
    await store.create(
        _recoverable_record(),
        limits=_limits(),
        root_budget_limit=_budget(),
    )

    stack = create_durable_agent_coordination_runtime_stack(
        configuration=_configuration(),
        descriptors=(descriptor,),
        child_services={child_configuration.agent_id: service},
        policy=PolicyEngine(),
        store=store,
        clock=lambda: _NOW + timedelta(minutes=1),
    )

    assert isinstance(stack, DurableAgentCoordinationRuntimeStack)
    assert stack.lifecycle.last_recovery_report is None

    context = RuntimeContext(services={})
    await stack.lifecycle.start(context)

    report = stack.lifecycle.last_recovery_report
    assert report is not None
    assert report.recoverable == 1
    assert (await stack.runtime.snapshot()).accepting

    await stack.lifecycle.stop(context)
    assert store.closed
    assert stack.registry.closed


@pytest.mark.asyncio
async def test_durable_composition_requires_explicit_open_store() -> None:
    child_configuration = _child_configuration()
    descriptor = _descriptor(child_configuration)
    service = _StubChildService(child_configuration)
    store = InMemoryDurableDelegationStore()

    await store.close()

    with pytest.raises(ValueError, match="open"):
        create_durable_agent_coordination_runtime_stack(
            configuration=_configuration(),
            descriptors=(descriptor,),
            child_services={child_configuration.agent_id: service},
            policy=PolicyEngine(),
            store=store,
        )
