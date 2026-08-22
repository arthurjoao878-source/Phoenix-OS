from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from phoenix_os.agent import (
    AGENT_COORDINATION_HEALTH_READ_PERMISSION,
    AgentAdministrationAccessDeniedError,
    AgentCancellationToken,
    AgentCoordinationAdministration,
    AgentCoordinationConfiguration,
    AgentCoordinationRuntime,
    AgentCoordinationRuntimeStack,
    AgentDelegationCoordinator,
    AgentDelegationRegistry,
    AgentId,
    AgentLimits,
    AgentRunId,
    AgentRunRequest,
    AgentRunResult,
    AgentRunStatus,
    AgentServiceConfiguration,
    ContentFreeAgentCoordinationObserver,
    CoordinationNamespace,
    CoordinationObservation,
    CoordinationOperation,
    CoordinationOperationOutcome,
    DelegableAgentDescriptor,
    DelegationBudget,
    DelegationDepth,
    DelegationId,
    DelegationLimits,
    NullAgentCoordinationObserver,
    coordination_health_resource,
    create_agent_coordination_runtime_stack,
)
from phoenix_os.inference import ModelId, ModelProviderId
from phoenix_os.policy import PolicyEngine, PrincipalType, SecurityContext

_NOW = datetime(2026, 8, 10, 18, 30, tzinfo=UTC)


class _AllowAuthorizer:
    async def authorize(
        self,
        request: object,
        descriptor: object,
        context: object,
    ) -> None:
        del request, descriptor, context


class _NeverCalledSessionSource:
    async def session(self, session_id: UUID) -> object:
        del session_id
        raise AssertionError("session lookup must not occur during stack construction")


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
        max_output_tokens=8_192,
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
        limits=AgentLimits(total_duration=timedelta(minutes=10)),
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


def test_coordination_observation_metadata_is_content_free() -> None:
    observation = CoordinationObservation(
        operation=CoordinationOperation.CHILD_RESULT,
        outcome=CoordinationOperationOutcome.SUCCEEDED,
        namespace=CoordinationNamespace("default"),
        delegation_id=DelegationId(),
        parent_agent_id=AgentId("parent"),
        parent_run_id=AgentRunId(),
        child_agent_id=AgentId("child"),
        child_run_id=AgentRunId(),
    )

    metadata = observation.metadata()
    assert set(metadata) == {
        "namespace",
        "delegation_id",
        "parent_agent_id",
        "parent_run_id",
        "child_agent_id",
        "child_run_id",
        "operation",
        "outcome",
    }
    assert "output" not in metadata
    assert "prompt" not in metadata
    assert "credential" not in metadata


@pytest.mark.asyncio
async def test_null_coordination_observer_is_safe_noop() -> None:
    observer = NullAgentCoordinationObserver()
    await observer.record(
        CoordinationObservation(
            operation=CoordinationOperation.ADMISSION,
            outcome=CoordinationOperationOutcome.SUCCEEDED,
            namespace=CoordinationNamespace("default"),
            delegation_id=DelegationId(),
            parent_agent_id=AgentId("parent"),
            parent_run_id=AgentRunId(),
            child_agent_id=AgentId("child"),
            child_run_id=AgentRunId(),
        ),
        SecurityContext(
            principal="service:parent",
            principal_type=PrincipalType.SERVICE,
            authenticated=True,
        ),
    )


@pytest.mark.asyncio
async def test_coordination_administration_is_permission_gated() -> None:
    registry = AgentDelegationRegistry()
    coordinator = AgentDelegationCoordinator(
        registry,
        _AllowAuthorizer(),
        limits=_limits(),
        root_budget_limit=_budget(),
        clock=lambda: _NOW,
    )
    runtime = AgentCoordinationRuntime(
        coordinator,
        _configuration(),
        {},
    )
    administration = AgentCoordinationAdministration(
        runtime,
        coordinator,
        CoordinationNamespace("default"),
    )

    denied = SecurityContext(
        principal="service:admin",
        principal_type=PrincipalType.SERVICE,
        authenticated=True,
    )
    with pytest.raises(AgentAdministrationAccessDeniedError):
        await administration.snapshot(denied)

    resource = coordination_health_resource(CoordinationNamespace("default"))
    allowed = SecurityContext(
        principal="service:admin",
        principal_type=PrincipalType.SERVICE,
        authenticated=True,
        permissions=frozenset({AGENT_COORDINATION_HEALTH_READ_PERMISSION}),
        attributes={"resource": resource},
    )
    snapshot = await administration.snapshot(allowed)
    assert snapshot.coordinator.delegations == 0
    assert snapshot.runtime.active_children == 0


def test_coordination_composition_is_explicit_opt_in_and_exact() -> None:
    child_configuration = _child_configuration()
    service = _StubChildService(child_configuration)
    descriptor = _descriptor(child_configuration)

    stack = create_agent_coordination_runtime_stack(
        configuration=_configuration(),
        descriptors=(descriptor,),
        child_services={child_configuration.agent_id: service},
        policy=PolicyEngine(),
    )

    assert isinstance(stack, AgentCoordinationRuntimeStack)
    assert stack.configuration.namespace == CoordinationNamespace("default")
    assert stack.registry.list_descriptors() == (descriptor,)
    assert stack.lifecycle is stack.runtime
    assert isinstance(stack.observer, ContentFreeAgentCoordinationObserver)


def test_coordination_composition_requires_exact_child_installation() -> None:
    child_configuration = _child_configuration()
    descriptor = _descriptor(child_configuration)

    with pytest.raises(ValueError, match="exactly match"):
        create_agent_coordination_runtime_stack(
            configuration=_configuration(),
            descriptors=(descriptor,),
            child_services={},
            policy=PolicyEngine(),
        )


def test_coordination_composition_accepts_session_freshness_source() -> None:
    child_configuration = _child_configuration()
    service = _StubChildService(child_configuration)
    descriptor = _descriptor(child_configuration)

    stack = create_agent_coordination_runtime_stack(
        configuration=_configuration(),
        descriptors=(descriptor,),
        child_services={child_configuration.agent_id: service},
        policy=PolicyEngine(),
        session_freshness_source=_NeverCalledSessionSource(),  # type: ignore[arg-type]
    )

    assert isinstance(stack, AgentCoordinationRuntimeStack)


def test_coordination_composition_rejects_invalid_session_freshness_source() -> None:
    child_configuration = _child_configuration()
    service = _StubChildService(child_configuration)
    descriptor = _descriptor(child_configuration)

    with pytest.raises(TypeError, match="SessionFreshnessSource"):
        create_agent_coordination_runtime_stack(
            configuration=_configuration(),
            descriptors=(descriptor,),
            child_services={child_configuration.agent_id: service},
            policy=PolicyEngine(),
            session_freshness_source=object(),  # type: ignore[arg-type]
        )
