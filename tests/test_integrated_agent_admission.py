from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from phoenix_os.agent import (
    AgentId,
    AgentLimits,
    AgentMessage,
    AgentMessageRole,
    AgentRunId,
)
from phoenix_os.agent.authorization import normalized_agent_run_authority_intent
from phoenix_os.agent.configuration import AgentServiceConfiguration
from phoenix_os.agent.contracts import AgentRunRequest
from phoenix_os.inference import ModelId, ModelProviderId
from phoenix_os.integrated_agent import (
    INTEGRATED_PLAN_UPDATE_TOOL_ID,
    IntegratedAgentAdmission,
    IntegratedAgentConfigurationError,
    IntegratedAgentError,
    IntegratedAgentErrorCode,
    IntegratedDataFlowDisposition,
    IntegratedDataFlowPolicy,
    IntegratedDataFlowRoute,
    IntegratedDataSink,
    IntegratedDataSourceKind,
    IntegratedExecutionProfile,
    IntegratedExecutionProfileCatalog,
    IntegratedExecutionProfileGeneration,
    IntegratedExecutionProfileId,
    IntegratedExecutionProfileSelection,
    IntegratedLocalTransformBinding,
    IntegratedTaskId,
    IntegratedTaskRequest,
)

_NOW = datetime(2026, 8, 27, 3, tzinfo=UTC)


def _policy() -> IntegratedDataFlowPolicy:
    return IntegratedDataFlowPolicy(
        (
            IntegratedDataFlowRoute(
                route_id="user-model",
                source_kind=IntegratedDataSourceKind.USER_TASK,
                sink=IntegratedDataSink.MODEL,
                disposition=IntegratedDataFlowDisposition.ALLOW,
            ),
        )
    )


def _profile(
    *,
    profile_id: str = "integrated-research",
    generation: int = 7,
    agent_id: str = "research-agent",
    enabled: bool = True,
    limits: AgentLimits | None = None,
) -> IntegratedExecutionProfile:
    return IntegratedExecutionProfile(
        profile_id=IntegratedExecutionProfileId(profile_id),
        generation=IntegratedExecutionProfileGeneration(generation),
        agent_id=AgentId(agent_id),
        tool_bindings=(
            (
                IntegratedLocalTransformBinding(
                    tool_id=INTEGRATED_PLAN_UPDATE_TOOL_ID,
                    transform_id="integrated.plan.update",
                    advisory_state_keys=("plan",),
                ),
            )
            if enabled
            else ()
        ),
        data_flow_policy=_policy(),
        limits=limits or AgentLimits(),
        enabled=enabled,
    )


def _configuration(
    *,
    agent_id: str = "research-agent",
    limits: AgentLimits | None = None,
) -> AgentServiceConfiguration:
    return AgentServiceConfiguration(
        agent_id=AgentId(agent_id),
        provider_id=ModelProviderId("local"),
        model_id=ModelId("chat"),
        limits=limits or AgentLimits(),
    )


def _admission(
    *,
    profile: IntegratedExecutionProfile | None = None,
    selection_id: str = "integrated-research",
    selection_generation: int = 7,
    configuration: AgentServiceConfiguration | None = None,
) -> IntegratedAgentAdmission:
    resolved_profile = profile or _profile()
    return IntegratedAgentAdmission(
        IntegratedExecutionProfileCatalog((resolved_profile,)),
        IntegratedExecutionProfileSelection(
            profile_id=IntegratedExecutionProfileId(selection_id),
            generation=IntegratedExecutionProfileGeneration(selection_generation),
        ),
        configuration or _configuration(),
    )


def _request(
    *,
    agent_id: str = "research-agent",
    provider_id: str = "local",
    model_id: str = "chat",
    metadata: dict[str, str] | None = None,
    run_id: AgentRunId | None = None,
    limits: AgentLimits | None = None,
) -> AgentRunRequest:
    return AgentRunRequest(
        agent_id=AgentId(agent_id),
        provider_id=ModelProviderId(provider_id),
        model_id=ModelId(model_id),
        messages=(AgentMessage(AgentMessageRole.USER, "compare the reviewed suppliers"),),
        metadata=metadata or {},
        run_id=run_id or AgentRunId(UUID("11111111-1111-1111-1111-111111111111")),
        limits=limits or AgentLimits(),
        created_at=_NOW,
        deadline=_NOW + timedelta(minutes=20),
    )


def _task(
    *,
    task_id: IntegratedTaskId | None = None,
    objective: str = "Compare reviewed suppliers and return a report.",
) -> IntegratedTaskRequest:
    return IntegratedTaskRequest(
        task_id=task_id or IntegratedTaskId(UUID("22222222-2222-2222-2222-222222222222")),
        objective=objective,
    )


@pytest.mark.asyncio
async def test_admission_binds_exact_task_profile_generation_and_existing_agent_run_id() -> None:
    profile_limits = AgentLimits(max_steps=6, max_model_turns=6, max_tool_calls=6)
    service_limits = AgentLimits(max_steps=5, max_model_turns=5, max_tool_calls=5)
    request_limits = AgentLimits(max_steps=4, max_model_turns=4, max_tool_calls=4)
    admission = _admission(
        profile=_profile(limits=profile_limits),
        configuration=_configuration(limits=service_limits),
    )
    task = _task()
    request = _request(
        limits=request_limits,
        metadata={
            "integrated_profile_id": "caller-forged",
            "integrated_task_digest": "sha256:" + ("f" * 64),
        },
    )

    lease = await admission.admit(task, request)
    binding = lease.binding

    assert binding.run_id == request.run_id
    assert binding.task_id == task.task_id
    assert binding.task_digest == task.digest
    assert binding.profile_id == IntegratedExecutionProfileId("integrated-research")
    assert binding.profile_generation == IntegratedExecutionProfileGeneration(7)
    assert lease.request.limits.max_steps == 4
    assert binding.effective_limits == lease.request.limits

    attributes = dict(binding.authority.attributes)
    assert attributes["integrated_task_id"] == str(task.task_id)
    assert attributes["integrated_task_digest"] == str(task.digest)
    assert attributes["integrated_profile_id"] == "integrated-research"
    assert attributes["integrated_profile_generation"] == "7"
    assert "caller-forged" not in repr(binding.authority)

    intent = normalized_agent_run_authority_intent(lease.request, binding.authority)
    assert intent.action == "agent.run"
    assert intent.canonical_resource == "agent:research-agent"
    assert intent.parameter_digest == binding.authority.parameter_digest
    assert len(intent.freshness_bindings) == 1
    assert intent.freshness_bindings[0].kind == "integrated.profile"
    assert intent.freshness_bindings[0].identity == "integrated-research:7"

    equivalent = await _admission().admit(task, _request(metadata={"other": "value"}))
    assert equivalent.binding.authority.parameter_digest == binding.authority.parameter_digest

    await equivalent.release()
    await lease.release()
    assert await admission.binding_for_run(request.run_id) is None


@pytest.mark.asyncio
async def test_task_identity_cannot_be_reused_with_changed_canonical_bytes() -> None:
    admission = _admission()
    task_id = IntegratedTaskId(UUID("33333333-3333-3333-3333-333333333333"))
    first = await admission.admit(_task(task_id=task_id), _request())
    await first.release()

    with pytest.raises(IntegratedAgentError) as captured:
        await admission.admit(
            _task(task_id=task_id, objective="Changed canonical task bytes."),
            _request(run_id=AgentRunId(UUID("44444444-4444-4444-4444-444444444444"))),
        )
    assert captured.value.code is IntegratedAgentErrorCode.VALIDATION_FAILED


@pytest.mark.asyncio
async def test_agent_run_id_is_single_use_even_after_binding_release() -> None:
    admission = _admission()
    request = _request()
    first = await admission.admit(_task(), request)
    await first.release()

    with pytest.raises(IntegratedAgentError) as captured:
        await admission.admit(_task(), request)
    assert captured.value.code is IntegratedAgentErrorCode.REJECTED


def test_profile_selection_is_server_resolved_enabled_generation_bound_and_agent_bound() -> None:
    with pytest.raises(IntegratedAgentConfigurationError):
        _admission(selection_id="missing")

    with pytest.raises(IntegratedAgentConfigurationError):
        _admission(profile=_profile(enabled=False))

    with pytest.raises(IntegratedAgentError) as stale:
        _admission(selection_generation=8)
    assert stale.value.code is IntegratedAgentErrorCode.STALE

    with pytest.raises(IntegratedAgentConfigurationError):
        _admission(profile=_profile(agent_id="other-agent"))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("run_request", "expected"),
    (
        (_request(agent_id="other-agent"), IntegratedAgentErrorCode.VALIDATION_FAILED),
        (_request(provider_id="other-provider"), IntegratedAgentErrorCode.VALIDATION_FAILED),
        (_request(model_id="other-model"), IntegratedAgentErrorCode.VALIDATION_FAILED),
    ),
)
async def test_request_cannot_substitute_server_owned_agent_provider_or_model(
    run_request: AgentRunRequest,
    expected: IntegratedAgentErrorCode,
) -> None:
    admission = _admission()
    with pytest.raises(IntegratedAgentError) as captured:
        await admission.admit(_task(), run_request)
    assert captured.value.code is expected


@pytest.mark.asyncio
async def test_closed_admission_rejects_new_run_without_reopening() -> None:
    admission = _admission()
    await admission.close()

    with pytest.raises(IntegratedAgentError) as captured:
        await admission.admit(_task(), _request())
    assert captured.value.code is IntegratedAgentErrorCode.REJECTED
