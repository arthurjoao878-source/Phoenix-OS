from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from phoenix_os.agent.configuration import AgentServiceConfiguration
from phoenix_os.agent.contracts import (
    AgentId,
    AgentMessage,
    AgentMessageRole,
    AgentRunId,
    AgentRunRequest,
)
from phoenix_os.inference import ModelId, ModelProviderId
from phoenix_os.integrated_agent.admission import (
    IntegratedAgentAdmission,
    IntegratedExecutionProfileSelection,
)
from phoenix_os.integrated_agent.contracts import (
    IntegratedBudgetExtension,
    IntegratedDataFlowDisposition,
    IntegratedDataFlowPolicy,
    IntegratedDataFlowRoute,
    IntegratedDataSink,
    IntegratedDataSourceKind,
    IntegratedExecutionProfileGeneration,
    IntegratedExecutionProfileId,
    IntegratedTaskId,
    IntegratedTaskRequest,
)
from phoenix_os.integrated_agent.errors import (
    IntegratedAgentRejectedError,
    IntegratedAgentValidationError,
)
from phoenix_os.integrated_agent.profiles import (
    INTEGRATED_PLAN_UPDATE_TOOL_ID,
    INTEGRATED_PLAN_UPDATE_TRANSFORM_ID,
    IntegratedExecutionProfile,
    IntegratedExecutionProfileCatalog,
    IntegratedLocalTransformBinding,
)

_NOW = datetime(2026, 9, 8, 23, 40, tzinfo=UTC)
_RUN_ID = AgentRunId(UUID(int=3001))
_TASK_ID = IntegratedTaskId(UUID(int=3002))
_AGENT_ID = AgentId("assistant")
_LOCAL_PROVIDER_ID = ModelProviderId("local")


def _profile() -> IntegratedExecutionProfile:
    return IntegratedExecutionProfile(
        profile_id=IntegratedExecutionProfileId("development"),
        generation=IntegratedExecutionProfileGeneration(9),
        agent_id=_AGENT_ID,
        tool_bindings=(
            IntegratedLocalTransformBinding(
                tool_id=INTEGRATED_PLAN_UPDATE_TOOL_ID,
                transform_id=INTEGRATED_PLAN_UPDATE_TRANSFORM_ID,
                advisory_state_keys=("plan",),
            ),
        ),
        data_flow_policy=IntegratedDataFlowPolicy(
            (
                IntegratedDataFlowRoute(
                    route_id="user-model",
                    source_kind=IntegratedDataSourceKind.USER_TASK,
                    sink=IntegratedDataSink.MODEL,
                    disposition=IntegratedDataFlowDisposition.ALLOW,
                ),
            )
        ),
        budget_extension=IntegratedBudgetExtension(
            max_integrated_steps=4,
            max_plan_revisions=3,
        ),
    )


def _admission(profile: IntegratedExecutionProfile) -> IntegratedAgentAdmission:
    return IntegratedAgentAdmission(
        IntegratedExecutionProfileCatalog((profile,)),
        IntegratedExecutionProfileSelection(
            profile_id=profile.profile_id,
            generation=profile.generation,
        ),
        AgentServiceConfiguration(
            agent_id=_AGENT_ID,
            provider_id=ModelProviderId("local"),
            model_id=ModelId("chat"),
        ),
    )


def _task(*, objective: str = "Continue the exact reviewed durable task.") -> IntegratedTaskRequest:
    return IntegratedTaskRequest(
        task_id=_TASK_ID,
        objective=objective,
    )


def _request(
    *,
    message: str = "continue",
    provider_id: ModelProviderId = _LOCAL_PROVIDER_ID,
) -> AgentRunRequest:
    return AgentRunRequest(
        agent_id=_AGENT_ID,
        provider_id=provider_id,
        model_id=ModelId("chat"),
        messages=(AgentMessage(AgentMessageRole.USER, message),),
        run_id=_RUN_ID,
        created_at=_NOW - timedelta(minutes=5),
        deadline=_NOW + timedelta(minutes=15),
    )


@pytest.mark.asyncio
async def test_restore_run_reactivates_exact_released_live_state() -> None:
    profile = _profile()
    admission = _admission(profile)
    task = _task()
    request = _request()

    first = await admission.admit(task, request)
    expected_binding = first.binding
    expected_request = first.request
    await first.release()

    restored = await admission.restore_run(task, request)
    try:
        assert restored.binding == expected_binding
        assert restored.request == expected_request
        assert await admission.binding_for_run(_RUN_ID) == expected_binding
        assert await admission.request_for_run(_RUN_ID) == expected_request
    finally:
        await restored.release()

    assert await admission.binding_for_run(_RUN_ID) is None
    assert await admission.request_for_run(_RUN_ID) is None


@pytest.mark.asyncio
async def test_restore_run_on_fresh_controller_matches_normal_admission() -> None:
    profile = _profile()
    task = _task()
    request = _request()

    seed = _admission(profile)
    seed_lease = await seed.admit(task, request)
    expected_binding = seed_lease.binding
    expected_request = seed_lease.request
    await seed_lease.release()

    restarted = _admission(profile)
    restored = await restarted.restore_run(task, request)
    try:
        assert restored.binding == expected_binding
        assert restored.request == expected_request
    finally:
        await restored.release()


@pytest.mark.asyncio
async def test_restore_run_rejects_changed_request_for_seen_run_id() -> None:
    profile = _profile()
    admission = _admission(profile)
    task = _task()

    first = await admission.admit(task, _request())
    await first.release()

    with pytest.raises(
        IntegratedAgentValidationError,
        match="changed effective request",
    ):
        await admission.restore_run(task, _request(message="changed continuation"))


@pytest.mark.asyncio
async def test_restore_run_rejects_changed_task_canonical_bytes() -> None:
    profile = _profile()
    admission = _admission(profile)

    first = await admission.admit(_task(), _request())
    await first.release()

    with pytest.raises(
        IntegratedAgentValidationError,
        match="changed canonical bytes",
    ):
        await admission.restore_run(
            _task(objective="Different task bytes."),
            _request(),
        )


@pytest.mark.asyncio
async def test_restore_run_rejects_active_or_wrong_server_binding() -> None:
    profile = _profile()
    admission = _admission(profile)
    task = _task()
    request = _request()

    live = await admission.restore_run(task, request)
    try:
        with pytest.raises(
            IntegratedAgentRejectedError,
            match="already active",
        ):
            await admission.restore_run(task, request)
    finally:
        await live.release()

    with pytest.raises(
        IntegratedAgentValidationError,
        match="server-owned integrated execution binding",
    ):
        await _admission(profile).restore_run(
            task,
            _request(provider_id=ModelProviderId("other")),
        )
