from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from phoenix_os.agent import AgentId, AgentToolConfiguration
from phoenix_os.agent.authorization import AGENT_RUN_ACTION, TOOL_INVOKE_ACTION
from phoenix_os.agent.composition import AgentRuntimeStack, create_agent_runtime_stack
from phoenix_os.agent.configuration import AgentServiceConfiguration
from phoenix_os.agent.contracts import (
    AgentMessage,
    AgentMessageRole,
    AgentRunId,
    AgentRunRequest,
    AgentStepId,
)
from phoenix_os.agent.durable_authorization import AGENT_RESUME_ACTION
from phoenix_os.agent.durable_codec import seal_checkpoint_envelope
from phoenix_os.agent.durable_compatibility import (
    DurableCompatibilityPolicy,
    StaticDurableCompatibilityValidator,
)
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
    DurableRunStatus,
    DurableRunVersion,
    ExecutionAttemptStatus,
    IndeterminateReason,
    ReconciliationDecision,
    ResumeReason,
)
from phoenix_os.agent.durable_memory import InMemoryDurableRunStore
from phoenix_os.agent.durable_reconciliation import DurableReconciliationDispositionRecord
from phoenix_os.agent.durable_runtime import (
    DurableAgentRuntimeStack,
    create_durable_agent_runtime_stack,
)
from phoenix_os.agent.durable_status_lookup import (
    DurableAttemptExternalStatus,
    DurableAttemptStatusLookupOutcome,
)
from phoenix_os.agent.fake import DeterministicFinalTurn, DeterministicModelTurnAdapter
from phoenix_os.agent.state import AgentBudgetSnapshot
from phoenix_os.control_plane.task_policy_binding import (
    TaskExecutionPolicyBinding,
    TaskExecutionPolicyTargets,
    TaskToolAuthorityTarget,
)
from phoenix_os.control_plane.task_resume_preparation import (
    TaskResumePreparationError,
    prepare_same_lease_durable_task_resume,
)
from phoenix_os.control_plane.task_runtime_bridge import TaskExecutionAuthority
from phoenix_os.control_plane.task_runtime_composition import (
    ServerOwnedDurableIntegratedTaskResumeSupport,
    ServerOwnedDurableIntegratedTaskRuntime,
    compose_server_owned_durable_integrated_task_resume_support,
    compose_server_owned_durable_integrated_task_runtime,
)
from phoenix_os.inference import ModelId, ModelProviderId
from phoenix_os.inference.authorization import INFERENCE_MODEL_ACTION
from phoenix_os.integrated_agent.checkout_durable_history import (
    create_integrated_checkout_durable_history_validator,
)
from phoenix_os.integrated_agent.composition import (
    IntegratedAgentToolComposition,
    integrated_plan_update_registration,
)
from phoenix_os.integrated_agent.contracts import (
    IntegratedBudgetUsage,
    IntegratedDataFlowDisposition,
    IntegratedDataFlowPolicy,
    IntegratedDataFlowRoute,
    IntegratedDataProvenance,
    IntegratedDataSink,
    IntegratedDataSourceKind,
    IntegratedExecutionProfileGeneration,
    IntegratedExecutionProfileId,
    IntegratedTaskId,
    IntegratedTaskRequest,
)
from phoenix_os.integrated_agent.durable_live_revalidation import (
    IntegratedDurableRecoveryLiveProbes,
)
from phoenix_os.integrated_agent.durable_root import create_integrated_durable_root
from phoenix_os.integrated_agent.durable_run import integrated_durable_run_id
from phoenix_os.integrated_agent.durable_transitions import (
    IntegratedDurableCheckpointMetadataProjector,
)
from phoenix_os.integrated_agent.errors import IntegratedAgentValidationError
from phoenix_os.integrated_agent.execution_guard import IntegratedAgentExecutionGuard
from phoenix_os.integrated_agent.planning import IntegratedPlanner
from phoenix_os.integrated_agent.profiles import (
    INTEGRATED_PLAN_UPDATE_TOOL_ID,
    INTEGRATED_PLAN_UPDATE_TRANSFORM_ID,
    IntegratedExecutionProfile,
    IntegratedLocalTransformBinding,
)
from phoenix_os.policy import PolicyEngine, PrincipalType, SecurityContext

_NOW = datetime(2026, 9, 9, 7, 0, tzinfo=UTC)
_AGENT_ID = AgentId("assistant")
_PROVIDER_ID = ModelProviderId("local")
_MODEL_ID = ModelId("chat")
_RUN_ID = AgentRunId(UUID("51000000-0000-4000-8000-000000000001"))
_TASK_ID = IntegratedTaskId(UUID("52000000-0000-4000-8000-000000000002"))
_STEP_ID = AgentStepId(UUID("53000000-0000-4000-8000-000000000003"))
_ROOT_CHECKPOINT_ID = CheckpointId(UUID("54000000-0000-4000-8000-000000000004"))


def _digest(character: str) -> CheckpointDigest:
    return CheckpointDigest(character * 64)


def _profile(
    *,
    allow_user_result: bool = False,
) -> IntegratedExecutionProfile:
    routes: tuple[IntegratedDataFlowRoute, ...] = (
        IntegratedDataFlowRoute(
            route_id="user-model",
            source_kind=IntegratedDataSourceKind.USER_TASK,
            sink=IntegratedDataSink.MODEL,
            disposition=IntegratedDataFlowDisposition.ALLOW,
        ),
    )
    if allow_user_result:
        routes += (
            IntegratedDataFlowRoute(
                route_id="user-user-result",
                source_kind=IntegratedDataSourceKind.USER_TASK,
                sink=IntegratedDataSink.USER_RESULT,
                disposition=IntegratedDataFlowDisposition.ALLOW,
                requires_audience_match=True,
            ),
            IntegratedDataFlowRoute(
                route_id="model-output-user-result",
                source_kind=IntegratedDataSourceKind.MODEL_OUTPUT,
                sink=IntegratedDataSink.USER_RESULT,
                disposition=IntegratedDataFlowDisposition.ALLOW,
                requires_audience_match=True,
            ),
        )
    return IntegratedExecutionProfile(
        profile_id=IntegratedExecutionProfileId("development"),
        generation=IntegratedExecutionProfileGeneration(1),
        agent_id=_AGENT_ID,
        tool_bindings=(
            IntegratedLocalTransformBinding(
                tool_id=INTEGRATED_PLAN_UPDATE_TOOL_ID,
                transform_id=INTEGRATED_PLAN_UPDATE_TRANSFORM_ID,
                advisory_state_keys=("plan",),
            ),
        ),
        data_flow_policy=IntegratedDataFlowPolicy(routes),
    )


def _compatibility() -> DurableCompatibilityPolicy:
    return DurableCompatibilityPolicy(
        agent_id=_AGENT_ID,
        current=CompatibilityDigests(
            configuration=_digest("a"),
            tool_registry=_digest("b"),
            model_provider=_digest("c"),
            checkpoint_codec=_digest("d"),
        ),
        payload_profile=CheckpointPayloadProfile.METADATA_ONLY,
    )


def _agent_stack(
    planner: IntegratedPlanner,
    guard: IntegratedAgentExecutionGuard,
    policy: PolicyEngine,
) -> AgentRuntimeStack:
    configuration = AgentServiceConfiguration(
        agent_id=_AGENT_ID,
        provider_id=_PROVIDER_ID,
        model_id=_MODEL_ID,
        tools=(AgentToolConfiguration(planner.descriptor),),
    )
    return create_agent_runtime_stack(
        configuration=configuration,
        model_adapter=DeterministicModelTurnAdapter((DeterministicFinalTurn("done"),)),
        tool_resolvers=(planner.resource_resolver,),
        tool_adapters=(planner.adapter,),
        policy=policy,
        execution_interceptor=guard,
    )


def _durable_stack(policy: DurableCompatibilityPolicy) -> DurableAgentRuntimeStack:
    store = InMemoryDurableRunStore()
    return create_durable_agent_runtime_stack(
        store=store,
        lease_manager=store.lease_manager,
        compatibility_validator=StaticDurableCompatibilityValidator((policy,)),
        metadata_projector=IntegratedDurableCheckpointMetadataProjector(),
        history_validator=create_integrated_checkout_durable_history_validator(),
    )


def _context() -> SecurityContext:
    return SecurityContext(
        principal="operator-1",
        principal_type=PrincipalType.USER,
        authenticated=True,
        permissions=frozenset(
            {
                AGENT_RUN_ACTION,
                INFERENCE_MODEL_ACTION,
                TOOL_INVOKE_ACTION,
                AGENT_RESUME_ACTION,
            }
        ),
    )


def _task() -> IntegratedTaskRequest:
    return IntegratedTaskRequest(
        task_id=_TASK_ID,
        objective="Continue the exact reviewed durable task.",
    )


def _request() -> AgentRunRequest:
    return AgentRunRequest(
        agent_id=_AGENT_ID,
        provider_id=_PROVIDER_ID,
        model_id=_MODEL_ID,
        messages=(AgentMessage(AgentMessageRole.USER, "continue"),),
        run_id=_RUN_ID,
        created_at=_NOW - timedelta(minutes=5),
        deadline=_NOW + timedelta(minutes=15),
    )


def _root(
    request: AgentRunRequest,
    compatibility: DurableCompatibilityPolicy,
) -> CheckpointEnvelope:
    return seal_checkpoint_envelope(
        CheckpointEnvelope(
            schema_version=CheckpointSchemaVersion(),
            durable_run_id=integrated_durable_run_id(request.run_id),
            checkpoint_id=_ROOT_CHECKPOINT_ID,
            sequence=CheckpointSequence(1),
            previous_digest=None,
            run_version=DurableRunVersion(1),
            status=DurableRunStatus.ACTIVE,
            agent_run_id=request.run_id,
            step_id=_STEP_ID,
            metadata=CheckpointMetadata(
                agent_id=request.agent_id,
                actor_id="origin-worker",
                next_operation=CheckpointNextOperation.MODEL_TURN,
                budget=AgentBudgetSnapshot(
                    steps=0,
                    model_turns=0,
                    tool_calls=0,
                    model_output_bytes=0,
                    tool_result_bytes=0,
                    input_tokens=0,
                    output_tokens=0,
                    started_at=request.created_at,
                    deadline=request.deadline,
                ),
                compatibility=compatibility.current,
                payload_profile=CheckpointPayloadProfile.METADATA_ONLY,
                retention_deadline=_NOW + timedelta(days=1),
                metadata={},
            ),
            created_at=_NOW,
            digest=_digest("0"),
        )
    )


def _cancelled(_run_id: AgentRunId) -> bool:
    return False


def _context_current(_provenance: IntegratedDataProvenance) -> bool:
    return True


@dataclass(slots=True)
class _Environment:
    policy: PolicyEngine
    policy_binding: TaskExecutionPolicyBinding
    durable_stack: DurableAgentRuntimeStack
    owner: ServerOwnedDurableIntegratedTaskRuntime
    support: ServerOwnedDurableIntegratedTaskResumeSupport
    authority: TaskExecutionAuthority
    task: IntegratedTaskRequest
    request: AgentRunRequest
    provenance: IntegratedDataProvenance
    durable_run_id: DurableAgentRunId
    checkpoint: CheckpointEnvelope

    async def close(self) -> None:
        await self.policy_binding.close()
        await self.durable_stack.close()
        await self.policy.close()


async def _environment(
    *,
    pause_for_context_resupply: bool,
    live_runtime_clock: bool = False,
    allow_user_result: bool = False,
) -> _Environment:
    profile = _profile(allow_user_result=allow_user_result)
    guard = IntegratedAgentExecutionGuard(profile, clock=lambda: _NOW)
    planner = IntegratedPlanner(profile, provenance_provider=guard)
    binding = profile.require_tool_binding(INTEGRATED_PLAN_UPDATE_TOOL_ID)
    assert isinstance(binding, IntegratedLocalTransformBinding)
    composition = IntegratedAgentToolComposition(
        profile,
        (integrated_plan_update_registration(binding, planner),),
    )

    policy = PolicyEngine()
    agent_stack = _agent_stack(planner, guard, policy)
    compatibility = _compatibility()
    durable_stack = _durable_stack(compatibility)
    runtime_clock = (lambda: datetime.now(UTC)) if live_runtime_clock else (lambda: _NOW)
    owner = compose_server_owned_durable_integrated_task_runtime(
        service=agent_stack.service,
        durable_stack=durable_stack,
        profile=profile,
        execution_guard=guard,
        compatibility_policy=compatibility,
        actor_id="rfc0039-task",
        owner_id="rfc0039-task-runtime",
        composition=composition,
        clock=runtime_clock,
    )

    context = _context()
    authority = TaskExecutionAuthority(policy=policy, context=context)
    registration = composition.require_registration(INTEGRATED_PLAN_UPDATE_TOOL_ID)
    policy_binding = await TaskExecutionPolicyBinding.open(
        authority,
        TaskExecutionPolicyTargets(
            run_id=_RUN_ID,
            agent_id=_AGENT_ID,
            provider_id=_PROVIDER_ID,
            model_id=_MODEL_ID,
            tools=(
                TaskToolAuthorityTarget(
                    tool_id=registration.descriptor.tool_id,
                    effect=registration.descriptor.effect,
                ),
            ),
        ),
    )

    task = _task()
    admission_lease = await owner.admission.admit(task, _request())
    effective_request = admission_lease.request

    seed_guard = IntegratedAgentExecutionGuard(profile, clock=lambda: _NOW)
    seed_guard.begin_run(task, effective_request)
    provenance = seed_guard.current_provenance(effective_request.run_id)
    assert provenance is not None
    seed_guard.release_run(effective_request.run_id)

    checkpoint = await create_integrated_durable_root(
        durable_stack.store,
        _root(effective_request, compatibility),
        admission_lease.binding,
        provenance=provenance,
    )
    await admission_lease.release()

    support = compose_server_owned_durable_integrated_task_resume_support(
        owner,
        context=context,
        probes=IntegratedDurableRecoveryLiveProbes(
            cancellation_probe=_cancelled,
            context_freshness_probe=_context_current,
        ),
    )
    assert support.context is authority.context

    durable_run_id = checkpoint.durable_run_id
    if pause_for_context_resupply:
        setup_lease = await durable_stack.lease_manager.acquire(
            durable_run_id,
            owner_id="context-resupply-setup",
            now=_NOW,
        )
        try:
            checkpoint = await support.context_resupply.pause_candidate_with_lease(
                durable_run_id,
                lease=setup_lease,
                now=_NOW,
            )
        finally:
            await durable_stack.lease_manager.release(setup_lease, now=_NOW)

    return _Environment(
        policy=policy,
        policy_binding=policy_binding,
        durable_stack=durable_stack,
        owner=owner,
        support=support,
        authority=authority,
        task=task,
        request=effective_request,
        provenance=provenance,
        durable_run_id=durable_run_id,
        checkpoint=checkpoint,
    )


@pytest.mark.asyncio
async def test_same_lease_resume_preparation_restores_authorizes_and_holds_one_lease() -> None:
    environment = await _environment(pause_for_context_resupply=True)
    try:
        prepared = await prepare_same_lease_durable_task_resume(
            owner=environment.owner,
            support=environment.support,
            durable_run_id=environment.durable_run_id,
            authority=environment.authority,
            lease_owner_id="operator-resume",
            task=environment.task,
            request=environment.request,
            provenance=environment.provenance,
            budget_usage=IntegratedBudgetUsage(),
            plan=None,
            now=_NOW,
        )
        assert prepared.checkpoint == environment.checkpoint
        assert prepared.resume_request.reason is ResumeReason.OPERATOR_REQUEST
        assert prepared.resume_request.expected_version == environment.checkpoint.run_version
        assert prepared.resume_request.generation == prepared.durable_lease.generation
        assert prepared.durable_lease.generation.value == 2
        assert (
            await environment.durable_stack.lease_manager.require_current(
                prepared.durable_lease,
                now=_NOW,
            )
            == prepared.durable_lease
        )
        assert prepared.live_state.request == environment.request
        assert await environment.owner.admission.request_for_run(_RUN_ID) == environment.request
        assert (
            environment.owner.execution_guard.current_provenance(_RUN_ID) == environment.provenance
        )
        assert (
            environment.owner.execution_guard.current_budget_usage(_RUN_ID)
            == IntegratedBudgetUsage()
        )
        planner = environment.owner.planner
        assert planner is not None
        assert planner.current_revision(_RUN_ID) == 0
        assert planner.current_plan(_RUN_ID) is None

        await prepared.release(now=_NOW)
        await prepared.release(now=_NOW)
        assert prepared.released is True
        assert (
            await environment.durable_stack.lease_manager.get_current(
                environment.durable_run_id,
                now=_NOW,
            )
            is None
        )
        assert await environment.owner.admission.request_for_run(_RUN_ID) is None
        assert environment.owner.execution_guard.current_provenance(_RUN_ID) is None
        assert planner.current_revision(_RUN_ID) is None

        changed_request = replace(
            environment.request,
            messages=(AgentMessage(AgentMessageRole.USER, "changed"),),
        )
        with pytest.raises(IntegratedAgentValidationError):
            await prepare_same_lease_durable_task_resume(
                owner=environment.owner,
                support=environment.support,
                durable_run_id=environment.durable_run_id,
                authority=environment.authority,
                lease_owner_id="operator-resume-retry",
                task=environment.task,
                request=changed_request,
                provenance=environment.provenance,
                budget_usage=IntegratedBudgetUsage(),
                plan=None,
                now=_NOW,
            )
        assert (
            await environment.durable_stack.lease_manager.get_current(
                environment.durable_run_id,
                now=_NOW,
            )
            is None
        )
        assert await environment.owner.admission.request_for_run(_RUN_ID) is None
        assert environment.owner.execution_guard.current_provenance(_RUN_ID) is None
    finally:
        await environment.close()


@pytest.mark.asyncio
async def test_same_lease_resume_preparation_materializes_active_context_resupply() -> None:
    from phoenix_os.integrated_agent.contracts import (
        IntegratedOrchestrationPhase,
        IntegratedWaitingReason,
    )
    from phoenix_os.integrated_agent.durable_projection import (
        decode_integrated_durable_projection,
    )

    environment = await _environment(pause_for_context_resupply=False)
    prepared = None
    try:
        prepared = await prepare_same_lease_durable_task_resume(
            owner=environment.owner,
            support=environment.support,
            durable_run_id=environment.durable_run_id,
            authority=environment.authority,
            lease_owner_id="operator-resume",
            task=environment.task,
            request=environment.request,
            provenance=environment.provenance,
            budget_usage=IntegratedBudgetUsage(),
            plan=None,
            now=_NOW,
        )
        assert environment.checkpoint.status is DurableRunStatus.ACTIVE
        assert prepared.checkpoint.status is DurableRunStatus.PAUSED_OPERATOR
        assert prepared.checkpoint.previous_digest == environment.checkpoint.digest
        assert prepared.checkpoint.sequence == environment.checkpoint.sequence.next()
        projection = decode_integrated_durable_projection(prepared.checkpoint)
        assert projection is not None
        assert projection.orchestration_phase is IntegratedOrchestrationPhase.WAITING
        assert projection.waiting_reason is IntegratedWaitingReason.CONTEXT_RESUPPLY
        assert prepared.checkpoint.metadata.active_attempt is None
    finally:
        if prepared is not None:
            await prepared.release(now=_NOW)
        assert (
            await environment.durable_stack.lease_manager.get_current(
                environment.durable_run_id,
                now=_NOW,
            )
            is None
        )
        await environment.close()


@pytest.mark.asyncio
async def test_same_lease_resume_preparation_recovers_prepared_without_started_work() -> None:
    environment = await _environment(pause_for_context_resupply=False)
    prepared_resume = None
    try:
        setup_lease = await environment.durable_stack.lease_manager.acquire(
            environment.durable_run_id,
            owner_id="prepare-attempt-setup",
            now=_NOW,
        )
        try:
            prepared_attempt = (
                await environment.durable_stack.attempt_recorder.prepare_model_attempt(
                    environment.durable_run_id,
                    expected_version=environment.checkpoint.run_version,
                    lease=setup_lease,
                    external_request_digest=_digest("f"),
                    now=_NOW,
                )
            )
        finally:
            await environment.durable_stack.lease_manager.release(setup_lease, now=_NOW)

        original_attempt = prepared_attempt.metadata.active_attempt
        assert original_attempt is not None
        assert original_attempt.status is ExecutionAttemptStatus.PREPARED
        assert original_attempt.started_at is None

        prepared_resume = await prepare_same_lease_durable_task_resume(
            owner=environment.owner,
            support=environment.support,
            durable_run_id=environment.durable_run_id,
            authority=environment.authority,
            lease_owner_id="operator-resume-prepared",
            task=environment.task,
            request=environment.request,
            provenance=environment.provenance,
            budget_usage=IntegratedBudgetUsage(),
            plan=None,
            now=_NOW,
        )

        assert prepared_resume.checkpoint.status is DurableRunStatus.PAUSED_OPERATOR
        assert prepared_resume.checkpoint.metadata.active_attempt is None
        history = await environment.durable_stack.store.list_history(
            environment.durable_run_id,
            limit=prepared_resume.checkpoint.sequence.value,
        )
        cancelled = history[-2]
        cancelled_attempt = cancelled.metadata.active_attempt
        assert cancelled.status is DurableRunStatus.PAUSED_OPERATOR
        assert cancelled_attempt is not None
        assert cancelled_attempt.attempt_id == original_attempt.attempt_id
        assert cancelled_attempt.status is ExecutionAttemptStatus.CANCELLED
        assert cancelled_attempt.started_at is None
        assert cancelled_attempt.completed_at == _NOW
    finally:
        if prepared_resume is not None:
            await prepared_resume.release(now=_NOW)
        await environment.close()


@pytest.mark.asyncio
async def test_same_lease_resume_preparation_marks_started_attempt_indeterminate_and_stops() -> (
    None
):
    environment = await _environment(pause_for_context_resupply=False)
    try:
        setup_lease = await environment.durable_stack.lease_manager.acquire(
            environment.durable_run_id,
            owner_id="started-attempt-setup",
            now=_NOW,
        )
        try:
            prepared_attempt = (
                await environment.durable_stack.attempt_recorder.prepare_model_attempt(
                    environment.durable_run_id,
                    expected_version=environment.checkpoint.run_version,
                    lease=setup_lease,
                    external_request_digest=_digest("e"),
                    now=_NOW,
                )
            )
            attempt = prepared_attempt.metadata.active_attempt
            assert attempt is not None
            started = await environment.durable_stack.attempt_recorder.mark_started(
                environment.durable_run_id,
                attempt.attempt_id,
                expected_version=prepared_attempt.run_version,
                lease=setup_lease,
                now=_NOW,
            )
        finally:
            await environment.durable_stack.lease_manager.release(setup_lease, now=_NOW)

        with pytest.raises(TaskResumePreparationError):
            await prepare_same_lease_durable_task_resume(
                owner=environment.owner,
                support=environment.support,
                durable_run_id=environment.durable_run_id,
                authority=environment.authority,
                lease_owner_id="operator-resume-started",
                task=environment.task,
                request=environment.request,
                provenance=environment.provenance,
                budget_usage=IntegratedBudgetUsage(),
                plan=None,
                now=_NOW,
            )

        current = await environment.durable_stack.store.get_current(environment.durable_run_id)
        assert current is not None
        current_attempt = current.metadata.active_attempt
        assert current.status is DurableRunStatus.INDETERMINATE_MODEL
        assert current.previous_digest == started.digest
        assert current_attempt is not None
        assert current_attempt.status is ExecutionAttemptStatus.INDETERMINATE
        assert current_attempt.indeterminate_reason is IndeterminateReason.PROVIDER_STATUS_UNKNOWN
        assert (
            await environment.durable_stack.lease_manager.get_current(
                environment.durable_run_id,
                now=_NOW,
            )
            is None
        )
    finally:
        await environment.close()


@pytest.mark.asyncio
async def test_confirm_not_started_reconciliation_resumes_and_consumes_head_metadata() -> None:
    from phoenix_os.control_plane.task_resume_activation import (
        activate_prepared_same_lease_durable_task_resume,
    )

    environment = await _environment(pause_for_context_resupply=False)
    prepared_resume = None
    try:
        setup_lease = await environment.durable_stack.lease_manager.acquire(
            environment.durable_run_id,
            owner_id="reconciliation-bridge-setup",
            now=_NOW,
        )
        try:
            prepared_attempt = (
                await environment.durable_stack.attempt_recorder.prepare_model_attempt(
                    environment.durable_run_id,
                    expected_version=environment.checkpoint.run_version,
                    lease=setup_lease,
                    external_request_digest=_digest("d"),
                    now=_NOW,
                )
            )
            prepared_state = prepared_attempt.metadata.active_attempt
            assert prepared_state is not None
            started = await environment.durable_stack.attempt_recorder.mark_started(
                environment.durable_run_id,
                prepared_state.attempt_id,
                expected_version=prepared_attempt.run_version,
                lease=setup_lease,
                now=_NOW,
            )
            indeterminate = await environment.durable_stack.attempt_recorder.mark_indeterminate(
                environment.durable_run_id,
                prepared_state.attempt_id,
                expected_version=started.run_version,
                lease=setup_lease,
                reason=IndeterminateReason.PROVIDER_STATUS_UNKNOWN,
                now=_NOW,
            )
            indeterminate_attempt = indeterminate.metadata.active_attempt
            assert indeterminate_attempt is not None
            assert indeterminate_attempt.started_at is not None

            record = DurableReconciliationDispositionRecord(
                reconciliation_id=UUID("55000000-0000-4000-8000-000000000005"),
                run_id=environment.durable_run_id,
                source_checkpoint_id=indeterminate.checkpoint_id,
                source_checkpoint_digest=indeterminate.digest,
                source_version=indeterminate.run_version,
                source_status=DurableRunStatus.INDETERMINATE_MODEL,
                attempt_id=indeterminate_attempt.attempt_id,
                actor_id="operator-1",
                generation=setup_lease.generation,
                decision=ReconciliationDecision.CONFIRM_NOT_STARTED,
                external_request_digest=indeterminate_attempt.external_request_digest,
                requested_at=_NOW,
                applied_at=_NOW,
                result_status=DurableRunStatus.PAUSED_OPERATOR,
                result_attempt_status=ExecutionAttemptStatus.CANCELLED,
                lookup_id=UUID("56000000-0000-4000-8000-000000000006"),
                lookup_outcome=DurableAttemptStatusLookupOutcome.OBSERVED,
                lookup_adapter_id="reviewed.status",
                external_status=DurableAttemptExternalStatus.NOT_STARTED,
                evidence_type="adapter-receipt",
                evidence_digest=_digest("c"),
                evidence_observed_at=_NOW,
            )
            cancelled_attempt = replace(
                indeterminate_attempt,
                status=ExecutionAttemptStatus.CANCELLED,
                completed_at=_NOW,
                indeterminate_reason=None,
                error_code=None,
            )
            projector = environment.durable_stack.metadata_projector
            assert isinstance(projector, IntegratedDurableCheckpointMetadataProjector)
            reconciliation_checkpoint_id = CheckpointId(
                UUID("57000000-0000-4000-8000-000000000007")
            )
            reconciliation_metadata = dict(indeterminate.metadata.metadata)
            reconciliation_metadata.update(record.to_metadata())
            projected_metadata = projector.project_metadata(
                indeterminate,
                checkpoint_id=reconciliation_checkpoint_id,
                status=DurableRunStatus.PAUSED_OPERATOR,
                step_id=indeterminate.step_id,
                next_operation=CheckpointNextOperation.MODEL_TURN,
                active_attempt=cancelled_attempt,
                metadata=reconciliation_metadata,
            )
            reconciled = seal_checkpoint_envelope(
                replace(
                    indeterminate,
                    checkpoint_id=reconciliation_checkpoint_id,
                    sequence=indeterminate.sequence.next(),
                    previous_digest=indeterminate.digest,
                    run_version=indeterminate.run_version.next(),
                    status=DurableRunStatus.PAUSED_OPERATOR,
                    metadata=replace(
                        indeterminate.metadata,
                        next_operation=CheckpointNextOperation.MODEL_TURN,
                        active_attempt=cancelled_attempt,
                        metadata=projected_metadata,
                    ),
                    created_at=_NOW,
                )
            )
            await environment.durable_stack.store.append(
                reconciled,
                expected_version=indeterminate.run_version,
                lease=setup_lease,
                now=_NOW,
            )
        finally:
            await environment.durable_stack.lease_manager.release(setup_lease, now=_NOW)

        prepared_resume = await prepare_same_lease_durable_task_resume(
            owner=environment.owner,
            support=environment.support,
            durable_run_id=environment.durable_run_id,
            authority=environment.authority,
            lease_owner_id="operator-resume-reconciled",
            task=environment.task,
            request=environment.request,
            provenance=environment.provenance,
            budget_usage=IntegratedBudgetUsage(),
            plan=None,
            now=_NOW,
        )
        source = prepared_resume.checkpoint
        assert source.status is DurableRunStatus.PAUSED_OPERATOR
        assert source.metadata.active_attempt is None
        assert any(key.startswith("reconciliation.") for key in source.metadata.metadata)

        activation = await activate_prepared_same_lease_durable_task_resume(
            owner=environment.owner,
            support=environment.support,
            prepared=prepared_resume,
            authority=environment.authority,
            now=_NOW,
        )
        recovering = activation.recovering_checkpoint
        active = activation.checkpoint
        assert any(key.startswith("reconciliation.") for key in recovering.metadata.metadata)
        assert not any(key.startswith("reconciliation.") for key in active.metadata.metadata)
        assert active.status is DurableRunStatus.ACTIVE
        assert active.metadata.active_attempt is None
    finally:
        if prepared_resume is not None:
            await prepared_resume.release(now=_NOW)
        await environment.close()


# RFC0039-P0B3A2C3AD3C3-SAME-LEASE-RESUME-ACTIVATION-TESTS-V1


@pytest.mark.asyncio
async def test_same_lease_resume_activation_reuses_prepared_lease_and_history() -> None:
    from phoenix_os.control_plane.task_resume_activation import (
        TaskResumeActivationError,
        activate_prepared_same_lease_durable_task_resume,
    )

    environment = await _environment(pause_for_context_resupply=True)
    prepared = None
    try:
        prepared = await prepare_same_lease_durable_task_resume(
            owner=environment.owner,
            support=environment.support,
            durable_run_id=environment.durable_run_id,
            authority=environment.authority,
            lease_owner_id="operator-resume-activation",
            task=environment.task,
            request=environment.request,
            provenance=environment.provenance,
            budget_usage=IntegratedBudgetUsage(),
            plan=None,
            now=_NOW,
        )
        source = prepared.checkpoint
        before_history = await environment.durable_stack.store.list_history(
            environment.durable_run_id,
            limit=source.sequence.value,
        )

        activation = await activate_prepared_same_lease_durable_task_resume(
            owner=environment.owner,
            support=environment.support,
            prepared=prepared,
            authority=environment.authority,
            now=_NOW,
        )

        recovering = activation.recovering_checkpoint
        active = activation.checkpoint
        from phoenix_os.integrated_agent.contracts import (
            IntegratedOrchestrationPhase,
            IntegratedWaitingReason,
        )
        from phoenix_os.integrated_agent.durable_projection import (
            decode_integrated_durable_projection,
        )

        source_projection = decode_integrated_durable_projection(source)
        recovering_projection = decode_integrated_durable_projection(recovering)
        active_projection = decode_integrated_durable_projection(active)
        assert source_projection is not None
        assert recovering_projection is not None
        assert active_projection is not None
        assert source_projection.orchestration_phase is IntegratedOrchestrationPhase.WAITING
        assert source_projection.waiting_reason is IntegratedWaitingReason.CONTEXT_RESUPPLY
        assert recovering_projection.orchestration_phase is IntegratedOrchestrationPhase.EXECUTING
        assert recovering_projection.waiting_reason is None
        assert active_projection.orchestration_phase is IntegratedOrchestrationPhase.EXECUTING
        assert active_projection.waiting_reason is None
        assert (
            recovering_projection.budget_extension_usage == source_projection.budget_extension_usage
        )
        assert active_projection.budget_extension_usage == source_projection.budget_extension_usage
        assert activation.prepared is prepared
        assert recovering.status is DurableRunStatus.RECOVERING
        assert active.status is DurableRunStatus.ACTIVE
        assert recovering.sequence == source.sequence.next()
        assert recovering.run_version == source.run_version.next()
        assert recovering.previous_digest == source.digest
        assert active.sequence == recovering.sequence.next()
        assert active.run_version == recovering.run_version.next()
        assert active.previous_digest == recovering.digest
        assert recovering.agent_run_id == source.agent_run_id
        assert active.agent_run_id == source.agent_run_id
        assert recovering.durable_run_id == source.durable_run_id
        assert active.durable_run_id == source.durable_run_id
        assert recovering.metadata.next_operation is CheckpointNextOperation.MODEL_TURN
        assert active.metadata.next_operation is CheckpointNextOperation.MODEL_TURN
        assert recovering.metadata.active_attempt is None
        assert active.metadata.active_attempt is None
        assert recovering.metadata.budget == source.metadata.budget
        assert active.metadata.budget == source.metadata.budget

        history = await environment.durable_stack.store.list_history(
            environment.durable_run_id,
            limit=active.sequence.value,
        )
        assert history[: len(before_history)] == before_history
        assert history[-2:] == (recovering, active)

        authoritative_lease = await environment.durable_stack.lease_manager.require_current(
            prepared.durable_lease,
            now=_NOW,
        )
        assert authoritative_lease == prepared.durable_lease
        assert authoritative_lease.generation == prepared.durable_lease.generation

        with pytest.raises(TaskResumeActivationError):
            await activate_prepared_same_lease_durable_task_resume(
                owner=environment.owner,
                support=environment.support,
                prepared=prepared,
                authority=environment.authority,
                now=_NOW,
            )
        assert (
            await environment.durable_stack.store.get_current(environment.durable_run_id) == active
        )
    finally:
        if prepared is not None:
            await prepared.release(now=_NOW)
        await environment.close()


# RFC0039-P0B3A2C3AD3C3-RESUME-ACTIVATION-STEP-UNBINDING-TESTS-V2


@pytest.mark.asyncio
async def test_context_resupply_activation_unbinds_stale_step_for_fresh_durable_model_turn() -> (
    None
):
    from phoenix_os.agent.durable_contracts import ExecutionAttemptStatus
    from phoenix_os.agent.execution import BoundedAgentExecutor
    from phoenix_os.agent.fake import AgentModelTurnRequest
    from phoenix_os.agent.model_turn import agent_model_turn_inference_messages
    from phoenix_os.agent.state import AgentCancellationToken
    from phoenix_os.control_plane.task_resume_activation import (
        activate_prepared_same_lease_durable_task_resume,
    )
    from phoenix_os.inference import InferenceRequest
    from phoenix_os.integrated_agent.durable_projection import (
        decode_integrated_durable_projection,
    )

    environment = await _environment(pause_for_context_resupply=True)
    prepared = None
    try:
        prepared = await prepare_same_lease_durable_task_resume(
            owner=environment.owner,
            support=environment.support,
            durable_run_id=environment.durable_run_id,
            authority=environment.authority,
            lease_owner_id="operator-resume-step-unbinding",
            task=environment.task,
            request=environment.request,
            provenance=environment.provenance,
            budget_usage=IntegratedBudgetUsage(),
            plan=None,
            now=_NOW,
        )
        source = prepared.checkpoint
        source_projection = decode_integrated_durable_projection(source)
        assert source_projection is not None
        assert source.step_id == _STEP_ID
        assert source_projection.current_agent_step_id == source.step_id
        assert source.metadata.active_attempt is None

        activation = await activate_prepared_same_lease_durable_task_resume(
            owner=environment.owner,
            support=environment.support,
            prepared=prepared,
            authority=environment.authority,
            now=_NOW,
        )
        recovering = activation.recovering_checkpoint
        active = activation.checkpoint
        recovering_projection = decode_integrated_durable_projection(recovering)
        active_projection = decode_integrated_durable_projection(active)

        assert recovering_projection is not None
        assert active_projection is not None
        assert recovering.step_id is None
        assert active.step_id is None
        assert recovering_projection.current_agent_step_id is None
        assert active_projection.current_agent_step_id is None
        assert recovering.metadata.next_operation is CheckpointNextOperation.MODEL_TURN
        assert active.metadata.next_operation is CheckpointNextOperation.MODEL_TURN
        assert recovering.metadata.active_attempt is None
        assert active.metadata.active_attempt is None
        assert recovering.metadata.budget == source.metadata.budget
        assert active.metadata.budget == source.metadata.budget

        fresh_step = AgentStepId()
        turn = AgentModelTurnRequest(
            run_id=environment.request.run_id,
            step_id=fresh_step,
            messages=environment.request.messages,
            created_at=_NOW,
            deadline=environment.request.deadline,
        )
        inference = InferenceRequest(
            provider_id=environment.request.provider_id,
            model_id=environment.request.model_id,
            messages=agent_model_turn_inference_messages(turn),
            max_output_tokens=32,
            metadata={
                "agent_run_id": str(turn.run_id),
                "agent_step_id": str(turn.step_id),
            },
            correlation_id=str(turn.run_id),
            created_at=turn.created_at,
            deadline=turn.deadline,
        )
        model_driver = environment.durable_stack.create_model_turn_execution_driver(
            lease=prepared.durable_lease,
            lease_renewal_interval=timedelta(seconds=10),
            clock=lambda: _NOW,
        )
        model_result = await model_driver.execute(
            BoundedAgentExecutor(clock=lambda: _NOW),
            DeterministicModelTurnAdapter((DeterministicFinalTurn("done"),)),
            turn,
            inference,
            environment.authority.context,
            timeout_seconds=30,
            cancellation_grace=0.1,
            cancellation=AgentCancellationToken(),
            prepare_time=_NOW,
        )

        assert model_result.run_id == environment.request.run_id
        assert model_result.step_id == fresh_step
        assert model_result.final_output == "done"

        terminal_attempt_checkpoint = model_driver.last_checkpoint
        assert terminal_attempt_checkpoint is not None
        assert terminal_attempt_checkpoint.durable_run_id == environment.durable_run_id
        assert terminal_attempt_checkpoint.agent_run_id == environment.request.run_id
        assert terminal_attempt_checkpoint.step_id == fresh_step
        assert (
            terminal_attempt_checkpoint.metadata.next_operation is CheckpointNextOperation.COMPLETE
        )
        attempt = terminal_attempt_checkpoint.metadata.active_attempt
        assert attempt is not None
        assert attempt.status is ExecutionAttemptStatus.SUCCEEDED
        assert attempt.step_id == fresh_step
        assert terminal_attempt_checkpoint.run_version > active.run_version
    finally:
        if prepared is not None:
            await prepared.release(now=_NOW)
        await environment.close()


# RFC0039-P0B3A2C3AD3C3-SAME-LEASE-RESUME-EXECUTION-OWNER-TESTS-V6


@pytest.mark.asyncio
async def test_same_lease_resume_execution_owner_continues_existing_run_and_releases_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from phoenix_os.agent.contracts import AgentRunStatus
    from phoenix_os.control_plane.task_resume_execution import (
        execute_same_lease_durable_task_resume,
    )
    from phoenix_os.runtime import RuntimeContext

    monkeypatch.setitem(globals(), "_NOW", datetime.now(UTC))
    environment = await _environment(
        pause_for_context_resupply=True,
        live_runtime_clock=True,
        allow_user_result=True,
    )
    runtime_context = RuntimeContext(services={})
    runtime_started = False
    try:
        await environment.owner.runtime.start(runtime_context)
        runtime_started = True
        before = await environment.durable_stack.store.list_history(
            environment.durable_run_id,
            limit=environment.checkpoint.sequence.value,
        )

        result = await execute_same_lease_durable_task_resume(
            owner=environment.owner,
            support=environment.support,
            durable_run_id=environment.durable_run_id,
            authority=environment.authority,
            lease_owner_id="operator-resume-execution-owner",
            task=environment.task,
            request=environment.request,
            provenance=environment.provenance,
            budget_usage=IntegratedBudgetUsage(),
            plan=None,
            now=_NOW,
            clock=lambda: datetime.now(UTC),
        )

        assert result.run_id == environment.request.run_id
        assert result.status is AgentRunStatus.COMPLETED
        assert result.final_output == "done"

        final = await environment.durable_stack.store.get_current(environment.durable_run_id)
        assert final is not None
        assert final.status is DurableRunStatus.COMPLETED
        assert final.run_version > environment.checkpoint.run_version

        history = await environment.durable_stack.store.list_history(
            environment.durable_run_id,
            limit=final.sequence.value,
        )
        assert history[: len(before)] == before
        assert history[-1] == final
        assert sum(item.previous_digest is None for item in history) == 1
        assert all(item.durable_run_id == environment.durable_run_id for item in history)
        assert all(item.agent_run_id == environment.request.run_id for item in history)

        assert (
            await environment.durable_stack.lease_manager.get_current(
                environment.durable_run_id,
                now=_NOW,
            )
            is None
        )
        assert await environment.owner.admission.request_for_run(_RUN_ID) is None
        assert await environment.owner.admission.binding_for_run(_RUN_ID) is None
        assert environment.owner.execution_guard.current_provenance(_RUN_ID) is None
        planner = environment.owner.planner
        assert planner is not None
        assert planner.current_revision(_RUN_ID) is None
    finally:
        if runtime_started:
            await environment.owner.runtime.stop(runtime_context)
        await environment.close()


@pytest.mark.asyncio
async def test_same_lease_resume_execution_owner_releases_after_pre_cancelled_continuation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from phoenix_os.agent.contracts import AgentRunStatus
    from phoenix_os.agent.state import AgentCancellationToken
    from phoenix_os.control_plane.task_resume_execution import (
        execute_same_lease_durable_task_resume,
    )
    from phoenix_os.runtime import RuntimeContext

    monkeypatch.setitem(globals(), "_NOW", datetime.now(UTC))
    environment = await _environment(
        pause_for_context_resupply=True,
        live_runtime_clock=True,
        allow_user_result=True,
    )
    runtime_context = RuntimeContext(services={})
    runtime_started = False
    token = AgentCancellationToken()
    token.cancel()

    try:
        await environment.owner.runtime.start(runtime_context)
        runtime_started = True
        result = await execute_same_lease_durable_task_resume(
            owner=environment.owner,
            support=environment.support,
            durable_run_id=environment.durable_run_id,
            authority=environment.authority,
            lease_owner_id="operator-resume-pre-cancelled",
            task=environment.task,
            request=environment.request,
            provenance=environment.provenance,
            budget_usage=IntegratedBudgetUsage(),
            plan=None,
            now=_NOW,
            cancellation=token,
            clock=lambda: datetime.now(UTC),
        )

        assert result.run_id == environment.request.run_id
        assert result.status is AgentRunStatus.CANCELLED
        current = await environment.durable_stack.store.get_current(environment.durable_run_id)
        assert current is not None
        assert current.status is DurableRunStatus.CANCELLED
        assert (
            await environment.durable_stack.lease_manager.get_current(
                environment.durable_run_id,
                now=_NOW,
            )
            is None
        )
        assert await environment.owner.admission.request_for_run(_RUN_ID) is None
        assert await environment.owner.admission.binding_for_run(_RUN_ID) is None
        assert environment.owner.execution_guard.current_provenance(_RUN_ID) is None
    finally:
        if runtime_started:
            await environment.owner.runtime.stop(runtime_context)
        await environment.close()
