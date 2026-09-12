from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from phoenix_os.agent.authorization import AgentRunAuthorityBinding
from phoenix_os.agent.configuration import AgentServiceConfiguration
from phoenix_os.agent.contracts import (
    AgentId,
    AgentMessage,
    AgentMessageRole,
    AgentRunId,
    AgentRunRequest,
    AgentRunResult,
    AgentRunStatus,
    AgentStepId,
)
from phoenix_os.agent.durable_cancellation import durable_cancellation_requested
from phoenix_os.agent.durable_codec import (
    checkpoint_envelope_digest,
    seal_checkpoint_envelope,
)
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
    DurableCancellationRequest,
    DurableLease,
    DurableRunStatus,
    DurableRunVersion,
    ExecutionAttemptStatus,
)
from phoenix_os.agent.durable_memory import InMemoryDurableRunStore
from phoenix_os.agent.durable_runtime import (
    DurableAgentRuntimeStack,
    create_durable_agent_runtime_stack,
)
from phoenix_os.agent.errors import (
    AgentErrorCode,
    AgentServiceUnavailableError,
    AgentStateConflictError,
)
from phoenix_os.agent.execution import BoundedAgentExecutor
from phoenix_os.agent.fake import (
    AgentModelTurnAdapter,
    AgentModelTurnKind,
    AgentModelTurnRequest,
    AgentModelTurnResult,
)
from phoenix_os.agent.loop import AgentModelTurnExecutionDriver, AgentToolExecutionDriver
from phoenix_os.agent.model_turn import agent_model_turn_inference_messages
from phoenix_os.agent.service import AgentServiceState
from phoenix_os.agent.state import AgentBudgetSnapshot, AgentCancellationToken
from phoenix_os.authority import AuthorityFreshnessValidator
from phoenix_os.inference import InferenceRequest, ModelId, ModelProviderId
from phoenix_os.integrated_agent.admission import (
    IntegratedAgentAdmission,
    IntegratedAgentAdmissionLease,
    IntegratedAgentRunBinding,
    IntegratedExecutionProfileSelection,
)
from phoenix_os.integrated_agent.checkout_durable_history import (
    create_integrated_checkout_durable_history_validator,
)
from phoenix_os.integrated_agent.contracts import (
    IntegratedDataFlowDisposition,
    IntegratedDataFlowPolicy,
    IntegratedDataFlowRoute,
    IntegratedDataProvenance,
    IntegratedDataSink,
    IntegratedDataSourceKind,
    IntegratedExecutionProfileGeneration,
    IntegratedExecutionProfileId,
    IntegratedOrchestrationPhase,
    IntegratedTaskId,
    IntegratedTaskRequest,
)
from phoenix_os.integrated_agent.durable_projection import decode_integrated_durable_projection
from phoenix_os.integrated_agent.durable_root import (
    create_integrated_durable_root,
    project_integrated_durable_root,
)
from phoenix_os.integrated_agent.durable_run import (
    IntegratedDurableRootProvider,
    IntegratedDurableRunCoordinator,
    PolicyBackedIntegratedDurableRootProvider,
    integrated_durable_run_id,
)
from phoenix_os.integrated_agent.durable_transitions import (
    IntegratedDurableCheckpointMetadataProjector,
)
from phoenix_os.integrated_agent.errors import IntegratedAgentValidationError
from phoenix_os.integrated_agent.execution_guard import IntegratedAgentExecutionGuard
from phoenix_os.integrated_agent.profiles import (
    INTEGRATED_PLAN_UPDATE_TOOL_ID,
    INTEGRATED_PLAN_UPDATE_TRANSFORM_ID,
    IntegratedExecutionProfile,
    IntegratedExecutionProfileCatalog,
    IntegratedLocalTransformBinding,
)
from phoenix_os.integrated_agent.runtime import IntegratedAgentRunExecutor
from phoenix_os.policy import PrincipalType, SecurityContext
from phoenix_os.runtime import RuntimeContext

NOW = datetime(2026, 9, 5, 20, 0, tzinfo=UTC)
ROOT_TIME = NOW + timedelta(seconds=1)
TURN_TIME = NOW + timedelta(seconds=2)
DURABLE_RUN_ID = DurableAgentRunId(UUID("10000000-0000-0000-0000-000000000701"))
STEP_ID = AgentStepId(UUID("30000000-0000-0000-0000-000000000703"))


class _Clock:
    def __init__(self, value: datetime) -> None:
        self.value = value

    def __call__(self) -> datetime:
        return self.value


def _digest(character: str) -> CheckpointDigest:
    return CheckpointDigest(character * 64)


def test_integrated_durable_run_id_reuses_agent_uuid_with_distinct_type() -> None:
    agent_run_id = AgentRunId(UUID("90000000-0000-0000-0000-000000000799"))

    durable_run_id = integrated_durable_run_id(agent_run_id)

    assert isinstance(durable_run_id, DurableAgentRunId)
    assert str(durable_run_id) == str(agent_run_id)


def _compatibility_policy(
    *,
    agent_id: AgentId | None = None,
) -> DurableCompatibilityPolicy:
    selected_agent_id = AgentId("assistant") if agent_id is None else agent_id
    return DurableCompatibilityPolicy(
        agent_id=selected_agent_id,
        current=CompatibilityDigests(
            configuration=_digest("a"),
            tool_registry=_digest("b"),
            model_provider=_digest("c"),
            checkpoint_codec=_digest("d"),
        ),
        payload_profile=CheckpointPayloadProfile.METADATA_ONLY,
    )


def _profile() -> IntegratedExecutionProfile:
    return IntegratedExecutionProfile(
        profile_id=IntegratedExecutionProfileId("research"),
        generation=IntegratedExecutionProfileGeneration(3),
        agent_id=AgentId("assistant"),
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
    )


def _configuration() -> AgentServiceConfiguration:
    return AgentServiceConfiguration(
        agent_id=AgentId("assistant"),
        provider_id=ModelProviderId("local"),
        model_id=ModelId("chat"),
    )


def _admission(
    profile: IntegratedExecutionProfile,
    configuration: AgentServiceConfiguration,
) -> IntegratedAgentAdmission:
    return IntegratedAgentAdmission(
        IntegratedExecutionProfileCatalog((profile,)),
        IntegratedExecutionProfileSelection(
            profile_id=profile.profile_id,
            generation=profile.generation,
        ),
        configuration,
    )


def _task() -> IntegratedTaskRequest:
    return IntegratedTaskRequest(
        task_id=IntegratedTaskId(UUID("70000000-0000-0000-0000-000000000705")),
        objective="Complete one exact durable integrated run.",
    )


def _request() -> AgentRunRequest:
    return AgentRunRequest(
        agent_id=AgentId("assistant"),
        provider_id=ModelProviderId("local"),
        model_id=ModelId("chat"),
        messages=(AgentMessage(AgentMessageRole.USER, "finish deterministically"),),
        created_at=NOW,
        deadline=NOW + timedelta(minutes=20),
    )


async def _binding() -> tuple[
    IntegratedAgentAdmissionLease,
    IntegratedDataProvenance,
]:
    profile = _profile()
    admission = _admission(profile, _configuration())
    lease = await admission.admit(_task(), _request())
    guard = IntegratedAgentExecutionGuard(profile, clock=lambda: ROOT_TIME)
    guard.begin_run(_task(), lease.request)
    provenance = guard.current_provenance(lease.request.run_id)
    assert provenance is not None
    guard.release_run(lease.request.run_id)
    return lease, provenance


def _root(request: AgentRunRequest) -> CheckpointEnvelope:
    return seal_checkpoint_envelope(
        CheckpointEnvelope(
            schema_version=CheckpointSchemaVersion(),
            durable_run_id=DURABLE_RUN_ID,
            checkpoint_id=CheckpointId(UUID("40000000-0000-0000-0000-000000000704")),
            sequence=CheckpointSequence(1),
            previous_digest=None,
            run_version=DurableRunVersion(1),
            status=DurableRunStatus.ACTIVE,
            agent_run_id=request.run_id,
            step_id=None,
            metadata=CheckpointMetadata(
                agent_id=request.agent_id,
                actor_id="integrated-worker",
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
                compatibility=CompatibilityDigests(
                    configuration=_digest("a"),
                    tool_registry=_digest("b"),
                    model_provider=_digest("c"),
                    checkpoint_codec=_digest("d"),
                ),
                payload_profile=CheckpointPayloadProfile.METADATA_ONLY,
                retention_deadline=NOW + timedelta(days=1),
                metadata={"tenant": "demo"},
            ),
            created_at=ROOT_TIME,
            digest=_digest("0"),
        )
    )


@pytest.mark.asyncio
async def test_policy_backed_root_provider_default_id_correlates_agent_run_uuid() -> None:
    admission_lease, provenance = await _binding()
    provider = PolicyBackedIntegratedDurableRootProvider(
        policy=_compatibility_policy(),
        actor_id="integrated-worker",
        clock=lambda: ROOT_TIME,
    )

    try:
        root = provider.build_root(
            admission_lease.request,
            admission_lease.binding,
            provenance,
        )

        assert str(root.durable_run_id) == str(admission_lease.request.run_id)
        assert root.agent_run_id == admission_lease.request.run_id
    finally:
        await admission_lease.release()


@pytest.mark.asyncio
async def test_policy_backed_root_provider_builds_exact_sealed_sequence_one_root() -> None:
    admission_lease, provenance = await _binding()
    checkpoint_id = CheckpointId(UUID("40000000-0000-0000-0000-000000000704"))
    policy = _compatibility_policy()
    provider = PolicyBackedIntegratedDurableRootProvider(
        policy=policy,
        actor_id="integrated-worker",
        retention=timedelta(days=2),
        clock=lambda: ROOT_TIME,
        durable_run_id_factory=lambda: DURABLE_RUN_ID,
        checkpoint_id_factory=lambda: checkpoint_id,
    )

    try:
        root = provider.build_root(
            admission_lease.request,
            admission_lease.binding,
            provenance,
        )

        assert isinstance(provider, IntegratedDurableRootProvider)
        assert provider.policy is policy
        assert root.durable_run_id == DURABLE_RUN_ID
        assert root.checkpoint_id == checkpoint_id
        assert root.sequence == CheckpointSequence(1)
        assert root.run_version == DurableRunVersion(1)
        assert root.previous_digest is None
        assert root.status is DurableRunStatus.ACTIVE
        assert root.agent_run_id == admission_lease.request.run_id
        assert root.step_id is None
        assert root.metadata.agent_id == admission_lease.request.agent_id
        assert root.metadata.actor_id == "integrated-worker"
        assert root.metadata.next_operation is CheckpointNextOperation.MODEL_TURN
        assert root.metadata.compatibility == policy.current
        assert root.metadata.payload_profile is CheckpointPayloadProfile.METADATA_ONLY
        assert root.metadata.active_attempt is None
        assert root.metadata.payload_reference is None
        assert root.metadata.retention_deadline == ROOT_TIME + timedelta(days=2)
        assert root.created_at == ROOT_TIME
        assert root.digest == checkpoint_envelope_digest(root)

        budget = root.metadata.budget
        assert budget.steps == 0
        assert budget.model_turns == 0
        assert budget.tool_calls == 0
        assert budget.model_output_bytes == 0
        assert budget.tool_result_bytes == 0
        assert budget.input_tokens == 0
        assert budget.output_tokens == 0
        assert budget.started_at == admission_lease.request.created_at
        assert budget.deadline == admission_lease.request.deadline

        projected = project_integrated_durable_root(
            root,
            admission_lease.binding,
            provenance=provenance,
        )
        projection = decode_integrated_durable_projection(projected)
        assert projection is not None
        assert projection.task_id == admission_lease.binding.task_id
        assert projection.execution_profile_id == admission_lease.binding.profile_id
    finally:
        await admission_lease.release()


@pytest.mark.asyncio
async def test_policy_backed_root_provider_rejects_wrong_agent_and_expired_request() -> None:
    admission_lease, provenance = await _binding()

    try:
        wrong_agent = PolicyBackedIntegratedDurableRootProvider(
            policy=_compatibility_policy(agent_id=AgentId("other")),
            actor_id="integrated-worker",
            clock=lambda: ROOT_TIME,
        )
        with pytest.raises(IntegratedAgentValidationError, match="admitted integrated binding"):
            wrong_agent.build_root(
                admission_lease.request,
                admission_lease.binding,
                provenance,
            )

        expired = PolicyBackedIntegratedDurableRootProvider(
            policy=_compatibility_policy(),
            actor_id="integrated-worker",
            clock=lambda: admission_lease.request.deadline,
        )
        with pytest.raises(AgentStateConflictError):
            expired.build_root(
                admission_lease.request,
                admission_lease.binding,
                provenance,
            )
    finally:
        await admission_lease.release()


class _RootProvider:
    def __init__(self) -> None:
        self.calls = 0

    def build_root(
        self,
        request: AgentRunRequest,
        binding: IntegratedAgentRunBinding,
        provenance: IntegratedDataProvenance,
    ) -> CheckpointEnvelope:
        del binding, provenance
        self.calls += 1
        return _root(request)


class _FinalModel:
    adapter_id = "durable-run-final-model"

    async def complete_turn(self, request: AgentModelTurnRequest) -> AgentModelTurnResult:
        return AgentModelTurnResult(
            run_id=request.run_id,
            step_id=request.step_id,
            kind=AgentModelTurnKind.FINAL_OUTPUT,
            final_output="durable complete",
        )


class _FailingModel:
    adapter_id = "durable-run-failing-model"

    async def complete_turn(self, request: AgentModelTurnRequest) -> AgentModelTurnResult:
        del request
        raise RuntimeError("private model transport failure")


class _DurableService:
    def __init__(
        self,
        configuration: AgentServiceConfiguration,
        clock: _Clock,
        *,
        fail_model: bool = False,
        immediate_status: AgentRunStatus | None = None,
    ) -> None:
        self._configuration = configuration
        self._clock = clock
        self._fail_model = fail_model
        self._immediate_status = immediate_status
        self.model_driver: AgentModelTurnExecutionDriver | None = None
        self.tool_driver: AgentToolExecutionDriver | None = None
        self.restored_budget: AgentBudgetSnapshot | None = None

    @property
    def configuration(self) -> AgentServiceConfiguration:
        return self._configuration

    @property
    def state(self) -> AgentServiceState:
        return AgentServiceState.RUNNING

    async def start(self, context: RuntimeContext) -> None:
        del context

    async def stop(self, context: RuntimeContext) -> None:
        del context

    async def run(
        self,
        request: AgentRunRequest,
        context: SecurityContext,
        *,
        cancellation: AgentCancellationToken | None = None,
        _authority_binding: AgentRunAuthorityBinding | None = None,
        _authority_freshness: AuthorityFreshnessValidator | None = None,
        _model_turn_execution_driver: AgentModelTurnExecutionDriver | None = None,
        _tool_execution_driver: AgentToolExecutionDriver | None = None,
    ) -> AgentRunResult:
        del _authority_binding, _authority_freshness
        assert isinstance(context, SecurityContext)
        self.model_driver = _model_turn_execution_driver
        self.tool_driver = _tool_execution_driver

        if self._immediate_status is not None:
            error_code = (
                AgentErrorCode.CANCELLED.value
                if self._immediate_status is AgentRunStatus.CANCELLED
                else AgentErrorCode.SERVICE_UNAVAILABLE.value
            )
            return AgentRunResult(
                run_id=request.run_id,
                status=self._immediate_status,
                model_turns=0,
                tool_calls=0,
                error_code=error_code,
                started_at=ROOT_TIME,
                completed_at=ROOT_TIME,
            )

        assert self.model_driver is not None
        assert self.tool_driver is not None
        token = cancellation or AgentCancellationToken()
        self._clock.value = TURN_TIME
        turn = AgentModelTurnRequest(
            run_id=request.run_id,
            step_id=STEP_ID,
            messages=request.messages,
            created_at=TURN_TIME,
            deadline=request.deadline,
        )
        inference = InferenceRequest(
            provider_id=request.provider_id,
            model_id=request.model_id,
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
        adapter: AgentModelTurnAdapter = _FailingModel() if self._fail_model else _FinalModel()

        try:
            model_result = await self.model_driver.execute(
                BoundedAgentExecutor(clock=self._clock),
                adapter,
                turn,
                inference,
                context,
                timeout_seconds=30,
                cancellation_grace=0.1,
                cancellation=token,
                prepare_time=TURN_TIME,
            )
        except AgentServiceUnavailableError:
            return AgentRunResult(
                run_id=request.run_id,
                status=AgentRunStatus.FAILED,
                model_turns=1,
                tool_calls=0,
                error_code=AgentErrorCode.SERVICE_UNAVAILABLE.value,
                started_at=ROOT_TIME,
                completed_at=TURN_TIME,
            )

        assert model_result.final_output is not None
        return AgentRunResult(
            run_id=request.run_id,
            status=AgentRunStatus.COMPLETED,
            model_turns=1,
            tool_calls=0,
            final_output=model_result.final_output,
            started_at=ROOT_TIME,
            completed_at=TURN_TIME,
        )

    async def continue_model_turn(
        self,
        request: AgentRunRequest,
        context: SecurityContext,
        *,
        restored_budget: AgentBudgetSnapshot,
        cancellation: AgentCancellationToken | None = None,
        _authority_binding: AgentRunAuthorityBinding | None = None,
        _model_turn_execution_driver: AgentModelTurnExecutionDriver | None = None,
        _tool_execution_driver: AgentToolExecutionDriver | None = None,
    ) -> AgentRunResult:
        self.restored_budget = restored_budget
        return await self.run(
            request,
            context,
            cancellation=cancellation,
            _authority_binding=_authority_binding,
            _model_turn_execution_driver=_model_turn_execution_driver,
            _tool_execution_driver=_tool_execution_driver,
        )


class _AllowCancellationAuthorizer:
    def __init__(self) -> None:
        self.request: DurableCancellationRequest | None = None
        self.lease: DurableLease | None = None
        self.context: SecurityContext | None = None

    async def authorize(
        self,
        request: DurableCancellationRequest,
        checkpoint: CheckpointEnvelope,
        lease: DurableLease,
        context: SecurityContext,
    ) -> None:
        assert checkpoint.durable_run_id == request.run_id
        self.request = request
        self.lease = lease
        self.context = context


class _BlockingDurableService(_DurableService):
    def __init__(self, configuration: AgentServiceConfiguration, clock: _Clock) -> None:
        super().__init__(configuration, clock)
        self.entered = asyncio.Event()
        self.cancellation: AgentCancellationToken | None = None

    async def run(
        self,
        request: AgentRunRequest,
        context: SecurityContext,
        *,
        cancellation: AgentCancellationToken | None = None,
        _authority_binding: AgentRunAuthorityBinding | None = None,
        _authority_freshness: AuthorityFreshnessValidator | None = None,
        _model_turn_execution_driver: AgentModelTurnExecutionDriver | None = None,
        _tool_execution_driver: AgentToolExecutionDriver | None = None,
    ) -> AgentRunResult:
        del (
            _authority_binding,
            _authority_freshness,
            _model_turn_execution_driver,
            _tool_execution_driver,
        )
        assert isinstance(context, SecurityContext)
        assert isinstance(cancellation, AgentCancellationToken)
        self.cancellation = cancellation
        self.entered.set()
        await cancellation.wait()
        return AgentRunResult(
            run_id=request.run_id,
            status=AgentRunStatus.CANCELLED,
            model_turns=0,
            tool_calls=0,
            error_code=AgentErrorCode.CANCELLED.value,
            started_at=ROOT_TIME,
            completed_at=self._clock.value,
        )


def _context() -> SecurityContext:
    return SecurityContext(
        principal="service:assistant",
        principal_type=PrincipalType.SERVICE,
        authenticated=True,
    )


async def _environment(
    *,
    fail_model: bool = False,
    immediate_status: AgentRunStatus | None = None,
) -> tuple[
    IntegratedAgentAdmissionLease,
    IntegratedDataProvenance,
    _Clock,
    InMemoryDurableRunStore,
    DurableAgentRuntimeStack,
    _RootProvider,
    _DurableService,
    IntegratedDurableRunCoordinator,
]:
    admission_lease, provenance = await _binding()
    clock = _Clock(ROOT_TIME)
    store = InMemoryDurableRunStore()
    stack = create_durable_agent_runtime_stack(
        store=store,
        lease_manager=store.lease_manager,
        compatibility_validator=StaticDurableCompatibilityValidator(()),
        metadata_projector=IntegratedDurableCheckpointMetadataProjector(),
        history_validator=create_integrated_checkout_durable_history_validator(),
    )
    provider = _RootProvider()
    service = _DurableService(
        _configuration(),
        clock,
        fail_model=fail_model,
        immediate_status=immediate_status,
    )
    coordinator = IntegratedDurableRunCoordinator(
        service=service,
        durable_stack=stack,
        root_provider=provider,
        owner_id="integrated-live-worker",
        lease_renewal_interval=timedelta(seconds=10),
        clock=clock,
    )
    return admission_lease, provenance, clock, store, stack, provider, service, coordinator


async def _prepare_existing_active_run(
    admission_lease: IntegratedAgentAdmissionLease,
    provenance: IntegratedDataProvenance,
    clock: _Clock,
    store: InMemoryDurableRunStore,
) -> tuple[CheckpointEnvelope, DurableLease]:
    provider = PolicyBackedIntegratedDurableRootProvider(
        policy=_compatibility_policy(),
        actor_id="integrated-worker",
        clock=clock,
    )
    root = provider.build_root(
        admission_lease.request,
        admission_lease.binding,
        provenance,
    )
    current = await create_integrated_durable_root(
        store,
        root,
        admission_lease.binding,
        provenance=provenance,
    )
    lease = await store.lease_manager.acquire(
        current.durable_run_id,
        owner_id="outer-resume-owner",
        now=clock.value,
    )
    return current, lease


@pytest.mark.asyncio
async def test_same_lease_continuation_reuses_existing_root_lease_and_budget() -> None:
    admission_lease, provenance = await _binding()
    clock = _Clock(ROOT_TIME)
    store = InMemoryDurableRunStore()
    stack = create_durable_agent_runtime_stack(
        store=store,
        lease_manager=store.lease_manager,
        compatibility_validator=StaticDurableCompatibilityValidator(()),
        metadata_projector=IntegratedDurableCheckpointMetadataProjector(),
        history_validator=create_integrated_checkout_durable_history_validator(),
    )
    service = _DurableService(_configuration(), clock)
    unused_root_provider = _RootProvider()
    coordinator = IntegratedDurableRunCoordinator(
        service=service,
        durable_stack=stack,
        root_provider=unused_root_provider,
        owner_id="integrated-live-worker",
        lease_renewal_interval=timedelta(seconds=10),
        clock=clock,
    )
    current, lease = await _prepare_existing_active_run(
        admission_lease,
        provenance,
        clock,
        store,
    )

    try:
        history_before = await store.list_history(current.durable_run_id, limit=16)
        assert history_before == (current,)

        result = await coordinator.continue_same_lease(
            admission_lease.request,
            admission_lease.binding,
            _context(),
            active_checkpoint=current,
            lease=lease,
            restored_budget=current.metadata.budget,
        )

        assert result.run_id == admission_lease.request.run_id
        assert result.status is AgentRunStatus.COMPLETED
        assert result.final_output == "durable complete"
        assert service.restored_budget == current.metadata.budget
        assert service.model_driver is not None
        assert service.tool_driver is not None
        assert unused_root_provider.calls == 0

        final = await store.get_current(current.durable_run_id)
        assert final is not None
        assert final.status is DurableRunStatus.COMPLETED
        history_after = await store.list_history(current.durable_run_id, limit=16)
        assert history_after[0] == current
        assert history_after[-1] == final
        assert final.run_version > current.run_version

        live_lease = await store.lease_manager.get_current(
            current.durable_run_id,
            now=clock.value,
        )
        assert live_lease is not None
        assert live_lease.lease_id == lease.lease_id
        assert live_lease.owner_id == lease.owner_id
        assert live_lease.generation == lease.generation
    finally:
        live_lease = await store.lease_manager.get_current(
            current.durable_run_id,
            now=clock.value,
        )
        if live_lease is not None:
            await store.lease_manager.release(live_lease, now=clock.value)
        await admission_lease.release()
        await stack.close()


@pytest.mark.asyncio
async def test_same_lease_continuation_cancel_uses_same_control_and_retains_outer_lease() -> None:
    admission_lease, provenance = await _binding()
    clock = _Clock(ROOT_TIME)
    store = InMemoryDurableRunStore()
    authorizer = _AllowCancellationAuthorizer()
    stack = create_durable_agent_runtime_stack(
        store=store,
        lease_manager=store.lease_manager,
        compatibility_validator=StaticDurableCompatibilityValidator(()),
        metadata_projector=IntegratedDurableCheckpointMetadataProjector(),
        history_validator=create_integrated_checkout_durable_history_validator(),
        cancellation_authorizer=authorizer,
    )
    service = _BlockingDurableService(_configuration(), clock)
    unused_root_provider = _RootProvider()
    coordinator = IntegratedDurableRunCoordinator(
        service=service,
        durable_stack=stack,
        root_provider=unused_root_provider,
        owner_id="integrated-live-worker",
        lease_renewal_interval=timedelta(seconds=10),
        clock=clock,
    )
    current, lease = await _prepare_existing_active_run(
        admission_lease,
        provenance,
        clock,
        store,
    )
    token = AgentCancellationToken()
    execution = asyncio.create_task(
        coordinator.continue_same_lease(
            admission_lease.request,
            admission_lease.binding,
            _context(),
            active_checkpoint=current,
            lease=lease,
            restored_budget=current.metadata.budget,
            cancellation=token,
        )
    )

    try:
        await asyncio.wait_for(service.entered.wait(), timeout=1.0)
        live_before_cancel = await store.lease_manager.get_current(
            current.durable_run_id,
            now=clock.value,
        )
        assert live_before_cancel is not None
        assert live_before_cancel.lease_id == lease.lease_id
        assert live_before_cancel.generation == lease.generation

        cancelled = await coordinator.cancel_active(
            admission_lease.request.run_id,
            _context(),
            actor_id="service-assistant",
        )
        assert cancelled.status is DurableRunStatus.CANCELLED
        assert durable_cancellation_requested(cancelled)
        assert token.cancelled
        assert authorizer.lease is not None
        assert authorizer.lease.lease_id == lease.lease_id
        assert authorizer.lease.owner_id == lease.owner_id
        assert authorizer.lease.generation == lease.generation

        result = await asyncio.wait_for(execution, timeout=1.0)
        assert result.status is AgentRunStatus.CANCELLED
        assert service.restored_budget == current.metadata.budget
        assert unused_root_provider.calls == 0

        retained = await store.lease_manager.get_current(
            current.durable_run_id,
            now=clock.value,
        )
        assert retained is not None
        assert retained.lease_id == lease.lease_id
        assert retained.owner_id == lease.owner_id
        assert retained.generation == lease.generation
        assert await store.get_current(current.durable_run_id) == cancelled
    finally:
        if not execution.done():
            execution.cancel()
            with pytest.raises(asyncio.CancelledError):
                await execution
        retained = await store.lease_manager.get_current(
            current.durable_run_id,
            now=clock.value,
        )
        if retained is not None:
            await store.lease_manager.release(retained, now=clock.value)
        await admission_lease.release()
        await stack.close()


@pytest.mark.asyncio
async def test_live_coordinator_rejects_missing_checkout_history_runtime_binding() -> None:
    clock = _Clock(ROOT_TIME)
    store = InMemoryDurableRunStore()
    stack = create_durable_agent_runtime_stack(
        store=store,
        lease_manager=store.lease_manager,
        compatibility_validator=StaticDurableCompatibilityValidator(()),
        metadata_projector=IntegratedDurableCheckpointMetadataProjector(),
    )
    try:
        with pytest.raises(
            ValueError,
            match="integrated recovery before checkout-read durable history validation",
        ):
            IntegratedDurableRunCoordinator(
                service=_DurableService(_configuration(), clock),
                durable_stack=stack,
                root_provider=_RootProvider(),
                owner_id="integrated-live-worker",
                clock=clock,
            )
    finally:
        await stack.close()


@pytest.mark.asyncio
async def test_live_cancel_control_uses_exact_coordinator_owned_lease_and_token() -> None:
    admission_lease, provenance = await _binding()
    durable_run_id = integrated_durable_run_id(admission_lease.request.run_id)
    clock = _Clock(ROOT_TIME)
    store = InMemoryDurableRunStore()
    authorizer = _AllowCancellationAuthorizer()
    stack = create_durable_agent_runtime_stack(
        store=store,
        lease_manager=store.lease_manager,
        compatibility_validator=StaticDurableCompatibilityValidator(()),
        metadata_projector=IntegratedDurableCheckpointMetadataProjector(),
        history_validator=create_integrated_checkout_durable_history_validator(),
        cancellation_authorizer=authorizer,
    )
    provider = PolicyBackedIntegratedDurableRootProvider(
        policy=_compatibility_policy(),
        actor_id="integrated-worker",
        clock=clock,
    )
    service = _BlockingDurableService(_configuration(), clock)
    coordinator = IntegratedDurableRunCoordinator(
        service=service,
        durable_stack=stack,
        root_provider=provider,
        owner_id="integrated-live-worker",
        lease_renewal_interval=timedelta(seconds=10),
        clock=clock,
    )
    token = AgentCancellationToken()

    try:
        with pytest.raises(AgentStateConflictError):
            await coordinator.cancel_active(
                admission_lease.request.run_id,
                _context(),
                actor_id="service-assistant",
            )
        assert await store.get_current(durable_run_id) is None

        execution = asyncio.create_task(
            coordinator.execute(
                admission_lease.request,
                admission_lease.binding,
                provenance,
                _context(),
                cancellation=token,
            )
        )
        await asyncio.wait_for(service.entered.wait(), timeout=1.0)

        live_lease = await store.lease_manager.get_current(
            durable_run_id,
            now=clock.value,
        )
        assert live_lease is not None
        assert service.cancellation is token
        assert not token.cancelled

        cancelled = await coordinator.cancel_active(
            admission_lease.request.run_id,
            _context(),
            actor_id="service-assistant",
        )

        assert cancelled.status is DurableRunStatus.CANCELLED
        assert durable_cancellation_requested(cancelled)
        assert token.cancelled
        assert authorizer.request is not None
        assert authorizer.request.run_id == durable_run_id
        assert authorizer.request.expected_version == DurableRunVersion(1)
        assert authorizer.request.generation == live_lease.generation
        assert authorizer.lease == live_lease
        assert authorizer.context == _context()

        result = await asyncio.wait_for(execution, timeout=1.0)
        assert result.status is AgentRunStatus.CANCELLED
        current = await store.get_current(durable_run_id)
        assert current == cancelled
        assert (
            await store.lease_manager.get_current(
                durable_run_id,
                now=clock.value,
            )
            is None
        )

        with pytest.raises(AgentStateConflictError):
            await coordinator.cancel_active(
                admission_lease.request.run_id,
                _context(),
                actor_id="service-assistant",
            )
        assert await store.get_current(durable_run_id) == cancelled
    finally:
        await admission_lease.release()
        await stack.close()


@pytest.mark.asyncio
async def test_live_cancel_control_fails_closed_without_cancellation_authority() -> None:
    admission_lease, provenance = await _binding()
    durable_run_id = integrated_durable_run_id(admission_lease.request.run_id)
    clock = _Clock(ROOT_TIME)
    store = InMemoryDurableRunStore()
    stack = create_durable_agent_runtime_stack(
        store=store,
        lease_manager=store.lease_manager,
        compatibility_validator=StaticDurableCompatibilityValidator(()),
        metadata_projector=IntegratedDurableCheckpointMetadataProjector(),
        history_validator=create_integrated_checkout_durable_history_validator(),
    )
    provider = PolicyBackedIntegratedDurableRootProvider(
        policy=_compatibility_policy(),
        actor_id="integrated-worker",
        clock=clock,
    )
    service = _BlockingDurableService(_configuration(), clock)
    coordinator = IntegratedDurableRunCoordinator(
        service=service,
        durable_stack=stack,
        root_provider=provider,
        owner_id="integrated-live-worker",
        lease_renewal_interval=timedelta(seconds=10),
        clock=clock,
    )

    execution = asyncio.create_task(
        coordinator.execute(
            admission_lease.request,
            admission_lease.binding,
            provenance,
            _context(),
        )
    )
    try:
        await asyncio.wait_for(service.entered.wait(), timeout=1.0)
        assert await store.get_current(durable_run_id) is not None
        assert service.cancellation is not None
        with pytest.raises(AgentStateConflictError):
            await coordinator.cancel_active(
                admission_lease.request.run_id,
                _context(),
                actor_id="service-assistant",
            )
        assert not service.cancellation.cancelled

        service.cancellation.cancel()
        result = await asyncio.wait_for(execution, timeout=1.0)
        assert result.status is AgentRunStatus.CANCELLED
    finally:
        if not execution.done():
            execution.cancel()
            with pytest.raises(asyncio.CancelledError):
                await execution
        await admission_lease.release()
        await stack.close()


@pytest.mark.asyncio
async def test_live_coordinator_completes_via_checkpointing() -> None:
    (
        admission_lease,
        provenance,
        clock,
        store,
        stack,
        provider,
        service,
        coordinator,
    ) = await _environment()
    assert isinstance(coordinator, IntegratedAgentRunExecutor)
    assert isinstance(provider, IntegratedDurableRootProvider)

    try:
        result = await coordinator.execute(
            admission_lease.request,
            admission_lease.binding,
            provenance,
            _context(),
        )

        assert result.status is AgentRunStatus.COMPLETED
        assert result.final_output == "durable complete"
        assert service.model_driver is not None
        assert service.tool_driver is not None
        assert provider.calls == 1

        current = await store.get_current(DURABLE_RUN_ID)
        assert current is not None
        assert current.status is DurableRunStatus.COMPLETED
        assert current.sequence == CheckpointSequence(7)
        assert current.metadata.next_operation is CheckpointNextOperation.NONE
        assert current.metadata.active_attempt is None

        history = await store.list_history(DURABLE_RUN_ID, limit=16)
        statuses = tuple(checkpoint.status for checkpoint in history)
        assert DurableRunStatus.CHECKPOINTING in statuses
        assert statuses[-1] is DurableRunStatus.COMPLETED

        projection = decode_integrated_durable_projection(current)
        assert projection is not None
        assert projection.orchestration_phase is IntegratedOrchestrationPhase.TERMINAL
        assert (
            await store.lease_manager.get_current(
                DURABLE_RUN_ID,
                now=clock.value,
            )
            is None
        )
    finally:
        await admission_lease.release()
        await stack.close()


@pytest.mark.asyncio
async def test_indeterminate_model_state_is_not_overwritten_by_failed_agent_result() -> None:
    (
        admission_lease,
        provenance,
        clock,
        store,
        stack,
        _provider,
        _service,
        coordinator,
    ) = await _environment(fail_model=True)

    try:
        result = await coordinator.execute(
            admission_lease.request,
            admission_lease.binding,
            provenance,
            _context(),
        )

        assert result.status is AgentRunStatus.FAILED
        current = await store.get_current(DURABLE_RUN_ID)
        assert current is not None
        assert current.status is DurableRunStatus.INDETERMINATE_MODEL
        assert current.metadata.next_operation is CheckpointNextOperation.OPERATOR_REVIEW
        attempt = current.metadata.active_attempt
        assert attempt is not None
        assert attempt.status is ExecutionAttemptStatus.INDETERMINATE
        assert (
            await store.lease_manager.get_current(
                DURABLE_RUN_ID,
                now=clock.value,
            )
            is None
        )
    finally:
        await admission_lease.release()
        await stack.close()


@pytest.mark.asyncio
async def test_definitive_pre_attempt_failure_terminalizes_without_fabricating_attempt() -> None:
    (
        admission_lease,
        provenance,
        clock,
        store,
        stack,
        provider,
        _service,
        coordinator,
    ) = await _environment(immediate_status=AgentRunStatus.FAILED)

    try:
        result = await coordinator.execute(
            admission_lease.request,
            admission_lease.binding,
            provenance,
            _context(),
        )

        assert result.status is AgentRunStatus.FAILED
        assert provider.calls == 1
        current = await store.get_current(DURABLE_RUN_ID)
        assert current is not None
        assert current.status is DurableRunStatus.FAILED
        assert current.sequence == CheckpointSequence(2)
        assert current.metadata.next_operation is CheckpointNextOperation.NONE
        assert current.metadata.active_attempt is None
        projection = decode_integrated_durable_projection(current)
        assert projection is not None
        assert projection.orchestration_phase is IntegratedOrchestrationPhase.TERMINAL
        assert (
            await store.lease_manager.get_current(
                DURABLE_RUN_ID,
                now=clock.value,
            )
            is None
        )
    finally:
        await admission_lease.release()
        await stack.close()


@pytest.mark.asyncio
async def test_missing_provenance_rejects_before_root_publication_or_lease_acquisition() -> None:
    (
        admission_lease,
        _provenance,
        clock,
        store,
        stack,
        provider,
        _service,
        coordinator,
    ) = await _environment()

    try:
        with pytest.raises(IntegratedAgentValidationError, match="reviewed provenance"):
            await coordinator.execute(
                admission_lease.request,
                admission_lease.binding,
                None,
                _context(),
            )

        assert provider.calls == 0
        assert await store.get_current(DURABLE_RUN_ID) is None
        assert (
            await store.lease_manager.get_current(
                DURABLE_RUN_ID,
                now=clock.value,
            )
            is None
        )
    finally:
        await admission_lease.release()
        await stack.close()
