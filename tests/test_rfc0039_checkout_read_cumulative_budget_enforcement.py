from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest

from phoenix_os.agent.checkout_agent_tools import (
    CHECKOUT_READ_TOOL_ID,
    CheckoutToolAdapter,
    checkout_tool_descriptors,
    checkout_tool_surface_resource,
)
from phoenix_os.agent.checkout_authorization import (
    CheckoutListAuthorizationRequest,
    CheckoutPatchAuthorizationRequest,
    CheckoutReadAuthorizationRequest,
)
from phoenix_os.agent.checkout_durable_evidence import CheckoutReadCumulativeByteBudget
from phoenix_os.agent.checkout_workspace import RegisteredDevelopmentCheckoutAdapter
from phoenix_os.agent.configuration import AgentServiceConfiguration
from phoenix_os.agent.contracts import (
    AgentId,
    AgentMessage,
    AgentMessageRole,
    AgentRunId,
    AgentRunRequest,
    AgentStepId,
    ToolCallId,
    ToolInvocationRequest,
    ToolResultStatus,
)
from phoenix_os.agent.durable_codec import seal_checkpoint_envelope
from phoenix_os.agent.durable_compatibility import StaticDurableCompatibilityValidator
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
    ExecutionAttempt,
    ExecutionAttemptId,
    ExecutionAttemptKind,
    ExecutionAttemptStatus,
    IndeterminateReason,
)
from phoenix_os.agent.durable_memory import InMemoryDurableRunStore
from phoenix_os.agent.durable_runtime import create_durable_agent_runtime_stack
from phoenix_os.agent.errors import AgentLimitExceededError
from phoenix_os.agent.execution import BoundedAgentExecutor
from phoenix_os.agent.state import AgentBudgetSnapshot, AgentCancellationToken
from phoenix_os.inference import ModelId, ModelProviderId
from phoenix_os.integrated_agent import (
    INTEGRATED_PLAN_UPDATE_TOOL_ID,
    IntegratedAgentAdmission,
    IntegratedBudgetExtension,
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
from phoenix_os.integrated_agent.durable_run import (
    _create_checkout_read_cumulative_byte_budget,
    _create_checkout_read_durable_tool_execution_driver,
)
from phoenix_os.policy import PrincipalType, SecurityContext

NOW = datetime(2026, 9, 7, 16, tzinfo=UTC)
LEASE_TIME = NOW + timedelta(seconds=1)
INVOCATION_TIME = NOW + timedelta(seconds=2)
PREPARE_TIME = NOW + timedelta(seconds=3)
SUBMIT_TIME = NOW + timedelta(seconds=4)

DURABLE_RUN_ID = DurableAgentRunId(UUID("13000000-0000-0000-0000-000000000043"))
AGENT_RUN_ID = AgentRunId(UUID("23000000-0000-0000-0000-000000000043"))
STEP_ID = AgentStepId(UUID("33000000-0000-0000-0000-000000000043"))
CALL_ID = ToolCallId(UUID("43000000-0000-0000-0000-000000000043"))
MODEL_ATTEMPT_ID = ExecutionAttemptId(UUID("53000000-0000-0000-0000-000000000043"))
WORKSPACE_ID = UUID("63000000-0000-0000-0000-000000000043")


def _digest(character: str) -> CheckpointDigest:
    return CheckpointDigest(character * 64)


def _compatibility() -> CompatibilityDigests:
    return CompatibilityDigests(
        configuration=_digest("a"),
        tool_registry=_digest("b"),
        model_provider=_digest("c"),
        checkpoint_codec=_digest("d"),
    )


def _budget_snapshot() -> AgentBudgetSnapshot:
    return AgentBudgetSnapshot(
        steps=1,
        model_turns=1,
        tool_calls=0,
        model_output_bytes=64,
        tool_result_bytes=0,
        input_tokens=8,
        output_tokens=8,
        started_at=NOW - timedelta(minutes=1),
        deadline=NOW + timedelta(minutes=10),
    )


def _model_attempt() -> ExecutionAttempt:
    return ExecutionAttempt(
        attempt_id=MODEL_ATTEMPT_ID,
        kind=ExecutionAttemptKind.MODEL_TURN,
        status=ExecutionAttemptStatus.SUCCEEDED,
        agent_run_id=AGENT_RUN_ID,
        step_id=STEP_ID,
        prepared_at=NOW - timedelta(seconds=3),
        started_at=NOW - timedelta(seconds=2),
        completed_at=NOW - timedelta(seconds=1),
        external_request_digest=_digest("e"),
    )


def _prior_evidence(total_bytes: int) -> dict[str, str]:
    if total_bytes == 0:
        return {}
    return {
        "rfc0039.checkout.read.count": "1",
        "rfc0039.checkout.read.bytes": str(total_bytes),
        "rfc0039.checkout.read.last.workspace_id": str(WORKSPACE_ID),
        "rfc0039.checkout.read.last.registration_generation": "7",
        "rfc0039.checkout.read.last.root_identity": "sha256:" + ("a" * 64),
        "rfc0039.checkout.read.last.file_identity": "sha256:" + ("b" * 64),
        "rfc0039.checkout.read.last.content_digest": "sha256:" + ("c" * 64),
        "rfc0039.checkout.read.last.byte_length": str(total_bytes),
    }


def _checkpoint(*, prior_bytes: int) -> CheckpointEnvelope:
    return seal_checkpoint_envelope(
        CheckpointEnvelope(
            schema_version=CheckpointSchemaVersion(),
            durable_run_id=DURABLE_RUN_ID,
            checkpoint_id=CheckpointId(UUID("73000000-0000-0000-0000-000000000043")),
            sequence=CheckpointSequence(1),
            previous_digest=None,
            run_version=DurableRunVersion(1),
            status=DurableRunStatus.ACTIVE,
            agent_run_id=AGENT_RUN_ID,
            step_id=STEP_ID,
            metadata=CheckpointMetadata(
                agent_id=AgentId("assistant"),
                actor_id="rfc0039-checkout-read-budget-test",
                next_operation=CheckpointNextOperation.VALIDATE_PROPOSAL,
                budget=_budget_snapshot(),
                compatibility=_compatibility(),
                payload_profile=CheckpointPayloadProfile.METADATA_ONLY,
                retention_deadline=NOW + timedelta(days=1),
                active_attempt=_model_attempt(),
                metadata=_prior_evidence(prior_bytes),
            ),
            created_at=NOW,
            digest=_digest("0"),
        )
    )


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


async def _admitted_budget(max_workspace_read_bytes: int) -> CheckoutReadCumulativeByteBudget:
    profile = IntegratedExecutionProfile(
        profile_id=IntegratedExecutionProfileId("integrated-checkout-budget"),
        generation=IntegratedExecutionProfileGeneration(7),
        agent_id=AgentId("assistant"),
        tool_bindings=(
            IntegratedLocalTransformBinding(
                tool_id=INTEGRATED_PLAN_UPDATE_TOOL_ID,
                transform_id="integrated.plan.update",
                advisory_state_keys=("plan",),
            ),
        ),
        data_flow_policy=_policy(),
        budget_extension=IntegratedBudgetExtension(
            max_workspace_read_bytes=max_workspace_read_bytes
        ),
    )
    admission = IntegratedAgentAdmission(
        IntegratedExecutionProfileCatalog((profile,)),
        IntegratedExecutionProfileSelection(
            profile_id=profile.profile_id,
            generation=profile.generation,
        ),
        AgentServiceConfiguration(
            agent_id=profile.agent_id,
            provider_id=ModelProviderId("local"),
            model_id=ModelId("chat"),
        ),
    )
    request = AgentRunRequest(
        agent_id=profile.agent_id,
        provider_id=ModelProviderId("local"),
        model_id=ModelId("chat"),
        messages=(AgentMessage(AgentMessageRole.USER, "read the reviewed checkout"),),
        run_id=AGENT_RUN_ID,
        created_at=NOW,
        deadline=NOW + timedelta(minutes=10),
    )
    lease = await admission.admit(
        IntegratedTaskRequest(
            task_id=IntegratedTaskId(UUID("83000000-0000-0000-0000-000000000043")),
            objective="Read only the admitted development checkout.",
        ),
        request,
    )
    try:
        budget = _create_checkout_read_cumulative_byte_budget(lease.binding)
        assert budget.max_bytes == max_workspace_read_bytes
        return budget
    finally:
        await lease.release()
        await admission.close()


class _RecordingCheckoutAuthorizer:
    def __init__(self) -> None:
        self.list_calls: list[CheckoutListAuthorizationRequest] = []
        self.read_calls: list[CheckoutReadAuthorizationRequest] = []

    async def authorize_list(
        self,
        request: CheckoutListAuthorizationRequest,
        context: SecurityContext,
    ) -> None:
        assert context.authenticated
        self.list_calls.append(request)

    async def authorize_read(
        self,
        request: CheckoutReadAuthorizationRequest,
        context: SecurityContext,
    ) -> None:
        assert context.authenticated
        self.read_calls.append(request)

    async def authorize_patch(
        self,
        request: CheckoutPatchAuthorizationRequest,
        context: SecurityContext,
    ) -> None:
        del request, context
        raise AssertionError("patch authorization is not expected")


def _security_context() -> SecurityContext:
    return SecurityContext(
        principal="service:checkout-budget-test",
        principal_type=PrincipalType.SERVICE,
        authenticated=True,
    )


def _checkout(tmp_path: Path, payload: bytes) -> tuple[RegisteredDevelopmentCheckoutAdapter, Path]:
    root = tmp_path / "checkout"
    (root / "src").mkdir(parents=True)
    target = root / "src" / "sample.txt"
    target.write_bytes(payload)
    return (
        RegisteredDevelopmentCheckoutAdapter(
            workspace_id=WORKSPACE_ID,
            workspace_name="project",
            generation=7,
            root=root,
            read_prefixes=("src",),
        ),
        target,
    )


def _invocation(checkout: RegisteredDevelopmentCheckoutAdapter) -> ToolInvocationRequest:
    return ToolInvocationRequest(
        agent_id=AgentId("assistant"),
        run_id=AGENT_RUN_ID,
        step_id=STEP_ID,
        call_id=CALL_ID,
        tool_id=CHECKOUT_READ_TOOL_ID,
        arguments={"logical_path": "src/sample.txt"},
        resolved_resource=checkout_tool_surface_resource(checkout.registration),
        created_at=INVOCATION_TIME,
        deadline=INVOCATION_TIME + timedelta(minutes=1),
    )


async def _driver(
    store: InMemoryDurableRunStore,
    budget: CheckoutReadCumulativeByteBudget,
) -> tuple[Any, Any]:
    stack = create_durable_agent_runtime_stack(
        store=store,
        lease_manager=store.lease_manager,
        compatibility_validator=StaticDurableCompatibilityValidator(()),
    )
    lease = await store.lease_manager.acquire(
        DURABLE_RUN_ID,
        owner_id="rfc0039-checkout-read-budget-test",
        now=LEASE_TIME,
    )
    driver = _create_checkout_read_durable_tool_execution_driver(
        stack,
        lease=lease,
        lease_renewal_interval=timedelta(seconds=10),
        read_budget=budget,
        clock=lambda: SUBMIT_TIME,
    )
    return stack, driver


@pytest.mark.asyncio
async def test_exhausted_prior_bytes_fail_before_checkout_adapter_dispatch(tmp_path: Path) -> None:
    checkout, _target = _checkout(tmp_path, b"x")
    authorizer = _RecordingCheckoutAuthorizer()
    budget = await _admitted_budget(5)
    adapter = CheckoutToolAdapter(
        checkout,
        authorizer,
        tool_id=CHECKOUT_READ_TOOL_ID,
    )
    store = InMemoryDurableRunStore()
    await store.create(_checkpoint(prior_bytes=5))
    stack, driver = await _driver(store, budget)

    try:
        with pytest.raises(AgentLimitExceededError):
            await driver.execute(
                BoundedAgentExecutor(clock=lambda: SUBMIT_TIME),
                adapter,
                _invocation(checkout),
                checkout_tool_descriptors()[1],
                _security_context(),
                final_admission=None,
                timeout_seconds=30,
                cancellation_grace=0.1,
                cancellation=AgentCancellationToken(),
                prepare_time=PREPARE_TIME,
            )

        assert authorizer.read_calls == []
        current = await store.get_current(DURABLE_RUN_ID)
        assert current is not None
        attempt = current.metadata.active_attempt
        assert attempt is not None
        assert attempt.status is ExecutionAttemptStatus.FAILED
        assert attempt.started_at is None
        assert attempt.error_code == "limit_exceeded"
        assert current.metadata.metadata["rfc0039.checkout.read.bytes"] == "5"
    finally:
        await stack.close()


@pytest.mark.asyncio
async def test_remaining_budget_rejects_before_content_open_after_specific_authorization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkout, target = _checkout(tmp_path, b"abc")
    authorizer = _RecordingCheckoutAuthorizer()
    budget = await _admitted_budget(5)
    adapter = CheckoutToolAdapter(
        checkout,
        authorizer,
        tool_id=CHECKOUT_READ_TOOL_ID,
    )
    store = InMemoryDurableRunStore()
    await store.create(_checkpoint(prior_bytes=3))
    stack, driver = await _driver(store, budget)

    original_open = Path.open
    target_open_calls = 0

    def tracking_open(path: Path, *args: Any, **kwargs: Any) -> Any:
        nonlocal target_open_calls
        if path == target:
            target_open_calls += 1
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", tracking_open)

    try:
        result = await driver.execute(
            BoundedAgentExecutor(clock=lambda: SUBMIT_TIME),
            adapter,
            _invocation(checkout),
            checkout_tool_descriptors()[1],
            _security_context(),
            final_admission=None,
            timeout_seconds=30,
            cancellation_grace=0.1,
            cancellation=AgentCancellationToken(),
            prepare_time=PREPARE_TIME,
        )

        assert result.status is ToolResultStatus.INDETERMINATE
        assert result.output is None
        assert len(authorizer.read_calls) == 1
        assert target_open_calls == 0

        current = await store.get_current(DURABLE_RUN_ID)
        assert current is not None
        assert current.status is DurableRunStatus.INDETERMINATE_TOOL
        assert current.metadata.next_operation is CheckpointNextOperation.OPERATOR_REVIEW
        attempt = current.metadata.active_attempt
        assert attempt is not None
        assert attempt.status is ExecutionAttemptStatus.INDETERMINATE
        assert attempt.started_at == SUBMIT_TIME
        assert attempt.indeterminate_reason is IndeterminateReason.TOOL_STATUS_UNKNOWN
        assert current.metadata.metadata["rfc0039.checkout.read.bytes"] == "3"
    finally:
        await stack.close()


@pytest.mark.asyncio
async def test_read_at_remaining_boundary_reuses_authoritative_durable_counter(
    tmp_path: Path,
) -> None:
    checkout, _target = _checkout(tmp_path, b"ab")
    authorizer = _RecordingCheckoutAuthorizer()
    budget = await _admitted_budget(5)
    adapter = CheckoutToolAdapter(
        checkout,
        authorizer,
        tool_id=CHECKOUT_READ_TOOL_ID,
    )
    store = InMemoryDurableRunStore()
    await store.create(_checkpoint(prior_bytes=3))
    stack, driver = await _driver(store, budget)

    try:
        result = await driver.execute(
            BoundedAgentExecutor(clock=lambda: SUBMIT_TIME),
            adapter,
            _invocation(checkout),
            checkout_tool_descriptors()[1],
            _security_context(),
            final_admission=None,
            timeout_seconds=30,
            cancellation_grace=0.1,
            cancellation=AgentCancellationToken(),
            prepare_time=PREPARE_TIME,
        )

        assert len(authorizer.read_calls) == 1
        assert result.output is not None
        current = await store.get_current(DURABLE_RUN_ID)
        assert current is not None
        assert current.metadata.metadata["rfc0039.checkout.read.count"] == "2"
        assert current.metadata.metadata["rfc0039.checkout.read.bytes"] == "5"
        assert "workspace_read_bytes" not in repr(current.metadata)
    finally:
        await stack.close()
