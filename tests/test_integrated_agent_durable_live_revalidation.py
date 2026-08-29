from __future__ import annotations

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
    AgentStepId,
    ToolInvocationRequest,
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
    DurableRunStatus,
    DurableRunVersion,
)
from phoenix_os.agent.errors import AgentAuthorizationRejectedError
from phoenix_os.agent.fake import DeterministicFinalTurn, DeterministicModelTurnAdapter
from phoenix_os.agent.loop import AgentLoop
from phoenix_os.agent.registry import ToolRegistry
from phoenix_os.agent.state import AgentBudgetSnapshot
from phoenix_os.agent.tools import ToolDescriptor
from phoenix_os.inference import InferenceRequest, ModelId, ModelProviderId
from phoenix_os.integrated_agent.admission import (
    IntegratedAgentAdmission,
    IntegratedExecutionProfileSelection,
)
from phoenix_os.integrated_agent.contracts import (
    IntegratedDataFlowDisposition,
    IntegratedDataFlowPolicy,
    IntegratedDataFlowRoute,
    IntegratedDataProvenance,
    IntegratedDataProvenanceAtom,
    IntegratedDataSink,
    IntegratedDataSourceKind,
    IntegratedExecutionProfileGeneration,
    IntegratedExecutionProfileId,
    IntegratedTaskId,
    IntegratedTaskRequest,
)
from phoenix_os.integrated_agent.durable_live_revalidation import (
    AgentLoopIntegratedDurableRecoveryLiveRevalidator,
)
from phoenix_os.integrated_agent.profiles import (
    INTEGRATED_PLAN_UPDATE_TOOL_ID,
    INTEGRATED_PLAN_UPDATE_TRANSFORM_ID,
    IntegratedExecutionProfile,
    IntegratedExecutionProfileCatalog,
    IntegratedLocalTransformBinding,
)
from phoenix_os.policy import PrincipalType, SecurityContext

_NOW = datetime(2026, 8, 29, 0, 15, tzinfo=UTC)
_RUN_ID = AgentRunId(UUID(int=1201))
_DURABLE_RUN_ID = DurableAgentRunId(UUID(int=1202))


def _digest(character: str) -> CheckpointDigest:
    return CheckpointDigest(character * 64)


def _configuration() -> AgentServiceConfiguration:
    return AgentServiceConfiguration(
        agent_id=AgentId("assistant"),
        provider_id=ModelProviderId("local"),
        model_id=ModelId("chat"),
    )


def _profile() -> IntegratedExecutionProfile:
    return IntegratedExecutionProfile(
        profile_id=IntegratedExecutionProfileId("research"),
        generation=IntegratedExecutionProfileGeneration(8),
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


def _task() -> IntegratedTaskRequest:
    return IntegratedTaskRequest(
        task_id=IntegratedTaskId(UUID(int=1203)),
        objective="Resume only after current authority and freshness are revalidated.",
    )


def _request() -> AgentRunRequest:
    return AgentRunRequest(
        agent_id=AgentId("assistant"),
        provider_id=ModelProviderId("local"),
        model_id=ModelId("chat"),
        messages=(AgentMessage(AgentMessageRole.USER, "continue"),),
        run_id=_RUN_ID,
        created_at=_NOW - timedelta(minutes=2),
        deadline=_NOW + timedelta(minutes=10),
    )


def _context() -> SecurityContext:
    return SecurityContext(
        principal="service:assistant",
        principal_type=PrincipalType.SERVICE,
        authenticated=True,
    )


def _admission() -> IntegratedAgentAdmission:
    profile = _profile()
    return IntegratedAgentAdmission(
        IntegratedExecutionProfileCatalog((profile,)),
        IntegratedExecutionProfileSelection(
            profile_id=profile.profile_id,
            generation=profile.generation,
        ),
        _configuration(),
    )


def _checkpoint(request: AgentRunRequest) -> CheckpointEnvelope:
    return seal_checkpoint_envelope(
        CheckpointEnvelope(
            schema_version=CheckpointSchemaVersion(),
            durable_run_id=_DURABLE_RUN_ID,
            checkpoint_id=CheckpointId(UUID(int=1204)),
            sequence=CheckpointSequence(1),
            previous_digest=None,
            run_version=DurableRunVersion(1),
            status=DurableRunStatus.ACTIVE,
            agent_run_id=request.run_id,
            step_id=AgentStepId(UUID(int=1205)),
            metadata=CheckpointMetadata(
                agent_id=request.agent_id,
                actor_id="worker-1",
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
                retention_deadline=_NOW + timedelta(days=1),
            ),
            created_at=_NOW - timedelta(minutes=1),
            digest=_digest("0"),
        )
    )


class _BoundRunAuthorizer:
    def __init__(self) -> None:
        self.allow = True
        self.plain_calls = 0
        self.bound_calls: list[tuple[AgentRunRequest, AgentRunAuthorityBinding]] = []

    async def authorize(self, request: AgentRunRequest, context: SecurityContext) -> None:
        del request, context
        self.plain_calls += 1

    async def authorize_bound(
        self,
        request: AgentRunRequest,
        context: SecurityContext,
        binding: AgentRunAuthorityBinding,
    ) -> None:
        assert context.authenticated
        if not self.allow:
            raise AgentAuthorizationRejectedError()
        self.bound_calls.append((request, binding))


class _ModelAuthorizer:
    async def authorize(self, request: InferenceRequest, context: SecurityContext) -> None:
        del request, context


class _ToolAuthorizer:
    async def authorize(
        self,
        request: ToolInvocationRequest,
        descriptor: ToolDescriptor,
        context: SecurityContext,
    ) -> None:
        del request, descriptor, context


class _FreshnessValidator:
    def __init__(self) -> None:
        self.calls = 0

    async def validate(self, context: SecurityContext) -> None:
        assert context.authenticated
        self.calls += 1


def _loop(
    authorizer: _BoundRunAuthorizer,
    freshness: _FreshnessValidator,
) -> AgentLoop:
    registry = ToolRegistry()
    registry.seal()
    return AgentLoop(
        run_authorizer=authorizer,
        model_authorizer=_ModelAuthorizer(),
        tool_authorizer=_ToolAuthorizer(),
        model_adapter=DeterministicModelTurnAdapter((DeterministicFinalTurn("unused"),)),
        registry=registry,
        authority_freshness=freshness,
        clock=lambda: _NOW,
    )


@pytest.mark.asyncio
async def test_admission_exposes_exact_effective_request_only_while_active() -> None:
    admission = _admission()
    lease = await admission.admit(_task(), _request())

    assert await admission.request_for_run(_RUN_ID) is lease.request
    assert await admission.binding_for_run(_RUN_ID) is lease.binding

    await lease.release()

    assert await admission.request_for_run(_RUN_ID) is None
    assert await admission.binding_for_run(_RUN_ID) is None


@pytest.mark.asyncio
async def test_agent_loop_revalidation_reuses_bound_policy_and_authority_freshness() -> None:
    admission = _admission()
    lease = await admission.admit(_task(), _request())
    authorizer = _BoundRunAuthorizer()
    freshness = _FreshnessValidator()
    loop = _loop(authorizer, freshness)

    await loop.revalidate_run_authority(
        lease.request,
        _context(),
        lease.binding.authority,
    )

    assert authorizer.plain_calls == 0
    assert authorizer.bound_calls == [(lease.request, lease.binding.authority)]
    assert freshness.calls == 1
    await lease.release()


@pytest.mark.asyncio
async def test_live_revalidator_denies_cancellation_authority_and_stale_browser_context() -> None:
    admission = _admission()
    lease = await admission.admit(_task(), _request())
    authorizer = _BoundRunAuthorizer()
    freshness = _FreshnessValidator()
    loop = _loop(authorizer, freshness)
    state = {"cancelled": False, "context_current": True}

    live = AgentLoopIntegratedDurableRecoveryLiveRevalidator(
        loop=loop,
        configuration=_configuration(),
        context=_context(),
        cancellation_probe=lambda _run_id: state["cancelled"],
        context_freshness_probe=lambda _provenance: state["context_current"],
    )
    checkpoint = _checkpoint(lease.request)
    browser_provenance = IntegratedDataProvenance(
        (
            IntegratedDataProvenanceAtom(
                source_kind=IntegratedDataSourceKind.BROWSER,
                source_binding="browser:page/session-1",
                freshness_bindings=("browser-revision:1",),
            ),
        )
    )

    assert await live.revalidate_run(
        checkpoint,
        lease.binding,
        lease.request,
        now=_NOW,
    )
    assert await live.revalidate_context(
        checkpoint,
        browser_provenance,
        now=_NOW,
    )

    state["context_current"] = False
    assert not await live.revalidate_context(
        checkpoint,
        browser_provenance,
        now=_NOW,
    )

    state["context_current"] = True
    state["cancelled"] = True
    assert not await live.revalidate_run(
        checkpoint,
        lease.binding,
        lease.request,
        now=_NOW,
    )

    state["cancelled"] = False
    authorizer.allow = False
    assert not await live.revalidate_run(
        checkpoint,
        lease.binding,
        lease.request,
        now=_NOW,
    )
    await lease.release()
