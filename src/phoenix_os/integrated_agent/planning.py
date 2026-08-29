"""Bounded advisory planner and local plan-update tool for RFC-0036 S3."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import timedelta
from threading import RLock
from typing import Protocol, cast, runtime_checkable

from phoenix_os.agent.contracts import (
    MAX_AGENT_ARGUMENT_BYTES,
    AgentJsonValue,
    AgentRunId,
    ToolAvailability,
    ToolCallId,
    ToolEffect,
    ToolId,
    ToolInvocationRequest,
    ToolInvocationResult,
    ToolResultStatus,
)
from phoenix_os.agent.errors import ToolExecutionError
from phoenix_os.agent.schemas import (
    ToolInputSchema,
    ToolOutputSchema,
    ToolSchema,
    ToolSchemaType,
)
from phoenix_os.agent.tools import (
    ToolAdapter,
    ToolDescriptor,
    ToolResourceResolutionContext,
    ToolResourceResolver,
)
from phoenix_os.integrated_agent.admission import IntegratedAgentRunBinding
from phoenix_os.integrated_agent.contracts import (
    MAX_INTEGRATED_PLAN_REVISION,
    MAX_INTEGRATED_PLAN_STATEMENT_CHARS,
    MAX_INTEGRATED_PLAN_STATEMENTS,
    IntegratedDataProvenance,
    IntegratedDataProvenanceAtom,
    IntegratedDataSourceKind,
    NormalizedPlan,
    PlanProposal,
    PlanRevision,
)
from phoenix_os.integrated_agent.data_flow import integrated_provenance_union
from phoenix_os.integrated_agent.errors import (
    IntegratedAgentConfigurationError,
    IntegratedAgentError,
    IntegratedAgentRejectedError,
    IntegratedAgentStaleError,
    IntegratedAgentValidationError,
)
from phoenix_os.integrated_agent.profiles import (
    INTEGRATED_PLAN_UPDATE_TOOL_ID,
    IntegratedExecutionProfile,
    IntegratedLocalTransformBinding,
)

_PLAN_RESOLVER_ID = "integrated.plan.update.resource"
_PLAN_ADAPTER_ID = "integrated.plan.update.local"

_PLAN_STATEMENT_SCHEMA = ToolSchema(
    kind=ToolSchemaType.STRING,
    min_length=1,
    max_length=MAX_INTEGRATED_PLAN_STATEMENT_CHARS,
)
_PLAN_INPUT_SCHEMA = ToolInputSchema(
    ToolSchema(
        kind=ToolSchemaType.OBJECT,
        properties={
            "statements": ToolSchema(
                kind=ToolSchemaType.ARRAY,
                items=_PLAN_STATEMENT_SCHEMA,
                min_items=1,
                max_items=MAX_INTEGRATED_PLAN_STATEMENTS,
            )
        },
        required=frozenset({"statements"}),
    )
)
_PLAN_OUTPUT_SCHEMA = ToolOutputSchema(
    ToolSchema(
        kind=ToolSchemaType.OBJECT,
        properties={
            "revision": ToolSchema(
                kind=ToolSchemaType.INTEGER,
                minimum=1,
                maximum=MAX_INTEGRATED_PLAN_REVISION,
            ),
            "digest": ToolSchema(
                kind=ToolSchemaType.STRING,
                min_length=71,
                max_length=71,
            ),
        },
        required=frozenset({"revision", "digest"}),
    )
)
_PLAN_DESCRIPTOR = ToolDescriptor(
    tool_id=INTEGRATED_PLAN_UPDATE_TOOL_ID,
    name="Update integrated advisory plan",
    description=(
        "Replace bounded advisory future intent for the current integrated task without "
        "granting authority or executing protected effects."
    ),
    input_schema=_PLAN_INPUT_SCHEMA,
    output_schema=_PLAN_OUTPUT_SCHEMA,
    effect=ToolEffect.READ_ONLY,
    approval_may_be_required=False,
    max_input_bytes=MAX_AGENT_ARGUMENT_BYTES,
    max_output_bytes=4_096,
    timeout=timedelta(seconds=5),
    resolver_id=_PLAN_RESOLVER_ID,
    adapter_id=_PLAN_ADAPTER_ID,
    availability=ToolAvailability.ACTIVE,
)


@dataclass(slots=True)
class _PlannerRunState:
    binding: IntegratedAgentRunBinding
    revision: int = 0
    plan: NormalizedPlan | None = None


class _IntegratedPlanUpdateResourceResolver:
    def __init__(self, planner: IntegratedPlanner) -> None:
        self._planner = planner

    @property
    def resolver_id(self) -> str:
        return _PLAN_RESOLVER_ID

    def resolve_resource(self, arguments: Mapping[str, AgentJsonValue]) -> str:
        del arguments
        raise ToolExecutionError()

    def resolve_resource_with_context(
        self,
        arguments: Mapping[str, AgentJsonValue],
        context: ToolResourceResolutionContext,
    ) -> str:
        if not isinstance(arguments, Mapping):
            raise TypeError("arguments must be a mapping")
        return self._planner._resource_for(context)


class _IntegratedPlanUpdateAdapter:
    def __init__(self, planner: IntegratedPlanner) -> None:
        self._planner = planner

    @property
    def adapter_id(self) -> str:
        return _PLAN_ADAPTER_ID

    @property
    def tool_id(self) -> ToolId:
        return INTEGRATED_PLAN_UPDATE_TOOL_ID

    async def invoke(self, request: ToolInvocationRequest) -> ToolInvocationResult:
        try:
            plan = self._planner._accept(request)
        except IntegratedAgentError as exception:
            return ToolInvocationResult(
                run_id=request.run_id,
                step_id=request.step_id,
                call_id=request.call_id,
                tool_id=request.tool_id,
                status=ToolResultStatus.FAILED,
                error_code=exception.code.value,
                started_at=request.created_at,
                completed_at=request.created_at,
            )
        return ToolInvocationResult(
            run_id=request.run_id,
            step_id=request.step_id,
            call_id=request.call_id,
            tool_id=request.tool_id,
            status=ToolResultStatus.SUCCEEDED,
            output={
                "revision": plan.revision.value,
                "digest": str(plan.digest),
            },
            started_at=request.created_at,
            completed_at=request.created_at,
        )


@runtime_checkable
class IntegratedAttemptProvenanceProvider(Protocol):
    """Provide exact already-admitted provenance for one local-transform attempt."""

    def provenance_for_attempt(
        self,
        run_id: AgentRunId,
        call_id: ToolCallId,
    ) -> IntegratedDataProvenance: ...


class IntegratedPlanner:
    """Own bounded in-memory advisory plan revisions for exact admitted agent runs."""

    def __init__(
        self,
        profile: IntegratedExecutionProfile,
        *,
        provenance_provider: IntegratedAttemptProvenanceProvider | None = None,
    ) -> None:
        if not isinstance(profile, IntegratedExecutionProfile):
            raise TypeError("profile must be IntegratedExecutionProfile")
        if provenance_provider is not None and not isinstance(
            provenance_provider,
            IntegratedAttemptProvenanceProvider,
        ):
            raise TypeError(
                "provenance_provider must implement IntegratedAttemptProvenanceProvider"
            )
        try:
            binding = profile.require_tool_binding(INTEGRATED_PLAN_UPDATE_TOOL_ID)
        except KeyError as exception:
            raise IntegratedAgentConfigurationError() from exception
        if not isinstance(binding, IntegratedLocalTransformBinding):
            raise IntegratedAgentConfigurationError()

        self._profile = profile
        self._provenance_provider = provenance_provider
        self._resolver = _IntegratedPlanUpdateResourceResolver(self)
        self._adapter = _IntegratedPlanUpdateAdapter(self)
        self._active: dict[AgentRunId, _PlannerRunState] = {}
        self._seen: set[AgentRunId] = set()
        self._closed = False
        self._lock = RLock()

    @property
    def profile(self) -> IntegratedExecutionProfile:
        return self._profile

    @property
    def provenance_provider(self) -> IntegratedAttemptProvenanceProvider | None:
        return self._provenance_provider

    @property
    def descriptor(self) -> ToolDescriptor:
        return _PLAN_DESCRIPTOR

    @property
    def resource_resolver(self) -> ToolResourceResolver:
        return self._resolver

    @property
    def adapter(self) -> ToolAdapter:
        return self._adapter

    @property
    def closed(self) -> bool:
        with self._lock:
            return self._closed

    def begin_run(self, binding: IntegratedAgentRunBinding) -> None:
        if not isinstance(binding, IntegratedAgentRunBinding):
            raise TypeError("binding must be IntegratedAgentRunBinding")
        if (
            binding.profile_id != self._profile.profile_id
            or binding.profile_generation != self._profile.generation
            or binding.agent_id != self._profile.agent_id
        ):
            raise IntegratedAgentConfigurationError()
        with self._lock:
            self._require_open()
            if binding.run_id in self._seen:
                raise IntegratedAgentRejectedError(
                    "agent run id cannot be reused for integrated planning"
                )
            self._seen.add(binding.run_id)
            self._active[binding.run_id] = _PlannerRunState(binding=binding)

    def restore_run(
        self,
        binding: IntegratedAgentRunBinding,
        *,
        plan: NormalizedPlan | None,
    ) -> None:
        """Restore exact reviewed advisory plan state for one recovered run."""

        if not isinstance(binding, IntegratedAgentRunBinding):
            raise TypeError("binding must be IntegratedAgentRunBinding")
        if plan is not None and not isinstance(plan, NormalizedPlan):
            raise TypeError("plan must be NormalizedPlan or None")
        if (
            binding.profile_id != self._profile.profile_id
            or binding.profile_generation != self._profile.generation
            or binding.agent_id != self._profile.agent_id
        ):
            raise IntegratedAgentConfigurationError()
        if plan is not None and (
            plan.task_id != binding.task_id
            or plan.revision.value > self._profile.budget_extension.max_plan_revisions
        ):
            raise IntegratedAgentValidationError(
                "restored integrated plan does not match active binding"
            )
        state = _PlannerRunState(
            binding=binding,
            revision=0 if plan is None else plan.revision.value,
            plan=plan,
        )
        with self._lock:
            self._require_open()
            if binding.run_id in self._seen or binding.run_id in self._active:
                raise IntegratedAgentRejectedError(
                    "agent run id cannot be reused for integrated planning"
                )
            self._seen.add(binding.run_id)
            self._active[binding.run_id] = state

    def release_run(self, run_id: AgentRunId) -> None:
        if not isinstance(run_id, AgentRunId):
            raise TypeError("run_id must be AgentRunId")
        with self._lock:
            self._active.pop(run_id, None)

    def current_plan(self, run_id: AgentRunId) -> NormalizedPlan | None:
        if not isinstance(run_id, AgentRunId):
            raise TypeError("run_id must be AgentRunId")
        with self._lock:
            state = self._active.get(run_id)
            return None if state is None else state.plan

    def current_revision(self, run_id: AgentRunId) -> int | None:
        if not isinstance(run_id, AgentRunId):
            raise TypeError("run_id must be AgentRunId")
        with self._lock:
            state = self._active.get(run_id)
            return None if state is None else state.revision

    def close(self) -> None:
        with self._lock:
            self._active.clear()
            self._closed = True

    def _resource_for(self, context: ToolResourceResolutionContext) -> str:
        if not isinstance(context, ToolResourceResolutionContext):
            raise TypeError("context must be ToolResourceResolutionContext")
        with self._lock:
            self._require_open()
            state = self._active.get(context.run_id)
            if state is None or state.binding.agent_id != context.agent_id:
                raise IntegratedAgentStaleError("integrated planning run is not active")
            return _plan_resource(state)

    def _accept(self, request: ToolInvocationRequest) -> NormalizedPlan:
        if not isinstance(request, ToolInvocationRequest):
            raise TypeError("request must be ToolInvocationRequest")
        if request.tool_id != INTEGRATED_PLAN_UPDATE_TOOL_ID:
            raise IntegratedAgentValidationError("unexpected integrated planning tool")
        with self._lock:
            self._require_open()
            state = self._active.get(request.run_id)
            if (
                state is None
                or request.agent_id is None
                or request.agent_id != state.binding.agent_id
            ):
                raise IntegratedAgentStaleError("integrated planning run is not active")
            if request.resolved_resource != _plan_resource(state):
                raise IntegratedAgentStaleError("integrated plan revision is stale")
            proposal = _proposal_from_arguments(request.arguments)
            next_revision = state.revision + 1
            if next_revision > self._profile.budget_extension.max_plan_revisions:
                raise IntegratedAgentRejectedError("integrated plan revision budget is exhausted")
            provenance = _plan_provenance(state.binding)
            if self._provenance_provider is not None:
                inherited = self._provenance_provider.provenance_for_attempt(
                    request.run_id,
                    request.call_id,
                )
                provenance = integrated_provenance_union(
                    inherited,
                    derived_atom=IntegratedDataProvenanceAtom(
                        source_kind=IntegratedDataSourceKind.TOOL_RESULT,
                        source_binding=f"tool-result:{request.call_id}",
                        freshness_bindings=(f"tool:{request.tool_id}",),
                    ),
                )
            plan = NormalizedPlan.create(
                task_id=state.binding.task_id,
                revision=PlanRevision(next_revision),
                statements=proposal.statements,
                provenance=provenance,
            )
            state.revision = next_revision
            state.plan = plan
            return plan

    def _require_open(self) -> None:
        if self._closed:
            raise IntegratedAgentRejectedError("integrated planner is closed")


def _plan_resource(state: _PlannerRunState) -> str:
    return (
        f"integrated-plan:task/{state.binding.task_id}"
        f"/run/{state.binding.run_id}/revision/{state.revision}"
    )


def _proposal_from_arguments(arguments: Mapping[str, object]) -> PlanProposal:
    if not isinstance(arguments, Mapping):
        raise TypeError("arguments must be a mapping")
    if set(arguments) != {"statements"}:
        raise IntegratedAgentValidationError("integrated plan update arguments are invalid")
    statements = arguments["statements"]
    if not isinstance(statements, tuple) or any(
        not isinstance(statement, str) for statement in statements
    ):
        raise IntegratedAgentValidationError("integrated plan statements are invalid")
    try:
        return PlanProposal(cast(tuple[str, ...], statements))
    except (TypeError, ValueError) as exception:
        raise IntegratedAgentValidationError("integrated plan proposal is invalid") from exception


def _plan_provenance(binding: IntegratedAgentRunBinding) -> IntegratedDataProvenance:
    return IntegratedDataProvenance(
        (
            IntegratedDataProvenanceAtom(
                source_kind=IntegratedDataSourceKind.USER_TASK,
                source_binding=f"integrated-task:{binding.task_id}",
                freshness_bindings=(f"task-digest:{binding.task_digest}",),
            ),
            IntegratedDataProvenanceAtom(
                source_kind=IntegratedDataSourceKind.MODEL_OUTPUT,
                source_binding=f"agent-run:{binding.run_id}",
                freshness_bindings=(
                    f"integrated-profile:{binding.profile_id}:{binding.profile_generation}",
                ),
            ),
        )
    )
