"""Run-scoped integrated provenance, data-flow, budget, and effect interception for RFC-0036 S5."""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from threading import RLock
from typing import cast
from uuid import UUID

from phoenix_os.agent.contracts import (
    AgentJsonValue,
    AgentRunId,
    AgentRunRequest,
    AgentStepId,
    ToolCallId,
    ToolEffect,
    ToolInvocationRequest,
    ToolInvocationResult,
    ToolResultStatus,
)
from phoenix_os.agent.errors import (
    AgentAuthorizationRejectedError,
    AgentCancelledError,
    AgentError,
    AgentLimitExceededError,
    AgentTimeoutError,
    ToolExecutionError,
)
from phoenix_os.agent.fake import AgentModelTurnRequest
from phoenix_os.agent.memory_authorization import (
    MEMORY_DELETE_ACTION,
    MEMORY_READ_ACTION,
    MEMORY_SEARCH_ACTION,
    MEMORY_WRITE_ACTION,
)
from phoenix_os.agent.state import AgentCancellationToken
from phoenix_os.agent.tools import (
    ToolAdapter,
    ToolDescriptor,
    ToolFinalAdmissionContext,
    ToolFinalAdmissionGrant,
)
from phoenix_os.agent.workspace_authorization import (
    WORKSPACE_DELETE_ACTION,
    WORKSPACE_EXPORT_ACTION,
    WORKSPACE_IMPORT_ACTION,
    WORKSPACE_LIST_ACTION,
    WORKSPACE_READ_ACTION,
    WORKSPACE_WRITE_ACTION,
)
from phoenix_os.host_automation.agent_control_tools import HostEpochBoundToolAdapter
from phoenix_os.host_automation.authorization import (
    HOST_CLIPBOARD_READ_ACTION,
    HOST_CLIPBOARD_WRITE_ACTION,
)
from phoenix_os.integrated_agent.contracts import (
    IntegratedDataProvenance,
    IntegratedDataProvenanceAtom,
    IntegratedDataSink,
    IntegratedDataSourceKind,
    IntegratedFailureClass,
    IntegratedTaskRequest,
)
from phoenix_os.integrated_agent.data_flow import (
    IntegratedDataFlowGuard,
    integrated_provenance_from_persistence_attributes,
    integrated_provenance_to_persistence_attributes,
    integrated_provenance_union,
)
from phoenix_os.integrated_agent.errors import (
    IntegratedAgentError,
    IntegratedAgentProvenanceOverflowError,
    IntegratedAgentStaleError,
    IntegratedAgentValidationError,
)
from phoenix_os.integrated_agent.execution_control import (
    IntegratedEffectLedger,
    IntegratedRunBudget,
    classify_integrated_failure,
)
from phoenix_os.integrated_agent.profiles import (
    IntegratedDownstreamBoundary,
    IntegratedDownstreamBridgeBinding,
    IntegratedExecutionProfile,
    IntegratedLocalTransformBinding,
    IntegratedToolBinding,
)
from phoenix_os.policy import SecurityContext


def _utc_now() -> datetime:
    return datetime.now(UTC)


@dataclass(slots=True)
class _IntegratedExecutionRunState:
    request: AgentRunRequest
    task: IntegratedTaskRequest
    provenance: IntegratedDataProvenance
    budget: IntegratedRunBudget
    effects: IntegratedEffectLedger = field(default_factory=IntegratedEffectLedger)
    model_steps: set[AgentStepId] = field(default_factory=set)
    pending: dict[ToolCallId, IntegratedDataProvenance] = field(default_factory=dict)


class IntegratedAgentExecutionGuard:
    """One server-owned interceptor for exact run-scoped S5 control metadata."""

    def __init__(
        self,
        profile: IntegratedExecutionProfile,
        *,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        if not isinstance(profile, IntegratedExecutionProfile):
            raise TypeError("profile must be IntegratedExecutionProfile")
        if not callable(clock):
            raise TypeError("clock must be callable")
        self._profile = profile
        self._data_flow = IntegratedDataFlowGuard(profile.data_flow_policy)
        self._clock = clock
        self._active: dict[AgentRunId, _IntegratedExecutionRunState] = {}
        self._seen: set[AgentRunId] = set()
        self._failures: dict[AgentRunId, IntegratedFailureClass] = {}
        self._closed = False
        self._lock = RLock()

    @property
    def profile(self) -> IntegratedExecutionProfile:
        return self._profile

    @property
    def closed(self) -> bool:
        with self._lock:
            return self._closed

    def begin_run(
        self,
        task: IntegratedTaskRequest,
        request: AgentRunRequest,
    ) -> None:
        if not isinstance(task, IntegratedTaskRequest):
            raise TypeError("task must be IntegratedTaskRequest")
        if not isinstance(request, AgentRunRequest):
            raise TypeError("request must be AgentRunRequest")
        if request.agent_id != self._profile.agent_id:
            raise IntegratedAgentValidationError("integrated run agent does not match profile")
        state = _IntegratedExecutionRunState(
            request=request,
            task=task,
            provenance=_task_provenance(task),
            budget=IntegratedRunBudget(
                self._profile.budget_extension,
                started_at=request.created_at,
                parent_deadline=request.deadline,
            ),
        )
        with self._lock:
            self._require_open()
            if request.run_id in self._seen or request.run_id in self._active:
                raise IntegratedAgentStaleError("integrated execution run id cannot be reused")
            self._seen.add(request.run_id)
            self._active[request.run_id] = state

    def release_run(self, run_id: AgentRunId) -> None:
        if not isinstance(run_id, AgentRunId):
            raise TypeError("run_id must be AgentRunId")
        with self._lock:
            self._active.pop(run_id, None)

    def current_provenance(self, run_id: AgentRunId) -> IntegratedDataProvenance | None:
        if not isinstance(run_id, AgentRunId):
            raise TypeError("run_id must be AgentRunId")
        with self._lock:
            state = self._active.get(run_id)
            return None if state is None else state.provenance

    def failure_for(self, run_id: AgentRunId) -> IntegratedFailureClass | None:
        if not isinstance(run_id, AgentRunId):
            raise TypeError("run_id must be AgentRunId")
        with self._lock:
            return self._failures.get(run_id)

    def provenance_for_attempt(
        self,
        run_id: AgentRunId,
        call_id: ToolCallId,
    ) -> IntegratedDataProvenance:
        """Return exact pending provenance only for one already-admitted attempt."""

        if not isinstance(call_id, ToolCallId):
            raise TypeError("call_id must be ToolCallId")
        state = self._require_state(run_id)
        provenance = state.pending.get(call_id)
        if provenance is None:
            raise IntegratedAgentStaleError(
                "integrated tool attempt does not have pending provenance"
            )
        return provenance

    def close(self) -> None:
        with self._lock:
            self._active.clear()
            self._closed = True

    async def before_model_turn(
        self,
        turn: AgentModelTurnRequest,
        context: SecurityContext,
        cancellation: AgentCancellationToken,
    ) -> None:
        state = self._require_state(turn.run_id)
        self._require_turn(state, turn)
        try:
            state.budget.require_active(now=self._now(), cancellation=cancellation)
            self._data_flow.admit(
                state.provenance,
                IntegratedDataSink.MODEL,
                context=context,
            )
            state.model_steps.add(turn.step_id)
        except IntegratedAgentError as exception:
            raise self._translate(turn.run_id, exception) from exception

    async def before_tool_authorization(
        self,
        invocation: ToolInvocationRequest,
        descriptor: ToolDescriptor,
        context: SecurityContext,
        cancellation: AgentCancellationToken,
    ) -> None:
        state = self._require_state(invocation.run_id)
        try:
            binding = self._binding_for(invocation, descriptor)
            provenance = self._model_output_provenance(state, invocation.step_id)
            sink = _sink_for(binding, descriptor)
            if sink is not None:
                self._data_flow.admit(provenance, sink, context=context)
            state.budget.require_step(
                binding,
                cast(Mapping[str, AgentJsonValue], invocation.arguments),
                now=self._now(),
                cancellation=cancellation,
            )
            state.effects.require_admission(descriptor)
            if invocation.call_id in state.pending:
                raise IntegratedAgentStaleError("integrated tool attempt already exists")
            state.pending[invocation.call_id] = provenance
        except IntegratedAgentError as exception:
            raise self._translate(invocation.run_id, exception) from exception

    async def before_tool_invocation(
        self,
        invocation: ToolInvocationRequest,
        descriptor: ToolDescriptor,
        context: SecurityContext,
        cancellation: AgentCancellationToken,
    ) -> None:
        del context
        state = self._require_state(invocation.run_id)
        try:
            binding = self._binding_for(invocation, descriptor)
            if invocation.call_id not in state.pending:
                raise IntegratedAgentStaleError("integrated tool attempt was not admitted")
            state.effects.require_admission(descriptor)
            state.budget.consume_step(
                invocation.call_id,
                binding,
                cast(Mapping[str, AgentJsonValue], invocation.arguments),
                now=self._now(),
                cancellation=cancellation,
            )
        except IntegratedAgentError as exception:
            raise self._translate(invocation.run_id, exception) from exception

    async def final_tool_admission(
        self,
        invocation: ToolInvocationRequest,
        descriptor: ToolDescriptor,
        context: SecurityContext,
        cancellation: AgentCancellationToken,
        details: ToolFinalAdmissionContext | None = None,
    ) -> ToolFinalAdmissionGrant | None:
        state = self._require_state(invocation.run_id)
        try:
            binding = self._binding_for(invocation, descriptor)
            provenance = state.pending.get(invocation.call_id)
            if provenance is None:
                raise IntegratedAgentStaleError("integrated tool attempt was not admitted")

            if details is not None and details.source_provenance_attributes:
                if not _accepts_persisted_lineage_sources(binding):
                    raise IntegratedAgentValidationError(
                        "persisted source lineage is invalid for this bridge"
                    )
                for attributes in details.source_provenance_attributes:
                    restored = integrated_provenance_from_persistence_attributes(attributes)
                    if restored is not None:
                        provenance = integrated_provenance_union(
                            provenance,
                            restored,
                        )

            if _is_workspace_export(binding):
                if details is None:
                    raise IntegratedAgentValidationError(
                        "workspace export requires exact source freshness"
                    )
                if len(details.source_provenance_attributes) != 1:
                    raise IntegratedAgentValidationError(
                        "workspace export requires one authoritative source record"
                    )
                provenance = integrated_provenance_union(
                    provenance,
                    derived_atom=_workspace_export_source_atom(
                        invocation,
                        details,
                    ),
                )
                sink = _sink_for(binding, descriptor)
                if sink is not IntegratedDataSink.WORKSPACE_EXPORT:
                    raise IntegratedAgentValidationError("workspace export sink derivation failed")
                self._data_flow.admit(
                    provenance,
                    sink,
                    context=context,
                )
            elif details is not None and (
                details.source_record_version is not None
                or details.source_content_digest is not None
            ):
                raise IntegratedAgentValidationError(
                    "exact source freshness is valid only for workspace export"
                )

            state.budget.require_active(
                now=self._now(),
                cancellation=cancellation,
            )
            state.effects.require_admission(descriptor)
            if details is not None and details.mutation_bytes:
                if (
                    not isinstance(binding, IntegratedDownstreamBridgeBinding)
                    or binding.boundary is not IntegratedDownstreamBoundary.WORKSPACE
                ):
                    raise IntegratedAgentValidationError(
                        "mutation bytes are valid only for a workspace bridge"
                    )
                state.budget.consume_workspace_mutation(
                    invocation.call_id,
                    details.mutation_bytes,
                    now=self._now(),
                    cancellation=cancellation,
                )

            state.pending[invocation.call_id] = provenance
            if _requires_persisted_lineage(binding):
                return ToolFinalAdmissionGrant(
                    provenance_attributes=(
                        integrated_provenance_to_persistence_attributes(provenance)
                    )
                )
            return None
        except IntegratedAgentError as exception:
            raise self._translate(invocation.run_id, exception) from exception

    async def after_tool_result(
        self,
        invocation: ToolInvocationRequest,
        descriptor: ToolDescriptor,
        result: ToolInvocationResult,
        context: SecurityContext,
        cancellation: AgentCancellationToken,
        adapter: ToolAdapter | None = None,
    ) -> None:
        del context, cancellation
        state = self._require_state(invocation.run_id)
        try:
            binding = self._binding_for(invocation, descriptor)
            inherited = state.pending.pop(invocation.call_id, None)
            if inherited is None:
                raise IntegratedAgentStaleError("integrated tool attempt was not pending")
            state.effects.record(descriptor, result)
            if result.status is ToolResultStatus.SUCCEEDED:
                state.provenance = _tool_result_provenance(
                    inherited,
                    binding,
                    invocation,
                    result,
                    adapter=adapter,
                )
        except IntegratedAgentError as exception:
            raise self._translate(invocation.run_id, exception) from exception

    async def before_final_output(
        self,
        turn: AgentModelTurnRequest,
        final_output: str,
        context: SecurityContext,
        cancellation: AgentCancellationToken,
    ) -> None:
        if not isinstance(final_output, str):
            raise TypeError("final_output must be a string")
        state = self._require_state(turn.run_id)
        self._require_turn(state, turn)
        try:
            state.budget.require_active(now=self._now(), cancellation=cancellation)
            provenance = self._model_output_provenance(state, turn.step_id)
            self._data_flow.admit(
                provenance,
                IntegratedDataSink.USER_RESULT,
                context=context,
            )
        except IntegratedAgentError as exception:
            raise self._translate(turn.run_id, exception) from exception

    def _binding_for(
        self,
        invocation: ToolInvocationRequest,
        descriptor: ToolDescriptor,
    ) -> IntegratedToolBinding:
        if descriptor.tool_id != invocation.tool_id:
            raise IntegratedAgentValidationError("integrated descriptor/tool mismatch")
        try:
            return self._profile.require_tool_binding(invocation.tool_id)
        except KeyError as exception:
            raise IntegratedAgentValidationError(
                "integrated tool binding is unavailable"
            ) from exception

    def _model_output_provenance(
        self,
        state: _IntegratedExecutionRunState,
        step_id: AgentStepId,
    ) -> IntegratedDataProvenance:
        if step_id not in state.model_steps:
            raise IntegratedAgentStaleError("integrated model step was not admitted")
        return integrated_provenance_union(
            state.provenance,
            derived_atom=IntegratedDataProvenanceAtom(
                source_kind=IntegratedDataSourceKind.MODEL_OUTPUT,
                source_binding=f"agent-run:{state.request.run_id}/step:{step_id}",
                freshness_bindings=(
                    f"integrated-profile:{self._profile.profile_id}:{self._profile.generation}",
                ),
            ),
        )

    def _require_state(self, run_id: AgentRunId) -> _IntegratedExecutionRunState:
        if not isinstance(run_id, AgentRunId):
            raise TypeError("run_id must be AgentRunId")
        with self._lock:
            self._require_open()
            state = self._active.get(run_id)
            if state is None:
                raise AgentAuthorizationRejectedError()
            return state

    def _require_turn(
        self,
        state: _IntegratedExecutionRunState,
        turn: AgentModelTurnRequest,
    ) -> None:
        if not isinstance(turn, AgentModelTurnRequest):
            raise TypeError("turn must be AgentModelTurnRequest")
        if turn.run_id != state.request.run_id:
            raise AgentAuthorizationRejectedError()

    def _translate(
        self,
        run_id: AgentRunId,
        exception: IntegratedAgentError,
    ) -> AgentError:
        failure = classify_integrated_failure(exception)
        with self._lock:
            self._failures[run_id] = failure
        if failure in {
            IntegratedFailureClass.DATA_FLOW_DENIED,
            IntegratedFailureClass.AUTHORITY_DENIED,
            IntegratedFailureClass.APPROVAL_REQUIRED,
        }:
            return AgentAuthorizationRejectedError()
        if failure in {
            IntegratedFailureClass.PROVENANCE_OVERFLOW,
            IntegratedFailureClass.BUDGET_EXHAUSTED,
        }:
            return AgentLimitExceededError()
        if failure is IntegratedFailureClass.DEADLINE_EXCEEDED:
            return AgentTimeoutError()
        if failure is IntegratedFailureClass.CANCELLED:
            return AgentCancelledError()
        return ToolExecutionError()

    def _require_open(self) -> None:
        if self._closed:
            raise AgentAuthorizationRejectedError()

    def _now(self) -> datetime:
        value = self._clock()
        if not isinstance(value, datetime):
            raise TypeError("clock result must be datetime")
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("clock result must be timezone-aware")
        return value


def _task_provenance(task: IntegratedTaskRequest) -> IntegratedDataProvenance:
    atoms = [
        IntegratedDataProvenanceAtom(
            source_kind=IntegratedDataSourceKind.USER_TASK,
            source_binding=f"integrated-task:{task.task_id}",
            freshness_bindings=(f"task-digest:{task.digest}",),
        )
    ]
    atoms.extend(
        IntegratedDataProvenanceAtom(
            source_kind=item.source_kind,
            source_binding=item.source_binding,
            freshness_bindings=item.freshness_bindings,
        )
        for item in task.input_references
    )
    try:
        return IntegratedDataProvenance(tuple(atoms))
    except ValueError as exception:
        if "PROVENANCE_OVERFLOW" in str(exception):
            raise IntegratedAgentProvenanceOverflowError() from exception
        raise


def _is_workspace_export(
    binding: IntegratedToolBinding,
) -> bool:
    return (
        isinstance(binding, IntegratedDownstreamBridgeBinding)
        and binding.boundary is IntegratedDownstreamBoundary.WORKSPACE
        and binding.action_family == WORKSPACE_EXPORT_ACTION
    )


def _workspace_export_source_atom(
    invocation: ToolInvocationRequest,
    details: ToolFinalAdmissionContext,
) -> IntegratedDataProvenanceAtom:
    version = _required_positive_int(
        details.source_record_version,
        label="workspace export source version",
    )
    digest = _required_digest(
        details.source_content_digest,
        label="workspace export source content digest",
    )
    expected_version = _required_positive_int(
        invocation.arguments.get("expected_version"),
        label="workspace export expected version",
    )
    if version != expected_version:
        raise IntegratedAgentStaleError("workspace export source version changed")
    artifact_id = _required_uuid_text(
        invocation.arguments.get("artifact_id"),
        label="workspace export artifact id",
    )
    resource = _exact_child_resource(
        invocation.resolved_resource,
        "artifact",
        artifact_id,
    )
    return IntegratedDataProvenanceAtom(
        source_kind=IntegratedDataSourceKind.WORKSPACE,
        source_binding=resource,
        freshness_bindings=(
            f"content-digest:{digest}",
            f"tool-call:{invocation.call_id}",
            f"version:{version}",
        ),
    )


def _accepts_persisted_lineage_sources(
    binding: IntegratedToolBinding,
) -> bool:
    if not isinstance(binding, IntegratedDownstreamBridgeBinding):
        return False
    if binding.boundary is IntegratedDownstreamBoundary.MEMORY:
        return binding.action_family in {
            MEMORY_SEARCH_ACTION,
            MEMORY_READ_ACTION,
        }
    if binding.boundary is IntegratedDownstreamBoundary.WORKSPACE:
        return binding.action_family in {
            WORKSPACE_LIST_ACTION,
            WORKSPACE_READ_ACTION,
            WORKSPACE_EXPORT_ACTION,
        }
    return False


def _requires_persisted_lineage(
    binding: IntegratedToolBinding,
) -> bool:
    if not isinstance(binding, IntegratedDownstreamBridgeBinding):
        return False
    if binding.boundary is IntegratedDownstreamBoundary.MEMORY:
        return binding.action_family == MEMORY_WRITE_ACTION
    if binding.boundary is IntegratedDownstreamBoundary.WORKSPACE:
        return binding.action_family in {
            WORKSPACE_WRITE_ACTION,
            WORKSPACE_IMPORT_ACTION,
        }
    return False


def _sink_for(
    binding: IntegratedToolBinding,
    descriptor: ToolDescriptor,
) -> IntegratedDataSink | None:
    if isinstance(binding, IntegratedLocalTransformBinding):
        return IntegratedDataSink.ORCHESTRATION_STATE
    if binding.boundary is IntegratedDownstreamBoundary.MEMORY:
        return IntegratedDataSink.MEMORY
    if binding.boundary is IntegratedDownstreamBoundary.WORKSPACE:
        if binding.action_family == WORKSPACE_EXPORT_ACTION:
            return IntegratedDataSink.WORKSPACE_EXPORT
        return IntegratedDataSink.WORKSPACE
    if binding.boundary is IntegratedDownstreamBoundary.NETWORK:
        return IntegratedDataSink.NETWORK
    if (
        binding.boundary is IntegratedDownstreamBoundary.BROWSER
        and descriptor.effect is not ToolEffect.READ_ONLY
    ):
        return IntegratedDataSink.BROWSER_EFFECT
    if (
        binding.boundary is IntegratedDownstreamBoundary.HOST
        and descriptor.effect is not ToolEffect.READ_ONLY
    ):
        return IntegratedDataSink.HOST_EFFECT
    return None


def _tool_result_provenance(
    inherited: IntegratedDataProvenance,
    binding: IntegratedToolBinding,
    invocation: ToolInvocationRequest,
    result: ToolInvocationResult,
    *,
    adapter: ToolAdapter | None = None,
) -> IntegratedDataProvenance:
    """Conservatively union exact downstream source atoms plus the exact tool attempt."""

    if result.status is not ToolResultStatus.SUCCEEDED or result.output is None:
        raise IntegratedAgentValidationError(
            "successful integrated result provenance requires validated output"
        )
    atoms = list(_downstream_result_atoms(binding, invocation, result, adapter=adapter))
    atoms.append(
        IntegratedDataProvenanceAtom(
            source_kind=IntegratedDataSourceKind.TOOL_RESULT,
            source_binding=(
                f"agent-run:{invocation.run_id}/step:{invocation.step_id}"
                f"/tool:{invocation.tool_id}/call:{invocation.call_id}"
            ),
            freshness_bindings=(f"tool:{invocation.tool_id}",),
        )
    )
    provenance = inherited
    for atom in atoms:
        provenance = integrated_provenance_union(provenance, derived_atom=atom)
    return provenance


def _downstream_result_atoms(
    binding: IntegratedToolBinding,
    invocation: ToolInvocationRequest,
    result: ToolInvocationResult,
    *,
    adapter: ToolAdapter | None,
) -> tuple[IntegratedDataProvenanceAtom, ...]:
    if isinstance(binding, IntegratedLocalTransformBinding):
        return ()
    output = _validated_result_output(result)
    if binding.boundary is IntegratedDownstreamBoundary.MEMORY:
        return _memory_result_atoms(binding, invocation, output)
    if binding.boundary is IntegratedDownstreamBoundary.WORKSPACE:
        return _workspace_result_atoms(binding, invocation, output)
    if binding.boundary is IntegratedDownstreamBoundary.NETWORK:
        return (_network_result_atom(binding, invocation),)
    if binding.boundary is IntegratedDownstreamBoundary.BROWSER:
        return (_browser_result_atom(binding, invocation, output),)
    if binding.boundary is IntegratedDownstreamBoundary.HOST and binding.action_family in {
        HOST_CLIPBOARD_READ_ACTION,
        HOST_CLIPBOARD_WRITE_ACTION,
    }:
        return (_host_clipboard_result_atom(binding, invocation, output, adapter),)
    return ()


def _memory_result_atoms(
    binding: IntegratedDownstreamBridgeBinding,
    invocation: ToolInvocationRequest,
    output: Mapping[str, AgentJsonValue],
) -> tuple[IntegratedDataProvenanceAtom, ...]:
    action = binding.action_family
    common = (f"tool-call:{invocation.call_id}",)
    if action == MEMORY_SEARCH_ACTION:
        records = _required_sequence(output.get("records"), label="memory search records")
        atoms = [
            IntegratedDataProvenanceAtom(
                source_kind=IntegratedDataSourceKind.MEMORY,
                source_binding=invocation.resolved_resource,
                freshness_bindings=(*common, "operation:search"),
            )
        ]
        atoms.extend(
            _memory_record_atom(
                invocation.resolved_resource,
                _required_mapping(record, label="memory search record"),
                invocation.call_id,
            )
            for record in records
        )
        return tuple(atoms)
    if action == MEMORY_READ_ACTION:
        found = _required_bool(output.get("found"), label="memory found")
        if not found:
            return (
                IntegratedDataProvenanceAtom(
                    source_kind=IntegratedDataSourceKind.MEMORY,
                    source_binding=invocation.resolved_resource,
                    freshness_bindings=(*common, "record-state:not-found"),
                ),
            )
        return (_memory_record_atom(invocation.resolved_resource, output, invocation.call_id),)
    if action == MEMORY_WRITE_ACTION:
        return (_memory_record_atom(invocation.resolved_resource, output, invocation.call_id),)
    if action == MEMORY_DELETE_ACTION:
        if _required_bool(output.get("deleted"), label="memory deleted") is not True:
            raise IntegratedAgentValidationError("memory delete result is not authoritative")
        version = _required_positive_int(
            invocation.arguments.get("expected_version"),
            label="memory expected version",
        )
        incarnation = _required_uuid_text(
            invocation.arguments.get("expected_incarnation"),
            label="memory expected incarnation",
        )
        return (
            IntegratedDataProvenanceAtom(
                source_kind=IntegratedDataSourceKind.MEMORY,
                source_binding=invocation.resolved_resource,
                freshness_bindings=(
                    *common,
                    f"incarnation:{incarnation}",
                    f"version:{version}",
                    "record-state:deleted",
                ),
            ),
        )
    raise IntegratedAgentValidationError("unknown integrated memory result action")


def _memory_record_atom(
    base_resource: str,
    record: Mapping[str, AgentJsonValue],
    call_id: ToolCallId,
) -> IntegratedDataProvenanceAtom:
    memory_id = _required_uuid_text(record.get("memory_id"), label="memory id")
    incarnation = _required_uuid_text(record.get("incarnation"), label="memory incarnation")
    version = _required_positive_int(record.get("version"), label="memory version")
    digest = _required_digest(record.get("content_digest"), label="memory content digest")
    resource = _exact_child_resource(base_resource, "record", memory_id)
    return IntegratedDataProvenanceAtom(
        source_kind=IntegratedDataSourceKind.MEMORY,
        source_binding=resource,
        freshness_bindings=(
            f"content-digest:{digest}",
            f"incarnation:{incarnation}",
            f"tool-call:{call_id}",
            f"version:{version}",
        ),
    )


def _workspace_result_atoms(
    binding: IntegratedDownstreamBridgeBinding,
    invocation: ToolInvocationRequest,
    output: Mapping[str, AgentJsonValue],
) -> tuple[IntegratedDataProvenanceAtom, ...]:
    action = binding.action_family
    common = (f"tool-call:{invocation.call_id}",)
    if action == WORKSPACE_LIST_ACTION:
        artifacts = _required_sequence(output.get("artifacts"), label="workspace artifacts")
        atoms = [
            IntegratedDataProvenanceAtom(
                source_kind=IntegratedDataSourceKind.WORKSPACE,
                source_binding=invocation.resolved_resource,
                freshness_bindings=(*common, "operation:list"),
            )
        ]
        atoms.extend(
            _workspace_record_atom(
                invocation.resolved_resource,
                _required_mapping(artifact, label="workspace artifact"),
                invocation.call_id,
            )
            for artifact in artifacts
        )
        return tuple(atoms)
    if action == WORKSPACE_READ_ACTION:
        found = _required_bool(output.get("found"), label="workspace found")
        if not found:
            return (
                IntegratedDataProvenanceAtom(
                    source_kind=IntegratedDataSourceKind.WORKSPACE,
                    source_binding=invocation.resolved_resource,
                    freshness_bindings=(*common, "artifact-state:not-found"),
                ),
            )
        return (_workspace_record_atom(invocation.resolved_resource, output, invocation.call_id),)
    if action in {WORKSPACE_WRITE_ACTION, WORKSPACE_IMPORT_ACTION, WORKSPACE_EXPORT_ACTION}:
        return (_workspace_record_atom(invocation.resolved_resource, output, invocation.call_id),)
    if action == WORKSPACE_DELETE_ACTION:
        if _required_bool(output.get("deleted"), label="workspace deleted") is not True:
            raise IntegratedAgentValidationError("workspace delete result is not authoritative")
        version = _required_positive_int(
            invocation.arguments.get("expected_version"),
            label="workspace expected version",
        )
        return (
            IntegratedDataProvenanceAtom(
                source_kind=IntegratedDataSourceKind.WORKSPACE,
                source_binding=invocation.resolved_resource,
                freshness_bindings=(
                    *common,
                    f"version:{version}",
                    "artifact-state:deleted",
                ),
            ),
        )
    raise IntegratedAgentValidationError("unknown integrated workspace result action")


def _workspace_record_atom(
    base_resource: str,
    record: Mapping[str, AgentJsonValue],
    call_id: ToolCallId,
) -> IntegratedDataProvenanceAtom:
    artifact_id = _required_uuid_text(record.get("artifact_id"), label="workspace artifact id")
    version = _required_positive_int(record.get("version"), label="workspace artifact version")
    digest = _required_digest(record.get("content_digest"), label="workspace content digest")
    resource = _exact_child_resource(base_resource, "artifact", artifact_id)
    return IntegratedDataProvenanceAtom(
        source_kind=IntegratedDataSourceKind.WORKSPACE,
        source_binding=resource,
        freshness_bindings=(
            f"content-digest:{digest}",
            f"tool-call:{call_id}",
            f"version:{version}",
        ),
    )


def _network_result_atom(
    binding: IntegratedDownstreamBridgeBinding,
    invocation: ToolInvocationRequest,
) -> IntegratedDataProvenanceAtom:
    generation = binding.generation
    if generation is None:
        raise IntegratedAgentValidationError("network result lacks profile generation")
    generation_segment = f"/generation:{generation}/"
    if generation_segment not in invocation.resolved_resource or "/operation:" not in (
        invocation.resolved_resource
    ):
        raise IntegratedAgentValidationError(
            "network result resource is not generation/operation exact"
        )
    return IntegratedDataProvenanceAtom(
        source_kind=IntegratedDataSourceKind.NETWORK,
        source_binding=invocation.resolved_resource,
        freshness_bindings=(
            f"binding-generation:{generation}",
            f"tool-call:{invocation.call_id}",
        ),
    )


def _browser_result_atom(
    binding: IntegratedDownstreamBridgeBinding,
    invocation: ToolInvocationRequest,
    output: Mapping[str, AgentJsonValue],
) -> IntegratedDataProvenanceAtom:
    generation = binding.generation
    if generation is None:
        raise IntegratedAgentValidationError("browser result lacks profile generation")
    session_id = _required_uuid_text(output.get("session_id"), label="browser session id")
    page_id = _required_uuid_text(output.get("page_id"), label="browser page id")
    revision = _required_positive_int(output.get("revision"), label="browser page revision")

    expected_session = invocation.arguments.get("session_id")
    if expected_session is not None and expected_session != session_id:
        raise IntegratedAgentValidationError("browser result session identity changed")
    expected_page = invocation.arguments.get("page_id")
    if expected_page is not None and expected_page != page_id:
        raise IntegratedAgentValidationError("browser result page identity changed")

    profile_generation = output.get("profile_generation")
    if profile_generation is not None and profile_generation != generation:
        raise IntegratedAgentValidationError("browser result profile generation changed")
    profile_id = output.get("profile_id")
    if profile_id is not None:
        if not isinstance(profile_id, str) or binding.binding_id != f"browser:profile/{profile_id}":
            raise IntegratedAgentValidationError("browser result profile identity changed")

    return IntegratedDataProvenanceAtom(
        source_kind=IntegratedDataSourceKind.BROWSER,
        source_binding=(
            f"{binding.binding_id}/generation:{generation}/session:{session_id}/page:{page_id}"
        ),
        freshness_bindings=(
            f"revision:{revision}",
            f"tool-call:{invocation.call_id}",
        ),
    )


def _host_clipboard_result_atom(
    binding: IntegratedDownstreamBridgeBinding,
    invocation: ToolInvocationRequest,
    output: Mapping[str, AgentJsonValue],
    adapter: ToolAdapter | None,
) -> IntegratedDataProvenanceAtom:
    if not isinstance(adapter, HostEpochBoundToolAdapter):
        raise IntegratedAgentValidationError("host clipboard result lacks exact host epoch")
    expected_resource = f"{binding.binding_id}/clipboard:text"
    if invocation.resolved_resource != expected_resource:
        raise IntegratedAgentValidationError("host clipboard result resource changed")
    epoch = adapter.host_epoch
    if binding.action_family == HOST_CLIPBOARD_READ_ACTION:
        text = output.get("text")
    else:
        text = invocation.arguments.get("text")
    if not isinstance(text, str):
        raise IntegratedAgentValidationError("host clipboard result lacks reviewed text binding")
    digest = "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()
    return IntegratedDataProvenanceAtom(
        source_kind=IntegratedDataSourceKind.HOST_CLIPBOARD,
        source_binding=f"{binding.binding_id}/epoch:{epoch}/clipboard:text",
        freshness_bindings=(
            f"content-digest:{digest}",
            f"tool-call:{invocation.call_id}",
        ),
    )


def _validated_result_output(
    result: ToolInvocationResult,
) -> Mapping[str, AgentJsonValue]:
    output = result.output
    if result.status is not ToolResultStatus.SUCCEEDED or output is None:
        raise IntegratedAgentValidationError("integrated result is not a successful output")
    return cast(Mapping[str, AgentJsonValue], output)


def _required_mapping(
    value: AgentJsonValue | None,
    *,
    label: str,
) -> Mapping[str, AgentJsonValue]:
    if not isinstance(value, Mapping):
        raise IntegratedAgentValidationError(f"{label} must be an object")
    return value


def _required_sequence(
    value: AgentJsonValue | None,
    *,
    label: str,
) -> Sequence[AgentJsonValue]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise IntegratedAgentValidationError(f"{label} must be an array")
    return cast(Sequence[AgentJsonValue], value)


def _required_bool(value: AgentJsonValue | None, *, label: str) -> bool:
    if not isinstance(value, bool):
        raise IntegratedAgentValidationError(f"{label} must be a boolean")
    return value


def _required_positive_int(value: object, *, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise IntegratedAgentValidationError(f"{label} must be a positive integer")
    return value


def _required_uuid_text(value: object, *, label: str) -> str:
    if not isinstance(value, str):
        raise IntegratedAgentValidationError(f"{label} must be a canonical UUID")
    try:
        parsed = UUID(value)
    except ValueError:
        raise IntegratedAgentValidationError(f"{label} must be a canonical UUID") from None
    if str(parsed) != value:
        raise IntegratedAgentValidationError(f"{label} must be a canonical UUID")
    return value


def _required_digest(value: AgentJsonValue | None, *, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 71
        or not value.startswith("sha256:")
        or any(character not in "0123456789abcdef" for character in value[7:])
    ):
        raise IntegratedAgentValidationError(f"{label} must be a canonical SHA-256 digest")
    return value


def _exact_child_resource(base: str, kind: str, identifier: str) -> str:
    marker = f"/{kind}:"
    child = f"{marker}{identifier}"
    if marker not in base:
        return f"{base}{child}"
    if base.endswith(child):
        return base
    raise IntegratedAgentValidationError("downstream result identity changed")
