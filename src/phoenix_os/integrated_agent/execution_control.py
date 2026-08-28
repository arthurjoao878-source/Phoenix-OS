"""Integrated budget, deadline, cancellation, failure, and effect controls for RFC-0036 S5."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace
from datetime import datetime
from threading import RLock

from phoenix_os.agent.contracts import (
    AgentJsonValue,
    ToolCallId,
    ToolEffect,
    ToolInvocationResult,
    ToolResultStatus,
)
from phoenix_os.agent.errors import (
    AgentApprovalRejectedError,
    AgentAuthorizationRejectedError,
    AgentCancelledError,
    AgentLimitExceededError,
    AgentServiceUnavailableError,
    AgentTimeoutError,
    ToolExecutionError,
)
from phoenix_os.agent.state import AgentCancellationToken
from phoenix_os.agent.tools import ToolDescriptor
from phoenix_os.integrated_agent.contracts import (
    IntegratedBudgetExtension,
    IntegratedBudgetUsage,
    IntegratedEffectDisposition,
    IntegratedFailureClass,
)
from phoenix_os.integrated_agent.errors import (
    IntegratedAgentBudgetExhaustedError,
    IntegratedAgentCancelledError,
    IntegratedAgentDataFlowDeniedError,
    IntegratedAgentDeadlineExceededError,
    IntegratedAgentError,
    IntegratedAgentIndeterminateEffectError,
    IntegratedAgentProvenanceOverflowError,
    IntegratedAgentStaleError,
    IntegratedAgentValidationError,
)
from phoenix_os.integrated_agent.profiles import (
    INTEGRATED_PLAN_UPDATE_TOOL_ID,
    IntegratedDownstreamBoundary,
    IntegratedDownstreamBridgeBinding,
    IntegratedLocalTransformBinding,
    IntegratedToolBinding,
)


def _require_aware(value: datetime, *, label: str) -> None:
    if not isinstance(value, datetime):
        raise TypeError(f"{label} must be datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")


class IntegratedRunBudget:
    """Own only RFC-0036 cross-subsystem counters and the stricter integrated deadline."""

    def __init__(
        self,
        extension: IntegratedBudgetExtension,
        *,
        started_at: datetime,
        parent_deadline: datetime,
    ) -> None:
        if not isinstance(extension, IntegratedBudgetExtension):
            raise TypeError("extension must be IntegratedBudgetExtension")
        _require_aware(started_at, label="started_at")
        _require_aware(parent_deadline, label="parent_deadline")
        if parent_deadline <= started_at:
            raise ValueError("parent_deadline must follow started_at")
        self._extension = extension
        self._started_at = started_at
        self._deadline = min(
            parent_deadline,
            started_at + extension.total_duration,
        )
        self._usage = IntegratedBudgetUsage()
        self._accounted_calls: set[ToolCallId] = set()
        self._accounted_workspace_mutations: set[ToolCallId] = set()
        self._lock = RLock()

    @property
    def extension(self) -> IntegratedBudgetExtension:
        return self._extension

    @property
    def started_at(self) -> datetime:
        return self._started_at

    @property
    def deadline(self) -> datetime:
        return self._deadline

    @property
    def usage(self) -> IntegratedBudgetUsage:
        with self._lock:
            return self._usage

    def remaining_seconds(self, *, now: datetime) -> float:
        self.require_active(now=now)
        return (self._deadline - now).total_seconds()

    def require_active(
        self,
        *,
        now: datetime,
        cancellation: AgentCancellationToken | None = None,
    ) -> None:
        _require_aware(now, label="now")
        if now < self._started_at:
            raise ValueError("now cannot precede started_at")
        if cancellation is not None:
            if not isinstance(cancellation, AgentCancellationToken):
                raise TypeError("cancellation must be AgentCancellationToken or None")
            if cancellation.cancelled:
                raise IntegratedAgentCancelledError()
        if now >= self._deadline:
            raise IntegratedAgentDeadlineExceededError()

    def require_step(
        self,
        binding: IntegratedToolBinding,
        arguments: Mapping[str, AgentJsonValue],
        *,
        now: datetime,
        cancellation: AgentCancellationToken | None = None,
        workspace_mutation_bytes: int = 0,
    ) -> IntegratedBudgetUsage:
        """Validate one prospective integrated step without consuming its counters."""

        self.require_active(now=now, cancellation=cancellation)
        with self._lock:
            prospective = self._prospective_usage(
                self._usage,
                binding,
                arguments,
                workspace_mutation_bytes=workspace_mutation_bytes,
            )
            self._require_within_extension(prospective)
            return prospective

    def consume_step(
        self,
        call_id: ToolCallId,
        binding: IntegratedToolBinding,
        arguments: Mapping[str, AgentJsonValue],
        *,
        now: datetime,
        cancellation: AgentCancellationToken | None = None,
        workspace_mutation_bytes: int = 0,
    ) -> IntegratedBudgetUsage:
        """Consume one exact attempt only after all earlier S5 admissions have succeeded."""

        if not isinstance(call_id, ToolCallId):
            raise TypeError("call_id must be ToolCallId")
        self.require_active(now=now, cancellation=cancellation)
        with self._lock:
            if call_id in self._accounted_calls:
                raise IntegratedAgentStaleError("integrated attempt budget was already consumed")
            prospective = self._prospective_usage(
                self._usage,
                binding,
                arguments,
                workspace_mutation_bytes=workspace_mutation_bytes,
            )
            self._require_within_extension(prospective)
            self._accounted_calls.add(call_id)
            self._usage = prospective
            return self._usage

    def consume_workspace_mutation(
        self,
        call_id: ToolCallId,
        mutation_bytes: int,
        *,
        now: datetime,
        cancellation: AgentCancellationToken | None = None,
    ) -> IntegratedBudgetUsage:
        """Consume exact authoritative workspace mutation bytes once per admitted attempt."""

        if not isinstance(call_id, ToolCallId):
            raise TypeError("call_id must be ToolCallId")
        if (
            isinstance(mutation_bytes, bool)
            or not isinstance(mutation_bytes, int)
            or mutation_bytes < 0
        ):
            raise ValueError("mutation_bytes must be a non-negative integer")
        self.require_active(now=now, cancellation=cancellation)
        with self._lock:
            if call_id not in self._accounted_calls:
                raise IntegratedAgentStaleError(
                    "workspace mutation budget requires an admitted integrated step"
                )
            if call_id in self._accounted_workspace_mutations:
                raise IntegratedAgentStaleError("workspace mutation budget was already consumed")
            prospective = replace(
                self._usage,
                workspace_mutation_bytes=(self._usage.workspace_mutation_bytes + mutation_bytes),
            )
            self._require_within_extension(prospective)
            self._accounted_workspace_mutations.add(call_id)
            self._usage = prospective
            return self._usage

    def _prospective_usage(
        self,
        current: IntegratedBudgetUsage,
        binding: IntegratedToolBinding,
        arguments: Mapping[str, AgentJsonValue],
        *,
        workspace_mutation_bytes: int,
    ) -> IntegratedBudgetUsage:
        if not isinstance(
            binding,
            (IntegratedLocalTransformBinding, IntegratedDownstreamBridgeBinding),
        ):
            raise TypeError("binding must be an IntegratedToolBinding")
        if not isinstance(arguments, Mapping):
            raise TypeError("arguments must be a mapping")
        if (
            isinstance(workspace_mutation_bytes, bool)
            or not isinstance(workspace_mutation_bytes, int)
            or workspace_mutation_bytes < 0
        ):
            raise ValueError("workspace_mutation_bytes must be a non-negative integer")

        updates: dict[str, int] = {
            "integrated_steps": current.integrated_steps + 1,
        }
        if isinstance(binding, IntegratedLocalTransformBinding):
            if workspace_mutation_bytes:
                raise ValueError("local transforms cannot consume workspace mutation bytes")
            if binding.tool_id == INTEGRATED_PLAN_UPDATE_TOOL_ID:
                updates["plan_revisions"] = current.plan_revisions + 1
            return replace(current, **updates)

        if (
            binding.boundary is not IntegratedDownstreamBoundary.WORKSPACE
            and workspace_mutation_bytes
        ):
            raise ValueError("workspace mutation bytes apply only to workspace bridges")

        counter = {
            IntegratedDownstreamBoundary.BROWSER: "browser_operations",
            IntegratedDownstreamBoundary.NETWORK: "network_operations",
            IntegratedDownstreamBoundary.MEMORY: "memory_operations",
            IntegratedDownstreamBoundary.WORKSPACE: "workspace_operations",
            IntegratedDownstreamBoundary.HOST: "host_operations",
        }[binding.boundary]
        updates[counter] = getattr(current, counter) + 1
        if binding.boundary is IntegratedDownstreamBoundary.WORKSPACE:
            updates["workspace_mutation_bytes"] = (
                current.workspace_mutation_bytes + workspace_mutation_bytes
            )
        return replace(current, **updates)

    def _require_within_extension(self, usage: IntegratedBudgetUsage) -> None:
        extension = self._extension
        if (
            usage.plan_revisions > extension.max_plan_revisions
            or usage.integrated_steps > extension.max_integrated_steps
            or usage.browser_operations > extension.max_browser_operations
            or usage.network_operations > extension.max_network_operations
            or usage.memory_operations > extension.max_memory_operations
            or usage.workspace_operations > extension.max_workspace_operations
            or usage.workspace_mutation_bytes > extension.max_workspace_mutation_bytes
            or usage.host_operations > extension.max_host_operations
        ):
            raise IntegratedAgentBudgetExhaustedError()


def integrated_effect_disposition(
    descriptor: ToolDescriptor,
    result: ToolInvocationResult,
) -> IntegratedEffectDisposition:
    """Normalize effect certainty without inventing knowledge absent from RFC-0027."""

    if not isinstance(descriptor, ToolDescriptor):
        raise TypeError("descriptor must be ToolDescriptor")
    if not isinstance(result, ToolInvocationResult):
        raise TypeError("result must be ToolInvocationResult")
    if result.tool_id != descriptor.tool_id:
        raise IntegratedAgentValidationError("tool result does not match its descriptor")
    if descriptor.effect is ToolEffect.READ_ONLY:
        return IntegratedEffectDisposition.NO_EFFECT
    if result.status is ToolResultStatus.SUCCEEDED:
        return IntegratedEffectDisposition.CONFIRMED_EFFECT
    if result.status is ToolResultStatus.FAILED:
        return IntegratedEffectDisposition.NO_EFFECT
    return IntegratedEffectDisposition.INDETERMINATE


class IntegratedEffectLedger:
    """Remember exact effect dispositions.

    Block automatic effectful progress after uncertainty.
    """

    def __init__(self) -> None:
        self._dispositions: dict[ToolCallId, IntegratedEffectDisposition] = {}
        self._indeterminate = False
        self._lock = RLock()

    @property
    def indeterminate(self) -> bool:
        with self._lock:
            return self._indeterminate

    def require_admission(self, descriptor: ToolDescriptor) -> None:
        if not isinstance(descriptor, ToolDescriptor):
            raise TypeError("descriptor must be ToolDescriptor")
        with self._lock:
            if descriptor.effect is not ToolEffect.READ_ONLY and self._indeterminate:
                raise IntegratedAgentIndeterminateEffectError()

    def record(
        self,
        descriptor: ToolDescriptor,
        result: ToolInvocationResult,
    ) -> IntegratedEffectDisposition:
        if not isinstance(descriptor, ToolDescriptor):
            raise TypeError("descriptor must be ToolDescriptor")
        if not isinstance(result, ToolInvocationResult):
            raise TypeError("result must be ToolInvocationResult")
        disposition = integrated_effect_disposition(descriptor, result)
        with self._lock:
            if result.call_id in self._dispositions:
                raise IntegratedAgentStaleError("integrated effect attempt was already recorded")
            self._dispositions[result.call_id] = disposition
            if (
                descriptor.effect is not ToolEffect.READ_ONLY
                and disposition is IntegratedEffectDisposition.INDETERMINATE
            ):
                self._indeterminate = True
        return disposition

    def disposition_for(self, call_id: ToolCallId) -> IntegratedEffectDisposition | None:
        if not isinstance(call_id, ToolCallId):
            raise TypeError("call_id must be ToolCallId")
        with self._lock:
            return self._dispositions.get(call_id)


def classify_integrated_failure(exception: BaseException) -> IntegratedFailureClass:
    """Map internal failures to the finite sanitized RFC-0036 failure vocabulary."""

    if not isinstance(exception, BaseException):
        raise TypeError("exception must be BaseException")
    if isinstance(exception, IntegratedAgentProvenanceOverflowError):
        return IntegratedFailureClass.PROVENANCE_OVERFLOW
    if isinstance(exception, IntegratedAgentDataFlowDeniedError):
        return IntegratedFailureClass.DATA_FLOW_DENIED
    if isinstance(exception, IntegratedAgentBudgetExhaustedError):
        return IntegratedFailureClass.BUDGET_EXHAUSTED
    if isinstance(exception, IntegratedAgentDeadlineExceededError):
        return IntegratedFailureClass.DEADLINE_EXCEEDED
    if isinstance(exception, (IntegratedAgentCancelledError, AgentCancelledError)):
        return IntegratedFailureClass.CANCELLED
    if isinstance(exception, IntegratedAgentIndeterminateEffectError):
        return IntegratedFailureClass.INDETERMINATE_EFFECT
    if isinstance(exception, IntegratedAgentStaleError):
        return IntegratedFailureClass.STALE_STATE
    if isinstance(exception, IntegratedAgentValidationError):
        return IntegratedFailureClass.VALIDATION_FAILED
    if isinstance(exception, AgentApprovalRejectedError):
        return IntegratedFailureClass.APPROVAL_REQUIRED
    if isinstance(exception, AgentAuthorizationRejectedError):
        return IntegratedFailureClass.AUTHORITY_DENIED
    if isinstance(exception, AgentLimitExceededError):
        return IntegratedFailureClass.BUDGET_EXHAUSTED
    if isinstance(exception, AgentTimeoutError):
        return IntegratedFailureClass.DEADLINE_EXCEEDED
    if isinstance(exception, AgentServiceUnavailableError):
        return IntegratedFailureClass.DEPENDENCY_UNAVAILABLE
    if isinstance(exception, ToolExecutionError):
        return IntegratedFailureClass.DEFINITIVE_OPERATION_FAILURE
    if isinstance(exception, IntegratedAgentError):
        return IntegratedFailureClass.INTERNAL_FAILURE
    return IntegratedFailureClass.INTERNAL_FAILURE
