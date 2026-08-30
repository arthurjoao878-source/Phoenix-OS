"""Fresh live authority/configuration/freshness revalidation for RFC-0036 recovery."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from typing import Protocol, runtime_checkable

from phoenix_os.agent.configuration import AgentServiceConfiguration
from phoenix_os.agent.contracts import AgentRunId, AgentRunRequest
from phoenix_os.agent.durable_contracts import (
    CheckpointEnvelope,
    CheckpointNextOperation,
)
from phoenix_os.agent.errors import AgentAuthorizationRejectedError
from phoenix_os.agent.loop import AgentLoop
from phoenix_os.integrated_agent.admission import IntegratedAgentRunBinding
from phoenix_os.integrated_agent.composition import IntegratedAgentToolComposition
from phoenix_os.integrated_agent.contracts import IntegratedDataProvenance
from phoenix_os.integrated_agent.errors import IntegratedAgentConfigurationError
from phoenix_os.policy import SecurityContext


@runtime_checkable
class IntegratedDurableRecoveryLiveRevalidator(Protocol):
    """Revalidate current live authority/lifecycle and recovered context freshness."""

    async def revalidate_run(
        self,
        checkpoint: CheckpointEnvelope,
        binding: IntegratedAgentRunBinding,
        request: AgentRunRequest,
        *,
        now: datetime,
    ) -> bool: ...

    async def revalidate_context(
        self,
        checkpoint: CheckpointEnvelope,
        provenance: IntegratedDataProvenance,
        *,
        now: datetime,
    ) -> bool: ...


class AgentLoopIntegratedDurableRecoveryLiveRevalidator:
    """Reuse AgentLoop authorization plus server-owned live recovery probes."""

    def __init__(
        self,
        *,
        loop: AgentLoop,
        configuration: AgentServiceConfiguration,
        context: SecurityContext,
        cancellation_probe: Callable[[AgentRunId], bool],
        context_freshness_probe: Callable[[IntegratedDataProvenance], bool],
        composition: IntegratedAgentToolComposition | None = None,
    ) -> None:
        if not isinstance(loop, AgentLoop):
            raise TypeError("loop must be AgentLoop")
        if not isinstance(configuration, AgentServiceConfiguration):
            raise TypeError("configuration must be AgentServiceConfiguration")
        if not isinstance(context, SecurityContext):
            raise TypeError("context must be SecurityContext")
        if not callable(cancellation_probe):
            raise TypeError("cancellation_probe must be callable")
        if not callable(context_freshness_probe):
            raise TypeError("context_freshness_probe must be callable")
        if composition is not None and not isinstance(
            composition,
            IntegratedAgentToolComposition,
        ):
            raise TypeError("composition must be IntegratedAgentToolComposition or None")
        if configuration.tool_ids and composition is None:
            raise ValueError("configured integrated tools require current composition")

        self._loop = loop
        self._configuration = configuration
        self._context = context
        self._cancellation_probe = cancellation_probe
        self._context_freshness_probe = context_freshness_probe
        self._composition = composition

    async def revalidate_run(
        self,
        checkpoint: CheckpointEnvelope,
        binding: IntegratedAgentRunBinding,
        request: AgentRunRequest,
        *,
        now: datetime,
    ) -> bool:
        if not isinstance(checkpoint, CheckpointEnvelope):
            raise TypeError("checkpoint must be CheckpointEnvelope")
        if not isinstance(binding, IntegratedAgentRunBinding):
            raise TypeError("binding must be IntegratedAgentRunBinding")
        if not isinstance(request, AgentRunRequest):
            raise TypeError("request must be AgentRunRequest")
        _require_timezone_aware(now)

        configuration = self._configuration
        if (
            checkpoint.agent_run_id != request.run_id
            or binding.run_id != request.run_id
            or checkpoint.metadata.agent_id != binding.agent_id
            or request.agent_id != binding.agent_id
            or request.agent_id != configuration.agent_id
            or request.provider_id != configuration.provider_id
            or request.model_id != configuration.model_id
            or request.limits != binding.effective_limits
            or checkpoint.metadata.budget.started_at != request.created_at
            or request.deadline > checkpoint.metadata.budget.deadline
            or now < request.created_at
            or now >= request.deadline
        ):
            return False

        if not _budget_within_current_limits(checkpoint, request):
            return False

        cancelled = self._cancellation_probe(request.run_id)
        if type(cancelled) is not bool:
            raise TypeError("cancellation_probe must return bool")
        if cancelled:
            return False

        try:
            if self._loop.registry.closed:
                return False
            composition = self._composition
            if composition is None:
                if configuration.tool_ids or self._loop.registry.list_states():
                    return False
            else:
                composition.require_service_configuration(configuration)
                composition.require_registry(self._loop.registry)
            await self._loop.revalidate_run_authority(
                request,
                self._context,
                binding.authority,
            )
        except (AgentAuthorizationRejectedError, IntegratedAgentConfigurationError):
            return False
        return True

    async def revalidate_context(
        self,
        checkpoint: CheckpointEnvelope,
        provenance: IntegratedDataProvenance,
        *,
        now: datetime,
    ) -> bool:
        if not isinstance(checkpoint, CheckpointEnvelope):
            raise TypeError("checkpoint must be CheckpointEnvelope")
        if not isinstance(provenance, IntegratedDataProvenance):
            raise TypeError("provenance must be IntegratedDataProvenance")
        _require_timezone_aware(now)
        current = self._context_freshness_probe(provenance)
        if type(current) is not bool:
            raise TypeError("context_freshness_probe must return bool")
        return current


def _budget_within_current_limits(
    checkpoint: CheckpointEnvelope,
    request: AgentRunRequest,
) -> bool:
    budget = checkpoint.metadata.budget
    limits = request.limits
    if not (
        budget.steps <= limits.max_steps
        and budget.model_turns <= limits.max_model_turns
        and budget.tool_calls <= limits.max_tool_calls
        and budget.model_output_bytes <= limits.max_model_output_bytes
        and budget.tool_result_bytes <= limits.max_tool_result_bytes
        and budget.input_tokens <= limits.max_input_tokens
        and budget.output_tokens <= limits.max_output_tokens
    ):
        return False

    next_operation = checkpoint.metadata.next_operation
    if next_operation is CheckpointNextOperation.MODEL_TURN:
        return (
            budget.steps < limits.max_steps
            and budget.model_turns < limits.max_model_turns
            and budget.model_output_bytes < limits.max_model_output_bytes
            and budget.input_tokens < limits.max_input_tokens
            and budget.output_tokens < limits.max_output_tokens
        )
    if next_operation is CheckpointNextOperation.TOOL_INVOCATION:
        return (
            budget.steps < limits.max_steps
            and budget.tool_calls < limits.max_tool_calls
            and budget.tool_result_bytes < limits.max_tool_result_bytes
        )
    return True


def _require_timezone_aware(value: datetime) -> None:
    if not isinstance(value, datetime):
        raise TypeError("now must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("now must be timezone-aware")
