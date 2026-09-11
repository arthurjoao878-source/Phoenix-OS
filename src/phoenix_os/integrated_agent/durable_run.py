"""Live RFC-0036 durable run coordination over one caller-supplied root."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from typing import Protocol, runtime_checkable
from uuid import UUID

from phoenix_os.agent.authorization import AgentRunAuthorityBinding
from phoenix_os.agent.checkout_agent_tools import (
    CHECKOUT_READ_TOOL_ID,
    CHECKOUT_TOOL_ADAPTER_ID,
    CHECKOUT_TOOL_RESOLVER_ID,
    CheckoutToolAdapter,
)
from phoenix_os.agent.checkout_durable_evidence import (
    CheckoutReadCumulativeByteBudget,
    CheckoutReadDurableEvidenceHistoryValidator,
    CheckoutReadDurableResultMetadataProjectorFactory,
)
from phoenix_os.agent.contracts import (
    AgentRunId,
    AgentRunRequest,
    AgentRunResult,
    AgentRunStatus,
    ToolInvocationRequest,
    ToolInvocationResult,
)
from phoenix_os.agent.durable_cancellation import durable_cancellation_requested
from phoenix_os.agent.durable_codec import seal_checkpoint_envelope
from phoenix_os.agent.durable_compatibility import DurableCompatibilityPolicy
from phoenix_os.agent.durable_contracts import (
    MAX_METADATA_RETENTION,
    CheckpointDigest,
    CheckpointEnvelope,
    CheckpointId,
    CheckpointMetadata,
    CheckpointNextOperation,
    CheckpointPayloadProfile,
    CheckpointSchemaVersion,
    CheckpointSequence,
    DurableAgentRunId,
    DurableCancellationRequest,
    DurableLease,
    DurableRunLimits,
    DurableRunStatus,
    DurableRunVersion,
    ExecutionAttempt,
    ExecutionAttemptKind,
    ExecutionAttemptStatus,
)
from phoenix_os.agent.durable_live_model_turn import DurableAgentModelTurnExecutionDriver
from phoenix_os.agent.durable_metadata import (
    ChainedDurableCheckpointHistoryValidator,
    ChainedDurableCheckpointMetadataProjector,
    DurableCheckpointHistoryValidator,
    DurableCheckpointMetadataProjector,
    project_durable_checkpoint_metadata,
)
from phoenix_os.agent.durable_mutation import append_durable_checkpoint_confirmed
from phoenix_os.agent.durable_runtime import DurableAgentRuntimeStack
from phoenix_os.agent.durable_state import DurableCheckpointBoundary, DurableRunStateMachine
from phoenix_os.agent.errors import AgentStateConflictError
from phoenix_os.agent.execution import BoundedAgentExecutor
from phoenix_os.agent.loop import AgentModelTurnExecutionDriver, AgentToolExecutionDriver
from phoenix_os.agent.state import AgentBudgetSnapshot, AgentCancellationToken
from phoenix_os.agent.tools import ToolAdapter, ToolDescriptor, ToolFinalAdmissionValidator
from phoenix_os.authority import AuthorityFreshnessValidator
from phoenix_os.integrated_agent.admission import IntegratedAgentRunBinding
from phoenix_os.integrated_agent.contracts import IntegratedDataProvenance
from phoenix_os.integrated_agent.durable_recovery import (
    IntegratedDurableRecoveryHistoryValidator,
)
from phoenix_os.integrated_agent.durable_root import create_integrated_durable_root
from phoenix_os.integrated_agent.durable_transitions import (
    IntegratedDurableCheckpointMetadataProjector,
)
from phoenix_os.integrated_agent.errors import IntegratedAgentValidationError
from phoenix_os.integrated_agent.runtime import IntegratedAgentServiceDelegate
from phoenix_os.policy import SecurityContext


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _require_timezone_aware(value: datetime, *, label: str) -> None:
    if not isinstance(value, datetime):
        raise TypeError(f"{label} must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")


_INTEGRATED_PROJECTOR_ERROR = (
    "integrated durable coordination requires IntegratedDurableCheckpointMetadataProjector"
)


def _count_integrated_metadata_projectors(
    projector: DurableCheckpointMetadataProjector | None,
    *,
    seen: set[int] | None = None,
) -> int:
    if projector is None:
        return 0
    if isinstance(projector, IntegratedDurableCheckpointMetadataProjector):
        return 1
    if not isinstance(projector, ChainedDurableCheckpointMetadataProjector):
        return 0

    chain_id = id(projector)
    active = set() if seen is None else seen
    if chain_id in active:
        raise ValueError(_INTEGRATED_PROJECTOR_ERROR)
    active.add(chain_id)
    try:
        total = 0
        for item in projector.projectors:
            total += _count_integrated_metadata_projectors(item, seen=active)
            if total > 1:
                return total
        return total
    finally:
        active.remove(chain_id)


def _require_integrated_metadata_projector(
    projector: DurableCheckpointMetadataProjector | None,
) -> None:
    if _count_integrated_metadata_projectors(projector) != 1:
        raise ValueError(_INTEGRATED_PROJECTOR_ERROR)


_INTEGRATED_HISTORY_VALIDATOR_ERROR = (
    "integrated durable coordination requires integrated recovery before "
    "checkout-read durable history validation"
)


def _required_history_validator_order(
    validator: DurableCheckpointHistoryValidator | None,
    *,
    seen: set[int] | None = None,
) -> tuple[str, ...]:
    if validator is None:
        return ()
    if isinstance(validator, IntegratedDurableRecoveryHistoryValidator):
        return ("integrated",)
    if isinstance(validator, CheckoutReadDurableEvidenceHistoryValidator):
        return ("checkout",)
    if not isinstance(validator, ChainedDurableCheckpointHistoryValidator):
        return ()

    chain_id = id(validator)
    active = set() if seen is None else seen
    if chain_id in active:
        raise ValueError(_INTEGRATED_HISTORY_VALIDATOR_ERROR)
    active.add(chain_id)
    try:
        order: tuple[str, ...] = ()
        for item in validator.validators:
            order += _required_history_validator_order(item, seen=active)
            if len(order) > 2:
                return order
        return order
    finally:
        active.remove(chain_id)


def _require_integrated_checkout_history_validator(
    validator: DurableCheckpointHistoryValidator | None,
) -> None:
    if _required_history_validator_order(validator) != ("integrated", "checkout"):
        raise ValueError(_INTEGRATED_HISTORY_VALIDATOR_ERROR)


def _create_checkout_read_cumulative_byte_budget(
    binding: IntegratedAgentRunBinding,
) -> CheckoutReadCumulativeByteBudget:
    if not isinstance(binding, IntegratedAgentRunBinding):
        raise TypeError("binding must be IntegratedAgentRunBinding")
    return CheckoutReadCumulativeByteBudget(
        binding.run_id,
        max_bytes=binding.budget_extension.max_workspace_read_bytes,
    )


def _is_checkout_read_descriptor(descriptor: ToolDescriptor) -> bool:
    if not isinstance(descriptor, ToolDescriptor):
        raise TypeError("descriptor must be ToolDescriptor")
    return (
        descriptor.tool_id == CHECKOUT_READ_TOOL_ID
        and descriptor.resolver_id == CHECKOUT_TOOL_RESOLVER_ID
        and descriptor.adapter_id == CHECKOUT_TOOL_ADAPTER_ID
    )


class _CheckoutReadBudgetBoundToolExecutionDriver:
    """Bind one admitted per-run checkout read budget without mutating the shared registry."""

    def __init__(
        self,
        driver: AgentToolExecutionDriver,
        read_budget: CheckoutReadCumulativeByteBudget,
    ) -> None:
        if not isinstance(driver, AgentToolExecutionDriver):
            raise TypeError("driver must implement AgentToolExecutionDriver")
        if not isinstance(read_budget, CheckoutReadCumulativeByteBudget):
            raise TypeError("read_budget must be CheckoutReadCumulativeByteBudget")
        self._driver = driver
        self._read_budget = read_budget

    async def execute(
        self,
        executor: BoundedAgentExecutor,
        adapter: ToolAdapter,
        invocation: ToolInvocationRequest,
        descriptor: ToolDescriptor,
        context: SecurityContext,
        *,
        final_admission: ToolFinalAdmissionValidator | None,
        timeout_seconds: float,
        cancellation_grace: float,
        cancellation: AgentCancellationToken,
        prepare_time: datetime,
    ) -> ToolInvocationResult:
        selected_adapter = adapter
        if _is_checkout_read_descriptor(descriptor):
            if not isinstance(adapter, CheckoutToolAdapter):
                raise AgentStateConflictError()
            selected_adapter = adapter.bind_read_byte_limit_provider(self._read_budget)
        return await self._driver.execute(
            executor,
            selected_adapter,
            invocation,
            descriptor,
            context,
            final_admission=final_admission,
            timeout_seconds=timeout_seconds,
            cancellation_grace=cancellation_grace,
            cancellation=cancellation,
            prepare_time=prepare_time,
        )


def _create_checkout_read_durable_tool_execution_driver(
    durable_stack: DurableAgentRuntimeStack,
    *,
    lease: DurableLease,
    lease_renewal_interval: timedelta,
    read_budget: CheckoutReadCumulativeByteBudget,
    clock: Callable[[], datetime],
) -> AgentToolExecutionDriver:
    if not isinstance(read_budget, CheckoutReadCumulativeByteBudget):
        raise TypeError("read_budget must be CheckoutReadCumulativeByteBudget")
    driver = durable_stack.create_tool_execution_driver(
        lease=lease,
        lease_renewal_interval=lease_renewal_interval,
        pre_submit_validator=read_budget,
        result_metadata_projector_factory=CheckoutReadDurableResultMetadataProjectorFactory(),
        clock=clock,
    )
    return _CheckoutReadBudgetBoundToolExecutionDriver(driver, read_budget)


def integrated_durable_run_id(run_id: AgentRunId) -> DurableAgentRunId:
    """Derive the 1:1 durable correlation identity for one Phoenix agent run."""

    if not isinstance(run_id, AgentRunId):
        raise TypeError("run_id must be AgentRunId")
    return DurableAgentRunId(UUID(str(run_id)))


@runtime_checkable
class IntegratedDurableAgentServiceDelegate(IntegratedAgentServiceDelegate, Protocol):
    """AgentService-compatible surface that accepts caller-owned durable drivers."""

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
    ) -> AgentRunResult: ...


@runtime_checkable
class IntegratedDurableAgentContinuationServiceDelegate(
    IntegratedDurableAgentServiceDelegate,
    Protocol,
):
    """AgentService surface for one reviewed pre-model-turn continuation."""

    async def continue_model_turn(
        self,
        request: AgentRunRequest,
        context: SecurityContext,
        *,
        restored_budget: AgentBudgetSnapshot,
        cancellation: AgentCancellationToken | None = None,
        _authority_binding: AgentRunAuthorityBinding | None = None,
        _authority_freshness: AuthorityFreshnessValidator | None = None,
        _model_turn_execution_driver: AgentModelTurnExecutionDriver | None = None,
        _tool_execution_driver: AgentToolExecutionDriver | None = None,
    ) -> AgentRunResult: ...


@runtime_checkable
class IntegratedDurableRootProvider(Protocol):
    """Build one legitimate sealed RFC-0028 root without publishing it."""

    def build_root(
        self,
        request: AgentRunRequest,
        binding: IntegratedAgentRunBinding,
        provenance: IntegratedDataProvenance,
    ) -> CheckpointEnvelope: ...


class PolicyBackedIntegratedDurableRootProvider:
    """Build fresh metadata-only roots from one reviewed compatibility policy."""

    def __init__(
        self,
        *,
        policy: DurableCompatibilityPolicy,
        actor_id: str,
        retention: timedelta | None = None,
        clock: Callable[[], datetime] = _utc_now,
        durable_run_id_factory: Callable[[], DurableAgentRunId] | None = None,
        checkpoint_id_factory: Callable[[], CheckpointId] = CheckpointId,
    ) -> None:
        if not isinstance(policy, DurableCompatibilityPolicy):
            raise TypeError("policy must be DurableCompatibilityPolicy")
        if policy.payload_profile is not CheckpointPayloadProfile.METADATA_ONLY:
            raise ValueError("initial integrated durable roots require metadata-only compatibility")
        if not isinstance(actor_id, str):
            raise TypeError("actor_id must be a string")
        normalized_actor_id = actor_id.strip()
        if not normalized_actor_id:
            raise ValueError("actor_id must not be blank")

        selected_retention = (
            DurableRunLimits().max_total_lifetime if retention is None else retention
        )
        if not isinstance(selected_retention, timedelta):
            raise TypeError("retention must be timedelta or None")
        if selected_retention <= timedelta(0):
            raise ValueError("retention must be greater than zero")
        if selected_retention > MAX_METADATA_RETENTION:
            raise ValueError("retention exceeds metadata retention maximum")
        if not callable(clock):
            raise TypeError("clock must be callable")
        if durable_run_id_factory is not None and not callable(durable_run_id_factory):
            raise TypeError("durable_run_id_factory must be callable or None")
        if not callable(checkpoint_id_factory):
            raise TypeError("checkpoint_id_factory must be callable")

        self._policy = policy
        self._actor_id = normalized_actor_id
        self._retention = selected_retention
        self._clock = clock
        self._durable_run_id_factory = durable_run_id_factory
        self._checkpoint_id_factory = checkpoint_id_factory

    @property
    def policy(self) -> DurableCompatibilityPolicy:
        return self._policy

    def build_root(
        self,
        request: AgentRunRequest,
        binding: IntegratedAgentRunBinding,
        provenance: IntegratedDataProvenance,
    ) -> CheckpointEnvelope:
        if not isinstance(request, AgentRunRequest):
            raise TypeError("request must be AgentRunRequest")
        if not isinstance(binding, IntegratedAgentRunBinding):
            raise TypeError("binding must be IntegratedAgentRunBinding")
        if not isinstance(provenance, IntegratedDataProvenance):
            raise TypeError("provenance must be IntegratedDataProvenance")
        if (
            request.run_id != binding.run_id
            or request.agent_id != binding.agent_id
            or request.limits != binding.effective_limits
            or self._policy.agent_id != binding.agent_id
        ):
            raise IntegratedAgentValidationError(
                "durable root inputs do not match the admitted integrated binding"
            )

        now = self._clock()
        _require_timezone_aware(now, label="clock result")
        if now < request.created_at or now >= request.deadline:
            raise AgentStateConflictError()

        durable_run_id_factory = self._durable_run_id_factory
        durable_run_id = (
            integrated_durable_run_id(request.run_id)
            if durable_run_id_factory is None
            else durable_run_id_factory()
        )
        if not isinstance(durable_run_id, DurableAgentRunId):
            raise TypeError("durable_run_id_factory must return DurableAgentRunId")
        checkpoint_id = self._checkpoint_id_factory()
        if not isinstance(checkpoint_id, CheckpointId):
            raise TypeError("checkpoint_id_factory must return CheckpointId")

        try:
            root = CheckpointEnvelope(
                schema_version=CheckpointSchemaVersion(),
                durable_run_id=durable_run_id,
                checkpoint_id=checkpoint_id,
                sequence=CheckpointSequence(1),
                previous_digest=None,
                run_version=DurableRunVersion(1),
                status=DurableRunStatus.ACTIVE,
                agent_run_id=request.run_id,
                step_id=None,
                metadata=CheckpointMetadata(
                    agent_id=request.agent_id,
                    actor_id=self._actor_id,
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
                    compatibility=self._policy.current,
                    payload_profile=self._policy.payload_profile,
                    retention_deadline=now + self._retention,
                ),
                created_at=now,
                digest=CheckpointDigest("0" * 64),
            )
        except (OverflowError, TypeError, ValueError) as exception:
            raise AgentStateConflictError() from exception

        return seal_checkpoint_envelope(root)


@dataclass(frozen=True, slots=True)
class _IntegratedDurableLiveRunControl:
    lease: DurableLease
    cancellation: AgentCancellationToken

    def __post_init__(self) -> None:
        if not isinstance(self.lease, DurableLease):
            raise TypeError("lease must be DurableLease")
        if not isinstance(self.cancellation, AgentCancellationToken):
            raise TypeError("cancellation must be AgentCancellationToken")


class IntegratedDurableRunCoordinator:
    """Own one durable lease while an admitted integrated run executes."""

    def __init__(
        self,
        *,
        service: IntegratedDurableAgentServiceDelegate,
        durable_stack: DurableAgentRuntimeStack,
        root_provider: IntegratedDurableRootProvider,
        owner_id: str,
        lease_renewal_interval: timedelta = timedelta(seconds=10),
        clock: Callable[[], datetime] = _utc_now,
        checkpoint_id_factory: Callable[[], CheckpointId] = CheckpointId,
    ) -> None:
        if not isinstance(service, IntegratedDurableAgentServiceDelegate):
            raise TypeError("service must implement IntegratedDurableAgentServiceDelegate")
        if not isinstance(durable_stack, DurableAgentRuntimeStack):
            raise TypeError("durable_stack must be DurableAgentRuntimeStack")
        if not isinstance(root_provider, IntegratedDurableRootProvider):
            raise TypeError("root_provider must implement IntegratedDurableRootProvider")
        if not isinstance(owner_id, str):
            raise TypeError("owner_id must be a string")
        if not owner_id.strip():
            raise ValueError("owner_id must not be blank")
        if not isinstance(lease_renewal_interval, timedelta):
            raise TypeError("lease_renewal_interval must be timedelta")
        if lease_renewal_interval <= timedelta(0):
            raise ValueError("lease_renewal_interval must be greater than zero")
        if not callable(clock):
            raise TypeError("clock must be callable")
        if not callable(checkpoint_id_factory):
            raise TypeError("checkpoint_id_factory must be callable")
        _require_integrated_metadata_projector(durable_stack.metadata_projector)
        _require_integrated_checkout_history_validator(durable_stack.history_validator)

        self._service = service
        self._durable_stack = durable_stack
        self._root_provider = root_provider
        self._owner_id = owner_id
        self._lease_renewal_interval = lease_renewal_interval
        self._clock = clock
        self._checkpoint_id_factory = checkpoint_id_factory
        self._active_controls: dict[AgentRunId, _IntegratedDurableLiveRunControl] = {}
        self._control_lock = asyncio.Lock()

    @property
    def service(self) -> IntegratedDurableAgentServiceDelegate:
        return self._service

    async def execute(
        self,
        request: AgentRunRequest,
        binding: IntegratedAgentRunBinding,
        provenance: IntegratedDataProvenance | None,
        context: SecurityContext,
        *,
        cancellation: AgentCancellationToken | None = None,
        _authority_freshness: AuthorityFreshnessValidator | None = None,
    ) -> AgentRunResult:
        if not isinstance(request, AgentRunRequest):
            raise TypeError("request must be AgentRunRequest")
        if not isinstance(binding, IntegratedAgentRunBinding):
            raise TypeError("binding must be IntegratedAgentRunBinding")
        if provenance is None:
            raise IntegratedAgentValidationError(
                "durable integrated execution requires reviewed provenance"
            )
        if not isinstance(provenance, IntegratedDataProvenance):
            raise TypeError("provenance must be IntegratedDataProvenance or None")
        if not isinstance(context, SecurityContext):
            raise TypeError("context must be SecurityContext")
        if cancellation is not None and not isinstance(cancellation, AgentCancellationToken):
            raise TypeError("cancellation must be AgentCancellationToken or None")
        if _authority_freshness is not None and not isinstance(
            _authority_freshness,
            AuthorityFreshnessValidator,
        ):
            raise TypeError("_authority_freshness must implement AuthorityFreshnessValidator")
        token = cancellation or AgentCancellationToken()
        if (
            request.run_id != binding.run_id
            or request.agent_id != binding.agent_id
            or request.limits != binding.effective_limits
        ):
            raise IntegratedAgentValidationError(
                "agent request does not match the admitted integrated binding"
            )

        root = self._root_provider.build_root(request, binding, provenance)
        if not isinstance(root, CheckpointEnvelope):
            raise TypeError("root_provider must return CheckpointEnvelope")
        self._require_executable_root(root, request=request, binding=binding)

        now = self._now()
        if (
            now < root.created_at
            or now >= root.metadata.retention_deadline
            or now >= root.metadata.budget.deadline
            or now >= request.deadline
        ):
            raise AgentStateConflictError()

        created = await create_integrated_durable_root(
            self._durable_stack.store,
            root,
            binding,
            provenance=provenance,
        )
        lease = await self._durable_stack.lease_manager.acquire(
            created.durable_run_id,
            owner_id=self._owner_id,
            now=now,
        )

        registered = False
        try:
            await self._register_active_control(
                request.run_id,
                _IntegratedDurableLiveRunControl(
                    lease=lease,
                    cancellation=token,
                ),
            )
            registered = True
            model_driver = self._durable_stack.create_model_turn_execution_driver(
                lease=lease,
                lease_renewal_interval=self._lease_renewal_interval,
                clock=self._clock,
            )
            read_budget = _create_checkout_read_cumulative_byte_budget(binding)
            tool_driver = _create_checkout_read_durable_tool_execution_driver(
                self._durable_stack,
                lease=lease,
                lease_renewal_interval=self._lease_renewal_interval,
                read_budget=read_budget,
                clock=self._clock,
            )
            if _authority_freshness is None:
                result = await self._service.run(
                    request,
                    context,
                    cancellation=token,
                    _authority_binding=binding.authority,
                    _model_turn_execution_driver=model_driver,
                    _tool_execution_driver=tool_driver,
                )
            else:
                result = await self._service.run(
                    request,
                    context,
                    cancellation=token,
                    _authority_binding=binding.authority,
                    _authority_freshness=_authority_freshness,
                    _model_turn_execution_driver=model_driver,
                    _tool_execution_driver=tool_driver,
                )
            await self._finalize_result(
                result,
                lease=lease,
                model_driver=model_driver,
            )
        except BaseException:
            try:
                await self._release_owned_lease(lease)
            except (Exception, asyncio.CancelledError):
                pass
            raise
        finally:
            if registered:
                await self._remove_active_control(request.run_id, lease=lease)

        await self._release_owned_lease(lease)
        return result

    async def continue_same_lease(
        self,
        request: AgentRunRequest,
        binding: IntegratedAgentRunBinding,
        context: SecurityContext,
        *,
        active_checkpoint: CheckpointEnvelope,
        lease: DurableLease,
        restored_budget: AgentBudgetSnapshot,
        cancellation: AgentCancellationToken | None = None,
        _authority_freshness: AuthorityFreshnessValidator | None = None,
    ) -> AgentRunResult:
        """Continue one already-active durable run under a caller-owned lease."""

        if not isinstance(request, AgentRunRequest):
            raise TypeError("request must be AgentRunRequest")
        if not isinstance(binding, IntegratedAgentRunBinding):
            raise TypeError("binding must be IntegratedAgentRunBinding")
        if not isinstance(context, SecurityContext):
            raise TypeError("context must be SecurityContext")
        if not isinstance(active_checkpoint, CheckpointEnvelope):
            raise TypeError("active_checkpoint must be CheckpointEnvelope")
        if not isinstance(lease, DurableLease):
            raise TypeError("lease must be DurableLease")
        if not isinstance(restored_budget, AgentBudgetSnapshot):
            raise TypeError("restored_budget must be AgentBudgetSnapshot")
        if cancellation is not None and not isinstance(cancellation, AgentCancellationToken):
            raise TypeError("cancellation must be AgentCancellationToken or None")
        if _authority_freshness is not None and not isinstance(
            _authority_freshness,
            AuthorityFreshnessValidator,
        ):
            raise TypeError("_authority_freshness must implement AuthorityFreshnessValidator")
        if not isinstance(self._service, IntegratedDurableAgentContinuationServiceDelegate):
            raise AgentStateConflictError()
        if (
            request.run_id != binding.run_id
            or request.agent_id != binding.agent_id
            or request.limits != binding.effective_limits
        ):
            raise IntegratedAgentValidationError(
                "agent request does not match the admitted integrated binding"
            )

        now = self._now()
        authoritative_lease = await self._durable_stack.lease_manager.require_current(
            lease,
            now=now,
        )
        current = await self._durable_stack.store.get_current(authoritative_lease.run_id)
        if current is None or current != active_checkpoint:
            raise AgentStateConflictError()
        if (
            current.durable_run_id != authoritative_lease.run_id
            or current.durable_run_id != integrated_durable_run_id(request.run_id)
            or current.agent_run_id != request.run_id
            or current.agent_run_id != binding.run_id
            or current.metadata.agent_id != binding.agent_id
            or current.status is not DurableRunStatus.ACTIVE
            or current.metadata.next_operation is not CheckpointNextOperation.MODEL_TURN
            or current.metadata.active_attempt is not None
            or current.metadata.budget != restored_budget
            or restored_budget.started_at != request.created_at
            or restored_budget.deadline != request.deadline
            or now >= current.metadata.retention_deadline
            or now >= restored_budget.deadline
            or now >= request.deadline
        ):
            raise AgentStateConflictError()

        token = cancellation or AgentCancellationToken()
        registered = False
        try:
            await self._register_active_control(
                request.run_id,
                _IntegratedDurableLiveRunControl(
                    lease=authoritative_lease,
                    cancellation=token,
                ),
            )
            registered = True
            model_driver = self._durable_stack.create_model_turn_execution_driver(
                lease=authoritative_lease,
                lease_renewal_interval=self._lease_renewal_interval,
                clock=self._clock,
            )
            read_budget = _create_checkout_read_cumulative_byte_budget(binding)
            tool_driver = _create_checkout_read_durable_tool_execution_driver(
                self._durable_stack,
                lease=authoritative_lease,
                lease_renewal_interval=self._lease_renewal_interval,
                read_budget=read_budget,
                clock=self._clock,
            )
            service = self._service
            if not isinstance(service, IntegratedDurableAgentContinuationServiceDelegate):
                raise AgentStateConflictError()
            if _authority_freshness is None:
                result = await service.continue_model_turn(
                    request,
                    context,
                    restored_budget=restored_budget,
                    cancellation=token,
                    _authority_binding=binding.authority,
                    _model_turn_execution_driver=model_driver,
                    _tool_execution_driver=tool_driver,
                )
            else:
                result = await service.continue_model_turn(
                    request,
                    context,
                    restored_budget=restored_budget,
                    cancellation=token,
                    _authority_binding=binding.authority,
                    _authority_freshness=_authority_freshness,
                    _model_turn_execution_driver=model_driver,
                    _tool_execution_driver=tool_driver,
                )
            await self._finalize_result(
                result,
                lease=authoritative_lease,
                model_driver=model_driver,
            )
            return result
        finally:
            if registered:
                await self._remove_active_control(
                    request.run_id,
                    lease=authoritative_lease,
                )

    async def cancel_active(
        self,
        run_id: AgentRunId,
        context: SecurityContext,
        *,
        actor_id: str,
    ) -> CheckpointEnvelope:
        """Cancel one currently executing run under its coordinator-owned lease."""

        if not isinstance(run_id, AgentRunId):
            raise TypeError("run_id must be AgentRunId")
        if not isinstance(context, SecurityContext):
            raise TypeError("context must be SecurityContext")
        if not isinstance(actor_id, str):
            raise TypeError("actor_id must be a string")
        if not actor_id.strip() or actor_id != actor_id.strip():
            raise ValueError("actor_id must be a non-blank canonical string")

        async with self._control_lock:
            control = self._active_controls.get(run_id)
        if control is None:
            raise AgentStateConflictError()

        cancellation = self._durable_stack.cancellation
        if cancellation is None:
            raise AgentStateConflictError()

        now = self._now()
        lease = await self._durable_stack.lease_manager.require_current(
            control.lease,
            now=now,
        )
        current = await self._durable_stack.store.get_current(lease.run_id)
        if (
            current is None
            or current.agent_run_id != run_id
            or current.durable_run_id != integrated_durable_run_id(run_id)
            or current.durable_run_id != lease.run_id
        ):
            raise AgentStateConflictError()

        result = await cancellation.cancel(
            DurableCancellationRequest(
                run_id=current.durable_run_id,
                actor_id=actor_id,
                expected_version=current.run_version,
                generation=lease.generation,
                requested_at=now,
            ),
            lease=lease,
            context=context,
            now=now,
        )
        if (
            result.agent_run_id != run_id
            or result.durable_run_id != lease.run_id
            or not durable_cancellation_requested(result)
            or (result.status is not DurableRunStatus.CANCELLED and not result.status.indeterminate)
        ):
            raise AgentStateConflictError()

        control.cancellation.cancel()
        return result

    async def _register_active_control(
        self,
        run_id: AgentRunId,
        control: _IntegratedDurableLiveRunControl,
    ) -> None:
        async with self._control_lock:
            if run_id in self._active_controls:
                raise AgentStateConflictError()
            self._active_controls[run_id] = control

    async def _remove_active_control(
        self,
        run_id: AgentRunId,
        *,
        lease: DurableLease,
    ) -> None:
        async with self._control_lock:
            current = self._active_controls.get(run_id)
            if current is None:
                return
            if (
                current.lease.run_id != lease.run_id
                or current.lease.lease_id != lease.lease_id
                or current.lease.owner_id != lease.owner_id
                or current.lease.generation != lease.generation
            ):
                return
            del self._active_controls[run_id]

    def _require_executable_root(
        self,
        root: CheckpointEnvelope,
        *,
        request: AgentRunRequest,
        binding: IntegratedAgentRunBinding,
    ) -> None:
        if (
            root.status is not DurableRunStatus.ACTIVE
            or root.agent_run_id != request.run_id
            or root.agent_run_id != binding.run_id
            or root.metadata.agent_id != binding.agent_id
            or root.step_id is not None
            or root.metadata.next_operation is not CheckpointNextOperation.MODEL_TURN
            or root.metadata.active_attempt is not None
        ):
            raise IntegratedAgentValidationError(
                "durable root is not an executable unbound model-turn boundary"
            )

    async def _finalize_result(
        self,
        result: AgentRunResult,
        *,
        lease: DurableLease,
        model_driver: DurableAgentModelTurnExecutionDriver,
    ) -> CheckpointEnvelope:
        if not isinstance(result, AgentRunResult):
            raise TypeError("service must return AgentRunResult")

        if result.status is AgentRunStatus.COMPLETED:
            return await self._complete_from_model_result(
                result,
                lease=lease,
                model_driver=model_driver,
            )
        if result.status is AgentRunStatus.FAILED:
            return await self._terminalize_definitive_result(
                result,
                lease=lease,
                target=DurableRunStatus.FAILED,
            )
        if result.status is AgentRunStatus.CANCELLED:
            return await self._terminalize_definitive_result(
                result,
                lease=lease,
                target=DurableRunStatus.CANCELLED,
            )
        raise AgentStateConflictError()

    async def _complete_from_model_result(
        self,
        result: AgentRunResult,
        *,
        lease: DurableLease,
        model_driver: DurableAgentModelTurnExecutionDriver,
    ) -> CheckpointEnvelope:
        now = self._now()
        authoritative_lease = await self._durable_stack.lease_manager.require_current(
            lease,
            now=now,
        )
        current = await self._require_current_checkpoint(
            authoritative_lease,
            result=result,
        )

        if current.status is DurableRunStatus.COMPLETED:
            return current
        if current.status in {
            DurableRunStatus.PAUSED_OPERATOR,
            DurableRunStatus.INDETERMINATE_MODEL,
            DurableRunStatus.INDETERMINATE_TOOL,
        }:
            raise AgentStateConflictError()

        last_checkpoint = model_driver.last_checkpoint
        attempt = current.metadata.active_attempt
        if (
            current.status is not DurableRunStatus.ACTIVE
            or current.metadata.next_operation is not CheckpointNextOperation.COMPLETE
            or current.step_id is None
            or attempt is None
            or attempt.kind is not ExecutionAttemptKind.MODEL_TURN
            or attempt.status is not ExecutionAttemptStatus.SUCCEEDED
            or attempt.agent_run_id != current.agent_run_id
            or attempt.step_id != current.step_id
            or last_checkpoint != current
        ):
            raise AgentStateConflictError()

        machine = DurableRunStateMachine.from_checkpoint(current)
        boundary = DurableCheckpointBoundary(
            next_operation=CheckpointNextOperation.NONE,
        )
        machine.transition(
            DurableRunStatus.CHECKPOINTING,
            now=now,
            boundary=boundary,
        )
        checkpointing = await self._append_checkpoint(
            current,
            lease=authoritative_lease,
            status=DurableRunStatus.CHECKPOINTING,
            next_operation=CheckpointNextOperation.NONE,
            active_attempt=None,
            now=now,
        )

        completed_at = self._now()
        authoritative_lease = await self._durable_stack.lease_manager.require_current(
            authoritative_lease,
            now=completed_at,
        )
        machine.transition(
            DurableRunStatus.COMPLETED,
            now=completed_at,
        )
        return await self._append_checkpoint(
            checkpointing,
            lease=authoritative_lease,
            status=DurableRunStatus.COMPLETED,
            next_operation=CheckpointNextOperation.NONE,
            active_attempt=None,
            now=completed_at,
        )

    async def _terminalize_definitive_result(
        self,
        result: AgentRunResult,
        *,
        lease: DurableLease,
        target: DurableRunStatus,
    ) -> CheckpointEnvelope:
        if target not in {DurableRunStatus.FAILED, DurableRunStatus.CANCELLED}:
            raise ValueError("target must be a definitive durable terminal status")
        now = self._now()
        authoritative_lease = await self._durable_stack.lease_manager.require_current(
            lease,
            now=now,
        )
        current = await self._require_current_checkpoint(
            authoritative_lease,
            result=result,
        )

        if current.status in {
            DurableRunStatus.PAUSED_OPERATOR,
            DurableRunStatus.INDETERMINATE_MODEL,
            DurableRunStatus.INDETERMINATE_TOOL,
        }:
            return current
        if current.status.terminal:
            if current.status is not target:
                raise AgentStateConflictError()
            return current
        if current.status is not DurableRunStatus.ACTIVE:
            raise AgentStateConflictError()

        attempt = current.metadata.active_attempt
        if attempt is not None and not attempt.status.terminal:
            raise AgentStateConflictError()

        machine = DurableRunStateMachine.from_checkpoint(current)
        machine.transition(target, now=now)
        return await self._append_checkpoint(
            current,
            lease=authoritative_lease,
            status=target,
            next_operation=CheckpointNextOperation.NONE,
            active_attempt=None,
            now=now,
        )

    async def _require_current_checkpoint(
        self,
        lease: DurableLease,
        *,
        result: AgentRunResult,
    ) -> CheckpointEnvelope:
        current = await self._durable_stack.store.get_current(lease.run_id)
        if (
            current is None
            or current.durable_run_id != lease.run_id
            or current.agent_run_id != result.run_id
        ):
            raise AgentStateConflictError()
        return current

    async def _append_checkpoint(
        self,
        current: CheckpointEnvelope,
        *,
        lease: DurableLease,
        status: DurableRunStatus,
        next_operation: CheckpointNextOperation,
        active_attempt: ExecutionAttempt | None,
        now: datetime,
    ) -> CheckpointEnvelope:
        checkpoint_id = self._checkpoint_id_factory()
        if not isinstance(checkpoint_id, CheckpointId):
            raise TypeError("checkpoint_id_factory must return CheckpointId")

        metadata_values = project_durable_checkpoint_metadata(
            self._durable_stack.metadata_projector,
            current,
            checkpoint_id=checkpoint_id,
            status=status,
            step_id=current.step_id,
            next_operation=next_operation,
            active_attempt=active_attempt,
            metadata=current.metadata.metadata,
        )
        try:
            metadata = replace(
                current.metadata,
                next_operation=next_operation,
                active_attempt=active_attempt,
                metadata=metadata_values,
            )
            candidate = seal_checkpoint_envelope(
                replace(
                    current,
                    checkpoint_id=checkpoint_id,
                    sequence=current.sequence.next(),
                    previous_digest=current.digest,
                    run_version=current.run_version.next(),
                    status=status,
                    metadata=metadata,
                    created_at=now,
                    digest=CheckpointDigest("0" * 64),
                )
            )
        except (TypeError, ValueError, OverflowError) as exception:
            raise AgentStateConflictError() from exception

        return await append_durable_checkpoint_confirmed(
            self._durable_stack.store,
            current=current,
            intended=candidate,
            lease=lease,
            now=now,
        )

    async def _release_owned_lease(self, lease: DurableLease) -> None:
        now = self._now()
        current = await self._durable_stack.lease_manager.get_current(
            lease.run_id,
            now=now,
        )
        if current is None:
            return
        if (
            current.run_id != lease.run_id
            or current.lease_id != lease.lease_id
            or current.owner_id != lease.owner_id
            or current.generation != lease.generation
        ):
            return
        await self._durable_stack.lease_manager.release(
            current,
            now=now,
        )

    def _now(self) -> datetime:
        value = self._clock()
        _require_timezone_aware(value, label="clock result")
        return value
