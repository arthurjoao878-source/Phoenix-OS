"""Runtime-owned execution, cancellation, and draining for delegated child agents."""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Protocol, runtime_checkable

from phoenix_os.agent.configuration import AgentServiceConfiguration
from phoenix_os.agent.contracts import (
    MAX_AGENT_CANCELLATION_GRACE,
    MAX_AGENT_MESSAGE_CHARS,
    MAX_AGENT_SHUTDOWN_GRACE,
    AgentId,
    AgentLimits,
    AgentMessage,
    AgentMessageRole,
    AgentRunId,
    AgentRunRequest,
    AgentRunResult,
    canonical_agent_json_bytes,
    freeze_agent_json_object,
)
from phoenix_os.agent.coordination import AgentDelegationCoordinator, DelegatedChildRun
from phoenix_os.agent.coordination_contracts import (
    CoordinationNamespace,
    DelegationBudget,
    DelegationId,
    DelegationLimits,
    DelegationRequest,
)
from phoenix_os.agent.coordination_observer import (
    AgentCoordinationObserver,
    CoordinationObservation,
    CoordinationOperation,
    CoordinationOperationOutcome,
    NullAgentCoordinationObserver,
)
from phoenix_os.agent.coordination_results import (
    ChildResultStatus,
    DelegatedChildResult,
    delegated_child_result_from_agent_result,
)
from phoenix_os.agent.errors import (
    AgentCancelledError,
    AgentLimitExceededError,
    AgentServiceUnavailableError,
)
from phoenix_os.agent.state import AgentCancellationToken
from phoenix_os.policy import SecurityContext
from phoenix_os.runtime import RuntimeContext


class AgentCoordinationRuntimeState(StrEnum):
    CREATED = "created"
    RUNNING = "running"
    STOPPING = "stopping"
    STOPPED = "stopped"


@dataclass(frozen=True, slots=True)
class AgentCoordinationConfiguration:
    """Explicit opt-in configuration for runtime-owned agent coordination."""

    namespace: CoordinationNamespace
    limits: DelegationLimits
    root_budget_limit: DelegationBudget
    shutdown_grace: timedelta = timedelta(seconds=30)
    cancellation_grace: timedelta = timedelta(seconds=10)
    source: str = "phoenix.agent.coordination"

    def __post_init__(self) -> None:
        if not isinstance(self.namespace, CoordinationNamespace):
            raise TypeError("namespace must be CoordinationNamespace")
        if not isinstance(self.limits, DelegationLimits):
            raise TypeError("limits must be DelegationLimits")
        if not isinstance(self.root_budget_limit, DelegationBudget):
            raise TypeError("root_budget_limit must be DelegationBudget")
        _require_positive_duration(
            self.shutdown_grace,
            label="shutdown_grace",
            maximum=MAX_AGENT_SHUTDOWN_GRACE,
        )
        _require_positive_duration(
            self.cancellation_grace,
            label="cancellation_grace",
            maximum=MAX_AGENT_CANCELLATION_GRACE,
        )
        normalized_source = self.source.strip()
        if not normalized_source:
            raise ValueError("source must not be blank")
        object.__setattr__(self, "source", normalized_source)


@dataclass(frozen=True, slots=True)
class AgentCoordinationRuntimeSnapshot:
    state: AgentCoordinationRuntimeState
    active_children: int
    forced_cancellations: int

    def __post_init__(self) -> None:
        if not isinstance(self.state, AgentCoordinationRuntimeState):
            raise TypeError("state must be AgentCoordinationRuntimeState")
        for label, value in (
            ("active_children", self.active_children),
            ("forced_cancellations", self.forced_cancellations),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"{label} must be a non-negative integer")

    @property
    def accepting(self) -> bool:
        return self.state is AgentCoordinationRuntimeState.RUNNING


@runtime_checkable
class DelegatedAgentService(Protocol):
    @property
    def configuration(self) -> AgentServiceConfiguration: ...

    async def run(
        self,
        request: AgentRunRequest,
        context: SecurityContext,
        *,
        cancellation: AgentCancellationToken | None = None,
    ) -> AgentRunResult: ...


@dataclass(frozen=True, slots=True)
class _ActiveChild:
    task: asyncio.Task[object]
    token: AgentCancellationToken
    parent_run_id: AgentRunId


class AgentCoordinationRuntime:
    """Own child execution tasks while child services retain their own run authority."""

    def __init__(
        self,
        coordinator: AgentDelegationCoordinator,
        configuration: AgentCoordinationConfiguration,
        child_services: Mapping[AgentId, DelegatedAgentService],
        *,
        observer: AgentCoordinationObserver | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        if not isinstance(coordinator, AgentDelegationCoordinator):
            raise TypeError("coordinator must be AgentDelegationCoordinator")
        if not isinstance(configuration, AgentCoordinationConfiguration):
            raise TypeError("configuration must be AgentCoordinationConfiguration")
        resolved_observer = NullAgentCoordinationObserver() if observer is None else observer
        if not isinstance(resolved_observer, AgentCoordinationObserver):
            raise TypeError("observer must implement AgentCoordinationObserver")
        if not callable(clock):
            raise TypeError("clock must be callable")

        normalized_services: dict[AgentId, DelegatedAgentService] = {}
        for agent_id, service in child_services.items():
            if not isinstance(service, DelegatedAgentService):
                raise TypeError("child service must implement DelegatedAgentService")
            service_agent_id = service.configuration.agent_id
            if agent_id != service_agent_id:
                raise ValueError("child service key must match service configuration agent_id")
            if agent_id in normalized_services:
                raise ValueError("child services contain a duplicate agent_id")
            normalized_services[agent_id] = service

        self._coordinator = coordinator
        self._configuration = configuration
        self._child_services = normalized_services
        self._observer = resolved_observer
        self._clock = clock
        self._state = AgentCoordinationRuntimeState.CREATED
        self._active: dict[DelegationId, _ActiveChild] = {}
        self._forced_cancellations = 0
        self._lock = asyncio.Lock()

    @property
    def coordinator(self) -> AgentDelegationCoordinator:
        return self._coordinator

    @property
    def configuration(self) -> AgentCoordinationConfiguration:
        return self._configuration

    @property
    def state(self) -> AgentCoordinationRuntimeState:
        return self._state

    async def start(self, context: RuntimeContext) -> None:
        if not isinstance(context, RuntimeContext):
            raise TypeError("context must be RuntimeContext")
        async with self._lock:
            if self._state is AgentCoordinationRuntimeState.RUNNING:
                return
            if self._state is not AgentCoordinationRuntimeState.CREATED:
                raise AgentServiceUnavailableError()
            self._state = AgentCoordinationRuntimeState.RUNNING

    async def stop(self, context: RuntimeContext) -> None:
        if not isinstance(context, RuntimeContext):
            raise TypeError("context must be RuntimeContext")
        async with self._lock:
            if self._state is AgentCoordinationRuntimeState.STOPPED:
                return
            if self._state is AgentCoordinationRuntimeState.STOPPING:
                return
            self._state = AgentCoordinationRuntimeState.STOPPING
            active = tuple(self._active.values())

        for item in active:
            item.token.cancel()

        tasks = {item.task for item in active if not item.task.done()}
        if tasks:
            _done, pending = await asyncio.wait(
                tasks,
                timeout=self._configuration.shutdown_grace.total_seconds(),
            )
            if pending:
                async with self._lock:
                    self._forced_cancellations += len(pending)
                for task in pending:
                    task.cancel()
                _done, stubborn = await asyncio.wait(
                    pending,
                    timeout=self._configuration.cancellation_grace.total_seconds(),
                )
                for task in stubborn:
                    task.add_done_callback(_consume_task)

        async with self._lock:
            self._active.clear()
            self._state = AgentCoordinationRuntimeState.STOPPED

    async def snapshot(self) -> AgentCoordinationRuntimeSnapshot:
        async with self._lock:
            return AgentCoordinationRuntimeSnapshot(
                state=self._state,
                active_children=len(self._active),
                forced_cancellations=self._forced_cancellations,
            )

    async def delegate_and_run(
        self,
        request: DelegationRequest,
        context: SecurityContext,
        *,
        parent_cancellation: AgentCancellationToken | None = None,
    ) -> DelegatedChildResult:
        if not isinstance(request, DelegationRequest):
            raise TypeError("request must be DelegationRequest")
        if not isinstance(context, SecurityContext):
            raise TypeError("context must be SecurityContext")
        if parent_cancellation is not None and not isinstance(
            parent_cancellation,
            AgentCancellationToken,
        ):
            raise TypeError("parent_cancellation must be AgentCancellationToken or None")
        if parent_cancellation is not None:
            parent_cancellation.raise_if_cancelled()

        task = asyncio.current_task()
        if task is None:  # pragma: no cover - asyncio invariant
            raise RuntimeError("delegated child execution requires an asyncio task")
        token = AgentCancellationToken()
        owned = _ActiveChild(
            task=task,
            token=token,
            parent_run_id=request.parent_run_id,
        )

        async with self._lock:
            if self._state is not AgentCoordinationRuntimeState.RUNNING:
                raise AgentServiceUnavailableError()
            if request.delegation_id in self._active:
                raise AgentServiceUnavailableError()
            self._active[request.delegation_id] = owned

        forwarder: asyncio.Task[None] | None = None
        if parent_cancellation is not None:
            forwarder = asyncio.create_task(_forward_cancellation(parent_cancellation, token))

        admitted: DelegatedChildRun | None = None
        try:
            admitted = await self._coordinator.delegate(
                request,
                context,
                cancellation=token,
            )
            token.raise_if_cancelled()

            child_service = self._child_services.get(admitted.child_agent_id)
            if child_service is None:
                await self._coordinator.fail(admitted.delegation_id)
                raise AgentServiceUnavailableError()

            started = self._clock()
            await self._observe(
                request,
                admitted,
                context,
                operation=CoordinationOperation.CHILD_RUN,
                outcome=CoordinationOperationOutcome.STARTED,
            )
            token.raise_if_cancelled()
            child_request = _child_run_request(
                request,
                admitted,
                child_service,
                now=started,
            )
            await self._coordinator.start(admitted.delegation_id, now=started)
            run_result = await child_service.run(
                child_request,
                context,
                cancellation=token,
            )
            child_result = delegated_child_result_from_agent_result(
                admitted,
                run_result,
                limits=request.limits,
                max_result_bytes=request.budget.max_result_bytes,
            )
            now = self._clock()
            if child_result.status is ChildResultStatus.SUCCEEDED:
                await self._coordinator.complete(admitted.delegation_id, now=now)
                outcome = CoordinationOperationOutcome.SUCCEEDED
            elif child_result.status is ChildResultStatus.CANCELLED:
                await self._coordinator.cancel(admitted.delegation_id, now=now)
                outcome = CoordinationOperationOutcome.CANCELLED
            elif child_result.status is ChildResultStatus.TIMED_OUT:
                await self._coordinator.fail(admitted.delegation_id, now=now)
                outcome = CoordinationOperationOutcome.TIMED_OUT
            else:
                await self._coordinator.fail(admitted.delegation_id, now=now)
                outcome = CoordinationOperationOutcome.FAILED

            await self._observe(
                request,
                admitted,
                context,
                operation=CoordinationOperation.CHILD_RESULT,
                outcome=outcome,
                error_code=child_result.error_code,
            )
            return child_result
        except AgentCancelledError:
            token.cancel()
            if admitted is not None:
                await self._cancel_if_active(admitted.delegation_id)
                await self._observe(
                    request,
                    admitted,
                    context,
                    operation=CoordinationOperation.CANCELLATION,
                    outcome=CoordinationOperationOutcome.CANCELLED,
                    error_code="cancelled",
                )
            raise
        except asyncio.CancelledError:
            token.cancel()
            if admitted is not None:
                await self._cancel_if_active(admitted.delegation_id)
            raise
        except Exception:
            if admitted is not None:
                await self._fail_if_active(admitted.delegation_id)
                await self._observe(
                    request,
                    admitted,
                    context,
                    operation=CoordinationOperation.CHILD_RESULT,
                    outcome=CoordinationOperationOutcome.FAILED,
                    error_code="child_failed",
                )
            raise
        finally:
            if forwarder is not None:
                forwarder.cancel()
                await asyncio.gather(forwarder, return_exceptions=True)
            async with self._lock:
                self._active.pop(request.delegation_id, None)

    async def cancel_parent(self, parent_run_id: AgentRunId) -> int:
        if not isinstance(parent_run_id, AgentRunId):
            raise TypeError("parent_run_id must be AgentRunId")
        async with self._lock:
            matches = tuple(
                item for item in self._active.values() if item.parent_run_id == parent_run_id
            )
        for item in matches:
            item.token.cancel()
        return len(matches)

    async def _require_running(self) -> None:
        async with self._lock:
            if self._state is not AgentCoordinationRuntimeState.RUNNING:
                raise AgentServiceUnavailableError()

    async def _cancel_if_active(self, delegation_id: DelegationId) -> None:
        child = await self._coordinator.get(delegation_id)
        if not child.status.terminal:
            await self._coordinator.cancel(delegation_id)

    async def _fail_if_active(self, delegation_id: DelegationId) -> None:
        child = await self._coordinator.get(delegation_id)
        if not child.status.terminal:
            await self._coordinator.fail(delegation_id)

    async def _observe(
        self,
        request: DelegationRequest,
        child: DelegatedChildRun,
        context: SecurityContext,
        *,
        operation: CoordinationOperation,
        outcome: CoordinationOperationOutcome,
        error_code: str | None = None,
    ) -> None:
        try:
            await self._observer.record(
                CoordinationObservation(
                    operation=operation,
                    outcome=outcome,
                    namespace=request.namespace,
                    delegation_id=request.delegation_id,
                    parent_agent_id=request.parent_agent_id,
                    parent_run_id=request.parent_run_id,
                    child_agent_id=request.child_agent_id,
                    child_run_id=child.child_run_id,
                    error_code=error_code,
                ),
                context,
            )
        except Exception:
            pass


def _child_run_request(
    request: DelegationRequest,
    child: DelegatedChildRun,
    service: DelegatedAgentService,
    *,
    now: datetime,
) -> AgentRunRequest:
    frozen = freeze_agent_json_object(request.input)
    encoded = canonical_agent_json_bytes(frozen)
    effective_input_bytes = min(
        request.limits.max_input_bytes,
        request.budget.max_prompt_bytes,
    )
    if len(encoded) > effective_input_bytes:
        raise AgentLimitExceededError()
    content = encoded.decode("utf-8")
    if len(content) > MAX_AGENT_MESSAGE_CHARS:
        raise AgentLimitExceededError()

    configured = service.configuration.limits
    limits = _delegated_agent_limits(configured, request.budget)
    if request.deadline <= now:
        raise AgentCancelledError()
    return AgentRunRequest(
        agent_id=service.configuration.agent_id,
        provider_id=service.configuration.provider_id,
        model_id=service.configuration.model_id,
        messages=(AgentMessage(AgentMessageRole.USER, content),),
        limits=limits,
        metadata={
            "delegation_id": str(request.delegation_id),
            "parent_run_id": str(request.parent_run_id),
            "root_run_id": str(request.lineage.root_run_id),
        },
        run_id=child.child_run_id,
        created_at=now,
        deadline=request.deadline,
    )


def _delegated_agent_limits(
    configured: AgentLimits,
    budget: DelegationBudget,
) -> AgentLimits:
    if not isinstance(configured, AgentLimits):
        raise TypeError("configured must be AgentLimits")
    if not isinstance(budget, DelegationBudget):
        raise TypeError("budget must be DelegationBudget")

    total_duration = min(configured.total_duration, budget.duration)
    max_steps = min(
        configured.max_steps,
        budget.max_model_turns + budget.max_tool_calls,
    )
    return replace(
        configured,
        max_steps=max_steps,
        max_model_turns=min(configured.max_model_turns, budget.max_model_turns),
        max_tool_calls=min(configured.max_tool_calls, budget.max_tool_calls),
        max_prompt_bytes=min(configured.max_prompt_bytes, budget.max_prompt_bytes),
        max_model_output_bytes=min(
            configured.max_model_output_bytes,
            budget.max_result_bytes,
        ),
        max_tool_result_bytes=min(
            configured.max_tool_result_bytes,
            budget.max_result_bytes,
        ),
        max_input_tokens=min(configured.max_input_tokens, budget.max_input_tokens),
        max_output_tokens=min(configured.max_output_tokens, budget.max_output_tokens),
        max_argument_bytes=min(configured.max_argument_bytes, budget.max_prompt_bytes),
        max_result_bytes=min(configured.max_result_bytes, budget.max_result_bytes),
        model_turn_timeout=min(configured.model_turn_timeout, total_duration),
        tool_call_timeout=min(configured.tool_call_timeout, total_duration),
        approval_wait_timeout=min(configured.approval_wait_timeout, total_duration),
        total_duration=total_duration,
    )


async def _forward_cancellation(
    parent: AgentCancellationToken,
    child: AgentCancellationToken,
) -> None:
    await parent.wait()
    child.cancel()


def _require_positive_duration(
    value: timedelta,
    *,
    label: str,
    maximum: timedelta,
) -> None:
    if not isinstance(value, timedelta):
        raise TypeError(f"{label} must be a timedelta")
    if value <= timedelta(0):
        raise ValueError(f"{label} must be greater than zero")
    if value > maximum:
        raise ValueError(f"{label} exceeds the global maximum")


def _consume_task(task: asyncio.Task[object]) -> None:
    try:
        task.exception()
    except (asyncio.CancelledError, Exception):
        pass
