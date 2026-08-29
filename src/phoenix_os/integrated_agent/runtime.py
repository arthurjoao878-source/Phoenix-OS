"""Integrated runtime lifecycle adapter for RFC-0036 S2."""

from __future__ import annotations

import asyncio
from time import monotonic_ns
from typing import Protocol, runtime_checkable

from phoenix_os.agent.authorization import AgentRunAuthorityBinding
from phoenix_os.agent.configuration import AgentServiceConfiguration
from phoenix_os.agent.contracts import AgentRunRequest, AgentRunResult, AgentRunStatus
from phoenix_os.agent.errors import AgentErrorCode
from phoenix_os.agent.loop import AgentLoop
from phoenix_os.agent.registry import ToolRegistry
from phoenix_os.agent.service import AgentServiceState
from phoenix_os.agent.state import AgentCancellationToken
from phoenix_os.integrated_agent.admission import IntegratedAgentAdmission
from phoenix_os.integrated_agent.composition import IntegratedAgentToolComposition
from phoenix_os.integrated_agent.contracts import (
    IntegratedFailureClass,
    IntegratedOrchestrationPhase,
    IntegratedTaskRequest,
    PlanRevision,
)
from phoenix_os.integrated_agent.errors import IntegratedAgentConfigurationError
from phoenix_os.integrated_agent.execution_control import classify_integrated_failure
from phoenix_os.integrated_agent.execution_guard import IntegratedAgentExecutionGuard
from phoenix_os.integrated_agent.observer import (
    MAX_INTEGRATED_OBSERVATION_DURATION_MS,
    IntegratedAgentObservation,
    IntegratedAgentObserver,
    NullIntegratedAgentObserver,
)
from phoenix_os.integrated_agent.planning import IntegratedPlanner
from phoenix_os.policy import SecurityContext
from phoenix_os.runtime import RuntimeContext

_MAX_INTEGRATED_OBSERVER_RECORD_SECONDS = 0.25
_MAX_INTEGRATED_OBSERVER_DRAIN_SECONDS = 0.30


def _duration_ms(started_ns: int) -> int:
    elapsed = max(0, (monotonic_ns() - started_ns) // 1_000_000)
    return min(elapsed, MAX_INTEGRATED_OBSERVATION_DURATION_MS)


def _result_failure_class(
    result: AgentRunResult,
    guard: IntegratedAgentExecutionGuard | None,
) -> IntegratedFailureClass | None:
    if result.status is AgentRunStatus.COMPLETED:
        return None
    if result.status is AgentRunStatus.CANCELLED:
        return IntegratedFailureClass.CANCELLED

    if guard is not None:
        failure = guard.failure_for(result.run_id)
        if failure is not None:
            return failure

    mapping = {
        AgentErrorCode.SCHEMA_INVALID.value: IntegratedFailureClass.VALIDATION_FAILED,
        AgentErrorCode.CODEC_INVALID.value: IntegratedFailureClass.VALIDATION_FAILED,
        AgentErrorCode.MALFORMED_PROPOSAL.value: IntegratedFailureClass.VALIDATION_FAILED,
        AgentErrorCode.AUTHORIZATION_REJECTED.value: IntegratedFailureClass.AUTHORITY_DENIED,
        AgentErrorCode.APPROVAL_REJECTED.value: IntegratedFailureClass.APPROVAL_REQUIRED,
        AgentErrorCode.LIMIT_EXCEEDED.value: IntegratedFailureClass.BUDGET_EXHAUSTED,
        AgentErrorCode.TIMEOUT.value: IntegratedFailureClass.DEADLINE_EXCEEDED,
        AgentErrorCode.CANCELLED.value: IntegratedFailureClass.CANCELLED,
        AgentErrorCode.SERVICE_UNAVAILABLE.value: IntegratedFailureClass.DEPENDENCY_UNAVAILABLE,
        AgentErrorCode.TOOL_FAILED.value: IntegratedFailureClass.DEFINITIVE_OPERATION_FAILURE,
        AgentErrorCode.STATE_CONFLICT.value: IntegratedFailureClass.STALE_STATE,
    }
    if result.error_code is None:
        return IntegratedFailureClass.INTERNAL_FAILURE
    return mapping.get(result.error_code, IntegratedFailureClass.INTERNAL_FAILURE)


@runtime_checkable
class IntegratedAgentServiceDelegate(Protocol):
    """Existing RFC-0027 AgentService surface reused by integrated execution."""

    @property
    def configuration(self) -> AgentServiceConfiguration: ...

    @property
    def state(self) -> AgentServiceState: ...

    async def start(self, context: RuntimeContext) -> None: ...

    async def stop(self, context: RuntimeContext) -> None: ...

    async def run(
        self,
        request: AgentRunRequest,
        context: SecurityContext,
        *,
        cancellation: AgentCancellationToken | None = None,
        _authority_binding: AgentRunAuthorityBinding | None = None,
    ) -> AgentRunResult: ...


class IntegratedAgentRuntime:
    """Bind integrated admission into the existing AgentService/AgentLoop lifecycle."""

    def __init__(
        self,
        service: IntegratedAgentServiceDelegate,
        admission: IntegratedAgentAdmission,
        *,
        planner: IntegratedPlanner | None = None,
        composition: IntegratedAgentToolComposition | None = None,
        execution_guard: IntegratedAgentExecutionGuard | None = None,
        observer: IntegratedAgentObserver | None = None,
    ) -> None:
        if not isinstance(service, IntegratedAgentServiceDelegate):
            raise TypeError("service must implement IntegratedAgentServiceDelegate")
        if not isinstance(admission, IntegratedAgentAdmission):
            raise TypeError("admission must be IntegratedAgentAdmission")
        if service.configuration != admission.service_configuration:
            raise IntegratedAgentConfigurationError()
        if planner is not None and not isinstance(planner, IntegratedPlanner):
            raise TypeError("planner must be IntegratedPlanner or None")
        if composition is not None and not isinstance(
            composition,
            IntegratedAgentToolComposition,
        ):
            raise TypeError("composition must be IntegratedAgentToolComposition or None")
        if execution_guard is not None and not isinstance(
            execution_guard,
            IntegratedAgentExecutionGuard,
        ):
            raise TypeError("execution_guard must be IntegratedAgentExecutionGuard or None")
        if observer is not None and not isinstance(observer, IntegratedAgentObserver):
            raise TypeError("observer must implement IntegratedAgentObserver or be None")
        if execution_guard is not None:
            if execution_guard.profile != admission.profile:
                raise IntegratedAgentConfigurationError()
            if planner is not None and planner.provenance_provider is not execution_guard:
                raise IntegratedAgentConfigurationError()
            service_runtime = getattr(service, "runtime", None)
            if (
                not isinstance(service_runtime, AgentLoop)
                or service_runtime.execution_interceptor is not execution_guard
                or service_runtime.memory_context_provider is not None
                or service_runtime.artifact_context_provider is not None
            ):
                raise IntegratedAgentConfigurationError()

        registry: ToolRegistry | None = None
        if service.configuration.tool_ids:
            if composition is None or composition.profile != admission.profile:
                raise IntegratedAgentConfigurationError()
            composition.require_service_configuration(service.configuration)
            candidate = getattr(service, "registry", None)
            if not isinstance(candidate, ToolRegistry):
                raise IntegratedAgentConfigurationError()
            composition.require_registry(candidate)
            service_runtime = getattr(service, "runtime", None)
            if service_runtime is not None and (
                not isinstance(service_runtime, AgentLoop)
                or service_runtime.registry is not candidate
            ):
                raise IntegratedAgentConfigurationError()
            registry = candidate
        elif composition is not None:
            raise IntegratedAgentConfigurationError()

        if planner is not None:
            if planner.profile != admission.profile:
                raise IntegratedAgentConfigurationError()
            configured_descriptor = next(
                (
                    descriptor
                    for descriptor in service.configuration.descriptors
                    if descriptor.tool_id == planner.descriptor.tool_id
                ),
                None,
            )
            if configured_descriptor != planner.descriptor:
                raise IntegratedAgentConfigurationError()
            if composition is None:
                raise IntegratedAgentConfigurationError()
            registration = composition.require_registration(planner.descriptor.tool_id)
            if (
                registration.descriptor != planner.descriptor
                or registration.resolver is not planner.resource_resolver
                or registration.adapter is not planner.adapter
            ):
                raise IntegratedAgentConfigurationError()

        self._service = service
        self._admission = admission
        self._planner = planner
        self._composition = composition
        self._execution_guard = execution_guard
        self._registry = registry
        self._observer = observer if observer is not None else NullIntegratedAgentObserver()
        self._observer_tasks: set[asyncio.Task[None]] = set()

    @property
    def service(self) -> IntegratedAgentServiceDelegate:
        return self._service

    @property
    def admission(self) -> IntegratedAgentAdmission:
        return self._admission

    @property
    def planner(self) -> IntegratedPlanner | None:
        return self._planner

    @property
    def composition(self) -> IntegratedAgentToolComposition | None:
        return self._composition

    @property
    def execution_guard(self) -> IntegratedAgentExecutionGuard | None:
        return self._execution_guard

    @property
    def state(self) -> AgentServiceState:
        return self._service.state

    @property
    def observer(self) -> IntegratedAgentObserver:
        return self._observer

    def _require_current_tool_surface(self) -> None:
        if self._composition is None:
            return
        assert self._registry is not None
        self._composition.require_registry(self._registry)

    async def start(self, context: RuntimeContext) -> None:
        if not isinstance(context, RuntimeContext):
            raise TypeError("context must be RuntimeContext")
        self._require_current_tool_surface()
        await self._service.start(context)

    async def stop(self, context: RuntimeContext) -> None:
        if not isinstance(context, RuntimeContext):
            raise TypeError("context must be RuntimeContext")
        try:
            if self._planner is not None:
                self._planner.close()
            if self._execution_guard is not None:
                self._execution_guard.close()
            await self._admission.close()
            await self._service.stop(context)
        finally:
            await self._drain_observers()

    async def run(
        self,
        task: IntegratedTaskRequest,
        request: AgentRunRequest,
        context: SecurityContext,
        *,
        cancellation: AgentCancellationToken | None = None,
    ) -> AgentRunResult:
        if not isinstance(task, IntegratedTaskRequest):
            raise TypeError("task must be IntegratedTaskRequest")
        if not isinstance(request, AgentRunRequest):
            raise TypeError("request must be AgentRunRequest")
        if not isinstance(context, SecurityContext):
            raise TypeError("context must be SecurityContext")
        if cancellation is not None and not isinstance(cancellation, AgentCancellationToken):
            raise TypeError("cancellation must be AgentCancellationToken")
        self._require_current_tool_surface()

        started_ns = monotonic_ns()
        lease = await self._admission.admit(task, request)
        self._record_run_observation(
            lease.binding,
            IntegratedOrchestrationPhase.CREATED,
            context,
        )
        planner_started = False
        guard_started = False
        try:
            if self._execution_guard is not None:
                self._execution_guard.begin_run(task, lease.request)
                guard_started = True
            if self._planner is not None:
                self._planner.begin_run(lease.binding)
                planner_started = True
                self._record_run_observation(
                    lease.binding,
                    IntegratedOrchestrationPhase.PLANNING,
                    context,
                )
            self._record_run_observation(
                lease.binding,
                IntegratedOrchestrationPhase.EXECUTING,
                context,
            )
            result = await self._service.run(
                lease.request,
                context,
                cancellation=cancellation,
                _authority_binding=lease.binding.authority,
            )
            self._record_run_observation(
                lease.binding,
                IntegratedOrchestrationPhase.TERMINAL,
                context,
                failure_class=_result_failure_class(result, self._execution_guard),
                duration_ms=_duration_ms(started_ns),
            )
            return result
        except asyncio.CancelledError:
            self._record_run_observation(
                lease.binding,
                IntegratedOrchestrationPhase.TERMINAL,
                context,
                failure_class=IntegratedFailureClass.CANCELLED,
                duration_ms=_duration_ms(started_ns),
            )
            raise
        except Exception as exception:
            self._record_run_observation(
                lease.binding,
                IntegratedOrchestrationPhase.TERMINAL,
                context,
                failure_class=classify_integrated_failure(exception),
                duration_ms=_duration_ms(started_ns),
            )
            raise
        finally:
            try:
                if planner_started and self._planner is not None:
                    self._planner.release_run(lease.binding.run_id)
            finally:
                try:
                    if guard_started and self._execution_guard is not None:
                        self._execution_guard.release_run(lease.binding.run_id)
                finally:
                    await lease.release()

    def _record_run_observation(
        self,
        binding: object,
        phase: IntegratedOrchestrationPhase,
        context: SecurityContext,
        *,
        failure_class: IntegratedFailureClass | None = None,
        duration_ms: int | None = None,
    ) -> None:
        from phoenix_os.integrated_agent.admission import IntegratedAgentRunBinding

        if not isinstance(binding, IntegratedAgentRunBinding):
            return
        try:
            plan_revision = None
            if self._planner is not None:
                current = self._planner.current_revision(binding.run_id)
                if current:
                    plan_revision = PlanRevision(current)
            budget_usage = None
            if self._execution_guard is not None:
                budget_usage = self._execution_guard.current_budget_usage(binding.run_id)
            observation = IntegratedAgentObservation(
                task_id=binding.task_id,
                run_id=binding.run_id,
                phase=phase,
                profile_id=binding.profile_id,
                profile_generation=binding.profile_generation,
                plan_revision=plan_revision,
                failure_class=failure_class,
                budget_usage=budget_usage,
                duration_ms=duration_ms,
            )
        except Exception:
            return
        self._record_observation(observation, context)

    def _record_observation(
        self,
        observation: IntegratedAgentObservation,
        context: SecurityContext,
    ) -> None:
        if isinstance(self._observer, NullIntegratedAgentObserver):
            return
        try:
            task = asyncio.create_task(self._observe(observation, context))
        except RuntimeError:
            return
        self._observer_tasks.add(task)
        task.add_done_callback(self._observer_task_done)

    async def _observe(
        self,
        observation: IntegratedAgentObservation,
        context: SecurityContext,
    ) -> None:
        worker = asyncio.create_task(self._observer.record(observation, context))
        try:
            done, _pending = await asyncio.wait(
                {worker},
                timeout=_MAX_INTEGRATED_OBSERVER_RECORD_SECONDS,
                return_when=asyncio.ALL_COMPLETED,
            )
        except asyncio.CancelledError:
            worker.cancel()
            worker.add_done_callback(self._consume_future)
            raise
        if worker not in done:
            worker.cancel()
            worker.add_done_callback(self._consume_future)
            return
        self._consume_future(worker)

    def _observer_task_done(self, task: asyncio.Task[None]) -> None:
        self._observer_tasks.discard(task)
        self._consume_future(task)

    @staticmethod
    def _consume_future(worker: asyncio.Future[None]) -> None:
        if worker.cancelled():
            return
        try:
            worker.result()
        except (Exception, asyncio.CancelledError):
            pass

    async def _drain_observers(self) -> None:
        tasks = tuple(self._observer_tasks)
        if not tasks:
            return
        _done, pending = await asyncio.wait(
            tasks,
            timeout=_MAX_INTEGRATED_OBSERVER_DRAIN_SECONDS,
            return_when=asyncio.ALL_COMPLETED,
        )
        for task in pending:
            task.cancel()
        if pending:
            await asyncio.wait(
                pending,
                timeout=0.05,
                return_when=asyncio.ALL_COMPLETED,
            )
        for task in tuple(self._observer_tasks):
            if task.done():
                self._observer_task_done(task)
