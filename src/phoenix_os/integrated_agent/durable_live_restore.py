"""Reviewed live-state restoration for durable integrated recovery."""

from __future__ import annotations

import asyncio
from typing import Self

from phoenix_os.agent.contracts import AgentRunRequest
from phoenix_os.integrated_agent.admission import (
    IntegratedAgentAdmission,
    IntegratedAgentAdmissionLease,
    IntegratedAgentRunBinding,
)
from phoenix_os.integrated_agent.contracts import (
    IntegratedBudgetUsage,
    IntegratedDataProvenance,
    IntegratedTaskRequest,
    NormalizedPlan,
)
from phoenix_os.integrated_agent.errors import IntegratedAgentConfigurationError
from phoenix_os.integrated_agent.execution_guard import IntegratedAgentExecutionGuard
from phoenix_os.integrated_agent.planning import IntegratedPlanner


class IntegratedDurableRecoveryLiveStateLease:
    """Own one restored admission/guard/planner live-state bundle."""

    def __init__(
        self,
        *,
        admission_lease: IntegratedAgentAdmissionLease,
        execution_guard: IntegratedAgentExecutionGuard,
        planner: IntegratedPlanner,
    ) -> None:
        if not isinstance(admission_lease, IntegratedAgentAdmissionLease):
            raise TypeError("admission_lease must be IntegratedAgentAdmissionLease")
        if not isinstance(execution_guard, IntegratedAgentExecutionGuard):
            raise TypeError("execution_guard must be IntegratedAgentExecutionGuard")
        if not isinstance(planner, IntegratedPlanner):
            raise TypeError("planner must be IntegratedPlanner")

        self._admission_lease = admission_lease
        self._execution_guard = execution_guard
        self._planner = planner
        self._released = False
        self._lock = asyncio.Lock()

    @property
    def request(self) -> AgentRunRequest:
        return self._admission_lease.request

    @property
    def binding(self) -> IntegratedAgentRunBinding:
        return self._admission_lease.binding

    @property
    def released(self) -> bool:
        return self._released

    async def release(self) -> None:
        async with self._lock:
            if self._released:
                return

            cleanup = asyncio.create_task(
                _release_live_state_components(
                    admission_lease=self._admission_lease,
                    execution_guard=self._execution_guard,
                    planner=self._planner,
                    release_guard=True,
                    release_planner=True,
                )
            )
            pending_cancellation: asyncio.CancelledError | None = None
            while not cleanup.done():
                try:
                    await asyncio.shield(cleanup)
                except asyncio.CancelledError as exception:
                    if pending_cancellation is None:
                        pending_cancellation = exception
                except BaseException:
                    break
            cleanup.result()
            self._released = True
            if pending_cancellation is not None:
                raise pending_cancellation

    async def __aenter__(self) -> Self:
        if self._released:
            raise RuntimeError("restored live-state lease is already released")
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: object,
    ) -> None:
        del exc_type, exc_value, traceback
        await self.release()


async def restore_integrated_durable_recovery_live_state(
    *,
    admission: IntegratedAgentAdmission,
    execution_guard: IntegratedAgentExecutionGuard,
    planner: IntegratedPlanner,
    task: IntegratedTaskRequest,
    request: AgentRunRequest,
    provenance: IntegratedDataProvenance,
    budget_usage: IntegratedBudgetUsage,
    plan: NormalizedPlan | None,
) -> IntegratedDurableRecoveryLiveStateLease:
    """Restore exact reviewed live state without durable mutation or execution."""

    if not isinstance(admission, IntegratedAgentAdmission):
        raise TypeError("admission must be IntegratedAgentAdmission")
    if not isinstance(execution_guard, IntegratedAgentExecutionGuard):
        raise TypeError("execution_guard must be IntegratedAgentExecutionGuard")
    if not isinstance(planner, IntegratedPlanner):
        raise TypeError("planner must be IntegratedPlanner")
    if not isinstance(task, IntegratedTaskRequest):
        raise TypeError("task must be IntegratedTaskRequest")
    if not isinstance(request, AgentRunRequest):
        raise TypeError("request must be AgentRunRequest")
    if not isinstance(provenance, IntegratedDataProvenance):
        raise TypeError("provenance must be IntegratedDataProvenance")
    if not isinstance(budget_usage, IntegratedBudgetUsage):
        raise TypeError("budget_usage must be IntegratedBudgetUsage")
    if plan is not None and not isinstance(plan, NormalizedPlan):
        raise TypeError("plan must be NormalizedPlan or None")

    profile = admission.profile
    if (
        execution_guard.profile is not profile
        or planner.profile is not profile
        or planner.provenance_provider is not execution_guard
    ):
        raise IntegratedAgentConfigurationError()

    admission_lease = await admission.restore_run(task, request)
    guard_restored = False
    planner_restored = False

    try:
        execution_guard.restore_run(
            task,
            admission_lease.request,
            provenance=provenance,
            budget_usage=budget_usage,
        )
        guard_restored = True

        planner.restore_run(admission_lease.binding, plan=plan)
        planner_restored = True

        return IntegratedDurableRecoveryLiveStateLease(
            admission_lease=admission_lease,
            execution_guard=execution_guard,
            planner=planner,
        )
    except BaseException as primary:
        cleanup = asyncio.create_task(
            _release_live_state_components(
                admission_lease=admission_lease,
                execution_guard=execution_guard,
                planner=planner,
                release_guard=guard_restored,
                release_planner=planner_restored,
            )
        )
        try:
            await asyncio.shield(cleanup)
        except BaseException:
            while not cleanup.done():
                try:
                    await asyncio.shield(cleanup)
                except BaseException:
                    continue
        try:
            cleanup.result()
        except BaseException as cleanup_error:
            raise primary from cleanup_error
        raise


async def _release_live_state_components(
    *,
    admission_lease: IntegratedAgentAdmissionLease,
    execution_guard: IntegratedAgentExecutionGuard,
    planner: IntegratedPlanner,
    release_guard: bool,
    release_planner: bool,
) -> None:
    run_id = admission_lease.binding.run_id
    failure: BaseException | None = None
    if release_planner:
        try:
            planner.release_run(run_id)
        except BaseException as exception:
            failure = exception
    if release_guard:
        try:
            execution_guard.release_run(run_id)
        except BaseException as exception:
            if failure is None:
                failure = exception
    try:
        await admission_lease.release()
    except BaseException as exception:
        if failure is None:
            failure = exception
    if failure is not None:
        raise failure
