"""Exact outer owner for one authorized same-lease durable task continuation."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime

from phoenix_os.agent.contracts import AgentRunRequest, AgentRunResult
from phoenix_os.agent.durable_contracts import DurableAgentRunId
from phoenix_os.agent.state import AgentCancellationToken
from phoenix_os.control_plane.task_resume_activation import (
    activate_prepared_same_lease_durable_task_resume,
)
from phoenix_os.control_plane.task_resume_preparation import (
    prepare_same_lease_durable_task_resume,
)
from phoenix_os.control_plane.task_runtime_bridge import TaskExecutionAuthority
from phoenix_os.control_plane.task_runtime_composition import (
    ServerOwnedDurableIntegratedTaskResumeSupport,
    ServerOwnedDurableIntegratedTaskRuntime,
)
from phoenix_os.integrated_agent.contracts import (
    IntegratedBudgetUsage,
    IntegratedDataProvenance,
    IntegratedTaskRequest,
    NormalizedPlan,
)


def _utc_now() -> datetime:
    return datetime.now(UTC)


async def execute_same_lease_durable_task_resume(
    *,
    owner: ServerOwnedDurableIntegratedTaskRuntime,
    support: ServerOwnedDurableIntegratedTaskResumeSupport,
    durable_run_id: DurableAgentRunId,
    authority: TaskExecutionAuthority,
    lease_owner_id: str,
    task: IntegratedTaskRequest,
    request: AgentRunRequest,
    provenance: IntegratedDataProvenance,
    budget_usage: IntegratedBudgetUsage,
    plan: NormalizedPlan | None,
    now: datetime,
    cancellation: AgentCancellationToken | None = None,
    clock: Callable[[], datetime] = _utc_now,
) -> AgentRunResult:
    """Prepare, activate, continue, then release one exact existing durable run."""

    if cancellation is not None and not isinstance(cancellation, AgentCancellationToken):
        raise TypeError("cancellation must be AgentCancellationToken or None")
    if not callable(clock):
        raise TypeError("clock must be callable")

    prepared = await prepare_same_lease_durable_task_resume(
        owner=owner,
        support=support,
        durable_run_id=durable_run_id,
        authority=authority,
        lease_owner_id=lease_owner_id,
        task=task,
        request=request,
        provenance=provenance,
        budget_usage=budget_usage,
        plan=plan,
        now=now,
        clock=clock,
    )
    try:
        activation = await activate_prepared_same_lease_durable_task_resume(
            owner=owner,
            support=support,
            prepared=prepared,
            authority=authority,
            now=clock(),
            clock=clock,
        )
        if (
            activation.prepared is not prepared
            or prepared.released
            or prepared.live_state.released
            or prepared.live_state.request != request
            or activation.checkpoint.metadata.budget != prepared.checkpoint.metadata.budget
        ):
            raise RuntimeError("same-lease durable resume activation continuity failed")

        if support.authority_freshness is None:
            result = await owner.coordinator.continue_same_lease(
                request,
                prepared.live_state.binding,
                authority.context,
                active_checkpoint=activation.checkpoint,
                lease=prepared.durable_lease,
                restored_budget=activation.checkpoint.metadata.budget,
                cancellation=cancellation,
            )
        else:
            result = await owner.coordinator.continue_same_lease(
                request,
                prepared.live_state.binding,
                authority.context,
                active_checkpoint=activation.checkpoint,
                lease=prepared.durable_lease,
                restored_budget=activation.checkpoint.metadata.budget,
                cancellation=cancellation,
                _authority_freshness=support.authority_freshness,
            )
    except BaseException as primary:
        try:
            await prepared.release(now=clock())
        except BaseException as cleanup_error:
            raise primary from cleanup_error
        raise
    else:
        await prepared.release(now=clock())
        return result

