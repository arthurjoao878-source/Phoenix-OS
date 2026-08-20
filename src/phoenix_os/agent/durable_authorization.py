"""Exact deny-by-default authorization for durable recovery operations."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from phoenix_os.agent.durable_contracts import (
    CheckpointEnvelope,
    CheckpointNextOperation,
    DurableAgentRunId,
    DurableLease,
    DurableRunStatus,
    ExecutionAttemptId,
    ExecutionAttemptKind,
    ExecutionAttemptStatus,
    ReconciliationRequest,
    ResumeRequest,
)
from phoenix_os.agent.errors import AgentAuthorizationRejectedError
from phoenix_os.policy import (
    PhoenixPolicyError,
    PolicyEngine,
    PolicyRequest,
    SecurityContext,
)

AGENT_RECONCILE_ACTION = "agent.reconcile"
AGENT_RESUME_ACTION = "agent.resume"

_TRUSTED_DURABLE_ACTOR_ATTRIBUTE = "durable_actor_id"
_ALLOWED_RESUME_STATUSES = frozenset(
    {
        DurableRunStatus.CREATED,
        DurableRunStatus.ACTIVE,
        DurableRunStatus.PAUSED_APPROVAL,
        DurableRunStatus.PAUSED_OPERATOR,
        DurableRunStatus.PAUSED_SHUTDOWN,
    }
)


def durable_agent_run_resource(run_id: DurableAgentRunId) -> str:
    """Return the exact policy resource for one durable agent run."""

    if not isinstance(run_id, DurableAgentRunId):
        raise TypeError("run_id must be DurableAgentRunId")
    return f"durable-agent-run:{run_id}"


def durable_reconciliation_resource(
    run_id: DurableAgentRunId,
    attempt_id: ExecutionAttemptId,
) -> str:
    """Return the exact policy resource for one durable execution attempt."""

    if not isinstance(run_id, DurableAgentRunId):
        raise TypeError("run_id must be DurableAgentRunId")
    if not isinstance(attempt_id, ExecutionAttemptId):
        raise TypeError("attempt_id must be ExecutionAttemptId")
    return f"{durable_agent_run_resource(run_id)}/attempt:{attempt_id}"


@runtime_checkable
class DurableResumeAuthorizer(Protocol):
    """Authorize orchestration for one exact durable resume request."""

    async def authorize(
        self,
        request: ResumeRequest,
        checkpoint: CheckpointEnvelope,
        lease: DurableLease,
        context: SecurityContext,
    ) -> None: ...


@runtime_checkable
class DurableReconciliationAuthorizer(Protocol):
    """Authorize one exact reconciliation request without applying it."""

    async def authorize(
        self,
        request: ReconciliationRequest,
        checkpoint: CheckpointEnvelope,
        lease: DurableLease,
        context: SecurityContext,
    ) -> None: ...


class PolicyEngineDurableResumeAuthorizer:
    """Apply exact ``agent.resume`` policy to current content-free state."""

    def __init__(self, policy: PolicyEngine) -> None:
        if not isinstance(policy, PolicyEngine):
            raise TypeError("policy must be PolicyEngine")
        self._policy = policy

    async def authorize(
        self,
        request: ResumeRequest,
        checkpoint: CheckpointEnvelope,
        lease: DurableLease,
        context: SecurityContext,
    ) -> None:
        if not isinstance(request, ResumeRequest):
            raise TypeError("request must be ResumeRequest")
        if not isinstance(checkpoint, CheckpointEnvelope):
            raise TypeError("checkpoint must be CheckpointEnvelope")
        if not isinstance(lease, DurableLease):
            raise TypeError("lease must be DurableLease")
        _require_authenticated_actor(context, actor_id=request.actor_id)
        _validate_resume_request(request, checkpoint, lease)

        try:
            await self._policy.enforce(
                PolicyRequest(
                    action=AGENT_RESUME_ACTION,
                    resource=durable_agent_run_resource(request.run_id),
                    context=context,
                    attributes=_resume_attributes(request, checkpoint),
                    created_at=request.requested_at,
                )
            )
        except PhoenixPolicyError as exception:
            raise AgentAuthorizationRejectedError() from exception


class PolicyEngineDurableReconciliationAuthorizer:
    """Apply exact ``agent.reconcile`` policy without mutating durable state."""

    def __init__(self, policy: PolicyEngine) -> None:
        if not isinstance(policy, PolicyEngine):
            raise TypeError("policy must be PolicyEngine")
        self._policy = policy

    async def authorize(
        self,
        request: ReconciliationRequest,
        checkpoint: CheckpointEnvelope,
        lease: DurableLease,
        context: SecurityContext,
    ) -> None:
        if not isinstance(request, ReconciliationRequest):
            raise TypeError("request must be ReconciliationRequest")
        if not isinstance(checkpoint, CheckpointEnvelope):
            raise TypeError("checkpoint must be CheckpointEnvelope")
        if not isinstance(lease, DurableLease):
            raise TypeError("lease must be DurableLease")
        _require_authenticated_actor(context, actor_id=request.actor_id)
        _validate_reconciliation_request(request, checkpoint, lease)

        try:
            await self._policy.enforce(
                PolicyRequest(
                    action=AGENT_RECONCILE_ACTION,
                    resource=durable_reconciliation_resource(
                        request.run_id,
                        request.attempt_id,
                    ),
                    context=context,
                    attributes=_reconciliation_attributes(request, checkpoint),
                    created_at=request.requested_at,
                )
            )
        except PhoenixPolicyError as exception:
            raise AgentAuthorizationRejectedError() from exception


def _require_authenticated_actor(
    context: SecurityContext,
    *,
    actor_id: str,
) -> None:
    if not isinstance(context, SecurityContext):
        raise TypeError("context must be SecurityContext")
    if not context.authenticated:
        raise AgentAuthorizationRejectedError()

    trusted_actor = context.attributes.get(
        _TRUSTED_DURABLE_ACTOR_ATTRIBUTE,
        context.principal,
    )
    if trusted_actor.strip().lower() != actor_id:
        raise AgentAuthorizationRejectedError()


def _validate_resume_request(
    request: ResumeRequest,
    checkpoint: CheckpointEnvelope,
    lease: DurableLease,
) -> None:
    if (
        request.run_id != checkpoint.durable_run_id
        or request.expected_version != checkpoint.run_version
        or lease.run_id != request.run_id
        or lease.generation != request.generation
        or not lease.active_at(request.requested_at)
        or checkpoint.status not in _ALLOWED_RESUME_STATUSES
        or checkpoint.status.terminal
        or checkpoint.status.indeterminate
        or request.requested_at < checkpoint.created_at
        or request.requested_at >= checkpoint.metadata.retention_deadline
        or request.requested_at >= checkpoint.metadata.budget.deadline
    ):
        raise AgentAuthorizationRejectedError()

    attempt = checkpoint.metadata.active_attempt
    if attempt is not None and attempt.status in {
        ExecutionAttemptStatus.STARTED,
        ExecutionAttemptStatus.INDETERMINATE,
    }:
        raise AgentAuthorizationRejectedError()


def _validate_reconciliation_request(
    request: ReconciliationRequest,
    checkpoint: CheckpointEnvelope,
    lease: DurableLease,
) -> None:
    attempt = checkpoint.metadata.active_attempt
    if (
        request.run_id != checkpoint.durable_run_id
        or request.expected_version != checkpoint.run_version
        or request.requested_at < checkpoint.created_at
        or request.requested_at >= checkpoint.metadata.retention_deadline
        or checkpoint.status
        not in {
            DurableRunStatus.INDETERMINATE_MODEL,
            DurableRunStatus.INDETERMINATE_TOOL,
        }
        or checkpoint.metadata.next_operation is not CheckpointNextOperation.OPERATOR_REVIEW
        or attempt is None
        or attempt.attempt_id != request.attempt_id
        or attempt.status is not ExecutionAttemptStatus.INDETERMINATE
        or lease.run_id != request.run_id
        or lease.generation != request.generation
        or not lease.active_at(request.requested_at)
    ):
        raise AgentAuthorizationRejectedError()

    expected_kind = (
        ExecutionAttemptKind.MODEL_TURN
        if checkpoint.status is DurableRunStatus.INDETERMINATE_MODEL
        else ExecutionAttemptKind.TOOL_INVOCATION
    )
    if attempt.kind is not expected_kind:
        raise AgentAuthorizationRejectedError()

    evidence = request.evidence
    if evidence is not None and evidence.observed_at > request.requested_at:
        raise AgentAuthorizationRejectedError()


def _attempt_attributes(checkpoint: CheckpointEnvelope) -> dict[str, str]:
    attempt = checkpoint.metadata.active_attempt
    if attempt is None:
        return {
            "attempt_kind": "none",
            "attempt_status": "none",
            "effect": "none",
        }
    return {
        "attempt_kind": attempt.kind.value,
        "attempt_status": attempt.status.value,
        "effect": attempt.tool_effect.value if attempt.tool_effect is not None else "none",
    }


def _resume_attributes(
    request: ResumeRequest,
    checkpoint: CheckpointEnvelope,
) -> dict[str, str]:
    attributes = {
        "agent_id": str(checkpoint.metadata.agent_id),
        "agent_run_id": str(checkpoint.agent_run_id),
        "actor_id": request.actor_id,
        "checkpoint_sequence": str(checkpoint.sequence.value),
        "current_status": checkpoint.status.value,
        "expected_version": str(request.expected_version.value),
        "fencing_generation": str(request.generation.value),
        "next_operation": checkpoint.metadata.next_operation.value,
        "payload_profile": checkpoint.metadata.payload_profile.value,
        "resume_reason": request.reason.value,
        "run_id": str(request.run_id),
    }
    attributes.update(_attempt_attributes(checkpoint))
    return attributes


def _reconciliation_attributes(
    request: ReconciliationRequest,
    checkpoint: CheckpointEnvelope,
) -> dict[str, str]:
    evidence = request.evidence
    attributes = {
        "actor_id": request.actor_id,
        "attempt_id": str(request.attempt_id),
        "checkpoint_sequence": str(checkpoint.sequence.value),
        "current_status": checkpoint.status.value,
        "decision": request.decision.value,
        "evidence_present": "true" if evidence is not None else "false",
        "evidence_type": evidence.evidence_type if evidence is not None else "none",
        "expected_version": str(request.expected_version.value),
        "fencing_generation": str(request.generation.value),
        "run_id": str(request.run_id),
    }
    attributes.update(_attempt_attributes(checkpoint))
    return attributes
