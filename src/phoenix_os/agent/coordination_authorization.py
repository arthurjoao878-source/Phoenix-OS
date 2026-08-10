"""Exact deny-by-default authorization for one bounded agent delegation."""

from __future__ import annotations

import hashlib
from typing import Protocol, runtime_checkable

from phoenix_os.agent.contracts import (
    AgentId,
    canonical_agent_json_bytes,
    freeze_agent_json_object,
)
from phoenix_os.agent.coordination_contracts import (
    CoordinationNamespace,
    DelegationRequest,
    delegation_budget_fits_agent_limits,
)
from phoenix_os.agent.coordination_registry import DelegableAgentDescriptor
from phoenix_os.agent.errors import AgentAuthorizationRejectedError
from phoenix_os.policy import PhoenixPolicyError, PolicyEngine, PolicyRequest, SecurityContext

AGENT_DELEGATE_ACTION = "agent.delegate"
_DELEGATION_DIGEST_PREFIX = "sha256:"


def agent_delegation_resource(
    *,
    namespace: CoordinationNamespace,
    parent_agent_id: AgentId,
    child_agent_id: AgentId,
) -> str:
    """Return the exact content-free policy resource for one delegation edge."""

    if not isinstance(namespace, CoordinationNamespace):
        raise TypeError("namespace must be CoordinationNamespace")
    if not isinstance(parent_agent_id, AgentId):
        raise TypeError("parent_agent_id must be AgentId")
    if not isinstance(child_agent_id, AgentId):
        raise TypeError("child_agent_id must be AgentId")
    return f"agent-delegation:{namespace}/parent:{parent_agent_id}/child:{child_agent_id}"


def canonical_delegation_input_digest(request: DelegationRequest) -> str:
    """Return a stable content-free digest binding authorization to child input."""

    if not isinstance(request, DelegationRequest):
        raise TypeError("request must be DelegationRequest")
    encoded = canonical_agent_json_bytes(freeze_agent_json_object(request.input))
    return _DELEGATION_DIGEST_PREFIX + hashlib.sha256(encoded).hexdigest()


@runtime_checkable
class DelegationAuthorizer(Protocol):
    """Authorize one exact delegation without admitting or executing the child."""

    async def authorize(
        self,
        request: DelegationRequest,
        descriptor: DelegableAgentDescriptor,
        context: SecurityContext,
    ) -> None: ...


class PolicyEngineDelegationAuthorizer:
    """Apply exact ``agent.delegate`` policy to current trusted registry state."""

    def __init__(self, policy: PolicyEngine) -> None:
        if not isinstance(policy, PolicyEngine):
            raise TypeError("policy must be PolicyEngine")
        self._policy = policy

    async def authorize(
        self,
        request: DelegationRequest,
        descriptor: DelegableAgentDescriptor,
        context: SecurityContext,
    ) -> None:
        if not isinstance(request, DelegationRequest):
            raise TypeError("request must be DelegationRequest")
        if not isinstance(descriptor, DelegableAgentDescriptor):
            raise TypeError("descriptor must be DelegableAgentDescriptor")
        _require_authenticated_context(context)
        _validate_descriptor_binding(request, descriptor)

        try:
            await self._policy.enforce(
                PolicyRequest(
                    action=AGENT_DELEGATE_ACTION,
                    resource=agent_delegation_resource(
                        namespace=request.namespace,
                        parent_agent_id=request.parent_agent_id,
                        child_agent_id=request.child_agent_id,
                    ),
                    context=context,
                    attributes=_delegation_attributes(request, descriptor),
                    created_at=request.created_at,
                )
            )
        except PhoenixPolicyError as exception:
            raise AgentAuthorizationRejectedError() from exception


def _require_authenticated_context(context: SecurityContext) -> None:
    if not isinstance(context, SecurityContext):
        raise TypeError("context must be SecurityContext")
    if not context.authenticated:
        raise AgentAuthorizationRejectedError()


def _validate_descriptor_binding(
    request: DelegationRequest,
    descriptor: DelegableAgentDescriptor,
) -> None:
    child_limits = descriptor.configuration.limits
    if (
        descriptor.agent_id != request.child_agent_id
        or descriptor.namespace != request.namespace
        or not descriptor.allow_inbound
        or request.parent_agent_id not in descriptor.allowed_parent_agents
        or request.child_depth.value > descriptor.max_accepted_depth.value
        or (request.child_depth.value > 1 and not descriptor.allow_nested_delegation)
        or not descriptor.delegation_limits.contains(request.limits)
        or not delegation_budget_fits_agent_limits(
            request.budget,
            max_model_turns=child_limits.max_model_turns,
            max_tool_calls=child_limits.max_tool_calls,
            max_input_tokens=child_limits.max_input_tokens,
            max_output_tokens=child_limits.max_output_tokens,
            max_prompt_bytes=child_limits.max_prompt_bytes,
            max_result_bytes=child_limits.max_result_bytes,
            total_duration=child_limits.total_duration,
        )
    ):
        raise AgentAuthorizationRejectedError()


def _delegation_attributes(
    request: DelegationRequest,
    descriptor: DelegableAgentDescriptor,
) -> dict[str, str]:
    return {
        "compatibility_digest": descriptor.compatibility_digest,
        "coordination_namespace": str(request.namespace),
        "delegation_depth": str(request.child_depth.value),
        "delegation_id": str(request.delegation_id),
        "input_digest": canonical_delegation_input_digest(request),
        "parent_agent_id": str(request.parent_agent_id),
        "parent_run_id": str(request.parent_run_id),
        "root_run_id": str(request.lineage.root_run_id),
        "child_agent_id": str(request.child_agent_id),
        "budget_model_turns": str(request.budget.max_model_turns),
        "budget_tool_calls": str(request.budget.max_tool_calls),
        "budget_input_tokens": str(request.budget.max_input_tokens),
        "budget_output_tokens": str(request.budget.max_output_tokens),
        "budget_prompt_bytes": str(request.budget.max_prompt_bytes),
        "budget_result_bytes": str(request.budget.max_result_bytes),
    }
