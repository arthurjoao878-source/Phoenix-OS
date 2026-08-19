"""Exact deny-by-default authority boundaries for agent orchestration."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from typing import Protocol, runtime_checkable

from phoenix_os.agent.contracts import (
    AgentId,
    AgentJsonInput,
    AgentRunRequest,
    ToolEffect,
    ToolInvocationRequest,
    canonical_agent_json_bytes,
    freeze_agent_json_object,
)
from phoenix_os.agent.errors import AgentAuthorizationRejectedError
from phoenix_os.agent.tools import ToolDescriptor
from phoenix_os.inference import InferenceAuthorizationRejectedError, InferenceRequest
from phoenix_os.policy import PhoenixPolicyError, PolicyEngine, PolicyRequest, SecurityContext

AGENT_RUN_ACTION = "agent.run"
TOOL_INVOKE_ACTION = "tool.invoke"
_ARGUMENT_DIGEST_PREFIX = "sha256:"


def agent_run_resource(agent_id: AgentId) -> str:
    """Return the exact policy resource for one configured agent."""

    if not isinstance(agent_id, AgentId):
        raise TypeError("agent_id must be AgentId")
    return f"agent:{agent_id}"


def tool_invocation_resource(request: ToolInvocationRequest) -> str:
    """Return the exact policy resource from one trusted resolved invocation."""

    if not isinstance(request, ToolInvocationRequest):
        raise TypeError("request must be ToolInvocationRequest")
    return f"tool:{request.tool_id}/{request.resolved_resource}"


def canonical_tool_argument_digest(arguments: Mapping[str, AgentJsonInput]) -> str:
    """Return a stable content-free digest over canonical validated arguments."""

    frozen = freeze_agent_json_object(arguments)
    encoded = canonical_agent_json_bytes(frozen)
    return _ARGUMENT_DIGEST_PREFIX + hashlib.sha256(encoded).hexdigest()


@runtime_checkable
class AgentRunAuthorizer(Protocol):
    """Authorize one exact configured agent run and nothing nested inside it."""

    async def authorize(self, request: AgentRunRequest, context: SecurityContext) -> None: ...


@runtime_checkable
class AgentModelTurnAuthorizer(Protocol):
    """Authorize one RFC-0026 inference request for one model turn."""

    async def authorize(self, request: InferenceRequest, context: SecurityContext) -> None: ...


@runtime_checkable
class ToolAuthorizer(Protocol):
    """Authorize one exact trusted tool invocation after resource resolution."""

    async def authorize(
        self,
        request: ToolInvocationRequest,
        descriptor: ToolDescriptor,
        context: SecurityContext,
    ) -> None: ...


class PolicyEngineAgentRunAuthorizer:
    """Apply exact ``agent.run`` policy without granting nested authority."""

    def __init__(self, policy: PolicyEngine) -> None:
        if not isinstance(policy, PolicyEngine):
            raise TypeError("policy must be PolicyEngine")
        self._policy = policy

    async def authorize(self, request: AgentRunRequest, context: SecurityContext) -> None:
        if not isinstance(request, AgentRunRequest):
            raise TypeError("request must be AgentRunRequest")
        _require_authenticated_context(context)
        try:
            await self._policy.enforce(
                PolicyRequest(
                    action=AGENT_RUN_ACTION,
                    resource=agent_run_resource(request.agent_id),
                    context=context,
                    attributes={
                        "agent_id": str(request.agent_id),
                        "run_id": str(request.run_id),
                        "provider_id": str(request.provider_id),
                        "model_id": str(request.model_id),
                    },
                )
            )
        except PhoenixPolicyError as exception:
            raise AgentAuthorizationRejectedError() from exception


class DelegatingAgentModelTurnAuthorizer:
    """Require a separate RFC-0026 authorization decision for every model turn."""

    def __init__(self, authorizer: AgentModelTurnAuthorizer) -> None:
        if not callable(getattr(authorizer, "authorize", None)):
            raise TypeError("authorizer must provide authorize")
        self._authorizer = authorizer

    async def authorize(self, request: InferenceRequest, context: SecurityContext) -> None:
        if not isinstance(request, InferenceRequest):
            raise TypeError("request must be InferenceRequest")
        _require_authenticated_context(context)
        try:
            await self._authorizer.authorize(request, context)
        except InferenceAuthorizationRejectedError as exception:
            raise AgentAuthorizationRejectedError() from exception


class PolicyEngineToolAuthorizer:
    """Apply exact ``tool.invoke`` policy to trusted descriptor and resolution data."""

    def __init__(self, policy: PolicyEngine) -> None:
        if not isinstance(policy, PolicyEngine):
            raise TypeError("policy must be PolicyEngine")
        self._policy = policy

    async def authorize(
        self,
        request: ToolInvocationRequest,
        descriptor: ToolDescriptor,
        context: SecurityContext,
    ) -> None:
        if not isinstance(request, ToolInvocationRequest):
            raise TypeError("request must be ToolInvocationRequest")
        if not isinstance(descriptor, ToolDescriptor):
            raise TypeError("descriptor must be ToolDescriptor")
        _require_authenticated_context(context)
        if request.agent_id is None:
            raise AgentAuthorizationRejectedError()
        if descriptor.tool_id != request.tool_id:
            raise AgentAuthorizationRejectedError()

        argument_digest = canonical_tool_argument_digest(request.arguments)
        try:
            await self._policy.enforce(
                PolicyRequest(
                    action=TOOL_INVOKE_ACTION,
                    resource=tool_invocation_resource(request),
                    context=context,
                    attributes={
                        "agent_id": str(request.agent_id),
                        "tool_id": str(request.tool_id),
                        "effect": descriptor.effect.value,
                        "run_id": str(request.run_id),
                        "step_id": str(request.step_id),
                        "call_id": str(request.call_id),
                        "argument_digest": argument_digest,
                    },
                )
            )
        except PhoenixPolicyError as exception:
            raise AgentAuthorizationRejectedError() from exception


def tool_effect_requires_approval(effect: ToolEffect) -> bool:
    """Return the conservative default approval requirement for one effect class."""

    if not isinstance(effect, ToolEffect):
        raise TypeError("effect must be ToolEffect")
    return effect is not ToolEffect.READ_ONLY


def _require_authenticated_context(context: SecurityContext) -> None:
    if not isinstance(context, SecurityContext):
        raise TypeError("context must be SecurityContext")
    if not context.authenticated:
        raise AgentAuthorizationRejectedError()
