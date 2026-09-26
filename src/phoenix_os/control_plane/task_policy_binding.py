"""Ephemeral exact RFC-0039 policy projection for one admitted task execution."""

from __future__ import annotations

from dataclasses import dataclass

from phoenix_os.agent.authorization import (
    AGENT_RUN_ACTION,
    TOOL_INVOKE_ACTION,
    agent_run_resource,
)
from phoenix_os.agent.checkout_workspace import (
    RegisteredDevelopmentCheckout,
    checkout_path_resource,
    checkout_prefix_resource,
)
from phoenix_os.agent.contracts import AgentId, AgentRunId, ToolEffect, ToolId
from phoenix_os.agent.durable_authorization import (
    AGENT_CANCEL_ACTION,
    AGENT_RESUME_ACTION,
    durable_agent_run_resource,
)
from phoenix_os.agent.workspace_authorization import (
    WORKSPACE_LIST_ACTION,
    WORKSPACE_PATCH_ACTION,
    WORKSPACE_READ_ACTION,
    workspace_scope_resource,
)
from phoenix_os.agent.workspace_contracts import WorkspaceScope
from phoenix_os.control_plane.task_runtime_bridge import TaskExecutionAuthority
from phoenix_os.inference.authorization import (
    INFERENCE_MODEL_ACTION,
    inference_model_resource,
)
from phoenix_os.inference.contracts import ModelId, ModelProviderId
from phoenix_os.integrated_agent.durable_run import integrated_durable_run_id
from phoenix_os.policy import (
    PolicyEffect,
    PolicyEngine,
    PolicyRegistration,
    PolicyRule,
    PrincipalType,
    SecurityContext,
)

_TASK_POLICY_PRIORITY = -1000


class TaskExecutionPolicyBindingError(RuntimeError):
    """Content-free failure while binding or releasing one task policy projection."""


@dataclass(frozen=True, slots=True, order=True)
class TaskToolAuthorityTarget:
    """Exact tool identity/effect copied from one reviewed runtime composition."""

    tool_id: ToolId
    effect: ToolEffect

    def __post_init__(self) -> None:
        if not isinstance(self.tool_id, ToolId):
            raise TypeError("tool_id must be ToolId")
        if not isinstance(self.effect, ToolEffect):
            raise TypeError("effect must be ToolEffect")


@dataclass(frozen=True, slots=True)
class TaskCheckoutAuthorityTarget:
    """Exact content-free checkout registration selected by the reviewed runtime."""

    registration: RegisteredDevelopmentCheckout

    def __post_init__(self) -> None:
        if not isinstance(self.registration, RegisteredDevelopmentCheckout):
            raise TypeError("registration must be RegisteredDevelopmentCheckout")


@dataclass(frozen=True, slots=True)
class TaskExecutionPolicyTargets:
    """Content-free exact resources selected for one already-admitted task run."""

    run_id: AgentRunId
    agent_id: AgentId
    provider_id: ModelProviderId
    model_id: ModelId
    tools: tuple[TaskToolAuthorityTarget, ...] = ()
    workspace_scopes: tuple[WorkspaceScope, ...] = ()
    checkout: TaskCheckoutAuthorityTarget | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.run_id, AgentRunId):
            raise TypeError("run_id must be AgentRunId")
        if not isinstance(self.agent_id, AgentId):
            raise TypeError("agent_id must be AgentId")
        if not isinstance(self.provider_id, ModelProviderId):
            raise TypeError("provider_id must be ModelProviderId")
        if not isinstance(self.model_id, ModelId):
            raise TypeError("model_id must be ModelId")

        tools = tuple(self.tools)
        if any(not isinstance(item, TaskToolAuthorityTarget) for item in tools):
            raise TypeError("tools must contain TaskToolAuthorityTarget values")
        if len({item.tool_id for item in tools}) != len(tools):
            raise ValueError("task policy targets contain duplicate tool ids")

        scopes = tuple(self.workspace_scopes)
        if any(not isinstance(item, WorkspaceScope) for item in scopes):
            raise TypeError("workspace_scopes must contain WorkspaceScope values")
        if len(set(scopes)) != len(scopes):
            raise ValueError("task policy targets contain duplicate workspace scopes")
        if self.checkout is not None and not isinstance(
            self.checkout,
            TaskCheckoutAuthorityTarget,
        ):
            raise TypeError("checkout must be TaskCheckoutAuthorityTarget or None")

        object.__setattr__(self, "tools", tuple(sorted(tools)))
        object.__setattr__(self, "workspace_scopes", tuple(sorted(scopes)))


class TaskExecutionPolicyBinding:
    """Own only the low-priority rules projected for one task run."""

    def __init__(
        self,
        *,
        policy: PolicyEngine,
        context: SecurityContext,
        targets: TaskExecutionPolicyTargets,
        registrations: tuple[PolicyRegistration, ...],
    ) -> None:
        if not isinstance(policy, PolicyEngine):
            raise TypeError("policy must be PolicyEngine")
        if not isinstance(context, SecurityContext):
            raise TypeError("context must be SecurityContext")
        if not isinstance(targets, TaskExecutionPolicyTargets):
            raise TypeError("targets must be TaskExecutionPolicyTargets")
        if any(not isinstance(item, PolicyRegistration) for item in registrations):
            raise TypeError("registrations must contain PolicyRegistration values")
        self._policy = policy
        self._context = context
        self._targets = targets
        self._registrations = list(registrations)
        self._closed = False

    @classmethod
    async def open(
        cls,
        authority: TaskExecutionAuthority,
        targets: TaskExecutionPolicyTargets,
    ) -> TaskExecutionPolicyBinding:
        """Register exact rules derived only from explicit caller permissions."""

        if not isinstance(authority, TaskExecutionAuthority):
            raise TypeError("authority must be TaskExecutionAuthority")
        if not isinstance(targets, TaskExecutionPolicyTargets):
            raise TypeError("targets must be TaskExecutionPolicyTargets")

        policy = authority.policy
        context = authority.context
        if policy.closed:
            raise TaskExecutionPolicyBindingError()
        if not context.authenticated or context.principal_type is not PrincipalType.USER:
            raise TaskExecutionPolicyBindingError()

        rules = _task_policy_rules(context=context, targets=targets)
        registrations: list[PolicyRegistration] = []
        try:
            for rule in rules:
                registrations.append(await policy.register(rule))
        except BaseException:
            try:
                await _rollback(policy, registrations)
            except Exception as rollback_exception:
                raise TaskExecutionPolicyBindingError() from rollback_exception
            raise

        return cls(
            policy=policy,
            context=context,
            targets=targets,
            registrations=tuple(registrations),
        )

    @property
    def policy(self) -> PolicyEngine:
        return self._policy

    @property
    def context(self) -> SecurityContext:
        return self._context

    @property
    def targets(self) -> TaskExecutionPolicyTargets:
        return self._targets

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def cancellation_actor_id(self) -> str:
        return self._context.principal

    async def close(self) -> None:
        """Remove only the exact registrations owned by this binding."""

        if self._closed:
            return
        if self._policy.closed:
            self._registrations.clear()
            self._closed = True
            return

        while self._registrations:
            registration = self._registrations[-1]
            if not await self._policy.unregister(registration):
                raise TaskExecutionPolicyBindingError()
            self._registrations.pop()
        self._closed = True


def _task_policy_rules(
    *,
    context: SecurityContext,
    targets: TaskExecutionPolicyTargets,
) -> tuple[PolicyRule, ...]:
    required_permissions = {
        AGENT_RUN_ACTION,
        INFERENCE_MODEL_ACTION,
    }
    if targets.tools:
        required_permissions.add(TOOL_INVOKE_ACTION)
    if targets.workspace_scopes or targets.checkout is not None:
        required_permissions.update(
            {
                WORKSPACE_LIST_ACTION,
                WORKSPACE_READ_ACTION,
            }
        )
    if targets.checkout is not None and targets.checkout.registration.patch_prefixes:
        required_permissions.add(WORKSPACE_PATCH_ACTION)
    if not required_permissions <= context.permissions:
        raise TaskExecutionPolicyBindingError()

    prefix = f"rfc0039.task.{targets.run_id}"
    rules: list[PolicyRule] = [
        _allow_rule(
            rule_id=f"{prefix}.agent-run",
            action=AGENT_RUN_ACTION,
            resource=agent_run_resource(targets.agent_id),
            permission=AGENT_RUN_ACTION,
            context=context,
            attributes={
                "agent_id": str(targets.agent_id),
                "run_id": str(targets.run_id),
                "provider_id": str(targets.provider_id),
                "model_id": str(targets.model_id),
            },
        ),
        _allow_rule(
            rule_id=f"{prefix}.model-infer",
            action=INFERENCE_MODEL_ACTION,
            resource=inference_model_resource(
                targets.provider_id,
                targets.model_id,
            ),
            permission=INFERENCE_MODEL_ACTION,
            context=context,
            attributes={
                "provider_id": str(targets.provider_id),
                "model_id": str(targets.model_id),
            },
        ),
    ]

    for index, target in enumerate(targets.tools):
        rules.append(
            _allow_rule(
                rule_id=f"{prefix}.tool-{index}",
                action=TOOL_INVOKE_ACTION,
                resource=f"tool:{target.tool_id}/*",
                permission=TOOL_INVOKE_ACTION,
                context=context,
                attributes={
                    "agent_id": str(targets.agent_id),
                    "tool_id": str(target.tool_id),
                    "effect": target.effect.value,
                    "run_id": str(targets.run_id),
                },
            )
        )

    for index, scope in enumerate(targets.workspace_scopes):
        scope_resource = workspace_scope_resource(scope)
        rules.extend(
            (
                _allow_rule(
                    rule_id=f"{prefix}.workspace-list-{index}",
                    action=WORKSPACE_LIST_ACTION,
                    resource=scope_resource,
                    permission=WORKSPACE_LIST_ACTION,
                    context=context,
                ),
                _allow_rule(
                    rule_id=f"{prefix}.workspace-read-{index}",
                    action=WORKSPACE_READ_ACTION,
                    resource=f"{scope_resource}/artifact:*",
                    permission=WORKSPACE_READ_ACTION,
                    context=context,
                ),
            )
        )

    checkout = targets.checkout
    if checkout is not None:
        registration = checkout.registration
        checkout_attributes = {
            "checkout_workspace_id": str(registration.workspace_id),
            "checkout_registration_generation": str(registration.generation),
            "run_id": str(targets.run_id),
        }
        for index, read_prefix in enumerate(registration.read_prefixes):
            list_resource = checkout_prefix_resource(registration, read_prefix)
            read_resource = checkout_path_resource(registration, read_prefix)
            rules.extend(
                (
                    _allow_rule(
                        rule_id=f"{prefix}.checkout-list-exact-{index}",
                        action=WORKSPACE_LIST_ACTION,
                        resource=list_resource,
                        permission=WORKSPACE_LIST_ACTION,
                        context=context,
                        attributes=checkout_attributes,
                    ),
                    _allow_rule(
                        rule_id=f"{prefix}.checkout-list-descendants-{index}",
                        action=WORKSPACE_LIST_ACTION,
                        resource=f"{list_resource}/*",
                        permission=WORKSPACE_LIST_ACTION,
                        context=context,
                        attributes=checkout_attributes,
                    ),
                    _allow_rule(
                        rule_id=f"{prefix}.checkout-read-exact-{index}",
                        action=WORKSPACE_READ_ACTION,
                        resource=read_resource,
                        permission=WORKSPACE_READ_ACTION,
                        context=context,
                        attributes=checkout_attributes,
                    ),
                    _allow_rule(
                        rule_id=f"{prefix}.checkout-read-descendants-{index}",
                        action=WORKSPACE_READ_ACTION,
                        resource=f"{read_resource}/*",
                        permission=WORKSPACE_READ_ACTION,
                        context=context,
                        attributes=checkout_attributes,
                    ),
                )
            )

        for index, patch_prefix in enumerate(registration.patch_prefixes):
            patch_resource = checkout_path_resource(registration, patch_prefix)
            rules.extend(
                (
                    _allow_rule(
                        rule_id=f"{prefix}.checkout-patch-exact-{index}",
                        action=WORKSPACE_PATCH_ACTION,
                        resource=patch_resource,
                        permission=WORKSPACE_PATCH_ACTION,
                        context=context,
                        attributes=checkout_attributes,
                    ),
                    _allow_rule(
                        rule_id=f"{prefix}.checkout-patch-descendants-{index}",
                        action=WORKSPACE_PATCH_ACTION,
                        resource=f"{patch_resource}/*",
                        permission=WORKSPACE_PATCH_ACTION,
                        context=context,
                        attributes=checkout_attributes,
                    ),
                )
            )

    if AGENT_CANCEL_ACTION in context.permissions or AGENT_RESUME_ACTION in context.permissions:
        durable_run_id = integrated_durable_run_id(targets.run_id)
        durable_resource = durable_agent_run_resource(durable_run_id)
        durable_attributes = {
            "agent_id": str(targets.agent_id),
            "agent_run_id": str(targets.run_id),
            "actor_id": context.principal,
            "run_id": str(durable_run_id),
        }
        if AGENT_CANCEL_ACTION in context.permissions:
            rules.append(
                _allow_rule(
                    rule_id=f"{prefix}.cancel",
                    action=AGENT_CANCEL_ACTION,
                    resource=durable_resource,
                    permission=AGENT_CANCEL_ACTION,
                    context=context,
                    attributes=durable_attributes,
                )
            )
        if AGENT_RESUME_ACTION in context.permissions:
            rules.append(
                _allow_rule(
                    rule_id=f"{prefix}.resume",
                    action=AGENT_RESUME_ACTION,
                    resource=durable_resource,
                    permission=AGENT_RESUME_ACTION,
                    context=context,
                    attributes=durable_attributes,
                )
            )

    return tuple(rules)


def _allow_rule(
    *,
    rule_id: str,
    action: str,
    resource: str,
    permission: str,
    context: SecurityContext,
    attributes: dict[str, str] | None = None,
) -> PolicyRule:
    return PolicyRule(
        rule_id=rule_id,
        effect=PolicyEffect.ALLOW,
        actions=frozenset({action}),
        resources=frozenset({resource}),
        principals=frozenset({context.principal}),
        principal_types=frozenset({PrincipalType.USER}),
        required_permissions=frozenset({permission}),
        authenticated=True,
        attribute_equals={} if attributes is None else attributes,
        priority=_TASK_POLICY_PRIORITY,
        reason="rfc0039 exact task execution grant",
        metadata={"authority_source": "explicit_operator_permission"},
    )


async def _rollback(
    policy: PolicyEngine,
    registrations: list[PolicyRegistration],
) -> None:
    while registrations:
        registration = registrations[-1]
        if not await policy.unregister(registration):
            raise TaskExecutionPolicyBindingError()
        registrations.pop()
