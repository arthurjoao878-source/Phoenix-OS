from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

import pytest

from phoenix_os.agent.authorization import (
    AGENT_RUN_ACTION,
    TOOL_INVOKE_ACTION,
    agent_run_resource,
)
from phoenix_os.agent.checkout_authorization import (
    CheckoutListAuthorizationRequest,
    CheckoutReadAuthorizationRequest,
    PolicyEngineCheckoutWorkspaceAuthorizer,
)
from phoenix_os.agent.checkout_workspace import RegisteredDevelopmentCheckout
from phoenix_os.agent.contracts import AgentId, AgentRunId, ToolEffect, ToolId
from phoenix_os.agent.durable_authorization import (
    AGENT_CANCEL_ACTION,
    durable_agent_run_resource,
)
from phoenix_os.agent.errors import AgentAuthorizationRejectedError
from phoenix_os.agent.workspace_authorization import (
    WORKSPACE_LIST_ACTION,
    WORKSPACE_READ_ACTION,
    workspace_scope_resource,
)
from phoenix_os.agent.workspace_contracts import (
    WorkspaceNamespace,
    WorkspaceScope,
    WorkspaceScopeId,
    WorkspaceScopeKind,
)
from phoenix_os.control_plane.task_policy_binding import (
    TaskCheckoutAuthorityTarget,
    TaskExecutionPolicyBinding,
    TaskExecutionPolicyBindingError,
    TaskExecutionPolicyTargets,
    TaskToolAuthorityTarget,
)
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
    PolicyRequest,
    PolicyRule,
    PrincipalType,
    SecurityContext,
)

_RUN_ID = AgentRunId(UUID("10000000-0000-4000-8000-000000000001"))
_AGENT_ID = AgentId("task-agent")
_PROVIDER_ID = ModelProviderId("ollama-local")
_MODEL_ID = ModelId("dev")
_NOW = datetime(2026, 9, 10, 18, 0, tzinfo=UTC)
_CHECKOUT = RegisteredDevelopmentCheckout(
    workspace_id=UUID("30000000-0000-4000-8000-000000000003"),
    workspace_name="project",
    generation=7,
    root_identity="sha256:" + ("1" * 64),
    read_prefixes=("src", "tests"),
)
_TOOL = TaskToolAuthorityTarget(
    tool_id=ToolId("workspace.list"),
    effect=ToolEffect.READ_ONLY,
)
_SCOPE = WorkspaceScope(
    namespace=WorkspaceNamespace("task"),
    kind=WorkspaceScopeKind.RUN,
    scope_id=WorkspaceScopeId(str(_RUN_ID)),
)


def _context(*, cancel: bool = True, read: bool = True) -> SecurityContext:
    permissions = {
        AGENT_RUN_ACTION,
        INFERENCE_MODEL_ACTION,
        TOOL_INVOKE_ACTION,
        WORKSPACE_LIST_ACTION,
    }
    if read:
        permissions.add(WORKSPACE_READ_ACTION)
    if cancel:
        permissions.add(AGENT_CANCEL_ACTION)
    return SecurityContext(
        principal="operator-1",
        principal_type=PrincipalType.USER,
        authenticated=True,
        permissions=frozenset(permissions),
        session_id=UUID("20000000-0000-4000-8000-000000000002"),
    )


def _targets() -> TaskExecutionPolicyTargets:
    return TaskExecutionPolicyTargets(
        run_id=_RUN_ID,
        agent_id=_AGENT_ID,
        provider_id=_PROVIDER_ID,
        model_id=_MODEL_ID,
        tools=(_TOOL,),
        workspace_scopes=(_SCOPE,),
    )


@pytest.mark.asyncio
async def test_binding_preserves_exact_authority_and_removes_only_owned_rules() -> None:
    policy = PolicyEngine()
    context = _context()
    authority = TaskExecutionAuthority(policy=policy, context=context)
    binding = await TaskExecutionPolicyBinding.open(authority, _targets())

    assert binding.policy is policy
    assert binding.context is context
    assert binding.targets == _targets()
    assert binding.cancellation_actor_id == context.principal
    assert not binding.closed

    rules = await policy.list_rules()
    assert len(rules) == 6
    assert all(rule.effect is PolicyEffect.ALLOW for rule in rules)
    assert all(rule.priority == -1000 for rule in rules)
    assert all(rule.principals == frozenset({context.principal}) for rule in rules)
    assert all(rule.authenticated is True for rule in rules)
    assert all(rule.resources != frozenset({"*"}) for rule in rules)
    assert all(rule.actions != frozenset({"*"}) for rule in rules)

    await binding.close()
    assert binding.closed
    assert await policy.list_rules() == ()
    await binding.close()
    await policy.close()


@pytest.mark.asyncio
async def test_exact_run_model_tool_workspace_and_cancel_resources_are_enforced() -> None:
    policy = PolicyEngine()
    context = _context()
    binding = await TaskExecutionPolicyBinding.open(
        TaskExecutionAuthority(policy=policy, context=context),
        _targets(),
    )
    durable_run_id = integrated_durable_run_id(_RUN_ID)
    scope_resource = workspace_scope_resource(_SCOPE)

    try:
        exact_requests = (
            PolicyRequest(
                action=AGENT_RUN_ACTION,
                resource=agent_run_resource(_AGENT_ID),
                context=context,
                attributes={
                    "agent_id": str(_AGENT_ID),
                    "run_id": str(_RUN_ID),
                    "provider_id": str(_PROVIDER_ID),
                    "model_id": str(_MODEL_ID),
                },
            ),
            PolicyRequest(
                action=INFERENCE_MODEL_ACTION,
                resource=inference_model_resource(_PROVIDER_ID, _MODEL_ID),
                context=context,
                attributes={
                    "provider_id": str(_PROVIDER_ID),
                    "model_id": str(_MODEL_ID),
                },
            ),
            PolicyRequest(
                action=TOOL_INVOKE_ACTION,
                resource=f"tool:{_TOOL.tool_id}/resolved",
                context=context,
                attributes={
                    "agent_id": str(_AGENT_ID),
                    "tool_id": str(_TOOL.tool_id),
                    "effect": _TOOL.effect.value,
                    "run_id": str(_RUN_ID),
                },
            ),
            PolicyRequest(
                action=WORKSPACE_LIST_ACTION,
                resource=scope_resource,
                context=context,
            ),
            PolicyRequest(
                action=WORKSPACE_READ_ACTION,
                resource=f"{scope_resource}/artifact:30000000-0000-4000-8000-000000000003",
                context=context,
            ),
            PolicyRequest(
                action=AGENT_CANCEL_ACTION,
                resource=durable_agent_run_resource(durable_run_id),
                context=context,
                attributes={
                    "agent_id": str(_AGENT_ID),
                    "agent_run_id": str(_RUN_ID),
                    "actor_id": context.principal,
                    "run_id": str(durable_run_id),
                },
            ),
        )
        for request in exact_requests:
            assert (await policy.evaluate(request)).effect is PolicyEffect.ALLOW

        wrong_run = PolicyRequest(
            action=AGENT_RUN_ACTION,
            resource=agent_run_resource(_AGENT_ID),
            context=context,
            attributes={
                "agent_id": str(_AGENT_ID),
                "run_id": str(AgentRunId()),
                "provider_id": str(_PROVIDER_ID),
                "model_id": str(_MODEL_ID),
            },
        )
        assert (await policy.evaluate(wrong_run)).effect is PolicyEffect.DENY

        wrong_model = PolicyRequest(
            action=INFERENCE_MODEL_ACTION,
            resource=inference_model_resource(_PROVIDER_ID, ModelId("other")),
            context=context,
            attributes={
                "provider_id": str(_PROVIDER_ID),
                "model_id": "other",
            },
        )
        assert (await policy.evaluate(wrong_model)).effect is PolicyEffect.DENY

        wrong_tool_run = PolicyRequest(
            action=TOOL_INVOKE_ACTION,
            resource=f"tool:{_TOOL.tool_id}/resolved",
            context=context,
            attributes={
                "agent_id": str(_AGENT_ID),
                "tool_id": str(_TOOL.tool_id),
                "effect": _TOOL.effect.value,
                "run_id": str(AgentRunId()),
            },
        )
        assert (await policy.evaluate(wrong_tool_run)).effect is PolicyEffect.DENY

        other_scope = WorkspaceScope(
            namespace=WorkspaceNamespace("other"),
            kind=WorkspaceScopeKind.RUN,
            scope_id=WorkspaceScopeId(str(_RUN_ID)),
        )
        wrong_workspace = PolicyRequest(
            action=WORKSPACE_LIST_ACTION,
            resource=workspace_scope_resource(other_scope),
            context=context,
        )
        assert (await policy.evaluate(wrong_workspace)).effect is PolicyEffect.DENY
    finally:
        await binding.close()
        await policy.close()


@pytest.mark.asyncio
async def test_missing_explicit_permission_fails_before_any_registration() -> None:
    policy = PolicyEngine()
    try:
        with pytest.raises(TaskExecutionPolicyBindingError):
            await TaskExecutionPolicyBinding.open(
                TaskExecutionAuthority(policy=policy, context=_context(read=False)),
                _targets(),
            )
        assert await policy.list_rules() == ()
    finally:
        await policy.close()


@pytest.mark.asyncio
async def test_cancel_rule_is_absent_without_explicit_cancel_permission() -> None:
    policy = PolicyEngine()
    context = _context(cancel=False)
    binding = await TaskExecutionPolicyBinding.open(
        TaskExecutionAuthority(policy=policy, context=context),
        _targets(),
    )
    durable_run_id = integrated_durable_run_id(_RUN_ID)

    try:
        decision = await policy.evaluate(
            PolicyRequest(
                action=AGENT_CANCEL_ACTION,
                resource=durable_agent_run_resource(durable_run_id),
                context=context,
                attributes={
                    "agent_id": str(_AGENT_ID),
                    "agent_run_id": str(_RUN_ID),
                    "actor_id": context.principal,
                    "run_id": str(durable_run_id),
                },
            )
        )
        assert decision.effect is PolicyEffect.DENY
    finally:
        await binding.close()
        await policy.close()


@pytest.mark.asyncio
async def test_existing_normal_priority_deny_overrides_task_projection() -> None:
    context = _context()
    policy = PolicyEngine(
        (
            PolicyRule(
                rule_id="test-deny-agent-run",
                effect=PolicyEffect.DENY,
                actions=frozenset({AGENT_RUN_ACTION}),
                resources=frozenset({"agent:*"}),
                principals=frozenset({context.principal}),
                principal_types=frozenset({PrincipalType.USER}),
                authenticated=True,
                priority=0,
            ),
        )
    )
    binding = await TaskExecutionPolicyBinding.open(
        TaskExecutionAuthority(policy=policy, context=context),
        _targets(),
    )

    try:
        decision = await policy.evaluate(
            PolicyRequest(
                action=AGENT_RUN_ACTION,
                resource=agent_run_resource(_AGENT_ID),
                context=context,
                attributes={
                    "agent_id": str(_AGENT_ID),
                    "run_id": str(_RUN_ID),
                    "provider_id": str(_PROVIDER_ID),
                    "model_id": str(_MODEL_ID),
                },
            )
        )
        assert decision.effect is PolicyEffect.DENY
        assert decision.rule_id == "test-deny-agent-run"
    finally:
        await binding.close()
        assert tuple(rule.rule_id for rule in await policy.list_rules()) == ("test-deny-agent-run",)
        await policy.close()


def test_targets_reject_duplicate_tools_and_workspace_scopes() -> None:
    with pytest.raises(ValueError):
        TaskExecutionPolicyTargets(
            run_id=_RUN_ID,
            agent_id=_AGENT_ID,
            provider_id=_PROVIDER_ID,
            model_id=_MODEL_ID,
            tools=(_TOOL, _TOOL),
        )
    with pytest.raises(ValueError):
        TaskExecutionPolicyTargets(
            run_id=_RUN_ID,
            agent_id=_AGENT_ID,
            provider_id=_PROVIDER_ID,
            model_id=_MODEL_ID,
            workspace_scopes=(_SCOPE, _SCOPE),
        )


def _checkout_targets() -> TaskExecutionPolicyTargets:
    return TaskExecutionPolicyTargets(
        run_id=_RUN_ID,
        agent_id=_AGENT_ID,
        provider_id=_PROVIDER_ID,
        model_id=_MODEL_ID,
        tools=(
            TaskToolAuthorityTarget(
                tool_id=ToolId("workspace.list"),
                effect=ToolEffect.READ_ONLY,
            ),
            TaskToolAuthorityTarget(
                tool_id=ToolId("workspace.read"),
                effect=ToolEffect.READ_ONLY,
            ),
        ),
        checkout=TaskCheckoutAuthorityTarget(_CHECKOUT),
    )


@pytest.mark.asyncio
async def test_checkout_projection_authorizes_only_current_run_registration_and_prefixes() -> None:
    policy = PolicyEngine()
    context = _context()
    binding = await TaskExecutionPolicyBinding.open(
        TaskExecutionAuthority(policy=policy, context=context),
        _checkout_targets(),
    )
    authorizer = PolicyEngineCheckoutWorkspaceAuthorizer(policy)

    try:
        await authorizer.authorize_list(
            CheckoutListAuthorizationRequest(
                run_id=_RUN_ID,
                registration=_CHECKOUT,
                prefix="src",
                max_entries=8,
                created_at=_NOW,
            ),
            context,
        )
        await authorizer.authorize_list(
            CheckoutListAuthorizationRequest(
                run_id=_RUN_ID,
                registration=_CHECKOUT,
                prefix="src/pkg",
                max_entries=8,
                created_at=_NOW,
            ),
            context,
        )
        await authorizer.authorize_read(
            CheckoutReadAuthorizationRequest(
                run_id=_RUN_ID,
                registration=_CHECKOUT,
                logical_path="tests",
                created_at=_NOW,
            ),
            context,
        )
        await authorizer.authorize_read(
            CheckoutReadAuthorizationRequest(
                run_id=_RUN_ID,
                registration=_CHECKOUT,
                logical_path="tests/pkg/example.py",
                created_at=_NOW,
            ),
            context,
        )

        with pytest.raises(AgentAuthorizationRejectedError):
            await authorizer.authorize_read(
                CheckoutReadAuthorizationRequest(
                    run_id=_RUN_ID,
                    registration=_CHECKOUT,
                    logical_path="src2/example.py",
                    created_at=_NOW,
                ),
                context,
            )

        with pytest.raises(AgentAuthorizationRejectedError):
            await authorizer.authorize_read(
                CheckoutReadAuthorizationRequest(
                    run_id=AgentRunId(),
                    registration=_CHECKOUT,
                    logical_path="src/example.py",
                    created_at=_NOW,
                ),
                context,
            )

        wrong_generation = RegisteredDevelopmentCheckout(
            workspace_id=_CHECKOUT.workspace_id,
            workspace_name=_CHECKOUT.workspace_name,
            generation=_CHECKOUT.generation + 1,
            root_identity=_CHECKOUT.root_identity,
            read_prefixes=_CHECKOUT.read_prefixes,
        )
        with pytest.raises(AgentAuthorizationRejectedError):
            await authorizer.authorize_read(
                CheckoutReadAuthorizationRequest(
                    run_id=_RUN_ID,
                    registration=wrong_generation,
                    logical_path="src/example.py",
                    created_at=_NOW,
                ),
                context,
            )
    finally:
        await binding.close()
        await policy.close()


@pytest.mark.asyncio
async def test_checkout_projection_requires_explicit_list_and_read_permissions() -> None:
    policy = PolicyEngine()
    try:
        with pytest.raises(TaskExecutionPolicyBindingError):
            await TaskExecutionPolicyBinding.open(
                TaskExecutionAuthority(policy=policy, context=_context(read=False)),
                _checkout_targets(),
            )
        assert await policy.list_rules() == ()
    finally:
        await policy.close()


def test_checkout_target_rejects_non_registration() -> None:
    with pytest.raises(TypeError):
        TaskCheckoutAuthorityTarget(object())  # type: ignore[arg-type]
