from datetime import UTC, datetime, timedelta

import pytest

from phoenix_os.agent import (
    AGENT_DELEGATE_ACTION,
    AgentAuthorizationRejectedError,
    AgentDelegationRegistry,
    AgentId,
    AgentLimits,
    AgentRunId,
    AgentServiceConfiguration,
    CoordinationNamespace,
    DelegableAgentDescriptor,
    DelegationBudget,
    DelegationDepth,
    DelegationLineage,
    DelegationLineageEntry,
    DelegationRequest,
    PolicyEngineDelegationAuthorizer,
    agent_delegation_resource,
    canonical_delegation_input_digest,
)
from phoenix_os.inference import ModelId, ModelProviderId
from phoenix_os.policy import (
    PolicyEffect,
    PolicyEngine,
    PolicyRule,
    PrincipalType,
    SecurityContext,
)

_NOW = datetime(2026, 8, 10, 17, tzinfo=UTC)


def _context(*, authenticated: bool = True) -> SecurityContext:
    return SecurityContext(
        principal="service:parent" if authenticated else "anonymous",
        principal_type=PrincipalType.SERVICE if authenticated else PrincipalType.ANONYMOUS,
        authenticated=authenticated,
    )


def _descriptor(
    child: str = "researcher",
    *,
    max_model_turns: int = 8,
) -> DelegableAgentDescriptor:
    return DelegableAgentDescriptor(
        configuration=AgentServiceConfiguration(
            agent_id=AgentId(child),
            provider_id=ModelProviderId("local"),
            model_id=ModelId("chat"),
            limits=AgentLimits(
                max_model_turns=max_model_turns,
                max_tool_calls=min(8, max_model_turns),
                total_duration=timedelta(minutes=10),
            ),
        ),
        namespace=CoordinationNamespace("default"),
        allowed_parent_agents=(AgentId("parent"),),
        compatibility_digest="sha256:" + "a" * 64,
        max_accepted_depth=DelegationDepth(2),
        allow_nested_delegation=True,
    )


def _request(
    child: str = "researcher",
    *,
    task: str = "summarize",
    budget: DelegationBudget | None = None,
) -> DelegationRequest:
    run_id = AgentRunId()
    lineage = DelegationLineage((DelegationLineageEntry(AgentId("parent"), run_id),))
    return DelegationRequest(
        parent_agent_id=AgentId("parent"),
        parent_run_id=run_id,
        child_agent_id=AgentId(child),
        namespace=CoordinationNamespace("default"),
        lineage=lineage,
        input={"task": task},
        budget=budget or DelegationBudget(),
        created_at=_NOW,
        deadline=_NOW + timedelta(minutes=5),
    )


def test_action_resource_and_input_digest_are_exact() -> None:
    request = _request()

    assert AGENT_DELEGATE_ACTION == "agent.delegate"
    assert (
        agent_delegation_resource(
            namespace=request.namespace,
            parent_agent_id=request.parent_agent_id,
            child_agent_id=request.child_agent_id,
        )
        == "agent-delegation:default/parent:parent/child:researcher"
    )
    assert canonical_delegation_input_digest(request).startswith("sha256:")
    assert canonical_delegation_input_digest(_request(task="a")) != (
        canonical_delegation_input_digest(_request(task="b"))
    )


@pytest.mark.asyncio
async def test_delegation_authorization_is_exact_and_default_deny() -> None:
    request = _request()
    digest = canonical_delegation_input_digest(request)
    policy = PolicyEngine(
        (
            PolicyRule(
                rule_id="allow.parent.researcher",
                effect=PolicyEffect.ALLOW,
                actions=frozenset({"agent.delegate"}),
                resources=frozenset({"agent-delegation:default/parent:parent/child:researcher"}),
                principals=frozenset({"service:parent"}),
                authenticated=True,
                attribute_equals={
                    "child_agent_id": "researcher",
                    "delegation_depth": "1",
                    "input_digest": digest,
                },
            ),
        )
    )
    authorizer = PolicyEngineDelegationAuthorizer(policy)

    await authorizer.authorize(request, _descriptor(), _context())
    with pytest.raises(AgentAuthorizationRejectedError):
        await authorizer.authorize(
            _request(child="analyst"),
            _descriptor("analyst"),
            _context(),
        )

    snapshot = await policy.snapshot()
    assert snapshot.allowed == 1
    assert snapshot.denied == 1


@pytest.mark.asyncio
async def test_agent_run_authority_does_not_grant_delegation() -> None:
    policy = PolicyEngine(
        (
            PolicyRule(
                rule_id="agent.run.only",
                effect=PolicyEffect.ALLOW,
                actions=frozenset({"agent.run"}),
                resources=frozenset({"agent:parent"}),
                principals=frozenset({"service:parent"}),
                authenticated=True,
            ),
        )
    )

    with pytest.raises(AgentAuthorizationRejectedError):
        await PolicyEngineDelegationAuthorizer(policy).authorize(
            _request(),
            _descriptor(),
            _context(),
        )


@pytest.mark.asyncio
async def test_registry_descriptor_mismatch_fails_before_policy_evaluation() -> None:
    policy = PolicyEngine()
    authorizer = PolicyEngineDelegationAuthorizer(policy)

    with pytest.raises(AgentAuthorizationRejectedError):
        await authorizer.authorize(
            _request(),
            _descriptor("other"),
            _context(),
        )

    assert (await policy.snapshot()).evaluations == 0


@pytest.mark.asyncio
async def test_child_budget_cannot_exceed_registered_agent_limits() -> None:
    policy = PolicyEngine()
    authorizer = PolicyEngineDelegationAuthorizer(policy)
    request = _request(
        budget=DelegationBudget(
            max_model_turns=4,
            max_tool_calls=4,
            max_input_tokens=32_768,
            max_output_tokens=16_384,
            max_prompt_bytes=131_072,
            max_result_bytes=524_288,
            duration=timedelta(minutes=5),
        )
    )

    with pytest.raises(AgentAuthorizationRejectedError):
        await authorizer.authorize(
            request,
            _descriptor(max_model_turns=2),
            _context(),
        )

    assert (await policy.snapshot()).evaluations == 0


@pytest.mark.asyncio
async def test_unauthenticated_delegation_fails_before_policy_evaluation() -> None:
    policy = PolicyEngine()

    with pytest.raises(AgentAuthorizationRejectedError):
        await PolicyEngineDelegationAuthorizer(policy).authorize(
            _request(),
            _descriptor(),
            _context(authenticated=False),
        )

    assert (await policy.snapshot()).evaluations == 0


def test_registry_and_authorizer_compose_without_creating_child_work() -> None:
    registry = AgentDelegationRegistry()
    descriptor = _descriptor()
    registry.register_agent(descriptor)
    request = _request()

    assert registry.resolve_request(request) == descriptor
    assert request.input == {"task": "summarize"}
    assert request.child_depth == DelegationDepth(1)
