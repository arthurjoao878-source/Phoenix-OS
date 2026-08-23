import asyncio
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from phoenix_os.agent import (
    AGENT_DELEGATE_ACTION,
    AgentAuthorizationRejectedError,
    AgentDelegationCoordinator,
    AgentDelegationRegistry,
    AgentId,
    AgentLimitExceededError,
    AgentLimits,
    AgentRunId,
    AgentServiceConfiguration,
    AgentStateConflictError,
    CoordinationNamespace,
    DelegableAgentDescriptor,
    DelegationAlreadyExistsError,
    DelegationBudget,
    DelegationDepth,
    DelegationId,
    DelegationLimits,
    DelegationLineage,
    DelegationLineageEntry,
    DelegationNotFoundError,
    DelegationRequest,
    DelegationStatus,
    PolicyEngineDelegationAuthorizer,
    agent_delegation_resource,
)
from phoenix_os.inference import ModelId, ModelProviderId
from phoenix_os.policy import (
    PolicyEffect,
    PolicyEngine,
    PolicyRule,
    PrincipalType,
    SecurityContext,
)

_NOW = datetime(2026, 8, 10, 18, tzinfo=UTC)


class _RecordingAuthorizer:
    def __init__(self) -> None:
        self.calls: list[DelegationId] = []

    async def authorize(
        self,
        request: DelegationRequest,
        descriptor: DelegableAgentDescriptor,
        context: SecurityContext,
    ) -> None:
        assert descriptor.agent_id == request.child_agent_id
        assert context.authenticated
        self.calls.append(request.delegation_id)


class _RecordingFreshnessValidator:
    def __init__(self) -> None:
        self.contexts: list[SecurityContext] = []

    async def validate(self, context: SecurityContext) -> None:
        self.contexts.append(context)


def _context() -> SecurityContext:
    return SecurityContext(
        principal="service:parent",
        principal_type=PrincipalType.SERVICE,
        authenticated=True,
    )


def _limits(
    *,
    fan_out: int = 4,
    total: int = 8,
    concurrent: int = 2,
    queue: int = 4,
) -> DelegationLimits:
    return DelegationLimits(
        max_depth=3,
        max_fan_out=fan_out,
        max_total_children=total,
        max_concurrent_children=concurrent,
        max_queue_depth=queue,
        max_input_bytes=65_536,
        max_result_bytes=262_144,
        max_result_depth=8,
        child_timeout=timedelta(minutes=5),
    )


def _child_budget() -> DelegationBudget:
    return DelegationBudget(
        max_model_turns=2,
        max_tool_calls=1,
        max_input_tokens=8_192,
        max_output_tokens=4_096,
        max_prompt_bytes=32_768,
        max_result_bytes=131_072,
        duration=timedelta(minutes=2),
    )


def _root_budget(*, children: int = 4) -> DelegationBudget:
    child = _child_budget()
    return DelegationBudget(
        max_model_turns=child.max_model_turns * children,
        max_tool_calls=child.max_tool_calls * children,
        max_input_tokens=child.max_input_tokens * children,
        max_output_tokens=child.max_output_tokens * children,
        max_prompt_bytes=child.max_prompt_bytes * children,
        max_result_bytes=child.max_result_bytes * children,
        duration=child.duration * children,
    )


def _descriptor(
    child: str,
    *,
    parents: tuple[str, ...] = ("parent",),
    nested: bool = True,
    max_depth: int = 3,
) -> DelegableAgentDescriptor:
    return DelegableAgentDescriptor(
        configuration=AgentServiceConfiguration(
            agent_id=AgentId(child),
            provider_id=ModelProviderId("local"),
            model_id=ModelId("chat"),
            limits=AgentLimits(
                max_model_turns=8,
                max_tool_calls=4,
                max_input_tokens=65_536,
                max_output_tokens=32_768,
                max_prompt_bytes=262_144,
                max_result_bytes=1_048_576,
                total_duration=timedelta(minutes=10),
            ),
        ),
        namespace=CoordinationNamespace("default"),
        allowed_parent_agents=tuple(AgentId(parent) for parent in parents),
        compatibility_digest="sha256:" + "a" * 64,
        allow_nested_delegation=nested,
        max_accepted_depth=DelegationDepth(max_depth),
    )


def _registry(*children: str) -> AgentDelegationRegistry:
    registry = AgentDelegationRegistry()
    for child in children:
        registry.register_agent(_descriptor(child))
    return registry


def _request(
    child: str,
    *,
    limits: DelegationLimits,
    parent_run: AgentRunId | None = None,
    root_run: AgentRunId | None = None,
    delegation_id: DelegationId | None = None,
    parent_agent: str = "parent",
    lineage: DelegationLineage | None = None,
) -> DelegationRequest:
    selected_parent_run = parent_run or AgentRunId()
    selected_root = root_run or selected_parent_run
    selected_lineage = lineage or DelegationLineage(
        (
            DelegationLineageEntry(
                AgentId(parent_agent),
                selected_root,
            ),
        )
    )
    if selected_lineage.parent_run_id != selected_parent_run:
        selected_parent_run = selected_lineage.parent_run_id
    return DelegationRequest(
        parent_agent_id=selected_lineage.parent_agent_id,
        parent_run_id=selected_parent_run,
        child_agent_id=AgentId(child),
        namespace=CoordinationNamespace("default"),
        lineage=selected_lineage,
        input={"task": f"work:{child}"},
        budget=_child_budget(),
        limits=limits,
        delegation_id=delegation_id or DelegationId(),
        created_at=_NOW,
        deadline=_NOW + timedelta(minutes=2),
    )


def _coordinator(
    registry: AgentDelegationRegistry,
    authorizer: object,
    *,
    limits: DelegationLimits,
    root_children: int = 4,
    authority_freshness: _RecordingFreshnessValidator | None = None,
) -> AgentDelegationCoordinator:
    return AgentDelegationCoordinator(
        registry,
        authorizer,  # type: ignore[arg-type]
        limits=limits,
        root_budget_limit=_root_budget(children=root_children),
        authority_freshness=authority_freshness,
        clock=lambda: _NOW,
    )


@pytest.mark.asyncio
async def test_coordinator_authorizes_and_admits_one_unique_child() -> None:
    limits = _limits()
    authorizer = _RecordingAuthorizer()
    coordinator = _coordinator(_registry("researcher"), authorizer, limits=limits)
    request = _request("researcher", limits=limits)

    child = await coordinator.delegate(request, _context())

    assert child.delegation_id == request.delegation_id
    assert child.child_agent_id == AgentId("researcher")
    assert child.child_run_id != request.parent_run_id
    assert child.status is DelegationStatus.ADMITTED
    assert authorizer.calls == [request.delegation_id]

    budget = coordinator.root_budget_snapshot(request.lineage.root_run_id)
    assert budget.children == 1
    assert budget.model_turns == request.budget.max_model_turns


@pytest.mark.asyncio
async def test_duplicate_delegation_id_never_creates_second_child() -> None:
    limits = _limits()
    coordinator = _coordinator(
        _registry("researcher"),
        _RecordingAuthorizer(),
        limits=limits,
    )
    identity = DelegationId()
    first = _request("researcher", limits=limits, delegation_id=identity)
    second = _request("researcher", limits=limits, delegation_id=identity)

    admitted = await coordinator.delegate(first, _context())
    with pytest.raises(DelegationAlreadyExistsError):
        await coordinator.delegate(second, _context())

    stored = await coordinator.get(identity)
    assert stored.child_run_id == admitted.child_run_id
    assert (await coordinator.snapshot()).delegations == 1


@pytest.mark.asyncio
async def test_exact_lifecycle_is_admitted_running_terminal() -> None:
    limits = _limits()
    coordinator = _coordinator(
        _registry("researcher"),
        _RecordingAuthorizer(),
        limits=limits,
    )
    request = _request("researcher", limits=limits)

    admitted = await coordinator.delegate(request, _context())
    running = await coordinator.start(request.delegation_id, now=_NOW)
    completed = await coordinator.complete(request.delegation_id, now=_NOW)

    assert admitted.status is DelegationStatus.ADMITTED
    assert running.status is DelegationStatus.RUNNING
    assert completed.status is DelegationStatus.COMPLETED
    assert (await coordinator.snapshot()).active == 0

    with pytest.raises(AgentStateConflictError):
        await coordinator.fail(request.delegation_id, now=_NOW)


@pytest.mark.asyncio
async def test_concurrency_queues_then_admits_after_release() -> None:
    limits = _limits(concurrent=1, queue=1)
    coordinator = _coordinator(
        _registry("first", "second"),
        _RecordingAuthorizer(),
        limits=limits,
    )
    root = AgentRunId()
    first = _request("first", limits=limits, root_run=root, parent_run=root)
    second = _request("second", limits=limits, root_run=root, parent_run=root)

    admitted_first = await coordinator.delegate(first, _context())
    assert admitted_first.status is DelegationStatus.ADMITTED

    pending = asyncio.create_task(coordinator.delegate(second, _context()))
    await asyncio.sleep(0)

    snapshot = await coordinator.snapshot()
    assert snapshot.active == 1
    assert snapshot.queued == 1

    await coordinator.start(first.delegation_id, now=_NOW)
    await coordinator.complete(first.delegation_id, now=_NOW)

    admitted_second = await asyncio.wait_for(pending, timeout=1)
    assert admitted_second.status is DelegationStatus.ADMITTED
    assert (await coordinator.snapshot()).active == 1


@pytest.mark.asyncio
async def test_queue_capacity_rejects_saturation_without_unbounded_waiters() -> None:
    limits = _limits(concurrent=1, queue=1)
    coordinator = _coordinator(
        _registry("first", "second", "third"),
        _RecordingAuthorizer(),
        limits=limits,
    )
    root = AgentRunId()
    first = _request("first", limits=limits, root_run=root, parent_run=root)
    second = _request("second", limits=limits, root_run=root, parent_run=root)
    third = _request("third", limits=limits, root_run=root, parent_run=root)

    await coordinator.delegate(first, _context())
    queued = asyncio.create_task(coordinator.delegate(second, _context()))
    await asyncio.sleep(0)

    with pytest.raises(AgentLimitExceededError):
        await coordinator.delegate(third, _context())

    assert (await coordinator.snapshot()).queued == 1

    await coordinator.start(first.delegation_id, now=_NOW)
    await coordinator.complete(first.delegation_id, now=_NOW)
    await asyncio.wait_for(queued, timeout=1)


@pytest.mark.asyncio
async def test_fanout_limit_is_lifetime_bound_not_concurrency_bound() -> None:
    limits = _limits(fan_out=1, concurrent=1)
    coordinator = _coordinator(
        _registry("first", "second"),
        _RecordingAuthorizer(),
        limits=limits,
        root_children=2,
    )
    parent = AgentRunId()
    first = _request("first", limits=limits, parent_run=parent, root_run=parent)
    second = _request("second", limits=limits, parent_run=parent, root_run=parent)

    await coordinator.delegate(first, _context())
    await coordinator.start(first.delegation_id, now=_NOW)
    await coordinator.complete(first.delegation_id, now=_NOW)

    with pytest.raises(AgentLimitExceededError):
        await coordinator.delegate(second, _context())


@pytest.mark.asyncio
async def test_root_budget_prevents_child_budget_multiplication() -> None:
    limits = _limits(fan_out=4, total=4, concurrent=2)
    coordinator = _coordinator(
        _registry("first", "second"),
        _RecordingAuthorizer(),
        limits=limits,
        root_children=1,
    )
    root = AgentRunId()
    first = _request("first", limits=limits, root_run=root, parent_run=root)
    second = _request("second", limits=limits, root_run=root, parent_run=root)

    await coordinator.delegate(first, _context())
    await coordinator.start(first.delegation_id, now=_NOW)
    await coordinator.complete(first.delegation_id, now=_NOW)

    with pytest.raises(AgentLimitExceededError):
        await coordinator.delegate(second, _context())

    assert coordinator.root_budget_snapshot(root).children == 1


@pytest.mark.asyncio
async def test_cycle_is_rejected_before_coordinator_can_create_child() -> None:
    limits = _limits()
    coordinator = _coordinator(
        _registry("root"),
        _RecordingAuthorizer(),
        limits=limits,
    )
    root_run = AgentRunId()
    lineage = DelegationLineage((DelegationLineageEntry(AgentId("root"), root_run),))

    with pytest.raises(ValueError, match="cycle"):
        _request(
            "root",
            limits=limits,
            parent_run=root_run,
            root_run=root_run,
            parent_agent="root",
            lineage=lineage,
        )

    assert (await coordinator.snapshot()).delegations == 0


@pytest.mark.asyncio
async def test_unknown_delegation_lookup_is_safe() -> None:
    coordinator = _coordinator(
        _registry("researcher"),
        _RecordingAuthorizer(),
        limits=_limits(),
    )

    with pytest.raises(DelegationNotFoundError):
        await coordinator.get(DelegationId())


@pytest.mark.asyncio
async def test_session_backed_delegation_without_freshness_validator_fails_closed() -> None:
    limits = _limits()
    authorizer = _RecordingAuthorizer()
    coordinator = _coordinator(_registry("researcher"), authorizer, limits=limits)
    context = SecurityContext(
        principal="service:parent",
        principal_type=PrincipalType.SERVICE,
        authenticated=True,
        session_id=UUID("72000000-0000-4000-8000-000000000033"),
    )

    with pytest.raises(AgentAuthorizationRejectedError):
        await coordinator.delegate(_request("researcher", limits=limits), context)

    assert authorizer.calls == []
    snapshot = await coordinator.snapshot()
    assert snapshot.delegations == 0
    assert snapshot.active == 0
    assert snapshot.queued == 0


@pytest.mark.asyncio
async def test_queued_delegation_revalidates_subject_and_policy_after_wait() -> None:
    limits = _limits(concurrent=1, queue=1)
    authorizer = _RecordingAuthorizer()
    freshness = _RecordingFreshnessValidator()
    coordinator = _coordinator(
        _registry("first", "second"),
        authorizer,
        limits=limits,
        authority_freshness=freshness,
    )
    root = AgentRunId()
    first = _request("first", limits=limits, root_run=root, parent_run=root)
    second = _request("second", limits=limits, root_run=root, parent_run=root)
    first_context = _context()
    second_context = _context()

    await coordinator.delegate(first, first_context)
    pending = asyncio.create_task(coordinator.delegate(second, second_context))

    for _ in range(32):
        if (await coordinator.snapshot()).queued == 1:
            break
        await asyncio.sleep(0)
    assert (await coordinator.snapshot()).queued == 1

    await coordinator.start(first.delegation_id, now=_NOW)
    await coordinator.complete(first.delegation_id, now=_NOW)
    admitted = await asyncio.wait_for(pending, timeout=1)

    assert admitted.status is DelegationStatus.ADMITTED
    assert authorizer.calls == [
        first.delegation_id,
        second.delegation_id,
        second.delegation_id,
    ]
    assert freshness.contexts == [first_context, second_context, second_context]
    assert freshness.contexts[0] is first_context
    assert freshness.contexts[1] is second_context
    assert freshness.contexts[2] is second_context


@pytest.mark.asyncio
async def test_queued_delegation_policy_revocation_blocks_fresh_admission() -> None:
    limits = _limits(concurrent=1, queue=1)
    policy = PolicyEngine()
    rule = PolicyRule(
        rule_id="allow-queued-delegation",
        effect=PolicyEffect.ALLOW,
        actions=frozenset({AGENT_DELEGATE_ACTION}),
        resources=frozenset(
            {
                agent_delegation_resource(
                    namespace=CoordinationNamespace("default"),
                    parent_agent_id=AgentId("parent"),
                    child_agent_id=AgentId("first"),
                ),
                agent_delegation_resource(
                    namespace=CoordinationNamespace("default"),
                    parent_agent_id=AgentId("parent"),
                    child_agent_id=AgentId("second"),
                ),
            }
        ),
        principals=frozenset({"service:parent"}),
        authenticated=True,
    )
    registration = await policy.register(rule)
    coordinator = _coordinator(
        _registry("first", "second"),
        PolicyEngineDelegationAuthorizer(policy),
        limits=limits,
    )
    root = AgentRunId()
    first = _request("first", limits=limits, root_run=root, parent_run=root)
    second = _request("second", limits=limits, root_run=root, parent_run=root)
    context = _context()

    await coordinator.delegate(first, context)
    pending = asyncio.create_task(coordinator.delegate(second, context))

    for _ in range(32):
        if (await coordinator.snapshot()).queued == 1:
            break
        await asyncio.sleep(0)
    assert (await coordinator.snapshot()).queued == 1

    assert await policy.unregister(registration)
    await coordinator.start(first.delegation_id, now=_NOW)
    await coordinator.complete(first.delegation_id, now=_NOW)

    with pytest.raises(AgentAuthorizationRejectedError):
        await asyncio.wait_for(pending, timeout=1)

    snapshot = await coordinator.snapshot()
    assert snapshot.active == 0
    assert snapshot.queued == 0
    assert snapshot.failed == 1

    policy_snapshot = await policy.snapshot()
    assert (policy_snapshot.allowed, policy_snapshot.denied) == (2, 1)
