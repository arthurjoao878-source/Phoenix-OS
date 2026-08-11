import asyncio
import json
from datetime import UTC, datetime, timedelta

import pytest

from phoenix_os.agent import (
    AgentCancellationToken,
    AgentCancelledError,
    AgentCoordinationConfiguration,
    AgentCoordinationRuntime,
    AgentDelegationCoordinator,
    AgentDelegationRegistry,
    AgentId,
    AgentLimits,
    AgentRunId,
    AgentRunRequest,
    AgentRunResult,
    AgentRunStatus,
    AgentServiceConfiguration,
    ChildResultStatus,
    CoordinationNamespace,
    DelegableAgentDescriptor,
    DelegationBudget,
    DelegationDepth,
    DelegationLimits,
    DelegationLineage,
    DelegationLineageEntry,
    DelegationRequest,
)
from phoenix_os.inference import ModelId, ModelProviderId
from phoenix_os.policy import PrincipalType, SecurityContext
from phoenix_os.runtime import RuntimeContext

_NOW = datetime(2026, 8, 10, 18, 30, tzinfo=UTC)


class _RecordingAuthorizer:
    async def authorize(
        self,
        request: DelegationRequest,
        descriptor: DelegableAgentDescriptor,
        context: SecurityContext,
    ) -> None:
        assert descriptor.agent_id == request.child_agent_id
        assert context.authenticated


class _FakeChildService:
    def __init__(self, agent_id: str, *, block: bool = False) -> None:
        self._configuration = AgentServiceConfiguration(
            agent_id=AgentId(agent_id),
            provider_id=ModelProviderId("local"),
            model_id=ModelId("chat"),
            limits=AgentLimits(
                max_model_turns=4,
                max_tool_calls=2,
                max_input_tokens=16_384,
                max_output_tokens=8_192,
                max_prompt_bytes=65_536,
                max_result_bytes=262_144,
                approval_wait_timeout=timedelta(minutes=5),
                total_duration=timedelta(minutes=5),
            ),
        )
        self.block = block
        self.started = asyncio.Event()
        self.requests: list[AgentRunRequest] = []

    @property
    def configuration(self) -> AgentServiceConfiguration:
        return self._configuration

    async def run(
        self,
        request: AgentRunRequest,
        context: SecurityContext,
        *,
        cancellation: AgentCancellationToken | None = None,
    ) -> AgentRunResult:
        assert context.authenticated
        self.requests.append(request)
        self.started.set()
        if self.block:
            assert cancellation is not None
            await cancellation.wait()
            return AgentRunResult(
                run_id=request.run_id,
                status=AgentRunStatus.CANCELLED,
                model_turns=0,
                tool_calls=0,
                error_code="cancelled",
                started_at=_NOW,
                completed_at=_NOW,
            )
        return AgentRunResult(
            run_id=request.run_id,
            status=AgentRunStatus.COMPLETED,
            model_turns=1,
            tool_calls=0,
            final_output="child answer",
            started_at=_NOW,
            completed_at=_NOW,
        )


def _context() -> SecurityContext:
    return SecurityContext(
        principal="service:parent",
        principal_type=PrincipalType.SERVICE,
        authenticated=True,
    )


def _limits(*, concurrent: int = 2, queue: int = 4) -> DelegationLimits:
    return DelegationLimits(
        max_depth=3,
        max_fan_out=4,
        max_total_children=8,
        max_concurrent_children=concurrent,
        max_queue_depth=queue,
        max_input_bytes=16_384,
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
        max_prompt_bytes=16_384,
        max_result_bytes=65_536,
        duration=timedelta(minutes=2),
    )


def _root_budget(children: int = 4) -> DelegationBudget:
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


def _descriptor(service: _FakeChildService) -> DelegableAgentDescriptor:
    return DelegableAgentDescriptor(
        configuration=service.configuration,
        namespace=CoordinationNamespace("default"),
        allowed_parent_agents=(AgentId("parent"),),
        compatibility_digest="sha256:" + "a" * 64,
        allow_nested_delegation=True,
        max_accepted_depth=DelegationDepth(3),
    )


def _runtime(
    services: tuple[_FakeChildService, ...],
    *,
    limits: DelegationLimits,
) -> AgentCoordinationRuntime:
    registry = AgentDelegationRegistry()
    for service in services:
        registry.register_agent(_descriptor(service))
    coordinator = AgentDelegationCoordinator(
        registry,
        _RecordingAuthorizer(),
        limits=limits,
        root_budget_limit=_root_budget(),
        clock=lambda: _NOW,
    )
    return AgentCoordinationRuntime(
        coordinator,
        AgentCoordinationConfiguration(
            namespace=CoordinationNamespace("default"),
            limits=limits,
            root_budget_limit=_root_budget(),
            shutdown_grace=timedelta(seconds=1),
            cancellation_grace=timedelta(seconds=1),
        ),
        {service.configuration.agent_id: service for service in services},
        clock=lambda: _NOW,
    )


def _request(
    child: str,
    *,
    limits: DelegationLimits,
    root_run: AgentRunId | None = None,
    parent_run: AgentRunId | None = None,
) -> DelegationRequest:
    selected_root = root_run or AgentRunId()
    selected_parent = parent_run or selected_root
    lineage = DelegationLineage((DelegationLineageEntry(AgentId("parent"), selected_parent),))
    return DelegationRequest(
        parent_agent_id=AgentId("parent"),
        parent_run_id=selected_parent,
        child_agent_id=AgentId(child),
        namespace=CoordinationNamespace("default"),
        lineage=lineage,
        input={"task": "bounded work", "priority": 1},
        budget=_child_budget(),
        limits=limits,
        created_at=_NOW,
        deadline=_NOW + timedelta(minutes=2),
    )


@pytest.mark.asyncio
async def test_runtime_builds_tight_child_request_and_validates_result() -> None:
    limits = _limits()
    service = _FakeChildService("child")
    runtime = _runtime((service,), limits=limits)
    await runtime.start(RuntimeContext(services={}))

    request = _request("child", limits=limits)
    result = await runtime.delegate_and_run(request, _context())

    assert result.status is ChildResultStatus.SUCCEEDED
    assert result.output == {"final_output": "child answer"}
    assert len(service.requests) == 1

    child_request = service.requests[0]
    assert child_request.run_id == result.child_run_id
    assert child_request.limits.max_model_turns == request.budget.max_model_turns
    assert child_request.limits.max_tool_calls == request.budget.max_tool_calls
    assert json.loads(child_request.messages[0].content) == {
        "priority": 1,
        "task": "bounded work",
    }


@pytest.mark.asyncio
async def test_parent_cancellation_propagates_to_active_child() -> None:
    limits = _limits()
    service = _FakeChildService("child", block=True)
    runtime = _runtime((service,), limits=limits)
    await runtime.start(RuntimeContext(services={}))
    parent = AgentCancellationToken()

    task = asyncio.create_task(
        runtime.delegate_and_run(
            _request("child", limits=limits),
            _context(),
            parent_cancellation=parent,
        )
    )
    await asyncio.wait_for(service.started.wait(), timeout=1)
    parent.cancel()

    result = await asyncio.wait_for(task, timeout=1)
    assert result.status is ChildResultStatus.CANCELLED
    assert (await runtime.snapshot()).active_children == 0


@pytest.mark.asyncio
async def test_cancelled_queued_delegation_is_never_admitted() -> None:
    limits = _limits(concurrent=1, queue=1)
    first = _FakeChildService("first", block=True)
    second = _FakeChildService("second")
    runtime = _runtime((first, second), limits=limits)
    await runtime.start(RuntimeContext(services={}))

    root = AgentRunId()
    first_parent = AgentCancellationToken()
    first_task = asyncio.create_task(
        runtime.delegate_and_run(
            _request("first", limits=limits, root_run=root, parent_run=root),
            _context(),
            parent_cancellation=first_parent,
        )
    )
    await asyncio.wait_for(first.started.wait(), timeout=1)

    second_parent = AgentCancellationToken()
    second_task = asyncio.create_task(
        runtime.delegate_and_run(
            _request("second", limits=limits, root_run=root, parent_run=root),
            _context(),
            parent_cancellation=second_parent,
        )
    )
    await asyncio.sleep(0)
    second_parent.cancel()

    with pytest.raises(AgentCancelledError):
        await asyncio.wait_for(second_task, timeout=1)
    assert second.requests == []

    first_parent.cancel()
    await asyncio.wait_for(first_task, timeout=1)


@pytest.mark.asyncio
async def test_stop_cancels_active_children_and_rejects_new_work() -> None:
    limits = _limits()
    service = _FakeChildService("child", block=True)
    runtime = _runtime((service,), limits=limits)
    context = RuntimeContext(services={})
    await runtime.start(context)

    task = asyncio.create_task(
        runtime.delegate_and_run(_request("child", limits=limits), _context())
    )
    await asyncio.wait_for(service.started.wait(), timeout=1)

    await runtime.stop(context)
    await asyncio.wait_for(task, timeout=1)

    snapshot = await runtime.snapshot()
    assert not snapshot.accepting
    assert snapshot.active_children == 0
