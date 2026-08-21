from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from phoenix_os.agent import (
    AgentId,
    AgentLoop,
    AgentMessage,
    AgentMessageRole,
    AgentRunRequest,
    AgentRunStatus,
    BoundedAgentExecutor,
    DeterministicFinalTurn,
    DeterministicModelTurnAdapter,
    DeterministicToolTurn,
    InMemoryToolApprovalService,
    PolicyEngineAgentRunAuthorizer,
    PolicyEngineToolAuthorizer,
    ToolApprovalChallenge,
    ToolApprovalEvidence,
    ToolDescriptor,
    ToolInvocationRequest,
    ToolRegistry,
    agent_run_resource,
)
from phoenix_os.host_automation import (
    HOST_APPLICATION_LAUNCH_ACTION,
    HOST_APPLICATION_LAUNCH_TOOL_ID,
    HOST_PROCESS_LIST_ACTION,
    HOST_PROCESS_LIST_TOOL_ID,
    DeterministicHostAutomationAdapter,
    HostApplicationId,
    HostApplicationLaunchRequest,
    HostApplicationLaunchResult,
    HostApplicationLaunchToolAdapter,
    HostAutomationLimits,
    HostAutomationService,
    HostId,
    HostProcessListRequest,
    HostProcessListResult,
    HostProcessListToolAdapter,
    PolicyEngineHostAutomationAuthorizer,
    host_application_launch_tool_descriptor,
    host_application_launch_tool_resolver,
    host_application_resource,
    host_process_collection_resource,
    host_process_list_tool_descriptor,
    host_process_list_tool_resolver,
)
from phoenix_os.inference import InferenceRequest, ModelId, ModelProviderId
from phoenix_os.policy import (
    PolicyEffect,
    PolicyEngine,
    PolicyRule,
    PrincipalType,
    SecurityContext,
)

_NOW = datetime(2026, 8, 21, 18, tzinfo=UTC)
_AGENT_ID = AgentId("assistant")
_HOST_ID = HostId("desktop")
_APP_ID = HostApplicationId("editor")
_REQUESTER = "service:requester"
_INTERNAL_HOST = "service:host-internal"
_APPROVER = "service:approver"


def _context(principal: str = _REQUESTER) -> SecurityContext:
    return SecurityContext(
        principal=principal,
        principal_type=PrincipalType.SERVICE,
        authenticated=True,
    )


def _request() -> AgentRunRequest:
    return AgentRunRequest(
        agent_id=_AGENT_ID,
        provider_id=ModelProviderId("local"),
        model_id=ModelId("chat"),
        messages=(AgentMessage(AgentMessageRole.USER, "list processes"),),
        created_at=_NOW,
        deadline=_NOW + timedelta(minutes=2),
    )


def _limits() -> HostAutomationLimits:
    return HostAutomationLimits(
        max_process_results=4,
        max_window_results=4,
        max_process_label_chars=256,
        max_window_title_chars=512,
        operation_timeout=timedelta(seconds=30),
    )


def _allow_rule(
    rule_id: str,
    *,
    action: str,
    resource: str,
    principal: str,
) -> PolicyRule:
    return PolicyRule(
        rule_id=rule_id,
        effect=PolicyEffect.ALLOW,
        actions=frozenset({action}),
        resources=frozenset({resource}),
        principals=frozenset({principal}),
        authenticated=True,
    )


def _run_policy(principal: str) -> PolicyEngine:
    return PolicyEngine(
        (
            _allow_rule(
                "allow-agent-run",
                action="agent.run",
                resource=agent_run_resource(_AGENT_ID),
                principal=principal,
            ),
        )
    )


def _tool_policy(principal: str) -> PolicyEngine:
    host_resource = host_process_collection_resource(_HOST_ID)
    return PolicyEngine(
        (
            _allow_rule(
                "allow-tool-invoke",
                action="tool.invoke",
                resource=f"tool:{HOST_PROCESS_LIST_TOOL_ID}/{host_resource}",
                principal=principal,
            ),
        )
    )


def _host_policy(principal: str) -> PolicyEngine:
    return PolicyEngine(
        (
            _allow_rule(
                "allow-host-process-list",
                action=HOST_PROCESS_LIST_ACTION,
                resource=host_process_collection_resource(_HOST_ID),
                principal=principal,
            ),
        )
    )


def _launch_tool_policy(principal: str) -> PolicyEngine:
    resource = host_application_resource(_HOST_ID, _APP_ID)
    return PolicyEngine(
        (
            _allow_rule(
                "allow-launch-tool-invoke",
                action="tool.invoke",
                resource=f"tool:{HOST_APPLICATION_LAUNCH_TOOL_ID}/{resource}",
                principal=principal,
            ),
        )
    )


def _launch_host_policy(principal: str) -> PolicyEngine:
    return PolicyEngine(
        (
            _allow_rule(
                "allow-host-application-launch",
                action=HOST_APPLICATION_LAUNCH_ACTION,
                resource=host_application_resource(_HOST_ID, _APP_ID),
                principal=principal,
            ),
        )
    )


class _AllowModelAuthorizer:
    async def authorize(
        self,
        request: InferenceRequest,
        context: SecurityContext,
    ) -> None:
        assert isinstance(request, InferenceRequest)
        assert context.authenticated


class _ImmediateApprovalResolver:
    def __init__(
        self,
        service: InMemoryToolApprovalService,
        approver: SecurityContext,
    ) -> None:
        self.service = service
        self.approver = approver
        self.challenges: list[ToolApprovalChallenge] = []

    async def resolve(self, challenge: ToolApprovalChallenge) -> ToolApprovalEvidence:
        self.challenges.append(challenge)
        return await self.service.approve(challenge.approval_id, self.approver)


class _RecordingRunAuthorizer(PolicyEngineAgentRunAuthorizer):
    def __init__(self, policy: PolicyEngine) -> None:
        super().__init__(policy)
        self.requests: list[AgentRunRequest] = []
        self.contexts: list[SecurityContext] = []

    async def authorize(
        self,
        request: AgentRunRequest,
        context: SecurityContext,
    ) -> None:
        self.requests.append(request)
        self.contexts.append(context)
        await super().authorize(request, context)


class _RecordingToolAuthorizer(PolicyEngineToolAuthorizer):
    def __init__(self, policy: PolicyEngine) -> None:
        super().__init__(policy)
        self.requests: list[ToolInvocationRequest] = []
        self.contexts: list[SecurityContext] = []

    async def authorize(
        self,
        request: ToolInvocationRequest,
        descriptor: ToolDescriptor,
        context: SecurityContext,
    ) -> None:
        self.requests.append(request)
        self.contexts.append(context)
        await super().authorize(request, descriptor, context)


class _RecordingHostAuthorizer(PolicyEngineHostAutomationAuthorizer):
    def __init__(self, policy: PolicyEngine) -> None:
        super().__init__(policy)
        self.process_list_contexts: list[SecurityContext] = []
        self.application_launch_contexts: list[SecurityContext] = []

    async def authorize_process_list(
        self,
        request: HostProcessListRequest,
        context: SecurityContext,
    ) -> None:
        self.process_list_contexts.append(context)
        await super().authorize_process_list(request, context)

    async def authorize_application_launch(
        self,
        request: HostApplicationLaunchRequest,
        context: SecurityContext,
    ) -> None:
        self.application_launch_contexts.append(context)
        await super().authorize_application_launch(request, context)


class _CountingHostAdapter(DeterministicHostAutomationAdapter):
    def __init__(self, limits: HostAutomationLimits) -> None:
        super().__init__(
            host_id=_HOST_ID,
            limits=limits,
            applications=(_APP_ID,),
        )
        self.process_list_calls = 0
        self.application_launch_calls = 0

    async def list_processes(
        self,
        request: HostProcessListRequest,
    ) -> HostProcessListResult:
        self.process_list_calls += 1
        return await super().list_processes(request)

    async def launch_application(
        self,
        request: HostApplicationLaunchRequest,
    ) -> HostApplicationLaunchResult:
        self.application_launch_calls += 1
        return await super().launch_application(request)


def _composition_path(
    *,
    run_policy: PolicyEngine,
    tool_policy: PolicyEngine,
    host_policy: PolicyEngine,
) -> tuple[
    AgentLoop,
    _RecordingRunAuthorizer,
    _RecordingToolAuthorizer,
    _RecordingHostAuthorizer,
    _CountingHostAdapter,
]:
    limits = _limits()
    native = _CountingHostAdapter(limits)
    host_authorizer = _RecordingHostAuthorizer(host_policy)
    service = HostAutomationService(
        adapter=native,
        authorizer=host_authorizer,
    )

    registry = ToolRegistry()
    registry.register_tool(
        host_process_list_tool_descriptor(limits),
        resolver=host_process_list_tool_resolver(_HOST_ID),
        adapter=HostProcessListToolAdapter(
            service,
            host_id=_HOST_ID,
            limits=limits,
        ),
    )

    run_authorizer = _RecordingRunAuthorizer(run_policy)
    tool_authorizer = _RecordingToolAuthorizer(tool_policy)
    loop = AgentLoop(
        run_authorizer=run_authorizer,
        model_authorizer=_AllowModelAuthorizer(),
        tool_authorizer=tool_authorizer,
        model_adapter=DeterministicModelTurnAdapter(
            (
                DeterministicToolTurn(
                    HOST_PROCESS_LIST_TOOL_ID,
                    {"limit": 1},
                ),
                DeterministicFinalTurn("complete"),
            )
        ),
        registry=registry,
        executor=BoundedAgentExecutor(clock=lambda: _NOW),
        clock=lambda: _NOW,
    )
    return loop, run_authorizer, tool_authorizer, host_authorizer, native


def _effectful_composition_path(
    *,
    run_policy: PolicyEngine,
    tool_policy: PolicyEngine,
    host_policy: PolicyEngine,
) -> tuple[
    AgentLoop,
    _RecordingRunAuthorizer,
    _RecordingToolAuthorizer,
    _RecordingHostAuthorizer,
    _CountingHostAdapter,
    InMemoryToolApprovalService,
    _ImmediateApprovalResolver,
]:
    limits = _limits()
    native = _CountingHostAdapter(limits)
    host_authorizer = _RecordingHostAuthorizer(host_policy)
    service = HostAutomationService(
        adapter=native,
        authorizer=host_authorizer,
    )

    registry = ToolRegistry()
    registry.register_tool(
        host_application_launch_tool_descriptor(limits),
        resolver=host_application_launch_tool_resolver(_HOST_ID, (_APP_ID,)),
        adapter=HostApplicationLaunchToolAdapter(
            service,
            host_id=_HOST_ID,
            limits=limits,
            applications=(_APP_ID,),
        ),
    )

    approval_service = InMemoryToolApprovalService(clock=lambda: _NOW)
    approval_resolver = _ImmediateApprovalResolver(
        approval_service,
        _context(_APPROVER),
    )
    run_authorizer = _RecordingRunAuthorizer(run_policy)
    tool_authorizer = _RecordingToolAuthorizer(tool_policy)
    loop = AgentLoop(
        run_authorizer=run_authorizer,
        model_authorizer=_AllowModelAuthorizer(),
        tool_authorizer=tool_authorizer,
        model_adapter=DeterministicModelTurnAdapter(
            (
                DeterministicToolTurn(
                    HOST_APPLICATION_LAUNCH_TOOL_ID,
                    {"application_id": str(_APP_ID)},
                ),
                DeterministicFinalTurn("complete"),
            )
        ),
        registry=registry,
        executor=BoundedAgentExecutor(clock=lambda: _NOW),
        approval_service=approval_service,
        approval_resolver=approval_resolver,
        clock=lambda: _NOW,
    )
    return (
        loop,
        run_authorizer,
        tool_authorizer,
        host_authorizer,
        native,
        approval_service,
        approval_resolver,
    )


@pytest.mark.asyncio
async def test_agent_tool_host_path_cannot_bypass_agent_run_boundary() -> None:
    context = _context()
    request = _request()
    run_policy = _run_policy(_INTERNAL_HOST)
    tool_policy = _tool_policy(_REQUESTER)
    host_policy = _host_policy(_REQUESTER)
    loop, run_authorizer, tool_authorizer, host_authorizer, native = _composition_path(
        run_policy=run_policy,
        tool_policy=tool_policy,
        host_policy=host_policy,
    )

    result = await loop.run(request, context)

    assert result.status is AgentRunStatus.FAILED
    assert result.error_code == "authorization_rejected"
    assert run_authorizer.contexts == [context]
    assert run_authorizer.contexts[0] is context
    assert tool_authorizer.contexts == []
    assert host_authorizer.process_list_contexts == []
    assert native.process_list_calls == 0

    run_snapshot = await run_policy.snapshot()
    tool_snapshot = await tool_policy.snapshot()
    host_snapshot = await host_policy.snapshot()
    assert (run_snapshot.allowed, run_snapshot.denied) == (0, 1)
    assert (tool_snapshot.allowed, tool_snapshot.denied) == (0, 0)
    assert (host_snapshot.allowed, host_snapshot.denied) == (0, 0)


@pytest.mark.asyncio
async def test_agent_tool_host_path_cannot_bypass_tool_boundary() -> None:
    context = _context()
    request = _request()
    run_policy = _run_policy(_REQUESTER)
    tool_policy = _tool_policy(_INTERNAL_HOST)
    host_policy = _host_policy(_REQUESTER)
    loop, run_authorizer, tool_authorizer, host_authorizer, native = _composition_path(
        run_policy=run_policy,
        tool_policy=tool_policy,
        host_policy=host_policy,
    )

    result = await loop.run(request, context)

    assert result.status is AgentRunStatus.FAILED
    assert result.error_code == "authorization_rejected"
    assert run_authorizer.contexts == [context]
    assert tool_authorizer.contexts == [context]
    assert tool_authorizer.contexts[0] is context
    assert host_authorizer.process_list_contexts == []
    assert native.process_list_calls == 0

    run_snapshot = await run_policy.snapshot()
    tool_snapshot = await tool_policy.snapshot()
    host_snapshot = await host_policy.snapshot()
    assert (run_snapshot.allowed, run_snapshot.denied) == (1, 0)
    assert (tool_snapshot.allowed, tool_snapshot.denied) == (0, 1)
    assert (host_snapshot.allowed, host_snapshot.denied) == (0, 0)


@pytest.mark.asyncio
async def test_agent_tool_host_path_does_not_substitute_stronger_internal_identity() -> None:
    context = _context()
    request = _request()
    run_policy = _run_policy(_REQUESTER)
    tool_policy = _tool_policy(_REQUESTER)
    host_policy = _host_policy(_INTERNAL_HOST)
    loop, run_authorizer, tool_authorizer, host_authorizer, native = _composition_path(
        run_policy=run_policy,
        tool_policy=tool_policy,
        host_policy=host_policy,
    )

    result = await loop.run(request, context)

    assert result.status is AgentRunStatus.FAILED
    assert result.error_code == "tool_failed"
    assert run_authorizer.contexts == [context]
    assert len(tool_authorizer.contexts) == 2
    assert all(item is context for item in tool_authorizer.contexts)
    assert host_authorizer.process_list_contexts == [context]
    assert host_authorizer.process_list_contexts[0] is context
    assert host_authorizer.process_list_contexts[0].principal == _REQUESTER
    assert host_authorizer.process_list_contexts[0].principal != _INTERNAL_HOST
    assert native.process_list_calls == 0

    run_snapshot = await run_policy.snapshot()
    tool_snapshot = await tool_policy.snapshot()
    host_snapshot = await host_policy.snapshot()
    assert (run_snapshot.allowed, run_snapshot.denied) == (1, 0)
    assert (tool_snapshot.allowed, tool_snapshot.denied) == (2, 0)
    assert (host_snapshot.allowed, host_snapshot.denied) == (0, 1)


@pytest.mark.asyncio
async def test_agent_tool_host_path_requires_full_intersection_and_preserves_subject() -> None:
    context = _context()
    request = _request()
    run_policy = _run_policy(_REQUESTER)
    tool_policy = _tool_policy(_REQUESTER)
    host_policy = _host_policy(_REQUESTER)
    loop, run_authorizer, tool_authorizer, host_authorizer, native = _composition_path(
        run_policy=run_policy,
        tool_policy=tool_policy,
        host_policy=host_policy,
    )

    result = await loop.run(request, context)

    assert result.status is AgentRunStatus.COMPLETED
    assert result.final_output == "complete"
    assert run_authorizer.requests == [request]
    assert run_authorizer.contexts == [context]
    assert run_authorizer.contexts[0] is context

    assert len(tool_authorizer.requests) == 2
    assert tool_authorizer.requests[0] is tool_authorizer.requests[1]
    assert tool_authorizer.requests[0].agent_id == request.agent_id
    assert tool_authorizer.requests[0].run_id == request.run_id
    assert len(tool_authorizer.contexts) == 2
    assert all(item is context for item in tool_authorizer.contexts)

    assert host_authorizer.process_list_contexts == [context]
    assert host_authorizer.process_list_contexts[0] is context
    assert native.process_list_calls == 1

    run_snapshot = await run_policy.snapshot()
    tool_snapshot = await tool_policy.snapshot()
    host_snapshot = await host_policy.snapshot()
    assert (run_snapshot.allowed, run_snapshot.denied) == (1, 0)
    assert (tool_snapshot.allowed, tool_snapshot.denied) == (2, 0)
    assert (host_snapshot.allowed, host_snapshot.denied) == (1, 0)


@pytest.mark.asyncio
async def test_effectful_agent_tool_host_approval_cannot_replace_requester_subject() -> None:
    context = _context()
    request = _request()
    run_policy = _run_policy(_REQUESTER)
    tool_policy = _launch_tool_policy(_REQUESTER)
    host_policy = _launch_host_policy(_APPROVER)
    (
        loop,
        run_authorizer,
        tool_authorizer,
        host_authorizer,
        native,
        approval_service,
        approval_resolver,
    ) = _effectful_composition_path(
        run_policy=run_policy,
        tool_policy=tool_policy,
        host_policy=host_policy,
    )

    result = await loop.run(request, context)

    assert result.status is AgentRunStatus.FAILED
    assert result.error_code == "tool_failed"
    assert run_authorizer.contexts == [context]
    assert len(tool_authorizer.contexts) == 2
    assert all(item is context for item in tool_authorizer.contexts)
    assert len(approval_resolver.challenges) == 1
    assert approval_resolver.approver.principal == _APPROVER
    assert host_authorizer.application_launch_contexts == [context]
    assert host_authorizer.application_launch_contexts[0] is context
    assert host_authorizer.application_launch_contexts[0].principal == _REQUESTER
    assert host_authorizer.application_launch_contexts[0].principal != _APPROVER
    assert native.application_launch_calls == 0

    approval_snapshot = await approval_service.snapshot()
    assert approval_snapshot.consumed == 1
    assert approval_snapshot.pending == 0

    run_snapshot = await run_policy.snapshot()
    tool_snapshot = await tool_policy.snapshot()
    host_snapshot = await host_policy.snapshot()
    assert (run_snapshot.allowed, run_snapshot.denied) == (1, 0)
    assert (tool_snapshot.allowed, tool_snapshot.denied) == (2, 0)
    assert (host_snapshot.allowed, host_snapshot.denied) == (0, 1)


@pytest.mark.asyncio
async def test_effectful_agent_tool_host_requires_approval_and_full_intersection() -> None:
    context = _context()
    request = _request()
    run_policy = _run_policy(_REQUESTER)
    tool_policy = _launch_tool_policy(_REQUESTER)
    host_policy = _launch_host_policy(_REQUESTER)
    (
        loop,
        run_authorizer,
        tool_authorizer,
        host_authorizer,
        native,
        approval_service,
        approval_resolver,
    ) = _effectful_composition_path(
        run_policy=run_policy,
        tool_policy=tool_policy,
        host_policy=host_policy,
    )

    result = await loop.run(request, context)

    assert result.status is AgentRunStatus.COMPLETED
    assert result.final_output == "complete"
    assert run_authorizer.contexts == [context]
    assert len(tool_authorizer.requests) == 2
    assert tool_authorizer.requests[0] is tool_authorizer.requests[1]
    assert tool_authorizer.requests[0].agent_id == request.agent_id
    assert tool_authorizer.requests[0].run_id == request.run_id
    assert all(item is context for item in tool_authorizer.contexts)
    assert len(approval_resolver.challenges) == 1
    assert approval_resolver.approver.principal == _APPROVER
    assert host_authorizer.application_launch_contexts == [context]
    assert host_authorizer.application_launch_contexts[0] is context
    assert host_authorizer.application_launch_contexts[0].principal == _REQUESTER
    assert host_authorizer.application_launch_contexts[0].principal != _APPROVER
    assert native.application_launch_calls == 1

    approval_snapshot = await approval_service.snapshot()
    assert approval_snapshot.consumed == 1
    assert approval_snapshot.pending == 0

    run_snapshot = await run_policy.snapshot()
    tool_snapshot = await tool_policy.snapshot()
    host_snapshot = await host_policy.snapshot()
    assert (run_snapshot.allowed, run_snapshot.denied) == (1, 0)
    assert (tool_snapshot.allowed, tool_snapshot.denied) == (2, 0)
    assert (host_snapshot.allowed, host_snapshot.denied) == (1, 0)
