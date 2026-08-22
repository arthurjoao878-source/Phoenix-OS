from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from phoenix_os.agent import (
    AgentAdmissionController,
    AgentCancellationToken,
    AgentId,
    AgentLimits,
    AgentLoop,
    AgentMessage,
    AgentMessageRole,
    AgentRunRequest,
    AgentRunStatus,
    AgentServiceConfiguration,
    AgentToolConfiguration,
    BoundedAgentExecutor,
    DeterministicFinalTurn,
    DeterministicModelTurnAdapter,
    DeterministicReadOnlyTool,
    DeterministicSideEffectTool,
    DeterministicToolTurn,
    InMemoryToolApprovalService,
    PolicyEngineToolAuthorizer,
    StaticToolResourceResolver,
    ToolApprovalChallenge,
    ToolApprovalEvidence,
    ToolDescriptor,
    ToolEffect,
    ToolId,
    ToolInputSchema,
    ToolInvocationRequest,
    ToolOutputSchema,
    ToolRegistry,
    ToolSchema,
    ToolSchemaType,
    create_agent_runtime_stack,
)
from phoenix_os.authority import CurrentSessionFreshnessValidator
from phoenix_os.identity.contracts import Identity, Session, SessionStatus
from phoenix_os.inference import InferenceRequest, ModelId, ModelProviderId
from phoenix_os.policy import (
    PolicyEffect,
    PolicyEngine,
    PolicyRegistration,
    PolicyRule,
    PrincipalType,
    SecurityContext,
)

_NOW = datetime(2026, 8, 19, 22, tzinfo=UTC)
_SESSION_ID = UUID("30000000-0000-4000-8000-000000000033")


def _service_context() -> SecurityContext:
    return SecurityContext(
        principal="service:assistant",
        principal_type=PrincipalType.SERVICE,
        authenticated=True,
    )


def _request(*, now: datetime = _NOW) -> AgentRunRequest:
    return AgentRunRequest(
        agent_id=AgentId("assistant"),
        provider_id=ModelProviderId("local"),
        model_id=ModelId("chat"),
        messages=(AgentMessage(AgentMessageRole.USER, "run the reviewed tool"),),
        created_at=now,
        deadline=now + timedelta(minutes=5),
    )


def _schema() -> ToolSchema:
    return ToolSchema(
        kind=ToolSchemaType.OBJECT,
        properties={
            "value": ToolSchema(
                kind=ToolSchemaType.STRING,
                min_length=1,
                max_length=128,
            )
        },
        required=frozenset({"value"}),
    )


def _descriptor(
    *,
    tool_id: str = "lookup",
    effect: ToolEffect = ToolEffect.READ_ONLY,
    adapter_id: str = "deterministic-read-only",
) -> ToolDescriptor:
    schema = _schema()
    return ToolDescriptor(
        tool_id=ToolId(tool_id),
        name="Reviewed tool",
        description="Perform one exact reviewed tool operation.",
        input_schema=ToolInputSchema(schema),
        output_schema=ToolOutputSchema(schema),
        effect=effect,
        approval_may_be_required=effect is not ToolEffect.READ_ONLY,
        max_input_bytes=4_096,
        max_output_bytes=4_096,
        timeout=timedelta(seconds=10),
        resolver_id="static-resource",
        adapter_id=adapter_id,
    )


class _RunAuthorizer:
    async def authorize(self, request: AgentRunRequest, context: SecurityContext) -> None:
        assert context.authenticated


class _ModelAuthorizer:
    async def authorize(self, request: InferenceRequest, context: SecurityContext) -> None:
        assert context.authenticated


class _AllowToolAuthorizer:
    def __init__(self) -> None:
        self.calls = 0

    async def authorize(
        self,
        request: ToolInvocationRequest,
        descriptor: ToolDescriptor,
        context: SecurityContext,
    ) -> None:
        assert descriptor.tool_id == request.tool_id
        assert context.authenticated
        self.calls += 1


class _PolicyRevokingApprovalResolver:
    def __init__(
        self,
        service: InMemoryToolApprovalService,
        policy: PolicyEngine,
        registration: PolicyRegistration,
    ) -> None:
        self._service = service
        self._policy = policy
        self._registration = registration

    async def resolve(self, challenge: ToolApprovalChallenge) -> ToolApprovalEvidence:
        evidence = await self._service.approve(
            challenge.approval_id,
            _service_context(),
        )
        assert await self._policy.unregister(self._registration)
        return evidence


class _MutableSessionSource:
    def __init__(self, session: Session) -> None:
        self.current = session
        self.calls: list[UUID] = []

    async def session(self, session_id: UUID) -> Session:
        self.calls.append(session_id)
        return self.current


class _SessionRevokingApprovalResolver:
    def __init__(
        self,
        service: InMemoryToolApprovalService,
        source: _MutableSessionSource,
    ) -> None:
        self._service = service
        self._source = source

    async def resolve(self, challenge: ToolApprovalChallenge) -> ToolApprovalEvidence:
        evidence = await self._service.approve(
            challenge.approval_id,
            _service_context(),
        )
        self._source.current = replace(
            self._source.current,
            status=SessionStatus.REVOKED,
            revoked_at=_NOW,
            revocation_reason="test revocation",
        )
        return evidence


def _session() -> Session:
    issued_at = _NOW - timedelta(minutes=5)
    return Session(
        id=_SESSION_ID,
        identity=Identity(
            subject="arthur",
            principal_type=PrincipalType.USER,
            authenticated_at=issued_at,
        ),
        issued_at=issued_at,
        expires_at=_NOW + timedelta(days=3650),
        last_seen_at=issued_at,
    )


def _loop(
    *,
    descriptor: ToolDescriptor,
    adapter: DeterministicReadOnlyTool | DeterministicSideEffectTool,
    tool_authorizer: object,
    approval_service: InMemoryToolApprovalService | None = None,
    approval_resolver: object | None = None,
    authority_freshness: CurrentSessionFreshnessValidator | None = None,
    admission: AgentAdmissionController | None = None,
) -> AgentLoop:
    registry = ToolRegistry()
    registry.register_tool(
        descriptor,
        resolver=StaticToolResourceResolver("static-resource", "record:fixed"),
        adapter=adapter,
    )
    return AgentLoop(
        run_authorizer=_RunAuthorizer(),
        model_authorizer=_ModelAuthorizer(),
        tool_authorizer=tool_authorizer,  # type: ignore[arg-type]
        model_adapter=DeterministicModelTurnAdapter(
            (
                DeterministicToolTurn(descriptor.tool_id, {"value": "input"}),
                DeterministicFinalTurn("complete"),
            )
        ),
        registry=registry,
        executor=BoundedAgentExecutor(clock=lambda: _NOW),
        approval_service=approval_service,
        approval_resolver=approval_resolver,  # type: ignore[arg-type]
        authority_freshness=authority_freshness,
        admission=admission,
        clock=lambda: _NOW,
    )


def _single_tool_admission() -> AgentAdmissionController:
    return AgentAdmissionController(
        AgentLimits(
            max_concurrent_tool_calls=1,
        )
    )


async def _wait_for_tool_queue(admission: AgentAdmissionController) -> None:
    for _ in range(500):
        snapshot = await admission.snapshot()
        if snapshot.active_tool_calls == 1 and snapshot.queued == 1:
            return
        await asyncio.sleep(0)
    raise AssertionError("tool invocation did not enter the admission queue")


@pytest.mark.asyncio
async def test_session_backed_agent_path_fails_closed_without_freshness_validator() -> None:
    descriptor = _descriptor()
    adapter = DeterministicReadOnlyTool("lookup", {"value": "not reached"})
    authorizer = _AllowToolAuthorizer()
    loop = _loop(
        descriptor=descriptor,
        adapter=adapter,
        tool_authorizer=authorizer,
    )

    result = await loop.run(_request(), _session().security_context())

    assert result.status is AgentRunStatus.FAILED
    assert result.error_code == "authorization_rejected"
    assert result.tool_calls == 0
    assert authorizer.calls == 0
    assert len(adapter.requests) == 0


@pytest.mark.asyncio
async def test_policy_change_during_approval_is_denied_before_side_effect_admission() -> None:
    descriptor = _descriptor(
        tool_id="write",
        effect=ToolEffect.REVERSIBLE_WRITE,
        adapter_id="deterministic-side-effect",
    )
    adapter = DeterministicSideEffectTool("write", {"value": "written"})
    policy = PolicyEngine()
    registration = await policy.register(
        PolicyRule(
            rule_id="allow.write.before-approval",
            effect=PolicyEffect.ALLOW,
            actions=frozenset({"tool.invoke"}),
            resources=frozenset({"tool:write/record:fixed"}),
            principals=frozenset({"service:assistant"}),
            authenticated=True,
            attribute_equals={
                "agent_id": "assistant",
                "effect": "reversible_write",
            },
        )
    )
    approvals = InMemoryToolApprovalService(clock=lambda: _NOW)
    resolver = _PolicyRevokingApprovalResolver(approvals, policy, registration)
    loop = _loop(
        descriptor=descriptor,
        adapter=adapter,
        tool_authorizer=PolicyEngineToolAuthorizer(policy),
        approval_service=approvals,
        approval_resolver=resolver,
    )

    result = await loop.run(_request(), _service_context())

    assert result.status is AgentRunStatus.FAILED
    assert result.error_code == "authorization_rejected"
    assert result.tool_calls == 0
    assert adapter.effect_count == 0
    policy_snapshot = await policy.snapshot()
    assert policy_snapshot.evaluations == 2
    assert policy_snapshot.allowed == 1
    assert policy_snapshot.denied == 1
    approval_snapshot = await approvals.snapshot()
    assert approval_snapshot.consumed == 1


@pytest.mark.asyncio
async def test_session_revocation_during_approval_is_denied_before_side_effect_admission() -> None:
    descriptor = _descriptor(
        tool_id="write",
        effect=ToolEffect.REVERSIBLE_WRITE,
        adapter_id="deterministic-side-effect",
    )
    adapter = DeterministicSideEffectTool("write", {"value": "written"})
    active_session = _session()
    source = _MutableSessionSource(active_session)
    validator = CurrentSessionFreshnessValidator(source, clock=lambda: _NOW)
    authorizer = _AllowToolAuthorizer()
    approvals = InMemoryToolApprovalService(clock=lambda: _NOW)
    resolver = _SessionRevokingApprovalResolver(approvals, source)
    loop = _loop(
        descriptor=descriptor,
        adapter=adapter,
        tool_authorizer=authorizer,
        approval_service=approvals,
        approval_resolver=resolver,
        authority_freshness=validator,
    )

    result = await loop.run(_request(), active_session.security_context())

    assert result.status is AgentRunStatus.FAILED
    assert result.error_code == "authorization_rejected"
    assert result.tool_calls == 0
    assert authorizer.calls == 1
    assert source.calls == [_SESSION_ID, _SESSION_ID, _SESSION_ID]
    assert adapter.effect_count == 0
    approval_snapshot = await approvals.snapshot()
    assert approval_snapshot.consumed == 1


@pytest.mark.asyncio
async def test_policy_change_while_waiting_for_tool_lease_is_denied_after_queue() -> None:
    descriptor = _descriptor()
    adapter = DeterministicReadOnlyTool("lookup", {"value": "not reached"})
    policy = PolicyEngine()
    registration = await policy.register(
        PolicyRule(
            rule_id="allow.lookup.before-queue",
            effect=PolicyEffect.ALLOW,
            actions=frozenset({"tool.invoke"}),
            resources=frozenset({"tool:lookup/record:fixed"}),
            principals=frozenset({"service:assistant"}),
            authenticated=True,
            attribute_equals={
                "agent_id": "assistant",
                "effect": "read_only",
            },
        )
    )
    admission = _single_tool_admission()
    holder = await admission.acquire_tool(
        timeout_seconds=1,
        cancellation=AgentCancellationToken(),
    )
    loop = _loop(
        descriptor=descriptor,
        adapter=adapter,
        tool_authorizer=PolicyEngineToolAuthorizer(policy),
        admission=admission,
    )
    task = asyncio.create_task(loop.run(_request(), _service_context()))

    try:
        await _wait_for_tool_queue(admission)
        assert await policy.unregister(registration)
    finally:
        await holder.release()

    result = await task

    assert result.status is AgentRunStatus.FAILED
    assert result.error_code == "authorization_rejected"
    assert result.tool_calls == 0
    assert len(adapter.requests) == 0
    policy_snapshot = await policy.snapshot()
    assert policy_snapshot.evaluations == 2
    assert policy_snapshot.allowed == 1
    assert policy_snapshot.denied == 1
    admission_snapshot = await admission.snapshot()
    assert admission_snapshot.active_tool_calls == 0
    assert admission_snapshot.queued == 0


@pytest.mark.asyncio
async def test_session_revocation_while_waiting_for_tool_lease_is_denied_after_queue() -> None:
    descriptor = _descriptor()
    adapter = DeterministicReadOnlyTool("lookup", {"value": "not reached"})
    active_session = _session()
    source = _MutableSessionSource(active_session)
    validator = CurrentSessionFreshnessValidator(source, clock=lambda: _NOW)
    authorizer = _AllowToolAuthorizer()
    admission = _single_tool_admission()
    holder = await admission.acquire_tool(
        timeout_seconds=1,
        cancellation=AgentCancellationToken(),
    )
    loop = _loop(
        descriptor=descriptor,
        adapter=adapter,
        tool_authorizer=authorizer,
        authority_freshness=validator,
        admission=admission,
    )
    task = asyncio.create_task(loop.run(_request(), active_session.security_context()))

    try:
        await _wait_for_tool_queue(admission)
        source.current = replace(
            active_session,
            status=SessionStatus.REVOKED,
            revoked_at=_NOW,
            revocation_reason="revoked while queued",
        )
    finally:
        await holder.release()

    result = await task

    assert result.status is AgentRunStatus.FAILED
    assert result.error_code == "authorization_rejected"
    assert result.tool_calls == 0
    assert authorizer.calls == 1
    assert source.calls == [_SESSION_ID, _SESSION_ID, _SESSION_ID]
    assert len(adapter.requests) == 0
    admission_snapshot = await admission.snapshot()
    assert admission_snapshot.active_tool_calls == 0
    assert admission_snapshot.queued == 0


@pytest.mark.asyncio
async def test_composed_runtime_uses_supplied_session_freshness_source() -> None:
    descriptor = _descriptor()
    configuration = AgentServiceConfiguration(
        agent_id=AgentId("assistant"),
        provider_id=ModelProviderId("local"),
        model_id=ModelId("chat"),
        tools=(AgentToolConfiguration(descriptor),),
    )
    adapter = DeterministicReadOnlyTool("lookup", {"value": "ok"})
    session = _session()
    source = _MutableSessionSource(session)
    policy = PolicyEngine(
        (
            PolicyRule(
                rule_id="allow.composed.test",
                effect=PolicyEffect.ALLOW,
                actions=frozenset({"*"}),
                resources=frozenset({"*"}),
                principals=frozenset({"arthur"}),
                authenticated=True,
            ),
        )
    )
    stack = create_agent_runtime_stack(
        configuration=configuration,
        model_adapter=DeterministicModelTurnAdapter(
            (
                DeterministicToolTurn(descriptor.tool_id, {"value": "input"}),
                DeterministicFinalTurn("complete"),
            )
        ),
        tool_resolvers=(StaticToolResourceResolver(descriptor.resolver_id, "record:fixed"),),
        tool_adapters=(adapter,),
        policy=policy,
        session_freshness_source=source,
    )
    now = datetime.now(UTC)

    result = await stack.runtime.run(_request(now=now), session.security_context())

    assert result.status is AgentRunStatus.COMPLETED
    assert result.final_output == "complete"
    assert source.calls == [
        _SESSION_ID,
        _SESSION_ID,
        _SESSION_ID,
        _SESSION_ID,
    ]
    assert len(adapter.requests) == 1
