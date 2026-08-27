from datetime import UTC, datetime, timedelta

import pytest

from phoenix_os.agent import (
    AGENT_RUN_ACTION,
    TOOL_INVOKE_ACTION,
    AgentAuthorizationRejectedError,
    AgentId,
    AgentMessage,
    AgentMessageRole,
    AgentRunRequest,
    AgentStepId,
    DelegatingAgentModelTurnAuthorizer,
    PolicyEngineAgentRunAuthorizer,
    PolicyEngineToolAuthorizer,
    ToolCallId,
    ToolDescriptor,
    ToolEffect,
    ToolId,
    ToolInputSchema,
    ToolInvocationRequest,
    ToolOutputSchema,
    ToolSchema,
    ToolSchemaType,
    agent_run_resource,
    canonical_tool_argument_digest,
    tool_effect_requires_approval,
    tool_invocation_resource,
)
from phoenix_os.agent.authorization import (
    AgentRunAuthorityBinding,
    normalized_agent_run_authority_intent,
)
from phoenix_os.authority.contracts import AuthorityFreshnessBinding
from phoenix_os.inference import (
    InferenceAuthorizationRejectedError,
    InferenceMessage,
    InferenceRequest,
    InferenceRole,
    ModelId,
    ModelProviderId,
)
from phoenix_os.policy import (
    PolicyEffect,
    PolicyEngine,
    PolicyRule,
    PrincipalType,
    SecurityContext,
)

_NOW = datetime(2026, 7, 27, 12, tzinfo=UTC)


def _context(*, authenticated: bool = True) -> SecurityContext:
    return SecurityContext(
        principal="service:assistant" if authenticated else "anonymous",
        principal_type=PrincipalType.SERVICE if authenticated else PrincipalType.ANONYMOUS,
        authenticated=authenticated,
    )


def _run_request(*, agent_id: str = "assistant") -> AgentRunRequest:
    return AgentRunRequest(
        agent_id=AgentId(agent_id),
        provider_id=ModelProviderId("local"),
        model_id=ModelId("chat"),
        messages=(AgentMessage(AgentMessageRole.USER, "hello"),),
        created_at=_NOW,
        deadline=_NOW + timedelta(minutes=10),
    )


def _schema() -> ToolSchema:
    return ToolSchema(
        kind=ToolSchemaType.OBJECT,
        properties={
            "path": ToolSchema(
                kind=ToolSchemaType.STRING,
                min_length=1,
                max_length=128,
            )
        },
        required=frozenset({"path"}),
    )


def _descriptor(
    *,
    tool_id: str = "files.read",
    effect: ToolEffect = ToolEffect.READ_ONLY,
) -> ToolDescriptor:
    return ToolDescriptor(
        tool_id=ToolId(tool_id),
        name="Read reviewed file",
        description="Read one bounded admitted file.",
        input_schema=ToolInputSchema(_schema()),
        output_schema=ToolOutputSchema(_schema()),
        effect=effect,
        approval_may_be_required=effect is not ToolEffect.READ_ONLY,
        max_input_bytes=4_096,
        max_output_bytes=4_096,
        timeout=timedelta(seconds=10),
        resolver_id="workspace-file",
        adapter_id="deterministic-file-reader",
    )


def _invocation(
    *,
    agent_id: str | None = "assistant",
    tool_id: str = "files.read",
    path: str = "docs/readme.md",
    resource: str = "workspace:docs/readme.md",
) -> ToolInvocationRequest:
    return ToolInvocationRequest(
        agent_id=None if agent_id is None else AgentId(agent_id),
        run_id=_run_request().run_id,
        step_id=AgentStepId(),
        call_id=ToolCallId(),
        tool_id=ToolId(tool_id),
        arguments={"path": path},
        resolved_resource=resource,
        created_at=_NOW,
        deadline=_NOW + timedelta(seconds=10),
    )


def _inference_request() -> InferenceRequest:
    return InferenceRequest(
        provider_id=ModelProviderId("local"),
        model_id=ModelId("chat"),
        messages=(InferenceMessage(InferenceRole.USER, "hello"),),
        created_at=_NOW,
        deadline=_NOW + timedelta(minutes=1),
    )


def test_actions_resources_digest_and_effect_defaults_are_exact() -> None:
    request = _run_request()
    invocation = _invocation()

    assert AGENT_RUN_ACTION == "agent.run"
    assert TOOL_INVOKE_ACTION == "tool.invoke"
    assert agent_run_resource(request.agent_id) == "agent:assistant"
    assert tool_invocation_resource(invocation) == "tool:files.read/workspace:docs/readme.md"
    assert canonical_tool_argument_digest({"path": "docs/readme.md"}).startswith("sha256:")
    assert canonical_tool_argument_digest({"a": 1, "b": 2}) == canonical_tool_argument_digest(
        {"b": 2, "a": 1}
    )
    assert canonical_tool_argument_digest({"path": "one"}) != canonical_tool_argument_digest(
        {"path": "two"}
    )
    assert not tool_effect_requires_approval(ToolEffect.READ_ONLY)
    assert tool_effect_requires_approval(ToolEffect.REVERSIBLE_WRITE)
    assert tool_effect_requires_approval(ToolEffect.IRREVERSIBLE_WRITE)
    assert tool_effect_requires_approval(ToolEffect.EXTERNAL_COMMUNICATION)


@pytest.mark.asyncio
async def test_agent_run_authorization_is_exact_and_default_deny() -> None:
    policy = PolicyEngine(
        (
            PolicyRule(
                rule_id="allow.agent.assistant",
                effect=PolicyEffect.ALLOW,
                actions=frozenset({"agent.run"}),
                resources=frozenset({"agent:assistant"}),
                principals=frozenset({"service:assistant"}),
                authenticated=True,
            ),
        )
    )
    authorizer = PolicyEngineAgentRunAuthorizer(policy)

    await authorizer.authorize(_run_request(), _context())
    with pytest.raises(AgentAuthorizationRejectedError):
        await authorizer.authorize(_run_request(agent_id="other"), _context())

    snapshot = await policy.snapshot()
    assert snapshot.allowed == 1
    assert snapshot.denied == 1


@pytest.mark.asyncio
async def test_agent_run_does_not_grant_model_or_tool_authority() -> None:
    policy = PolicyEngine(
        (
            PolicyRule(
                rule_id="allow.agent.only",
                effect=PolicyEffect.ALLOW,
                actions=frozenset({"agent.run"}),
                resources=frozenset({"agent:assistant"}),
                principals=frozenset({"service:assistant"}),
                authenticated=True,
            ),
        )
    )

    await PolicyEngineAgentRunAuthorizer(policy).authorize(_run_request(), _context())
    with pytest.raises(AgentAuthorizationRejectedError):
        await PolicyEngineToolAuthorizer(policy).authorize(
            _invocation(),
            _descriptor(),
            _context(),
        )


@pytest.mark.asyncio
async def test_tool_authorization_uses_resolved_resource_effect_and_argument_digest() -> None:
    invocation = _invocation()
    descriptor = _descriptor(effect=ToolEffect.READ_ONLY)
    digest = canonical_tool_argument_digest(invocation.arguments)
    policy = PolicyEngine(
        (
            PolicyRule(
                rule_id="allow.exact.read",
                effect=PolicyEffect.ALLOW,
                actions=frozenset({"tool.invoke"}),
                resources=frozenset({"tool:files.read/workspace:docs/readme.md"}),
                principals=frozenset({"service:assistant"}),
                authenticated=True,
                attribute_equals={
                    "agent_id": "assistant",
                    "effect": "read_only",
                    "argument_digest": digest,
                },
            ),
        )
    )
    authorizer = PolicyEngineToolAuthorizer(policy)

    await authorizer.authorize(invocation, descriptor, _context())
    with pytest.raises(AgentAuthorizationRejectedError):
        await authorizer.authorize(
            _invocation(path="private.txt"),
            descriptor,
            _context(),
        )
    with pytest.raises(AgentAuthorizationRejectedError):
        await authorizer.authorize(
            _invocation(resource="workspace:other/readme.md"),
            descriptor,
            _context(),
        )
    with pytest.raises(AgentAuthorizationRejectedError):
        await authorizer.authorize(
            _invocation(agent_id="other"),
            descriptor,
            _context(),
        )


@pytest.mark.asyncio
async def test_tool_authorization_rejects_security_context_attribute_collision() -> None:
    invocation = _invocation()
    descriptor = _descriptor(effect=ToolEffect.READ_ONLY)
    digest = canonical_tool_argument_digest(invocation.arguments)
    policy = PolicyEngine(
        (
            PolicyRule(
                rule_id="allow.exact.read",
                effect=PolicyEffect.ALLOW,
                actions=frozenset({"tool.invoke"}),
                resources=frozenset({"tool:files.read/workspace:docs/readme.md"}),
                principals=frozenset({"service:assistant"}),
                authenticated=True,
                attribute_equals={
                    "agent_id": "assistant",
                    "effect": "read_only",
                    "argument_digest": digest,
                },
            ),
        )
    )
    context = SecurityContext(
        principal="service:assistant",
        principal_type=PrincipalType.SERVICE,
        authenticated=True,
        attributes={"agent_id": "assistant"},
    )

    with pytest.raises(AgentAuthorizationRejectedError):
        await PolicyEngineToolAuthorizer(policy).authorize(
            invocation,
            descriptor,
            context,
        )

    snapshot = await policy.snapshot()
    assert snapshot.evaluations == 1
    assert snapshot.allowed == 0
    assert snapshot.denied == 1


@pytest.mark.asyncio
async def test_missing_agent_binding_fails_before_policy_evaluation() -> None:
    policy = PolicyEngine()
    authorizer = PolicyEngineToolAuthorizer(policy)

    with pytest.raises(AgentAuthorizationRejectedError):
        await authorizer.authorize(
            _invocation(agent_id=None),
            _descriptor(),
            _context(),
        )

    assert (await policy.snapshot()).evaluations == 0


@pytest.mark.asyncio
async def test_tool_descriptor_mismatch_fails_before_policy_evaluation() -> None:
    policy = PolicyEngine()
    authorizer = PolicyEngineToolAuthorizer(policy)

    with pytest.raises(AgentAuthorizationRejectedError):
        await authorizer.authorize(
            _invocation(tool_id="files.read"),
            _descriptor(tool_id="files.write"),
            _context(),
        )

    assert (await policy.snapshot()).evaluations == 0


class _RecordingInferenceAuthorizer:
    def __init__(self, *, reject: bool = False) -> None:
        self.reject = reject
        self.requests: list[InferenceRequest] = []

    async def authorize(self, request: InferenceRequest, context: SecurityContext) -> None:
        assert context.authenticated
        self.requests.append(request)
        if self.reject:
            raise InferenceAuthorizationRejectedError()


@pytest.mark.asyncio
async def test_every_model_turn_requires_a_separate_inference_authorization() -> None:
    underlying = _RecordingInferenceAuthorizer()
    authorizer = DelegatingAgentModelTurnAuthorizer(underlying)
    request = _inference_request()

    await authorizer.authorize(request, _context())
    await authorizer.authorize(request, _context())

    assert underlying.requests == [request, request]


@pytest.mark.asyncio
async def test_model_denial_is_translated_to_safe_agent_denial() -> None:
    authorizer = DelegatingAgentModelTurnAuthorizer(_RecordingInferenceAuthorizer(reject=True))

    with pytest.raises(AgentAuthorizationRejectedError, match="authorization failed"):
        await authorizer.authorize(_inference_request(), _context())


@pytest.mark.asyncio
async def test_unauthenticated_requests_fail_before_policy_evaluation() -> None:
    policy = PolicyEngine()

    with pytest.raises(AgentAuthorizationRejectedError):
        await PolicyEngineAgentRunAuthorizer(policy).authorize(
            _run_request(),
            _context(authenticated=False),
        )
    with pytest.raises(AgentAuthorizationRejectedError):
        await PolicyEngineToolAuthorizer(policy).authorize(
            _invocation(),
            _descriptor(),
            _context(authenticated=False),
        )

    assert (await policy.snapshot()).evaluations == 0


@pytest.mark.asyncio
async def test_bound_agent_run_uses_normalized_intent_and_caller_metadata_cannot_forge_it() -> None:
    digest = "sha256:" + ("7" * 64)
    binding = AgentRunAuthorityBinding(
        parameter_digest=digest,
        freshness_bindings=(
            AuthorityFreshnessBinding(
                kind="integrated.profile",
                identity="integrated-research:7",
            ),
            AuthorityFreshnessBinding(
                kind="integrated.task",
                identity="task-123:" + digest,
            ),
        ),
        attributes=(
            ("integrated_task_digest", digest),
            ("integrated_profile_id", "integrated-research"),
            ("integrated_profile_generation", "7"),
        ),
    )
    request = _run_request()
    intent = normalized_agent_run_authority_intent(request, binding)

    assert intent.action == "agent.run"
    assert intent.canonical_resource == "agent:assistant"
    assert intent.parameter_digest == digest
    assert {item.kind for item in intent.freshness_bindings} == {
        "integrated.profile",
        "integrated.task",
    }

    policy = PolicyEngine(
        (
            PolicyRule(
                rule_id="allow.bound.agent.run",
                effect=PolicyEffect.ALLOW,
                actions=frozenset({"agent.run"}),
                resources=frozenset({"agent:assistant"}),
                principals=frozenset({"service:assistant"}),
                authenticated=True,
                attribute_equals={
                    "authority_parameter_digest": digest,
                    "integrated_task_digest": digest,
                    "integrated_profile_id": "integrated-research",
                    "integrated_profile_generation": "7",
                },
            ),
        )
    )
    authorizer = PolicyEngineAgentRunAuthorizer(policy)
    await authorizer.authorize_bound(request, _context(), binding)

    forged = AgentRunRequest(
        agent_id=request.agent_id,
        provider_id=request.provider_id,
        model_id=request.model_id,
        messages=request.messages,
        limits=request.limits,
        metadata={
            "authority_parameter_digest": digest,
            "integrated_task_digest": digest,
            "integrated_profile_id": "integrated-research",
            "integrated_profile_generation": "7",
        },
        run_id=request.run_id,
        created_at=request.created_at,
        deadline=request.deadline,
    )
    with pytest.raises(AgentAuthorizationRejectedError):
        await authorizer.authorize(forged, _context())

    snapshot = await policy.snapshot()
    assert snapshot.allowed == 1
    assert snapshot.denied == 1
