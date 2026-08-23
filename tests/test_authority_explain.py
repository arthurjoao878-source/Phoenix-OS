from __future__ import annotations

import inspect
from datetime import UTC, datetime
from uuid import UUID

import pytest

from phoenix_os.authority import (
    AUTHORITY_EXPLAIN_ACTION,
    AUTHORITY_INSPECT_ACTION,
    AuthorityConstraint,
    AuthorityDenialReason,
    AuthorityEffect,
    AuthorityExplainRequest,
    AuthorityFreshnessRejectedError,
    AuthorityInspectionRejectedError,
    AuthorityInspectionState,
    AuthorityInspectRequest,
    AuthorityIntent,
    AuthorityPathObservation,
    AuthorityService,
    AuthoritySubject,
    authority_explanation_resource,
    authority_subject_resource,
)
from phoenix_os.policy import (
    PolicyEffect,
    PolicyEngine,
    PolicyRule,
    PrincipalType,
    SecurityContext,
)

_NOW = datetime(2026, 8, 22, 22, tzinfo=UTC)
_SESSION_ID = UUID("40000000-0000-0000-0000-000000000033")
_RECORD_ID = UUID("50000000-0000-0000-0000-000000000033")
_CALLER = "service:authority-operator"
_TARGET = "service:agent-owner"
_TARGET_REF = "agent-42"
_RESOURCE_REF = "memory-slot"


def _caller(*, confirmed: bool = False) -> SecurityContext:
    return SecurityContext(
        principal=_CALLER,
        principal_type=PrincipalType.SERVICE,
        authenticated=True,
        confirmed=confirmed,
    )


def _subject() -> AuthoritySubject:
    return AuthoritySubject(
        principal_type=PrincipalType.SERVICE,
        principal=_TARGET,
        session_id=_SESSION_ID,
        agent_id="assistant",
        run_id="60000000-0000-0000-0000-000000000033",
    )


def _intent() -> AuthorityIntent:
    return AuthorityIntent(
        action="memory.write",
        canonical_resource=(f"agent-memory:composition/scope:agent:assistant/record:{_RECORD_ID}"),
        parameter_digest="sha256:" + "b" * 64,
    )


def _observation(intent: AuthorityIntent | None = None) -> AuthorityPathObservation:
    selected = _intent() if intent is None else intent
    return AuthorityPathObservation(
        intent=selected,
        boundaries=("agent.run", "tool.invoke", "memory.write"),
        effect=AuthorityEffect.DENIED,
        constraints=(
            AuthorityConstraint.POLICY,
            AuthorityConstraint.CANONICAL_BOUNDARY,
        ),
        denial_reason=AuthorityDenialReason.BOUNDARY_DENIED,
        blocked_downstream=("host.clipboard.write",),
    )


class _RecordingFreshness:
    def __init__(self) -> None:
        self.contexts: list[SecurityContext] = []
        self.reject = False

    async def validate(self, context: SecurityContext) -> None:
        self.contexts.append(context)
        if self.reject:
            raise AuthorityFreshnessRejectedError("stale caller")


class _RecordingSource:
    def __init__(self) -> None:
        self.subject = _subject()
        self.intent = _intent()
        self.observation = _observation(self.intent)
        self.resolve_subject_calls = 0
        self.inspect_calls = 0
        self.resolve_intent_calls = 0
        self.explain_calls = 0
        self.secret_failure: RuntimeError | None = None

    async def resolve_subject(self, target_ref: str) -> AuthoritySubject:
        self.resolve_subject_calls += 1
        assert target_ref == _TARGET_REF
        return self.subject

    async def inspect(self, subject: AuthoritySubject) -> AuthorityInspectionState:
        self.inspect_calls += 1
        assert subject == self.subject
        if self.secret_failure is not None:
            raise self.secret_failure
        return AuthorityInspectionState(
            subject=self.subject,
            observations=(self.observation,),
            observed_at=_NOW,
        )

    async def resolve_intent(
        self,
        subject: AuthoritySubject,
        *,
        action: str,
        resource_ref: str | None,
    ) -> AuthorityIntent:
        self.resolve_intent_calls += 1
        assert subject == self.subject
        assert action == self.intent.action
        assert resource_ref == _RESOURCE_REF
        return self.intent

    async def explain(
        self,
        subject: AuthoritySubject,
        intent: AuthorityIntent,
    ) -> tuple[AuthorityPathObservation, datetime]:
        self.explain_calls += 1
        assert subject == self.subject
        assert intent == self.intent
        if self.secret_failure is not None:
            raise self.secret_failure
        return self.observation, _NOW


def _allow_rule(action: str, resource: str) -> PolicyRule:
    return PolicyRule(
        rule_id=f"allow-{action.replace('.', '-')}",
        effect=PolicyEffect.ALLOW,
        actions=frozenset({action}),
        resources=frozenset({resource}),
        principals=frozenset({_CALLER}),
        principal_types=frozenset({PrincipalType.SERVICE}),
        authenticated=True,
    )


def _service(
    *,
    policy: PolicyEngine,
    source: _RecordingSource,
    freshness: _RecordingFreshness,
) -> AuthorityService:
    return AuthorityService(policy, source, freshness)


def test_authority_service_catalog_is_not_runtime_replaceable() -> None:
    assert "catalog" not in inspect.signature(AuthorityService.__init__).parameters


@pytest.mark.asyncio
async def test_inspection_requires_independent_exact_authorization() -> None:
    source = _RecordingSource()
    freshness = _RecordingFreshness()
    policy = PolicyEngine()
    service = _service(policy=policy, source=source, freshness=freshness)

    with pytest.raises(AuthorityInspectionRejectedError):
        await service.inspect(AuthorityInspectRequest(_TARGET_REF, created_at=_NOW), _caller())

    assert source.resolve_subject_calls == 1
    assert source.inspect_calls == 0
    assert freshness.contexts == [_caller()]
    snapshot = await policy.snapshot()
    assert (snapshot.allowed, snapshot.denied, snapshot.confirmations) == (0, 1, 0)


@pytest.mark.asyncio
async def test_inspection_returns_only_redacted_point_in_time_observation() -> None:
    source = _RecordingSource()
    freshness = _RecordingFreshness()
    resource = authority_subject_resource(source.subject)
    policy = PolicyEngine((_allow_rule(AUTHORITY_INSPECT_ACTION, resource),))
    service = _service(policy=policy, source=source, freshness=freshness)

    result = await service.inspect(
        AuthorityInspectRequest(_TARGET_REF, created_at=_NOW),
        _caller(),
    )

    assert result.subject.principal == _TARGET
    assert result.subject.session_identity is not None
    assert str(_SESSION_ID) not in repr(result)
    assert result.observations[0].requested_action == "memory.write"
    assert result.observations[0].authority_path == (
        "agent.run",
        "tool.invoke",
        "memory.write",
    )
    assert source.inspect_calls == 1
    assert freshness.contexts == [_caller(), _caller()]
    snapshot = await policy.snapshot()
    assert (snapshot.allowed, snapshot.denied, snapshot.confirmations) == (2, 0, 0)


@pytest.mark.asyncio
async def test_explanation_binds_policy_to_server_resolved_subject_and_intent() -> None:
    source = _RecordingSource()
    freshness = _RecordingFreshness()
    resource = authority_explanation_resource(source.subject, source.intent)
    policy = PolicyEngine((_allow_rule(AUTHORITY_EXPLAIN_ACTION, resource),))
    service = _service(policy=policy, source=source, freshness=freshness)

    result = await service.explain(
        AuthorityExplainRequest(
            _TARGET_REF,
            action="memory.write",
            resource_ref=_RESOURCE_REF,
            created_at=_NOW,
        ),
        _caller(),
    )

    assert result.observation.requested_action == "memory.write"
    assert result.observation.canonical_resource == source.intent.canonical_resource
    assert result.observation.denial_reason is AuthorityDenialReason.BOUNDARY_DENIED
    assert source.resolve_intent_calls == 1
    assert source.explain_calls == 1
    snapshot = await policy.snapshot()
    assert (snapshot.allowed, snapshot.denied, snapshot.confirmations) == (2, 0, 0)


@pytest.mark.asyncio
async def test_ambient_confirmation_cannot_satisfy_authority_inspection_policy() -> None:
    source = _RecordingSource()
    freshness = _RecordingFreshness()
    resource = authority_subject_resource(source.subject)
    policy = PolicyEngine(
        (
            PolicyRule(
                rule_id="confirm-inspection",
                effect=PolicyEffect.REQUIRE_CONFIRMATION,
                actions=frozenset({AUTHORITY_INSPECT_ACTION}),
                resources=frozenset({resource}),
                principals=frozenset({_CALLER}),
            ),
        )
    )
    service = _service(policy=policy, source=source, freshness=freshness)

    with pytest.raises(AuthorityInspectionRejectedError):
        await service.inspect(
            AuthorityInspectRequest(_TARGET_REF, created_at=_NOW),
            _caller(confirmed=True),
        )

    assert source.inspect_calls == 0
    snapshot = await policy.snapshot()
    assert (snapshot.allowed, snapshot.denied, snapshot.confirmations) == (0, 0, 1)


@pytest.mark.asyncio
async def test_caller_freshness_is_revalidated_before_releasing_result() -> None:
    source = _RecordingSource()

    class _RevokeOnSecondValidation(_RecordingFreshness):
        async def validate(self, context: SecurityContext) -> None:
            await super().validate(context)
            if len(self.contexts) == 2:
                raise AuthorityFreshnessRejectedError("revoked after source read")

    freshness = _RevokeOnSecondValidation()
    resource = authority_subject_resource(source.subject)
    policy = PolicyEngine((_allow_rule(AUTHORITY_INSPECT_ACTION, resource),))
    service = _service(policy=policy, source=source, freshness=freshness)

    with pytest.raises(AuthorityInspectionRejectedError):
        await service.inspect(AuthorityInspectRequest(_TARGET_REF, created_at=_NOW), _caller())

    assert source.inspect_calls == 1
    assert len(freshness.contexts) == 2
    snapshot = await policy.snapshot()
    assert (snapshot.allowed, snapshot.denied) == (1, 0)


@pytest.mark.asyncio
async def test_unknown_operation_from_trusted_source_fails_closed() -> None:
    source = _RecordingSource()
    source.intent = AuthorityIntent(
        action="future.network.send",
        canonical_resource="network:target",
        parameter_digest="sha256:" + "c" * 64,
    )
    source.observation = AuthorityPathObservation(
        intent=source.intent,
        boundaries=("future.network.send",),
        effect=AuthorityEffect.DENIED,
        denial_reason=AuthorityDenialReason.UNKNOWN_OPERATION,
    )
    freshness = _RecordingFreshness()
    policy = PolicyEngine()
    service = _service(policy=policy, source=source, freshness=freshness)

    with pytest.raises(AuthorityInspectionRejectedError):
        await service.explain(
            AuthorityExplainRequest(
                _TARGET_REF,
                action="future.network.send",
                resource_ref=_RESOURCE_REF,
                created_at=_NOW,
            ),
            _caller(),
        )

    assert source.explain_calls == 0
    snapshot = await policy.snapshot()
    assert snapshot.evaluations == 0


@pytest.mark.asyncio
async def test_source_failure_does_not_leak_sensitive_exception_text() -> None:
    source = _RecordingSource()
    source.secret_failure = RuntimeError("credential=super-secret-session-token")
    freshness = _RecordingFreshness()
    resource = authority_subject_resource(source.subject)
    policy = PolicyEngine((_allow_rule(AUTHORITY_INSPECT_ACTION, resource),))
    service = _service(policy=policy, source=source, freshness=freshness)

    with pytest.raises(AuthorityInspectionRejectedError) as captured:
        await service.inspect(AuthorityInspectRequest(_TARGET_REF, created_at=_NOW), _caller())

    assert str(captured.value) == "authority inspection rejected"
    assert "super-secret" not in str(captured.value)
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None
    assert source.inspect_calls == 1


@pytest.mark.asyncio
async def test_policy_rules_remain_unchanged_by_successful_inspection() -> None:
    source = _RecordingSource()
    freshness = _RecordingFreshness()
    resource = authority_subject_resource(source.subject)
    rule = _allow_rule(AUTHORITY_INSPECT_ACTION, resource)
    policy = PolicyEngine((rule,))
    service = _service(policy=policy, source=source, freshness=freshness)
    rules_before = await policy.list_rules()

    await service.inspect(AuthorityInspectRequest(_TARGET_REF, created_at=_NOW), _caller())

    assert await policy.list_rules() == rules_before
