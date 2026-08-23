from __future__ import annotations

import asyncio
import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from http import HTTPStatus
from uuid import UUID

import pytest

from phoenix_os.authority import (
    AUTHORITY_EXPLAIN_ACTION,
    AUTHORITY_INSPECT_ACTION,
    AuthorityEffect,
    AuthorityFreshnessRejectedError,
    AuthorityInspectionState,
    AuthorityIntent,
    AuthorityPathObservation,
    AuthoritySubject,
    authority_explanation_resource,
    authority_subject_resource,
)
from phoenix_os.control_plane.authority_http import (
    AUTHORITY_EXPLAIN_CONTROL_PLANE_PATH,
    AUTHORITY_INSPECT_CONTROL_PLANE_PATH,
    ControlPlaneAuthorityHttpAdapter,
)
from phoenix_os.control_plane.authority_integration import (
    ControlPlaneDurableAuthorityFreshnessValidator,
    control_plane_authority_security_context,
    create_control_plane_authority_service,
)
from phoenix_os.control_plane.csrf import ControlPlaneBrowserOrigin
from phoenix_os.control_plane.durable_session_access import (
    ControlPlaneDurableSessionAuthentication,
)
from phoenix_os.control_plane.durable_session_contracts import (
    ControlPlaneDurableCsrfSecret,
    ControlPlaneDurableSessionPolicy,
    ControlPlaneDurableSessionRecord,
    ControlPlaneDurableSessionStatus,
    ControlPlaneDurableSessionTerminationReason,
    ControlPlaneDurableSessionToken,
)
from phoenix_os.control_plane.durable_session_memory import (
    InMemoryControlPlaneDurableSessionRepository,
)
from phoenix_os.control_plane.errors import ControlPlaneDurableSessionCsrfRejectedError
from phoenix_os.control_plane.operator_contracts import (
    ControlPlaneOperatorRecord,
    ControlPlaneOperatorRole,
    ControlPlaneOperatorStatus,
)
from phoenix_os.control_plane.operator_memory import InMemoryControlPlaneOperatorRegistry
from phoenix_os.policy import (
    PolicyEffect,
    PolicyEngine,
    PolicyRule,
    PrincipalType,
    SecurityContext,
)

_NOW = datetime(2026, 8, 22, 23, 0, tzinfo=UTC)
_ORIGIN = ControlPlaneBrowserOrigin("http://127.0.0.1:8080")
_OPERATOR_ID = UUID("10000000-0000-0000-0000-000000000033")
_SESSION_ID = UUID("20000000-0000-0000-0000-000000000033")
_TARGET_SESSION_ID = UUID("30000000-0000-0000-0000-000000000033")
_MEMORY_ID = UUID("40000000-0000-0000-0000-000000000033")
_TOKEN = ControlPlaneDurableSessionToken("operator-session-token-0123456789abcdef")
_CSRF = ControlPlaneDurableCsrfSecret("operator-csrf-secret-0123456789abcdef")
_CSRF_HEADER = "csrf-proof"


class _Clock:
    def __init__(self, now: datetime = _NOW) -> None:
        self.now = now

    def __call__(self) -> datetime:
        return self.now


def _operator(*, revision: int = 1) -> ControlPlaneOperatorRecord:
    return ControlPlaneOperatorRecord(
        id=_OPERATOR_ID,
        username="alice",
        display_name="Alice",
        role=ControlPlaneOperatorRole.MAINTAINER,
        token_digest="a" * 64,
        created_at=_NOW,
        updated_at=_NOW,
        revision=revision,
    )


def _session(operator: ControlPlaneOperatorRecord) -> ControlPlaneDurableSessionRecord:
    return ControlPlaneDurableSessionRecord.issue(
        operator_id=operator.id,
        username=operator.username,
        token=_TOKEN,
        csrf_secret=_CSRF,
        operator_revision=operator.revision,
        operator_token_version=operator.token_version,
        issued_at=_NOW,
        policy=ControlPlaneDurableSessionPolicy(
            absolute_ttl=timedelta(hours=1),
            idle_ttl=timedelta(minutes=30),
            rotation_interval=timedelta(minutes=20),
        ),
        session_id=_SESSION_ID,
    )


def _authentication(
    operator: ControlPlaneOperatorRecord,
    session: ControlPlaneDurableSessionRecord,
) -> ControlPlaneDurableSessionAuthentication:
    return ControlPlaneDurableSessionAuthentication(
        session_id=session.id,
        operator_id=operator.id,
        principal=operator.principal(),
        generation=session.generation,
        authenticated_at=_NOW,
        absolute_expires_at=session.absolute_expires_at,
        idle_expires_at=session.idle_expires_at,
    )


class _CsrfBoundary:
    def __init__(self, record: ControlPlaneDurableSessionRecord) -> None:
        self.record = record
        self.calls = 0
        self.reject = False

    async def verify_csrf(
        self,
        token_value: str | None,
        authentication: ControlPlaneDurableSessionAuthentication,
        *,
        supplied_origin: ControlPlaneBrowserOrigin,
        expected_origin: ControlPlaneBrowserOrigin,
    ) -> ControlPlaneDurableSessionRecord:
        self.calls += 1
        if (
            self.reject
            or token_value != _CSRF_HEADER
            or authentication.session_id != self.record.id
            or supplied_origin != _ORIGIN
            or expected_origin != _ORIGIN
        ):
            raise ControlPlaneDurableSessionCsrfRejectedError("csrf rejected")
        return self.record


class _Source:
    def __init__(self) -> None:
        self.subject = AuthoritySubject(
            principal_type=PrincipalType.SERVICE,
            principal="service:agent-owner",
            session_id=_TARGET_SESSION_ID,
            agent_id="assistant",
            run_id="50000000-0000-0000-0000-000000000033",
        )
        self.intent = AuthorityIntent(
            action="memory.read",
            canonical_resource=(
                f"agent-memory:composition/scope:agent:assistant/record:{_MEMORY_ID}"
            ),
            parameter_digest="sha256:" + "b" * 64,
        )
        self.observation = AuthorityPathObservation(
            intent=self.intent,
            boundaries=("memory.read",),
            effect=AuthorityEffect.ALLOWED,
        )
        self.resolve_subject_calls = 0
        self.resolve_intent_calls = 0
        self.inspect_calls = 0
        self.explain_calls = 0
        self.inspect_entered: asyncio.Event | None = None
        self.inspect_release: asyncio.Event | None = None

    async def resolve_subject(self, target_ref: str) -> AuthoritySubject:
        self.resolve_subject_calls += 1
        assert target_ref == "agent-42"
        return self.subject

    async def inspect(self, subject: AuthoritySubject) -> AuthorityInspectionState:
        self.inspect_calls += 1
        assert subject == self.subject
        if self.inspect_entered is not None and self.inspect_release is not None:
            self.inspect_entered.set()
            await self.inspect_release.wait()
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
        assert action == "memory.read"
        assert resource_ref == "memory-slot"
        return self.intent

    async def explain(
        self,
        subject: AuthoritySubject,
        intent: AuthorityIntent,
    ) -> tuple[AuthorityPathObservation, datetime]:
        self.explain_calls += 1
        assert subject == self.subject
        assert intent == self.intent
        return self.observation, _NOW


def _allow_rule(action: str, resource: str) -> PolicyRule:
    return PolicyRule(
        rule_id=f"allow-{action.replace('.', '-')}",
        effect=PolicyEffect.ALLOW,
        actions=frozenset({action}),
        resources=frozenset({resource}),
        principals=frozenset({"alice"}),
        principal_types=frozenset({PrincipalType.USER}),
        authenticated=True,
    )


async def _setup(
    *,
    policy: PolicyEngine | None = None,
) -> tuple[
    ControlPlaneAuthorityHttpAdapter,
    _Source,
    _CsrfBoundary,
    InMemoryControlPlaneDurableSessionRepository,
    InMemoryControlPlaneOperatorRegistry,
    ControlPlaneOperatorRecord,
    ControlPlaneDurableSessionRecord,
    ControlPlaneDurableSessionAuthentication,
]:
    operator = _operator()
    registry = InMemoryControlPlaneOperatorRegistry()
    await registry.add(operator)
    session = _session(operator)
    repository = InMemoryControlPlaneDurableSessionRepository()
    await repository.add(session)
    authentication = _authentication(operator, session)
    source = _Source()
    boundary = _CsrfBoundary(session)
    selected_policy = PolicyEngine() if policy is None else policy
    service = create_control_plane_authority_service(
        policy=selected_policy,
        source=source,
        repository=repository,
        registry=registry,
        clock=lambda: _NOW,
    )
    adapter = ControlPlaneAuthorityHttpAdapter(
        service=service,
        boundary=boundary,
        clock=lambda: _NOW,
    )
    return (
        adapter,
        source,
        boundary,
        repository,
        registry,
        operator,
        session,
        authentication,
    )


def _headers() -> dict[str, tuple[str, ...]]:
    return {
        "origin": (_ORIGIN.value,),
        "x-phoenix-csrf": (_CSRF_HEADER,),
    }


def test_operator_authentication_maps_only_trusted_structural_caller_identity() -> None:
    operator = _operator()
    session = _session(operator)
    authentication = _authentication(operator, session)

    context = control_plane_authority_security_context(authentication)

    assert context == SecurityContext(
        principal="alice",
        principal_type=PrincipalType.USER,
        authenticated=True,
        permissions=operator.effective_permissions,
        session_id=_SESSION_ID,
    )
    assert context.session_id == authentication.session_id
    assert context.attributes == {}
    assert "session_id" not in context.attributes
    assert not context.confirmed


@pytest.mark.asyncio
async def test_durable_freshness_revalidates_without_mutating_session() -> None:
    operator = _operator()
    registry = InMemoryControlPlaneOperatorRegistry()
    await registry.add(operator)
    session = _session(operator)
    repository = InMemoryControlPlaneDurableSessionRepository()
    await repository.add(session)
    validator = ControlPlaneDurableAuthorityFreshnessValidator(
        repository=repository,
        registry=registry,
        clock=lambda: _NOW,
    )
    context = control_plane_authority_security_context(_authentication(operator, session))

    before = await repository.get(session.id)
    await validator.validate(context)
    after = await repository.get(session.id)

    assert before == session
    assert after == session


@pytest.mark.asyncio
@pytest.mark.parametrize("mutation", ["principal", "permissions", "attributes", "session"])
async def test_durable_freshness_rejects_fabricated_caller_dimensions(mutation: str) -> None:
    operator = _operator()
    registry = InMemoryControlPlaneOperatorRegistry()
    await registry.add(operator)
    session = _session(operator)
    repository = InMemoryControlPlaneDurableSessionRepository()
    await repository.add(session)
    validator = ControlPlaneDurableAuthorityFreshnessValidator(
        repository=repository,
        registry=registry,
        clock=lambda: _NOW,
    )
    context = control_plane_authority_security_context(_authentication(operator, session))
    if mutation == "principal":
        context = replace(context, principal="mallory")
    elif mutation == "permissions":
        context = replace(context, permissions=frozenset({"control-plane.read"}))
    elif mutation == "attributes":
        context = replace(context, attributes={"session_id": str(session.id)})
    else:
        context = replace(context, session_id=UUID(int=999))

    with pytest.raises(AuthorityFreshnessRejectedError):
        await validator.validate(context)


@pytest.mark.asyncio
async def test_durable_freshness_rejects_clock_rollback_and_stale_operator_revision() -> None:
    operator = _operator()
    registry = InMemoryControlPlaneOperatorRegistry()
    await registry.add(operator)
    session = _session(operator)
    repository = InMemoryControlPlaneDurableSessionRepository()
    await repository.add(session)
    context = control_plane_authority_security_context(_authentication(operator, session))

    rollback = ControlPlaneDurableAuthorityFreshnessValidator(
        repository=repository,
        registry=registry,
        clock=lambda: _NOW - timedelta(seconds=1),
    )
    with pytest.raises(AuthorityFreshnessRejectedError):
        await rollback.validate(context)

    stale_repository = InMemoryControlPlaneDurableSessionRepository()
    await stale_repository.add(replace(session, operator_revision=operator.revision + 1))
    stale = ControlPlaneDurableAuthorityFreshnessValidator(
        repository=stale_repository,
        registry=registry,
        clock=lambda: _NOW,
    )
    with pytest.raises(AuthorityFreshnessRejectedError):
        await stale.validate(context)


@pytest.mark.asyncio
async def test_http_inspection_requires_exact_authority_policy_not_control_plane_role() -> None:
    adapter, source, boundary, _, _, _, _, authentication = await _setup()

    status, payload, headers = await adapter.dispatch(
        authentication=authentication,
        method="POST",
        path=AUTHORITY_INSPECT_CONTROL_PLANE_PATH,
        query={},
        headers=_headers(),
        body=json.dumps({"target_ref": "agent-42"}).encode(),
        server_origin=_ORIGIN,
    )

    assert status is HTTPStatus.FORBIDDEN
    assert payload == {"error": "forbidden"}
    assert headers == {"Cache-Control": "no-store"}
    assert boundary.calls == 1
    assert source.resolve_subject_calls == 1
    assert source.inspect_calls == 0


@pytest.mark.asyncio
async def test_http_inspection_returns_only_service_redacted_projection() -> None:
    source = _Source()
    policy = PolicyEngine(
        (_allow_rule(AUTHORITY_INSPECT_ACTION, authority_subject_resource(source.subject)),)
    )
    (
        adapter,
        actual_source,
        boundary,
        _,
        _,
        _,
        _,
        authentication,
    ) = await _setup(policy=policy)
    assert actual_source.subject == source.subject

    status, payload, headers = await adapter.dispatch(
        authentication=authentication,
        method="POST",
        path=AUTHORITY_INSPECT_CONTROL_PLANE_PATH,
        query={},
        headers=_headers(),
        body=b'{"target_ref":"agent-42"}',
        server_origin=_ORIGIN,
    )

    assert status is HTTPStatus.OK
    assert headers == {"Cache-Control": "no-store"}
    assert payload["schema_version"] == 1
    subject = payload["subject"]
    assert isinstance(subject, dict)
    assert subject["principal"] == "service:agent-owner"
    assert isinstance(subject["session_identity"], str)
    encoded = json.dumps(payload, sort_keys=True)
    assert str(_TARGET_SESSION_ID) not in encoded
    assert "sha256:" in encoded
    assert boundary.calls == 1
    assert actual_source.inspect_calls == 1


@pytest.mark.asyncio
async def test_http_explanation_binds_exact_server_resolved_intent() -> None:
    source = _Source()
    policy = PolicyEngine(
        (
            _allow_rule(
                AUTHORITY_EXPLAIN_ACTION,
                authority_explanation_resource(source.subject, source.intent),
            ),
        )
    )
    (
        adapter,
        actual_source,
        _,
        _,
        _,
        _,
        _,
        authentication,
    ) = await _setup(policy=policy)
    assert actual_source.intent == source.intent

    status, payload, headers = await adapter.dispatch(
        authentication=authentication,
        method="POST",
        path=AUTHORITY_EXPLAIN_CONTROL_PLANE_PATH,
        query={},
        headers=_headers(),
        body=json.dumps(
            {
                "target_ref": "agent-42",
                "action": "memory.read",
                "resource_ref": "memory-slot",
            }
        ).encode(),
        server_origin=_ORIGIN,
    )

    assert status is HTTPStatus.OK
    assert headers == {"Cache-Control": "no-store"}
    observation = payload["observation"]
    assert isinstance(observation, dict)
    assert observation["requested_action"] == "memory.read"
    assert observation["canonical_resource"] == actual_source.intent.canonical_resource
    assert actual_source.resolve_intent_calls == 1
    assert actual_source.explain_calls == 1


@pytest.mark.asyncio
async def test_http_requires_session_bound_csrf_before_authority_resolution() -> None:
    adapter, source, boundary, _, _, _, _, authentication = await _setup()
    boundary.reject = True

    status, payload, headers = await adapter.dispatch(
        authentication=authentication,
        method="POST",
        path=AUTHORITY_INSPECT_CONTROL_PLANE_PATH,
        query={},
        headers=_headers(),
        body=b'{"target_ref":"agent-42"}',
        server_origin=_ORIGIN,
    )

    assert status is HTTPStatus.FORBIDDEN
    assert payload == {"error": "request_rejected"}
    assert headers == {"Cache-Control": "no-store"}
    assert source.resolve_subject_calls == 0


@pytest.mark.asyncio
async def test_http_rejects_identity_fields_in_request_body_as_data_only() -> None:
    adapter, source, _, _, _, _, _, authentication = await _setup()

    status, payload, headers = await adapter.dispatch(
        authentication=authentication,
        method="POST",
        path=AUTHORITY_INSPECT_CONTROL_PLANE_PATH,
        query={},
        headers=_headers(),
        body=json.dumps(
            {
                "target_ref": "agent-42",
                "session_id": str(_SESSION_ID),
                "principal": "mallory",
            }
        ).encode(),
        server_origin=_ORIGIN,
    )

    assert status is HTTPStatus.BAD_REQUEST
    assert payload == {"error": "invalid_authority_request"}
    assert headers == {"Cache-Control": "no-store"}
    assert source.resolve_subject_calls == 0


@pytest.mark.asyncio
async def test_session_revocation_during_source_wait_blocks_result_release() -> None:
    source = _Source()
    policy = PolicyEngine(
        (_allow_rule(AUTHORITY_INSPECT_ACTION, authority_subject_resource(source.subject)),)
    )
    (
        adapter,
        actual_source,
        _,
        repository,
        _,
        _,
        session,
        authentication,
    ) = await _setup(policy=policy)
    actual_source.inspect_entered = asyncio.Event()
    actual_source.inspect_release = asyncio.Event()

    task = asyncio.create_task(
        adapter.dispatch(
            authentication=authentication,
            method="POST",
            path=AUTHORITY_INSPECT_CONTROL_PLANE_PATH,
            query={},
            headers=_headers(),
            body=b'{"target_ref":"agent-42"}',
            server_origin=_ORIGIN,
        )
    )
    await actual_source.inspect_entered.wait()
    await repository.terminate(
        session.id,
        expected_revision=session.revision,
        status=ControlPlaneDurableSessionStatus.REVOKED,
        reason=ControlPlaneDurableSessionTerminationReason.ADMINISTRATIVE,
        terminated_at=_NOW + timedelta(seconds=1),
    )
    actual_source.inspect_release.set()

    status, payload, headers = await task

    assert status is HTTPStatus.FORBIDDEN
    assert payload == {"error": "forbidden"}
    assert headers == {"Cache-Control": "no-store"}
    assert actual_source.inspect_calls == 1


@pytest.mark.asyncio
async def test_inactive_operator_fails_freshness_without_session_mutation() -> None:
    operator = _operator()
    disabled = replace(
        operator,
        status=ControlPlaneOperatorStatus.DISABLED,
        disabled_at=_NOW,
        updated_at=_NOW,
        revision=operator.revision + 1,
    )
    registry = InMemoryControlPlaneOperatorRegistry()
    await registry.add(disabled)
    session = _session(operator)
    repository = InMemoryControlPlaneDurableSessionRepository()
    await repository.add(session)
    validator = ControlPlaneDurableAuthorityFreshnessValidator(
        repository=repository,
        registry=registry,
        clock=lambda: _NOW,
    )
    context = SecurityContext(
        principal="alice",
        principal_type=PrincipalType.USER,
        authenticated=True,
        permissions=operator.effective_permissions,
        session_id=session.id,
    )

    with pytest.raises(AuthorityFreshnessRejectedError):
        await validator.validate(context)

    assert await repository.get(session.id) == session


def test_runtime_composes_authority_http_only_with_durable_operator_mode_and_policy() -> None:
    from phoenix_os.capabilities import CapabilityRegistry
    from phoenix_os.control_plane.runtime import ControlPlaneRuntimeStack
    from phoenix_os.events import EventBus

    source = _Source()
    registry = InMemoryControlPlaneOperatorRegistry()
    repository = InMemoryControlPlaneDurableSessionRepository()

    with pytest.raises(ValueError, match="PolicyEngine"):
        ControlPlaneRuntimeStack.create(
            event_bus=EventBus(),
            capabilities=CapabilityRegistry(),
            operator_registry=registry,
            durable_session_repository=repository,
            authority_source=source,
        )

    stack = ControlPlaneRuntimeStack.create(
        event_bus=EventBus(),
        capabilities=CapabilityRegistry(),
        operator_registry=registry,
        durable_session_repository=repository,
        authority_source=source,
        policy_engine=PolicyEngine(),
    )

    assert isinstance(stack.http.authority_http, ControlPlaneAuthorityHttpAdapter)
