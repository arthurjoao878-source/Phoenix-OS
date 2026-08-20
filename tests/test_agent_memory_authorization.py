from datetime import UTC, datetime
from uuid import UUID

import pytest

from phoenix_os.agent import (
    MEMORY_ADMIN_ACTION,
    MEMORY_DELETE_ACTION,
    MEMORY_READ_ACTION,
    MEMORY_SEARCH_ACTION,
    MEMORY_WRITE_ACTION,
    AgentAuthorizationRejectedError,
    AgentId,
    AgentRunId,
    MemoryDeleteRequest,
    MemoryId,
    MemoryNamespace,
    MemoryOriginKind,
    MemoryProvenance,
    MemoryReadRequest,
    MemoryRecordIncarnation,
    MemoryRecordVersion,
    MemoryScope,
    MemorySearchRequest,
    MemoryWriteRequest,
    PolicyEngineMemoryAuthorizer,
    agent_memory_scope,
    canonical_memory_query_digest,
    memory_content_digest,
    memory_record_resource,
    memory_scope_resource,
    principal_memory_scope,
    run_memory_scope,
)
from phoenix_os.policy import (
    PolicyEffect,
    PolicyEngine,
    PolicyRule,
    PrincipalType,
    SecurityContext,
)

_NOW = datetime(2026, 8, 11, 23, 30, tzinfo=UTC)
_NAMESPACE = MemoryNamespace("default")
_MEMORY_ID = MemoryId(UUID("30000000-0000-0000-0000-000000000030"))
_INCARNATION = MemoryRecordIncarnation(UUID("60000000-0000-4000-8000-000000000030"))


def _context(
    principal: str = "service:memory-owner",
    *,
    authenticated: bool = True,
) -> SecurityContext:
    return SecurityContext(
        principal=principal if authenticated else "anonymous",
        principal_type=PrincipalType.SERVICE if authenticated else PrincipalType.ANONYMOUS,
        authenticated=authenticated,
    )


def _agent_scope() -> MemoryScope:
    return agent_memory_scope(
        namespace=_NAMESPACE,
        agent_id=AgentId("researcher"),
    )


def _provenance(content: str) -> MemoryProvenance:
    return MemoryProvenance(
        origin=MemoryOriginKind.AGENT_REQUEST,
        content_digest=memory_content_digest(content),
        created_at=_NOW,
        source_agent_id=AgentId("researcher"),
    )


def _write(content: str = "remembered fact") -> MemoryWriteRequest:
    return MemoryWriteRequest(
        scope=_agent_scope(),
        memory_id=_MEMORY_ID,
        content=content,
        provenance=_provenance(content),
        created_at=_NOW,
    )


def test_memory_actions_and_resources_are_exact() -> None:
    run_id = AgentRunId(UUID("10000000-0000-0000-0000-000000000030"))
    run_scope = run_memory_scope(namespace=_NAMESPACE, run_id=run_id)
    agent_scope = _agent_scope()

    assert MEMORY_SEARCH_ACTION == "memory.search"
    assert MEMORY_READ_ACTION == "memory.read"
    assert MEMORY_WRITE_ACTION == "memory.write"
    assert MEMORY_DELETE_ACTION == "memory.delete"
    assert MEMORY_ADMIN_ACTION == "memory.admin"
    assert memory_scope_resource(run_scope) == (
        "agent-memory:default/scope:run:10000000-0000-0000-0000-000000000030"
    )
    assert memory_scope_resource(agent_scope) == ("agent-memory:default/scope:agent:researcher")
    assert memory_record_resource(agent_scope, _MEMORY_ID) == (
        "agent-memory:default/scope:agent:researcher/record:30000000-0000-0000-0000-000000000030"
    )


def test_principal_scope_is_stable_content_free_and_does_not_leak_identity() -> None:
    context = _context()
    first = principal_memory_scope(namespace=_NAMESPACE, context=context)
    second = principal_memory_scope(namespace=_NAMESPACE, context=context)
    resource = memory_scope_resource(first)

    assert first == second
    assert first.kind.value == "principal"
    assert str(first.scope_id).startswith("service-")
    assert "service:memory-owner" not in resource
    assert "/" not in str(first.scope_id)
    assert ":" not in str(first.scope_id)


@pytest.mark.asyncio
async def test_search_authorization_is_exact_default_deny_and_query_bound() -> None:
    request = MemorySearchRequest(
        scope=_agent_scope(),
        query="project phoenix",
        max_results=4,
        max_bytes=4096,
        created_at=_NOW,
    )
    digest = canonical_memory_query_digest(request)
    policy = PolicyEngine(
        (
            PolicyRule(
                rule_id="allow.memory.search",
                effect=PolicyEffect.ALLOW,
                actions=frozenset({MEMORY_SEARCH_ACTION}),
                resources=frozenset({memory_scope_resource(request.scope)}),
                principals=frozenset({"service:memory-owner"}),
                authenticated=True,
                attribute_equals={
                    "query_digest": digest,
                    "query_bytes": str(len(request.query.encode("utf-8"))),
                    "max_results": "4",
                },
            ),
        )
    )
    authorizer = PolicyEngineMemoryAuthorizer(policy)

    await authorizer.authorize_search(request, _context())
    with pytest.raises(AgentAuthorizationRejectedError):
        await authorizer.authorize_search(
            MemorySearchRequest(
                scope=_agent_scope(),
                query="different query",
                max_results=4,
                max_bytes=4096,
                created_at=_NOW,
            ),
            _context(),
        )

    snapshot = await policy.snapshot()
    assert snapshot.allowed == 1
    assert snapshot.denied == 1


@pytest.mark.asyncio
async def test_memory_search_authority_does_not_grant_write() -> None:
    scope = _agent_scope()
    policy = PolicyEngine(
        (
            PolicyRule(
                rule_id="search.only",
                effect=PolicyEffect.ALLOW,
                actions=frozenset({MEMORY_SEARCH_ACTION}),
                resources=frozenset({memory_scope_resource(scope)}),
                principals=frozenset({"service:memory-owner"}),
                authenticated=True,
            ),
        )
    )

    with pytest.raises(AgentAuthorizationRejectedError):
        await PolicyEngineMemoryAuthorizer(policy).authorize_write(
            _write(),
            _context(),
        )


@pytest.mark.asyncio
async def test_agent_run_authority_does_not_grant_memory_access() -> None:
    policy = PolicyEngine(
        (
            PolicyRule(
                rule_id="agent.run.only",
                effect=PolicyEffect.ALLOW,
                actions=frozenset({"agent.run"}),
                resources=frozenset({"agent:researcher"}),
                principals=frozenset({"service:memory-owner"}),
                authenticated=True,
            ),
        )
    )

    with pytest.raises(AgentAuthorizationRejectedError):
        await PolicyEngineMemoryAuthorizer(policy).authorize_search(
            MemorySearchRequest(
                scope=_agent_scope(),
                query="query",
                created_at=_NOW,
            ),
            _context(),
        )


@pytest.mark.asyncio
async def test_write_authorization_binds_record_digest_without_exposing_content() -> None:
    request = _write("private remembered fact")
    digest = memory_content_digest(request.content)
    resource = memory_record_resource(request.scope, request.memory_id)
    policy = PolicyEngine(
        (
            PolicyRule(
                rule_id="allow.memory.write",
                effect=PolicyEffect.ALLOW,
                actions=frozenset({MEMORY_WRITE_ACTION}),
                resources=frozenset({resource}),
                principals=frozenset({"service:memory-owner"}),
                authenticated=True,
                attribute_equals={
                    "content_digest": digest,
                    "content_bytes": str(len(request.content.encode("utf-8"))),
                    "origin": MemoryOriginKind.AGENT_REQUEST.value,
                },
            ),
        )
    )

    assert request.content not in resource
    await PolicyEngineMemoryAuthorizer(policy).authorize_write(request, _context())
    assert (await policy.snapshot()).allowed == 1


@pytest.mark.asyncio
async def test_direct_read_and_delete_require_exact_record_authority() -> None:
    scope = _agent_scope()
    read = MemoryReadRequest(
        scope=scope,
        memory_id=_MEMORY_ID,
        expected_version=MemoryRecordVersion(3),
        expected_incarnation=_INCARNATION,
        created_at=_NOW,
    )
    delete = MemoryDeleteRequest(
        scope=scope,
        memory_id=_MEMORY_ID,
        expected_version=MemoryRecordVersion(3),
        expected_incarnation=_INCARNATION,
        created_at=_NOW,
    )
    resource = memory_record_resource(scope, _MEMORY_ID)
    read_policy = PolicyEngine(
        (
            PolicyRule(
                rule_id="read.one.record",
                effect=PolicyEffect.ALLOW,
                actions=frozenset({MEMORY_READ_ACTION}),
                resources=frozenset({resource}),
                principals=frozenset({"service:memory-owner"}),
                authenticated=True,
                attribute_equals={
                    "expected_version": "3",
                    "expected_incarnation": str(_INCARNATION),
                },
            ),
        )
    )
    delete_policy = PolicyEngine(
        (
            PolicyRule(
                rule_id="delete.one.record",
                effect=PolicyEffect.ALLOW,
                actions=frozenset({MEMORY_DELETE_ACTION}),
                resources=frozenset({resource}),
                principals=frozenset({"service:memory-owner"}),
                authenticated=True,
                attribute_equals={
                    "expected_version": "3",
                    "expected_incarnation": str(_INCARNATION),
                },
            ),
        )
    )

    await PolicyEngineMemoryAuthorizer(read_policy).authorize_read(read, _context())
    await PolicyEngineMemoryAuthorizer(delete_policy).authorize_delete(delete, _context())

    other = MemoryReadRequest(
        scope=scope,
        memory_id=MemoryId(UUID("40000000-0000-0000-0000-000000000030")),
        created_at=_NOW,
    )
    with pytest.raises(AgentAuthorizationRejectedError):
        await PolicyEngineMemoryAuthorizer(read_policy).authorize_read(other, _context())

    wrong_incarnation = MemoryReadRequest(
        scope=scope,
        memory_id=_MEMORY_ID,
        expected_version=MemoryRecordVersion(3),
        expected_incarnation=MemoryRecordIncarnation(UUID("70000000-0000-4000-8000-000000000030")),
        created_at=_NOW,
    )
    with pytest.raises(AgentAuthorizationRejectedError):
        await PolicyEngineMemoryAuthorizer(read_policy).authorize_read(
            wrong_incarnation,
            _context(),
        )


@pytest.mark.asyncio
async def test_admin_authorization_is_separate_and_collection_scoped() -> None:
    scope = _agent_scope()
    policy = PolicyEngine(
        (
            PolicyRule(
                rule_id="allow.memory.admin",
                effect=PolicyEffect.ALLOW,
                actions=frozenset({MEMORY_ADMIN_ACTION}),
                resources=frozenset({memory_scope_resource(scope)}),
                principals=frozenset({"service:memory-owner"}),
                authenticated=True,
            ),
        )
    )

    await PolicyEngineMemoryAuthorizer(policy).authorize_admin(
        scope,
        _context(),
        created_at=_NOW,
    )
    assert (await policy.snapshot()).allowed == 1


@pytest.mark.asyncio
async def test_principal_scope_mismatch_fails_before_policy_evaluation() -> None:
    owner = _context("service:owner")
    attacker = _context("service:attacker")
    scope = principal_memory_scope(namespace=_NAMESPACE, context=owner)
    policy = PolicyEngine(
        (
            PolicyRule(
                rule_id="allow.any.memory.search",
                effect=PolicyEffect.ALLOW,
                actions=frozenset({MEMORY_SEARCH_ACTION}),
                resources=frozenset({"agent-memory:*"}),
                principals=frozenset({"*"}),
                authenticated=True,
            ),
        )
    )
    request = MemorySearchRequest(scope=scope, query="query", created_at=_NOW)

    with pytest.raises(AgentAuthorizationRejectedError):
        await PolicyEngineMemoryAuthorizer(policy).authorize_search(request, attacker)

    assert (await policy.snapshot()).evaluations == 0


@pytest.mark.asyncio
async def test_unauthenticated_memory_access_fails_before_policy_evaluation() -> None:
    policy = PolicyEngine()
    request = MemorySearchRequest(
        scope=_agent_scope(),
        query="query",
        created_at=_NOW,
    )

    with pytest.raises(AgentAuthorizationRejectedError):
        await PolicyEngineMemoryAuthorizer(policy).authorize_search(
            request,
            _context(authenticated=False),
        )

    assert (await policy.snapshot()).evaluations == 0


@pytest.mark.asyncio
async def test_authorizer_uses_current_policy_on_every_operation() -> None:
    request = MemorySearchRequest(
        scope=_agent_scope(),
        query="query",
        created_at=_NOW,
    )
    policy = PolicyEngine()
    rule = PolicyRule(
        rule_id="temporary.memory.search",
        effect=PolicyEffect.ALLOW,
        actions=frozenset({MEMORY_SEARCH_ACTION}),
        resources=frozenset({memory_scope_resource(request.scope)}),
        principals=frozenset({"service:memory-owner"}),
        authenticated=True,
    )
    registration = await policy.register(rule)
    authorizer = PolicyEngineMemoryAuthorizer(policy)

    await authorizer.authorize_search(request, _context())
    assert await policy.unregister(registration)
    with pytest.raises(AgentAuthorizationRejectedError):
        await authorizer.authorize_search(request, _context())

    snapshot = await policy.snapshot()
    assert snapshot.allowed == 1
    assert snapshot.denied == 1
