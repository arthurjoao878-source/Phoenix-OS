import hashlib
from datetime import UTC, datetime
from uuid import UUID

import pytest

from phoenix_os.agent import (
    WORKSPACE_ADMIN_ACTION,
    WORKSPACE_DELETE_ACTION,
    WORKSPACE_EXPORT_ACTION,
    WORKSPACE_IMPORT_ACTION,
    WORKSPACE_LIST_ACTION,
    WORKSPACE_READ_ACTION,
    WORKSPACE_WRITE_ACTION,
    AgentAuthorizationRejectedError,
    AgentId,
    AgentRunId,
    ArtifactDeleteRequest,
    ArtifactExportRequest,
    ArtifactId,
    ArtifactImportRequest,
    ArtifactListRequest,
    ArtifactLogicalPath,
    ArtifactOriginKind,
    ArtifactProvenance,
    ArtifactReadRequest,
    ArtifactVersion,
    ArtifactWriteRequest,
    PolicyEngineWorkspaceAuthorizer,
    WorkspaceNamespace,
    WorkspaceScope,
    WorkspaceTransferReference,
    agent_workspace_scope,
    artifact_content_digest,
    canonical_artifact_path_digest,
    principal_workspace_scope,
    run_workspace_scope,
    workspace_artifact_resource,
    workspace_scope_resource,
)
from phoenix_os.policy import (
    PolicyEffect,
    PolicyEngine,
    PolicyRule,
    PrincipalType,
    SecurityContext,
)


def _require_logical_path(value: ArtifactLogicalPath | None) -> ArtifactLogicalPath:
    assert value is not None
    return value


_NOW = datetime(2026, 8, 12, 5, 45, tzinfo=UTC)
_NAMESPACE = WorkspaceNamespace("default")
_ARTIFACT_ID = ArtifactId(UUID("40000000-0000-0000-0000-000000000031"))


def _context(
    principal: str = "service:workspace-owner",
    *,
    authenticated: bool = True,
) -> SecurityContext:
    return SecurityContext(
        principal=principal if authenticated else "anonymous",
        principal_type=PrincipalType.SERVICE if authenticated else PrincipalType.ANONYMOUS,
        authenticated=authenticated,
    )


def _agent_scope() -> WorkspaceScope:
    return agent_workspace_scope(
        namespace=_NAMESPACE,
        agent_id=AgentId("researcher"),
    )


def _provenance(content: bytes) -> ArtifactProvenance:
    return ArtifactProvenance(
        origin=ArtifactOriginKind.AGENT_REQUEST,
        content_digest=artifact_content_digest(content),
        created_at=_NOW,
        source_agent_id=AgentId("researcher"),
    )


def _write(content: bytes = b"workspace artifact") -> ArtifactWriteRequest:
    return ArtifactWriteRequest(
        scope=_agent_scope(),
        artifact_id=_ARTIFACT_ID,
        logical_path=ArtifactLogicalPath("reports/result.txt"),
        content=content,
        provenance=_provenance(content),
        created_at=_NOW,
    )


def test_workspace_actions_and_resources_are_exact() -> None:
    run_id = AgentRunId(UUID("50000000-0000-0000-0000-000000000031"))
    run_scope = run_workspace_scope(namespace=_NAMESPACE, run_id=run_id)
    agent_scope = _agent_scope()

    assert WORKSPACE_LIST_ACTION == "workspace.list"
    assert WORKSPACE_READ_ACTION == "workspace.read"
    assert WORKSPACE_WRITE_ACTION == "workspace.write"
    assert WORKSPACE_DELETE_ACTION == "workspace.delete"
    assert WORKSPACE_IMPORT_ACTION == "workspace.import"
    assert WORKSPACE_EXPORT_ACTION == "workspace.export"
    assert WORKSPACE_ADMIN_ACTION == "workspace.admin"
    assert workspace_scope_resource(run_scope) == (
        "agent-workspace:default/scope:run:50000000-0000-0000-0000-000000000031"
    )
    assert workspace_scope_resource(agent_scope) == (
        "agent-workspace:default/scope:agent:researcher"
    )
    assert workspace_artifact_resource(agent_scope, _ARTIFACT_ID) == (
        "agent-workspace:default/scope:agent:researcher/"
        "artifact:40000000-0000-0000-0000-000000000031"
    )


def test_principal_scope_is_stable_content_free_and_does_not_leak_identity() -> None:
    context = _context()
    first = principal_workspace_scope(namespace=_NAMESPACE, context=context)
    second = principal_workspace_scope(namespace=_NAMESPACE, context=context)
    resource = workspace_scope_resource(first)

    assert first == second
    assert first.kind.value == "principal"
    assert str(first.scope_id).startswith("service-")
    assert "service:workspace-owner" not in resource
    assert "/" not in str(first.scope_id)
    assert ":" not in str(first.scope_id)


@pytest.mark.asyncio
async def test_list_authorization_is_exact_default_deny_and_prefix_bound() -> None:
    request = ArtifactListRequest(
        scope=_agent_scope(),
        prefix=ArtifactLogicalPath("Reports"),
        max_results=4,
        created_at=_NOW,
    )
    prefix_digest = canonical_artifact_path_digest(_require_logical_path(request.prefix))
    policy = PolicyEngine(
        (
            PolicyRule(
                rule_id="allow.workspace.list",
                effect=PolicyEffect.ALLOW,
                actions=frozenset({WORKSPACE_LIST_ACTION}),
                resources=frozenset({workspace_scope_resource(request.scope)}),
                principals=frozenset({"service:workspace-owner"}),
                authenticated=True,
                attribute_equals={
                    "prefix_digest": prefix_digest,
                    "max_results": "4",
                },
            ),
        )
    )
    authorizer = PolicyEngineWorkspaceAuthorizer(policy)

    await authorizer.authorize_list(request, _context())
    with pytest.raises(AgentAuthorizationRejectedError):
        await authorizer.authorize_list(
            ArtifactListRequest(
                scope=_agent_scope(),
                prefix=ArtifactLogicalPath("Private"),
                max_results=4,
                created_at=_NOW,
            ),
            _context(),
        )

    snapshot = await policy.snapshot()
    assert snapshot.allowed == 1
    assert snapshot.denied == 1


@pytest.mark.asyncio
async def test_workspace_list_authority_does_not_grant_read() -> None:
    scope = _agent_scope()
    policy = PolicyEngine(
        (
            PolicyRule(
                rule_id="list.only",
                effect=PolicyEffect.ALLOW,
                actions=frozenset({WORKSPACE_LIST_ACTION}),
                resources=frozenset({workspace_scope_resource(scope)}),
                principals=frozenset({"service:workspace-owner"}),
                authenticated=True,
            ),
        )
    )

    with pytest.raises(AgentAuthorizationRejectedError):
        await PolicyEngineWorkspaceAuthorizer(policy).authorize_read(
            ArtifactReadRequest(scope=scope, artifact_id=_ARTIFACT_ID, created_at=_NOW),
            _context(),
        )


@pytest.mark.asyncio
async def test_agent_and_memory_authority_do_not_grant_workspace_access() -> None:
    scope = _agent_scope()
    policy = PolicyEngine(
        (
            PolicyRule(
                rule_id="other.authority.only",
                effect=PolicyEffect.ALLOW,
                actions=frozenset({"agent.run", "memory.read"}),
                resources=frozenset({"*"}),
                principals=frozenset({"service:workspace-owner"}),
                authenticated=True,
            ),
        )
    )

    with pytest.raises(AgentAuthorizationRejectedError):
        await PolicyEngineWorkspaceAuthorizer(policy).authorize_list(
            ArtifactListRequest(scope=scope, created_at=_NOW),
            _context(),
        )


@pytest.mark.asyncio
async def test_write_authorization_binds_digest_path_and_size_without_exposing_bytes() -> None:
    request = _write(b"private workspace bytes")
    resource = workspace_artifact_resource(request.scope, request.artifact_id)
    policy = PolicyEngine(
        (
            PolicyRule(
                rule_id="allow.workspace.write",
                effect=PolicyEffect.ALLOW,
                actions=frozenset({WORKSPACE_WRITE_ACTION}),
                resources=frozenset({resource}),
                principals=frozenset({"service:workspace-owner"}),
                authenticated=True,
                attribute_equals={
                    "content_digest": str(request.provenance.content_digest),
                    "logical_path_digest": canonical_artifact_path_digest(
                        _require_logical_path(request.logical_path)
                    ),
                    "content_bytes": str(len(request.content)),
                    "origin": ArtifactOriginKind.AGENT_REQUEST.value,
                },
            ),
        )
    )

    assert request.content.decode() not in resource
    assert str(request.logical_path) not in resource
    await PolicyEngineWorkspaceAuthorizer(policy).authorize_write(request, _context())
    assert (await policy.snapshot()).allowed == 1


@pytest.mark.asyncio
async def test_direct_read_and_delete_require_exact_artifact_authority() -> None:
    scope = _agent_scope()
    read = ArtifactReadRequest(
        scope=scope,
        artifact_id=_ARTIFACT_ID,
        expected_version=ArtifactVersion(3),
        created_at=_NOW,
    )
    delete = ArtifactDeleteRequest(
        scope=scope,
        artifact_id=_ARTIFACT_ID,
        expected_version=ArtifactVersion(3),
        created_at=_NOW,
    )
    resource = workspace_artifact_resource(scope, _ARTIFACT_ID)
    read_policy = PolicyEngine(
        (
            PolicyRule(
                rule_id="read.one.artifact",
                effect=PolicyEffect.ALLOW,
                actions=frozenset({WORKSPACE_READ_ACTION}),
                resources=frozenset({resource}),
                principals=frozenset({"service:workspace-owner"}),
                authenticated=True,
                attribute_equals={"expected_version": "3"},
            ),
        )
    )
    delete_policy = PolicyEngine(
        (
            PolicyRule(
                rule_id="delete.one.artifact",
                effect=PolicyEffect.ALLOW,
                actions=frozenset({WORKSPACE_DELETE_ACTION}),
                resources=frozenset({resource}),
                principals=frozenset({"service:workspace-owner"}),
                authenticated=True,
                attribute_equals={"expected_version": "3"},
            ),
        )
    )

    await PolicyEngineWorkspaceAuthorizer(read_policy).authorize_read(read, _context())
    await PolicyEngineWorkspaceAuthorizer(delete_policy).authorize_delete(delete, _context())

    other = ArtifactReadRequest(
        scope=scope,
        artifact_id=ArtifactId(UUID("60000000-0000-0000-0000-000000000031")),
        created_at=_NOW,
    )
    with pytest.raises(AgentAuthorizationRejectedError):
        await PolicyEngineWorkspaceAuthorizer(read_policy).authorize_read(other, _context())


@pytest.mark.asyncio
async def test_import_and_export_are_independent_exact_artifact_authorities() -> None:
    scope = _agent_scope()
    resource = workspace_artifact_resource(scope, _ARTIFACT_ID)
    imported = ArtifactImportRequest(
        scope=scope,
        artifact_id=_ARTIFACT_ID,
        source_reference=WorkspaceTransferReference("source-object"),
        created_at=_NOW,
    )
    exported = ArtifactExportRequest(
        scope=scope,
        artifact_id=_ARTIFACT_ID,
        expected_version=ArtifactVersion(3),
        destination_reference=WorkspaceTransferReference("destination-object"),
        created_at=_NOW,
    )
    policy = PolicyEngine(
        (
            PolicyRule(
                rule_id="import.only",
                effect=PolicyEffect.ALLOW,
                actions=frozenset({WORKSPACE_IMPORT_ACTION}),
                resources=frozenset({resource}),
                principals=frozenset({"service:workspace-owner"}),
                authenticated=True,
            ),
        )
    )
    authorizer = PolicyEngineWorkspaceAuthorizer(policy)

    await authorizer.authorize_import(imported, _context())
    with pytest.raises(AgentAuthorizationRejectedError):
        await authorizer.authorize_export(exported, _context())

    snapshot = await policy.snapshot()
    assert snapshot.allowed == 1
    assert snapshot.denied == 1


@pytest.mark.asyncio
async def test_transfer_authorization_binds_version_and_reference_digest() -> None:
    scope = _agent_scope()
    resource = workspace_artifact_resource(scope, _ARTIFACT_ID)
    imported = ArtifactImportRequest(
        scope=scope,
        artifact_id=_ARTIFACT_ID,
        source_reference=WorkspaceTransferReference("source-alpha"),
        expected_version=ArtifactVersion(4),
        created_at=_NOW,
    )
    import_digest = (
        "sha256:" + hashlib.sha256(imported.source_reference.value.encode("utf-8")).hexdigest()
    )
    import_policy = PolicyEngine(
        (
            PolicyRule(
                rule_id="import.exact.intent",
                effect=PolicyEffect.ALLOW,
                actions=frozenset({WORKSPACE_IMPORT_ACTION}),
                resources=frozenset({resource}),
                principals=frozenset({"service:workspace-owner"}),
                authenticated=True,
                attribute_equals={
                    "expected_version": "4",
                    "source_reference_digest": import_digest,
                },
            ),
        )
    )
    import_authorizer = PolicyEngineWorkspaceAuthorizer(import_policy)

    await import_authorizer.authorize_import(imported, _context())
    with pytest.raises(AgentAuthorizationRejectedError):
        await import_authorizer.authorize_import(
            ArtifactImportRequest(
                scope=scope,
                artifact_id=_ARTIFACT_ID,
                source_reference=WorkspaceTransferReference("source-bravo"),
                expected_version=ArtifactVersion(4),
                created_at=_NOW,
            ),
            _context(),
        )
    with pytest.raises(AgentAuthorizationRejectedError):
        await import_authorizer.authorize_import(
            ArtifactImportRequest(
                scope=scope,
                artifact_id=_ARTIFACT_ID,
                source_reference=imported.source_reference,
                expected_version=ArtifactVersion(5),
                created_at=_NOW,
            ),
            _context(),
        )

    exported = ArtifactExportRequest(
        scope=scope,
        artifact_id=_ARTIFACT_ID,
        expected_version=ArtifactVersion(7),
        destination_reference=WorkspaceTransferReference("destination-alpha"),
        created_at=_NOW,
    )
    export_digest = (
        "sha256:" + hashlib.sha256(exported.destination_reference.value.encode("utf-8")).hexdigest()
    )
    export_policy = PolicyEngine(
        (
            PolicyRule(
                rule_id="export.exact.intent",
                effect=PolicyEffect.ALLOW,
                actions=frozenset({WORKSPACE_EXPORT_ACTION}),
                resources=frozenset({resource}),
                principals=frozenset({"service:workspace-owner"}),
                authenticated=True,
                attribute_equals={
                    "expected_version": "7",
                    "destination_reference_digest": export_digest,
                },
            ),
        )
    )
    export_authorizer = PolicyEngineWorkspaceAuthorizer(export_policy)

    await export_authorizer.authorize_export(exported, _context())
    with pytest.raises(AgentAuthorizationRejectedError):
        await export_authorizer.authorize_export(
            ArtifactExportRequest(
                scope=scope,
                artifact_id=_ARTIFACT_ID,
                expected_version=ArtifactVersion(7),
                destination_reference=WorkspaceTransferReference("destination-bravo"),
                created_at=_NOW,
            ),
            _context(),
        )
    with pytest.raises(AgentAuthorizationRejectedError):
        await export_authorizer.authorize_export(
            ArtifactExportRequest(
                scope=scope,
                artifact_id=_ARTIFACT_ID,
                expected_version=ArtifactVersion(8),
                destination_reference=exported.destination_reference,
                created_at=_NOW,
            ),
            _context(),
        )


@pytest.mark.asyncio
async def test_admin_authorization_is_separate_and_collection_scoped() -> None:
    scope = _agent_scope()
    policy = PolicyEngine(
        (
            PolicyRule(
                rule_id="allow.workspace.admin",
                effect=PolicyEffect.ALLOW,
                actions=frozenset({WORKSPACE_ADMIN_ACTION}),
                resources=frozenset({workspace_scope_resource(scope)}),
                principals=frozenset({"service:workspace-owner"}),
                authenticated=True,
            ),
        )
    )

    await PolicyEngineWorkspaceAuthorizer(policy).authorize_admin(
        scope,
        _context(),
        created_at=_NOW,
    )
    assert (await policy.snapshot()).allowed == 1


@pytest.mark.asyncio
async def test_principal_scope_mismatch_fails_before_policy_evaluation() -> None:
    owner = _context("service:owner")
    attacker = _context("service:attacker")
    scope = principal_workspace_scope(namespace=_NAMESPACE, context=owner)
    policy = PolicyEngine(
        (
            PolicyRule(
                rule_id="allow.any.workspace.list",
                effect=PolicyEffect.ALLOW,
                actions=frozenset({WORKSPACE_LIST_ACTION}),
                resources=frozenset({"agent-workspace:*"}),
                principals=frozenset({"*"}),
                authenticated=True,
            ),
        )
    )
    request = ArtifactListRequest(scope=scope, created_at=_NOW)

    with pytest.raises(AgentAuthorizationRejectedError):
        await PolicyEngineWorkspaceAuthorizer(policy).authorize_list(request, attacker)

    assert (await policy.snapshot()).evaluations == 0


@pytest.mark.asyncio
async def test_unauthenticated_workspace_access_fails_before_policy_evaluation() -> None:
    policy = PolicyEngine()
    request = ArtifactListRequest(scope=_agent_scope(), created_at=_NOW)

    with pytest.raises(AgentAuthorizationRejectedError):
        await PolicyEngineWorkspaceAuthorizer(policy).authorize_list(
            request,
            _context(authenticated=False),
        )

    assert (await policy.snapshot()).evaluations == 0


@pytest.mark.asyncio
async def test_authorizer_uses_current_policy_on_every_operation() -> None:
    request = ArtifactListRequest(scope=_agent_scope(), created_at=_NOW)
    policy = PolicyEngine()
    rule = PolicyRule(
        rule_id="temporary.workspace.list",
        effect=PolicyEffect.ALLOW,
        actions=frozenset({WORKSPACE_LIST_ACTION}),
        resources=frozenset({workspace_scope_resource(request.scope)}),
        principals=frozenset({"service:workspace-owner"}),
        authenticated=True,
    )
    registration = await policy.register(rule)
    authorizer = PolicyEngineWorkspaceAuthorizer(policy)

    await authorizer.authorize_list(request, _context())
    assert await policy.unregister(registration)
    with pytest.raises(AgentAuthorizationRejectedError):
        await authorizer.authorize_list(request, _context())

    snapshot = await policy.snapshot()
    assert snapshot.allowed == 1
    assert snapshot.denied == 1


@pytest.mark.asyncio
async def test_validation_happens_before_policy_evaluation() -> None:
    policy = PolicyEngine()

    with pytest.raises(TypeError):
        await PolicyEngineWorkspaceAuthorizer(policy).authorize_read(
            "not-a-request",  # type: ignore[arg-type]
            _context(),
        )

    assert (await policy.snapshot()).evaluations == 0
