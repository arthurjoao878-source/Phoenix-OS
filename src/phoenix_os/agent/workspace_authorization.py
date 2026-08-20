"""Exact deny-by-default authorization for secure Phoenix agent workspaces."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Protocol, runtime_checkable

from phoenix_os.agent.contracts import AgentId, AgentRunId
from phoenix_os.agent.errors import AgentAuthorizationRejectedError
from phoenix_os.agent.workspace_contracts import (
    ArtifactDeleteRequest,
    ArtifactExportRequest,
    ArtifactId,
    ArtifactImportRequest,
    ArtifactListRequest,
    ArtifactReadRequest,
    ArtifactWriteRequest,
    WorkspaceNamespace,
    WorkspaceScope,
    WorkspaceScopeId,
    WorkspaceScopeKind,
    WorkspaceTransferReference,
    canonical_artifact_path_digest,
)
from phoenix_os.policy import PhoenixPolicyError, PolicyEngine, PolicyRequest, SecurityContext

WORKSPACE_LIST_ACTION = "workspace.list"
WORKSPACE_READ_ACTION = "workspace.read"
WORKSPACE_WRITE_ACTION = "workspace.write"
WORKSPACE_DELETE_ACTION = "workspace.delete"
WORKSPACE_IMPORT_ACTION = "workspace.import"
WORKSPACE_EXPORT_ACTION = "workspace.export"
WORKSPACE_ADMIN_ACTION = "workspace.admin"


def run_workspace_scope(*, namespace: WorkspaceNamespace, run_id: AgentRunId) -> WorkspaceScope:
    """Derive one exact run scope from trusted Phoenix-owned identities."""

    if not isinstance(namespace, WorkspaceNamespace):
        raise TypeError("namespace must be WorkspaceNamespace")
    if not isinstance(run_id, AgentRunId):
        raise TypeError("run_id must be AgentRunId")
    return WorkspaceScope(
        namespace=namespace,
        kind=WorkspaceScopeKind.RUN,
        scope_id=WorkspaceScopeId(str(run_id)),
    )


def agent_workspace_scope(
    *,
    namespace: WorkspaceNamespace,
    agent_id: AgentId,
) -> WorkspaceScope:
    """Derive one exact agent scope from a trusted server-owned AgentId."""

    if not isinstance(namespace, WorkspaceNamespace):
        raise TypeError("namespace must be WorkspaceNamespace")
    if not isinstance(agent_id, AgentId):
        raise TypeError("agent_id must be AgentId")
    return WorkspaceScope(
        namespace=namespace,
        kind=WorkspaceScopeKind.AGENT,
        scope_id=WorkspaceScopeId(str(agent_id)),
    )


def principal_workspace_scope(
    *,
    namespace: WorkspaceNamespace,
    context: SecurityContext,
) -> WorkspaceScope:
    """Derive a content-free principal scope without exposing the raw principal."""

    if not isinstance(namespace, WorkspaceNamespace):
        raise TypeError("namespace must be WorkspaceNamespace")
    _require_authenticated_context(context)
    identity = f"{context.principal_type.value}\0{context.principal}".encode()
    digest = hashlib.sha256(identity).hexdigest()
    return WorkspaceScope(
        namespace=namespace,
        kind=WorkspaceScopeKind.PRINCIPAL,
        scope_id=WorkspaceScopeId(f"{context.principal_type.value}-{digest}"),
    )


def workspace_scope_resource(scope: WorkspaceScope) -> str:
    """Return the exact collection-level policy resource for one workspace scope."""

    if not isinstance(scope, WorkspaceScope):
        raise TypeError("scope must be WorkspaceScope")
    return f"agent-workspace:{scope.namespace}/scope:{scope.kind.value}:{scope.scope_id}"


def workspace_artifact_resource(scope: WorkspaceScope, artifact_id: ArtifactId) -> str:
    """Return the exact artifact-level policy resource for one Phoenix artifact."""

    if not isinstance(scope, WorkspaceScope):
        raise TypeError("scope must be WorkspaceScope")
    if not isinstance(artifact_id, ArtifactId):
        raise TypeError("artifact_id must be ArtifactId")
    return f"{workspace_scope_resource(scope)}/artifact:{artifact_id}"


def _canonical_transfer_reference_digest(reference: WorkspaceTransferReference) -> str:
    if not isinstance(reference, WorkspaceTransferReference):
        raise TypeError("reference must be WorkspaceTransferReference")
    return "sha256:" + hashlib.sha256(reference.value.encode("utf-8")).hexdigest()


@runtime_checkable
class WorkspaceAuthorizer(Protocol):
    """Authorize exact workspace operations without touching artifact bytes."""

    async def authorize_list(
        self,
        request: ArtifactListRequest,
        context: SecurityContext,
    ) -> None: ...

    async def authorize_read(
        self,
        request: ArtifactReadRequest,
        context: SecurityContext,
    ) -> None: ...

    async def authorize_write(
        self,
        request: ArtifactWriteRequest,
        context: SecurityContext,
    ) -> None: ...

    async def authorize_delete(
        self,
        request: ArtifactDeleteRequest,
        context: SecurityContext,
    ) -> None: ...

    async def authorize_import(
        self,
        request: ArtifactImportRequest,
        context: SecurityContext,
    ) -> None: ...

    async def authorize_export(
        self,
        request: ArtifactExportRequest,
        context: SecurityContext,
    ) -> None: ...

    async def authorize_admin(
        self,
        scope: WorkspaceScope,
        context: SecurityContext,
        *,
        created_at: datetime | None = None,
    ) -> None: ...


class PolicyEngineWorkspaceAuthorizer:
    """Apply fresh exact workspace policy to every current operation."""

    def __init__(self, policy: PolicyEngine) -> None:
        if not isinstance(policy, PolicyEngine):
            raise TypeError("policy must be PolicyEngine")
        self._policy = policy

    async def authorize_list(
        self,
        request: ArtifactListRequest,
        context: SecurityContext,
    ) -> None:
        if not isinstance(request, ArtifactListRequest):
            raise TypeError("request must be ArtifactListRequest")
        _require_authenticated_context(context)
        _validate_principal_scope_binding(request.scope, context)
        await self._enforce(
            action=WORKSPACE_LIST_ACTION,
            resource=workspace_scope_resource(request.scope),
            context=context,
            attributes={
                **_scope_attributes(request.scope),
                "prefix_digest": (
                    canonical_artifact_path_digest(request.prefix)
                    if request.prefix is not None
                    else "absent"
                ),
                "max_results": str(request.max_results),
            },
            created_at=request.created_at,
        )

    async def authorize_read(
        self,
        request: ArtifactReadRequest,
        context: SecurityContext,
    ) -> None:
        if not isinstance(request, ArtifactReadRequest):
            raise TypeError("request must be ArtifactReadRequest")
        _require_authenticated_context(context)
        _validate_principal_scope_binding(request.scope, context)
        await self._enforce(
            action=WORKSPACE_READ_ACTION,
            resource=workspace_artifact_resource(request.scope, request.artifact_id),
            context=context,
            attributes={
                **_scope_attributes(request.scope),
                "artifact_id": str(request.artifact_id),
                "expected_version": (
                    str(request.expected_version.value)
                    if request.expected_version is not None
                    else "absent"
                ),
            },
            created_at=request.created_at,
        )

    async def authorize_write(
        self,
        request: ArtifactWriteRequest,
        context: SecurityContext,
    ) -> None:
        if not isinstance(request, ArtifactWriteRequest):
            raise TypeError("request must be ArtifactWriteRequest")
        _require_authenticated_context(context)
        _validate_principal_scope_binding(request.scope, context)
        await self._enforce(
            action=WORKSPACE_WRITE_ACTION,
            resource=workspace_artifact_resource(request.scope, request.artifact_id),
            context=context,
            attributes={
                **_scope_attributes(request.scope),
                "artifact_id": str(request.artifact_id),
                "logical_path_digest": canonical_artifact_path_digest(request.logical_path),
                "content_digest": str(request.provenance.content_digest),
                "content_bytes": str(len(request.content)),
                "media_type": str(request.media_type),
                "metadata_items": str(len(request.metadata)),
                "expected_version": (
                    str(request.expected_version.value)
                    if request.expected_version is not None
                    else "absent"
                ),
                "origin": request.provenance.origin.value,
            },
            created_at=request.created_at,
        )

    async def authorize_delete(
        self,
        request: ArtifactDeleteRequest,
        context: SecurityContext,
    ) -> None:
        if not isinstance(request, ArtifactDeleteRequest):
            raise TypeError("request must be ArtifactDeleteRequest")
        _require_authenticated_context(context)
        _validate_principal_scope_binding(request.scope, context)
        await self._enforce(
            action=WORKSPACE_DELETE_ACTION,
            resource=workspace_artifact_resource(request.scope, request.artifact_id),
            context=context,
            attributes={
                **_scope_attributes(request.scope),
                "artifact_id": str(request.artifact_id),
                "expected_version": str(request.expected_version.value),
            },
            created_at=request.created_at,
        )

    async def authorize_import(
        self,
        request: ArtifactImportRequest,
        context: SecurityContext,
    ) -> None:
        if not isinstance(request, ArtifactImportRequest):
            raise TypeError("request must be ArtifactImportRequest")
        _require_authenticated_context(context)
        _validate_principal_scope_binding(request.scope, context)
        await self._enforce(
            action=WORKSPACE_IMPORT_ACTION,
            resource=workspace_artifact_resource(request.scope, request.artifact_id),
            context=context,
            attributes={
                **_scope_attributes(request.scope),
                "artifact_id": str(request.artifact_id),
                "expected_version": (
                    str(request.expected_version.value)
                    if request.expected_version is not None
                    else "absent"
                ),
                "source_reference_digest": _canonical_transfer_reference_digest(
                    request.source_reference
                ),
            },
            created_at=request.created_at,
        )

    async def authorize_export(
        self,
        request: ArtifactExportRequest,
        context: SecurityContext,
    ) -> None:
        if not isinstance(request, ArtifactExportRequest):
            raise TypeError("request must be ArtifactExportRequest")
        _require_authenticated_context(context)
        _validate_principal_scope_binding(request.scope, context)
        await self._enforce(
            action=WORKSPACE_EXPORT_ACTION,
            resource=workspace_artifact_resource(request.scope, request.artifact_id),
            context=context,
            attributes={
                **_scope_attributes(request.scope),
                "artifact_id": str(request.artifact_id),
                "expected_version": str(request.expected_version.value),
                "destination_reference_digest": _canonical_transfer_reference_digest(
                    request.destination_reference
                ),
            },
            created_at=request.created_at,
        )

    async def authorize_admin(
        self,
        scope: WorkspaceScope,
        context: SecurityContext,
        *,
        created_at: datetime | None = None,
    ) -> None:
        _validate_scope_and_context(scope, context)
        await self._enforce(
            action=WORKSPACE_ADMIN_ACTION,
            resource=workspace_scope_resource(scope),
            context=context,
            attributes=_scope_attributes(scope),
            created_at=_validated_timestamp(created_at),
        )

    async def _enforce(
        self,
        *,
        action: str,
        resource: str,
        context: SecurityContext,
        attributes: dict[str, str],
        created_at: datetime,
    ) -> None:
        try:
            await self._policy.enforce(
                PolicyRequest(
                    action=action,
                    resource=resource,
                    context=context,
                    attributes=attributes,
                    created_at=created_at,
                )
            )
        except PhoenixPolicyError as exception:
            raise AgentAuthorizationRejectedError() from exception


def _validated_timestamp(created_at: datetime | None) -> datetime:
    timestamp = created_at or datetime.now(UTC)
    if not isinstance(timestamp, datetime):
        raise TypeError("created_at must be a datetime")
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise ValueError("created_at must be timezone-aware")
    return timestamp


def _require_authenticated_context(context: SecurityContext) -> None:
    if not isinstance(context, SecurityContext):
        raise TypeError("context must be SecurityContext")
    if not context.authenticated:
        raise AgentAuthorizationRejectedError()


def _validate_principal_scope_binding(
    scope: WorkspaceScope,
    context: SecurityContext,
) -> None:
    if scope.kind is not WorkspaceScopeKind.PRINCIPAL:
        return
    if principal_workspace_scope(namespace=scope.namespace, context=context) != scope:
        raise AgentAuthorizationRejectedError()


def _validate_scope_and_context(
    scope: WorkspaceScope,
    context: SecurityContext,
) -> None:
    if not isinstance(scope, WorkspaceScope):
        raise TypeError("scope must be WorkspaceScope")
    _require_authenticated_context(context)
    _validate_principal_scope_binding(scope, context)


def _scope_attributes(scope: WorkspaceScope) -> dict[str, str]:
    return {
        "workspace_namespace": str(scope.namespace),
        "scope_kind": scope.kind.value,
        "scope_id": str(scope.scope_id),
    }
