"""Exact deny-by-default authorization for secure Phoenix agent memory."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Protocol, runtime_checkable

from phoenix_os.agent.contracts import AgentId, AgentRunId
from phoenix_os.agent.errors import AgentAuthorizationRejectedError
from phoenix_os.agent.memory_contracts import (
    MemoryDeleteRequest,
    MemoryId,
    MemoryNamespace,
    MemoryReadRequest,
    MemoryScope,
    MemoryScopeId,
    MemoryScopeKind,
    MemorySearchRequest,
    MemoryWriteRequest,
    memory_content_digest,
)
from phoenix_os.policy import PhoenixPolicyError, PolicyEngine, PolicyRequest, SecurityContext

MEMORY_SEARCH_ACTION = "memory.search"
MEMORY_READ_ACTION = "memory.read"
MEMORY_WRITE_ACTION = "memory.write"
MEMORY_DELETE_ACTION = "memory.delete"
MEMORY_ADMIN_ACTION = "memory.admin"


def run_memory_scope(*, namespace: MemoryNamespace, run_id: AgentRunId) -> MemoryScope:
    """Derive one exact run scope from trusted Phoenix-owned identities."""

    if not isinstance(namespace, MemoryNamespace):
        raise TypeError("namespace must be MemoryNamespace")
    if not isinstance(run_id, AgentRunId):
        raise TypeError("run_id must be AgentRunId")
    return MemoryScope(
        namespace=namespace,
        kind=MemoryScopeKind.RUN,
        scope_id=MemoryScopeId(str(run_id)),
    )


def agent_memory_scope(*, namespace: MemoryNamespace, agent_id: AgentId) -> MemoryScope:
    """Derive one exact agent scope from a trusted server-owned AgentId."""

    if not isinstance(namespace, MemoryNamespace):
        raise TypeError("namespace must be MemoryNamespace")
    if not isinstance(agent_id, AgentId):
        raise TypeError("agent_id must be AgentId")
    return MemoryScope(
        namespace=namespace,
        kind=MemoryScopeKind.AGENT,
        scope_id=MemoryScopeId(str(agent_id)),
    )


def principal_memory_scope(
    *,
    namespace: MemoryNamespace,
    context: SecurityContext,
) -> MemoryScope:
    """Derive a content-free principal scope without exposing the raw principal."""

    if not isinstance(namespace, MemoryNamespace):
        raise TypeError("namespace must be MemoryNamespace")
    _require_authenticated_context(context)
    identity = f"{context.principal_type.value}\0{context.principal}".encode()
    digest = hashlib.sha256(identity).hexdigest()
    return MemoryScope(
        namespace=namespace,
        kind=MemoryScopeKind.PRINCIPAL,
        scope_id=MemoryScopeId(f"{context.principal_type.value}-{digest}"),
    )


def memory_scope_resource(scope: MemoryScope) -> str:
    """Return the exact collection-level policy resource for one memory scope."""

    if not isinstance(scope, MemoryScope):
        raise TypeError("scope must be MemoryScope")
    return f"agent-memory:{scope.namespace}/scope:{scope.kind.value}:{scope.scope_id}"


def memory_record_resource(scope: MemoryScope, memory_id: MemoryId) -> str:
    """Return the exact record-level policy resource for one memory record."""

    if not isinstance(scope, MemoryScope):
        raise TypeError("scope must be MemoryScope")
    if not isinstance(memory_id, MemoryId):
        raise TypeError("memory_id must be MemoryId")
    return f"{memory_scope_resource(scope)}/record:{memory_id}"


def canonical_memory_query_digest(request: MemorySearchRequest) -> str:
    """Return a stable content-free digest binding authorization to one query."""

    if not isinstance(request, MemorySearchRequest):
        raise TypeError("request must be MemorySearchRequest")
    return "sha256:" + hashlib.sha256(request.query.encode("utf-8")).hexdigest()


@runtime_checkable
class MemoryAuthorizer(Protocol):
    """Authorize exact memory operations without reading, writing, or searching."""

    async def authorize_search(
        self,
        request: MemorySearchRequest,
        context: SecurityContext,
    ) -> None: ...

    async def authorize_read(
        self,
        request: MemoryReadRequest,
        context: SecurityContext,
    ) -> None: ...

    async def authorize_write(
        self,
        request: MemoryWriteRequest,
        context: SecurityContext,
    ) -> None: ...

    async def authorize_delete(
        self,
        request: MemoryDeleteRequest,
        context: SecurityContext,
    ) -> None: ...

    async def authorize_admin(
        self,
        scope: MemoryScope,
        context: SecurityContext,
        *,
        created_at: datetime | None = None,
    ) -> None: ...


class PolicyEngineMemoryAuthorizer:
    """Apply fresh exact memory policy to every current operation."""

    def __init__(self, policy: PolicyEngine) -> None:
        if not isinstance(policy, PolicyEngine):
            raise TypeError("policy must be PolicyEngine")
        self._policy = policy

    async def authorize_search(
        self,
        request: MemorySearchRequest,
        context: SecurityContext,
    ) -> None:
        if not isinstance(request, MemorySearchRequest):
            raise TypeError("request must be MemorySearchRequest")
        _require_authenticated_context(context)
        _validate_principal_scope_binding(request.scope, context)
        await self._enforce(
            action=MEMORY_SEARCH_ACTION,
            resource=memory_scope_resource(request.scope),
            context=context,
            attributes={
                **_scope_attributes(request.scope),
                "query_digest": canonical_memory_query_digest(request),
                "query_bytes": str(len(request.query.encode("utf-8"))),
                "max_results": str(request.max_results),
                "max_bytes": str(request.max_bytes),
            },
            created_at=request.created_at,
        )

    async def authorize_read(
        self,
        request: MemoryReadRequest,
        context: SecurityContext,
    ) -> None:
        if not isinstance(request, MemoryReadRequest):
            raise TypeError("request must be MemoryReadRequest")
        _require_authenticated_context(context)
        _validate_principal_scope_binding(request.scope, context)
        await self._enforce(
            action=MEMORY_READ_ACTION,
            resource=memory_record_resource(request.scope, request.memory_id),
            context=context,
            attributes={
                **_scope_attributes(request.scope),
                "memory_id": str(request.memory_id),
            },
            created_at=request.created_at,
        )

    async def authorize_write(
        self,
        request: MemoryWriteRequest,
        context: SecurityContext,
    ) -> None:
        if not isinstance(request, MemoryWriteRequest):
            raise TypeError("request must be MemoryWriteRequest")
        _require_authenticated_context(context)
        _validate_principal_scope_binding(request.scope, context)
        await self._enforce(
            action=MEMORY_WRITE_ACTION,
            resource=memory_record_resource(request.scope, request.memory_id),
            context=context,
            attributes={
                **_scope_attributes(request.scope),
                "memory_id": str(request.memory_id),
                "content_digest": memory_content_digest(request.content),
                "content_bytes": str(len(request.content.encode("utf-8"))),
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
        request: MemoryDeleteRequest,
        context: SecurityContext,
    ) -> None:
        if not isinstance(request, MemoryDeleteRequest):
            raise TypeError("request must be MemoryDeleteRequest")
        _require_authenticated_context(context)
        _validate_principal_scope_binding(request.scope, context)
        await self._enforce(
            action=MEMORY_DELETE_ACTION,
            resource=memory_record_resource(request.scope, request.memory_id),
            context=context,
            attributes={
                **_scope_attributes(request.scope),
                "memory_id": str(request.memory_id),
                "expected_version": str(request.expected_version.value),
            },
            created_at=request.created_at,
        )

    async def authorize_admin(
        self,
        scope: MemoryScope,
        context: SecurityContext,
        *,
        created_at: datetime | None = None,
    ) -> None:
        if not isinstance(scope, MemoryScope):
            raise TypeError("scope must be MemoryScope")
        _require_authenticated_context(context)
        _validate_principal_scope_binding(scope, context)
        timestamp = created_at or datetime.now(UTC)
        if not isinstance(timestamp, datetime):
            raise TypeError("created_at must be a datetime")
        if timestamp.tzinfo is None or timestamp.utcoffset() is None:
            raise ValueError("created_at must be timezone-aware")
        await self._enforce(
            action=MEMORY_ADMIN_ACTION,
            resource=memory_scope_resource(scope),
            context=context,
            attributes=_scope_attributes(scope),
            created_at=timestamp,
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


def _require_authenticated_context(context: SecurityContext) -> None:
    if not isinstance(context, SecurityContext):
        raise TypeError("context must be SecurityContext")
    if not context.authenticated:
        raise AgentAuthorizationRejectedError()


def _validate_principal_scope_binding(
    scope: MemoryScope,
    context: SecurityContext,
) -> None:
    if scope.kind is not MemoryScopeKind.PRINCIPAL:
        return
    if principal_memory_scope(namespace=scope.namespace, context=context) != scope:
        raise AgentAuthorizationRejectedError()


def _scope_attributes(scope: MemoryScope) -> dict[str, str]:
    return {
        "memory_namespace": str(scope.namespace),
        "scope_kind": scope.kind.value,
        "scope_id": str(scope.scope_id),
    }
