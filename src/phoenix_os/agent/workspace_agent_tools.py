"""Reviewed agent-tool facade for exact server-owned workspace operations."""

from __future__ import annotations

import base64
import binascii
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import timedelta
from typing import cast
from uuid import UUID

from phoenix_os.agent.contracts import (
    MAX_AGENT_ARGUMENT_BYTES,
    MAX_AGENT_RESULT_BYTES,
    AgentId,
    AgentJsonInput,
    AgentJsonValue,
    ToolEffect,
    ToolId,
    ToolInvocationRequest,
    ToolInvocationResult,
    ToolResultStatus,
)
from phoenix_os.agent.errors import ToolExecutionError
from phoenix_os.agent.schemas import (
    MAX_TOOL_SCHEMA_STRING_LENGTH,
    ToolInputSchema,
    ToolOutputSchema,
    ToolSchema,
    ToolSchemaType,
)
from phoenix_os.agent.tools import ToolDescriptor, ToolResourceResolutionContext
from phoenix_os.agent.workspace_authorization import (
    WORKSPACE_DELETE_ACTION,
    WORKSPACE_EXPORT_ACTION,
    WORKSPACE_IMPORT_ACTION,
    WORKSPACE_LIST_ACTION,
    WORKSPACE_READ_ACTION,
    WORKSPACE_WRITE_ACTION,
    agent_workspace_scope,
    principal_workspace_scope,
    run_workspace_scope,
    workspace_artifact_resource,
    workspace_scope_resource,
)
from phoenix_os.agent.workspace_contracts import (
    MAX_WORKSPACE_LIST_RESULTS,
    ArtifactDeleteRequest,
    ArtifactExportRequest,
    ArtifactId,
    ArtifactImportRequest,
    ArtifactListRequest,
    ArtifactLogicalPath,
    ArtifactMediaType,
    ArtifactOriginKind,
    ArtifactProvenance,
    ArtifactReadRequest,
    ArtifactReadResult,
    ArtifactRecord,
    ArtifactStatus,
    ArtifactTransferDirection,
    ArtifactTransferReceipt,
    ArtifactVersion,
    ArtifactWriteRequest,
    WorkspaceLimits,
    WorkspaceNamespace,
    WorkspaceScope,
    WorkspaceScopeKind,
    WorkspaceTransferReference,
    artifact_content_digest,
)
from phoenix_os.agent.workspace_service import AgentWorkspaceService
from phoenix_os.policy import SecurityContext

MAX_WORKSPACE_AGENT_TOOL_CONTENT_BYTES = 196_608
MAX_WORKSPACE_AGENT_TOOL_BASE64_CHARS = 262_144
WORKSPACE_TOOL_RESOLVER_ID = "workspace-tool-resource"
WORKSPACE_TOOL_ADAPTER_ID = "workspace-tool"

_WORKSPACE_ACTIONS = frozenset(
    {
        WORKSPACE_LIST_ACTION,
        WORKSPACE_READ_ACTION,
        WORKSPACE_WRITE_ACTION,
        WORKSPACE_DELETE_ACTION,
        WORKSPACE_IMPORT_ACTION,
        WORKSPACE_EXPORT_ACTION,
    }
)


@dataclass(frozen=True, slots=True)
class WorkspaceAgentToolBinding:
    """Server-owned binding from one agent tool to one exact workspace scope kind."""

    agent_id: AgentId
    tool_id: ToolId
    namespace: WorkspaceNamespace
    scope_kind: WorkspaceScopeKind
    action: str

    def __post_init__(self) -> None:
        if not isinstance(self.agent_id, AgentId):
            raise TypeError("agent_id must be AgentId")
        if not isinstance(self.tool_id, ToolId):
            raise TypeError("tool_id must be ToolId")
        if not isinstance(self.namespace, WorkspaceNamespace):
            raise TypeError("namespace must be WorkspaceNamespace")
        if not isinstance(self.scope_kind, WorkspaceScopeKind):
            raise TypeError("scope_kind must be WorkspaceScopeKind")
        if not isinstance(self.action, str):
            raise TypeError("action must be a string")
        normalized = self.action.strip().lower()
        if normalized not in _WORKSPACE_ACTIONS:
            raise ValueError("unsupported workspace agent-tool action")
        object.__setattr__(self, "action", normalized)

    @property
    def binding_id(self) -> str:
        return workspace_tool_binding_id(self.namespace, self.scope_kind)


def workspace_tool_binding_id(
    namespace: WorkspaceNamespace,
    scope_kind: WorkspaceScopeKind,
) -> str:
    """Return the stable capability identity for one configured workspace scope kind."""

    if not isinstance(namespace, WorkspaceNamespace):
        raise TypeError("namespace must be WorkspaceNamespace")
    if not isinstance(scope_kind, WorkspaceScopeKind):
        raise TypeError("scope_kind must be WorkspaceScopeKind")
    return f"agent-workspace:{namespace}/scope:{scope_kind.value}"


def workspace_tool_descriptor(
    binding: WorkspaceAgentToolBinding,
    limits: WorkspaceLimits,
) -> ToolDescriptor:
    """Return one strict descriptor for an exact workspace action."""

    _require_binding(binding)
    if not isinstance(limits, WorkspaceLimits):
        raise TypeError("limits must be WorkspaceLimits")
    input_schema, output_schema = _schemas(binding, limits)
    effect = _effect(binding.action)
    return ToolDescriptor(
        tool_id=binding.tool_id,
        name=_tool_name(binding.action),
        description="Execute one bounded server-configured workspace operation.",
        input_schema=input_schema,
        output_schema=output_schema,
        effect=effect,
        approval_may_be_required=effect is not ToolEffect.READ_ONLY,
        max_input_bytes=MAX_AGENT_ARGUMENT_BYTES,
        max_output_bytes=MAX_AGENT_RESULT_BYTES,
        timeout=timedelta(minutes=2),
        resolver_id=WORKSPACE_TOOL_RESOLVER_ID,
        adapter_id=WORKSPACE_TOOL_ADAPTER_ID,
        metadata={
            "downstream_action": binding.action,
            "workspace_namespace": str(binding.namespace),
            "scope_kind": binding.scope_kind.value,
        },
    )


def workspace_tool_resolver(
    binding: WorkspaceAgentToolBinding,
) -> WorkspaceToolResourceResolver:
    """Return a resolver that keeps namespace and scope kind server-owned."""

    return WorkspaceToolResourceResolver(binding)


class WorkspaceToolResourceResolver:
    resolver_id = WORKSPACE_TOOL_RESOLVER_ID

    def __init__(self, binding: WorkspaceAgentToolBinding) -> None:
        _require_binding(binding)
        self._binding = binding

    def resolve_resource(self, arguments: Mapping[str, AgentJsonValue]) -> str:
        del arguments
        raise ToolExecutionError()

    def resolve_resource_with_context(
        self,
        arguments: Mapping[str, AgentJsonValue],
        context: ToolResourceResolutionContext,
    ) -> str:
        if not isinstance(arguments, Mapping):
            raise TypeError("arguments must be a mapping")
        if not isinstance(context, ToolResourceResolutionContext):
            raise TypeError("context must be ToolResourceResolutionContext")
        if context.agent_id != self._binding.agent_id:
            raise ToolExecutionError()
        scope_resource = _resolution_scope_resource(self._binding, context)
        if self._binding.action == WORKSPACE_LIST_ACTION:
            return scope_resource
        artifact_id = _artifact_id_argument(arguments)
        if self._binding.scope_kind is WorkspaceScopeKind.PRINCIPAL:
            return f"{scope_resource}/artifact:{artifact_id}"
        scope = _resolution_scope(self._binding, context)
        assert scope is not None
        return workspace_artifact_resource(scope, artifact_id)


class WorkspaceToolAdapter:
    """Translate an exact admitted tool call into the canonical workspace service."""

    adapter_id = WORKSPACE_TOOL_ADAPTER_ID

    def __init__(
        self,
        service: AgentWorkspaceService,
        binding: WorkspaceAgentToolBinding,
    ) -> None:
        if not isinstance(service, AgentWorkspaceService):
            raise TypeError("service must be AgentWorkspaceService")
        _require_binding(binding)
        self._service = service
        self._binding = binding
        self._resolver = WorkspaceToolResourceResolver(binding)

    @property
    def tool_id(self) -> ToolId:
        return self._binding.tool_id

    async def invoke(self, request: ToolInvocationRequest) -> ToolInvocationResult:
        del request
        raise ToolExecutionError()

    async def invoke_with_context(
        self,
        request: ToolInvocationRequest,
        context: SecurityContext,
    ) -> ToolInvocationResult:
        if not isinstance(request, ToolInvocationRequest):
            raise TypeError("request must be ToolInvocationRequest")
        if not isinstance(context, SecurityContext):
            raise TypeError("context must be SecurityContext")
        scope = self._validated_scope(request, context)
        if self._binding.action == WORKSPACE_LIST_ACTION:
            output = await self._list(request, scope, context)
        elif self._binding.action == WORKSPACE_READ_ACTION:
            output = await self._read(request, scope, context)
        elif self._binding.action == WORKSPACE_WRITE_ACTION:
            output = await self._write(request, scope, context)
        elif self._binding.action == WORKSPACE_DELETE_ACTION:
            output = await self._delete(request, scope, context)
        elif self._binding.action == WORKSPACE_IMPORT_ACTION:
            output = await self._import(request, scope, context)
        elif self._binding.action == WORKSPACE_EXPORT_ACTION:
            output = await self._export(request, scope, context)
        else:
            raise ToolExecutionError()
        return _success(request, output)

    def _validated_scope(
        self,
        request: ToolInvocationRequest,
        context: SecurityContext,
    ) -> WorkspaceScope:
        if request.agent_id != self._binding.agent_id or request.tool_id != self._binding.tool_id:
            raise ToolExecutionError()
        assert request.agent_id is not None
        expected = self._resolver.resolve_resource_with_context(
            cast(Mapping[str, AgentJsonValue], request.arguments),
            ToolResourceResolutionContext(
                agent_id=request.agent_id,
                run_id=request.run_id,
                step_id=request.step_id,
            ),
        )
        if request.resolved_resource != expected:
            raise ToolExecutionError()
        return _invocation_scope(self._binding, request, context)

    async def _list(
        self,
        request: ToolInvocationRequest,
        scope: WorkspaceScope,
        context: SecurityContext,
    ) -> Mapping[str, AgentJsonInput]:
        prefix_value = request.arguments.get("prefix")
        prefix = None
        if prefix_value is not None:
            if not isinstance(prefix_value, str):
                raise ToolExecutionError()
            try:
                prefix = ArtifactLogicalPath(prefix_value)
            except (TypeError, ValueError):
                raise ToolExecutionError() from None
        max_results = _optional_positive_int(
            request.arguments,
            "max_results",
            default=min(self._service.limits.max_list_results, MAX_WORKSPACE_LIST_RESULTS),
        )
        if (
            max_results > self._service.limits.max_list_results
            or max_results > MAX_WORKSPACE_LIST_RESULTS
        ):
            raise ToolExecutionError()
        result = await self._service.list(
            ArtifactListRequest(
                scope=scope,
                prefix=prefix,
                max_results=max_results,
                created_at=request.created_at,
            ),
            context,
        )
        if result.scope != scope:
            raise ToolExecutionError()
        return {"artifacts": [_record_output(record) for record in result.artifacts]}

    async def _read(
        self,
        request: ToolInvocationRequest,
        scope: WorkspaceScope,
        context: SecurityContext,
    ) -> Mapping[str, AgentJsonInput]:
        artifact_id = _artifact_id_argument(request.arguments)
        expected_version = _optional_version(request.arguments)
        result = await self._service.read(
            ArtifactReadRequest(
                scope=scope,
                artifact_id=artifact_id,
                expected_version=expected_version,
                created_at=request.created_at,
            ),
            context,
        )
        if result is None:
            return {"found": False}
        if (
            not isinstance(result, ArtifactReadResult)
            or result.record.scope != scope
            or result.record.artifact_id != artifact_id
            or len(result.content) > MAX_WORKSPACE_AGENT_TOOL_CONTENT_BYTES
        ):
            raise ToolExecutionError()
        return {
            "found": True,
            **_record_output(result.record),
            "content_base64": base64.b64encode(result.content).decode("ascii"),
        }

    async def _write(
        self,
        request: ToolInvocationRequest,
        scope: WorkspaceScope,
        context: SecurityContext,
    ) -> Mapping[str, AgentJsonInput]:
        artifact_id = _artifact_id_argument(request.arguments)
        logical_path = _logical_path_argument(request.arguments)
        content = _content_argument(request.arguments)
        if (
            len(content) > self._service.limits.max_artifact_bytes
            or len(content) > MAX_WORKSPACE_AGENT_TOOL_CONTENT_BYTES
        ):
            raise ToolExecutionError()
        media_type_value = request.arguments.get("media_type", "application/octet-stream")
        if not isinstance(media_type_value, str):
            raise ToolExecutionError()
        try:
            media_type = ArtifactMediaType(media_type_value)
        except (TypeError, ValueError):
            raise ToolExecutionError() from None
        expected_version = _optional_version(request.arguments)
        digest = artifact_content_digest(content)
        record = await self._service.write(
            ArtifactWriteRequest(
                scope=scope,
                artifact_id=artifact_id,
                logical_path=logical_path,
                content=content,
                media_type=media_type,
                provenance=ArtifactProvenance(
                    origin=ArtifactOriginKind.AGENT_REQUEST,
                    content_digest=digest,
                    source_run_id=request.run_id,
                    source_agent_id=request.agent_id,
                    source_principal_id=(
                        scope.scope_id if scope.kind is WorkspaceScopeKind.PRINCIPAL else None
                    ),
                    attributes={"tool_id": str(request.tool_id)},
                    created_at=request.created_at,
                ),
                expected_version=expected_version,
                created_at=request.created_at,
            ),
            context,
        )
        if (
            record.scope != scope
            or record.artifact_id != artifact_id
            or record.logical_path != logical_path
            or record.content_digest != digest
            or record.byte_length != len(content)
        ):
            raise ToolExecutionError()
        return _record_output(record)

    async def _delete(
        self,
        request: ToolInvocationRequest,
        scope: WorkspaceScope,
        context: SecurityContext,
    ) -> Mapping[str, AgentJsonInput]:
        artifact_id = _artifact_id_argument(request.arguments)
        version = ArtifactVersion(_required_positive_int(request.arguments, "expected_version"))
        await self._service.delete(
            ArtifactDeleteRequest(
                scope=scope,
                artifact_id=artifact_id,
                expected_version=version,
                created_at=request.created_at,
            ),
            context,
        )
        return {"deleted": True}

    async def _import(
        self,
        request: ToolInvocationRequest,
        scope: WorkspaceScope,
        context: SecurityContext,
    ) -> Mapping[str, AgentJsonInput]:
        artifact_id = _artifact_id_argument(request.arguments)
        source_reference = _transfer_reference_argument(request.arguments, "source_reference")
        expected_version = _optional_version(request.arguments)
        receipt = await self._service.import_artifact(
            ArtifactImportRequest(
                scope=scope,
                artifact_id=artifact_id,
                source_reference=source_reference,
                expected_version=expected_version,
                created_at=request.created_at,
            ),
            context,
        )
        return _receipt_output(
            receipt,
            expected_direction=ArtifactTransferDirection.IMPORT,
            scope=scope,
            artifact_id=artifact_id,
        )

    async def _export(
        self,
        request: ToolInvocationRequest,
        scope: WorkspaceScope,
        context: SecurityContext,
    ) -> Mapping[str, AgentJsonInput]:
        artifact_id = _artifact_id_argument(request.arguments)
        version = ArtifactVersion(_required_positive_int(request.arguments, "expected_version"))
        destination = _transfer_reference_argument(
            request.arguments,
            "destination_reference",
        )
        receipt = await self._service.export_artifact(
            ArtifactExportRequest(
                scope=scope,
                artifact_id=artifact_id,
                expected_version=version,
                destination_reference=destination,
                created_at=request.created_at,
            ),
            context,
        )
        return _receipt_output(
            receipt,
            expected_direction=ArtifactTransferDirection.EXPORT,
            scope=scope,
            artifact_id=artifact_id,
        )


def _schemas(
    binding: WorkspaceAgentToolBinding,
    limits: WorkspaceLimits,
) -> tuple[ToolInputSchema, ToolOutputSchema]:
    record_schema = _record_schema()
    artifact_selector = {"artifact_id": _uuid_schema()}
    if binding.action == WORKSPACE_LIST_ACTION:
        return (
            ToolInputSchema(
                _object(
                    {
                        "prefix": _string(
                            max_length=min(
                                limits.max_logical_path_bytes,
                                MAX_TOOL_SCHEMA_STRING_LENGTH,
                            )
                        ),
                        "max_results": _integer(
                            maximum=min(
                                limits.max_list_results,
                                MAX_WORKSPACE_LIST_RESULTS,
                            )
                        ),
                    }
                )
            ),
            ToolOutputSchema(
                _object(
                    {
                        "artifacts": ToolSchema(
                            kind=ToolSchemaType.ARRAY,
                            items=record_schema,
                            max_items=min(
                                limits.max_list_results,
                                MAX_WORKSPACE_LIST_RESULTS,
                            ),
                        )
                    },
                    required={"artifacts"},
                )
            ),
        )
    if binding.action == WORKSPACE_READ_ACTION:
        return (
            ToolInputSchema(
                _object(
                    {
                        **artifact_selector,
                        "expected_version": _integer(),
                    },
                    required={"artifact_id"},
                )
            ),
            ToolOutputSchema(
                _object(
                    {
                        "found": ToolSchema(kind=ToolSchemaType.BOOLEAN),
                        **record_schema.properties,
                        "content_base64": _string(max_length=MAX_WORKSPACE_AGENT_TOOL_BASE64_CHARS),
                    },
                    required={"found"},
                )
            ),
        )
    if binding.action == WORKSPACE_WRITE_ACTION:
        return (
            ToolInputSchema(
                _object(
                    {
                        **artifact_selector,
                        "logical_path": _string(
                            max_length=min(
                                limits.max_logical_path_bytes,
                                MAX_TOOL_SCHEMA_STRING_LENGTH,
                            )
                        ),
                        "content_base64": _string(max_length=MAX_WORKSPACE_AGENT_TOOL_BASE64_CHARS),
                        "media_type": _string(max_length=255),
                        "expected_version": _integer(),
                    },
                    required={"artifact_id", "logical_path", "content_base64"},
                )
            ),
            ToolOutputSchema(record_schema),
        )
    if binding.action == WORKSPACE_DELETE_ACTION:
        return (
            ToolInputSchema(
                _object(
                    {
                        **artifact_selector,
                        "expected_version": _integer(),
                    },
                    required={"artifact_id", "expected_version"},
                )
            ),
            ToolOutputSchema(
                _object(
                    {"deleted": ToolSchema(kind=ToolSchemaType.BOOLEAN)},
                    required={"deleted"},
                )
            ),
        )
    if binding.action == WORKSPACE_IMPORT_ACTION:
        return (
            ToolInputSchema(
                _object(
                    {
                        **artifact_selector,
                        "source_reference": _string(max_length=512),
                        "expected_version": _integer(),
                    },
                    required={"artifact_id", "source_reference"},
                )
            ),
            ToolOutputSchema(_receipt_schema()),
        )
    return (
        ToolInputSchema(
            _object(
                {
                    **artifact_selector,
                    "expected_version": _integer(),
                    "destination_reference": _string(max_length=512),
                },
                required={
                    "artifact_id",
                    "expected_version",
                    "destination_reference",
                },
            )
        ),
        ToolOutputSchema(_receipt_schema()),
    )


def _record_schema() -> ToolSchema:
    properties = {
        "artifact_id": _uuid_schema(),
        "version": _integer(),
        "content_digest": _string(min_length=71, max_length=71),
        "byte_length": _non_negative_integer(),
        "logical_path": _string(max_length=1_024),
        "media_type": _string(max_length=255),
        "origin": _string(enum=tuple(item.value for item in ArtifactOriginKind)),
        "source_run_id": _uuid_schema(),
        "source_agent_id": _string(max_length=128),
        "source_principal_id": _string(max_length=192),
    }
    return _object(
        properties,
        required={
            "artifact_id",
            "version",
            "content_digest",
            "byte_length",
            "logical_path",
            "media_type",
            "origin",
        },
    )


def _receipt_schema() -> ToolSchema:
    return _object(
        {
            "direction": _string(enum=tuple(item.value for item in ArtifactTransferDirection)),
            "artifact_id": _uuid_schema(),
            "version": _integer(),
            "content_digest": _string(min_length=71, max_length=71),
            "byte_length": _non_negative_integer(),
            "adapter_id": _string(max_length=128),
            "transfer_reference": _string(max_length=512),
        },
        required={
            "direction",
            "artifact_id",
            "version",
            "content_digest",
            "byte_length",
            "adapter_id",
        },
    )


def _object(
    properties: Mapping[str, ToolSchema],
    *,
    required: set[str] | frozenset[str] | None = None,
) -> ToolSchema:
    return ToolSchema(
        kind=ToolSchemaType.OBJECT,
        properties=properties,
        required=frozenset() if required is None else frozenset(required),
    )


def _string(
    *,
    min_length: int = 1,
    max_length: int = MAX_TOOL_SCHEMA_STRING_LENGTH,
    enum: tuple[str, ...] = (),
) -> ToolSchema:
    return ToolSchema(
        kind=ToolSchemaType.STRING,
        min_length=min_length,
        max_length=max_length,
        enum=enum,
    )


def _integer(*, maximum: int = 2**63 - 1) -> ToolSchema:
    return ToolSchema(
        kind=ToolSchemaType.INTEGER,
        minimum=1,
        maximum=maximum,
    )


def _non_negative_integer() -> ToolSchema:
    return ToolSchema(
        kind=ToolSchemaType.INTEGER,
        minimum=0,
        maximum=2**63 - 1,
    )


def _uuid_schema() -> ToolSchema:
    return _string(min_length=36, max_length=36)


def _tool_name(action: str) -> str:
    return {
        WORKSPACE_LIST_ACTION: "List workspace artifacts",
        WORKSPACE_READ_ACTION: "Read workspace artifact",
        WORKSPACE_WRITE_ACTION: "Write workspace artifact",
        WORKSPACE_DELETE_ACTION: "Delete workspace artifact",
        WORKSPACE_IMPORT_ACTION: "Import workspace artifact",
        WORKSPACE_EXPORT_ACTION: "Export workspace artifact",
    }[action]


def _effect(action: str) -> ToolEffect:
    if action in {WORKSPACE_LIST_ACTION, WORKSPACE_READ_ACTION}:
        return ToolEffect.READ_ONLY
    if action in {WORKSPACE_IMPORT_ACTION, WORKSPACE_EXPORT_ACTION}:
        return ToolEffect.EXTERNAL_COMMUNICATION
    return ToolEffect.REVERSIBLE_WRITE


def _require_binding(binding: WorkspaceAgentToolBinding) -> None:
    if not isinstance(binding, WorkspaceAgentToolBinding):
        raise TypeError("binding must be WorkspaceAgentToolBinding")


def _resolution_scope(
    binding: WorkspaceAgentToolBinding,
    context: ToolResourceResolutionContext,
) -> WorkspaceScope | None:
    if binding.scope_kind is WorkspaceScopeKind.RUN:
        return run_workspace_scope(namespace=binding.namespace, run_id=context.run_id)
    if binding.scope_kind is WorkspaceScopeKind.AGENT:
        return agent_workspace_scope(namespace=binding.namespace, agent_id=context.agent_id)
    return None


def _resolution_scope_resource(
    binding: WorkspaceAgentToolBinding,
    context: ToolResourceResolutionContext,
) -> str:
    scope = _resolution_scope(binding, context)
    if scope is not None:
        return workspace_scope_resource(scope)
    return f"agent-workspace:{binding.namespace}/scope:principal:current"


def _invocation_scope(
    binding: WorkspaceAgentToolBinding,
    request: ToolInvocationRequest,
    context: SecurityContext,
) -> WorkspaceScope:
    if binding.scope_kind is WorkspaceScopeKind.RUN:
        return run_workspace_scope(namespace=binding.namespace, run_id=request.run_id)
    if binding.scope_kind is WorkspaceScopeKind.AGENT:
        assert request.agent_id is not None
        return agent_workspace_scope(namespace=binding.namespace, agent_id=request.agent_id)
    return principal_workspace_scope(namespace=binding.namespace, context=context)


def _artifact_id_argument(arguments: Mapping[str, AgentJsonInput]) -> ArtifactId:
    return ArtifactId(_required_uuid(arguments, "artifact_id"))


def _required_uuid(arguments: Mapping[str, AgentJsonInput], key: str) -> UUID:
    value = _required_text(arguments, key)
    try:
        parsed = UUID(value)
    except (ValueError, AttributeError):
        raise ToolExecutionError() from None
    if str(parsed) != value:
        raise ToolExecutionError()
    return parsed


def _required_text(arguments: Mapping[str, AgentJsonInput], key: str) -> str:
    value = arguments.get(key)
    if not isinstance(value, str) or not value:
        raise ToolExecutionError()
    return value


def _required_positive_int(arguments: Mapping[str, AgentJsonInput], key: str) -> int:
    value = arguments.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ToolExecutionError()
    return value


def _optional_positive_int(
    arguments: Mapping[str, AgentJsonInput],
    key: str,
    *,
    default: int,
) -> int:
    value = arguments.get(key)
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ToolExecutionError()
    return value


def _optional_version(
    arguments: Mapping[str, AgentJsonInput],
) -> ArtifactVersion | None:
    value = arguments.get("expected_version")
    if value is None:
        return None
    return ArtifactVersion(_required_positive_int(arguments, "expected_version"))


def _logical_path_argument(
    arguments: Mapping[str, AgentJsonInput],
) -> ArtifactLogicalPath:
    value = _required_text(arguments, "logical_path")
    try:
        return ArtifactLogicalPath(value)
    except (TypeError, ValueError):
        raise ToolExecutionError() from None


def _content_argument(arguments: Mapping[str, AgentJsonInput]) -> bytes:
    encoded = _required_text(arguments, "content_base64")
    try:
        ascii_bytes = encoded.encode("ascii")
        content = base64.b64decode(ascii_bytes, validate=True)
    except (UnicodeEncodeError, binascii.Error, ValueError):
        raise ToolExecutionError() from None
    if (
        base64.b64encode(content) != ascii_bytes
        or len(content) > MAX_WORKSPACE_AGENT_TOOL_CONTENT_BYTES
    ):
        raise ToolExecutionError()
    return content


def _transfer_reference_argument(
    arguments: Mapping[str, AgentJsonInput],
    key: str,
) -> WorkspaceTransferReference:
    value = _required_text(arguments, key)
    try:
        return WorkspaceTransferReference(value)
    except (TypeError, ValueError):
        raise ToolExecutionError() from None


def _record_output(record: ArtifactRecord) -> dict[str, AgentJsonInput]:
    if (
        not isinstance(record, ArtifactRecord)
        or record.status is not ArtifactStatus.ACTIVE
        or record.logical_path is None
        or record.media_type is None
        or record.provenance is None
    ):
        raise ToolExecutionError()
    provenance = record.provenance
    output: dict[str, AgentJsonInput] = {
        "artifact_id": str(record.artifact_id),
        "version": record.version.value,
        "content_digest": str(record.content_digest),
        "byte_length": record.byte_length,
        "logical_path": str(record.logical_path),
        "media_type": str(record.media_type),
        "origin": provenance.origin.value,
    }
    if provenance.source_run_id is not None:
        output["source_run_id"] = str(provenance.source_run_id)
    if provenance.source_agent_id is not None:
        output["source_agent_id"] = str(provenance.source_agent_id)
    if provenance.source_principal_id is not None:
        output["source_principal_id"] = str(provenance.source_principal_id)
    return output


def _receipt_output(
    receipt: ArtifactTransferReceipt,
    *,
    expected_direction: ArtifactTransferDirection,
    scope: WorkspaceScope,
    artifact_id: ArtifactId,
) -> dict[str, AgentJsonInput]:
    if (
        not isinstance(receipt, ArtifactTransferReceipt)
        or receipt.direction is not expected_direction
        or receipt.scope != scope
        or receipt.artifact_id != artifact_id
    ):
        raise ToolExecutionError()
    output: dict[str, AgentJsonInput] = {
        "direction": receipt.direction.value,
        "artifact_id": str(receipt.artifact_id),
        "version": receipt.version.value,
        "content_digest": str(receipt.content_digest),
        "byte_length": receipt.byte_length,
        "adapter_id": str(receipt.adapter_id),
    }
    if receipt.transfer_reference is not None:
        output["transfer_reference"] = str(receipt.transfer_reference)
    return output


def _success(
    request: ToolInvocationRequest,
    output: Mapping[str, AgentJsonInput],
) -> ToolInvocationResult:
    return ToolInvocationResult(
        run_id=request.run_id,
        step_id=request.step_id,
        call_id=request.call_id,
        tool_id=request.tool_id,
        status=ToolResultStatus.SUCCEEDED,
        output=output,
        started_at=request.created_at,
        completed_at=request.created_at,
    )
