"""Reviewed agent-tool facade for exact server-owned memory operations."""

from __future__ import annotations

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
from phoenix_os.agent.memory_authorization import (
    MEMORY_DELETE_ACTION,
    MEMORY_READ_ACTION,
    MEMORY_SEARCH_ACTION,
    MEMORY_WRITE_ACTION,
    agent_memory_scope,
    memory_record_resource,
    memory_scope_resource,
    principal_memory_scope,
    run_memory_scope,
)
from phoenix_os.agent.memory_contracts import (
    MAX_MEMORY_SEARCH_RESULTS,
    MemoryDeleteRequest,
    MemoryId,
    MemoryLimits,
    MemoryNamespace,
    MemoryOriginKind,
    MemoryProvenance,
    MemoryReadRequest,
    MemoryRecord,
    MemoryRecordIncarnation,
    MemoryRecordStatus,
    MemoryRecordVersion,
    MemoryScope,
    MemoryScopeKind,
    MemorySearchRequest,
    MemoryWriteRequest,
    memory_content_digest,
)
from phoenix_os.agent.memory_retrieval import AgentMemoryService
from phoenix_os.agent.schemas import (
    MAX_TOOL_SCHEMA_STRING_LENGTH,
    ToolInputSchema,
    ToolOutputSchema,
    ToolSchema,
    ToolSchemaType,
)
from phoenix_os.agent.tools import (
    ToolDescriptor,
    ToolFinalAdmissionValidator,
    ToolResourceResolutionContext,
)
from phoenix_os.policy import SecurityContext

MAX_MEMORY_AGENT_TOOL_CONTENT_BYTES = 196_608
MAX_MEMORY_AGENT_TOOL_SEARCH_BYTES = 1_048_576
MEMORY_TOOL_RESOLVER_ID = "memory-tool-resource"
MEMORY_TOOL_ADAPTER_ID = "memory-tool"

_MEMORY_ACTIONS = frozenset(
    {
        MEMORY_SEARCH_ACTION,
        MEMORY_READ_ACTION,
        MEMORY_WRITE_ACTION,
        MEMORY_DELETE_ACTION,
    }
)


@dataclass(frozen=True, slots=True)
class MemoryAgentToolBinding:
    """Server-owned binding from one agent tool to one exact memory scope kind."""

    agent_id: AgentId
    tool_id: ToolId
    namespace: MemoryNamespace
    scope_kind: MemoryScopeKind
    action: str

    def __post_init__(self) -> None:
        if not isinstance(self.agent_id, AgentId):
            raise TypeError("agent_id must be AgentId")
        if not isinstance(self.tool_id, ToolId):
            raise TypeError("tool_id must be ToolId")
        if not isinstance(self.namespace, MemoryNamespace):
            raise TypeError("namespace must be MemoryNamespace")
        if not isinstance(self.scope_kind, MemoryScopeKind):
            raise TypeError("scope_kind must be MemoryScopeKind")
        if not isinstance(self.action, str):
            raise TypeError("action must be a string")
        normalized = self.action.strip().lower()
        if normalized not in _MEMORY_ACTIONS:
            raise ValueError("unsupported memory agent-tool action")
        object.__setattr__(self, "action", normalized)

    @property
    def binding_id(self) -> str:
        return memory_tool_binding_id(self.namespace, self.scope_kind)


def memory_tool_binding_id(
    namespace: MemoryNamespace,
    scope_kind: MemoryScopeKind,
) -> str:
    """Return the stable capability identity for one configured memory scope kind."""

    if not isinstance(namespace, MemoryNamespace):
        raise TypeError("namespace must be MemoryNamespace")
    if not isinstance(scope_kind, MemoryScopeKind):
        raise TypeError("scope_kind must be MemoryScopeKind")
    return f"agent-memory:{namespace}/scope:{scope_kind.value}"


def memory_tool_descriptor(
    binding: MemoryAgentToolBinding,
    limits: MemoryLimits,
) -> ToolDescriptor:
    """Return one strict descriptor for an exact memory action."""

    _require_binding(binding)
    if not isinstance(limits, MemoryLimits):
        raise TypeError("limits must be MemoryLimits")
    input_schema, output_schema = _schemas(binding, limits)
    effect = (
        ToolEffect.READ_ONLY
        if binding.action in {MEMORY_SEARCH_ACTION, MEMORY_READ_ACTION}
        else ToolEffect.REVERSIBLE_WRITE
    )
    return ToolDescriptor(
        tool_id=binding.tool_id,
        name=_tool_name(binding.action),
        description="Execute one bounded server-configured memory operation.",
        input_schema=input_schema,
        output_schema=output_schema,
        effect=effect,
        approval_may_be_required=effect is not ToolEffect.READ_ONLY,
        max_input_bytes=MAX_AGENT_ARGUMENT_BYTES,
        max_output_bytes=MAX_AGENT_RESULT_BYTES,
        timeout=timedelta(minutes=2),
        resolver_id=MEMORY_TOOL_RESOLVER_ID,
        adapter_id=MEMORY_TOOL_ADAPTER_ID,
        metadata={
            "downstream_action": binding.action,
            "memory_namespace": str(binding.namespace),
            "scope_kind": binding.scope_kind.value,
        },
    )


def memory_tool_resolver(binding: MemoryAgentToolBinding) -> MemoryToolResourceResolver:
    """Return a resolver that keeps namespace and scope kind server-owned."""

    return MemoryToolResourceResolver(binding)


class MemoryToolResourceResolver:
    resolver_id = MEMORY_TOOL_RESOLVER_ID

    def __init__(self, binding: MemoryAgentToolBinding) -> None:
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
        if self._binding.action == MEMORY_SEARCH_ACTION:
            return scope_resource
        memory_id = _memory_id_argument(arguments)
        if self._binding.scope_kind is MemoryScopeKind.PRINCIPAL:
            return f"{scope_resource}/record:{memory_id}"
        scope = _resolution_scope(self._binding, context)
        assert scope is not None
        return memory_record_resource(scope, memory_id)


class MemoryToolAdapter:
    """Translate an exact admitted tool call into the canonical memory service."""

    adapter_id = MEMORY_TOOL_ADAPTER_ID

    def __init__(
        self,
        service: AgentMemoryService,
        binding: MemoryAgentToolBinding,
    ) -> None:
        if not isinstance(service, AgentMemoryService):
            raise TypeError("service must be AgentMemoryService")
        _require_binding(binding)
        self._service = service
        self._binding = binding
        self._resolver = MemoryToolResourceResolver(binding)

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
        return await self._invoke_with_context(
            request,
            context,
            final_admission=None,
        )

    async def invoke_with_context_and_final_admission(
        self,
        request: ToolInvocationRequest,
        context: SecurityContext,
        final_admission: ToolFinalAdmissionValidator,
    ) -> ToolInvocationResult:
        if not callable(final_admission):
            raise TypeError("final_admission must be callable")
        return await self._invoke_with_context(
            request,
            context,
            final_admission=final_admission,
        )

    async def _invoke_with_context(
        self,
        request: ToolInvocationRequest,
        context: SecurityContext,
        *,
        final_admission: ToolFinalAdmissionValidator | None,
    ) -> ToolInvocationResult:
        if not isinstance(request, ToolInvocationRequest):
            raise TypeError("request must be ToolInvocationRequest")
        if not isinstance(context, SecurityContext):
            raise TypeError("context must be SecurityContext")
        scope = self._validated_scope(request, context)
        if self._binding.action == MEMORY_SEARCH_ACTION:
            output = await self._search(
                request,
                scope,
                context,
                final_admission=final_admission,
            )
        elif self._binding.action == MEMORY_READ_ACTION:
            output = await self._read(
                request,
                scope,
                context,
                final_admission=final_admission,
            )
        elif self._binding.action == MEMORY_WRITE_ACTION:
            output = await self._write(
                request,
                scope,
                context,
                final_admission=final_admission,
            )
        elif self._binding.action == MEMORY_DELETE_ACTION:
            output = await self._delete(
                request,
                scope,
                context,
                final_admission=final_admission,
            )
        else:
            raise ToolExecutionError()
        return _success(request, output)

    def _validated_scope(
        self,
        request: ToolInvocationRequest,
        context: SecurityContext,
    ) -> MemoryScope:
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

    async def _search(
        self,
        request: ToolInvocationRequest,
        scope: MemoryScope,
        context: SecurityContext,
        *,
        final_admission: ToolFinalAdmissionValidator | None,
    ) -> Mapping[str, AgentJsonInput]:
        query = _required_text(request.arguments, "query")
        if len(query.encode("utf-8")) > self._service.limits.max_query_bytes:
            raise ToolExecutionError()
        max_results = _optional_positive_int(
            request.arguments,
            "max_results",
            default=min(self._service.limits.max_search_results, MAX_MEMORY_SEARCH_RESULTS),
        )
        max_bytes = _optional_positive_int(
            request.arguments,
            "max_bytes",
            default=min(
                self._service.limits.max_search_result_bytes,
                MAX_MEMORY_AGENT_TOOL_SEARCH_BYTES,
            ),
        )
        if (
            max_results > self._service.limits.max_search_results
            or max_results > MAX_MEMORY_SEARCH_RESULTS
            or max_bytes > self._service.limits.max_search_result_bytes
            or max_bytes > MAX_MEMORY_AGENT_TOOL_SEARCH_BYTES
        ):
            raise ToolExecutionError()
        search_request = MemorySearchRequest(
            scope=scope,
            query=query,
            max_results=max_results,
            max_bytes=max_bytes,
            created_at=request.created_at,
        )
        if final_admission is None:
            result = await self._service.search(search_request, context)
        else:
            result = await self._service.search(
                search_request,
                context,
                final_admission=final_admission,
            )
        if result.scope != scope:
            raise ToolExecutionError()
        return {"records": [_record_output(hit.record) for hit in result.hits]}

    async def _read(
        self,
        request: ToolInvocationRequest,
        scope: MemoryScope,
        context: SecurityContext,
        *,
        final_admission: ToolFinalAdmissionValidator | None,
    ) -> Mapping[str, AgentJsonInput]:
        memory_id = _memory_id_argument(request.arguments)
        expected_version, expected_incarnation = _optional_record_binding(request.arguments)
        read_request = MemoryReadRequest(
            scope=scope,
            memory_id=memory_id,
            expected_version=expected_version,
            expected_incarnation=expected_incarnation,
            created_at=request.created_at,
        )
        if final_admission is None:
            record = await self._service.read(read_request, context)
        else:
            record = await self._service.read(
                read_request,
                context,
                final_admission=final_admission,
            )
        if record is None:
            return {"found": False}
        if record.scope != scope or record.memory_id != memory_id:
            raise ToolExecutionError()
        return {"found": True, **_record_output(record)}

    async def _write(
        self,
        request: ToolInvocationRequest,
        scope: MemoryScope,
        context: SecurityContext,
        *,
        final_admission: ToolFinalAdmissionValidator | None,
    ) -> Mapping[str, AgentJsonInput]:
        memory_id = _memory_id_argument(request.arguments)
        content = _required_text(request.arguments, "content")
        if (
            len(content.encode("utf-8")) > self._service.limits.max_record_bytes
            or len(content.encode("utf-8")) > MAX_MEMORY_AGENT_TOOL_CONTENT_BYTES
        ):
            raise ToolExecutionError()
        expected_version, expected_incarnation = _optional_record_binding(request.arguments)
        digest = memory_content_digest(content)
        write_request = MemoryWriteRequest(
            scope=scope,
            memory_id=memory_id,
            content=content,
            provenance=MemoryProvenance(
                origin=MemoryOriginKind.AGENT_REQUEST,
                content_digest=digest,
                source_run_id=request.run_id,
                source_agent_id=request.agent_id,
                source_principal_id=(
                    scope.scope_id if scope.kind is MemoryScopeKind.PRINCIPAL else None
                ),
                attributes={"tool_id": str(request.tool_id)},
                created_at=request.created_at,
            ),
            expected_version=expected_version,
            expected_incarnation=expected_incarnation,
            created_at=request.created_at,
        )
        if final_admission is None:
            record = await self._service.write(write_request, context)
        else:
            record = await self._service.write(
                write_request,
                context,
                final_admission=final_admission,
            )
        if (
            record.scope != scope
            or record.memory_id != memory_id
            or record.content_digest != digest
            or record.content != content
        ):
            raise ToolExecutionError()
        return _write_output(record)

    async def _delete(
        self,
        request: ToolInvocationRequest,
        scope: MemoryScope,
        context: SecurityContext,
        *,
        final_admission: ToolFinalAdmissionValidator | None,
    ) -> Mapping[str, AgentJsonInput]:
        memory_id = _memory_id_argument(request.arguments)
        version = _required_positive_int(request.arguments, "expected_version")
        incarnation = _required_uuid(request.arguments, "expected_incarnation")
        delete_request = MemoryDeleteRequest(
            scope=scope,
            memory_id=memory_id,
            expected_version=MemoryRecordVersion(version),
            expected_incarnation=MemoryRecordIncarnation(incarnation),
            created_at=request.created_at,
        )
        if final_admission is None:
            await self._service.delete(delete_request, context)
        else:
            await self._service.delete(
                delete_request,
                context,
                final_admission=final_admission,
            )
        return {"deleted": True}


def _schemas(
    binding: MemoryAgentToolBinding,
    limits: MemoryLimits,
) -> tuple[ToolInputSchema, ToolOutputSchema]:
    record_schema = _record_schema(
        max_content_chars=min(
            limits.max_record_bytes,
            MAX_MEMORY_AGENT_TOOL_CONTENT_BYTES,
            MAX_TOOL_SCHEMA_STRING_LENGTH,
        )
    )
    if binding.action == MEMORY_SEARCH_ACTION:
        return (
            ToolInputSchema(
                _object(
                    {
                        "query": _string(
                            max_length=min(
                                limits.max_query_bytes,
                                MAX_TOOL_SCHEMA_STRING_LENGTH,
                            )
                        ),
                        "max_results": _integer(
                            maximum=min(
                                limits.max_search_results,
                                MAX_MEMORY_SEARCH_RESULTS,
                            )
                        ),
                        "max_bytes": _integer(
                            maximum=min(
                                limits.max_search_result_bytes,
                                MAX_MEMORY_AGENT_TOOL_SEARCH_BYTES,
                            )
                        ),
                    },
                    required={"query"},
                )
            ),
            ToolOutputSchema(
                _object(
                    {
                        "records": ToolSchema(
                            kind=ToolSchemaType.ARRAY,
                            items=record_schema,
                            max_items=min(
                                limits.max_search_results,
                                MAX_MEMORY_SEARCH_RESULTS,
                            ),
                        )
                    },
                    required={"records"},
                )
            ),
        )
    if binding.action == MEMORY_READ_ACTION:
        properties = {
            "found": ToolSchema(kind=ToolSchemaType.BOOLEAN),
            **record_schema.properties,
        }
        return (
            ToolInputSchema(_record_selector_schema(require_version=False)),
            ToolOutputSchema(_object(properties, required={"found"})),
        )
    if binding.action == MEMORY_WRITE_ACTION:
        selector = _record_selector_schema(require_version=False)
        properties = dict(selector.properties)
        properties["content"] = _string(
            max_length=min(
                limits.max_record_bytes,
                MAX_MEMORY_AGENT_TOOL_CONTENT_BYTES,
                MAX_TOOL_SCHEMA_STRING_LENGTH,
            )
        )
        return (
            ToolInputSchema(
                _object(
                    properties,
                    required={"memory_id", "content"},
                )
            ),
            ToolOutputSchema(
                _object(
                    _write_result_properties(),
                    required=set(_write_result_properties()),
                )
            ),
        )
    return (
        ToolInputSchema(_record_selector_schema(require_version=True)),
        ToolOutputSchema(
            _object(
                {"deleted": ToolSchema(kind=ToolSchemaType.BOOLEAN)},
                required={"deleted"},
            )
        ),
    )


def _record_selector_schema(*, require_version: bool) -> ToolSchema:
    properties = {
        "memory_id": _uuid_schema(),
        "expected_version": _integer(),
        "expected_incarnation": _uuid_schema(),
    }
    required = {"memory_id"}
    if require_version:
        required.update({"expected_version", "expected_incarnation"})
    return _object(properties, required=required)


def _record_schema(*, max_content_chars: int) -> ToolSchema:
    properties = {
        **_write_result_properties(),
        "content": _string(max_length=max_content_chars),
        "origin": _string(enum=tuple(item.value for item in MemoryOriginKind)),
        "source_run_id": _uuid_schema(),
        "source_agent_id": _string(max_length=128),
        "source_principal_id": _string(max_length=192),
    }
    return _object(
        properties,
        required={
            "memory_id",
            "incarnation",
            "version",
            "content_digest",
            "content",
            "origin",
        },
    )


def _write_result_properties() -> dict[str, ToolSchema]:
    return {
        "memory_id": _uuid_schema(),
        "incarnation": _uuid_schema(),
        "version": _integer(),
        "content_digest": _string(min_length=71, max_length=71),
    }


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


def _uuid_schema() -> ToolSchema:
    return _string(min_length=36, max_length=36)


def _tool_name(action: str) -> str:
    return {
        MEMORY_SEARCH_ACTION: "Search memory",
        MEMORY_READ_ACTION: "Read memory",
        MEMORY_WRITE_ACTION: "Write memory",
        MEMORY_DELETE_ACTION: "Delete memory",
    }[action]


def _require_binding(binding: MemoryAgentToolBinding) -> None:
    if not isinstance(binding, MemoryAgentToolBinding):
        raise TypeError("binding must be MemoryAgentToolBinding")


def _resolution_scope(
    binding: MemoryAgentToolBinding,
    context: ToolResourceResolutionContext,
) -> MemoryScope | None:
    if binding.scope_kind is MemoryScopeKind.RUN:
        return run_memory_scope(namespace=binding.namespace, run_id=context.run_id)
    if binding.scope_kind is MemoryScopeKind.AGENT:
        return agent_memory_scope(namespace=binding.namespace, agent_id=context.agent_id)
    return None


def _resolution_scope_resource(
    binding: MemoryAgentToolBinding,
    context: ToolResourceResolutionContext,
) -> str:
    scope = _resolution_scope(binding, context)
    if scope is not None:
        return memory_scope_resource(scope)
    return f"agent-memory:{binding.namespace}/scope:principal:current"


def _invocation_scope(
    binding: MemoryAgentToolBinding,
    request: ToolInvocationRequest,
    context: SecurityContext,
) -> MemoryScope:
    if binding.scope_kind is MemoryScopeKind.RUN:
        return run_memory_scope(namespace=binding.namespace, run_id=request.run_id)
    if binding.scope_kind is MemoryScopeKind.AGENT:
        assert request.agent_id is not None
        return agent_memory_scope(namespace=binding.namespace, agent_id=request.agent_id)
    return principal_memory_scope(namespace=binding.namespace, context=context)


def _memory_id_argument(arguments: Mapping[str, AgentJsonInput]) -> MemoryId:
    return MemoryId(_required_uuid(arguments, "memory_id"))


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


def _optional_record_binding(
    arguments: Mapping[str, AgentJsonInput],
) -> tuple[MemoryRecordVersion | None, MemoryRecordIncarnation | None]:
    version_value = arguments.get("expected_version")
    incarnation_value = arguments.get("expected_incarnation")
    if version_value is None and incarnation_value is None:
        return None, None
    if version_value is None or incarnation_value is None:
        raise ToolExecutionError()
    version = _required_positive_int(arguments, "expected_version")
    incarnation = _required_uuid(arguments, "expected_incarnation")
    return MemoryRecordVersion(version), MemoryRecordIncarnation(incarnation)


def _record_output(record: MemoryRecord) -> dict[str, AgentJsonInput]:
    if (
        not isinstance(record, MemoryRecord)
        or record.status is not MemoryRecordStatus.ACTIVE
        or record.content is None
        or record.provenance is None
        or record.content_bytes > MAX_MEMORY_AGENT_TOOL_CONTENT_BYTES
    ):
        raise ToolExecutionError()
    provenance = record.provenance
    output: dict[str, AgentJsonInput] = {
        "memory_id": str(record.memory_id),
        "incarnation": str(record.incarnation),
        "version": record.version.value,
        "content_digest": record.content_digest,
        "content": record.content,
        "origin": provenance.origin.value,
    }
    if provenance.source_run_id is not None:
        output["source_run_id"] = str(provenance.source_run_id)
    if provenance.source_agent_id is not None:
        output["source_agent_id"] = str(provenance.source_agent_id)
    if provenance.source_principal_id is not None:
        output["source_principal_id"] = str(provenance.source_principal_id)
    return output


def _write_output(record: MemoryRecord) -> dict[str, AgentJsonInput]:
    if not isinstance(record, MemoryRecord):
        raise ToolExecutionError()
    return {
        "memory_id": str(record.memory_id),
        "incarnation": str(record.incarnation),
        "version": record.version.value,
        "content_digest": record.content_digest,
    }


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
