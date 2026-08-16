"""Reviewed RFC-0027 bindings for bounded read-only host tools."""

from __future__ import annotations

from collections.abc import Mapping

from phoenix_os.agent.contracts import (
    MAX_AGENT_RESULT_BYTES,
    AgentJsonInput,
    ToolEffect,
    ToolId,
    ToolInvocationRequest,
    ToolInvocationResult,
    ToolResultStatus,
)
from phoenix_os.agent.errors import ToolExecutionError
from phoenix_os.agent.schemas import (
    ToolInputSchema,
    ToolOutputSchema,
    ToolSchema,
    ToolSchemaType,
)
from phoenix_os.agent.tools import StaticToolResourceResolver, ToolDescriptor
from phoenix_os.host_automation.authorization import (
    HOST_PROCESS_LIST_ACTION,
    HOST_WINDOW_LIST_ACTION,
    host_process_collection_resource,
    host_window_collection_resource,
)
from phoenix_os.host_automation.contracts import (
    MAX_HOST_IDENTIFIER_LENGTH,
    HostAutomationLimits,
    HostId,
    HostProcessListRequest,
    HostProcessListResult,
    HostWindowListRequest,
    HostWindowListResult,
)
from phoenix_os.host_automation.service import HostAutomationService
from phoenix_os.policy import SecurityContext

HOST_PROCESS_LIST_TOOL_ID = ToolId(HOST_PROCESS_LIST_ACTION)
HOST_WINDOW_LIST_TOOL_ID = ToolId(HOST_WINDOW_LIST_ACTION)

HOST_PROCESS_LIST_TOOL_RESOLVER_ID = "host-process-list-resource"
HOST_WINDOW_LIST_TOOL_RESOLVER_ID = "host-window-list-resource"
HOST_PROCESS_LIST_TOOL_ADAPTER_ID = "host-process-list"
HOST_WINDOW_LIST_TOOL_ADAPTER_ID = "host-window-list"

MAX_HOST_AGENT_TOOL_INPUT_BYTES = 256
MAX_HOST_AGENT_TOOL_OUTPUT_BYTES = MAX_AGENT_RESULT_BYTES

_UUID_TEXT_LENGTH = 36


def host_process_list_tool_descriptor(limits: HostAutomationLimits) -> ToolDescriptor:
    """Return the reviewed model-facing descriptor for bounded process discovery."""

    _require_limits(limits)
    return ToolDescriptor(
        tool_id=HOST_PROCESS_LIST_TOOL_ID,
        name="List host processes",
        description="List bounded reviewed process metadata from the configured host.",
        input_schema=ToolInputSchema(_list_input_schema(limits.max_process_results)),
        output_schema=ToolOutputSchema(_process_list_output_schema(limits)),
        effect=ToolEffect.READ_ONLY,
        approval_may_be_required=False,
        max_input_bytes=MAX_HOST_AGENT_TOOL_INPUT_BYTES,
        max_output_bytes=MAX_HOST_AGENT_TOOL_OUTPUT_BYTES,
        timeout=limits.operation_timeout,
        resolver_id=HOST_PROCESS_LIST_TOOL_RESOLVER_ID,
        adapter_id=HOST_PROCESS_LIST_TOOL_ADAPTER_ID,
    )


def host_window_list_tool_descriptor(limits: HostAutomationLimits) -> ToolDescriptor:
    """Return the reviewed model-facing descriptor for bounded window discovery."""

    _require_limits(limits)
    return ToolDescriptor(
        tool_id=HOST_WINDOW_LIST_TOOL_ID,
        name="List host windows",
        description="List bounded reviewed window metadata from the configured host.",
        input_schema=ToolInputSchema(_list_input_schema(limits.max_window_results)),
        output_schema=ToolOutputSchema(_window_list_output_schema(limits)),
        effect=ToolEffect.READ_ONLY,
        approval_may_be_required=False,
        max_input_bytes=MAX_HOST_AGENT_TOOL_INPUT_BYTES,
        max_output_bytes=MAX_HOST_AGENT_TOOL_OUTPUT_BYTES,
        timeout=limits.operation_timeout,
        resolver_id=HOST_WINDOW_LIST_TOOL_RESOLVER_ID,
        adapter_id=HOST_WINDOW_LIST_TOOL_ADAPTER_ID,
    )


def host_process_list_tool_resolver(host_id: HostId) -> StaticToolResourceResolver:
    """Bind process discovery to one server-owned configured host resource."""

    _require_host_id(host_id)
    return StaticToolResourceResolver(
        HOST_PROCESS_LIST_TOOL_RESOLVER_ID,
        host_process_collection_resource(host_id),
    )


def host_window_list_tool_resolver(host_id: HostId) -> StaticToolResourceResolver:
    """Bind window discovery to one server-owned configured host resource."""

    _require_host_id(host_id)
    return StaticToolResourceResolver(
        HOST_WINDOW_LIST_TOOL_RESOLVER_ID,
        host_window_collection_resource(host_id),
    )


class HostProcessListToolAdapter:
    """Translate one validated RFC-0027 tool call into one fresh host authorization."""

    adapter_id = HOST_PROCESS_LIST_TOOL_ADAPTER_ID
    tool_id = HOST_PROCESS_LIST_TOOL_ID

    def __init__(
        self,
        service: HostAutomationService,
        *,
        host_id: HostId,
        limits: HostAutomationLimits,
    ) -> None:
        if not isinstance(service, HostAutomationService):
            raise TypeError("service must be HostAutomationService")
        _require_host_id(host_id)
        _require_limits(limits)
        self._service = service
        self._host_id = host_id
        self._limits = limits
        self._resource = host_process_collection_resource(host_id)

    async def invoke(self, request: ToolInvocationRequest) -> ToolInvocationResult:
        """Fail closed when the explicit contextual execution path is bypassed."""

        del request
        raise ToolExecutionError()

    async def invoke_with_context(
        self,
        request: ToolInvocationRequest,
        context: SecurityContext,
    ) -> ToolInvocationResult:
        if not isinstance(context, SecurityContext):
            raise TypeError("context must be SecurityContext")
        limit = _validated_limit(
            request,
            tool_id=self.tool_id,
            resource=self._resource,
            maximum=self._limits.max_process_results,
        )
        host_request = HostProcessListRequest(host_id=self._host_id, limit=limit)
        result = await self._service.list_processes(host_request, context)
        output = _process_list_output(
            result,
            request=host_request,
            limits=self._limits,
        )
        return _successful_result(request, output)


class HostWindowListToolAdapter:
    """Translate one validated RFC-0027 tool call into one fresh host authorization."""

    adapter_id = HOST_WINDOW_LIST_TOOL_ADAPTER_ID
    tool_id = HOST_WINDOW_LIST_TOOL_ID

    def __init__(
        self,
        service: HostAutomationService,
        *,
        host_id: HostId,
        limits: HostAutomationLimits,
    ) -> None:
        if not isinstance(service, HostAutomationService):
            raise TypeError("service must be HostAutomationService")
        _require_host_id(host_id)
        _require_limits(limits)
        self._service = service
        self._host_id = host_id
        self._limits = limits
        self._resource = host_window_collection_resource(host_id)

    async def invoke(self, request: ToolInvocationRequest) -> ToolInvocationResult:
        """Fail closed when the explicit contextual execution path is bypassed."""

        del request
        raise ToolExecutionError()

    async def invoke_with_context(
        self,
        request: ToolInvocationRequest,
        context: SecurityContext,
    ) -> ToolInvocationResult:
        if not isinstance(context, SecurityContext):
            raise TypeError("context must be SecurityContext")
        limit = _validated_limit(
            request,
            tool_id=self.tool_id,
            resource=self._resource,
            maximum=self._limits.max_window_results,
        )
        host_request = HostWindowListRequest(host_id=self._host_id, limit=limit)
        result = await self._service.list_windows(host_request, context)
        output = _window_list_output(
            result,
            request=host_request,
            limits=self._limits,
        )
        return _successful_result(request, output)


def _list_input_schema(maximum: int) -> ToolSchema:
    return ToolSchema(
        kind=ToolSchemaType.OBJECT,
        properties={
            "limit": ToolSchema(
                kind=ToolSchemaType.INTEGER,
                minimum=1,
                maximum=maximum,
            )
        },
        required=frozenset({"limit"}),
    )


def _process_list_output_schema(limits: HostAutomationLimits) -> ToolSchema:
    process = ToolSchema(
        kind=ToolSchemaType.OBJECT,
        properties={
            "process_id": _uuid_schema(),
            "application_id": ToolSchema(
                kind=ToolSchemaType.STRING,
                min_length=1,
                max_length=MAX_HOST_IDENTIFIER_LENGTH,
            ),
            "label": ToolSchema(
                kind=ToolSchemaType.STRING,
                max_length=limits.max_process_label_chars,
            ),
        },
        required=frozenset({"process_id", "label"}),
    )
    return ToolSchema(
        kind=ToolSchemaType.OBJECT,
        properties={
            "host_epoch": _uuid_schema(),
            "processes": ToolSchema(
                kind=ToolSchemaType.ARRAY,
                items=process,
                max_items=limits.max_process_results,
            ),
            "truncated": ToolSchema(kind=ToolSchemaType.BOOLEAN),
        },
        required=frozenset({"host_epoch", "processes", "truncated"}),
    )


def _window_list_output_schema(limits: HostAutomationLimits) -> ToolSchema:
    window = ToolSchema(
        kind=ToolSchemaType.OBJECT,
        properties={
            "window_id": _uuid_schema(),
            "process_id": _uuid_schema(),
            "application_id": ToolSchema(
                kind=ToolSchemaType.STRING,
                min_length=1,
                max_length=MAX_HOST_IDENTIFIER_LENGTH,
            ),
            "title": ToolSchema(
                kind=ToolSchemaType.STRING,
                max_length=limits.max_window_title_chars,
            ),
        },
        required=frozenset({"window_id", "process_id", "title"}),
    )
    return ToolSchema(
        kind=ToolSchemaType.OBJECT,
        properties={
            "host_epoch": _uuid_schema(),
            "windows": ToolSchema(
                kind=ToolSchemaType.ARRAY,
                items=window,
                max_items=limits.max_window_results,
            ),
            "truncated": ToolSchema(kind=ToolSchemaType.BOOLEAN),
        },
        required=frozenset({"host_epoch", "windows", "truncated"}),
    )


def _uuid_schema() -> ToolSchema:
    return ToolSchema(
        kind=ToolSchemaType.STRING,
        min_length=_UUID_TEXT_LENGTH,
        max_length=_UUID_TEXT_LENGTH,
    )


def _validated_limit(
    request: ToolInvocationRequest,
    *,
    tool_id: ToolId,
    resource: str,
    maximum: int,
) -> int:
    if not isinstance(request, ToolInvocationRequest):
        raise TypeError("request must be ToolInvocationRequest")
    if request.tool_id != tool_id or request.resolved_resource != resource:
        raise ToolExecutionError()
    if frozenset(request.arguments) != frozenset({"limit"}):
        raise ToolExecutionError()
    value = request.arguments.get("limit")
    if isinstance(value, bool) or not isinstance(value, int):
        raise ToolExecutionError()
    if value <= 0 or value > maximum:
        raise ToolExecutionError()
    return value


def _process_list_output(
    result: HostProcessListResult,
    *,
    request: HostProcessListRequest,
    limits: HostAutomationLimits,
) -> Mapping[str, AgentJsonInput]:
    if not isinstance(result, HostProcessListResult):
        raise ToolExecutionError()
    if (
        result.request_id != request.request_id
        or result.host_id != request.host_id
        or len(result.processes) > request.limit
    ):
        raise ToolExecutionError()

    processes: list[dict[str, AgentJsonInput]] = []
    for descriptor in result.processes:
        if len(descriptor.label) > limits.max_process_label_chars:
            raise ToolExecutionError()
        item: dict[str, AgentJsonInput] = {
            "process_id": str(descriptor.process_id),
            "label": descriptor.label,
        }
        if descriptor.application_id is not None:
            item["application_id"] = str(descriptor.application_id)
        processes.append(item)
    return {
        "host_epoch": str(result.host_epoch),
        "processes": processes,
        "truncated": result.truncated,
    }


def _window_list_output(
    result: HostWindowListResult,
    *,
    request: HostWindowListRequest,
    limits: HostAutomationLimits,
) -> Mapping[str, AgentJsonInput]:
    if not isinstance(result, HostWindowListResult):
        raise ToolExecutionError()
    if (
        result.request_id != request.request_id
        or result.host_id != request.host_id
        or len(result.windows) > request.limit
    ):
        raise ToolExecutionError()

    windows: list[dict[str, AgentJsonInput]] = []
    for descriptor in result.windows:
        if len(descriptor.title) > limits.max_window_title_chars:
            raise ToolExecutionError()
        item: dict[str, AgentJsonInput] = {
            "window_id": str(descriptor.window_id),
            "process_id": str(descriptor.process_id),
            "title": descriptor.title,
        }
        if descriptor.application_id is not None:
            item["application_id"] = str(descriptor.application_id)
        windows.append(item)
    return {
        "host_epoch": str(result.host_epoch),
        "windows": windows,
        "truncated": result.truncated,
    }


def _successful_result(
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


def _require_host_id(value: HostId) -> None:
    if not isinstance(value, HostId):
        raise TypeError("host_id must be HostId")


def _require_limits(value: HostAutomationLimits) -> None:
    if not isinstance(value, HostAutomationLimits):
        raise TypeError("limits must be HostAutomationLimits")
