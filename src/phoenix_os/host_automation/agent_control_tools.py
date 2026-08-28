"""Reviewed RFC-0027 bindings for bounded host control tools."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Protocol, runtime_checkable
from uuid import UUID

from phoenix_os.agent.contracts import (
    MAX_AGENT_ARGUMENT_BYTES,
    MAX_AGENT_RESULT_BYTES,
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
from phoenix_os.agent.tools import (
    StaticToolResourceResolver,
    ToolDescriptor,
    ToolFinalAdmissionValidator,
)
from phoenix_os.host_automation.authorization import (
    HOST_APPLICATION_CLOSE_ACTION,
    HOST_APPLICATION_LAUNCH_ACTION,
    HOST_CLIPBOARD_READ_ACTION,
    HOST_CLIPBOARD_WRITE_ACTION,
    HOST_WINDOW_FOCUS_ACTION,
    host_application_resource,
    host_clipboard_resource,
    host_process_resource,
    host_window_resource,
)
from phoenix_os.host_automation.contracts import (
    MAX_HOST_IDENTIFIER_LENGTH,
    HostApplicationCloseRequest,
    HostApplicationCloseResult,
    HostApplicationId,
    HostApplicationLaunchRequest,
    HostApplicationLaunchResult,
    HostAutomationLimits,
    HostClipboardReadRequest,
    HostClipboardReadResult,
    HostClipboardWriteRequest,
    HostClipboardWriteResult,
    HostEpoch,
    HostId,
    HostProcessId,
    HostWindowFocusRequest,
    HostWindowFocusResult,
    HostWindowId,
)
from phoenix_os.host_automation.service import HostAutomationService
from phoenix_os.policy import SecurityContext

HOST_APPLICATION_LAUNCH_TOOL_ID = ToolId(HOST_APPLICATION_LAUNCH_ACTION)
HOST_WINDOW_FOCUS_TOOL_ID = ToolId(HOST_WINDOW_FOCUS_ACTION)
HOST_APPLICATION_CLOSE_TOOL_ID = ToolId(HOST_APPLICATION_CLOSE_ACTION)
HOST_CLIPBOARD_WRITE_TOOL_ID = ToolId(HOST_CLIPBOARD_WRITE_ACTION)
HOST_CLIPBOARD_READ_TOOL_ID = ToolId(HOST_CLIPBOARD_READ_ACTION)

HOST_APPLICATION_LAUNCH_TOOL_RESOLVER_ID = "host-application-launch-resource"
HOST_WINDOW_FOCUS_TOOL_RESOLVER_ID = "host-window-focus-resource"
HOST_APPLICATION_CLOSE_TOOL_RESOLVER_ID = "host-application-close-resource"
HOST_CLIPBOARD_WRITE_TOOL_RESOLVER_ID = "host-clipboard-write-resource"
HOST_CLIPBOARD_READ_TOOL_RESOLVER_ID = "host-clipboard-read-resource"

HOST_APPLICATION_LAUNCH_TOOL_ADAPTER_ID = "host-application-launch"
HOST_WINDOW_FOCUS_TOOL_ADAPTER_ID = "host-window-focus"
HOST_APPLICATION_CLOSE_TOOL_ADAPTER_ID = "host-application-close"
HOST_CLIPBOARD_WRITE_TOOL_ADAPTER_ID = "host-clipboard-write"
HOST_CLIPBOARD_READ_TOOL_ADAPTER_ID = "host-clipboard-read"

MAX_HOST_CONTROL_TOOL_INPUT_BYTES = 2_048
MAX_HOST_CLIPBOARD_TOOL_INPUT_BYTES = MAX_AGENT_ARGUMENT_BYTES
MAX_HOST_CONTROL_TOOL_OUTPUT_BYTES = MAX_AGENT_RESULT_BYTES

_UUID_TEXT_LENGTH = 36


@runtime_checkable
class HostEpochBoundToolAdapter(Protocol):
    # Reviewed host tool exposing current epoch only as control metadata.

    @property
    def host_epoch(self) -> HostEpoch: ...


def host_application_launch_tool_descriptor(limits: HostAutomationLimits) -> ToolDescriptor:
    _require_limits(limits)
    return ToolDescriptor(
        tool_id=HOST_APPLICATION_LAUNCH_TOOL_ID,
        name="Launch configured host application",
        description=(
            "Launch one exact server-configured application without command-line authority."
        ),
        input_schema=ToolInputSchema(
            _object_schema(
                {"application_id": _application_id_schema()},
                required={"application_id"},
            )
        ),
        output_schema=ToolOutputSchema(_launch_output_schema()),
        effect=ToolEffect.IRREVERSIBLE_WRITE,
        approval_may_be_required=False,
        max_input_bytes=MAX_HOST_CONTROL_TOOL_INPUT_BYTES,
        max_output_bytes=MAX_HOST_CONTROL_TOOL_OUTPUT_BYTES,
        timeout=limits.operation_timeout,
        resolver_id=HOST_APPLICATION_LAUNCH_TOOL_RESOLVER_ID,
        adapter_id=HOST_APPLICATION_LAUNCH_TOOL_ADAPTER_ID,
    )


def host_window_focus_tool_descriptor(limits: HostAutomationLimits) -> ToolDescriptor:
    _require_limits(limits)
    return ToolDescriptor(
        tool_id=HOST_WINDOW_FOCUS_TOOL_ID,
        name="Focus exact host window",
        description="Focus one exact opaque window identity after fresh host revalidation.",
        input_schema=ToolInputSchema(
            _object_schema(
                {
                    "host_epoch": _uuid_schema(),
                    "window_id": _uuid_schema(),
                    "process_id": _uuid_schema(),
                    "application_id": _application_id_schema(),
                },
                required={"host_epoch", "window_id", "process_id"},
            )
        ),
        output_schema=ToolOutputSchema(_focus_output_schema()),
        effect=ToolEffect.REVERSIBLE_WRITE,
        approval_may_be_required=False,
        max_input_bytes=MAX_HOST_CONTROL_TOOL_INPUT_BYTES,
        max_output_bytes=MAX_HOST_CONTROL_TOOL_OUTPUT_BYTES,
        timeout=limits.operation_timeout,
        resolver_id=HOST_WINDOW_FOCUS_TOOL_RESOLVER_ID,
        adapter_id=HOST_WINDOW_FOCUS_TOOL_ADAPTER_ID,
    )


def host_application_close_tool_descriptor(limits: HostAutomationLimits) -> ToolDescriptor:
    _require_limits(limits)
    return ToolDescriptor(
        tool_id=HOST_APPLICATION_CLOSE_TOOL_ID,
        name="Gracefully close configured host application",
        description="Request graceful close of one exact configured application process.",
        input_schema=ToolInputSchema(
            _object_schema(
                {
                    "host_epoch": _uuid_schema(),
                    "application_id": _application_id_schema(),
                    "process_id": _uuid_schema(),
                },
                required={"host_epoch", "application_id", "process_id"},
            )
        ),
        output_schema=ToolOutputSchema(_close_output_schema()),
        effect=ToolEffect.IRREVERSIBLE_WRITE,
        approval_may_be_required=True,
        max_input_bytes=MAX_HOST_CONTROL_TOOL_INPUT_BYTES,
        max_output_bytes=MAX_HOST_CONTROL_TOOL_OUTPUT_BYTES,
        timeout=limits.operation_timeout,
        resolver_id=HOST_APPLICATION_CLOSE_TOOL_RESOLVER_ID,
        adapter_id=HOST_APPLICATION_CLOSE_TOOL_ADAPTER_ID,
    )


def host_clipboard_write_tool_descriptor(limits: HostAutomationLimits) -> ToolDescriptor:
    _require_limits(limits)
    return ToolDescriptor(
        tool_id=HOST_CLIPBOARD_WRITE_TOOL_ID,
        name="Write bounded host clipboard text",
        description="Write bounded validated text to the configured host clipboard.",
        input_schema=ToolInputSchema(
            _object_schema(
                {"text": _clipboard_text_schema(limits)},
                required={"text"},
            )
        ),
        output_schema=ToolOutputSchema(_clipboard_write_output_schema(limits)),
        effect=ToolEffect.IRREVERSIBLE_WRITE,
        approval_may_be_required=False,
        max_input_bytes=MAX_HOST_CLIPBOARD_TOOL_INPUT_BYTES,
        max_output_bytes=MAX_HOST_CONTROL_TOOL_OUTPUT_BYTES,
        timeout=limits.operation_timeout,
        resolver_id=HOST_CLIPBOARD_WRITE_TOOL_RESOLVER_ID,
        adapter_id=HOST_CLIPBOARD_WRITE_TOOL_ADAPTER_ID,
    )


def host_clipboard_read_tool_descriptor(limits: HostAutomationLimits) -> ToolDescriptor:
    _require_limits(limits)
    return ToolDescriptor(
        tool_id=HOST_CLIPBOARD_READ_TOOL_ID,
        name="Read bounded host clipboard text",
        description="Read bounded text from the separately authorized configured host clipboard.",
        input_schema=ToolInputSchema(_object_schema({}, required=set())),
        output_schema=ToolOutputSchema(_clipboard_read_output_schema(limits)),
        effect=ToolEffect.READ_ONLY,
        approval_may_be_required=False,
        max_input_bytes=MAX_HOST_CONTROL_TOOL_INPUT_BYTES,
        max_output_bytes=MAX_HOST_CONTROL_TOOL_OUTPUT_BYTES,
        timeout=limits.operation_timeout,
        resolver_id=HOST_CLIPBOARD_READ_TOOL_RESOLVER_ID,
        adapter_id=HOST_CLIPBOARD_READ_TOOL_ADAPTER_ID,
    )


class _ApplicationLaunchResourceResolver:
    resolver_id = HOST_APPLICATION_LAUNCH_TOOL_RESOLVER_ID

    def __init__(
        self,
        host_id: HostId,
        applications: Sequence[HostApplicationId],
    ) -> None:
        _require_host_id(host_id)
        self._host_id = host_id
        self._applications = _configured_applications(applications)

    def resolve_resource(self, arguments: Mapping[str, AgentJsonValue]) -> str:
        application_id = _launch_arguments(arguments, self._applications)
        return host_application_resource(self._host_id, application_id)


class _WindowFocusResourceResolver:
    resolver_id = HOST_WINDOW_FOCUS_TOOL_RESOLVER_ID

    def __init__(
        self,
        host_id: HostId,
        applications: Sequence[HostApplicationId],
    ) -> None:
        _require_host_id(host_id)
        self._host_id = host_id
        self._applications = _configured_applications(applications)

    def resolve_resource(self, arguments: Mapping[str, AgentJsonValue]) -> str:
        _, window_id, _, _ = _focus_arguments(arguments, self._applications)
        return host_window_resource(self._host_id, window_id)


class _ApplicationCloseResourceResolver:
    resolver_id = HOST_APPLICATION_CLOSE_TOOL_RESOLVER_ID

    def __init__(
        self,
        host_id: HostId,
        applications: Sequence[HostApplicationId],
    ) -> None:
        _require_host_id(host_id)
        self._host_id = host_id
        self._applications = _configured_applications(applications)

    def resolve_resource(self, arguments: Mapping[str, AgentJsonValue]) -> str:
        _, _, process_id = _close_arguments(arguments, self._applications)
        return host_process_resource(self._host_id, process_id)


def host_application_launch_tool_resolver(
    host_id: HostId,
    applications: Sequence[HostApplicationId],
) -> _ApplicationLaunchResourceResolver:
    return _ApplicationLaunchResourceResolver(host_id, applications)


def host_window_focus_tool_resolver(
    host_id: HostId,
    applications: Sequence[HostApplicationId],
) -> _WindowFocusResourceResolver:
    return _WindowFocusResourceResolver(host_id, applications)


def host_application_close_tool_resolver(
    host_id: HostId,
    applications: Sequence[HostApplicationId],
) -> _ApplicationCloseResourceResolver:
    return _ApplicationCloseResourceResolver(host_id, applications)


def host_clipboard_write_tool_resolver(host_id: HostId) -> StaticToolResourceResolver:
    _require_host_id(host_id)
    return StaticToolResourceResolver(
        HOST_CLIPBOARD_WRITE_TOOL_RESOLVER_ID,
        host_clipboard_resource(host_id),
    )


def host_clipboard_read_tool_resolver(host_id: HostId) -> StaticToolResourceResolver:
    _require_host_id(host_id)
    return StaticToolResourceResolver(
        HOST_CLIPBOARD_READ_TOOL_RESOLVER_ID,
        host_clipboard_resource(host_id),
    )


class _ContextRequiredHostToolAdapter:
    async def invoke(self, request: ToolInvocationRequest) -> ToolInvocationResult:
        del request
        raise ToolExecutionError()


class HostApplicationLaunchToolAdapter(_ContextRequiredHostToolAdapter):
    adapter_id = HOST_APPLICATION_LAUNCH_TOOL_ADAPTER_ID
    tool_id = HOST_APPLICATION_LAUNCH_TOOL_ID

    def __init__(
        self,
        service: HostAutomationService,
        *,
        host_id: HostId,
        limits: HostAutomationLimits,
        applications: Sequence[HostApplicationId],
    ) -> None:
        _require_service(service)
        _require_host_id(host_id)
        _require_limits(limits)
        self._service = service
        self._host_id = host_id
        self._limits = limits
        self._applications = _configured_applications(applications)

    async def invoke_with_context(
        self,
        request: ToolInvocationRequest,
        context: SecurityContext,
        *,
        final_admission: ToolFinalAdmissionValidator | None = None,
    ) -> ToolInvocationResult:
        _require_context(context)
        _require_tool_request(request, self.tool_id)
        application_id = _launch_arguments(request.arguments, self._applications)
        resource = host_application_resource(self._host_id, application_id)
        _require_resolved_resource(request, resource)
        host_request = HostApplicationLaunchRequest(
            host_id=self._host_id,
            application_id=application_id,
        )
        if final_admission is None:
            result = await self._service.launch_application(host_request, context)
        else:
            result = await self._service.launch_application(
                host_request,
                context,
                final_admission=final_admission,
            )
        return _successful_result(
            request,
            _launch_output(result, request=host_request),
        )

    async def invoke_with_context_and_final_admission(
        self,
        request: ToolInvocationRequest,
        context: SecurityContext,
        final_admission: ToolFinalAdmissionValidator,
    ) -> ToolInvocationResult:
        return await self.invoke_with_context(
            request,
            context,
            final_admission=final_admission,
        )


class HostWindowFocusToolAdapter(_ContextRequiredHostToolAdapter):
    adapter_id = HOST_WINDOW_FOCUS_TOOL_ADAPTER_ID
    tool_id = HOST_WINDOW_FOCUS_TOOL_ID

    def __init__(
        self,
        service: HostAutomationService,
        *,
        host_id: HostId,
        limits: HostAutomationLimits,
        applications: Sequence[HostApplicationId],
    ) -> None:
        _require_service(service)
        _require_host_id(host_id)
        _require_limits(limits)
        self._service = service
        self._host_id = host_id
        self._limits = limits
        self._applications = _configured_applications(applications)

    async def invoke_with_context(
        self,
        request: ToolInvocationRequest,
        context: SecurityContext,
        *,
        final_admission: ToolFinalAdmissionValidator | None = None,
    ) -> ToolInvocationResult:
        _require_context(context)
        _require_tool_request(request, self.tool_id)
        host_epoch, window_id, process_id, application_id = _focus_arguments(
            request.arguments,
            self._applications,
        )
        resource = host_window_resource(self._host_id, window_id)
        _require_resolved_resource(request, resource)
        host_request = HostWindowFocusRequest(
            host_id=self._host_id,
            host_epoch=host_epoch,
            window_id=window_id,
            process_id=process_id,
            application_id=application_id,
        )
        if final_admission is None:
            result = await self._service.focus_window(host_request, context)
        else:
            result = await self._service.focus_window(
                host_request,
                context,
                final_admission=final_admission,
            )
        return _successful_result(
            request,
            _focus_output(result, request=host_request),
        )

    async def invoke_with_context_and_final_admission(
        self,
        request: ToolInvocationRequest,
        context: SecurityContext,
        final_admission: ToolFinalAdmissionValidator,
    ) -> ToolInvocationResult:
        return await self.invoke_with_context(
            request,
            context,
            final_admission=final_admission,
        )


class HostApplicationCloseToolAdapter(_ContextRequiredHostToolAdapter):
    adapter_id = HOST_APPLICATION_CLOSE_TOOL_ADAPTER_ID
    tool_id = HOST_APPLICATION_CLOSE_TOOL_ID

    def __init__(
        self,
        service: HostAutomationService,
        *,
        host_id: HostId,
        limits: HostAutomationLimits,
        applications: Sequence[HostApplicationId],
    ) -> None:
        _require_service(service)
        _require_host_id(host_id)
        _require_limits(limits)
        self._service = service
        self._host_id = host_id
        self._limits = limits
        self._applications = _configured_applications(applications)

    async def invoke_with_context(
        self,
        request: ToolInvocationRequest,
        context: SecurityContext,
        *,
        final_admission: ToolFinalAdmissionValidator | None = None,
    ) -> ToolInvocationResult:
        _require_context(context)
        _require_tool_request(request, self.tool_id)
        host_epoch, application_id, process_id = _close_arguments(
            request.arguments,
            self._applications,
        )
        resource = host_process_resource(self._host_id, process_id)
        _require_resolved_resource(request, resource)
        host_request = HostApplicationCloseRequest(
            host_id=self._host_id,
            host_epoch=host_epoch,
            application_id=application_id,
            process_id=process_id,
        )
        if final_admission is None:
            result = await self._service.close_application(host_request, context)
        else:
            result = await self._service.close_application(
                host_request,
                context,
                final_admission=final_admission,
            )
        return _successful_result(
            request,
            _close_output(result, request=host_request),
        )

    async def invoke_with_context_and_final_admission(
        self,
        request: ToolInvocationRequest,
        context: SecurityContext,
        final_admission: ToolFinalAdmissionValidator,
    ) -> ToolInvocationResult:
        return await self.invoke_with_context(
            request,
            context,
            final_admission=final_admission,
        )


class HostClipboardWriteToolAdapter(_ContextRequiredHostToolAdapter):
    adapter_id = HOST_CLIPBOARD_WRITE_TOOL_ADAPTER_ID
    tool_id = HOST_CLIPBOARD_WRITE_TOOL_ID

    def __init__(
        self,
        service: HostAutomationService,
        *,
        host_id: HostId,
        limits: HostAutomationLimits,
    ) -> None:
        _require_service(service)
        _require_host_id(host_id)
        _require_limits(limits)
        self._service = service
        self._host_id = host_id
        self._limits = limits
        self._resource = host_clipboard_resource(host_id)

    @property
    def host_epoch(self) -> HostEpoch:
        return self._service.host_epoch

    async def invoke_with_context(
        self,
        request: ToolInvocationRequest,
        context: SecurityContext,
        *,
        final_admission: ToolFinalAdmissionValidator | None = None,
    ) -> ToolInvocationResult:
        _require_context(context)
        _require_tool_request(request, self.tool_id)
        _require_resolved_resource(request, self._resource)
        text = _clipboard_write_arguments(request.arguments, self._limits)
        host_request = HostClipboardWriteRequest(host_id=self._host_id, text=text)
        if final_admission is None:
            result = await self._service.write_clipboard(host_request, context)
        else:
            result = await self._service.write_clipboard(
                host_request,
                context,
                final_admission=final_admission,
            )
        return _successful_result(
            request,
            _clipboard_write_output(result, request=host_request, limits=self._limits),
        )

    async def invoke_with_context_and_final_admission(
        self,
        request: ToolInvocationRequest,
        context: SecurityContext,
        final_admission: ToolFinalAdmissionValidator,
    ) -> ToolInvocationResult:
        return await self.invoke_with_context(
            request,
            context,
            final_admission=final_admission,
        )


class HostClipboardReadToolAdapter(_ContextRequiredHostToolAdapter):
    adapter_id = HOST_CLIPBOARD_READ_TOOL_ADAPTER_ID
    tool_id = HOST_CLIPBOARD_READ_TOOL_ID

    def __init__(
        self,
        service: HostAutomationService,
        *,
        host_id: HostId,
        limits: HostAutomationLimits,
    ) -> None:
        _require_service(service)
        _require_host_id(host_id)
        _require_limits(limits)
        self._service = service
        self._host_id = host_id
        self._limits = limits
        self._resource = host_clipboard_resource(host_id)

    @property
    def host_epoch(self) -> HostEpoch:
        return self._service.host_epoch

    async def invoke_with_context(
        self,
        request: ToolInvocationRequest,
        context: SecurityContext,
    ) -> ToolInvocationResult:
        _require_context(context)
        _require_tool_request(request, self.tool_id)
        _require_resolved_resource(request, self._resource)
        _clipboard_read_arguments(request.arguments)
        host_request = HostClipboardReadRequest(host_id=self._host_id)
        result = await self._service.read_clipboard(host_request, context)
        return _successful_result(
            request,
            _clipboard_read_output(result, request=host_request, limits=self._limits),
        )


def _object_schema(
    properties: Mapping[str, ToolSchema],
    *,
    required: set[str],
) -> ToolSchema:
    return ToolSchema(
        kind=ToolSchemaType.OBJECT,
        properties=properties,
        required=frozenset(required),
    )


def _uuid_schema() -> ToolSchema:
    return ToolSchema(
        kind=ToolSchemaType.STRING,
        min_length=_UUID_TEXT_LENGTH,
        max_length=_UUID_TEXT_LENGTH,
    )


def _application_id_schema() -> ToolSchema:
    return ToolSchema(
        kind=ToolSchemaType.STRING,
        min_length=1,
        max_length=MAX_HOST_IDENTIFIER_LENGTH,
    )


def _clipboard_char_limit(limits: HostAutomationLimits) -> int:
    return min(limits.max_clipboard_text_chars, MAX_TOOL_SCHEMA_STRING_LENGTH)


def _clipboard_text_schema(limits: HostAutomationLimits) -> ToolSchema:
    return ToolSchema(
        kind=ToolSchemaType.STRING,
        max_length=_clipboard_char_limit(limits),
    )


def _launch_output_schema() -> ToolSchema:
    return _object_schema(
        {
            "host_epoch": _uuid_schema(),
            "application_id": _application_id_schema(),
            "process_id": _uuid_schema(),
        },
        required={"host_epoch", "application_id", "process_id"},
    )


def _focus_output_schema() -> ToolSchema:
    return _object_schema(
        {
            "host_epoch": _uuid_schema(),
            "window_id": _uuid_schema(),
            "process_id": _uuid_schema(),
        },
        required={"host_epoch", "window_id", "process_id"},
    )


def _close_output_schema() -> ToolSchema:
    return _object_schema(
        {
            "host_epoch": _uuid_schema(),
            "application_id": _application_id_schema(),
            "process_id": _uuid_schema(),
        },
        required={"host_epoch", "application_id", "process_id"},
    )


def _clipboard_write_output_schema(limits: HostAutomationLimits) -> ToolSchema:
    return _object_schema(
        {
            "written_characters": ToolSchema(
                kind=ToolSchemaType.INTEGER,
                minimum=0,
                maximum=limits.max_clipboard_text_chars,
            ),
            "written_bytes": ToolSchema(
                kind=ToolSchemaType.INTEGER,
                minimum=0,
                maximum=limits.max_clipboard_text_bytes,
            ),
        },
        required={"written_characters", "written_bytes"},
    )


def _clipboard_read_output_schema(limits: HostAutomationLimits) -> ToolSchema:
    return _object_schema(
        {"text": _clipboard_text_schema(limits)},
        required={"text"},
    )


def _configured_applications(
    applications: Sequence[HostApplicationId],
) -> dict[str, HostApplicationId]:
    if isinstance(applications, (str, bytes)) or not isinstance(applications, Sequence):
        raise TypeError("applications must be a sequence")
    normalized: dict[str, HostApplicationId] = {}
    for application_id in applications:
        if not isinstance(application_id, HostApplicationId):
            raise TypeError("applications must contain HostApplicationId values")
        key = str(application_id)
        if key in normalized:
            raise ValueError("applications contain a duplicate application id")
        normalized[key] = application_id
    return normalized


def _launch_arguments(
    arguments: Mapping[str, object],
    applications: Mapping[str, HostApplicationId],
) -> HostApplicationId:
    _require_argument_keys(arguments, {"application_id"})
    return _configured_application_argument(arguments.get("application_id"), applications)


def _focus_arguments(
    arguments: Mapping[str, object],
    applications: Mapping[str, HostApplicationId],
) -> tuple[HostEpoch, HostWindowId, HostProcessId, HostApplicationId | None]:
    keys = frozenset(arguments)
    required = frozenset({"host_epoch", "window_id", "process_id"})
    if keys not in (required, required | {"application_id"}):
        raise ToolExecutionError()
    host_epoch = HostEpoch(_canonical_uuid(arguments.get("host_epoch")))
    window_id = HostWindowId(_canonical_uuid(arguments.get("window_id")))
    process_id = HostProcessId(_canonical_uuid(arguments.get("process_id")))
    application_id = (
        _configured_application_argument(arguments.get("application_id"), applications)
        if "application_id" in arguments
        else None
    )
    return host_epoch, window_id, process_id, application_id


def _close_arguments(
    arguments: Mapping[str, object],
    applications: Mapping[str, HostApplicationId],
) -> tuple[HostEpoch, HostApplicationId, HostProcessId]:
    _require_argument_keys(arguments, {"host_epoch", "application_id", "process_id"})
    return (
        HostEpoch(_canonical_uuid(arguments.get("host_epoch"))),
        _configured_application_argument(arguments.get("application_id"), applications),
        HostProcessId(_canonical_uuid(arguments.get("process_id"))),
    )


def _clipboard_write_arguments(
    arguments: Mapping[str, object],
    limits: HostAutomationLimits,
) -> str:
    _require_argument_keys(arguments, {"text"})
    value = arguments.get("text")
    if not isinstance(value, str):
        raise ToolExecutionError()
    if "\x00" in value or len(value) > _clipboard_char_limit(limits):
        raise ToolExecutionError()
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exception:
        raise ToolExecutionError() from exception
    if len(encoded) > limits.max_clipboard_text_bytes:
        raise ToolExecutionError()
    return value


def _clipboard_read_arguments(
    arguments: Mapping[str, object],
) -> None:
    _require_argument_keys(arguments, set())


def _require_argument_keys(
    arguments: Mapping[str, object],
    expected: set[str],
) -> None:
    if not isinstance(arguments, Mapping):
        raise TypeError("arguments must be a mapping")
    if frozenset(arguments) != frozenset(expected):
        raise ToolExecutionError()


def _configured_application_argument(
    value: object,
    applications: Mapping[str, HostApplicationId],
) -> HostApplicationId:
    if not isinstance(value, str):
        raise ToolExecutionError()
    try:
        parsed = HostApplicationId(value)
    except (TypeError, ValueError) as exception:
        raise ToolExecutionError() from exception
    if str(parsed) != value:
        raise ToolExecutionError()
    configured = applications.get(value)
    if configured is None or configured != parsed:
        raise ToolExecutionError()
    return configured


def _canonical_uuid(value: object) -> UUID:
    if not isinstance(value, str):
        raise ToolExecutionError()
    try:
        parsed = UUID(value)
    except (AttributeError, TypeError, ValueError) as exception:
        raise ToolExecutionError() from exception
    if str(parsed) != value:
        raise ToolExecutionError()
    return parsed


def _launch_output(
    result: HostApplicationLaunchResult,
    *,
    request: HostApplicationLaunchRequest,
) -> Mapping[str, AgentJsonInput]:
    if not isinstance(result, HostApplicationLaunchResult):
        raise ToolExecutionError()
    if (
        result.request_id != request.request_id
        or result.host_id != request.host_id
        or result.application_id != request.application_id
    ):
        raise ToolExecutionError()
    return {
        "host_epoch": str(result.host_epoch),
        "application_id": str(result.application_id),
        "process_id": str(result.process_id),
    }


def _focus_output(
    result: HostWindowFocusResult,
    *,
    request: HostWindowFocusRequest,
) -> Mapping[str, AgentJsonInput]:
    if not isinstance(result, HostWindowFocusResult):
        raise ToolExecutionError()
    if (
        result.request_id != request.request_id
        or result.host_id != request.host_id
        or result.host_epoch != request.host_epoch
        or result.window_id != request.window_id
        or result.process_id != request.process_id
    ):
        raise ToolExecutionError()
    return {
        "host_epoch": str(result.host_epoch),
        "window_id": str(result.window_id),
        "process_id": str(result.process_id),
    }


def _close_output(
    result: HostApplicationCloseResult,
    *,
    request: HostApplicationCloseRequest,
) -> Mapping[str, AgentJsonInput]:
    if not isinstance(result, HostApplicationCloseResult):
        raise ToolExecutionError()
    if (
        result.request_id != request.request_id
        or result.host_id != request.host_id
        or result.host_epoch != request.host_epoch
        or result.application_id != request.application_id
        or result.process_id != request.process_id
    ):
        raise ToolExecutionError()
    return {
        "host_epoch": str(result.host_epoch),
        "application_id": str(result.application_id),
        "process_id": str(result.process_id),
    }


def _clipboard_write_output(
    result: HostClipboardWriteResult,
    *,
    request: HostClipboardWriteRequest,
    limits: HostAutomationLimits,
) -> Mapping[str, AgentJsonInput]:
    if not isinstance(result, HostClipboardWriteResult):
        raise ToolExecutionError()
    expected_characters = len(request.text)
    expected_bytes = len(request.text.encode("utf-8"))
    if (
        result.request_id != request.request_id
        or result.host_id != request.host_id
        or result.written_characters != expected_characters
        or result.written_bytes != expected_bytes
        or result.written_characters > limits.max_clipboard_text_chars
        or result.written_bytes > limits.max_clipboard_text_bytes
    ):
        raise ToolExecutionError()
    return {
        "written_characters": result.written_characters,
        "written_bytes": result.written_bytes,
    }


def _clipboard_read_output(
    result: HostClipboardReadResult,
    *,
    request: HostClipboardReadRequest,
    limits: HostAutomationLimits,
) -> Mapping[str, AgentJsonInput]:
    if not isinstance(result, HostClipboardReadResult):
        raise ToolExecutionError()
    if result.request_id != request.request_id or result.host_id != request.host_id:
        raise ToolExecutionError()
    if "\x00" in result.text or len(result.text) > _clipboard_char_limit(limits):
        raise ToolExecutionError()
    try:
        encoded = result.text.encode("utf-8")
    except UnicodeEncodeError as exception:
        raise ToolExecutionError() from exception
    if len(encoded) > limits.max_clipboard_text_bytes:
        raise ToolExecutionError()
    return {"text": result.text}


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


def _require_tool_request(request: ToolInvocationRequest, tool_id: ToolId) -> None:
    if not isinstance(request, ToolInvocationRequest):
        raise TypeError("request must be ToolInvocationRequest")
    if request.tool_id != tool_id:
        raise ToolExecutionError()


def _require_resolved_resource(request: ToolInvocationRequest, resource: str) -> None:
    if request.resolved_resource != resource:
        raise ToolExecutionError()


def _require_service(service: HostAutomationService) -> None:
    if not isinstance(service, HostAutomationService):
        raise TypeError("service must be HostAutomationService")


def _require_context(context: SecurityContext) -> None:
    if not isinstance(context, SecurityContext):
        raise TypeError("context must be SecurityContext")


def _require_host_id(value: HostId) -> None:
    if not isinstance(value, HostId):
        raise TypeError("host_id must be HostId")


def _require_limits(value: HostAutomationLimits) -> None:
    if not isinstance(value, HostAutomationLimits):
        raise TypeError("limits must be HostAutomationLimits")
