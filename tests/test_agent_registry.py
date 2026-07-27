from datetime import UTC, datetime, timedelta

import pytest

from phoenix_os.agent import (
    AgentLimitExceededError,
    AgentRegistryClosedError,
    AgentSchemaError,
    StaticToolResourceResolver,
    ToolAdapter,
    ToolAlreadyRegisteredError,
    ToolAvailability,
    ToolDescriptor,
    ToolEffect,
    ToolId,
    ToolInputSchema,
    ToolInvocationRequest,
    ToolInvocationResult,
    ToolNotFoundError,
    ToolOutputSchema,
    ToolRegistry,
    ToolResultStatus,
    ToolSchema,
    ToolSchemaType,
)

NOW = datetime(2026, 7, 27, 12, tzinfo=UTC)


def _schema() -> ToolSchema:
    return ToolSchema(
        kind=ToolSchemaType.OBJECT,
        properties={"key": ToolSchema(kind=ToolSchemaType.STRING, min_length=1, max_length=64)},
        required=frozenset({"key"}),
    )


def _descriptor(
    tool_id: str,
    *,
    availability: ToolAvailability = ToolAvailability.ACTIVE,
    max_input_bytes: int = 4_096,
) -> ToolDescriptor:
    return ToolDescriptor(
        tool_id=ToolId(tool_id),
        name=f"Tool {tool_id}",
        description="Deterministic reviewed test tool.",
        input_schema=ToolInputSchema(_schema()),
        output_schema=ToolOutputSchema(
            ToolSchema(
                kind=ToolSchemaType.OBJECT,
                properties={"value": ToolSchema(kind=ToolSchemaType.STRING, max_length=64)},
                required=frozenset({"value"}),
            )
        ),
        effect=ToolEffect.READ_ONLY,
        approval_may_be_required=False,
        max_input_bytes=max_input_bytes,
        max_output_bytes=4_096,
        timeout=timedelta(seconds=5),
        resolver_id=f"resolver.{tool_id}",
        adapter_id=f"adapter.{tool_id}",
        availability=availability,
    )


class RecordingAdapter:
    def __init__(self, tool_id: str) -> None:
        self._tool_id = ToolId(tool_id)
        self._adapter_id = f"adapter.{tool_id}"
        self.requests: list[ToolInvocationRequest] = []

    @property
    def adapter_id(self) -> str:
        return self._adapter_id

    @property
    def tool_id(self) -> ToolId:
        return self._tool_id

    async def invoke(self, request: ToolInvocationRequest) -> ToolInvocationResult:
        self.requests.append(request)
        return ToolInvocationResult(
            run_id=request.run_id,
            step_id=request.step_id,
            call_id=request.call_id,
            tool_id=request.tool_id,
            status=ToolResultStatus.SUCCEEDED,
            output={"value": "ok"},
            started_at=NOW,
            completed_at=NOW,
        )


def _register(
    registry: ToolRegistry,
    descriptor: ToolDescriptor,
) -> RecordingAdapter:
    adapter = RecordingAdapter(str(descriptor.tool_id))
    resolver = StaticToolResourceResolver(
        descriptor.resolver_id,
        f"fixture:{descriptor.tool_id}",
    )
    registry.register_tool(descriptor, resolver=resolver, adapter=adapter)
    return adapter


def test_registry_registers_and_lists_active_tools_in_registration_order() -> None:
    registry = ToolRegistry()
    second = _descriptor("second")
    disabled = _descriptor("disabled", availability=ToolAvailability.DISABLED)
    first = _descriptor("first")

    _register(registry, second)
    _register(registry, disabled)
    _register(registry, first)

    assert registry.list_descriptors() == (second, first)
    assert registry.resolve_descriptor("first") == first
    assert isinstance(registry.resolve_adapter("first"), ToolAdapter)
    with pytest.raises(ToolNotFoundError):
        registry.resolve_descriptor("disabled")


def test_registry_rejects_duplicate_and_mismatched_registration() -> None:
    registry = ToolRegistry()
    descriptor = _descriptor("files.read")
    _register(registry, descriptor)

    with pytest.raises(ToolAlreadyRegisteredError):
        _register(registry, descriptor)

    wrong_adapter = RecordingAdapter("other")
    with pytest.raises(ValueError, match="adapter"):
        registry.register_tool(
            _descriptor("expected"),
            resolver=StaticToolResourceResolver(
                "resolver.expected",
                "fixture:expected",
            ),
            adapter=wrong_adapter,
        )


def test_admission_validates_arguments_then_resolves_server_resource() -> None:
    registry = ToolRegistry()
    descriptor = _descriptor("lookup")
    _register(registry, descriptor)
    caller_owned: dict[str, object] = {"key": "alpha"}

    resolution = registry.admit_tool_call("lookup", caller_owned)  # type: ignore[arg-type]
    caller_owned["key"] = "changed"

    assert resolution.descriptor == descriptor
    assert resolution.arguments == {"key": "alpha"}
    assert resolution.resolved_resource == "fixture:lookup"
    with pytest.raises(TypeError):
        resolution.arguments["key"] = "changed"  # type: ignore[index]
    with pytest.raises(AgentSchemaError, match="unknown"):
        registry.admit_tool_call("lookup", {"key": "alpha", "extra": True})


def test_admission_enforces_descriptor_input_byte_limit() -> None:
    registry = ToolRegistry()
    descriptor = _descriptor("tiny", max_input_bytes=8)
    _register(registry, descriptor)

    with pytest.raises(AgentLimitExceededError):
        registry.admit_tool_call("tiny", {"key": "alpha"})


def test_registry_close_is_terminal() -> None:
    registry = ToolRegistry()
    registry.close()

    assert registry.closed is True
    with pytest.raises(AgentRegistryClosedError):
        registry.list_descriptors()
    with pytest.raises(AgentRegistryClosedError):
        registry.register_tool(
            _descriptor("closed"),
            resolver=StaticToolResourceResolver("resolver.closed", "fixture:closed"),
            adapter=RecordingAdapter("closed"),
        )
