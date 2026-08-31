from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta

import pytest

from phoenix_os.agent import (
    AgentCancellationToken,
    AgentId,
    AgentLimits,
    AgentLoop,
    AgentMessage,
    AgentMessageRole,
    AgentRunRequest,
    AgentRunStatus,
    DeterministicReadOnlyTool,
    InferenceBackedAgentModelTurnAdapter,
    ToolDescriptor,
    ToolEffect,
    ToolId,
    ToolInputSchema,
    ToolInvocationRequest,
    ToolOutputSchema,
    ToolRegistry,
    ToolSchema,
    ToolSchemaType,
)
from phoenix_os.agent.tools import StaticToolResourceResolver
from phoenix_os.events import EventBus
from phoenix_os.inference import (
    InferenceLimits,
    InferenceProviderConfiguration,
    InferenceRequest,
    InferenceServiceConfiguration,
    ModelCapabilities,
    ModelDescriptor,
    ModelEndpointMode,
    ModelEndpointPolicy,
    ModelId,
)
from phoenix_os.inference.execution import InferenceRuntime
from phoenix_os.inference.ollama import (
    OLLAMA_ENDPOINT_URL,
    OLLAMA_PROVIDER_ID,
    OllamaModelBinding,
    OllamaModelProvider,
    OllamaTransportLimits,
)
from phoenix_os.inference.registry import ModelProviderRegistry
from phoenix_os.inference.service import InferenceService
from phoenix_os.policy import PrincipalType, SecurityContext
from phoenix_os.runtime import RuntimeContext


class _FakeConnection:
    def __init__(
        self,
        response: bytes,
        *,
        read_limit: int,
        hang: bool = False,
    ) -> None:
        self._reader = asyncio.StreamReader(limit=read_limit)
        if not hang:
            self._reader.feed_data(response)
            self._reader.feed_eof()
        self.written = bytearray()
        self.closed = False

    @property
    def reader(self) -> asyncio.StreamReader:
        return self._reader

    def write(self, data: bytes) -> None:
        self.written.extend(data)

    async def drain(self) -> None:
        await asyncio.sleep(0)

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        await asyncio.sleep(0)


class _FakeConnector:
    def __init__(
        self,
        responses: tuple[bytes, ...] = (),
        *,
        hang: bool = False,
    ) -> None:
        self._responses = list(responses)
        self._hang = hang
        self.calls: list[tuple[str, int, float, int]] = []
        self.connections: list[_FakeConnection] = []

    async def connect(
        self,
        address: str,
        port: int,
        *,
        connect_timeout: float,
        read_limit: int,
    ) -> _FakeConnection:
        self.calls.append((address, port, connect_timeout, read_limit))
        await asyncio.sleep(0)
        if self._hang:
            response = b""
        else:
            if not self._responses:
                raise AssertionError("fake Ollama connector has no response")
            response = self._responses.pop(0)
        connection = _FakeConnection(response, read_limit=read_limit, hang=self._hang)
        self.connections.append(connection)
        return connection


class _AllowRunAuthorizer:
    async def authorize(self, request: AgentRunRequest, context: SecurityContext) -> None:
        assert context.authenticated


class _RecordingInferenceAuthorizer:
    def __init__(self) -> None:
        self.requests: list[InferenceRequest] = []

    async def authorize(self, request: InferenceRequest, context: SecurityContext) -> None:
        assert context.authenticated
        self.requests.append(request)


class _RecordingToolAuthorizer:
    def __init__(self) -> None:
        self.requests: list[object] = []

    async def authorize(
        self,
        request: ToolInvocationRequest,
        descriptor: ToolDescriptor,
        context: SecurityContext,
    ) -> None:
        assert context.authenticated
        assert request.tool_id == descriptor.tool_id
        self.requests.append(request)


def _context() -> SecurityContext:
    return SecurityContext(
        principal="service:assistant",
        principal_type=PrincipalType.SERVICE,
        authenticated=True,
    )


def _tool_descriptor() -> ToolDescriptor:
    schema = ToolSchema(
        kind=ToolSchemaType.OBJECT,
        properties={
            "key": ToolSchema(
                kind=ToolSchemaType.STRING,
                min_length=1,
                max_length=128,
            )
        },
        required=frozenset({"key"}),
    )
    return ToolDescriptor(
        tool_id=ToolId("lookup"),
        name="Lookup",
        description="Look up one reviewed value.",
        input_schema=ToolInputSchema(schema),
        output_schema=ToolOutputSchema(schema),
        effect=ToolEffect.READ_ONLY,
        approval_may_be_required=False,
        max_input_bytes=4_096,
        max_output_bytes=4_096,
        timeout=timedelta(seconds=5),
        resolver_id="static-resource",
        adapter_id="deterministic-read-only",
    )


def _model_descriptor() -> ModelDescriptor:
    return ModelDescriptor(
        provider_id=OLLAMA_PROVIDER_ID,
        model_id=ModelId("qwen3-coder-30b"),
        provider_model_name="qwen3-coder:30b",
        capabilities=ModelCapabilities(complete=True, streaming=True),
        limits=InferenceLimits(
            max_messages=16,
            max_message_chars=32_768,
            max_total_input_chars=65_536,
            max_output_tokens=128,
            max_response_chars=16_384,
        ),
    )


def _provider_configuration() -> InferenceProviderConfiguration:
    return InferenceProviderConfiguration(
        OLLAMA_PROVIDER_ID,
        endpoint_policy=ModelEndpointPolicy(
            OLLAMA_ENDPOINT_URL,
            mode=ModelEndpointMode.LOOPBACK_HTTP,
            allowed_ports=frozenset({11_434}),
        ),
    )


def _chat_response(
    content: str,
    *,
    input_tokens: int = 16,
    output_tokens: int = 8,
) -> bytes:
    body = json.dumps(
        {
            "model": "qwen3-coder:30b",
            "message": {"role": "assistant", "content": content},
            "done": True,
            "done_reason": "stop",
            "prompt_eval_count": input_tokens,
            "eval_count": output_tokens,
        },
        separators=(",", ":"),
    ).encode("utf-8")
    return (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: application/json\r\n"
        + f"Content-Length: {len(body)}\r\n".encode("ascii")
        + b"\r\n"
        + body
    )


def _written_body(connection: _FakeConnection) -> dict[str, object]:
    _head, body = bytes(connection.written).split(b"\r\n\r\n", 1)
    decoded = json.loads(body)
    assert isinstance(decoded, dict)
    return decoded


def _service(
    connector: _FakeConnector,
    *,
    transport_limits: OllamaTransportLimits | None = None,
) -> tuple[InferenceService, _RecordingInferenceAuthorizer]:
    descriptor = _model_descriptor()
    provider_configuration = _provider_configuration()
    provider = OllamaModelProvider(
        provider_configuration,
        (OllamaModelBinding(descriptor),),
        transport_limits=transport_limits,
        _connector=connector,
    )
    configuration = InferenceServiceConfiguration(
        providers=(provider_configuration,),
        models=(descriptor,),
    )
    registry = ModelProviderRegistry()
    registry.register_provider(provider)
    registry.register_model(descriptor)
    authorizer = _RecordingInferenceAuthorizer()
    runtime = InferenceRuntime(registry, authorizer)
    service = InferenceService(
        runtime,
        registry,
        configuration,
        events=EventBus(),
    )
    return service, authorizer


@pytest.mark.asyncio
async def test_real_ollama_structured_turn_runs_tool_then_final_through_rfc0026() -> None:
    connector = _FakeConnector(
        (
            _chat_response(
                '{"version":1,"kind":"tool","tool":"lookup","arguments":{"key":"alpha"}}'
            ),
            _chat_response('{"version":1,"kind":"final","content":"done"}'),
        )
    )
    service, runtime_authorizer = _service(connector)
    runtime_context = RuntimeContext(services={"inference": service})
    await service.start(runtime_context)

    tool_registry = ToolRegistry()
    descriptor = _tool_descriptor()
    tool_registry.register_tool(
        descriptor,
        resolver=StaticToolResourceResolver(
            resolver_id="static-resource",
            resource="lookup:alpha",
        ),
        adapter=DeterministicReadOnlyTool(
            "lookup",
            {"key": "value"},
        ),
    )
    model_authorizer = _RecordingInferenceAuthorizer()
    tool_authorizer = _RecordingToolAuthorizer()
    loop = AgentLoop(
        run_authorizer=_AllowRunAuthorizer(),
        model_authorizer=model_authorizer,
        tool_authorizer=tool_authorizer,
        model_adapter=InferenceBackedAgentModelTurnAdapter(service),
        registry=tool_registry,
    )
    now = datetime.now(UTC)
    run = AgentRunRequest(
        agent_id=AgentId("assistant"),
        provider_id=OLLAMA_PROVIDER_ID,
        model_id=ModelId("qwen3-coder-30b"),
        messages=(
            AgentMessage(
                AgentMessageRole.USER,
                "Use the admitted lookup tool, then return a final result.",
            ),
        ),
        limits=AgentLimits(
            max_model_turns=4,
            max_tool_calls=2,
            max_output_tokens=128,
        ),
        created_at=now,
        deadline=now + timedelta(minutes=2),
    )

    try:
        result = await loop.run(run, _context())
    finally:
        await service.stop(runtime_context)

    assert result.status is AgentRunStatus.COMPLETED
    assert result.final_output == "done"
    assert len(connector.calls) == 2
    assert all(call[0:2] == ("127.0.0.1", 11_434) for call in connector.calls)
    assert all(connection.closed for connection in connector.connections)
    assert len(model_authorizer.requests) == 4
    assert len(tool_authorizer.requests) == 2
    assert len(runtime_authorizer.requests) == 2
    assert runtime_authorizer.requests[0] is model_authorizer.requests[0]
    assert runtime_authorizer.requests[1] is model_authorizer.requests[2]

    first = _written_body(connector.connections[0])
    second = _written_body(connector.connections[1])
    for native in (first, second):
        assert native["model"] == "qwen3-coder:30b"
        assert native["stream"] is False
        assert native["think"] is False
        assert "tools" not in native

    first_messages = first["messages"]
    assert isinstance(first_messages, list)
    first_control = json.loads(first_messages[0]["content"])
    assert first_control["kind"] == "phoenix.agent.model-turn-context"
    assert first_control["tools"][0]["tool_id"] == "lookup"
    assert first_control["tool_outcome_allowed"] is True

    second_messages = second["messages"]
    assert isinstance(second_messages, list)
    tool_result = json.loads(second_messages[-1]["content"])
    assert tool_result["kind"] == "phoenix.agent.tool-result"
    assert tool_result["tool_id"] == "lookup"
    assert tool_result["trust"] == "untrusted_tool_output"
    assert json.loads(tool_result["content"]) == {"key": "value"}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "model_output",
    [
        '{"version":1,"kind":"tool","tool":"unknown","arguments":{}}',
        '{"version":1,"kind":"tool","tool":"lookup","arguments":{},"content":"mixed"}',
        '{"version":1,"kind":"tool","tool":["lookup","other"],"arguments":{}}',
    ],
)
async def test_real_ollama_malformed_tool_outcomes_fail_before_tool_authorization(
    model_output: str,
) -> None:
    connector = _FakeConnector((_chat_response(model_output),))
    service, _runtime_authorizer = _service(connector)
    runtime_context = RuntimeContext(services={"inference": service})
    await service.start(runtime_context)

    tool_registry = ToolRegistry()
    descriptor = _tool_descriptor()
    tool_registry.register_tool(
        descriptor,
        resolver=StaticToolResourceResolver(
            resolver_id="static-resource",
            resource="lookup:alpha",
        ),
        adapter=DeterministicReadOnlyTool("lookup", {"key": "value"}),
    )
    tool_authorizer = _RecordingToolAuthorizer()
    loop = AgentLoop(
        run_authorizer=_AllowRunAuthorizer(),
        model_authorizer=_RecordingInferenceAuthorizer(),
        tool_authorizer=tool_authorizer,
        model_adapter=InferenceBackedAgentModelTurnAdapter(service),
        registry=tool_registry,
    )
    now = datetime.now(UTC)
    run = AgentRunRequest(
        agent_id=AgentId("assistant"),
        provider_id=OLLAMA_PROVIDER_ID,
        model_id=ModelId("qwen3-coder-30b"),
        messages=(AgentMessage(AgentMessageRole.USER, "perform task"),),
        limits=AgentLimits(max_output_tokens=128),
        created_at=now,
        deadline=now + timedelta(minutes=2),
    )

    try:
        result = await loop.run(run, _context())
    finally:
        await service.stop(runtime_context)

    assert result.status is AgentRunStatus.FAILED
    assert tool_authorizer.requests == []
    assert len(connector.calls) == 1


@pytest.mark.asyncio
async def test_real_ollama_cancellation_closes_inflight_connection_without_retry() -> None:
    connector = _FakeConnector(hang=True)
    service, _runtime_authorizer = _service(
        connector,
        transport_limits=OllamaTransportLimits(
            connect_timeout_seconds=0.05,
            read_timeout_seconds=1.0,
            total_timeout_seconds=1.0,
        ),
    )
    runtime_context = RuntimeContext(services={"inference": service})
    await service.start(runtime_context)

    token = AgentCancellationToken()
    tool_authorizer = _RecordingToolAuthorizer()
    loop = AgentLoop(
        run_authorizer=_AllowRunAuthorizer(),
        model_authorizer=_RecordingInferenceAuthorizer(),
        tool_authorizer=tool_authorizer,
        model_adapter=InferenceBackedAgentModelTurnAdapter(service),
        registry=ToolRegistry(),
    )
    now = datetime.now(UTC)
    run = AgentRunRequest(
        agent_id=AgentId("assistant"),
        provider_id=OLLAMA_PROVIDER_ID,
        model_id=ModelId("qwen3-coder-30b"),
        messages=(AgentMessage(AgentMessageRole.USER, "wait for cancellation"),),
        limits=AgentLimits(
            max_output_tokens=128,
            cancellation_grace=timedelta(seconds=1),
        ),
        created_at=now,
        deadline=now + timedelta(minutes=2),
    )

    task = asyncio.create_task(loop.run(run, _context(), cancellation=token))
    try:
        for _ in range(100):
            if connector.connections and connector.connections[0].written:
                break
            await asyncio.sleep(0)
        assert len(connector.connections) == 1
        assert connector.connections[0].written

        token.cancel()
        result = await task
    finally:
        if not task.done():
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        await service.stop(runtime_context)

    assert result.status is AgentRunStatus.CANCELLED
    assert result.error_code == "cancelled"
    assert result.model_turns == 1
    assert result.tool_calls == 0
    assert tool_authorizer.requests == []
    assert len(connector.calls) == 1
    assert connector.connections[0].closed is True


@pytest.mark.asyncio
async def test_real_ollama_timeout_is_bounded_closes_connection_and_does_not_retry() -> None:
    connector = _FakeConnector(hang=True)
    service, _runtime_authorizer = _service(
        connector,
        transport_limits=OllamaTransportLimits(
            connect_timeout_seconds=0.05,
            read_timeout_seconds=0.01,
            total_timeout_seconds=0.1,
        ),
    )
    runtime_context = RuntimeContext(services={"inference": service})
    await service.start(runtime_context)

    tool_authorizer = _RecordingToolAuthorizer()
    loop = AgentLoop(
        run_authorizer=_AllowRunAuthorizer(),
        model_authorizer=_RecordingInferenceAuthorizer(),
        tool_authorizer=tool_authorizer,
        model_adapter=InferenceBackedAgentModelTurnAdapter(service),
        registry=ToolRegistry(),
    )
    now = datetime.now(UTC)
    run = AgentRunRequest(
        agent_id=AgentId("assistant"),
        provider_id=OLLAMA_PROVIDER_ID,
        model_id=ModelId("qwen3-coder-30b"),
        messages=(AgentMessage(AgentMessageRole.USER, "wait for timeout"),),
        limits=AgentLimits(
            max_output_tokens=128,
            model_turn_timeout=timedelta(seconds=1),
        ),
        created_at=now,
        deadline=now + timedelta(minutes=2),
    )

    try:
        result = await loop.run(run, _context())
    finally:
        await service.stop(runtime_context)

    assert result.status is AgentRunStatus.FAILED
    assert result.error_code == "timeout"
    assert result.model_turns == 1
    assert result.tool_calls == 0
    assert tool_authorizer.requests == []
    assert len(connector.calls) == 1
    assert connector.connections[0].closed is True


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "model_output",
    (
        "not-json",
        '{"version":1,"kind":"final","content":"one","content":"two"}',
        '{"version":1,"kind":"final"}',
    ),
)
async def test_real_ollama_malformed_result_fails_closed_before_tool_authorization(
    model_output: str,
) -> None:
    connector = _FakeConnector((_chat_response(model_output),))
    service, _runtime_authorizer = _service(connector)
    runtime_context = RuntimeContext(services={"inference": service})
    await service.start(runtime_context)

    tool_authorizer = _RecordingToolAuthorizer()
    loop = AgentLoop(
        run_authorizer=_AllowRunAuthorizer(),
        model_authorizer=_RecordingInferenceAuthorizer(),
        tool_authorizer=tool_authorizer,
        model_adapter=InferenceBackedAgentModelTurnAdapter(service),
        registry=ToolRegistry(),
    )
    now = datetime.now(UTC)
    run = AgentRunRequest(
        agent_id=AgentId("assistant"),
        provider_id=OLLAMA_PROVIDER_ID,
        model_id=ModelId("qwen3-coder-30b"),
        messages=(AgentMessage(AgentMessageRole.USER, "return one envelope"),),
        limits=AgentLimits(max_output_tokens=128),
        created_at=now,
        deadline=now + timedelta(minutes=2),
    )

    try:
        result = await loop.run(run, _context())
    finally:
        await service.stop(runtime_context)

    assert result.status is AgentRunStatus.FAILED
    assert result.error_code == "malformed_proposal"
    assert result.model_turns == 1
    assert result.tool_calls == 0
    assert tool_authorizer.requests == []
    assert len(connector.calls) == 1
    assert connector.connections[0].closed is True


@pytest.mark.asyncio
async def test_real_ollama_accumulated_provider_usage_enforces_agent_token_budget() -> None:
    connector = _FakeConnector(
        (
            _chat_response(
                '{"version":1,"kind":"tool","tool":"lookup","arguments":{"key":"alpha"}}',
                input_tokens=4,
                output_tokens=2,
            ),
            _chat_response(
                '{"version":1,"kind":"final","content":"not returned"}',
                input_tokens=4,
                output_tokens=2,
            ),
        )
    )
    service, runtime_authorizer = _service(connector)
    runtime_context = RuntimeContext(services={"inference": service})
    await service.start(runtime_context)

    descriptor = _tool_descriptor()
    tool_registry = ToolRegistry()
    tool_registry.register_tool(
        descriptor,
        resolver=StaticToolResourceResolver(
            resolver_id="static-resource",
            resource="lookup:alpha",
        ),
        adapter=DeterministicReadOnlyTool("lookup", {"key": "value"}),
    )
    model_authorizer = _RecordingInferenceAuthorizer()
    tool_authorizer = _RecordingToolAuthorizer()
    loop = AgentLoop(
        run_authorizer=_AllowRunAuthorizer(),
        model_authorizer=model_authorizer,
        tool_authorizer=tool_authorizer,
        model_adapter=InferenceBackedAgentModelTurnAdapter(service),
        registry=tool_registry,
    )
    now = datetime.now(UTC)
    run = AgentRunRequest(
        agent_id=AgentId("assistant"),
        provider_id=OLLAMA_PROVIDER_ID,
        model_id=ModelId("qwen3-coder-30b"),
        messages=(AgentMessage(AgentMessageRole.USER, "use lookup then finish"),),
        limits=AgentLimits(
            max_model_turns=4,
            max_tool_calls=2,
            max_input_tokens=6,
            max_output_tokens=128,
        ),
        created_at=now,
        deadline=now + timedelta(minutes=2),
    )

    try:
        result = await loop.run(run, _context())
    finally:
        await service.stop(runtime_context)

    assert result.status is AgentRunStatus.FAILED
    assert result.error_code == "limit_exceeded"
    assert result.final_output is None
    assert result.model_turns == 2
    assert result.tool_calls == 1
    assert len(connector.calls) == 2
    assert len(model_authorizer.requests) == 4
    assert len(runtime_authorizer.requests) == 2
    assert len(tool_authorizer.requests) == 2
    assert all(connection.closed for connection in connector.connections)


@pytest.mark.asyncio
async def test_real_ollama_final_output_bytes_enforce_agent_model_output_budget() -> None:
    connector = _FakeConnector(
        (_chat_response('{"version":1,"kind":"final","content":"too-long"}'),)
    )
    service, _runtime_authorizer = _service(connector)
    runtime_context = RuntimeContext(services={"inference": service})
    await service.start(runtime_context)

    loop = AgentLoop(
        run_authorizer=_AllowRunAuthorizer(),
        model_authorizer=_RecordingInferenceAuthorizer(),
        tool_authorizer=_RecordingToolAuthorizer(),
        model_adapter=InferenceBackedAgentModelTurnAdapter(service),
        registry=ToolRegistry(),
    )
    now = datetime.now(UTC)
    run = AgentRunRequest(
        agent_id=AgentId("assistant"),
        provider_id=OLLAMA_PROVIDER_ID,
        model_id=ModelId("qwen3-coder-30b"),
        messages=(AgentMessage(AgentMessageRole.USER, "return final"),),
        limits=AgentLimits(
            max_model_output_bytes=4,
            max_output_tokens=128,
        ),
        created_at=now,
        deadline=now + timedelta(minutes=2),
    )

    try:
        result = await loop.run(run, _context())
    finally:
        await service.stop(runtime_context)

    assert result.status is AgentRunStatus.FAILED
    assert result.error_code == "limit_exceeded"
    assert result.final_output is None
    assert result.model_turns == 1
    assert result.tool_calls == 0
    assert len(connector.calls) == 1
    assert connector.connections[0].closed is True
