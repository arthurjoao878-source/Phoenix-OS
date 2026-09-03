from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta
from typing import Any, cast

import pytest

from phoenix_os.events import EventBus
from phoenix_os.inference import (
    InferenceConfigurationBoundProvider,
    InferenceFinishReason,
    InferenceLimitExceededError,
    InferenceLimits,
    InferenceMalformedOutputError,
    InferenceMessage,
    InferenceProviderConfiguration,
    InferenceRequest,
    InferenceRole,
    InferenceServiceConfiguration,
    InferenceTimeoutError,
    ModelCapabilities,
    ModelCredentialPolicy,
    ModelDescriptor,
    ModelEndpointMode,
    ModelEndpointPolicy,
    ModelId,
    ModelProviderExecutionError,
    ModelProviderId,
    create_inference_runtime_stack,
)
from phoenix_os.inference.ollama import (
    OLLAMA_PROVIDER_ID,
    OllamaModelAvailability,
    OllamaModelBinding,
    OllamaModelDiagnosticCause,
    OllamaModelProvider,
    OllamaTransportLimits,
)
from phoenix_os.policy import PolicyEngine
from phoenix_os.secrets import SecretRef


class _FakeConnection:
    def __init__(
        self,
        response: bytes,
        *,
        read_limit: int,
        feed_eof: bool = True,
    ) -> None:
        self._reader = asyncio.StreamReader(limit=read_limit)
        self._reader.feed_data(response)
        if feed_eof:
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
        failures: tuple[BaseException | None, ...] = (),
        hang: bool = False,
    ) -> None:
        self._responses = list(responses)
        self._failures = list(failures)
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
        if self._failures:
            failure = self._failures.pop(0)
            if failure is not None:
                raise failure
        if self._hang:
            connection = _FakeConnection(
                b"",
                read_limit=read_limit,
                feed_eof=False,
            )
            self.connections.append(connection)
            return connection
        if not self._responses:
            raise AssertionError("fake Ollama connector has no response")
        connection = _FakeConnection(self._responses.pop(0), read_limit=read_limit)
        self.connections.append(connection)
        return connection


def _endpoint(
    url: str = "http://127.0.0.1:11434/",
    *,
    mode: ModelEndpointMode = ModelEndpointMode.LOOPBACK_HTTP,
    port: int = 11_434,
) -> ModelEndpointPolicy:
    return ModelEndpointPolicy(
        url,
        mode=mode,
        allowed_ports=frozenset({port}),
    )


def _descriptor(
    *,
    model_id: str = "qwen3-coder-30b",
    provider_model_name: str = "qwen3-coder:30b",
) -> ModelDescriptor:
    return ModelDescriptor(
        provider_id=OLLAMA_PROVIDER_ID,
        model_id=ModelId(model_id),
        provider_model_name=provider_model_name,
        capabilities=ModelCapabilities(complete=True, streaming=True),
        limits=InferenceLimits(
            max_output_tokens=128,
            max_response_chars=16_384,
        ),
    )


def _configuration(
    *,
    endpoint: ModelEndpointPolicy | None = None,
    credential: ModelCredentialPolicy | None = None,
    provider_id: ModelProviderId = OLLAMA_PROVIDER_ID,
) -> InferenceProviderConfiguration:
    return InferenceProviderConfiguration(
        provider_id,
        endpoint_policy=_endpoint() if endpoint is None else endpoint,
        credential_policy=credential,
    )


def _service_configuration(
    provider_configuration: InferenceProviderConfiguration,
    descriptor: ModelDescriptor,
) -> InferenceServiceConfiguration:
    return InferenceServiceConfiguration(
        providers=(provider_configuration,),
        models=(descriptor,),
    )


def _provider(
    connector: _FakeConnector,
    *,
    descriptor: ModelDescriptor | None = None,
    expected_digest: str | None = None,
    structured_json: bool = False,
    transport_limits: OllamaTransportLimits | None = None,
) -> OllamaModelProvider:
    binding = OllamaModelBinding(
        _descriptor() if descriptor is None else descriptor,
        expected_digest=expected_digest,
        structured_json=structured_json,
    )
    return OllamaModelProvider(
        _configuration(),
        (binding,),
        transport_limits=transport_limits,
        _connector=connector,
    )


def _request(
    *,
    model_id: str = "qwen3-coder-30b",
    parameters: dict[str, object] | None = None,
    max_output_tokens: int = 32,
) -> InferenceRequest:
    now = datetime.now(UTC)
    return InferenceRequest(
        provider_id=OLLAMA_PROVIDER_ID,
        model_id=ModelId(model_id),
        messages=(
            InferenceMessage(InferenceRole.SYSTEM, "answer using the contract"),
            InferenceMessage(InferenceRole.USER, "hello"),
        ),
        max_output_tokens=max_output_tokens,
        parameters={} if parameters is None else cast(Any, parameters),
        created_at=now,
        deadline=now + timedelta(seconds=30),
    )


def _json_body(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":")).encode("utf-8")


def _http_response(
    status: int,
    reason: str,
    *,
    body: bytes = b"",
    headers: tuple[tuple[str, str], ...] | None = None,
) -> bytes:
    selected = (
        (("Content-Type", "application/json"), ("Content-Length", str(len(body))))
        if headers is None
        else headers
    )
    lines = [f"HTTP/1.1 {status} {reason}".encode("ascii")]
    lines.extend(f"{name}: {value}".encode("ascii") for name, value in selected)
    return b"\r\n".join((*lines, b"", body))


def _chat_document(
    *,
    model: str = "qwen3-coder:30b",
    content: str = "hello from ollama",
    done: bool = True,
    done_reason: str = "stop",
    input_tokens: int = 7,
    output_tokens: int = 4,
    message_changes: dict[str, object] | None = None,
) -> dict[str, object]:
    message: dict[str, object] = {
        "role": "assistant",
        "content": content,
    }
    if message_changes:
        message.update(message_changes)
    return {
        "model": model,
        "created_at": "2026-08-31T00:00:00Z",
        "message": message,
        "done": done,
        "done_reason": done_reason,
        "total_duration": 100,
        "load_duration": 10,
        "prompt_eval_count": input_tokens,
        "prompt_eval_duration": 20,
        "eval_count": output_tokens,
        "eval_duration": 30,
    }


def _tags_document(
    *,
    native_name: str = "qwen3-coder:30b",
    digest: str = "a" * 64,
    include_configured: bool = True,
    include_extra: bool = False,
) -> dict[str, object]:
    models: list[dict[str, object]] = []
    if include_configured:
        models.append(
            {
                "name": native_name,
                "model": native_name,
                "modified_at": "2026-08-31T00:00:00Z",
                "size": 123,
                "digest": digest,
                "details": {"format": "gguf"},
            }
        )
    if include_extra:
        models.append(
            {
                "name": "unreviewed:latest",
                "model": "unreviewed:latest",
                "modified_at": "2026-08-31T00:00:00Z",
                "size": 456,
                "digest": "b" * 64,
                "details": {"format": "gguf"},
            }
        )
    return {"models": models}


def _stream_document(
    *,
    content: str,
    done: bool,
    model: str = "qwen3-coder:30b",
    done_reason: str = "stop",
    input_tokens: int = 7,
    output_tokens: int = 4,
    message_changes: dict[str, object] | None = None,
) -> dict[str, object]:
    message: dict[str, object] = {
        "role": "assistant",
        "content": content,
    }
    if message_changes:
        message.update(message_changes)

    document: dict[str, object] = {
        "model": model,
        "created_at": "2026-08-31T00:00:00Z",
        "message": message,
        "done": done,
    }
    if done:
        document["done_reason"] = done_reason
        document["prompt_eval_count"] = input_tokens
        document["eval_count"] = output_tokens
    return document


def _ndjson(*documents: dict[str, object]) -> bytes:
    return b"".join(_json_body(document) + b"\n" for document in documents)


def _chunked_http_response(*chunks: bytes) -> bytes:
    encoded_chunks = [f"{len(chunk):X}\r\n".encode("ascii") + chunk + b"\r\n" for chunk in chunks]
    return (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: application/x-ndjson\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"\r\n" + b"".join(encoded_chunks) + b"0\r\n\r\n"
    )


class _ScriptedServerConnection:
    def __init__(
        self,
        response_parts: tuple[bytes, ...],
        *,
        read_limit: int,
    ) -> None:
        self._reader = asyncio.StreamReader(limit=read_limit)
        self._response_parts = response_parts
        self._feeder: asyncio.Task[None] | None = None
        self.written = bytearray()
        self.closed = False

    @property
    def reader(self) -> asyncio.StreamReader:
        return self._reader

    def write(self, data: bytes) -> None:
        self.written.extend(data)

    async def drain(self) -> None:
        if self._feeder is None:
            self._feeder = asyncio.create_task(self._feed_response())
        await asyncio.sleep(0)

    async def _feed_response(self) -> None:
        for part in self._response_parts:
            self._reader.feed_data(part)
            await asyncio.sleep(0)
        self._reader.feed_eof()

    def close(self) -> None:
        self.closed = True
        if self._feeder is None:
            self._reader.feed_eof()

    async def wait_closed(self) -> None:
        if self._feeder is not None:
            await self._feeder


class _ScriptedServerConnector:
    def __init__(self, response_parts: tuple[bytes, ...]) -> None:
        self._response_parts = response_parts
        self.calls: list[tuple[str, int, float, int]] = []
        self.connections: list[_ScriptedServerConnection] = []

    async def connect(
        self,
        address: str,
        port: int,
        *,
        connect_timeout: float,
        read_limit: int,
    ) -> _ScriptedServerConnection:
        self.calls.append((address, port, connect_timeout, read_limit))
        connection = _ScriptedServerConnection(
            self._response_parts,
            read_limit=read_limit,
        )
        self.connections.append(connection)
        return connection


def _written_body(
    connection: _FakeConnection | _ScriptedServerConnection,
) -> dict[str, object]:
    raw = bytes(connection.written)
    _head, body = raw.split(b"\r\n\r\n", 1)
    decoded = json.loads(body.decode("utf-8"))
    assert isinstance(decoded, dict)
    return cast(dict[str, object], decoded)


def test_provider_requires_exact_reviewed_loopback_endpoint_and_no_credentials() -> None:
    connector = _FakeConnector()
    provider = _provider(connector)
    assert provider.provider_id == OLLAMA_PROVIDER_ID
    assert provider.capabilities == ModelCapabilities(complete=True, streaming=True)

    invalid_configurations = (
        _configuration(
            endpoint=_endpoint(
                "http://localhost:11434/",
            )
        ),
        _configuration(
            endpoint=_endpoint(
                "http://127.0.0.1:11435/",
                port=11_435,
            )
        ),
        _configuration(
            endpoint=ModelEndpointPolicy("https://127.0.0.1:443/"),
        ),
        _configuration(
            credential=ModelCredentialPolicy(
                SecretRef("ollama-secret", namespace="inference", version=1)
            )
        ),
        _configuration(provider_id=ModelProviderId("other")),
    )

    for configuration in invalid_configurations:
        with pytest.raises(ValueError):
            OllamaModelProvider(
                configuration,
                (OllamaModelBinding(_descriptor()),),
                _connector=connector,
            )


def test_binding_is_immutable_provider_scoped_and_digest_bounded() -> None:
    binding = OllamaModelBinding(_descriptor(), expected_digest="A" * 64)

    assert binding.expected_digest == "a" * 64
    assert binding.descriptor.model_id == ModelId("qwen3-coder-30b")
    assert binding.structured_json is False

    structured = OllamaModelBinding(_descriptor(), structured_json=True)
    assert structured.structured_json is True

    with pytest.raises(TypeError, match="structured_json"):
        OllamaModelBinding(_descriptor(), structured_json=cast(Any, 1))

    with pytest.raises(ValueError, match="64-character"):
        OllamaModelBinding(_descriptor(), expected_digest="not-a-digest")

    wrong = ModelDescriptor(
        provider_id=ModelProviderId("other"),
        model_id=ModelId("chat"),
        provider_model_name="chat",
    )
    with pytest.raises(ValueError, match="ollama-local"):
        OllamaModelBinding(wrong)


def test_composition_accepts_exact_ollama_configuration_binding() -> None:
    provider_configuration = _configuration()
    descriptor = _descriptor()
    provider = OllamaModelProvider(
        provider_configuration,
        (OllamaModelBinding(descriptor),),
        _connector=_FakeConnector(),
    )

    assert isinstance(provider, InferenceConfigurationBoundProvider)

    stack = create_inference_runtime_stack(
        configuration=_service_configuration(provider_configuration, descriptor),
        providers=(provider,),
        policy=PolicyEngine(()),
        events=EventBus(),
    )
    try:
        assert stack.registry.resolve_model(OLLAMA_PROVIDER_ID, descriptor.model_id) is descriptor
    finally:
        stack.registry.close()


def test_composition_rejects_ollama_provider_configuration_drift() -> None:
    provider_configuration = _configuration()
    descriptor = _descriptor()
    provider = OllamaModelProvider(
        provider_configuration,
        (OllamaModelBinding(descriptor),),
        _connector=_FakeConnector(),
    )
    mismatched_configuration = InferenceProviderConfiguration(OLLAMA_PROVIDER_ID)

    with pytest.raises(ValueError, match="provider configuration mismatch"):
        create_inference_runtime_stack(
            configuration=_service_configuration(
                mismatched_configuration,
                descriptor,
            ),
            providers=(provider,),
            policy=PolicyEngine(()),
            events=EventBus(),
        )


def test_composition_rejects_ollama_model_descriptor_drift() -> None:
    provider_configuration = _configuration()
    configured_descriptor = _descriptor()
    provider_descriptor = _descriptor(provider_model_name="qwen3-coder:other")
    provider = OllamaModelProvider(
        provider_configuration,
        (OllamaModelBinding(provider_descriptor),),
        _connector=_FakeConnector(),
    )

    with pytest.raises(ValueError, match="model descriptor mismatch"):
        create_inference_runtime_stack(
            configuration=_service_configuration(
                provider_configuration,
                configured_descriptor,
            ),
            providers=(provider,),
            policy=PolicyEngine(()),
            events=EventBus(),
        )


@pytest.mark.asyncio
async def test_complete_translation_uses_exact_native_model_and_bounded_options() -> None:
    response = _http_response(200, "OK", body=_json_body(_chat_document()))
    connector = _FakeConnector((response,))
    provider = _provider(connector)
    request = _request(max_output_tokens=17)

    result = await provider.infer(request)

    assert result.request_id == request.request_id
    assert result.provider_id == request.provider_id
    assert result.model_id == request.model_id
    assert result.text == "hello from ollama"
    assert result.finish_reason is InferenceFinishReason.STOP
    assert result.usage.input_tokens == 7
    assert result.usage.output_tokens == 4

    assert len(connector.calls) == 1
    assert connector.calls[0][0:2] == ("127.0.0.1", 11_434)
    written = bytes(connector.connections[0].written)
    assert written.startswith(b"POST /api/chat HTTP/1.1\r\n")
    assert b"Host: 127.0.0.1:11434\r\n" in written
    assert b"Accept-Encoding: identity\r\n" in written
    assert b"Connection: close\r\n" in written

    assert _written_body(connector.connections[0]) == {
        "model": "qwen3-coder:30b",
        "messages": [
            {"role": "system", "content": "answer using the contract"},
            {"role": "user", "content": "hello"},
        ],
        "options": {"num_predict": 17},
        "stream": False,
        "think": False,
    }
    assert connector.connections[0].closed is True


@pytest.mark.asyncio
async def test_complete_structured_json_mode_is_binding_owned_and_explicit() -> None:
    response = _http_response(200, "OK", body=_json_body(_chat_document()))
    connector = _FakeConnector((response,))
    provider = _provider(connector, structured_json=True)
    request = _request(max_output_tokens=17)

    result = await provider.infer(request)

    assert result.text == "hello from ollama"
    assert _written_body(connector.connections[0]) == {
        "model": "qwen3-coder:30b",
        "messages": [
            {"role": "system", "content": "answer using the contract"},
            {"role": "user", "content": "hello"},
        ],
        "options": {"num_predict": 17},
        "stream": False,
        "think": False,
        "format": "json",
    }


@pytest.mark.asyncio
async def test_complete_maps_length_and_rejects_output_usage_above_request_limit() -> None:
    length_response = _http_response(
        200,
        "OK",
        body=_json_body(_chat_document(done_reason="length", output_tokens=8)),
    )
    too_large_response = _http_response(
        200,
        "OK",
        body=_json_body(_chat_document(output_tokens=33)),
    )
    connector = _FakeConnector((length_response, too_large_response))
    provider = _provider(connector)

    result = await provider.infer(_request(max_output_tokens=8))
    assert result.finish_reason is InferenceFinishReason.LENGTH

    with pytest.raises(InferenceLimitExceededError):
        await provider.infer(_request(max_output_tokens=32))

    assert len(connector.calls) == 2


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "parameters",
    (
        {"temperature": 0.2},
        {"format": "json"},
    ),
)
async def test_unreviewed_request_parameters_fail_before_transport(
    parameters: dict[str, object],
) -> None:
    connector = _FakeConnector()
    provider = _provider(connector)

    with pytest.raises(ModelProviderExecutionError):
        await provider.infer(_request(parameters=parameters))

    assert connector.calls == []


@pytest.mark.asyncio
async def test_unknown_phoenix_model_fails_before_transport() -> None:
    connector = _FakeConnector()
    provider = _provider(connector)

    with pytest.raises(ModelProviderExecutionError):
        await provider.infer(_request(model_id="unconfigured"))

    assert connector.calls == []


@pytest.mark.asyncio
async def test_complete_provider_error_property_fails_without_exposing_message() -> None:
    document = _chat_document()
    document["error"] = "private provider failure"
    connector = _FakeConnector((_http_response(200, "OK", body=_json_body(document)),))
    provider = _provider(connector)

    with pytest.raises(ModelProviderExecutionError) as captured:
        await provider.infer(_request())

    assert "private provider failure" not in str(captured.value)
    assert len(connector.calls) == 1


@pytest.mark.asyncio
async def test_complete_connection_failure_is_generic_and_not_retried() -> None:
    connector = _FakeConnector(failures=(OSError("private socket failure"),))
    provider = _provider(connector)

    with pytest.raises(ModelProviderExecutionError) as captured:
        await provider.infer(_request())

    assert "private socket failure" not in str(captured.value)
    assert len(connector.calls) == 1
    assert connector.connections == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "body",
    [
        b'{"model":"qwen3-coder:30b","model":"other","done":true}',
        _json_body(_chat_document(done=False)),
        _json_body(_chat_document(model="other:latest")),
        _json_body(_chat_document(done_reason="unknown")),
        _json_body(_chat_document(message_changes={"thinking": "private reasoning"})),
        _json_body(
            _chat_document(
                message_changes={"tool_calls": [{"function": {"name": "shell", "arguments": {}}}]}
            )
        ),
    ],
)
async def test_complete_rejects_malformed_or_unreviewed_native_results(body: bytes) -> None:
    connector = _FakeConnector((_http_response(200, "OK", body=body),))
    provider = _provider(connector)

    with pytest.raises(InferenceMalformedOutputError):
        await provider.infer(_request())

    assert len(connector.calls) == 1


@pytest.mark.asyncio
async def test_complete_response_body_limit_fails_closed() -> None:
    body = _json_body(_chat_document(content="x" * 256))
    connector = _FakeConnector((_http_response(200, "OK", body=body),))
    provider = _provider(
        connector,
        transport_limits=OllamaTransportLimits(max_response_bytes=64),
    )

    with pytest.raises(InferenceLimitExceededError):
        await provider.infer(_request())

    assert len(connector.calls) == 1


@pytest.mark.asyncio
async def test_request_limit_bounds_complete_http_request_not_only_json_body() -> None:
    connector = _FakeConnector()
    provider = _provider(
        connector,
        transport_limits=OllamaTransportLimits(max_request_bytes=250),
    )
    expected_body = _json_body(
        {
            "model": "qwen3-coder:30b",
            "messages": [
                {"role": "system", "content": "answer using the contract"},
                {"role": "user", "content": "hello"},
            ],
            "options": {"num_predict": 32},
            "stream": False,
            "think": False,
        }
    )
    assert len(expected_body) < 250

    with pytest.raises(InferenceLimitExceededError):
        await provider.infer(_request())

    assert connector.calls == []


@pytest.mark.asyncio
async def test_complete_read_timeout_is_finite_and_closes_connection() -> None:
    connector = _FakeConnector(hang=True)
    provider = _provider(
        connector,
        transport_limits=OllamaTransportLimits(
            connect_timeout_seconds=0.05,
            read_timeout_seconds=0.01,
            total_timeout_seconds=0.1,
        ),
    )

    with pytest.raises(InferenceTimeoutError):
        await provider.infer(_request())

    assert len(connector.calls) == 1
    assert connector.connections[0].closed is True


@pytest.mark.asyncio
async def test_empty_complete_body_is_malformed_output() -> None:
    connector = _FakeConnector((_http_response(200, "OK", body=b""),))
    provider = _provider(connector)

    with pytest.raises(InferenceMalformedOutputError):
        await provider.infer(_request())

    assert len(connector.calls) == 1


@pytest.mark.asyncio
async def test_truncated_complete_body_is_malformed_output() -> None:
    connector = _FakeConnector(
        (
            _http_response(
                200,
                "OK",
                headers=(("Content-Length", "10"),),
                body=b"{}",
            ),
        )
    )
    provider = _provider(connector)

    with pytest.raises(InferenceMalformedOutputError):
        await provider.infer(_request())

    assert len(connector.calls) == 1


@pytest.mark.asyncio
async def test_response_status_line_control_bytes_fail_closed() -> None:
    response = b"HTTP/1.1 200 OK\x00BAD\r\nContent-Length: 0\r\n\r\n"
    connector = _FakeConnector((response,))
    provider = _provider(connector)

    with pytest.raises(InferenceMalformedOutputError):
        await provider.infer(_request())

    assert len(connector.calls) == 1


@pytest.mark.asyncio
async def test_redirect_is_never_followed() -> None:
    connector = _FakeConnector(
        (
            _http_response(
                302,
                "Found",
                headers=(("Location", "http://127.0.0.1:9999/admin"), ("Content-Length", "0")),
            ),
        )
    )
    provider = _provider(connector)

    with pytest.raises(ModelProviderExecutionError):
        await provider.infer(_request())

    assert len(connector.calls) == 1


@pytest.mark.asyncio
async def test_model_diagnostic_ignores_unconfigured_discovery_entries() -> None:
    connector = _FakeConnector(
        (
            _http_response(
                200,
                "OK",
                body=_json_body(_tags_document(include_extra=True)),
            ),
        )
    )
    provider = _provider(connector, expected_digest="a" * 64)

    diagnostic = await provider.diagnose_model(ModelId("qwen3-coder-30b"))

    assert diagnostic.status is OllamaModelAvailability.AVAILABLE
    assert diagnostic.cause is OllamaModelDiagnosticCause.NONE
    assert len(connector.calls) == 1
    written = bytes(connector.connections[0].written)
    assert written.startswith(b"GET /api/tags HTTP/1.1\r\n")
    assert "unreviewed" not in repr(diagnostic)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("document", "expected_digest", "status"),
    [
        (
            _tags_document(include_configured=False),
            None,
            OllamaModelAvailability.UNAVAILABLE,
        ),
        (
            _tags_document(digest="b" * 64),
            "a" * 64,
            OllamaModelAvailability.REVISION_MISMATCH,
        ),
    ],
)
async def test_model_diagnostic_reports_missing_or_revision_mismatch(
    document: dict[str, object],
    expected_digest: str | None,
    status: OllamaModelAvailability,
) -> None:
    connector = _FakeConnector((_http_response(200, "OK", body=_json_body(document)),))
    provider = _provider(connector, expected_digest=expected_digest)

    diagnostic = await provider.diagnose_model(ModelId("qwen3-coder-30b"))

    assert diagnostic.status is status
    expected_cause = {
        OllamaModelAvailability.UNAVAILABLE: OllamaModelDiagnosticCause.MODEL_UNAVAILABLE,
        OllamaModelAvailability.REVISION_MISMATCH: (OllamaModelDiagnosticCause.REVISION_MISMATCH),
    }[status]
    assert diagnostic.cause is expected_cause


@pytest.mark.asyncio
async def test_provider_unreachable_is_content_free_diagnostic() -> None:
    connector = _FakeConnector(failures=(OSError("private socket detail"),))
    provider = _provider(connector)

    diagnostic = await provider.diagnose_model(ModelId("qwen3-coder-30b"))

    assert diagnostic.status is OllamaModelAvailability.PROVIDER_UNREACHABLE
    assert diagnostic.cause is OllamaModelDiagnosticCause.PROVIDER_UNREACHABLE
    assert "private" not in repr(diagnostic)


@pytest.mark.asyncio
async def test_provider_timeout_is_distinct_content_free_diagnostic_cause() -> None:
    connector = _FakeConnector(hang=True)
    provider = _provider(
        connector,
        transport_limits=OllamaTransportLimits(
            connect_timeout_seconds=0.05,
            read_timeout_seconds=0.01,
            total_timeout_seconds=0.1,
        ),
    )

    diagnostic = await provider.diagnose_model(ModelId("qwen3-coder-30b"))

    assert diagnostic.status is OllamaModelAvailability.PROVIDER_UNREACHABLE
    assert diagnostic.cause is OllamaModelDiagnosticCause.PROVIDER_TIMEOUT
    assert len(connector.calls) == 1
    assert connector.connections[0].closed is True


@pytest.mark.asyncio
async def test_expected_digest_mismatch_blocks_chat_before_inference_request() -> None:
    connector = _FakeConnector(
        (
            _http_response(
                200,
                "OK",
                body=_json_body(_tags_document(digest="b" * 64)),
            ),
        )
    )
    provider = _provider(connector, expected_digest="a" * 64)

    with pytest.raises(ModelProviderExecutionError):
        await provider.infer(_request())

    assert len(connector.calls) == 1
    assert bytes(connector.connections[0].written).startswith(b"GET /api/tags HTTP/1.1\r\n")


@pytest.mark.asyncio
async def test_stream_unreviewed_request_parameters_fail_before_transport() -> None:
    connector = _FakeConnector()
    provider = _provider(connector)

    with pytest.raises(ModelProviderExecutionError):
        async for _chunk in provider.stream(_request(parameters={"temperature": 0.2})):
            pass

    assert connector.calls == []


@pytest.mark.asyncio
async def test_stream_connection_failure_is_generic_and_not_retried() -> None:
    connector = _FakeConnector(failures=(OSError("private stream socket failure"),))
    provider = _provider(connector)

    with pytest.raises(ModelProviderExecutionError) as captured:
        async for _chunk in provider.stream(_request()):
            pass

    assert "private stream socket failure" not in str(captured.value)
    assert len(connector.calls) == 1
    assert connector.connections == []


@pytest.mark.asyncio
async def test_stream_provider_error_record_fails_without_exposing_message() -> None:
    body = _ndjson(
        _stream_document(content="partial", done=False),
        {"error": "private provider stream failure"},
    )
    connector = _FakeConnector((_http_response(200, "OK", body=body),))
    provider = _provider(connector)
    iterator = provider.stream(_request())

    first = await anext(iterator)
    assert first.text == "partial"

    with pytest.raises(ModelProviderExecutionError) as captured:
        await anext(iterator)

    assert "private provider stream failure" not in str(captured.value)
    assert connector.connections[0].closed is True


@pytest.mark.asyncio
async def test_streaming_translates_ordered_ndjson_and_terminal_usage() -> None:
    native = _ndjson(
        _stream_document(content="hel", done=False),
        _stream_document(content="lo", done=False),
        _stream_document(
            content="",
            done=True,
            done_reason="stop",
            input_tokens=9,
            output_tokens=2,
        ),
    )
    response = _chunked_http_response(
        native[:19],
        native[19:73],
        native[73:],
    )
    connector = _FakeConnector((response,))
    provider = _provider(connector)
    request = _request(max_output_tokens=8)

    chunks = [chunk async for chunk in provider.stream(request)]

    assert [chunk.index for chunk in chunks] == [0, 1, 2]
    assert [chunk.text for chunk in chunks] == ["hel", "lo", ""]
    assert [chunk.terminal for chunk in chunks] == [False, False, True]
    assert chunks[-1].finish_reason is InferenceFinishReason.STOP
    assert chunks[-1].usage is not None
    assert chunks[-1].usage.input_tokens == 9
    assert chunks[-1].usage.output_tokens == 2

    assert len(connector.calls) == 1
    written = bytes(connector.connections[0].written)
    assert written.startswith(b"POST /api/chat HTTP/1.1\r\n")
    assert _written_body(connector.connections[0]) == {
        "model": "qwen3-coder:30b",
        "messages": [
            {"role": "system", "content": "answer using the contract"},
            {"role": "user", "content": "hello"},
        ],
        "options": {"num_predict": 8},
        "stream": True,
        "think": False,
    }
    assert connector.connections[0].closed is True


@pytest.mark.asyncio
async def test_stream_structured_json_mode_is_binding_owned_and_explicit() -> None:
    body = _ndjson(
        _stream_document(
            content="done",
            done=True,
            input_tokens=5,
            output_tokens=1,
        )
    )
    connector = _FakeConnector((_http_response(200, "OK", body=body),))
    provider = _provider(connector, structured_json=True)

    chunks = [chunk async for chunk in provider.stream(_request(max_output_tokens=8))]

    assert len(chunks) == 1
    assert chunks[0].terminal is True
    assert _written_body(connector.connections[0]) == {
        "model": "qwen3-coder:30b",
        "messages": [
            {"role": "system", "content": "answer using the contract"},
            {"role": "user", "content": "hello"},
        ],
        "options": {"num_predict": 8},
        "stream": True,
        "think": False,
        "format": "json",
    }


@pytest.mark.asyncio
async def test_scripted_fake_server_delivers_stream_incrementally() -> None:
    native = _ndjson(
        _stream_document(content="one", done=False),
        _stream_document(
            content="two",
            done=True,
            done_reason="length",
            input_tokens=5,
            output_tokens=2,
        ),
    )
    response = _chunked_http_response(native[:11], native[11:37], native[37:])
    response_parts = (
        response[:31],
        response[31:79],
        response[79:131],
        response[131:],
    )
    connector = _ScriptedServerConnector(response_parts)
    provider = OllamaModelProvider(
        _configuration(),
        (OllamaModelBinding(_descriptor()),),
        _connector=connector,
    )

    chunks = [chunk async for chunk in provider.stream(_request(max_output_tokens=4))]

    assert [chunk.text for chunk in chunks] == ["one", "two"]
    assert chunks[-1].terminal is True
    assert chunks[-1].finish_reason is InferenceFinishReason.LENGTH
    assert connector.calls[0][0:2] == ("127.0.0.1", 11_434)
    assert connector.connections[0].closed is True


@pytest.mark.asyncio
async def test_stream_ending_without_terminal_record_fails_closed() -> None:
    body = _ndjson(_stream_document(content="partial", done=False))
    connector = _FakeConnector((_http_response(200, "OK", body=body),))
    provider = _provider(connector)
    iterator = provider.stream(_request())

    first = await anext(iterator)
    assert first.text == "partial"
    assert first.terminal is False

    with pytest.raises(InferenceMalformedOutputError):
        await anext(iterator)

    assert connector.connections[0].closed is True


@pytest.mark.asyncio
async def test_stream_rejects_extra_record_after_terminal() -> None:
    body = _ndjson(
        _stream_document(content="done", done=True),
        _stream_document(content="extra", done=False),
    )
    connector = _FakeConnector((_http_response(200, "OK", body=body),))
    provider = _provider(connector)
    iterator = provider.stream(_request())

    terminal = await anext(iterator)
    assert terminal.terminal is True

    with pytest.raises(InferenceMalformedOutputError):
        await anext(iterator)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "document",
    [
        _stream_document(content="x", done=False, model="other:latest"),
        _stream_document(
            content="x",
            done=False,
            message_changes={"thinking": "private"},
        ),
        _stream_document(
            content="x",
            done=False,
            message_changes={"tool_calls": [{"function": {"name": "shell", "arguments": {}}}]},
        ),
        _stream_document(
            content="",
            done=True,
            done_reason="unknown",
        ),
        _stream_document(
            content="",
            done=True,
            output_tokens=33,
        ),
    ],
)
async def test_stream_malformed_native_records_fail_closed(
    document: dict[str, object],
) -> None:
    connector = _FakeConnector((_http_response(200, "OK", body=_ndjson(document)),))
    provider = _provider(connector)

    expected = (
        InferenceLimitExceededError
        if document.get("eval_count") == 33
        else InferenceMalformedOutputError
    )
    with pytest.raises(expected):
        async for _chunk in provider.stream(_request(max_output_tokens=32)):
            pass


@pytest.mark.asyncio
async def test_stream_duplicate_json_keys_fail_closed() -> None:
    duplicate = (
        b'{"model":"qwen3-coder:30b","model":"other","message":'
        b'{"role":"assistant","content":"x"},"done":false}\n'
    )
    connector = _FakeConnector((_http_response(200, "OK", body=duplicate),))
    provider = _provider(connector)

    with pytest.raises(InferenceMalformedOutputError):
        async for _chunk in provider.stream(_request()):
            pass


@pytest.mark.asyncio
async def test_stream_frame_limit_is_bounded_before_json_decoding() -> None:
    oversized = b"{" + (b"x" * 262_144) + b"}\n"
    connector = _FakeConnector((_http_response(200, "OK", body=oversized),))
    provider = _provider(connector)

    with pytest.raises(InferenceLimitExceededError):
        async for _chunk in provider.stream(_request()):
            pass


@pytest.mark.asyncio
async def test_stream_read_timeout_is_finite_and_closes_connection() -> None:
    connector = _FakeConnector(hang=True)
    provider = _provider(
        connector,
        transport_limits=OllamaTransportLimits(
            connect_timeout_seconds=0.05,
            read_timeout_seconds=0.01,
            total_timeout_seconds=0.1,
        ),
    )

    with pytest.raises(InferenceTimeoutError):
        async for _chunk in provider.stream(_request()):
            pass

    assert len(connector.calls) == 1
    assert connector.connections[0].closed is True


@pytest.mark.asyncio
async def test_stream_cancellation_closes_connection_without_retry() -> None:
    connector = _FakeConnector(hang=True)
    provider = _provider(
        connector,
        transport_limits=OllamaTransportLimits(
            connect_timeout_seconds=0.05,
            read_timeout_seconds=1.0,
            total_timeout_seconds=1.0,
        ),
    )
    iterator = provider.stream(_request())
    task = asyncio.ensure_future(anext(iterator))

    for _ in range(20):
        if connector.connections:
            break
        await asyncio.sleep(0)
    assert len(connector.connections) == 1

    task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await task

    assert len(connector.calls) == 1
    assert connector.connections[0].closed is True


@pytest.mark.asyncio
async def test_expected_digest_mismatch_blocks_stream_before_chat_request() -> None:
    connector = _FakeConnector(
        (
            _http_response(
                200,
                "OK",
                body=_json_body(_tags_document(digest="b" * 64)),
            ),
        )
    )
    provider = _provider(connector, expected_digest="a" * 64)

    with pytest.raises(ModelProviderExecutionError):
        async for _chunk in provider.stream(_request()):
            pass

    assert len(connector.calls) == 1
    assert bytes(connector.connections[0].written).startswith(b"GET /api/tags HTTP/1.1\r\n")
