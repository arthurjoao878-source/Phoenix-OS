from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta
from typing import Any, cast

import pytest

from phoenix_os.inference import (
    InferenceLimits,
    InferenceMessage,
    InferenceRequest,
    InferenceRole,
    ModelCapabilities,
    ModelDescriptor,
    ModelEndpointMode,
    ModelEndpointPolicy,
    ModelId,
)
from phoenix_os.inference.configuration import InferenceProviderConfiguration
from phoenix_os.inference.ollama import (
    OLLAMA_PROVIDER_ID,
    OllamaModelBinding,
    OllamaModelProvider,
)

_SCHEMA = json.dumps(
    {
        "type": "object",
        "properties": {
            "version": {"type": "integer", "enum": [1]},
            "kind": {"type": "string", "enum": ["final"]},
            "content": {"type": "string"},
        },
        "required": ["version", "kind", "content"],
        "additionalProperties": False,
    },
    separators=(",", ":"),
    sort_keys=True,
)


class _FakeConnection:
    def __init__(self, response: bytes, *, read_limit: int) -> None:
        self._reader = asyncio.StreamReader(limit=read_limit)
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
    def __init__(self, responses: tuple[bytes, ...]) -> None:
        self._responses = list(responses)
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
        if not self._responses:
            raise AssertionError("fake connector has no response")
        connection = _FakeConnection(
            self._responses.pop(0),
            read_limit=read_limit,
        )
        self.connections.append(connection)
        return connection


def _descriptor() -> ModelDescriptor:
    return ModelDescriptor(
        provider_id=OLLAMA_PROVIDER_ID,
        model_id=ModelId("qwen3-4b-instruct"),
        provider_model_name="qwen3:4b-instruct",
        capabilities=ModelCapabilities(complete=True, streaming=True),
        limits=InferenceLimits(
            max_output_tokens=128,
            max_response_chars=16_384,
        ),
    )


def _configuration() -> InferenceProviderConfiguration:
    return InferenceProviderConfiguration(
        OLLAMA_PROVIDER_ID,
        endpoint_policy=ModelEndpointPolicy(
            "http://127.0.0.1:11434/",
            mode=ModelEndpointMode.LOOPBACK_HTTP,
            allowed_ports=frozenset({11_434}),
        ),
    )


def _request() -> InferenceRequest:
    now = datetime.now(UTC)
    return InferenceRequest(
        provider_id=OLLAMA_PROVIDER_ID,
        model_id=ModelId("qwen3-4b-instruct"),
        messages=(
            InferenceMessage(
                InferenceRole.SYSTEM,
                "return the reviewed structured contract",
            ),
            InferenceMessage(InferenceRole.USER, "canary"),
        ),
        max_output_tokens=32,
        created_at=now,
        deadline=now + timedelta(seconds=30),
    )


def _chat_document(
    *,
    content: str = '{"version":1,"kind":"final","content":"ok"}',
) -> dict[str, object]:
    return {
        "model": "qwen3:4b-instruct",
        "created_at": "2026-09-01T00:00:00Z",
        "message": {"role": "assistant", "content": content},
        "done": True,
        "done_reason": "stop",
        "prompt_eval_count": 7,
        "eval_count": 4,
    }


def _stream_document(
    *,
    content: str = '{"version":1,"kind":"final","content":"ok"}',
) -> dict[str, object]:
    return {
        "model": "qwen3:4b-instruct",
        "created_at": "2026-09-01T00:00:00Z",
        "message": {"role": "assistant", "content": content},
        "done": True,
        "done_reason": "stop",
        "prompt_eval_count": 7,
        "eval_count": 4,
    }


def _json_bytes(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":")).encode()


def _http_response(body: bytes) -> bytes:
    return (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: application/json\r\n"
        + f"Content-Length: {len(body)}\r\n".encode("ascii")
        + b"\r\n"
        + body
    )


def _ndjson_http_response(value: object) -> bytes:
    body = _json_bytes(value) + b"\n"
    return (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: application/x-ndjson\r\n"
        + f"Content-Length: {len(body)}\r\n".encode("ascii")
        + b"\r\n"
        + body
    )


def _written_body(connection: _FakeConnection) -> dict[str, object]:
    raw = bytes(connection.written)
    _head, body = raw.split(b"\r\n\r\n", 1)
    decoded = json.loads(body.decode("utf-8"))
    assert isinstance(decoded, dict)
    return cast(dict[str, object], decoded)


def _provider(connector: _FakeConnector) -> OllamaModelProvider:
    return OllamaModelProvider(
        _configuration(),
        (
            OllamaModelBinding(
                _descriptor(),
                structured_json_schema=_SCHEMA,
            ),
        ),
        _connector=connector,
    )


def test_structured_schema_is_canonical_bounded_and_exclusive() -> None:
    descriptor = _descriptor()
    binding = OllamaModelBinding(
        descriptor,
        structured_json_schema=' { "type" : "object" } ',
    )

    assert binding.structured_json is False
    assert binding.structured_json_schema == '{"type":"object"}'

    with pytest.raises(TypeError, match="structured_json_schema"):
        OllamaModelBinding(
            descriptor,
            structured_json_schema=cast(Any, 1),
        )

    with pytest.raises(ValueError, match="JSON object"):
        OllamaModelBinding(
            descriptor,
            structured_json_schema="[]",
        )

    with pytest.raises(ValueError, match="invalid"):
        OllamaModelBinding(
            descriptor,
            structured_json_schema='{"type":"object","type":"array"}',
        )

    with pytest.raises(ValueError, match="mutually exclusive"):
        OllamaModelBinding(
            descriptor,
            structured_json=True,
            structured_json_schema=_SCHEMA,
        )


@pytest.mark.asyncio
async def test_complete_sends_binding_owned_schema_as_format_object() -> None:
    connector = _FakeConnector((_http_response(_json_bytes(_chat_document())),))
    provider = _provider(connector)

    result = await provider.infer(_request())

    assert result.text == '{"version":1,"kind":"final","content":"ok"}'
    assert len(connector.calls) == 1
    body = _written_body(connector.connections[0])
    assert body["format"] == json.loads(_SCHEMA)
    assert body["stream"] is False
    assert body["think"] is False
    assert body["options"] == {"num_predict": 32}
    assert connector.connections[0].closed is True


@pytest.mark.asyncio
async def test_stream_sends_binding_owned_schema_as_format_object() -> None:
    connector = _FakeConnector((_ndjson_http_response(_stream_document()),))
    provider = _provider(connector)

    chunks = [chunk async for chunk in provider.stream(_request())]

    assert len(chunks) == 1
    assert chunks[0].terminal is True
    body = _written_body(connector.connections[0])
    assert body["format"] == json.loads(_SCHEMA)
    assert body["stream"] is True
    assert body["think"] is False
    assert body["options"] == {"num_predict": 32}
    assert connector.connections[0].closed is True
