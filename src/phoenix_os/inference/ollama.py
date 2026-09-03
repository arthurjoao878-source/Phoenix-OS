"""Reviewed dependency-free Ollama loopback provider for RFC-0038."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import math
import re
import socket
from collections.abc import AsyncGenerator, AsyncIterator, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol, cast

from phoenix_os.inference.configuration import InferenceProviderConfiguration
from phoenix_os.inference.contracts import (
    MAX_INFERENCE_PROVIDER_MODEL_NAME_LENGTH,
    InferenceChunk,
    InferenceFinishReason,
    InferenceRequest,
    InferenceResponse,
    InferenceUsage,
    ModelCapabilities,
    ModelDescriptor,
    ModelId,
    ModelProviderId,
)
from phoenix_os.inference.endpoints import (
    ModelEndpointMode,
    ResolvedModelEndpoint,
    admit_model_endpoint,
)
from phoenix_os.inference.errors import (
    InferenceError,
    InferenceLimitExceededError,
    InferenceMalformedOutputError,
    InferenceTimeoutError,
    ModelProviderExecutionError,
)

OLLAMA_PROVIDER_ID = ModelProviderId("ollama-local")
OLLAMA_ENDPOINT_URL = "http://127.0.0.1:11434/"
OLLAMA_PORT = 11_434
OLLAMA_CHAT_TARGET = "/api/chat"
OLLAMA_TAGS_TARGET = "/api/tags"

MAX_OLLAMA_REQUEST_BYTES = 1_048_576
MAX_OLLAMA_RESPONSE_BYTES = 1_048_576
MAX_OLLAMA_REQUEST_HEADER_BYTES = 32_768
MAX_OLLAMA_RESPONSE_HEADER_BYTES = 32_768
MAX_OLLAMA_RESPONSE_HEADERS = 64
MAX_OLLAMA_RESPONSE_LINE_BYTES = 8_192
MAX_OLLAMA_JSON_DEPTH = 32
MAX_OLLAMA_JSON_ITEMS = 8_192
MAX_OLLAMA_STREAM_FRAME_BYTES = 262_144

_HEADER_NAME_PATTERN = re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")
_CHUNK_SIZE_PATTERN = re.compile(rb"[0-9A-Fa-f]+\Z")
_DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True, slots=True)
class OllamaTransportLimits:
    """Finite provider-local HTTP limits supplied only by trusted composition."""

    connect_timeout_seconds: float = 5.0
    read_timeout_seconds: float = 60.0
    total_timeout_seconds: float = 60.0
    max_request_bytes: int = MAX_OLLAMA_REQUEST_BYTES
    max_response_bytes: int = MAX_OLLAMA_RESPONSE_BYTES

    def __post_init__(self) -> None:
        for label, value in (
            ("connect_timeout_seconds", self.connect_timeout_seconds),
            ("read_timeout_seconds", self.read_timeout_seconds),
            ("total_timeout_seconds", self.total_timeout_seconds),
        ):
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise TypeError(f"{label} must be a number")
            if not math.isfinite(value) or value <= 0:
                raise ValueError(f"{label} must be finite and positive")
        if self.connect_timeout_seconds > self.total_timeout_seconds:
            raise ValueError("connect timeout cannot exceed total timeout")
        if self.read_timeout_seconds > self.total_timeout_seconds:
            raise ValueError("read timeout cannot exceed total timeout")
        for label, value, maximum in (
            ("max_request_bytes", self.max_request_bytes, MAX_OLLAMA_REQUEST_BYTES),
            ("max_response_bytes", self.max_response_bytes, MAX_OLLAMA_RESPONSE_BYTES),
        ):
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"{label} must be an integer")
            if value <= 0 or value > maximum:
                raise ValueError(f"{label} is outside the reviewed bound")


@dataclass(frozen=True, slots=True)
class OllamaModelBinding:
    """Immutable Phoenix-to-Ollama model binding and optional revision evidence."""

    descriptor: ModelDescriptor
    expected_digest: str | None = field(default=None, repr=False)
    structured_json: bool = False
    structured_json_schema: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.descriptor, ModelDescriptor):
            raise TypeError("descriptor must be ModelDescriptor")
        if self.descriptor.provider_id != OLLAMA_PROVIDER_ID:
            raise ValueError("Ollama model binding requires provider ollama-local")
        if not isinstance(self.structured_json, bool):
            raise TypeError("structured_json must be a boolean")
        schema = self.structured_json_schema
        if schema is not None:
            if not isinstance(schema, str):
                raise TypeError("structured_json_schema must be a string or None")
            if self.structured_json:
                raise ValueError(
                    "structured_json and structured_json_schema are mutually exclusive"
                )
            object.__setattr__(
                self,
                "structured_json_schema",
                _canonicalize_structured_json_schema(schema),
            )
        digest = self.expected_digest
        if digest is not None:
            if not isinstance(digest, str):
                raise TypeError("expected_digest must be a string or None")
            normalized = digest.strip().lower()
            if _DIGEST_PATTERN.fullmatch(normalized) is None:
                raise ValueError("expected_digest must be a 64-character hexadecimal digest")
            object.__setattr__(self, "expected_digest", normalized)


class OllamaModelAvailability(StrEnum):
    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"
    REVISION_MISMATCH = "revision_mismatch"
    PROVIDER_UNREACHABLE = "provider_unreachable"


class OllamaModelDiagnosticCause(StrEnum):
    NONE = "none"
    MODEL_UNAVAILABLE = "model_unavailable"
    REVISION_MISMATCH = "revision_mismatch"
    PROVIDER_UNREACHABLE = "provider_unreachable"
    PROVIDER_TIMEOUT = "provider_timeout"


@dataclass(frozen=True, slots=True)
class OllamaModelDiagnostic:
    """Content-free availability result for one already-configured Phoenix model."""

    provider_id: ModelProviderId
    model_id: ModelId
    status: OllamaModelAvailability
    cause: OllamaModelDiagnosticCause | None = None

    def __post_init__(self) -> None:
        if self.provider_id != OLLAMA_PROVIDER_ID:
            raise ValueError("Ollama diagnostic requires provider ollama-local")
        if not isinstance(self.model_id, ModelId):
            raise TypeError("model_id must be ModelId")

        status = OllamaModelAvailability(self.status)
        object.__setattr__(self, "status", status)

        cause = self.cause
        if cause is None:
            cause = {
                OllamaModelAvailability.AVAILABLE: OllamaModelDiagnosticCause.NONE,
                OllamaModelAvailability.UNAVAILABLE: (OllamaModelDiagnosticCause.MODEL_UNAVAILABLE),
                OllamaModelAvailability.REVISION_MISMATCH: (
                    OllamaModelDiagnosticCause.REVISION_MISMATCH
                ),
                OllamaModelAvailability.PROVIDER_UNREACHABLE: (
                    OllamaModelDiagnosticCause.PROVIDER_UNREACHABLE
                ),
            }[status]
        else:
            if not isinstance(cause, (str, OllamaModelDiagnosticCause)):
                raise TypeError("cause must be OllamaModelDiagnosticCause, string, or None")
            cause = OllamaModelDiagnosticCause(cause)

        allowed_causes = {
            OllamaModelAvailability.AVAILABLE: frozenset({OllamaModelDiagnosticCause.NONE}),
            OllamaModelAvailability.UNAVAILABLE: frozenset(
                {OllamaModelDiagnosticCause.MODEL_UNAVAILABLE}
            ),
            OllamaModelAvailability.REVISION_MISMATCH: frozenset(
                {OllamaModelDiagnosticCause.REVISION_MISMATCH}
            ),
            OllamaModelAvailability.PROVIDER_UNREACHABLE: frozenset(
                {
                    OllamaModelDiagnosticCause.PROVIDER_UNREACHABLE,
                    OllamaModelDiagnosticCause.PROVIDER_TIMEOUT,
                }
            ),
        }
        if cause not in allowed_causes[status]:
            raise ValueError("diagnostic cause is incompatible with diagnostic status")
        object.__setattr__(self, "cause", cause)


class _OllamaConnection(Protocol):
    @property
    def reader(self) -> asyncio.StreamReader: ...

    def write(self, data: bytes) -> None: ...

    async def drain(self) -> None: ...

    def close(self) -> None: ...

    async def wait_closed(self) -> None: ...


class _OllamaConnector(Protocol):
    async def connect(
        self,
        address: str,
        port: int,
        *,
        connect_timeout: float,
        read_limit: int,
    ) -> _OllamaConnection: ...


class _StreamOllamaConnection:
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self._reader = reader
        self._writer = writer

    @property
    def reader(self) -> asyncio.StreamReader:
        return self._reader

    def write(self, data: bytes) -> None:
        self._writer.write(data)

    async def drain(self) -> None:
        await self._writer.drain()

    def close(self) -> None:
        self._writer.close()

    async def wait_closed(self) -> None:
        await self._writer.wait_closed()


class _AsyncioOllamaConnector:
    """Connect only to an already-reviewed numeric loopback address."""

    async def connect(
        self,
        address: str,
        port: int,
        *,
        connect_timeout: float,
        read_limit: int,
    ) -> _OllamaConnection:
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError as exception:
            raise ModelProviderExecutionError() from exception
        if parsed.compressed != address or not parsed.is_loopback:
            raise ModelProviderExecutionError()
        if port != OLLAMA_PORT:
            raise ModelProviderExecutionError()

        family = socket.AF_INET if parsed.version == 4 else socket.AF_INET6
        created_socket = socket.socket(family, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        created_socket.setblocking(False)
        raw_socket: socket.socket | None = created_socket
        reader: asyncio.StreamReader | None = None
        writer: asyncio.StreamWriter | None = None
        sockaddr: tuple[str, int] | tuple[str, int, int, int]
        if parsed.version == 4:
            sockaddr = (address, port)
        else:
            sockaddr = (address, port, 0, 0)

        try:
            async with asyncio.timeout(connect_timeout):
                loop = asyncio.get_running_loop()
                if raw_socket is None:  # pragma: no cover - construction invariant
                    raise RuntimeError("Ollama connector socket is unavailable")
                await loop.sock_connect(raw_socket, sockaddr)
                reader, writer = await asyncio.open_connection(
                    sock=raw_socket,
                    limit=read_limit,
                )
                raw_socket = None
        except BaseException:
            if writer is not None:
                writer.close()
            if raw_socket is not None:
                raw_socket.close()
            raise

        if reader is None or writer is None:  # pragma: no cover - asyncio invariant
            raise ModelProviderExecutionError()
        return _StreamOllamaConnection(reader, writer)


@dataclass(frozen=True, slots=True)
class _HttpResponseHead:
    status_code: int
    headers: Mapping[str, str]


@dataclass(frozen=True, slots=True)
class _HttpResponse:
    status_code: int
    body: bytes


class _StreamingHttpBody:
    def __init__(
        self,
        reader: asyncio.StreamReader,
        headers: Mapping[str, str],
        *,
        maximum_body_bytes: int,
    ) -> None:
        transfer_encoding = headers.get("transfer-encoding")
        content_length = headers.get("content-length")
        if transfer_encoding is not None and content_length is not None:
            raise InferenceMalformedOutputError()
        if maximum_body_bytes <= 0:
            raise ValueError("maximum_body_bytes must be positive")

        self._reader = reader
        self._maximum = maximum_body_bytes
        self._total = 0
        self._done = False
        self._chunk_remaining = 0

        if transfer_encoding is not None:
            if transfer_encoding.lower() != "chunked":
                raise InferenceMalformedOutputError()
            self._mode = "chunked"
            self._content_remaining: int | None = None
            return

        if content_length is not None:
            if not content_length.isdigit() or (
                len(content_length) > 1 and content_length.startswith("0")
            ):
                raise InferenceMalformedOutputError()
            length = int(content_length)
            if length > maximum_body_bytes:
                raise InferenceLimitExceededError()
            self._mode = "length"
            self._content_remaining = length
            return

        self._mode = "eof"
        self._content_remaining = None

    async def read(self, maximum_bytes: int) -> bytes:
        if isinstance(maximum_bytes, bool) or not isinstance(maximum_bytes, int):
            raise TypeError("maximum_bytes must be an integer")
        if maximum_bytes <= 0:
            raise ValueError("maximum_bytes must be positive")
        if self._done:
            return b""

        if self._mode == "length":
            remaining = self._content_remaining
            if remaining is None:  # pragma: no cover - construction invariant
                raise RuntimeError("content length state is unavailable")
            if remaining == 0:
                self._done = True
                return b""
            size = min(maximum_bytes, remaining)
            data = await self._reader.readexactly(size)
            self._content_remaining = remaining - len(data)
            self._account(len(data))
            return data

        if self._mode == "eof":
            size = min(maximum_bytes, self._maximum - self._total + 1)
            data = await self._reader.read(size)
            if not data:
                self._done = True
                return b""
            self._account(len(data))
            return data

        return await self._read_chunked(maximum_bytes)

    async def _read_chunked(self, maximum_bytes: int) -> bytes:
        while self._chunk_remaining == 0:
            line = await _bounded_readline(self._reader, 128)
            raw_size = line[:-2]
            if b";" in raw_size or _CHUNK_SIZE_PATTERN.fullmatch(raw_size) is None:
                raise InferenceMalformedOutputError()
            size = int(raw_size, 16)
            if size == 0:
                trailer = await _bounded_readline(
                    self._reader,
                    MAX_OLLAMA_RESPONSE_LINE_BYTES,
                )
                if trailer != b"\r\n":
                    raise InferenceMalformedOutputError()
                self._done = True
                return b""
            if self._total + size > self._maximum:
                raise InferenceLimitExceededError()
            self._chunk_remaining = size

        size = min(maximum_bytes, self._chunk_remaining)
        data = await self._reader.readexactly(size)
        self._chunk_remaining -= len(data)
        self._account(len(data))
        if self._chunk_remaining == 0:
            if await self._reader.readexactly(2) != b"\r\n":
                raise InferenceMalformedOutputError()
        return data

    def _account(self, amount: int) -> None:
        self._total += amount
        if self._total > self._maximum:
            raise InferenceLimitExceededError()


class _NdjsonBodyReader:
    def __init__(
        self,
        body: _StreamingHttpBody,
        *,
        maximum_frame_bytes: int,
    ) -> None:
        if maximum_frame_bytes <= 0:
            raise ValueError("maximum_frame_bytes must be positive")
        self._body = body
        self._maximum_frame_bytes = maximum_frame_bytes
        self._buffer = bytearray()

    async def read_record(self) -> bytes | None:
        while True:
            newline = self._buffer.find(b"\n")
            if newline >= 0:
                if newline > self._maximum_frame_bytes:
                    raise InferenceLimitExceededError()
                raw = bytes(self._buffer[:newline])
                del self._buffer[: newline + 1]
                if raw.endswith(b"\r"):
                    raw = raw[:-1]
                if not raw:
                    raise InferenceMalformedOutputError()
                return raw

            if len(self._buffer) > self._maximum_frame_bytes:
                raise InferenceLimitExceededError()

            available = self._maximum_frame_bytes - len(self._buffer) + 1
            data = await self._body.read(min(8_192, available))
            if not data:
                if self._buffer:
                    raise InferenceMalformedOutputError()
                return None
            self._buffer.extend(data)


class _OllamaHttpTransport:
    """One-shot direct HTTP/1.1 transport with no proxy, redirect, DNS, or retry."""

    def __init__(
        self,
        endpoint: ResolvedModelEndpoint,
        limits: OllamaTransportLimits,
        connector: _OllamaConnector,
    ) -> None:
        if not isinstance(endpoint, ResolvedModelEndpoint):
            raise TypeError("endpoint must be ResolvedModelEndpoint")
        if endpoint.policy.mode is not ModelEndpointMode.LOOPBACK_HTTP:
            raise ValueError("Ollama transport requires LOOPBACK_HTTP")
        if endpoint.addresses != ("127.0.0.1",):
            raise ValueError("Ollama transport requires pinned 127.0.0.1")
        if not isinstance(limits, OllamaTransportLimits):
            raise TypeError("limits must be OllamaTransportLimits")
        self._endpoint = endpoint
        self._limits = limits
        self._connector = connector

    async def request(self, method: str, target: str, body: bytes = b"") -> bytes:
        request_bytes = _build_http_request(
            method,
            target,
            body,
            maximum_bytes=self._limits.max_request_bytes,
        )
        connection: _OllamaConnection | None = None
        try:
            async with asyncio.timeout(self._limits.total_timeout_seconds):
                connection = await self._connector.connect(
                    self._endpoint.addresses[0],
                    OLLAMA_PORT,
                    connect_timeout=self._limits.connect_timeout_seconds,
                    read_limit=MAX_OLLAMA_RESPONSE_LINE_BYTES + 2,
                )
                connection.write(request_bytes)
                await connection.drain()
                async with asyncio.timeout(self._limits.read_timeout_seconds):
                    response = await _read_http_response(
                        connection.reader,
                        maximum_body_bytes=self._limits.max_response_bytes,
                    )
        except asyncio.CancelledError:
            raise
        except InferenceError:
            raise
        except TimeoutError as exception:
            raise InferenceTimeoutError() from exception
        except asyncio.IncompleteReadError as exception:
            raise InferenceMalformedOutputError() from exception
        except OSError as exception:
            raise ModelProviderExecutionError() from exception
        except Exception as exception:
            raise ModelProviderExecutionError() from exception
        finally:
            if connection is not None:
                connection.close()
                try:
                    async with asyncio.timeout(self._limits.connect_timeout_seconds):
                        await connection.wait_closed()
                except (TimeoutError, OSError):
                    pass

        if response.status_code != 200:
            raise ModelProviderExecutionError()
        return response.body

    async def stream(
        self,
        method: str,
        target: str,
        body: bytes = b"",
    ) -> AsyncGenerator[bytes, None]:
        request_bytes = _build_http_request(
            method,
            target,
            body,
            maximum_bytes=self._limits.max_request_bytes,
        )
        connection: _OllamaConnection | None = None
        deadline = asyncio.get_running_loop().time() + self._limits.total_timeout_seconds
        try:
            connect_timeout = _remaining_transport_timeout(
                deadline,
                self._limits.connect_timeout_seconds,
            )
            async with asyncio.timeout(connect_timeout):
                connection = await self._connector.connect(
                    self._endpoint.addresses[0],
                    OLLAMA_PORT,
                    connect_timeout=connect_timeout,
                    read_limit=MAX_OLLAMA_RESPONSE_LINE_BYTES + 2,
                )

            write_timeout = _remaining_transport_timeout(
                deadline,
                self._limits.read_timeout_seconds,
            )
            async with asyncio.timeout(write_timeout):
                connection.write(request_bytes)
                await connection.drain()

            head_timeout = _remaining_transport_timeout(
                deadline,
                self._limits.read_timeout_seconds,
            )
            async with asyncio.timeout(head_timeout):
                head = await _read_http_response_head(connection.reader)
            if head.status_code != 200:
                raise ModelProviderExecutionError()

            body_reader = _StreamingHttpBody(
                connection.reader,
                head.headers,
                maximum_body_bytes=self._limits.max_response_bytes,
            )
            ndjson_reader = _NdjsonBodyReader(
                body_reader,
                maximum_frame_bytes=MAX_OLLAMA_STREAM_FRAME_BYTES,
            )

            while True:
                read_timeout = _remaining_transport_timeout(
                    deadline,
                    self._limits.read_timeout_seconds,
                )
                async with asyncio.timeout(read_timeout):
                    frame = await ndjson_reader.read_record()
                if frame is None:
                    return
                yield frame
        except asyncio.CancelledError:
            raise
        except InferenceError:
            raise
        except TimeoutError as exception:
            raise InferenceTimeoutError() from exception
        except asyncio.IncompleteReadError as exception:
            raise InferenceMalformedOutputError() from exception
        except OSError as exception:
            raise ModelProviderExecutionError() from exception
        except Exception as exception:
            raise ModelProviderExecutionError() from exception
        finally:
            if connection is not None:
                connection.close()
                try:
                    async with asyncio.timeout(self._limits.connect_timeout_seconds):
                        await connection.wait_closed()
                except (TimeoutError, OSError):
                    pass


class OllamaModelProvider:
    """Reviewed local Ollama adapter behind the RFC-0026 ModelProvider boundary."""

    def __init__(
        self,
        provider_configuration: InferenceProviderConfiguration,
        bindings: tuple[OllamaModelBinding, ...],
        *,
        transport_limits: OllamaTransportLimits | None = None,
        _connector: _OllamaConnector | None = None,
    ) -> None:
        if not isinstance(provider_configuration, InferenceProviderConfiguration):
            raise TypeError("provider_configuration must be InferenceProviderConfiguration")
        if provider_configuration.provider_id != OLLAMA_PROVIDER_ID:
            raise ValueError("Ollama provider id must be ollama-local")
        if provider_configuration.credential_policy is not None:
            raise ValueError("local Ollama provider does not accept credentials")
        endpoint_policy = provider_configuration.endpoint_policy
        if endpoint_policy is None:
            raise ValueError("local Ollama provider requires an endpoint policy")
        if (
            endpoint_policy.mode is not ModelEndpointMode.LOOPBACK_HTTP
            or endpoint_policy.url != OLLAMA_ENDPOINT_URL
            or endpoint_policy.host != "127.0.0.1"
            or endpoint_policy.port != OLLAMA_PORT
            or endpoint_policy.request_target != "/"
            or endpoint_policy.follow_redirects
            or endpoint_policy.use_proxy
        ):
            raise ValueError("local Ollama endpoint must be exact reviewed loopback port 11434")

        normalized_bindings = tuple(bindings)
        if not normalized_bindings:
            raise ValueError("Ollama provider requires at least one model binding")
        if any(not isinstance(binding, OllamaModelBinding) for binding in normalized_bindings):
            raise TypeError("bindings must contain OllamaModelBinding values")
        model_ids = tuple(binding.descriptor.model_id for binding in normalized_bindings)
        if len(model_ids) != len(set(model_ids)):
            raise ValueError("Ollama provider contains duplicate Phoenix model bindings")

        limits = OllamaTransportLimits() if transport_limits is None else transport_limits
        if not isinstance(limits, OllamaTransportLimits):
            raise TypeError("transport_limits must be OllamaTransportLimits")

        endpoint = admit_model_endpoint(endpoint_policy, ("127.0.0.1",))
        connector = _AsyncioOllamaConnector() if _connector is None else _connector
        if not callable(getattr(connector, "connect", None)):
            raise TypeError("_connector must provide connect")

        self._provider_configuration = provider_configuration
        self._bindings = {binding.descriptor.model_id: binding for binding in normalized_bindings}
        self._transport = _OllamaHttpTransport(endpoint, limits, connector)

    @property
    def provider_id(self) -> ModelProviderId:
        return OLLAMA_PROVIDER_ID

    @property
    def capabilities(self) -> ModelCapabilities:
        return ModelCapabilities(complete=True, streaming=True)

    @property
    def provider_configuration(self) -> InferenceProviderConfiguration:
        return self._provider_configuration

    @property
    def model_bindings(self) -> tuple[OllamaModelBinding, ...]:
        return tuple(self._bindings.values())

    @property
    def model_descriptors(self) -> tuple[ModelDescriptor, ...]:
        return tuple(binding.descriptor for binding in self._bindings.values())

    async def infer(self, request: InferenceRequest) -> InferenceResponse:
        binding = self._binding_for_request(request)
        if request.parameters:
            raise ModelProviderExecutionError()

        if binding.expected_digest is not None:
            status = await self._diagnose_binding(binding)
            if status is not OllamaModelAvailability.AVAILABLE:
                raise ModelProviderExecutionError()

        document: dict[str, object] = {
            "model": binding.descriptor.provider_model_name,
            "messages": [
                {
                    "role": message.role.value,
                    "content": message.content,
                }
                for message in request.messages
            ],
            "options": {"num_predict": request.max_output_tokens},
            "stream": False,
            "think": False,
        }
        response_format = _binding_response_format(binding)
        if response_format is not None:
            document["format"] = response_format
        encoded = _encode_json(document, maximum_bytes=MAX_OLLAMA_REQUEST_BYTES)
        body = await self._transport.request("POST", OLLAMA_CHAT_TARGET, encoded)
        decoded = _decode_json(body)
        return _decode_complete_response(decoded, request, binding)

    async def stream(self, request: InferenceRequest) -> AsyncIterator[InferenceChunk]:
        binding = self._binding_for_request(request)
        if request.parameters:
            raise ModelProviderExecutionError()

        if binding.expected_digest is not None:
            status = await self._diagnose_binding(binding)
            if status is not OllamaModelAvailability.AVAILABLE:
                raise ModelProviderExecutionError()

        document: dict[str, object] = {
            "model": binding.descriptor.provider_model_name,
            "messages": [
                {
                    "role": message.role.value,
                    "content": message.content,
                }
                for message in request.messages
            ],
            "options": {"num_predict": request.max_output_tokens},
            "stream": True,
            "think": False,
        }
        response_format = _binding_response_format(binding)
        if response_format is not None:
            document["format"] = response_format
        encoded = _encode_json(document, maximum_bytes=MAX_OLLAMA_REQUEST_BYTES)

        index = 0
        terminal_seen = False
        frames = self._transport.stream(
            "POST",
            OLLAMA_CHAT_TARGET,
            encoded,
        )
        try:
            async for frame in frames:
                if terminal_seen:
                    raise InferenceMalformedOutputError()
                decoded = _decode_json(frame)
                chunk = _decode_stream_response(
                    decoded,
                    request,
                    binding,
                    index=index,
                )
                terminal_seen = chunk.terminal
                index += 1
                yield chunk
        finally:
            await frames.aclose()

        if not terminal_seen:
            raise InferenceMalformedOutputError()

    async def diagnose_model(self, model_id: ModelId) -> OllamaModelDiagnostic:
        if not isinstance(model_id, ModelId):
            raise TypeError("model_id must be ModelId")
        binding = self._bindings.get(model_id)
        if binding is None:
            raise ModelProviderExecutionError()
        cause: OllamaModelDiagnosticCause | None = None
        try:
            status = await self._diagnose_binding(binding)
        except InferenceTimeoutError:
            status = OllamaModelAvailability.PROVIDER_UNREACHABLE
            cause = OllamaModelDiagnosticCause.PROVIDER_TIMEOUT
        except ModelProviderExecutionError:
            status = OllamaModelAvailability.PROVIDER_UNREACHABLE
            cause = OllamaModelDiagnosticCause.PROVIDER_UNREACHABLE
        return OllamaModelDiagnostic(
            provider_id=self.provider_id,
            model_id=model_id,
            status=status,
            cause=cause,
        )

    def _binding_for_request(self, request: InferenceRequest) -> OllamaModelBinding:
        if not isinstance(request, InferenceRequest):
            raise TypeError("request must be InferenceRequest")
        if request.provider_id != self.provider_id:
            raise ModelProviderExecutionError()
        binding = self._bindings.get(request.model_id)
        if binding is None:
            raise ModelProviderExecutionError()
        if request.max_output_tokens > binding.descriptor.limits.max_output_tokens:
            raise InferenceLimitExceededError()
        return binding

    async def _diagnose_binding(
        self,
        binding: OllamaModelBinding,
    ) -> OllamaModelAvailability:
        body = await self._transport.request("GET", OLLAMA_TAGS_TARGET)
        document = _decode_json(body)
        models = _decode_tag_models(document)
        matches = [
            item
            for item in models
            if item[0] == binding.descriptor.provider_model_name
            or item[1] == binding.descriptor.provider_model_name
        ]
        if not matches:
            return OllamaModelAvailability.UNAVAILABLE
        if len(matches) != 1:
            raise InferenceMalformedOutputError()
        _name, _model, digest = matches[0]
        expected = binding.expected_digest
        if expected is not None and digest != expected:
            return OllamaModelAvailability.REVISION_MISMATCH
        return OllamaModelAvailability.AVAILABLE


def _build_http_request(
    method: str,
    target: str,
    body: bytes,
    *,
    maximum_bytes: int,
) -> bytes:
    if method not in {"GET", "POST"}:
        raise ValueError("unsupported Ollama HTTP method")
    if target not in {OLLAMA_CHAT_TARGET, OLLAMA_TAGS_TARGET}:
        raise ValueError("unsupported Ollama HTTP target")
    if not isinstance(body, bytes):
        raise TypeError("body must be bytes")
    if len(body) > maximum_bytes:
        raise InferenceLimitExceededError()

    headers = [
        b"Host: 127.0.0.1:11434",
        b"Accept: application/json",
        b"Accept-Encoding: identity",
        b"Connection: close",
        f"Content-Length: {len(body)}".encode("ascii"),
    ]
    if method == "POST":
        headers.append(b"Content-Type: application/json")
    request_head = b"\r\n".join(
        (
            f"{method} {target} HTTP/1.1".encode("ascii"),
            *headers,
            b"",
            b"",
        )
    )
    if len(request_head) > MAX_OLLAMA_REQUEST_HEADER_BYTES:
        raise InferenceLimitExceededError()
    if len(request_head) + len(body) > maximum_bytes:
        raise InferenceLimitExceededError()
    return request_head + body


async def _read_http_response(
    reader: asyncio.StreamReader,
    *,
    maximum_body_bytes: int,
) -> _HttpResponse:
    head = await _read_http_response_head(reader)
    body = await _read_http_body(
        reader,
        head.headers,
        maximum_body_bytes=maximum_body_bytes,
    )
    return _HttpResponse(status_code=head.status_code, body=body)


async def _read_http_response_head(
    reader: asyncio.StreamReader,
) -> _HttpResponseHead:
    status_line = await _bounded_readline(reader, MAX_OLLAMA_RESPONSE_LINE_BYTES)
    match = re.fullmatch(
        rb"HTTP/1\.[01] ([1-5][0-9]{2})(?: [^\r\n]*)?\r\n",
        status_line,
    )
    if match is None:
        raise InferenceMalformedOutputError()
    if any((byte < 32 and byte != 9) or byte == 127 for byte in status_line[:-2]):
        raise InferenceMalformedOutputError()
    status_code = int(match.group(1))
    if status_code < 200:
        raise InferenceMalformedOutputError()

    headers: dict[str, str] = {}
    total = len(status_line)
    for _ in range(MAX_OLLAMA_RESPONSE_HEADERS + 1):
        line = await _bounded_readline(reader, MAX_OLLAMA_RESPONSE_LINE_BYTES)
        total += len(line)
        if total > MAX_OLLAMA_RESPONSE_HEADER_BYTES:
            raise InferenceLimitExceededError()
        if line == b"\r\n":
            break
        if len(headers) >= MAX_OLLAMA_RESPONSE_HEADERS:
            raise InferenceLimitExceededError()
        if line[:1] in {b" ", b"\t"} or b":" not in line:
            raise InferenceMalformedOutputError()
        raw_name, raw_value = line[:-2].split(b":", 1)
        if _HEADER_NAME_PATTERN.fullmatch(raw_name) is None:
            raise InferenceMalformedOutputError()
        try:
            name = raw_name.decode("ascii").lower()
            value = raw_value.strip(b" \t").decode("ascii")
        except UnicodeDecodeError as exception:
            raise InferenceMalformedOutputError() from exception
        if name in headers:
            raise InferenceMalformedOutputError()
        if any(
            (ord(character) < 32 and character != "\t") or ord(character) == 127
            for character in value
        ):
            raise InferenceMalformedOutputError()
        headers[name] = value
    else:  # pragma: no cover - loop bound already fails above
        raise InferenceLimitExceededError()

    content_encoding = headers.get("content-encoding")
    if content_encoding is not None and content_encoding.lower() != "identity":
        raise InferenceMalformedOutputError()

    return _HttpResponseHead(status_code=status_code, headers=headers)


async def _read_http_body(
    reader: asyncio.StreamReader,
    headers: Mapping[str, str],
    *,
    maximum_body_bytes: int,
) -> bytes:
    transfer_encoding = headers.get("transfer-encoding")
    content_length = headers.get("content-length")
    if transfer_encoding is not None and content_length is not None:
        raise InferenceMalformedOutputError()

    if transfer_encoding is not None:
        if transfer_encoding.lower() != "chunked":
            raise InferenceMalformedOutputError()
        return await _read_chunked_body(
            reader,
            maximum_body_bytes=maximum_body_bytes,
        )

    if content_length is not None:
        if not content_length.isdigit() or (
            len(content_length) > 1 and content_length.startswith("0")
        ):
            raise InferenceMalformedOutputError()
        length = int(content_length)
        if length > maximum_body_bytes:
            raise InferenceLimitExceededError()
        return await reader.readexactly(length) if length else b""

    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = await reader.read(min(8_192, maximum_body_bytes - total + 1))
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)
        total += len(chunk)
        if total > maximum_body_bytes:
            raise InferenceLimitExceededError()


async def _read_chunked_body(
    reader: asyncio.StreamReader,
    *,
    maximum_body_bytes: int,
) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        line = await _bounded_readline(reader, 128)
        raw_size = line[:-2]
        if b";" in raw_size or _CHUNK_SIZE_PATTERN.fullmatch(raw_size) is None:
            raise InferenceMalformedOutputError()
        size = int(raw_size, 16)
        if size == 0:
            trailer = await _bounded_readline(reader, MAX_OLLAMA_RESPONSE_LINE_BYTES)
            if trailer != b"\r\n":
                raise InferenceMalformedOutputError()
            return b"".join(chunks)

        total += size
        if total > maximum_body_bytes:
            raise InferenceLimitExceededError()
        chunks.append(await reader.readexactly(size))
        if await reader.readexactly(2) != b"\r\n":
            raise InferenceMalformedOutputError()


async def _bounded_readline(reader: asyncio.StreamReader, limit: int) -> bytes:
    try:
        line = await reader.readline()
    except ValueError as exception:
        raise InferenceLimitExceededError() from exception
    if not line or len(line) > limit or not line.endswith(b"\r\n"):
        raise InferenceMalformedOutputError()
    return line


def _canonicalize_structured_json_schema(value: str) -> str:
    if not isinstance(value, str):
        raise TypeError("structured_json_schema must be a string")
    try:
        raw = value.encode("utf-8")
    except UnicodeEncodeError as exception:
        raise ValueError("structured_json_schema must be valid UTF-8") from exception
    if not raw or len(raw) > MAX_OLLAMA_REQUEST_BYTES:
        raise ValueError("structured_json_schema is outside the reviewed bound")

    try:
        decoded: object = json.loads(
            value,
            object_pairs_hook=_strict_json_object,
            parse_constant=_reject_json_constant,
        )
        _inspect_json(decoded, depth=0, count=[0])
    except (
        InferenceError,
        UnicodeError,
        json.JSONDecodeError,
        TypeError,
        ValueError,
        OverflowError,
        RecursionError,
    ) as exception:
        raise ValueError("structured_json_schema is invalid") from exception

    if not isinstance(decoded, Mapping):
        raise ValueError("structured_json_schema must be a JSON object")

    try:
        encoded = json.dumps(
            decoded,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (
        TypeError,
        ValueError,
        OverflowError,
        UnicodeEncodeError,
        RecursionError,
    ) as exception:
        raise ValueError("structured_json_schema is invalid") from exception
    if len(encoded) > MAX_OLLAMA_REQUEST_BYTES:
        raise ValueError("structured_json_schema is outside the reviewed bound")
    return encoded.decode("utf-8")


def _binding_response_format(binding: OllamaModelBinding) -> object | None:
    schema = binding.structured_json_schema
    if schema is not None:
        try:
            return cast(
                object,
                json.loads(
                    schema,
                    object_pairs_hook=_strict_json_object,
                    parse_constant=_reject_json_constant,
                ),
            )
        except (
            json.JSONDecodeError,
            TypeError,
            ValueError,
            OverflowError,
            RecursionError,
        ) as exception:  # pragma: no cover - binding canonicalization invariant
            raise ModelProviderExecutionError() from exception
    if binding.structured_json:
        return "json"
    return None


def _encode_json(value: object, *, maximum_bytes: int) -> bytes:
    try:
        encoded = json.dumps(
            value,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, OverflowError, UnicodeEncodeError) as exception:
        raise ModelProviderExecutionError() from exception
    if len(encoded) > maximum_bytes:
        raise InferenceLimitExceededError()
    return encoded


def _decode_json(encoded: bytes) -> object:
    if not isinstance(encoded, bytes):
        raise TypeError("encoded provider document must be bytes")
    if not encoded:
        raise InferenceMalformedOutputError()
    if len(encoded) > MAX_OLLAMA_RESPONSE_BYTES:
        raise InferenceLimitExceededError()
    try:
        text = encoded.decode("utf-8")
        decoded: object = json.loads(
            text,
            object_pairs_hook=_strict_json_object,
            parse_constant=_reject_json_constant,
        )
    except (
        UnicodeDecodeError,
        UnicodeEncodeError,
        json.JSONDecodeError,
        TypeError,
        ValueError,
        OverflowError,
        RecursionError,
    ) as exception:
        raise InferenceMalformedOutputError() from exception
    _inspect_json(decoded, depth=0, count=[0])
    return decoded


def _strict_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate provider JSON key")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> object:
    raise ValueError(f"unsupported provider JSON constant: {value}")


def _inspect_json(value: object, *, depth: int, count: list[int]) -> None:
    if depth > MAX_OLLAMA_JSON_DEPTH:
        raise InferenceMalformedOutputError()
    count[0] += 1
    if count[0] > MAX_OLLAMA_JSON_ITEMS:
        raise InferenceLimitExceededError()
    if isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeEncodeError as exception:
            raise InferenceMalformedOutputError() from exception
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise InferenceMalformedOutputError()
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            _inspect_json(key, depth=depth + 1, count=count)
            _inspect_json(item, depth=depth + 1, count=count)
        return
    if isinstance(value, list):
        for item in value:
            _inspect_json(item, depth=depth + 1, count=count)


def _decode_stream_response(
    value: object,
    request: InferenceRequest,
    binding: OllamaModelBinding,
    *,
    index: int,
) -> InferenceChunk:
    document = _mapping(value)
    _raise_for_provider_error(document)
    if _string(document, "model") != binding.descriptor.provider_model_name:
        raise InferenceMalformedOutputError()

    done = _boolean(document, "done")
    message = _mapping(document.get("message"))
    allowed_message_fields = frozenset({"role", "content", "thinking", "tool_calls", "images"})
    if not frozenset(message).issubset(allowed_message_fields):
        raise InferenceMalformedOutputError()
    if _string(message, "role") != "assistant":
        raise InferenceMalformedOutputError()
    content = _string(message, "content")
    thinking = message.get("thinking")
    if thinking is not None and thinking != "":
        raise InferenceMalformedOutputError()
    tool_calls = message.get("tool_calls")
    if tool_calls is not None and tool_calls != []:
        raise InferenceMalformedOutputError()
    images = message.get("images")
    if images is not None and images != []:
        raise InferenceMalformedOutputError()
    if len(content) > binding.descriptor.limits.max_chunk_chars:
        raise InferenceLimitExceededError()

    if not done:
        if any(key in document for key in ("done_reason", "prompt_eval_count", "eval_count")):
            raise InferenceMalformedOutputError()
        return InferenceChunk(
            request_id=request.request_id,
            provider_id=request.provider_id,
            model_id=request.model_id,
            index=index,
            text=content,
        )

    reason = _string(document, "done_reason")
    try:
        finish_reason = {
            "stop": InferenceFinishReason.STOP,
            "length": InferenceFinishReason.LENGTH,
        }[reason]
    except KeyError as exception:
        raise InferenceMalformedOutputError() from exception

    input_tokens = _nonnegative_integer(document, "prompt_eval_count")
    output_tokens = _nonnegative_integer(document, "eval_count")
    if (
        output_tokens > request.max_output_tokens
        or output_tokens > binding.descriptor.limits.max_output_tokens
    ):
        raise InferenceLimitExceededError()

    return InferenceChunk(
        request_id=request.request_id,
        provider_id=request.provider_id,
        model_id=request.model_id,
        index=index,
        text=content,
        terminal=True,
        finish_reason=finish_reason,
        usage=InferenceUsage(
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cached_input_tokens=0,
        ),
    )


def _decode_complete_response(
    value: object,
    request: InferenceRequest,
    binding: OllamaModelBinding,
) -> InferenceResponse:
    document = _mapping(value)
    _raise_for_provider_error(document)
    if _string(document, "model") != binding.descriptor.provider_model_name:
        raise InferenceMalformedOutputError()
    if _boolean(document, "done") is not True:
        raise InferenceMalformedOutputError()

    reason = _string(document, "done_reason")
    try:
        finish_reason = {
            "stop": InferenceFinishReason.STOP,
            "length": InferenceFinishReason.LENGTH,
        }[reason]
    except KeyError as exception:
        raise InferenceMalformedOutputError() from exception

    message = _mapping(document.get("message"))
    allowed_message_fields = frozenset({"role", "content", "thinking", "tool_calls", "images"})
    if not frozenset(message).issubset(allowed_message_fields):
        raise InferenceMalformedOutputError()
    if _string(message, "role") != "assistant":
        raise InferenceMalformedOutputError()
    content = _string(message, "content")
    thinking = message.get("thinking")
    if thinking is not None and thinking != "":
        raise InferenceMalformedOutputError()
    tool_calls = message.get("tool_calls")
    if tool_calls is not None and tool_calls != []:
        raise InferenceMalformedOutputError()
    images = message.get("images")
    if images is not None and images != []:
        raise InferenceMalformedOutputError()

    input_tokens = _nonnegative_integer(document, "prompt_eval_count")
    output_tokens = _nonnegative_integer(document, "eval_count")
    if (
        output_tokens > request.max_output_tokens
        or output_tokens > binding.descriptor.limits.max_output_tokens
    ):
        raise InferenceLimitExceededError()
    if len(content) > binding.descriptor.limits.max_response_chars:
        raise InferenceLimitExceededError()

    return InferenceResponse(
        request_id=request.request_id,
        provider_id=request.provider_id,
        model_id=request.model_id,
        text=content,
        finish_reason=finish_reason,
        usage=InferenceUsage(
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cached_input_tokens=0,
        ),
    )


def _decode_tag_models(value: object) -> tuple[tuple[str, str, str], ...]:
    document = _mapping(value)
    if frozenset(document) != frozenset({"models"}):
        raise InferenceMalformedOutputError()
    raw_models = document.get("models")
    if not isinstance(raw_models, list):
        raise InferenceMalformedOutputError()

    result: list[tuple[str, str, str]] = []
    for raw in raw_models:
        item = _mapping(raw)
        name = _string(item, "name")
        model = _string(item, "model")
        digest = _string(item, "digest").lower()
        if (
            not name
            or not model
            or len(name) > MAX_INFERENCE_PROVIDER_MODEL_NAME_LENGTH
            or len(model) > MAX_INFERENCE_PROVIDER_MODEL_NAME_LENGTH
            or _DIGEST_PATTERN.fullmatch(digest) is None
        ):
            raise InferenceMalformedOutputError()
        result.append((name, model, digest))
    return tuple(result)


def _remaining_transport_timeout(deadline: float, operation_limit: float) -> float:
    remaining = deadline - asyncio.get_running_loop().time()
    if remaining <= 0:
        raise InferenceTimeoutError()
    return min(remaining, operation_limit)


def _raise_for_provider_error(document: Mapping[str, object]) -> None:
    if "error" in document:
        raise ModelProviderExecutionError()


def _mapping(value: object) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise InferenceMalformedOutputError()
    raw = cast(Mapping[object, object], value)
    if any(not isinstance(key, str) for key in raw):
        raise InferenceMalformedOutputError()
    return cast(Mapping[str, object], raw)


def _string(value: Mapping[str, object], key: str) -> str:
    item = value.get(key)
    if not isinstance(item, str):
        raise InferenceMalformedOutputError()
    return item


def _boolean(value: Mapping[str, object], key: str) -> bool:
    item = value.get(key)
    if not isinstance(item, bool):
        raise InferenceMalformedOutputError()
    return item


def _nonnegative_integer(value: Mapping[str, object], key: str) -> int:
    item = value.get(key)
    if isinstance(item, bool) or not isinstance(item, int) or item < 0:
        raise InferenceMalformedOutputError()
    return item
