"""Pinned direct TCP/TLS HTTP/1.1 transport for RFC-0034 slice 2."""

from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
import ssl
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Protocol

from phoenix_os.network_egress._admission import (
    NetworkDestinationAdmission,
    admit_network_destination,
)
from phoenix_os.network_egress._errors import (
    NetworkDestinationRejectedError,
    NetworkTransportError,
)
from phoenix_os.network_egress.contracts import (
    MAX_NETWORK_HEADER_VALUE_LENGTH,
    NetworkHttpRequest,
)
from phoenix_os.network_egress.profiles import (
    NetworkDestinationMode,
    NetworkEgressOperation,
    NetworkEgressProfile,
    NetworkHttpMethod,
)

MAX_NETWORK_REQUEST_HEADER_BYTES = 32_768
MAX_NETWORK_RESPONSE_LINE_BYTES = 8_192
MAX_NETWORK_INFORMATIONAL_RESPONSES = 4

_HEADER_NAME_PATTERN = re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")
_CHUNK_SIZE_PATTERN = re.compile(rb"[0-9A-Fa-f]+\Z")


class NetworkConnection(Protocol):
    """Minimal direct stream used by the reviewed pinned transport."""

    @property
    def reader(self) -> asyncio.StreamReader: ...

    def write(self, data: bytes) -> None: ...

    async def drain(self) -> None: ...

    def close(self) -> None: ...

    async def wait_closed(self) -> None: ...


class NetworkConnector(Protocol):
    """Connect to one already-admitted literal without resolving another host."""

    async def connect(
        self,
        address: str,
        port: int,
        *,
        tls: bool,
        server_hostname: str | None,
        connect_timeout: float,
        read_limit: int,
    ) -> NetworkConnection: ...


class _StreamNetworkConnection:
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


class AsyncioNetworkConnector:
    """Direct numeric-address TCP/TLS connector with verified hostname TLS."""

    async def connect(
        self,
        address: str,
        port: int,
        *,
        tls: bool,
        server_hostname: str | None,
        connect_timeout: float,
        read_limit: int,
    ) -> NetworkConnection:
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError as exception:
            raise NetworkDestinationRejectedError("invalid_pinned_address") from exception
        if "%" in address or parsed.compressed != address:
            raise NetworkDestinationRejectedError("invalid_pinned_address")
        if tls and not server_hostname:
            raise NetworkDestinationRejectedError("tls_hostname_required")
        if not tls and server_hostname is not None:
            raise NetworkDestinationRejectedError("unexpected_tls_hostname")

        context: ssl.SSLContext | None = None
        if tls:
            context = ssl.create_default_context()
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.set_alpn_protocols(["http/1.1"])

        family = socket.AF_INET if parsed.version == 4 else socket.AF_INET6
        created_socket = socket.socket(
            family,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP,
        )
        created_socket.setblocking(False)
        raw_socket: socket.socket | None = created_socket
        sockaddr: tuple[str, int] | tuple[str, int, int, int]
        if parsed.version == 4:
            sockaddr = (address, port)
        else:
            sockaddr = (address, port, 0, 0)

        reader: asyncio.StreamReader | None = None
        writer: asyncio.StreamWriter | None = None
        try:
            async with asyncio.timeout(connect_timeout):
                loop = asyncio.get_running_loop()
                if raw_socket is None:  # pragma: no cover - local construction invariant
                    raise RuntimeError("numeric connector socket is unavailable")
                await loop.sock_connect(raw_socket, sockaddr)
                if tls:
                    reader, writer = await asyncio.open_connection(
                        sock=raw_socket,
                        ssl=context,
                        server_hostname=server_hostname,
                        ssl_handshake_timeout=connect_timeout,
                        ssl_shutdown_timeout=connect_timeout,
                        limit=read_limit,
                    )
                else:
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
            raise NetworkTransportError("connect_failed", request_started=False)

        if tls:
            ssl_object = writer.get_extra_info("ssl_object")
            if ssl_object is None:
                writer.close()
                try:
                    await writer.wait_closed()
                except OSError:
                    pass
                raise ssl.SSLError("TLS connection has no SSL object")
            negotiated = ssl_object.selected_alpn_protocol()
            if negotiated not in {None, "http/1.1"}:
                writer.close()
                try:
                    await writer.wait_closed()
                except OSError:
                    pass
                raise ssl.SSLError("unexpected ALPN protocol")

        return _StreamNetworkConnection(reader, writer)


@dataclass(frozen=True, slots=True)
class NetworkTransportResponse:
    """Bounded final HTTP response data after server-owned header filtering."""

    status_code: int
    body: bytes
    headers: Mapping[str, str]

    def __post_init__(self) -> None:
        if isinstance(self.status_code, bool) or not isinstance(self.status_code, int):
            raise TypeError("status_code must be an integer")
        if not 200 <= self.status_code <= 599:
            raise ValueError("status_code must be a final HTTP status")
        if not isinstance(self.body, bytes):
            raise TypeError("body must be bytes")
        if not isinstance(self.headers, Mapping):
            raise TypeError("headers must be a mapping")
        object.__setattr__(self, "headers", MappingProxyType(dict(self.headers)))


class NetworkTransportSession:
    """One connected pinned session that can perform at most one HTTP exchange."""

    def __init__(
        self,
        *,
        connection: NetworkConnection,
        profile: NetworkEgressProfile,
        operation: NetworkEgressOperation,
    ) -> None:
        self._connection = connection
        self._profile = profile
        self._operation = operation
        self._used = False
        self._closed = False
        self._request_started = False

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def used(self) -> bool:
        return self._used

    @property
    def request_started(self) -> bool:
        return self._request_started

    async def aclose(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._connection.close()
        try:
            async with asyncio.timeout(self._operation.limits.connect_timeout_seconds):
                await self._connection.wait_closed()
        except TimeoutError:
            pass
        except OSError:
            pass

    async def exchange(
        self,
        request: NetworkHttpRequest,
        *,
        credential_value: bytes | None = None,
    ) -> NetworkTransportResponse:
        if self._closed:
            raise NetworkTransportError("session_closed", request_started=False)
        if self._used:
            raise NetworkTransportError(
                "session_already_used",
                request_started=self._request_started,
            )

        self._used = True
        try:
            request_bytes = _build_request_bytes(
                request,
                self._profile,
                self._operation,
                credential_value=credential_value,
            )
            async with asyncio.timeout(self._operation.limits.total_timeout_seconds):
                self._request_started = True
                self._connection.write(request_bytes)
                await self._connection.drain()
                return await _read_response(
                    self._connection.reader,
                    self._operation,
                )
        except asyncio.CancelledError:
            raise
        except (NetworkDestinationRejectedError, NetworkTransportError):
            raise
        except TimeoutError as exception:
            raise NetworkTransportError(
                "timeout",
                request_started=self._request_started,
            ) from exception
        except asyncio.IncompleteReadError as exception:
            raise NetworkTransportError(
                "response_truncated",
                request_started=self._request_started,
            ) from exception
        except ssl.SSLError as exception:
            raise NetworkTransportError(
                "tls_failed",
                request_started=self._request_started,
            ) from exception
        except OSError as exception:
            raise NetworkTransportError(
                "io_failed",
                request_started=self._request_started,
            ) from exception
        except Exception as exception:
            raise NetworkTransportError(
                "transport_failed",
                request_started=self._request_started,
            ) from exception
        finally:
            try:
                await self.aclose()
            except OSError:
                self._closed = True


class NetworkTransport:
    """Open direct pinned sessions without writing HTTP request bytes."""

    def __init__(self, *, connector: NetworkConnector | None = None) -> None:
        self._connector = AsyncioNetworkConnector() if connector is None else connector

    async def open_session(
        self,
        profile: NetworkEgressProfile,
        operation: NetworkEgressOperation,
        admission: NetworkDestinationAdmission,
    ) -> NetworkTransportSession:
        if not isinstance(profile, NetworkEgressProfile):
            raise TypeError("profile must be NetworkEgressProfile")
        if not isinstance(operation, NetworkEgressOperation):
            raise TypeError("operation must be NetworkEgressOperation")
        if not isinstance(admission, NetworkDestinationAdmission):
            raise TypeError("admission must be NetworkDestinationAdmission")

        expected = admit_network_destination(profile, operation, admission.addresses)
        if expected != admission:
            raise NetworkDestinationRejectedError("admission_mismatch")

        tls = profile.mode is NetworkDestinationMode.HOSTED_HTTPS
        server_hostname = profile.host if tls else None
        port = profile.port
        if port is None:  # pragma: no cover - NetworkEgressProfile invariant
            raise RuntimeError("validated network profile has no port")

        try:
            async with asyncio.timeout(operation.limits.total_timeout_seconds):
                for address in admission.addresses:
                    try:
                        connection = await self._connector.connect(
                            address,
                            port,
                            tls=tls,
                            server_hostname=server_hostname,
                            connect_timeout=operation.limits.connect_timeout_seconds,
                            read_limit=MAX_NETWORK_RESPONSE_LINE_BYTES + 2,
                        )
                    except asyncio.CancelledError:
                        raise
                    except ssl.SSLError as exception:
                        raise NetworkTransportError(
                            "tls_failed",
                            request_started=False,
                        ) from exception
                    except (TimeoutError, OSError):
                        continue
                    except NetworkDestinationRejectedError:
                        raise
                    except Exception as exception:
                        raise NetworkTransportError(
                            "connect_failed",
                            request_started=False,
                        ) from exception
                    return NetworkTransportSession(
                        connection=connection,
                        profile=profile,
                        operation=operation,
                    )
        except asyncio.CancelledError:
            raise
        except NetworkTransportError:
            raise
        except TimeoutError as exception:
            raise NetworkTransportError(
                "connect_timeout",
                request_started=False,
            ) from exception

        raise NetworkTransportError("connect_failed", request_started=False)


def _build_request_bytes(
    request: NetworkHttpRequest,
    profile: NetworkEgressProfile,
    operation: NetworkEgressOperation,
    *,
    credential_value: bytes | None,
) -> bytes:
    if not isinstance(request, NetworkHttpRequest):
        raise TypeError("request must be NetworkHttpRequest")
    if request.profile_id != profile.profile_id or request.operation_id != operation.operation_id:
        raise NetworkDestinationRejectedError("request_mismatch")
    try:
        configured = profile.require_operation(operation.operation_id)
    except KeyError as exception:
        raise NetworkDestinationRejectedError("operation_mismatch") from exception
    if configured != operation:
        raise NetworkDestinationRejectedError("operation_mismatch")
    if len(request.body) > operation.limits.max_request_body_bytes:
        raise NetworkDestinationRejectedError("request_body_too_large")

    method = operation.method.value.encode("ascii")
    target = operation.request_target.encode("ascii")
    generated: list[tuple[bytes, bytes]] = [
        (b"Host", _host_header(profile).encode("ascii")),
        (b"Content-Length", str(len(request.body)).encode("ascii")),
        (b"Accept-Encoding", b"identity"),
        (b"Connection", b"close"),
    ]
    if operation.accept is not None:
        generated.append((b"Accept", operation.accept.encode("ascii")))
    if operation.content_type is not None:
        generated.append((b"Content-Type", operation.content_type.encode("ascii")))

    if profile.credential is None:
        if credential_value is not None:
            raise NetworkDestinationRejectedError("unexpected_credential_material")
    else:
        if credential_value is None:
            raise NetworkDestinationRejectedError("credential_required")
        if not isinstance(credential_value, bytes):
            raise TypeError("credential_value must be bytes or None")
        prefix = profile.credential.value_prefix.encode("ascii")
        value = prefix + credential_value
        if len(value) > MAX_NETWORK_HEADER_VALUE_LENGTH:
            raise NetworkDestinationRejectedError("credential_value_too_large")
        if any(byte < 32 or byte > 126 for byte in value):
            raise NetworkDestinationRejectedError("invalid_credential_material")
        generated.append((profile.credential.header_name.encode("ascii"), value))

    seen: set[bytes] = set()
    header_lines: list[bytes] = []
    for name, value in generated:
        lower = name.lower()
        if lower in seen:
            raise NetworkDestinationRejectedError("duplicate_request_header")
        if _HEADER_NAME_PATTERN.fullmatch(name) is None:
            raise NetworkDestinationRejectedError("invalid_request_header")
        if len(value) > MAX_NETWORK_HEADER_VALUE_LENGTH:
            raise NetworkDestinationRejectedError("request_header_value_too_large")
        if any(byte < 32 or byte > 126 for byte in value):
            raise NetworkDestinationRejectedError("invalid_request_header")
        seen.add(lower)
        header_lines.append(name + b": " + value)

    request_head = b"\r\n".join(
        (
            method + b" " + target + b" HTTP/1.1",
            *header_lines,
            b"",
            b"",
        )
    )
    if len(request_head) > MAX_NETWORK_REQUEST_HEADER_BYTES:
        raise NetworkDestinationRejectedError("request_headers_too_large")
    return request_head + request.body


def _host_header(profile: NetworkEgressProfile) -> str:
    host = f"[{profile.host}]" if ":" in profile.host else profile.host
    default_port = 443 if profile.mode is NetworkDestinationMode.HOSTED_HTTPS else 80
    port = profile.port
    if port is None:  # pragma: no cover - NetworkEgressProfile invariant
        raise RuntimeError("validated network profile has no port")
    if port == default_port:
        return host
    return f"{host}:{port}"


async def _read_response(
    reader: asyncio.StreamReader,
    operation: NetworkEgressOperation,
) -> NetworkTransportResponse:
    informational = 0
    while True:
        status_code, headers = await _read_response_head(reader, operation)
        if status_code == 101:
            raise NetworkTransportError("protocol_switch_rejected", request_started=True)
        if status_code >= 200:
            break
        informational += 1
        if informational > MAX_NETWORK_INFORMATIONAL_RESPONSES:
            raise NetworkTransportError(
                "too_many_informational_responses",
                request_started=True,
            )

    body = await _read_response_body(
        reader,
        operation,
        status_code,
        headers,
    )
    allowed = set(operation.exposed_response_headers)
    exposed = {name: value for name, value in headers.items() if name in allowed}
    return NetworkTransportResponse(
        status_code=status_code,
        body=body,
        headers=exposed,
    )


async def _read_response_head(
    reader: asyncio.StreamReader,
    operation: NetworkEgressOperation,
) -> tuple[int, dict[str, str]]:
    status_line = await _bounded_readline(reader, MAX_NETWORK_RESPONSE_LINE_BYTES)
    total = len(status_line)
    match = re.fullmatch(
        rb"HTTP/1\.[01] ([1-5][0-9]{2})(?: [^\r\n]*)?\r\n",
        status_line,
    )
    if match is None:
        raise NetworkTransportError("invalid_response", request_started=True)
    if any((byte < 32 and byte != 9) or byte == 127 for byte in status_line[:-2]):
        raise NetworkTransportError("invalid_response", request_started=True)

    status_code = int(match.group(1))
    headers: dict[str, str] = {}
    for _ in range(operation.limits.max_response_headers + 1):
        line = await _bounded_readline(reader, MAX_NETWORK_RESPONSE_LINE_BYTES)
        total += len(line)
        if total > operation.limits.max_response_header_bytes:
            raise NetworkTransportError(
                "response_headers_too_large",
                request_started=True,
            )
        if line == b"\r\n":
            return status_code, headers
        if len(headers) >= operation.limits.max_response_headers:
            raise NetworkTransportError(
                "too_many_response_headers",
                request_started=True,
            )
        if line[:1] in {b" ", b"\t"} or b":" not in line:
            raise NetworkTransportError("invalid_response", request_started=True)

        raw_name, raw_value = line[:-2].split(b":", 1)
        if _HEADER_NAME_PATTERN.fullmatch(raw_name) is None:
            raise NetworkTransportError("invalid_response", request_started=True)
        try:
            name = raw_name.decode("ascii").lower()
            value = raw_value.strip(b" \t").decode("ascii")
        except UnicodeDecodeError as exception:
            raise NetworkTransportError(
                "invalid_response",
                request_started=True,
            ) from exception
        if any(
            (ord(character) < 32 and character != "\t") or ord(character) == 127
            for character in value
        ):
            raise NetworkTransportError("invalid_response", request_started=True)
        if name in headers:
            raise NetworkTransportError(
                "duplicate_response_header",
                request_started=True,
            )
        headers[name] = value

    raise NetworkTransportError("too_many_response_headers", request_started=True)


async def _read_response_body(
    reader: asyncio.StreamReader,
    operation: NetworkEgressOperation,
    status_code: int,
    headers: dict[str, str],
) -> bytes:
    transfer_encoding = headers.get("transfer-encoding")
    content_length = headers.get("content-length")
    if transfer_encoding is not None and content_length is not None:
        raise NetworkTransportError(
            "ambiguous_response_framing",
            request_started=True,
        )

    if operation.method is NetworkHttpMethod.HEAD or status_code in {204, 304}:
        return b""

    if transfer_encoding is not None:
        if transfer_encoding.lower() != "chunked":
            raise NetworkTransportError(
                "unsupported_transfer_encoding",
                request_started=True,
            )
        return await _read_chunked_body(reader, operation)

    if content_length is not None:
        if not content_length.isdigit() or (
            len(content_length) > 1 and content_length.startswith("0")
        ):
            raise NetworkTransportError("invalid_response", request_started=True)
        length = int(content_length)
        if length > operation.limits.max_response_body_bytes:
            raise NetworkTransportError(
                "response_body_too_large",
                request_started=True,
            )
        return await reader.readexactly(length) if length else b""

    return await _read_until_eof(
        reader,
        operation.limits.max_response_body_bytes,
    )


async def _read_until_eof(reader: asyncio.StreamReader, limit: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = await reader.read(min(8_192, limit - total + 1))
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)
        total += len(chunk)
        if total > limit:
            raise NetworkTransportError(
                "response_body_too_large",
                request_started=True,
            )


async def _read_chunked_body(
    reader: asyncio.StreamReader,
    operation: NetworkEgressOperation,
) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        line = await _bounded_readline(reader, 128)
        raw_size = line[:-2]
        if b";" in raw_size or _CHUNK_SIZE_PATTERN.fullmatch(raw_size) is None:
            raise NetworkTransportError(
                "invalid_chunked_response",
                request_started=True,
            )
        size = int(raw_size, 16)
        if size == 0:
            trailer = await _bounded_readline(reader, MAX_NETWORK_RESPONSE_LINE_BYTES)
            if trailer != b"\r\n":
                raise NetworkTransportError(
                    "response_trailers_rejected",
                    request_started=True,
                )
            return b"".join(chunks)

        total += size
        if total > operation.limits.max_response_body_bytes:
            raise NetworkTransportError(
                "response_body_too_large",
                request_started=True,
            )
        chunks.append(await reader.readexactly(size))
        if await reader.readexactly(2) != b"\r\n":
            raise NetworkTransportError(
                "invalid_chunked_response",
                request_started=True,
            )


async def _bounded_readline(reader: asyncio.StreamReader, limit: int) -> bytes:
    try:
        line = await reader.readline()
    except ValueError as exception:
        raise NetworkTransportError(
            "response_line_too_large",
            request_started=True,
        ) from exception
    if not line or len(line) > limit or not line.endswith(b"\r\n"):
        raise NetworkTransportError("invalid_response", request_started=True)
    return line
