"""Fail-closed outbound HTTP transport for signed Phoenix webhook requests."""

from __future__ import annotations

import asyncio
import ipaddress
import math
import re
import socket
import ssl
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import urlsplit

from phoenix_os.webhooks.contracts import (
    MAX_WEBHOOK_DELIVERY_BODY_BYTES,
    WebhookEgressPolicy,
    WebhookEndpoint,
    WebhookHttpStatusClass,
    WebhookSubscription,
)
from phoenix_os.webhooks.errors import (
    WebhookEndpointRejectedError,
    WebhookTransportError,
)
from phoenix_os.webhooks.signing import WebhookSignedRequest

DEFAULT_WEBHOOK_CONNECT_TIMEOUT = 5.0
DEFAULT_WEBHOOK_TOTAL_TIMEOUT = 30.0
DEFAULT_WEBHOOK_RESPONSE_BODY_BYTES = 65_536
DEFAULT_WEBHOOK_RESPONSE_HEADER_BYTES = 32_768
DEFAULT_WEBHOOK_RESPONSE_HEADERS = 100
DEFAULT_WEBHOOK_RESOLVED_ADDRESSES = 16
MAX_WEBHOOK_CONNECT_TIMEOUT = 60.0
MAX_WEBHOOK_TOTAL_TIMEOUT = 300.0
MAX_WEBHOOK_RESPONSE_BODY_BYTES = 1_048_576
MAX_WEBHOOK_RESPONSE_HEADER_BYTES = 65_536
MAX_WEBHOOK_RESPONSE_HEADERS = 256
MAX_WEBHOOK_RESOLVED_ADDRESSES = 32
MAX_WEBHOOK_REQUEST_HEADER_BYTES = 32_768
MAX_WEBHOOK_RESPONSE_LINE_BYTES = 8_192

type _WebhookIpAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

_HEADER_NAME_PATTERN = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")
_HEX_PATTERN = re.compile(rb"[0-9A-Fa-f]+\Z")
_RESERVED_REQUEST_HEADERS = frozenset(
    {"accept-encoding", "connection", "content-length", "host", "transfer-encoding"}
)
_RETRYABLE_CLIENT_STATUSES = frozenset({408, 425, 429})


@dataclass(frozen=True, slots=True)
class WebhookTransportConfig:
    """Bounded time and response limits for one outbound webhook attempt."""

    connect_timeout: float = DEFAULT_WEBHOOK_CONNECT_TIMEOUT
    total_timeout: float = DEFAULT_WEBHOOK_TOTAL_TIMEOUT
    max_response_header_bytes: int = DEFAULT_WEBHOOK_RESPONSE_HEADER_BYTES
    max_response_headers: int = DEFAULT_WEBHOOK_RESPONSE_HEADERS
    max_response_body_bytes: int = DEFAULT_WEBHOOK_RESPONSE_BODY_BYTES
    max_resolved_addresses: int = DEFAULT_WEBHOOK_RESOLVED_ADDRESSES

    def __post_init__(self) -> None:
        if not math.isfinite(self.connect_timeout) or not (
            0 < self.connect_timeout <= MAX_WEBHOOK_CONNECT_TIMEOUT
        ):
            raise ValueError("webhook connect timeout is outside supported bounds")
        if not math.isfinite(self.total_timeout) or not (
            0 < self.total_timeout <= MAX_WEBHOOK_TOTAL_TIMEOUT
        ):
            raise ValueError("webhook total timeout is outside supported bounds")
        if self.connect_timeout > self.total_timeout:
            raise ValueError("webhook connect timeout cannot exceed total timeout")
        if not 1 <= self.max_response_header_bytes <= MAX_WEBHOOK_RESPONSE_HEADER_BYTES:
            raise ValueError("webhook response header limit is outside supported bounds")
        if not 1 <= self.max_response_headers <= MAX_WEBHOOK_RESPONSE_HEADERS:
            raise ValueError("webhook response header count is outside supported bounds")
        if not 0 <= self.max_response_body_bytes <= MAX_WEBHOOK_RESPONSE_BODY_BYTES:
            raise ValueError("webhook response body limit is outside supported bounds")
        if not 1 <= self.max_resolved_addresses <= MAX_WEBHOOK_RESOLVED_ADDRESSES:
            raise ValueError("webhook resolved-address limit is outside supported bounds")


@dataclass(frozen=True, slots=True)
class WebhookTransportResult:
    """Safe bounded result from one completed HTTP exchange."""

    status_code: int
    status_class: WebhookHttpStatusClass
    successful: bool
    retryable: bool
    error_category: str | None
    response_body_bytes: int

    def __post_init__(self) -> None:
        if not 100 <= self.status_code <= 599:
            raise ValueError("webhook response status code is outside supported bounds")
        status_class = WebhookHttpStatusClass(self.status_class)
        expected_class = _status_class(self.status_code)
        if status_class is not expected_class:
            raise ValueError("webhook response status class is inconsistent")
        if self.response_body_bytes < 0:
            raise ValueError("webhook response body count cannot be negative")
        if self.successful:
            if status_class is not WebhookHttpStatusClass.SUCCESSFUL:
                raise ValueError("successful webhook transport result requires 2xx")
            if self.retryable or self.error_category is not None:
                raise ValueError("successful webhook transport result cannot contain failure data")
        elif self.error_category is None:
            raise ValueError("failed webhook transport result requires an error category")
        object.__setattr__(self, "status_class", status_class)


class WebhookConnection(Protocol):
    """Minimal bounded stream used by the reviewed webhook transport."""

    @property
    def reader(self) -> asyncio.StreamReader: ...

    def write(self, data: bytes) -> None: ...

    async def drain(self) -> None: ...

    def close(self) -> None: ...

    async def wait_closed(self) -> None: ...


class WebhookResolver(Protocol):
    """Resolve one canonical host into literal destination addresses."""

    async def resolve(self, host: str, port: int) -> tuple[str, ...]: ...


class WebhookConnector(Protocol):
    """Connect only to one already-admitted literal destination address."""

    async def connect(
        self,
        address: str,
        port: int,
        *,
        tls: bool,
        server_hostname: str | None,
        connect_timeout: float,
        read_limit: int,
    ) -> WebhookConnection: ...


class AsyncioWebhookResolver:
    """System resolver adapter with normalized unique literal results."""

    async def resolve(self, host: str, port: int) -> tuple[str, ...]:
        loop = asyncio.get_running_loop()
        records = await loop.getaddrinfo(
            host,
            port,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
            proto=socket.IPPROTO_TCP,
        )
        addresses: set[str] = set()
        for family, _kind, _protocol, _canonical, sockaddr in records:
            if family not in {socket.AF_INET, socket.AF_INET6}:
                continue
            if not isinstance(sockaddr, tuple) or not sockaddr:
                continue
            address = sockaddr[0]
            if not isinstance(address, str):
                continue
            addresses.add(ipaddress.ip_address(address).compressed)
        return tuple(sorted(addresses, key=_address_sort_key))


class _StreamWebhookConnection:
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


class AsyncioWebhookConnector:
    """Direct TCP/TLS connector without proxies, redirects, or ambient clients."""

    async def connect(
        self,
        address: str,
        port: int,
        *,
        tls: bool,
        server_hostname: str | None,
        connect_timeout: float,
        read_limit: int,
    ) -> WebhookConnection:
        context: ssl.SSLContext | None = None
        if tls:
            context = ssl.create_default_context()
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.set_alpn_protocols(["http/1.1"])
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                address,
                port,
                ssl=context,
                server_hostname=server_hostname,
                limit=read_limit,
            ),
            timeout=connect_timeout,
        )
        return _StreamWebhookConnection(reader, writer)


class WebhookTransport:
    """Resolve, admit, pin, and exchange one signed webhook request."""

    def __init__(
        self,
        *,
        resolver: WebhookResolver | None = None,
        connector: WebhookConnector | None = None,
        config: WebhookTransportConfig | None = None,
    ) -> None:
        self._resolver = AsyncioWebhookResolver() if resolver is None else resolver
        self._connector = AsyncioWebhookConnector() if connector is None else connector
        self._config = WebhookTransportConfig() if config is None else config
        if not isinstance(self._config, WebhookTransportConfig):
            raise TypeError("webhook transport config must be WebhookTransportConfig")
        self._closed = False

    @property
    def closed(self) -> bool:
        return self._closed

    async def send(
        self,
        request: WebhookSignedRequest,
        subscription: WebhookSubscription,
        *,
        policy: WebhookEgressPolicy,
    ) -> WebhookTransportResult:
        self._ensure_open()
        if not isinstance(request, WebhookSignedRequest):
            raise TypeError("request must be WebhookSignedRequest")
        if not isinstance(subscription, WebhookSubscription):
            raise TypeError("subscription must be WebhookSubscription")
        if not isinstance(policy, WebhookEgressPolicy):
            raise TypeError("policy must be WebhookEgressPolicy")
        if request.subscription_id != subscription.id:
            raise ValueError("webhook signed request belongs to another subscription")
        if policy.name != subscription.egress_policy:
            raise WebhookEndpointRejectedError("policy_mismatch")
        if len(request.body) > MAX_WEBHOOK_DELIVERY_BODY_BYTES:
            raise WebhookEndpointRejectedError("request_body_too_large")

        connection: WebhookConnection | None = None
        try:
            async with asyncio.timeout(self._config.total_timeout):
                endpoint = subscription.endpoint
                addresses = await self._resolve(endpoint)
                admitted = _admit_destinations(endpoint, policy, addresses)
                request_bytes = _build_request_bytes(request, endpoint)
                connection = await self._connect(endpoint, admitted)
                connection.write(request_bytes)
                await connection.drain()
                status_code, response_body_bytes = await _read_response(
                    connection.reader,
                    self._config,
                )
                return _classify_response(status_code, response_body_bytes)
        except asyncio.CancelledError:
            raise
        except (WebhookEndpointRejectedError, WebhookTransportError):
            raise
        except TimeoutError as exception:
            raise WebhookTransportError("timeout", retryable=True) from exception
        except asyncio.IncompleteReadError as exception:
            raise WebhookTransportError("response_truncated", retryable=True) from exception
        except ssl.SSLError as exception:
            raise WebhookTransportError("tls_failed", retryable=False) from exception
        except socket.gaierror as exception:
            raise WebhookTransportError("dns_failed", retryable=True) from exception
        except OSError as exception:
            raise WebhookTransportError("io_failed", retryable=True) from exception
        except Exception as exception:
            raise WebhookTransportError("transport_failed", retryable=True) from exception
        finally:
            if connection is not None:
                connection.close()
                try:
                    await connection.wait_closed()
                except OSError:
                    pass

    def close(self) -> None:
        self._closed = True

    async def _resolve(self, endpoint: WebhookEndpoint) -> tuple[_WebhookIpAddress, ...]:
        try:
            literal = ipaddress.ip_address(endpoint.host)
        except ValueError:
            supplied = await self._resolver.resolve(endpoint.host, endpoint.port)
        else:
            supplied = (literal.compressed,)

        if not supplied:
            raise WebhookTransportError("dns_no_addresses", retryable=True)
        if len(supplied) > self._config.max_resolved_addresses:
            raise WebhookEndpointRejectedError("too_many_addresses")

        addresses: set[_WebhookIpAddress] = set()
        for value in supplied:
            try:
                addresses.add(ipaddress.ip_address(value))
            except ValueError as exception:
                raise WebhookEndpointRejectedError("invalid_resolved_address") from exception
        if not addresses:
            raise WebhookTransportError("dns_no_addresses", retryable=True)
        if len(addresses) > self._config.max_resolved_addresses:
            raise WebhookEndpointRejectedError("too_many_addresses")
        return tuple(sorted(addresses, key=_ip_sort_key))

    async def _connect(
        self,
        endpoint: WebhookEndpoint,
        addresses: Sequence[_WebhookIpAddress],
    ) -> WebhookConnection:
        tls = endpoint.scheme == "https"
        hostname = endpoint.host if tls else None
        for address in addresses:
            try:
                return await self._connector.connect(
                    address.compressed,
                    endpoint.port,
                    tls=tls,
                    server_hostname=hostname,
                    connect_timeout=self._config.connect_timeout,
                    read_limit=MAX_WEBHOOK_RESPONSE_LINE_BYTES + 2,
                )
            except asyncio.CancelledError:
                raise
            except ssl.SSLError:
                raise
            except OSError:
                continue
        raise WebhookTransportError("connect_failed", retryable=True)

    def _ensure_open(self) -> None:
        if self._closed:
            raise WebhookTransportError("transport_closed", retryable=False)


def _admit_destinations(
    endpoint: WebhookEndpoint,
    policy: WebhookEgressPolicy,
    addresses: Sequence[_WebhookIpAddress],
) -> tuple[_WebhookIpAddress, ...]:
    if endpoint.port not in policy.allowed_ports:
        raise WebhookEndpointRejectedError("port_not_allowed")
    if endpoint.loopback_development:
        if not policy.allow_insecure_loopback:
            raise WebhookEndpointRejectedError("insecure_loopback_not_allowed")
        if any(not _effective_address(address).is_loopback for address in addresses):
            raise WebhookEndpointRejectedError("loopback_resolution_mismatch")

    networks = tuple(ipaddress.ip_network(value) for value in policy.allowed_networks)
    for address in addresses:
        effective = _effective_address(address)
        explicit = any(
            effective.version == network.version and effective in network for network in networks
        )
        loopback_development = endpoint.loopback_development and effective.is_loopback
        public = policy.allow_public_networks and effective.is_global
        if not (explicit or loopback_development or public):
            raise WebhookEndpointRejectedError("destination_not_allowed")
    return tuple(addresses)


def _build_request_bytes(request: WebhookSignedRequest, endpoint: WebhookEndpoint) -> bytes:
    parsed = urlsplit(endpoint.url)
    target = parsed.path or "/"
    try:
        target_bytes = target.encode("ascii")
    except UnicodeEncodeError as exception:  # pragma: no cover - endpoint invariant
        raise WebhookEndpointRejectedError("invalid_request_target") from exception
    if any(byte <= 32 or byte == 127 for byte in target_bytes):
        raise WebhookEndpointRejectedError("invalid_request_target")

    seen: set[str] = set()
    header_lines: list[bytes] = []
    for name, value in request.headers.items():
        lower = name.lower()
        if lower in seen or lower in _RESERVED_REQUEST_HEADERS:
            raise WebhookEndpointRejectedError("invalid_request_headers")
        if _HEADER_NAME_PATTERN.fullmatch(name) is None:
            raise WebhookEndpointRejectedError("invalid_request_headers")
        try:
            encoded_value = value.encode("ascii")
        except UnicodeEncodeError as exception:
            raise WebhookEndpointRejectedError("invalid_request_headers") from exception
        if any((byte < 32 and byte != 9) or byte == 127 for byte in encoded_value):
            raise WebhookEndpointRejectedError("invalid_request_headers")
        seen.add(lower)
        header_lines.append(name.encode("ascii") + b": " + encoded_value)

    generated = (
        b"Host: " + parsed.netloc.encode("ascii"),
        b"Content-Length: " + str(len(request.body)).encode("ascii"),
        b"Accept-Encoding: identity",
        b"Connection: close",
    )
    request_head = b"\r\n".join(
        (
            b"POST " + target_bytes + b" HTTP/1.1",
            *generated,
            *header_lines,
            b"",
            b"",
        )
    )
    if len(request_head) > MAX_WEBHOOK_REQUEST_HEADER_BYTES:
        raise WebhookEndpointRejectedError("request_headers_too_large")
    return request_head + request.body


async def _read_response(
    reader: asyncio.StreamReader,
    config: WebhookTransportConfig,
) -> tuple[int, int]:
    informational = 0
    while True:
        status_code, headers = await _read_response_head(reader, config)
        if status_code == 101:
            raise WebhookTransportError("protocol_switch_rejected", retryable=False)
        if status_code >= 200:
            break
        informational += 1
        if informational > 4:
            raise WebhookTransportError("too_many_informational_responses", retryable=False)

    body_bytes = await _discard_response_body(reader, status_code, headers, config)
    return status_code, body_bytes


async def _read_response_head(
    reader: asyncio.StreamReader,
    config: WebhookTransportConfig,
) -> tuple[int, dict[str, str]]:
    status_line = await _bounded_readline(reader, MAX_WEBHOOK_RESPONSE_LINE_BYTES)
    total = len(status_line)
    match = re.fullmatch(rb"HTTP/1\.[01] ([1-5][0-9]{2})(?: [^\r\n]*)?\r\n", status_line)
    if match is None:
        raise WebhookTransportError("invalid_response", retryable=False)
    if any((byte < 32 and byte != 9) or byte == 127 for byte in status_line[:-2]):
        raise WebhookTransportError("invalid_response", retryable=False)
    status_code = int(match.group(1))

    headers: dict[str, str] = {}
    for _ in range(config.max_response_headers + 1):
        line = await _bounded_readline(reader, MAX_WEBHOOK_RESPONSE_LINE_BYTES)
        total += len(line)
        if total > config.max_response_header_bytes:
            raise WebhookTransportError("response_headers_too_large", retryable=False)
        if line == b"\r\n":
            return status_code, headers
        if len(headers) >= config.max_response_headers:
            raise WebhookTransportError("too_many_response_headers", retryable=False)
        if line[:1] in {b" ", b"\t"} or b":" not in line:
            raise WebhookTransportError("invalid_response", retryable=False)
        raw_name, raw_value = line[:-2].split(b":", 1)
        try:
            name = raw_name.decode("ascii").lower()
            value = raw_value.strip(b" \t").decode("ascii")
        except UnicodeDecodeError as exception:
            raise WebhookTransportError("invalid_response", retryable=False) from exception
        if _HEADER_NAME_PATTERN.fullmatch(name) is None:
            raise WebhookTransportError("invalid_response", retryable=False)
        if any(
            (ord(character) < 32 and character != "\t") or ord(character) == 127
            for character in value
        ):
            raise WebhookTransportError("invalid_response", retryable=False)
        if name in headers:
            raise WebhookTransportError("duplicate_response_header", retryable=False)
        headers[name] = value
    raise WebhookTransportError("too_many_response_headers", retryable=False)


async def _discard_response_body(
    reader: asyncio.StreamReader,
    status_code: int,
    headers: dict[str, str],
    config: WebhookTransportConfig,
) -> int:
    if status_code in {204, 304}:
        return 0
    transfer_encoding = headers.get("transfer-encoding")
    content_length = headers.get("content-length")
    if transfer_encoding is not None and content_length is not None:
        raise WebhookTransportError("ambiguous_response_framing", retryable=False)
    if transfer_encoding is not None:
        if transfer_encoding.lower() != "chunked":
            raise WebhookTransportError("unsupported_transfer_encoding", retryable=False)
        return await _discard_chunked_body(reader, config)
    if content_length is not None:
        if not content_length.isdigit() or (
            len(content_length) > 1 and content_length.startswith("0")
        ):
            raise WebhookTransportError("invalid_response", retryable=False)
        length = int(content_length)
        if length > config.max_response_body_bytes:
            raise WebhookTransportError("response_body_too_large", retryable=False)
        if length:
            await reader.readexactly(length)
        return length

    return await _discard_until_eof(reader, config.max_response_body_bytes)


async def _discard_until_eof(reader: asyncio.StreamReader, limit: int) -> int:
    total = 0
    while True:
        chunk = await reader.read(min(8_192, limit - total + 1))
        if not chunk:
            return total
        total += len(chunk)
        if total > limit:
            raise WebhookTransportError("response_body_too_large", retryable=False)


async def _discard_chunked_body(
    reader: asyncio.StreamReader,
    config: WebhookTransportConfig,
) -> int:
    total = 0
    while True:
        line = await _bounded_readline(reader, 128)
        raw_size = line[:-2]
        if b";" in raw_size or _HEX_PATTERN.fullmatch(raw_size) is None:
            raise WebhookTransportError("invalid_chunked_response", retryable=False)
        size = int(raw_size, 16)
        if size == 0:
            trailer = await _bounded_readline(reader, MAX_WEBHOOK_RESPONSE_LINE_BYTES)
            if trailer != b"\r\n":
                raise WebhookTransportError("response_trailers_rejected", retryable=False)
            return total
        total += size
        if total > config.max_response_body_bytes:
            raise WebhookTransportError("response_body_too_large", retryable=False)
        await reader.readexactly(size)
        if await reader.readexactly(2) != b"\r\n":
            raise WebhookTransportError("invalid_chunked_response", retryable=False)


async def _bounded_readline(reader: asyncio.StreamReader, limit: int) -> bytes:
    try:
        line = await reader.readline()
    except ValueError as exception:
        raise WebhookTransportError("response_line_too_large", retryable=False) from exception
    if not line or len(line) > limit or not line.endswith(b"\r\n"):
        raise WebhookTransportError("invalid_response", retryable=False)
    return line


def _classify_response(status_code: int, response_body_bytes: int) -> WebhookTransportResult:
    status_class = _status_class(status_code)
    if status_class is WebhookHttpStatusClass.SUCCESSFUL:
        return WebhookTransportResult(
            status_code=status_code,
            status_class=status_class,
            successful=True,
            retryable=False,
            error_category=None,
            response_body_bytes=response_body_bytes,
        )
    if status_class is WebhookHttpStatusClass.REDIRECTION:
        category, retryable = "http_redirect", False
    elif status_class is WebhookHttpStatusClass.CLIENT_ERROR:
        category = (
            "http_client_retryable"
            if status_code in _RETRYABLE_CLIENT_STATUSES
            else "http_client_error"
        )
        retryable = status_code in _RETRYABLE_CLIENT_STATUSES
    elif status_class is WebhookHttpStatusClass.SERVER_ERROR:
        category, retryable = "http_server_error", True
    else:
        category, retryable = "http_informational", False
    return WebhookTransportResult(
        status_code=status_code,
        status_class=status_class,
        successful=False,
        retryable=retryable,
        error_category=category,
        response_body_bytes=response_body_bytes,
    )


def _status_class(status_code: int) -> WebhookHttpStatusClass:
    return {
        1: WebhookHttpStatusClass.INFORMATIONAL,
        2: WebhookHttpStatusClass.SUCCESSFUL,
        3: WebhookHttpStatusClass.REDIRECTION,
        4: WebhookHttpStatusClass.CLIENT_ERROR,
        5: WebhookHttpStatusClass.SERVER_ERROR,
    }[status_code // 100]


def _effective_address(address: _WebhookIpAddress) -> _WebhookIpAddress:
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped
    return address


def _address_sort_key(value: str) -> tuple[int, int]:
    return _ip_sort_key(ipaddress.ip_address(value))


def _ip_sort_key(address: _WebhookIpAddress) -> tuple[int, int]:
    return address.version, int(address)
