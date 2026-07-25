"""Exact opt-in HTTP transport adapter for inbound event sources."""

from __future__ import annotations

import hashlib
import inspect
from collections.abc import Awaitable, Mapping
from dataclasses import dataclass, field
from http import HTTPStatus
from types import MappingProxyType
from typing import Protocol

from phoenix_os.inbound_events.authentication import (
    INBOUND_KEY_VERSION_HEADER,
    INBOUND_NONCE_HEADER,
    INBOUND_REQUEST_ID_HEADER,
    INBOUND_SIGNATURE_HEADER,
    INBOUND_SOURCE_EVENT_ID_HEADER,
    INBOUND_TIMESTAMP_HEADER,
    parse_inbound_timestamp,
)
from phoenix_os.inbound_events.contracts import (
    MAX_INBOUND_SOURCE_CAPACITY,
    InboundEventSource,
    InboundHmacPolicy,
    InboundRequestEvidence,
    InboundServiceAccountPolicy,
)

INBOUND_HTTP_PREFIX = "/v1/control-plane/inbound/"
INBOUND_CONTENT_TYPE = "application/json"
INBOUND_CORRELATION_ID_HEADER = "X-Phoenix-Correlation-Id"

_BROWSER_ONLY_HEADERS = frozenset(
    {
        "cookie",
        "x-phoenix-csrf",
        "x-phoenix-step-up",
    }
)
_BASE_SECURITY_HEADERS = frozenset(
    {
        INBOUND_REQUEST_ID_HEADER.lower(),
        INBOUND_SOURCE_EVENT_ID_HEADER.lower(),
        INBOUND_TIMESTAMP_HEADER.lower(),
        INBOUND_NONCE_HEADER.lower(),
    }
)
_HMAC_HEADERS = frozenset(
    {
        INBOUND_SIGNATURE_HEADER.lower(),
        INBOUND_KEY_VERSION_HEADER.lower(),
    }
)
_OPTIONAL_SECURITY_HEADERS = frozenset({INBOUND_CORRELATION_ID_HEADER.lower()})
_ALL_INBOUND_SECURITY_HEADERS = _BASE_SECURITY_HEADERS | _HMAC_HEADERS | _OPTIONAL_SECURITY_HEADERS

InboundHttpResponse = tuple[
    HTTPStatus,
    Mapping[str, object],
    dict[str, str],
]


class InboundHttpHandler(Protocol):
    """Consume one transport-validated request."""

    def __call__(
        self,
        request: InboundHttpRequest,
        transport_context: object | None,
    ) -> InboundHttpResponse | Awaitable[InboundHttpResponse]: ...


@dataclass(frozen=True, slots=True, repr=False)
class InboundHttpRequest:
    """Bounded request facts with credential fields hidden from representation."""

    source: InboundEventSource
    evidence: InboundRequestEvidence
    target: str
    body: bytes = field(repr=False)
    signature: str | None = field(default=None, repr=False)
    key_version: str | None = field(default=None, repr=False)
    authorization: str | None = field(default=None, repr=False)
    schema_version: int = 1

    def __post_init__(self) -> None:
        if not isinstance(self.source, InboundEventSource):
            raise TypeError("inbound HTTP request source is invalid")
        if not isinstance(self.evidence, InboundRequestEvidence):
            raise TypeError("inbound HTTP request evidence is invalid")
        if self.evidence.source_id != self.source.id:
            raise ValueError("inbound HTTP request evidence belongs to another source")
        expected_target = inbound_http_path(self.source)
        if self.target != expected_target:
            raise ValueError("inbound HTTP request target is invalid")
        if type(self.body) is not bytes or not self.body:
            raise ValueError("inbound HTTP request body must be non-empty bytes")
        if len(self.body) > self.source.max_body_bytes:
            raise ValueError("inbound HTTP request body exceeds source bounds")
        if self.schema_version != 1:
            raise ValueError("unsupported inbound HTTP request schema version")

        authentication = self.source.authentication
        if isinstance(authentication, InboundHmacPolicy):
            if self.signature is None or self.key_version is None:
                raise ValueError("inbound HMAC request requires signature headers")
            if self.authorization is not None:
                raise ValueError("inbound HMAC request cannot contain authorization")
        elif isinstance(authentication, InboundServiceAccountPolicy):
            if self.authorization is None:
                raise ValueError("inbound service-account request requires authorization")
            if self.signature is not None or self.key_version is not None:
                raise ValueError("inbound service-account request cannot contain HMAC headers")
        else:  # pragma: no cover - source contract invariant
            raise TypeError("inbound HTTP request authentication mode is invalid")

    def __repr__(self) -> str:
        return (
            "InboundHttpRequest("
            f"source_id={self.source.id!r}, "
            f"target={self.target!r}, "
            f"evidence={self.evidence!r}, "
            "body=<redacted>, credentials=<redacted>)"
        )


@dataclass(frozen=True, slots=True)
class InboundHttpRoute:
    """One exact source route registered only by explicit composition."""

    source: InboundEventSource
    handler: InboundHttpHandler = field(repr=False)
    schema_version: int = 1

    def __post_init__(self) -> None:
        if not isinstance(self.source, InboundEventSource):
            raise TypeError("inbound HTTP route source is invalid")
        if not callable(self.handler):
            raise TypeError("inbound HTTP route handler must be callable")
        if self.schema_version != 1:
            raise ValueError("unsupported inbound HTTP route schema version")

    @property
    def path(self) -> str:
        return inbound_http_path(self.source)


class InboundHttpAdapter:
    """Validate exact inbound routes before authentication or JSON parsing."""

    def __init__(self, routes: tuple[InboundHttpRoute, ...]) -> None:
        if not routes:
            raise ValueError("inbound HTTP adapter requires at least one explicit route")
        if len(routes) > MAX_INBOUND_SOURCE_CAPACITY:
            raise ValueError("inbound HTTP route capacity has been exceeded")
        indexed: dict[str, InboundHttpRoute] = {}
        for route in routes:
            if not isinstance(route, InboundHttpRoute):
                raise TypeError("inbound HTTP routes contain an invalid value")
            if route.path in indexed:
                raise ValueError("duplicate inbound HTTP source route")
            indexed[route.path] = route
        self._routes = MappingProxyType(indexed)

    def handles(self, path: str) -> bool:
        return path in self._routes

    def body_limit(self, path: str) -> int:
        route = self._routes.get(path)
        if route is None:
            raise KeyError("inbound HTTP route is not registered")
        return route.source.max_body_bytes

    async def dispatch(
        self,
        *,
        method: str,
        path: str,
        query: Mapping[str, tuple[str, ...]],
        headers: Mapping[str, tuple[str, ...]],
        body: bytes,
        transport_context: object | None,
    ) -> InboundHttpResponse:
        route = self._routes.get(path)
        if route is None:
            return _response(HTTPStatus.NOT_FOUND, "not_found")
        if method.strip().upper() != "POST":
            return (
                HTTPStatus.METHOD_NOT_ALLOWED,
                {"error": "method_not_allowed"},
                {"Allow": "POST", "Cache-Control": "no-store"},
            )
        if query:
            return _response(HTTPStatus.BAD_REQUEST, "invalid_query")

        try:
            request = _validated_request(route.source, path, headers, body)
        except _InboundHttpFailure as failure:
            return _response(failure.status, failure.code)

        result = route.handler(request, transport_context)
        if inspect.isawaitable(result):
            result = await result
        status, payload, response_headers = _validate_handler_response(result)
        merged = dict(response_headers)
        merged["Cache-Control"] = "no-store"
        return status, payload, merged


def inbound_http_path(source: InboundEventSource) -> str:
    if not isinstance(source, InboundEventSource):
        raise TypeError("inbound HTTP path requires InboundEventSource")
    return f"{INBOUND_HTTP_PREFIX}{source.name}"


def _validated_request(
    source: InboundEventSource,
    path: str,
    headers: Mapping[str, tuple[str, ...]],
    body: bytes,
) -> InboundHttpRequest:
    normalized = _normalize_headers(headers)
    if _header_bytes(normalized) > source.max_header_bytes:
        raise _InboundHttpFailure(
            HTTPStatus.REQUEST_HEADER_FIELDS_TOO_LARGE,
            "headers_too_large",
        )
    if any(normalized.get(name) for name in _BROWSER_ONLY_HEADERS):
        raise _InboundHttpFailure(HTTPStatus.FORBIDDEN, "request_rejected")
    if any(
        name.startswith("x-phoenix-inbound-") and name not in _ALL_INBOUND_SECURITY_HEADERS
        for name in normalized
    ):
        raise _InboundHttpFailure(HTTPStatus.BAD_REQUEST, "invalid_security_headers")
    _required_single(normalized, "host")
    content_type = _required_single(normalized, "content-type")
    if content_type != INBOUND_CONTENT_TYPE:
        raise _InboundHttpFailure(
            HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
            "unsupported_media_type",
        )
    if normalized.get("content-encoding"):
        raise _InboundHttpFailure(
            HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
            "unsupported_content_encoding",
        )
    if type(body) is not bytes or not body:
        raise _InboundHttpFailure(HTTPStatus.BAD_REQUEST, "invalid_request")
    if len(body) > source.max_body_bytes:
        raise _InboundHttpFailure(
            HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
            "request_body_too_large",
        )

    request_id = _required_single(normalized, INBOUND_REQUEST_ID_HEADER.lower())
    source_event_id = _required_single(
        normalized,
        INBOUND_SOURCE_EVENT_ID_HEADER.lower(),
    )
    timestamp = _required_single(normalized, INBOUND_TIMESTAMP_HEADER.lower())
    nonce = _required_single(normalized, INBOUND_NONCE_HEADER.lower())
    correlation_id = _optional_single(
        normalized,
        INBOUND_CORRELATION_ID_HEADER.lower(),
    )

    signature: str | None = None
    key_version: str | None = None
    authorization: str | None = None
    if isinstance(source.authentication, InboundHmacPolicy):
        signature = _required_single(normalized, INBOUND_SIGNATURE_HEADER.lower())
        key_version = _required_single(
            normalized,
            INBOUND_KEY_VERSION_HEADER.lower(),
        )
        if _optional_single(normalized, "authorization") is not None:
            raise _InboundHttpFailure(
                HTTPStatus.BAD_REQUEST,
                "invalid_authentication_mode",
            )
    elif isinstance(source.authentication, InboundServiceAccountPolicy):
        authorization = _required_single(normalized, "authorization")
        if (
            _optional_single(normalized, INBOUND_SIGNATURE_HEADER.lower()) is not None
            or _optional_single(
                normalized,
                INBOUND_KEY_VERSION_HEADER.lower(),
            )
            is not None
        ):
            raise _InboundHttpFailure(
                HTTPStatus.BAD_REQUEST,
                "invalid_authentication_mode",
            )
    else:  # pragma: no cover - source contract invariant
        raise _InboundHttpFailure(
            HTTPStatus.SERVICE_UNAVAILABLE,
            "service_unavailable",
        )

    try:
        evidence = InboundRequestEvidence(
            source_id=source.id,
            request_id=request_id,
            source_event_id=source_event_id,
            nonce=nonce,
            timestamp=parse_inbound_timestamp(timestamp),
            body_sha256=hashlib.sha256(body).hexdigest(),
            correlation_id=correlation_id,
        )
        return InboundHttpRequest(
            source=source,
            evidence=evidence,
            target=path,
            body=body,
            signature=signature,
            key_version=key_version,
            authorization=authorization,
        )
    except (TypeError, ValueError):
        raise _InboundHttpFailure(
            HTTPStatus.BAD_REQUEST,
            "invalid_security_headers",
        ) from None


def _normalize_headers(
    headers: Mapping[str, tuple[str, ...]],
) -> dict[str, tuple[str, ...]]:
    if not isinstance(headers, Mapping):
        raise _InboundHttpFailure(HTTPStatus.BAD_REQUEST, "malformed_headers")
    result: dict[str, tuple[str, ...]] = {}
    for raw_name, raw_values in headers.items():
        if not isinstance(raw_name, str):
            raise _InboundHttpFailure(HTTPStatus.BAD_REQUEST, "malformed_headers")
        name = raw_name.strip().lower()
        if not name or name != raw_name:
            raise _InboundHttpFailure(HTTPStatus.BAD_REQUEST, "malformed_headers")
        values = tuple(raw_values)
        if not all(isinstance(value, str) for value in values):
            raise _InboundHttpFailure(HTTPStatus.BAD_REQUEST, "malformed_headers")
        result[name] = values
    return result


def _required_single(
    headers: Mapping[str, tuple[str, ...]],
    name: str,
) -> str:
    values = headers.get(name, ())
    if len(values) != 1 or not values[0]:
        raise _InboundHttpFailure(
            HTTPStatus.BAD_REQUEST,
            "invalid_security_headers",
        )
    return values[0]


def _optional_single(
    headers: Mapping[str, tuple[str, ...]],
    name: str,
) -> str | None:
    values = headers.get(name, ())
    if not values:
        return None
    if len(values) != 1 or not values[0]:
        raise _InboundHttpFailure(
            HTTPStatus.BAD_REQUEST,
            "invalid_security_headers",
        )
    return values[0]


def _header_bytes(headers: Mapping[str, tuple[str, ...]]) -> int:
    return sum(
        len(name.encode("ascii", "ignore"))
        + sum(len(value.encode("iso-8859-1", "ignore")) + 4 for value in values)
        + 2
        for name, values in headers.items()
    )


def _validate_handler_response(value: object) -> InboundHttpResponse:
    if not isinstance(value, tuple) or len(value) != 3:
        raise TypeError("inbound HTTP handler returned an invalid response")
    status, payload, headers = value
    if not isinstance(status, HTTPStatus):
        raise TypeError("inbound HTTP handler status must be HTTPStatus")
    if not isinstance(payload, Mapping):
        raise TypeError("inbound HTTP handler payload must be a mapping")
    if not isinstance(headers, dict) or not all(
        isinstance(name, str) and isinstance(item, str) for name, item in headers.items()
    ):
        raise TypeError("inbound HTTP handler headers must contain strings")
    return status, payload, headers


def _response(status: HTTPStatus, code: str) -> InboundHttpResponse:
    return status, {"error": code}, {"Cache-Control": "no-store"}


@dataclass(frozen=True, slots=True)
class _InboundHttpFailure(Exception):
    status: HTTPStatus
    code: str
