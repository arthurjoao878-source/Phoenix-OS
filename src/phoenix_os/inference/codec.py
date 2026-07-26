"""Strict bounded schema-v1 codecs for inference transport contracts."""

from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import datetime
from typing import cast
from uuid import UUID

from phoenix_os.inference.contracts import (
    InferenceChunk,
    InferenceFinishReason,
    InferenceMessage,
    InferenceParameter,
    InferenceRequest,
    InferenceResponse,
    InferenceRole,
    InferenceUsage,
    ModelId,
    ModelProviderId,
)
from phoenix_os.inference.errors import InferenceCodecError

_SCHEMA_VERSION = 1
_REQUEST_KIND = "phoenix.inference.request"
_RESPONSE_KIND = "phoenix.inference.response"
_CHUNK_KIND = "phoenix.inference.chunk"

MAX_INFERENCE_REQUEST_DOCUMENT_BYTES = 1_048_576
MAX_INFERENCE_RESPONSE_DOCUMENT_BYTES = 2_097_152
MAX_INFERENCE_CHUNK_DOCUMENT_BYTES = 131_072

_ENVELOPE_FIELDS = frozenset({"schema_version", "kind", "record"})
_REQUEST_FIELDS = frozenset(
    {
        "request_id",
        "provider_id",
        "model_id",
        "messages",
        "max_output_tokens",
        "parameters",
        "metadata",
        "correlation_id",
        "created_at",
        "deadline",
    }
)
_MESSAGE_FIELDS = frozenset({"role", "content", "metadata"})
_RESPONSE_FIELDS = frozenset(
    {
        "request_id",
        "provider_id",
        "model_id",
        "text",
        "finish_reason",
        "usage",
        "created_at",
        "metadata",
    }
)
_CHUNK_FIELDS = frozenset(
    {
        "request_id",
        "provider_id",
        "model_id",
        "index",
        "text",
        "terminal",
        "finish_reason",
        "usage",
        "metadata",
    }
)
_USAGE_FIELDS = frozenset({"input_tokens", "output_tokens", "cached_input_tokens"})


def encode_inference_request(request: InferenceRequest) -> bytes:
    if not isinstance(request, InferenceRequest):
        raise TypeError("request must be InferenceRequest")
    return _encode(_REQUEST_KIND, _request_record(request), MAX_INFERENCE_REQUEST_DOCUMENT_BYTES)


def decode_inference_request(encoded: bytes) -> InferenceRequest:
    record = _decode(
        encoded,
        expected_kind=_REQUEST_KIND,
        maximum_bytes=MAX_INFERENCE_REQUEST_DOCUMENT_BYTES,
    )
    _require_exact_fields(record, _REQUEST_FIELDS, label="request record")
    try:
        messages = tuple(
            _decode_message(_mapping(item, label="message"))
            for item in _list(record.get("messages"), label="messages")
        )
        request = InferenceRequest(
            request_id=_uuid(record, "request_id"),
            provider_id=ModelProviderId(_string(record, "provider_id")),
            model_id=ModelId(_string(record, "model_id")),
            messages=messages,
            max_output_tokens=_integer(record, "max_output_tokens"),
            parameters=_parameters(record.get("parameters")),
            metadata=_string_mapping(record.get("metadata"), label="request metadata"),
            correlation_id=_optional_string(record, "correlation_id"),
            created_at=_datetime(record, "created_at"),
            deadline=_datetime(record, "deadline"),
        )
    except InferenceCodecError:
        raise
    except (TypeError, ValueError, OverflowError) as exception:
        raise InferenceCodecError() from exception
    if encode_inference_request(request) != encoded:
        raise InferenceCodecError("inference request is not canonical")
    return request


def encode_inference_response(response: InferenceResponse) -> bytes:
    if not isinstance(response, InferenceResponse):
        raise TypeError("response must be InferenceResponse")
    return _encode(
        _RESPONSE_KIND,
        _response_record(response),
        MAX_INFERENCE_RESPONSE_DOCUMENT_BYTES,
    )


def decode_inference_response(encoded: bytes) -> InferenceResponse:
    record = _decode(
        encoded,
        expected_kind=_RESPONSE_KIND,
        maximum_bytes=MAX_INFERENCE_RESPONSE_DOCUMENT_BYTES,
    )
    _require_exact_fields(record, _RESPONSE_FIELDS, label="response record")
    try:
        response = InferenceResponse(
            request_id=_uuid(record, "request_id"),
            provider_id=ModelProviderId(_string(record, "provider_id")),
            model_id=ModelId(_string(record, "model_id")),
            text=_string(record, "text"),
            finish_reason=InferenceFinishReason(_string(record, "finish_reason")),
            usage=_decode_usage(_mapping(record.get("usage"), label="usage")),
            created_at=_datetime(record, "created_at"),
            metadata=_string_mapping(record.get("metadata"), label="response metadata"),
        )
    except InferenceCodecError:
        raise
    except (TypeError, ValueError, OverflowError) as exception:
        raise InferenceCodecError() from exception
    if encode_inference_response(response) != encoded:
        raise InferenceCodecError("inference response is not canonical")
    return response


def encode_inference_chunk(chunk: InferenceChunk) -> bytes:
    if not isinstance(chunk, InferenceChunk):
        raise TypeError("chunk must be InferenceChunk")
    return _encode(_CHUNK_KIND, _chunk_record(chunk), MAX_INFERENCE_CHUNK_DOCUMENT_BYTES)


def decode_inference_chunk(encoded: bytes) -> InferenceChunk:
    record = _decode(
        encoded,
        expected_kind=_CHUNK_KIND,
        maximum_bytes=MAX_INFERENCE_CHUNK_DOCUMENT_BYTES,
    )
    _require_exact_fields(record, _CHUNK_FIELDS, label="chunk record")
    finish_value = record.get("finish_reason")
    usage_value = record.get("usage")
    try:
        chunk = InferenceChunk(
            request_id=_uuid(record, "request_id"),
            provider_id=ModelProviderId(_string(record, "provider_id")),
            model_id=ModelId(_string(record, "model_id")),
            index=_integer(record, "index"),
            text=_string(record, "text"),
            terminal=_boolean(record, "terminal"),
            finish_reason=(
                None
                if finish_value is None
                else InferenceFinishReason(_require_string(finish_value, label="finish_reason"))
            ),
            usage=(
                None if usage_value is None else _decode_usage(_mapping(usage_value, label="usage"))
            ),
            metadata=_string_mapping(record.get("metadata"), label="chunk metadata"),
        )
    except InferenceCodecError:
        raise
    except (TypeError, ValueError, OverflowError) as exception:
        raise InferenceCodecError() from exception
    if encode_inference_chunk(chunk) != encoded:
        raise InferenceCodecError("inference chunk is not canonical")
    return chunk


def canonical_inference_request_bytes(request: InferenceRequest) -> bytes:
    return encode_inference_request(request)


def canonical_inference_response_bytes(response: InferenceResponse) -> bytes:
    return encode_inference_response(response)


def canonical_inference_chunk_bytes(chunk: InferenceChunk) -> bytes:
    return encode_inference_chunk(chunk)


def _request_record(request: InferenceRequest) -> dict[str, object]:
    return {
        "request_id": str(request.request_id),
        "provider_id": str(request.provider_id),
        "model_id": str(request.model_id),
        "messages": [_message_record(message) for message in request.messages],
        "max_output_tokens": request.max_output_tokens,
        "parameters": dict(request.parameters),
        "metadata": dict(request.metadata),
        "correlation_id": request.correlation_id,
        "created_at": request.created_at.isoformat(),
        "deadline": request.deadline.isoformat(),
    }


def _message_record(message: InferenceMessage) -> dict[str, object]:
    return {
        "role": message.role.value,
        "content": message.content,
        "metadata": dict(message.metadata),
    }


def _response_record(response: InferenceResponse) -> dict[str, object]:
    return {
        "request_id": str(response.request_id),
        "provider_id": str(response.provider_id),
        "model_id": str(response.model_id),
        "text": response.text,
        "finish_reason": response.finish_reason.value,
        "usage": _usage_record(response.usage),
        "created_at": response.created_at.isoformat(),
        "metadata": dict(response.metadata),
    }


def _chunk_record(chunk: InferenceChunk) -> dict[str, object]:
    return {
        "request_id": str(chunk.request_id),
        "provider_id": str(chunk.provider_id),
        "model_id": str(chunk.model_id),
        "index": chunk.index,
        "text": chunk.text,
        "terminal": chunk.terminal,
        "finish_reason": (None if chunk.finish_reason is None else chunk.finish_reason.value),
        "usage": None if chunk.usage is None else _usage_record(chunk.usage),
        "metadata": dict(chunk.metadata),
    }


def _usage_record(usage: InferenceUsage) -> dict[str, object]:
    return {
        "input_tokens": usage.input_tokens,
        "output_tokens": usage.output_tokens,
        "cached_input_tokens": usage.cached_input_tokens,
    }


def _decode_message(record: Mapping[str, object]) -> InferenceMessage:
    _require_exact_fields(record, _MESSAGE_FIELDS, label="message record")
    return InferenceMessage(
        role=InferenceRole(_string(record, "role")),
        content=_string(record, "content"),
        metadata=_string_mapping(record.get("metadata"), label="message metadata"),
    )


def _decode_usage(record: Mapping[str, object]) -> InferenceUsage:
    _require_exact_fields(record, _USAGE_FIELDS, label="usage record")
    return InferenceUsage(
        input_tokens=_integer(record, "input_tokens"),
        output_tokens=_integer(record, "output_tokens"),
        cached_input_tokens=_integer(record, "cached_input_tokens"),
    )


def _encode(kind: str, record: Mapping[str, object], maximum_bytes: int) -> bytes:
    document = {
        "schema_version": _SCHEMA_VERSION,
        "kind": kind,
        "record": record,
    }
    try:
        encoded = json.dumps(
            document,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, OverflowError) as exception:
        raise InferenceCodecError() from exception
    if len(encoded) > maximum_bytes:
        raise InferenceCodecError("inference document exceeds the maximum size")
    return encoded


def _decode(
    encoded: bytes,
    *,
    expected_kind: str,
    maximum_bytes: int,
) -> Mapping[str, object]:
    if not isinstance(encoded, bytes):
        raise TypeError("encoded inference document must be bytes")
    if not encoded or len(encoded) > maximum_bytes:
        raise InferenceCodecError()
    try:
        decoded: object = json.loads(encoded.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exception:
        raise InferenceCodecError() from exception
    envelope = _mapping(decoded, label="inference envelope")
    _require_exact_fields(envelope, _ENVELOPE_FIELDS, label="inference envelope")
    if _integer(envelope, "schema_version") != _SCHEMA_VERSION:
        raise InferenceCodecError("unsupported inference schema version")
    if _string(envelope, "kind") != expected_kind:
        raise InferenceCodecError("unexpected inference document kind")
    return _mapping(envelope.get("record"), label="inference record")


def _mapping(value: object, *, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise InferenceCodecError(f"{label} must be an object")
    raw = cast(Mapping[object, object], value)
    if any(not isinstance(key, str) for key in raw):
        raise InferenceCodecError(f"{label} keys must be strings")
    return cast(Mapping[str, object], raw)


def _list(value: object, *, label: str) -> list[object]:
    if not isinstance(value, list):
        raise InferenceCodecError(f"{label} must be an array")
    return cast(list[object], value)


def _require_exact_fields(
    value: Mapping[str, object],
    expected: frozenset[str],
    *,
    label: str,
) -> None:
    if frozenset(value) != expected:
        raise InferenceCodecError(f"{label} fields are invalid")


def _string(value: Mapping[str, object], key: str) -> str:
    return _require_string(value.get(key), label=key)


def _require_string(value: object, *, label: str) -> str:
    if not isinstance(value, str):
        raise InferenceCodecError(f"{label} must be a string")
    return value


def _optional_string(value: Mapping[str, object], key: str) -> str | None:
    item = value.get(key)
    if item is None:
        return None
    return _require_string(item, label=key)


def _integer(value: Mapping[str, object], key: str) -> int:
    item = value.get(key)
    if isinstance(item, bool) or not isinstance(item, int):
        raise InferenceCodecError(f"{key} must be an integer")
    return item


def _boolean(value: Mapping[str, object], key: str) -> bool:
    item = value.get(key)
    if not isinstance(item, bool):
        raise InferenceCodecError(f"{key} must be a boolean")
    return item


def _uuid(value: Mapping[str, object], key: str) -> UUID:
    try:
        return UUID(_string(value, key))
    except ValueError as exception:
        raise InferenceCodecError(f"{key} must be a UUID") from exception


def _datetime(value: Mapping[str, object], key: str) -> datetime:
    try:
        return datetime.fromisoformat(_string(value, key))
    except ValueError as exception:
        raise InferenceCodecError(f"{key} must be a datetime") from exception


def _string_mapping(value: object, *, label: str) -> Mapping[str, str]:
    mapping = _mapping(value, label=label)
    result: dict[str, str] = {}
    for key, item in mapping.items():
        result[key] = _require_string(item, label=f"{label} value")
    return result


def _parameters(value: object) -> Mapping[str, InferenceParameter]:
    mapping = _mapping(value, label="parameters")
    result: dict[str, InferenceParameter] = {}
    for key, item in mapping.items():
        if item is None or isinstance(item, (str, bool, int, float)):
            result[key] = item
        else:
            raise InferenceCodecError("parameter values must be scalar")
    return result
