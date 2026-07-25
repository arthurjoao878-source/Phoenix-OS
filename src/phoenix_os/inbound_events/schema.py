"""Explicit schema registry and bounded normalization for inbound events."""

from __future__ import annotations

import asyncio
import inspect
import json
import math
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from types import MappingProxyType

from phoenix_os.inbound_events.contracts import (
    MAX_INBOUND_JSON_ITEMS,
    InboundEventNormalizer,
    InboundEventSchema,
    InboundEventSource,
    canonical_inbound_json_bytes,
)
from phoenix_os.inbound_events.errors import (
    InboundNormalizerError,
    InboundPayloadValidationError,
    InboundSchemaRegistrationError,
)

MAX_INBOUND_SCHEMA_REGISTRATIONS = 4_096

_EVENT_TYPE_PATTERN = re.compile(r"[a-z][a-z0-9._-]{2,127}\Z")
_TIMESTAMP_PATTERN = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")
_ENVELOPE_FIELDS = frozenset(
    {
        "schema_version",
        "event_type",
        "event_schema_version",
        "occurred_at",
        "payload",
    }
)


@dataclass(frozen=True, slots=True, repr=False)
class InboundNormalizedEnvelope:
    """Validated external envelope and reviewed normalized payload."""

    event_type: str
    event_schema_version: int
    internal_event_type: str
    occurred_at: datetime
    normalized_payload: Mapping[str, object] = field(repr=False)
    schema_version: int = 1

    def __post_init__(self) -> None:
        event_type = _canonical_event_type(self.event_type)
        internal_event_type = _canonical_event_type(self.internal_event_type)
        occurred_at = _aware_utc(self.occurred_at)
        if self.event_schema_version <= 0:
            raise ValueError("inbound normalized envelope schema version must be positive")
        if not isinstance(self.normalized_payload, Mapping):
            raise TypeError("inbound normalized envelope payload must be a mapping")
        if self.schema_version != 1:
            raise ValueError("unsupported inbound normalized envelope schema version")
        object.__setattr__(self, "event_type", event_type)
        object.__setattr__(self, "internal_event_type", internal_event_type)
        object.__setattr__(self, "occurred_at", occurred_at)
        object.__setattr__(
            self,
            "normalized_payload",
            MappingProxyType(dict(self.normalized_payload)),
        )

    def __repr__(self) -> str:
        return (
            "InboundNormalizedEnvelope("
            f"event_type={self.event_type!r}, "
            f"event_schema_version={self.event_schema_version!r}, "
            f"internal_event_type={self.internal_event_type!r}, "
            f"occurred_at={self.occurred_at!r}, "
            "normalized_payload=<redacted>)"
        )


@dataclass(frozen=True, slots=True)
class InboundSchemaRegistrySnapshot:
    """Safe deterministic registry diagnostics."""

    registrations: int
    capacity: int
    event_types: int
    schema_version: int = 1

    def __post_init__(self) -> None:
        if not 0 <= self.registrations <= self.capacity:
            raise ValueError("inbound schema registration count is inconsistent")
        if not 0 <= self.event_types <= self.registrations:
            raise ValueError("inbound schema event-type count is inconsistent")
        if not 1 <= self.capacity <= MAX_INBOUND_SCHEMA_REGISTRATIONS:
            raise ValueError("inbound schema registry capacity is outside bounds")
        if self.schema_version != 1:
            raise ValueError("unsupported inbound schema registry snapshot version")


class InboundSchemaRegistry:
    """Code-reviewed registry without dynamic replacement or arbitrary event names."""

    def __init__(self, *, capacity: int = 256) -> None:
        if not 1 <= capacity <= MAX_INBOUND_SCHEMA_REGISTRATIONS:
            raise ValueError(
                "inbound schema registry capacity must be between "
                f"1 and {MAX_INBOUND_SCHEMA_REGISTRATIONS}"
            )
        self._capacity = capacity
        self._normalizers: dict[tuple[str, int], InboundEventNormalizer] = {}

    def register(self, normalizer: InboundEventNormalizer) -> None:
        schema = getattr(normalizer, "schema", None)
        if not isinstance(schema, InboundEventSchema):
            raise TypeError("inbound normalizer must expose InboundEventSchema")
        if not callable(getattr(normalizer, "normalize", None)):
            raise TypeError("inbound normalizer must provide normalize")
        key = (schema.event_type, schema.event_schema_version)
        if key in self._normalizers:
            raise InboundSchemaRegistrationError("inbound event schema is already registered")
        if len(self._normalizers) >= self._capacity:
            raise InboundSchemaRegistrationError(
                "inbound schema registry capacity has been exhausted"
            )
        self._normalizers[key] = normalizer

    def resolve(
        self,
        event_type: str,
        event_schema_version: int,
    ) -> InboundEventNormalizer:
        canonical_type = _canonical_event_type(event_type)
        if event_schema_version <= 0:
            raise InboundPayloadValidationError
        normalizer = self._normalizers.get((canonical_type, event_schema_version))
        if normalizer is None:
            raise InboundPayloadValidationError
        return normalizer

    async def parse_and_normalize(
        self,
        source: InboundEventSource,
        body: bytes,
    ) -> InboundNormalizedEnvelope:
        """Strictly parse one bounded JSON envelope and invoke a reviewed normalizer."""

        if not isinstance(source, InboundEventSource):
            raise TypeError("inbound schema parsing requires InboundEventSource")
        if type(body) is not bytes:
            raise TypeError("inbound schema body must be bytes")
        if not body or len(body) > source.max_body_bytes:
            raise InboundPayloadValidationError

        document = _decode_document(body)
        if frozenset(document) != _ENVELOPE_FIELDS:
            raise InboundPayloadValidationError

        schema_version = _integer(document.get("schema_version"))
        if schema_version != 1:
            raise InboundPayloadValidationError
        event_type = _canonical_event_type(_string(document.get("event_type")))
        event_schema_version = _integer(document.get("event_schema_version"))
        if event_schema_version <= 0 or event_type not in source.event_types:
            raise InboundPayloadValidationError
        occurred_at = _parse_timestamp(_string(document.get("occurred_at")))
        payload = document.get("payload")
        if not isinstance(payload, Mapping):
            raise InboundPayloadValidationError

        normalizer = self.resolve(event_type, event_schema_version)
        schema = normalizer.schema
        if len(body) > schema.max_raw_body_bytes:
            raise InboundPayloadValidationError

        validated_payload = _validate_payload(payload, schema)
        try:
            normalized_result = normalizer.normalize(validated_payload)
            if inspect.isawaitable(normalized_result):
                normalized_result = await normalized_result
        except asyncio.CancelledError:
            raise
        except Exception:
            raise InboundNormalizerError from None

        if not isinstance(normalized_result, Mapping):
            raise InboundNormalizerError
        normalized = _validate_json_mapping(
            normalized_result,
            schema=schema,
            validate_declared_fields=False,
        )
        canonical = canonical_inbound_json_bytes(normalized)
        if len(canonical) > schema.max_normalized_payload_bytes:
            raise InboundNormalizerError

        return InboundNormalizedEnvelope(
            event_type=event_type,
            event_schema_version=event_schema_version,
            internal_event_type=schema.internal_event_type,
            occurred_at=occurred_at,
            normalized_payload=normalized,
        )

    def snapshot(self) -> InboundSchemaRegistrySnapshot:
        return InboundSchemaRegistrySnapshot(
            registrations=len(self._normalizers),
            capacity=self._capacity,
            event_types=len({event_type for event_type, _ in self._normalizers}),
        )


def _decode_document(body: bytes) -> Mapping[str, object]:
    try:
        text = body.decode("utf-8")
        if text.startswith("\ufeff"):
            raise ValueError("JSON byte order marks are unsupported")
        value = json.loads(
            text,
            object_pairs_hook=_strict_object,
            parse_constant=_reject_constant,
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        RecursionError,
        ValueError,
    ):
        raise InboundPayloadValidationError from None
    if not isinstance(value, Mapping):
        raise InboundPayloadValidationError
    return value


def _strict_object(pairs: Sequence[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(value: str) -> object:
    raise ValueError(f"unsupported JSON constant: {value}")


def _validate_payload(
    payload: Mapping[str, object],
    schema: InboundEventSchema,
) -> dict[str, object]:
    supplied = frozenset(payload)
    if not schema.required_fields.issubset(supplied):
        raise InboundPayloadValidationError
    if schema.reject_unknown_fields and not supplied.issubset(schema.allowed_fields):
        raise InboundPayloadValidationError
    return _validate_json_mapping(
        payload,
        schema=schema,
        validate_declared_fields=True,
    )


def _validate_json_mapping(
    payload: Mapping[str, object],
    *,
    schema: InboundEventSchema,
    validate_declared_fields: bool,
) -> dict[str, object]:
    budget = [MAX_INBOUND_JSON_ITEMS]
    validated = _validate_json_value(
        payload,
        schema=schema,
        depth=0,
        budget=budget,
    )
    if not isinstance(validated, dict):
        raise InboundPayloadValidationError
    if validate_declared_fields:
        supplied = frozenset(validated)
        if not schema.required_fields.issubset(supplied):
            raise InboundPayloadValidationError
    return validated


def _validate_json_value(
    value: object,
    *,
    schema: InboundEventSchema,
    depth: int,
    budget: list[int],
) -> object:
    if depth > schema.max_json_depth:
        raise InboundPayloadValidationError
    budget[0] -= 1
    if budget[0] < 0:
        raise InboundPayloadValidationError

    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, str):
        if len(value) > schema.max_string_length:
            raise InboundPayloadValidationError
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise InboundPayloadValidationError
        return value
    if isinstance(value, Mapping):
        if len(value) > schema.max_mapping_items:
            raise InboundPayloadValidationError
        result: dict[str, object] = {}
        for key, item in value.items():
            if not isinstance(key, str) or len(key) > schema.max_string_length:
                raise InboundPayloadValidationError
            result[key] = _validate_json_value(
                item,
                schema=schema,
                depth=depth + 1,
                budget=budget,
            )
        return result
    if isinstance(value, list):
        if len(value) > schema.max_sequence_items:
            raise InboundPayloadValidationError
        return [
            _validate_json_value(
                item,
                schema=schema,
                depth=depth + 1,
                budget=budget,
            )
            for item in value
        ]
    raise InboundPayloadValidationError


def _canonical_event_type(value: str) -> str:
    if not isinstance(value, str):
        raise InboundPayloadValidationError
    if value != value.strip().lower() or _EVENT_TYPE_PATTERN.fullmatch(value) is None:
        raise InboundPayloadValidationError
    return value


def _parse_timestamp(value: str) -> datetime:
    if _TIMESTAMP_PATTERN.fullmatch(value) is None:
        raise InboundPayloadValidationError
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError:
        raise InboundPayloadValidationError from None


def _aware_utc(value: datetime) -> datetime:
    if not isinstance(value, datetime):
        raise TypeError("inbound normalized occurred_at must be datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("inbound normalized occurred_at must be timezone-aware")
    return value.astimezone(UTC).replace(microsecond=0)


def _integer(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise InboundPayloadValidationError
    return value


def _string(value: object) -> str:
    if not isinstance(value, str):
        raise InboundPayloadValidationError
    return value
