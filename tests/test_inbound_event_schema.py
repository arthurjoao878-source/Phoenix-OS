from __future__ import annotations

import asyncio
import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

import pytest

from phoenix_os.inbound_events import (
    InboundEventSchema,
    InboundEventSource,
    InboundHmacPolicy,
    InboundNormalizerError,
    InboundPayloadValidationError,
    InboundSchemaRegistrationError,
    InboundSchemaRegistry,
)
from phoenix_os.secrets import SecretRef

_NOW = datetime(2026, 7, 25, 12, 0, tzinfo=UTC)
_SOURCE_ID = UUID("00000000-0000-4000-8000-000000000025")


def _schema(**overrides: object) -> InboundEventSchema:
    values: dict[str, object] = {
        "event_type": "release.completed",
        "event_schema_version": 1,
        "internal_event_type": "external.release.completed",
        "required_fields": frozenset({"release", "status"}),
        "optional_fields": frozenset({"metadata"}),
        "max_raw_body_bytes": 4_096,
        "max_normalized_payload_bytes": 2_048,
        "max_json_depth": 4,
        "max_mapping_items": 8,
        "max_sequence_items": 8,
        "max_string_length": 64,
    }
    values.update(overrides)
    return InboundEventSchema(**values)  # type: ignore[arg-type]


@dataclass(frozen=True)
class _Normalizer:
    schema: InboundEventSchema

    def normalize(
        self,
        payload: Mapping[str, object],
    ) -> Mapping[str, object]:
        return {
            "release": payload["release"],
            "status": payload["status"],
        }


@dataclass(frozen=True)
class _AsyncNormalizer:
    schema: InboundEventSchema

    async def normalize(
        self,
        payload: Mapping[str, object],
    ) -> Mapping[str, object]:
        await asyncio.sleep(0)
        return {"release": payload["release"], "status": payload["status"]}


@dataclass(frozen=True)
class _FailingNormalizer:
    schema: InboundEventSchema

    def normalize(
        self,
        payload: Mapping[str, object],
    ) -> Mapping[str, object]:
        del payload
        raise RuntimeError("private normalizer failure")


def _source(*, event_types: frozenset[str] | None = None) -> InboundEventSource:
    return InboundEventSource(
        id=_SOURCE_ID,
        name="release.events",
        display_name="Release Events",
        authentication=InboundHmacPolicy(SecretRef("release-inbound", "integrations", 1)),
        event_types=event_types or frozenset({"release.completed"}),
        created_at=_NOW,
        updated_at=_NOW,
        created_by="maintainer:test",
    )


def _body(
    *,
    payload: object | None = None,
    event_type: str = "release.completed",
    event_schema_version: int = 1,
) -> bytes:
    return json.dumps(
        {
            "schema_version": 1,
            "event_type": event_type,
            "event_schema_version": event_schema_version,
            "occurred_at": "2026-07-25T11:59:59Z",
            "payload": (
                {"release": "0.25.0", "status": "completed"} if payload is None else payload
            ),
        },
        separators=(",", ":"),
    ).encode()


def test_registry_is_explicit_bounded_and_rejects_replacement() -> None:
    registry = InboundSchemaRegistry(capacity=1)
    normalizer = _Normalizer(_schema())
    registry.register(normalizer)

    assert registry.resolve("release.completed", 1) is normalizer
    assert registry.snapshot().registrations == 1
    assert registry.snapshot().event_types == 1

    with pytest.raises(InboundSchemaRegistrationError, match="already"):
        registry.register(normalizer)
    with pytest.raises(InboundSchemaRegistrationError, match="capacity"):
        registry.register(
            _Normalizer(
                _schema(
                    event_type="release.created",
                    internal_event_type="external.release.created",
                )
            )
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("normalizer_type", [_Normalizer, _AsyncNormalizer])
async def test_registry_parses_and_normalizes_reviewed_schema(
    normalizer_type: type[_Normalizer] | type[_AsyncNormalizer],
) -> None:
    registry = InboundSchemaRegistry()
    registry.register(normalizer_type(_schema()))

    envelope = await registry.parse_and_normalize(_source(), _body())

    assert envelope.event_type == "release.completed"
    assert envelope.event_schema_version == 1
    assert envelope.internal_event_type == "external.release.completed"
    assert envelope.occurred_at == datetime(2026, 7, 25, 11, 59, 59, tzinfo=UTC)
    assert dict(envelope.normalized_payload) == {
        "release": "0.25.0",
        "status": "completed",
    }
    assert "0.25.0" not in repr(envelope)


@pytest.mark.asyncio
async def test_registry_rejects_unregistered_or_source_disallowed_schema() -> None:
    registry = InboundSchemaRegistry()
    registry.register(_Normalizer(_schema()))

    with pytest.raises(InboundPayloadValidationError):
        await registry.parse_and_normalize(
            _source(event_types=frozenset({"release.created"})),
            _body(),
        )
    with pytest.raises(InboundPayloadValidationError):
        await registry.parse_and_normalize(
            _source(),
            _body(event_schema_version=2),
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "body",
    [
        b"\xef\xbb\xbf{}",
        b'{"schema_version":1,"schema_version":1}',
        b'{"schema_version":1}',
        b"[]",
        b'{"schema_version":NaN}',
        b"\xff",
    ],
)
async def test_registry_rejects_malformed_or_ambiguous_json(body: bytes) -> None:
    registry = InboundSchemaRegistry()
    registry.register(_Normalizer(_schema()))

    with pytest.raises(InboundPayloadValidationError):
        await registry.parse_and_normalize(_source(), body)


@pytest.mark.asyncio
async def test_registry_enforces_fields_depth_width_and_string_bounds() -> None:
    registry = InboundSchemaRegistry()
    registry.register(_Normalizer(_schema()))

    invalid_payloads = (
        {"release": "0.25.0"},
        {"release": "0.25.0", "status": "completed", "unknown": True},
        {"release": "x" * 65, "status": "completed"},
        {
            "release": "0.25.0",
            "status": "completed",
            "metadata": {"a": {"b": {"c": {"d": "too-deep"}}}},
        },
        {
            "release": "0.25.0",
            "status": "completed",
            "metadata": list(range(9)),
        },
    )
    for payload in invalid_payloads:
        with pytest.raises(InboundPayloadValidationError):
            await registry.parse_and_normalize(_source(), _body(payload=payload))


@pytest.mark.asyncio
async def test_registry_wraps_normalizer_failures_without_private_details() -> None:
    registry = InboundSchemaRegistry()
    registry.register(_FailingNormalizer(_schema()))

    with pytest.raises(
        InboundNormalizerError,
        match="inbound event normalization failed",
    ) as raised:
        await registry.parse_and_normalize(_source(), _body())

    assert "private normalizer failure" not in str(raised.value)


@pytest.mark.asyncio
async def test_registry_rejects_oversized_normalized_output() -> None:
    @dataclass(frozen=True)
    class LargeNormalizer:
        schema: InboundEventSchema

        def normalize(
            self,
            payload: Mapping[str, object],
        ) -> Mapping[str, object]:
            del payload
            return {"release": "x" * 64, "status": "x" * 64}

    registry = InboundSchemaRegistry()
    registry.register(
        LargeNormalizer(
            _schema(
                max_normalized_payload_bytes=32,
            )
        )
    )

    with pytest.raises(InboundNormalizerError):
        await registry.parse_and_normalize(_source(), _body())
