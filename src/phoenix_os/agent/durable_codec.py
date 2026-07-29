"""Strict canonical codec for durable Phoenix agent checkpoint envelopes."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import replace
from datetime import datetime
from typing import NoReturn, cast
from uuid import UUID

from phoenix_os.agent.contracts import (
    AgentId,
    AgentRunId,
    AgentStepId,
    ToolCallId,
    ToolEffect,
)
from phoenix_os.agent.durable_contracts import (
    CURRENT_CHECKPOINT_SCHEMA_VERSION,
    MAX_CHECKPOINT_ENVELOPE_BYTES,
    CheckpointDigest,
    CheckpointEnvelope,
    CheckpointId,
    CheckpointMetadata,
    CheckpointNextOperation,
    CheckpointPayloadProfile,
    CheckpointSchemaVersion,
    CheckpointSequence,
    CompatibilityDigests,
    DurableAgentRunId,
    DurableRunStatus,
    DurableRunVersion,
    ExecutionAttempt,
    ExecutionAttemptId,
    ExecutionAttemptKind,
    ExecutionAttemptStatus,
    IndeterminateReason,
    ProtectedPayloadReference,
)
from phoenix_os.agent.errors import AgentCodecError
from phoenix_os.agent.state import AgentBudgetSnapshot

DURABLE_CHECKPOINT_CODEC_SCHEMA_VERSION = 1
MAX_DURABLE_CHECKPOINT_JSON_DEPTH = 64
MAX_DURABLE_CHECKPOINT_JSON_ITEMS = 65_536

_CHECKPOINT_KIND = "phoenix.agent.durable-checkpoint"
_CHECKPOINT_DIGEST_KIND = "phoenix.agent.durable-checkpoint-digest"

_DOCUMENT_FIELDS = frozenset({"schema_version", "kind", "record"})
_CHECKPOINT_FIELDS = frozenset(
    {
        "schema_version",
        "durable_run_id",
        "checkpoint_id",
        "sequence",
        "previous_digest",
        "run_version",
        "status",
        "agent_run_id",
        "step_id",
        "metadata",
        "created_at",
        "digest",
    }
)
_CHECKPOINT_DIGEST_FIELDS = frozenset(_CHECKPOINT_FIELDS - {"digest"})
_METADATA_FIELDS = frozenset(
    {
        "agent_id",
        "actor_id",
        "next_operation",
        "budget",
        "compatibility",
        "payload_profile",
        "retention_deadline",
        "active_attempt",
        "payload_reference",
        "metadata",
    }
)
_BUDGET_FIELDS = frozenset(
    {
        "steps",
        "model_turns",
        "tool_calls",
        "model_output_bytes",
        "tool_result_bytes",
        "input_tokens",
        "output_tokens",
        "started_at",
        "deadline",
    }
)
_COMPATIBILITY_FIELDS = frozenset(
    {
        "configuration",
        "tool_registry",
        "model_provider",
        "checkpoint_codec",
        "payload_codec",
    }
)
_ATTEMPT_FIELDS = frozenset(
    {
        "attempt_id",
        "kind",
        "status",
        "agent_run_id",
        "step_id",
        "prepared_at",
        "tool_call_id",
        "tool_effect",
        "started_at",
        "completed_at",
        "external_request_digest",
        "indeterminate_reason",
        "error_code",
    }
)
_PAYLOAD_REFERENCE_FIELDS = frozenset(
    {
        "reference",
        "key_version",
        "plaintext_bytes",
        "ciphertext_bytes",
        "ciphertext_digest",
        "created_at",
    }
)


class CanonicalCheckpointCodec:
    """Stateless strict implementation of the durable checkpoint codec contract."""

    def encode(self, envelope: CheckpointEnvelope) -> bytes:
        return encode_checkpoint_envelope(envelope)

    def decode(self, payload: bytes) -> CheckpointEnvelope:
        return decode_checkpoint_envelope(payload)

    def digest(self, envelope: CheckpointEnvelope) -> CheckpointDigest:
        return checkpoint_envelope_digest(envelope)


def encode_checkpoint_envelope(envelope: CheckpointEnvelope) -> bytes:
    """Encode one sealed checkpoint and reject stale or substituted digests."""

    if not isinstance(envelope, CheckpointEnvelope):
        raise TypeError("envelope must be CheckpointEnvelope")
    expected_digest = checkpoint_envelope_digest(envelope)
    if envelope.digest != expected_digest:
        raise AgentCodecError("checkpoint digest does not match canonical content")
    return _encode_document(
        kind=_CHECKPOINT_KIND,
        record=_checkpoint_record(envelope, include_digest=True),
        maximum_bytes=MAX_CHECKPOINT_ENVELOPE_BYTES,
    )


def decode_checkpoint_envelope(encoded: bytes) -> CheckpointEnvelope:
    """Decode, validate, digest-check, and canonicality-check one checkpoint."""

    record = _decode_document(
        encoded,
        expected_kind=_CHECKPOINT_KIND,
        maximum_bytes=MAX_CHECKPOINT_ENVELOPE_BYTES,
    )
    _require_exact_fields(record, _CHECKPOINT_FIELDS, label="checkpoint record")
    try:
        envelope = CheckpointEnvelope(
            schema_version=CheckpointSchemaVersion(_integer(record, "schema_version")),
            durable_run_id=DurableAgentRunId(_uuid(record, "durable_run_id")),
            checkpoint_id=CheckpointId(_uuid(record, "checkpoint_id")),
            sequence=CheckpointSequence(_integer(record, "sequence")),
            previous_digest=_optional_digest(record, "previous_digest"),
            run_version=DurableRunVersion(_integer(record, "run_version")),
            status=DurableRunStatus(_string(record, "status")),
            agent_run_id=AgentRunId(_uuid(record, "agent_run_id")),
            step_id=_optional_step_id(record, "step_id"),
            metadata=_decode_metadata(_mapping(record.get("metadata"), label="metadata")),
            created_at=_datetime(record, "created_at"),
            digest=CheckpointDigest(_string(record, "digest")),
        )
    except AgentCodecError:
        raise
    except (TypeError, ValueError, OverflowError) as exception:
        raise AgentCodecError("checkpoint record is invalid") from exception

    if envelope.schema_version.value != CURRENT_CHECKPOINT_SCHEMA_VERSION:
        raise AgentCodecError("unsupported checkpoint schema version")
    if checkpoint_envelope_digest(envelope) != envelope.digest:
        raise AgentCodecError("checkpoint digest does not match canonical content")
    if encode_checkpoint_envelope(envelope) != encoded:
        raise AgentCodecError("checkpoint document is not canonical")
    return envelope


def canonical_checkpoint_envelope_bytes(envelope: CheckpointEnvelope) -> bytes:
    """Return the canonical serialized bytes for one sealed checkpoint."""

    return encode_checkpoint_envelope(envelope)


def checkpoint_envelope_digest(envelope: CheckpointEnvelope) -> CheckpointDigest:
    """Compute the canonical SHA-256 digest without trusting the stored digest."""

    if not isinstance(envelope, CheckpointEnvelope):
        raise TypeError("envelope must be CheckpointEnvelope")
    encoded = _encode_document(
        kind=_CHECKPOINT_DIGEST_KIND,
        record=_checkpoint_record(envelope, include_digest=False),
        maximum_bytes=MAX_CHECKPOINT_ENVELOPE_BYTES,
    )
    return CheckpointDigest(hashlib.sha256(encoded).hexdigest())


def seal_checkpoint_envelope(envelope: CheckpointEnvelope) -> CheckpointEnvelope:
    """Return an immutable copy with its canonical digest populated."""

    if not isinstance(envelope, CheckpointEnvelope):
        raise TypeError("envelope must be CheckpointEnvelope")
    return replace(envelope, digest=checkpoint_envelope_digest(envelope))


def _checkpoint_record(
    envelope: CheckpointEnvelope,
    *,
    include_digest: bool,
) -> Mapping[str, object]:
    record: dict[str, object] = {
        "schema_version": envelope.schema_version.value,
        "durable_run_id": str(envelope.durable_run_id),
        "checkpoint_id": str(envelope.checkpoint_id),
        "sequence": envelope.sequence.value,
        "previous_digest": (
            None if envelope.previous_digest is None else str(envelope.previous_digest)
        ),
        "run_version": envelope.run_version.value,
        "status": envelope.status.value,
        "agent_run_id": str(envelope.agent_run_id),
        "step_id": None if envelope.step_id is None else str(envelope.step_id),
        "metadata": _metadata_record(envelope.metadata),
        "created_at": envelope.created_at.isoformat(),
    }
    if include_digest:
        record["digest"] = str(envelope.digest)
    expected = _CHECKPOINT_FIELDS if include_digest else _CHECKPOINT_DIGEST_FIELDS
    if frozenset(record) != expected:
        raise AgentCodecError("internal checkpoint record fields are invalid")
    return record


def _metadata_record(metadata: CheckpointMetadata) -> Mapping[str, object]:
    return {
        "agent_id": str(metadata.agent_id),
        "actor_id": metadata.actor_id,
        "next_operation": metadata.next_operation.value,
        "budget": _budget_record(metadata.budget),
        "compatibility": _compatibility_record(metadata.compatibility),
        "payload_profile": metadata.payload_profile.value,
        "retention_deadline": metadata.retention_deadline.isoformat(),
        "active_attempt": (
            None if metadata.active_attempt is None else _attempt_record(metadata.active_attempt)
        ),
        "payload_reference": (
            None
            if metadata.payload_reference is None
            else _payload_reference_record(metadata.payload_reference)
        ),
        "metadata": dict(metadata.metadata),
    }


def _decode_metadata(record: Mapping[str, object]) -> CheckpointMetadata:
    _require_exact_fields(record, _METADATA_FIELDS, label="checkpoint metadata")
    active_attempt_value = record.get("active_attempt")
    payload_reference_value = record.get("payload_reference")
    return CheckpointMetadata(
        agent_id=AgentId(_string(record, "agent_id")),
        actor_id=_string(record, "actor_id"),
        next_operation=CheckpointNextOperation(_string(record, "next_operation")),
        budget=_decode_budget(_mapping(record.get("budget"), label="checkpoint budget")),
        compatibility=_decode_compatibility(
            _mapping(record.get("compatibility"), label="compatibility digests")
        ),
        payload_profile=CheckpointPayloadProfile(_string(record, "payload_profile")),
        retention_deadline=_datetime(record, "retention_deadline"),
        active_attempt=(
            None
            if active_attempt_value is None
            else _decode_attempt(_mapping(active_attempt_value, label="execution attempt"))
        ),
        payload_reference=(
            None
            if payload_reference_value is None
            else _decode_payload_reference(
                _mapping(payload_reference_value, label="protected payload reference")
            )
        ),
        metadata=_string_mapping(record.get("metadata"), label="checkpoint metadata values"),
    )


def _budget_record(budget: AgentBudgetSnapshot) -> Mapping[str, object]:
    return {
        "steps": budget.steps,
        "model_turns": budget.model_turns,
        "tool_calls": budget.tool_calls,
        "model_output_bytes": budget.model_output_bytes,
        "tool_result_bytes": budget.tool_result_bytes,
        "input_tokens": budget.input_tokens,
        "output_tokens": budget.output_tokens,
        "started_at": budget.started_at.isoformat(),
        "deadline": budget.deadline.isoformat(),
    }


def _decode_budget(record: Mapping[str, object]) -> AgentBudgetSnapshot:
    _require_exact_fields(record, _BUDGET_FIELDS, label="checkpoint budget")
    return AgentBudgetSnapshot(
        steps=_integer(record, "steps"),
        model_turns=_integer(record, "model_turns"),
        tool_calls=_integer(record, "tool_calls"),
        model_output_bytes=_integer(record, "model_output_bytes"),
        tool_result_bytes=_integer(record, "tool_result_bytes"),
        input_tokens=_integer(record, "input_tokens"),
        output_tokens=_integer(record, "output_tokens"),
        started_at=_datetime(record, "started_at"),
        deadline=_datetime(record, "deadline"),
    )


def _compatibility_record(digests: CompatibilityDigests) -> Mapping[str, object]:
    return {
        "configuration": str(digests.configuration),
        "tool_registry": str(digests.tool_registry),
        "model_provider": str(digests.model_provider),
        "checkpoint_codec": str(digests.checkpoint_codec),
        "payload_codec": None if digests.payload_codec is None else str(digests.payload_codec),
    }


def _decode_compatibility(record: Mapping[str, object]) -> CompatibilityDigests:
    _require_exact_fields(record, _COMPATIBILITY_FIELDS, label="compatibility digests")
    return CompatibilityDigests(
        configuration=CheckpointDigest(_string(record, "configuration")),
        tool_registry=CheckpointDigest(_string(record, "tool_registry")),
        model_provider=CheckpointDigest(_string(record, "model_provider")),
        checkpoint_codec=CheckpointDigest(_string(record, "checkpoint_codec")),
        payload_codec=_optional_digest(record, "payload_codec"),
    )


def _attempt_record(attempt: ExecutionAttempt) -> Mapping[str, object]:
    return {
        "attempt_id": str(attempt.attempt_id),
        "kind": attempt.kind.value,
        "status": attempt.status.value,
        "agent_run_id": str(attempt.agent_run_id),
        "step_id": str(attempt.step_id),
        "prepared_at": attempt.prepared_at.isoformat(),
        "tool_call_id": None if attempt.tool_call_id is None else str(attempt.tool_call_id),
        "tool_effect": None if attempt.tool_effect is None else attempt.tool_effect.value,
        "started_at": None if attempt.started_at is None else attempt.started_at.isoformat(),
        "completed_at": (
            None if attempt.completed_at is None else attempt.completed_at.isoformat()
        ),
        "external_request_digest": (
            None
            if attempt.external_request_digest is None
            else str(attempt.external_request_digest)
        ),
        "indeterminate_reason": (
            None if attempt.indeterminate_reason is None else attempt.indeterminate_reason.value
        ),
        "error_code": attempt.error_code,
    }


def _decode_attempt(record: Mapping[str, object]) -> ExecutionAttempt:
    _require_exact_fields(record, _ATTEMPT_FIELDS, label="execution attempt")
    call_id = _optional_uuid(record, "tool_call_id")
    tool_effect = _optional_string(record, "tool_effect")
    indeterminate_reason = _optional_string(record, "indeterminate_reason")
    return ExecutionAttempt(
        attempt_id=ExecutionAttemptId(_uuid(record, "attempt_id")),
        kind=ExecutionAttemptKind(_string(record, "kind")),
        status=ExecutionAttemptStatus(_string(record, "status")),
        agent_run_id=AgentRunId(_uuid(record, "agent_run_id")),
        step_id=AgentStepId(_uuid(record, "step_id")),
        prepared_at=_datetime(record, "prepared_at"),
        tool_call_id=None if call_id is None else ToolCallId(call_id),
        tool_effect=None if tool_effect is None else ToolEffect(tool_effect),
        started_at=_optional_datetime(record, "started_at"),
        completed_at=_optional_datetime(record, "completed_at"),
        external_request_digest=_optional_digest(record, "external_request_digest"),
        indeterminate_reason=(
            None if indeterminate_reason is None else IndeterminateReason(indeterminate_reason)
        ),
        error_code=_optional_string(record, "error_code"),
    )


def _payload_reference_record(reference: ProtectedPayloadReference) -> Mapping[str, object]:
    return {
        "reference": reference.reference,
        "key_version": reference.key_version,
        "plaintext_bytes": reference.plaintext_bytes,
        "ciphertext_bytes": reference.ciphertext_bytes,
        "ciphertext_digest": str(reference.ciphertext_digest),
        "created_at": reference.created_at.isoformat(),
    }


def _decode_payload_reference(record: Mapping[str, object]) -> ProtectedPayloadReference:
    _require_exact_fields(
        record,
        _PAYLOAD_REFERENCE_FIELDS,
        label="protected payload reference",
    )
    return ProtectedPayloadReference(
        reference=_string(record, "reference"),
        key_version=_string(record, "key_version"),
        plaintext_bytes=_integer(record, "plaintext_bytes"),
        ciphertext_bytes=_integer(record, "ciphertext_bytes"),
        ciphertext_digest=CheckpointDigest(_string(record, "ciphertext_digest")),
        created_at=_datetime(record, "created_at"),
    )


def _encode_document(
    *,
    kind: str,
    record: Mapping[str, object],
    maximum_bytes: int,
) -> bytes:
    document = {
        "schema_version": DURABLE_CHECKPOINT_CODEC_SCHEMA_VERSION,
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
    except (TypeError, ValueError, OverflowError, UnicodeEncodeError) as exception:
        raise AgentCodecError("checkpoint document cannot be encoded") from exception
    if len(encoded) > maximum_bytes:
        raise AgentCodecError("checkpoint document exceeds the maximum size")
    return encoded


def _decode_document(
    encoded: bytes,
    *,
    expected_kind: str,
    maximum_bytes: int,
) -> Mapping[str, object]:
    if not isinstance(encoded, bytes):
        raise TypeError("encoded checkpoint document must be bytes")
    if not encoded or len(encoded) > maximum_bytes:
        raise AgentCodecError("checkpoint document size is invalid")
    try:
        decoded: object = json.loads(
            encoded.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_non_finite_constant,
        )
    except AgentCodecError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exception:
        raise AgentCodecError("checkpoint document is malformed") from exception
    _inspect_json(decoded, depth=0, count=[0])
    document = _mapping(decoded, label="checkpoint document")
    _require_exact_fields(document, _DOCUMENT_FIELDS, label="checkpoint document")
    if _integer(document, "schema_version") != DURABLE_CHECKPOINT_CODEC_SCHEMA_VERSION:
        raise AgentCodecError("unsupported checkpoint codec schema version")
    if _string(document, "kind") != expected_kind:
        raise AgentCodecError("unexpected checkpoint document kind")
    return _mapping(document.get("record"), label="checkpoint record")


def _reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise AgentCodecError("checkpoint document contains duplicate object keys")
        result[key] = value
    return result


def _reject_non_finite_constant(value: str) -> NoReturn:
    raise AgentCodecError(f"non-finite JSON number is not allowed: {value}")


def _inspect_json(value: object, *, depth: int, count: list[int]) -> None:
    if depth > MAX_DURABLE_CHECKPOINT_JSON_DEPTH:
        raise AgentCodecError("checkpoint document exceeds the maximum JSON depth")
    count[0] += 1
    if count[0] > MAX_DURABLE_CHECKPOINT_JSON_ITEMS:
        raise AgentCodecError("checkpoint document exceeds the maximum JSON item count")
    if isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeEncodeError as exception:
            raise AgentCodecError("checkpoint document contains invalid Unicode") from exception
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            _inspect_json(key, depth=depth + 1, count=count)
            _inspect_json(item, depth=depth + 1, count=count)
        return
    if isinstance(value, list):
        for item in value:
            _inspect_json(item, depth=depth + 1, count=count)


def _mapping(value: object, *, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise AgentCodecError(f"{label} must be an object")
    raw = cast(Mapping[object, object], value)
    if any(not isinstance(key, str) for key in raw):
        raise AgentCodecError(f"{label} keys must be strings")
    return cast(Mapping[str, object], raw)


def _require_exact_fields(
    value: Mapping[str, object],
    expected: frozenset[str],
    *,
    label: str,
) -> None:
    if frozenset(value) != expected:
        raise AgentCodecError(f"{label} fields are invalid")


def _string(value: Mapping[str, object], key: str) -> str:
    item = value.get(key)
    if not isinstance(item, str):
        raise AgentCodecError(f"{key} must be a string")
    return item


def _optional_string(value: Mapping[str, object], key: str) -> str | None:
    item = value.get(key)
    if item is None:
        return None
    if not isinstance(item, str):
        raise AgentCodecError(f"{key} must be a string or null")
    return item


def _integer(value: Mapping[str, object], key: str) -> int:
    item = value.get(key)
    if isinstance(item, bool) or not isinstance(item, int):
        raise AgentCodecError(f"{key} must be an integer")
    return item


def _uuid(value: Mapping[str, object], key: str) -> UUID:
    try:
        return UUID(_string(value, key))
    except ValueError as exception:
        raise AgentCodecError(f"{key} must be a UUID") from exception


def _optional_uuid(value: Mapping[str, object], key: str) -> UUID | None:
    item = _optional_string(value, key)
    if item is None:
        return None
    try:
        return UUID(item)
    except ValueError as exception:
        raise AgentCodecError(f"{key} must be a UUID or null") from exception


def _datetime(value: Mapping[str, object], key: str) -> datetime:
    try:
        return datetime.fromisoformat(_string(value, key))
    except ValueError as exception:
        raise AgentCodecError(f"{key} must be an ISO-8601 datetime") from exception


def _optional_datetime(value: Mapping[str, object], key: str) -> datetime | None:
    item = _optional_string(value, key)
    if item is None:
        return None
    try:
        return datetime.fromisoformat(item)
    except ValueError as exception:
        raise AgentCodecError(f"{key} must be an ISO-8601 datetime or null") from exception


def _optional_digest(
    value: Mapping[str, object],
    key: str,
) -> CheckpointDigest | None:
    item = _optional_string(value, key)
    return None if item is None else CheckpointDigest(item)


def _optional_step_id(
    value: Mapping[str, object],
    key: str,
) -> AgentStepId | None:
    item = _optional_uuid(value, key)
    return None if item is None else AgentStepId(item)


def _string_mapping(value: object, *, label: str) -> Mapping[str, str]:
    mapped = _mapping(value, label=label)
    if any(not isinstance(item, str) for item in mapped.values()):
        raise AgentCodecError(f"{label} values must be strings")
    return cast(Mapping[str, str], mapped)
