import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from phoenix_os.agent.contracts import (
    AgentId,
    AgentRunId,
    AgentStepId,
    ToolCallId,
    ToolEffect,
)
from phoenix_os.agent.durable_codec import (
    MAX_DURABLE_CHECKPOINT_JSON_DEPTH,
    CanonicalCheckpointCodec,
    canonical_checkpoint_envelope_bytes,
    checkpoint_envelope_digest,
    decode_checkpoint_envelope,
    encode_checkpoint_envelope,
    seal_checkpoint_envelope,
)
from phoenix_os.agent.durable_contracts import (
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
    ProtectedPayloadReference,
)
from phoenix_os.agent.errors import AgentCodecError
from phoenix_os.agent.state import AgentBudgetSnapshot

NOW = datetime(2026, 7, 29, 15, tzinfo=UTC)
DURABLE_RUN_ID = DurableAgentRunId(UUID("10000000-0000-0000-0000-000000000001"))
AGENT_RUN_ID = AgentRunId(UUID("20000000-0000-0000-0000-000000000002"))
STEP_ID = AgentStepId(UUID("30000000-0000-0000-0000-000000000003"))
CALL_ID = ToolCallId(UUID("40000000-0000-0000-0000-000000000004"))
CHECKPOINT_ID = CheckpointId(UUID("50000000-0000-0000-0000-000000000005"))
SECOND_CHECKPOINT_ID = CheckpointId(UUID("50000000-0000-0000-0000-000000000006"))
ATTEMPT_ID = ExecutionAttemptId(UUID("60000000-0000-0000-0000-000000000006"))


def _digest(character: str) -> CheckpointDigest:
    return CheckpointDigest(character * 64)


def _budget() -> AgentBudgetSnapshot:
    return AgentBudgetSnapshot(
        steps=2,
        model_turns=1,
        tool_calls=1,
        model_output_bytes=128,
        tool_result_bytes=64,
        input_tokens=32,
        output_tokens=16,
        started_at=NOW,
        deadline=NOW + timedelta(hours=1),
    )


def _compatibility(*, protected: bool = False) -> CompatibilityDigests:
    return CompatibilityDigests(
        configuration=_digest("a"),
        tool_registry=_digest("b"),
        model_provider=_digest("c"),
        checkpoint_codec=_digest("d"),
        payload_codec=_digest("e") if protected else None,
    )


def _started_tool_attempt() -> ExecutionAttempt:
    return ExecutionAttempt(
        attempt_id=ATTEMPT_ID,
        kind=ExecutionAttemptKind.TOOL_INVOCATION,
        status=ExecutionAttemptStatus.STARTED,
        agent_run_id=AGENT_RUN_ID,
        step_id=STEP_ID,
        tool_call_id=CALL_ID,
        tool_effect=ToolEffect.REVERSIBLE_WRITE,
        prepared_at=NOW,
        started_at=NOW + timedelta(seconds=1),
        external_request_digest=_digest("f"),
    )


def _metadata(*, protected: bool = False) -> CheckpointMetadata:
    reference = None
    if protected:
        reference = ProtectedPayloadReference(
            reference="payload:run-1/checkpoint-1",
            key_version="key-v1",
            plaintext_bytes=128,
            ciphertext_bytes=160,
            ciphertext_digest=_digest("1"),
            created_at=NOW,
        )
    return CheckpointMetadata(
        agent_id=AgentId("assistant"),
        actor_id="worker-1",
        next_operation=CheckpointNextOperation.TOOL_INVOCATION,
        budget=_budget(),
        compatibility=_compatibility(protected=protected),
        payload_profile=(
            CheckpointPayloadProfile.PROTECTED_CONTENT
            if protected
            else CheckpointPayloadProfile.METADATA_ONLY
        ),
        retention_deadline=NOW + timedelta(days=7),
        active_attempt=_started_tool_attempt(),
        payload_reference=reference,
        metadata={"tenant": "demo", "zone": "local"},
    )


def _unsealed_envelope(
    *,
    checkpoint_id: CheckpointId = CHECKPOINT_ID,
    sequence: CheckpointSequence | None = None,
    previous_digest: CheckpointDigest | None = None,
    protected: bool = False,
) -> CheckpointEnvelope:
    resolved_sequence = sequence or CheckpointSequence(1)
    return CheckpointEnvelope(
        schema_version=CheckpointSchemaVersion(),
        durable_run_id=DURABLE_RUN_ID,
        checkpoint_id=checkpoint_id,
        sequence=resolved_sequence,
        previous_digest=previous_digest,
        run_version=DurableRunVersion(resolved_sequence.value),
        status=DurableRunStatus.ACTIVE,
        agent_run_id=AGENT_RUN_ID,
        step_id=STEP_ID,
        metadata=_metadata(protected=protected),
        created_at=NOW + timedelta(seconds=resolved_sequence.value + 1),
        digest=_digest("0"),
    )


def _sealed_envelope(*, protected: bool = False) -> CheckpointEnvelope:
    return seal_checkpoint_envelope(_unsealed_envelope(protected=protected))


def _canonical_document(document: object) -> bytes:
    return json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def test_checkpoint_codec_round_trips_metadata_only_checkpoint() -> None:
    envelope = _sealed_envelope()

    encoded = encode_checkpoint_envelope(envelope)

    assert decode_checkpoint_envelope(encoded) == envelope
    assert encoded == canonical_checkpoint_envelope_bytes(envelope)
    assert encoded.startswith(b'{"kind":"phoenix.agent.durable-checkpoint"')
    assert b"\n" not in encoded
    assert b": " not in encoded


def test_checkpoint_codec_round_trips_protected_payload_and_active_attempt() -> None:
    envelope = _sealed_envelope(protected=True)

    decoded = decode_checkpoint_envelope(encode_checkpoint_envelope(envelope))

    assert decoded == envelope
    assert decoded.metadata.payload_reference == envelope.metadata.payload_reference
    assert decoded.metadata.active_attempt == envelope.metadata.active_attempt
    assert decoded.metadata.compatibility.payload_codec == _digest("e")


def test_codec_facade_uses_the_same_canonical_implementation() -> None:
    codec = CanonicalCheckpointCodec()
    envelope = _sealed_envelope()

    encoded = codec.encode(envelope)

    assert codec.decode(encoded) == envelope
    assert codec.digest(envelope) == checkpoint_envelope_digest(envelope)


def test_sealing_is_deterministic_and_does_not_trust_existing_digest() -> None:
    unsealed = _unsealed_envelope()

    first = seal_checkpoint_envelope(unsealed)
    second = seal_checkpoint_envelope(replace(unsealed, digest=_digest("9")))

    assert first.digest == second.digest
    assert first.digest == checkpoint_envelope_digest(unsealed)
    assert first.digest != unsealed.digest


def test_encoder_rejects_stale_or_substituted_digest() -> None:
    envelope = _unsealed_envelope()

    with pytest.raises(AgentCodecError, match="digest"):
        encode_checkpoint_envelope(envelope)

    sealed = _sealed_envelope()
    with pytest.raises(AgentCodecError, match="digest"):
        encode_checkpoint_envelope(replace(sealed, digest=_digest("8")))


def test_digest_chain_round_trips_without_recomputing_previous_checkpoint() -> None:
    first = _sealed_envelope()
    second = seal_checkpoint_envelope(
        _unsealed_envelope(
            checkpoint_id=SECOND_CHECKPOINT_ID,
            sequence=CheckpointSequence(2),
            previous_digest=first.digest,
        )
    )

    decoded = decode_checkpoint_envelope(encode_checkpoint_envelope(second))

    assert decoded.sequence == CheckpointSequence(2)
    assert decoded.previous_digest == first.digest
    assert decoded.digest == second.digest


def test_decoder_rejects_noncanonical_unknown_and_wrong_kind_documents() -> None:
    encoded = encode_checkpoint_envelope(_sealed_envelope())
    document = json.loads(encoded)

    pretty = json.dumps(document, indent=2).encode("utf-8")
    with pytest.raises(AgentCodecError, match="canonical"):
        decode_checkpoint_envelope(pretty)

    document["record"]["unexpected"] = True
    with pytest.raises(AgentCodecError, match="fields"):
        decode_checkpoint_envelope(_canonical_document(document))

    document = json.loads(encoded)
    document["kind"] = "phoenix.agent.other"
    with pytest.raises(AgentCodecError, match="kind"):
        decode_checkpoint_envelope(_canonical_document(document))


def test_decoder_rejects_unsupported_codec_and_checkpoint_schema_versions() -> None:
    encoded = encode_checkpoint_envelope(_sealed_envelope())
    document = json.loads(encoded)
    document["schema_version"] = 2

    with pytest.raises(AgentCodecError, match="codec schema version"):
        decode_checkpoint_envelope(_canonical_document(document))

    document = json.loads(encoded)
    document["record"]["schema_version"] = 2
    with pytest.raises(AgentCodecError, match="checkpoint schema version"):
        decode_checkpoint_envelope(_canonical_document(document))


def test_decoder_rejects_duplicate_keys_nonfinite_numbers_and_invalid_unicode() -> None:
    encoded = encode_checkpoint_envelope(_sealed_envelope())
    duplicate = encoded.replace(
        b'"kind":"phoenix.agent.durable-checkpoint"',
        (b'"kind":"phoenix.agent.durable-checkpoint","kind":"phoenix.agent.durable-checkpoint"'),
        1,
    )
    with pytest.raises(AgentCodecError, match="duplicate"):
        decode_checkpoint_envelope(duplicate)

    nonfinite = encoded.replace(b'"steps":2', b'"steps":NaN', 1)
    with pytest.raises(AgentCodecError, match="non-finite"):
        decode_checkpoint_envelope(nonfinite)

    invalid_unicode = encoded.replace(b"worker-1", b"\\ud800", 1)
    with pytest.raises(AgentCodecError, match="Unicode"):
        decode_checkpoint_envelope(invalid_unicode)


def test_decoder_rejects_digest_tampering_even_when_json_is_canonical() -> None:
    encoded = encode_checkpoint_envelope(_sealed_envelope())
    document = json.loads(encoded)
    document["record"]["metadata"]["actor_id"] = "worker-2"

    with pytest.raises(AgentCodecError, match="digest"):
        decode_checkpoint_envelope(_canonical_document(document))


def test_decoder_rejects_wrong_scalar_types_and_naive_timestamps() -> None:
    encoded = encode_checkpoint_envelope(_sealed_envelope())
    document = json.loads(encoded)
    document["record"]["sequence"] = True

    with pytest.raises(AgentCodecError, match="integer"):
        decode_checkpoint_envelope(_canonical_document(document))

    document = json.loads(encoded)
    document["record"]["created_at"] = "2026-07-29T15:00:02"
    with pytest.raises(AgentCodecError, match="invalid"):
        decode_checkpoint_envelope(_canonical_document(document))


def test_decoder_rejects_malformed_empty_oversized_and_nonbyte_documents() -> None:
    with pytest.raises(AgentCodecError, match="size"):
        decode_checkpoint_envelope(b"")
    with pytest.raises(AgentCodecError, match="malformed"):
        decode_checkpoint_envelope(b"not-json")
    with pytest.raises(AgentCodecError, match="size"):
        decode_checkpoint_envelope(b"{" + b"x" * MAX_CHECKPOINT_ENVELOPE_BYTES)
    with pytest.raises(TypeError, match="bytes"):
        decode_checkpoint_envelope("not-bytes")  # type: ignore[arg-type]


def test_decoder_rejects_documents_beyond_the_json_depth_limit() -> None:
    encoded = encode_checkpoint_envelope(_sealed_envelope())
    document = json.loads(encoded)
    nested: object = "leaf"
    for _ in range(MAX_DURABLE_CHECKPOINT_JSON_DEPTH + 2):
        nested = [nested]
    document["unexpected"] = nested

    with pytest.raises(AgentCodecError, match="depth"):
        decode_checkpoint_envelope(_canonical_document(document))
