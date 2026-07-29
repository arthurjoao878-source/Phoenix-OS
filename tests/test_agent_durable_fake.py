"""Tests for the deterministic durable checkpoint protector fake."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from uuid import UUID

import pytest

from phoenix_os.agent.durable_contracts import (
    CheckpointId,
    CheckpointProtector,
    CheckpointSequence,
    DurableAgentRunId,
)
from phoenix_os.agent.durable_fake import DeterministicCheckpointProtector
from phoenix_os.agent.errors import AgentCodecError

RUN_ID = DurableAgentRunId(UUID("10000000-0000-0000-0000-000000000001"))
OTHER_RUN_ID = DurableAgentRunId(UUID("10000000-0000-0000-0000-000000000002"))
CHECKPOINT_ID = CheckpointId(UUID("20000000-0000-0000-0000-000000000001"))
OTHER_CHECKPOINT_ID = CheckpointId(UUID("20000000-0000-0000-0000-000000000002"))
SEQUENCE = CheckpointSequence(1)
OTHER_SEQUENCE = CheckpointSequence(2)
NOW = datetime(2026, 7, 29, 12, 0, tzinfo=UTC)
SECRET = b"0123456789abcdef0123456789abcdef"


def _protector(
    *,
    secret: bytes = SECRET,
    protector_id: str = "deterministic-checkpoint-protector",
    key_version: str = "test-key-v1",
) -> DeterministicCheckpointProtector:
    return DeterministicCheckpointProtector(
        secret,
        protector_id=protector_id,
        key_version=key_version,
        clock=lambda: NOW,
    )


def test_fake_implements_checkpoint_protector_protocol() -> None:
    protector = _protector()

    assert isinstance(protector, CheckpointProtector)
    assert protector.protector_id == "deterministic-checkpoint-protector"
    assert protector.key_version == "test-key-v1"
    assert protector.protect_observations == ()
    assert protector.unprotect_observations == ()


def test_protect_and_unprotect_round_trip_records_content_free_observations() -> None:
    protector = _protector()
    plaintext = b'{"continuation":"protected"}'

    reference, ciphertext = protector.protect(
        run_id=RUN_ID,
        checkpoint_id=CHECKPOINT_ID,
        sequence=SEQUENCE,
        plaintext=plaintext,
    )
    restored = protector.unprotect(
        run_id=RUN_ID,
        checkpoint_id=CHECKPOINT_ID,
        sequence=SEQUENCE,
        reference=reference,
        ciphertext=ciphertext,
    )

    assert restored == plaintext
    assert reference.key_version == protector.key_version
    assert reference.plaintext_bytes == len(plaintext)
    assert reference.ciphertext_bytes == len(ciphertext)
    assert reference.created_at == NOW
    assert reference.reference.startswith(
        "fake-protected:deterministic-checkpoint-protector:test-key-v1:"
    )

    assert len(protector.protect_observations) == 1
    protect_observation = protector.protect_observations[0]
    assert protect_observation.run_id == RUN_ID
    assert protect_observation.checkpoint_id == CHECKPOINT_ID
    assert protect_observation.sequence == SEQUENCE
    assert protect_observation.plaintext_bytes == len(plaintext)
    assert protect_observation.ciphertext_bytes == len(ciphertext)
    assert protect_observation.ciphertext_digest == reference.ciphertext_digest

    assert len(protector.unprotect_observations) == 1
    unprotect_observation = protector.unprotect_observations[0]
    assert unprotect_observation.run_id == RUN_ID
    assert unprotect_observation.checkpoint_id == CHECKPOINT_ID
    assert unprotect_observation.sequence == SEQUENCE
    assert unprotect_observation.ciphertext_bytes == len(ciphertext)
    assert unprotect_observation.ciphertext_digest == reference.ciphertext_digest
    assert unprotect_observation.plaintext_bytes == len(plaintext)


def test_same_context_secret_and_plaintext_are_deterministic() -> None:
    first = _protector()
    second = _protector()
    plaintext = b"same deterministic payload"

    first_reference, first_ciphertext = first.protect(
        run_id=RUN_ID,
        checkpoint_id=CHECKPOINT_ID,
        sequence=SEQUENCE,
        plaintext=plaintext,
    )
    second_reference, second_ciphertext = second.protect(
        run_id=RUN_ID,
        checkpoint_id=CHECKPOINT_ID,
        sequence=SEQUENCE,
        plaintext=plaintext,
    )

    assert first_ciphertext == second_ciphertext
    assert first_reference.reference == second_reference.reference
    assert first_reference.ciphertext_digest == second_reference.ciphertext_digest


@pytest.mark.parametrize(
    ("run_id", "checkpoint_id", "sequence"),
    [
        (OTHER_RUN_ID, CHECKPOINT_ID, SEQUENCE),
        (RUN_ID, OTHER_CHECKPOINT_ID, SEQUENCE),
        (RUN_ID, CHECKPOINT_ID, OTHER_SEQUENCE),
    ],
)
def test_context_changes_ciphertext_and_reference(
    run_id: DurableAgentRunId,
    checkpoint_id: CheckpointId,
    sequence: CheckpointSequence,
) -> None:
    protector = _protector()
    plaintext = b"context-bound payload"

    baseline_reference, baseline_ciphertext = protector.protect(
        run_id=RUN_ID,
        checkpoint_id=CHECKPOINT_ID,
        sequence=SEQUENCE,
        plaintext=plaintext,
    )
    changed_reference, changed_ciphertext = protector.protect(
        run_id=run_id,
        checkpoint_id=checkpoint_id,
        sequence=sequence,
        plaintext=plaintext,
    )

    assert changed_ciphertext != baseline_ciphertext
    assert changed_reference.reference != baseline_reference.reference
    assert changed_reference.ciphertext_digest != baseline_reference.ciphertext_digest


def test_unprotect_rejects_tampered_ciphertext_without_recording_success() -> None:
    protector = _protector()
    reference, ciphertext = protector.protect(
        run_id=RUN_ID,
        checkpoint_id=CHECKPOINT_ID,
        sequence=SEQUENCE,
        plaintext=b"tamper-detection",
    )
    tampered = bytearray(ciphertext)
    tampered[-1] ^= 1

    with pytest.raises(
        AgentCodecError,
        match="ciphertext digest is invalid",
    ):
        protector.unprotect(
            run_id=RUN_ID,
            checkpoint_id=CHECKPOINT_ID,
            sequence=SEQUENCE,
            reference=reference,
            ciphertext=bytes(tampered),
        )

    assert protector.unprotect_observations == ()


@pytest.mark.parametrize(
    ("run_id", "checkpoint_id", "sequence"),
    [
        (OTHER_RUN_ID, CHECKPOINT_ID, SEQUENCE),
        (RUN_ID, OTHER_CHECKPOINT_ID, SEQUENCE),
        (RUN_ID, CHECKPOINT_ID, OTHER_SEQUENCE),
    ],
)
def test_unprotect_rejects_the_wrong_context(
    run_id: DurableAgentRunId,
    checkpoint_id: CheckpointId,
    sequence: CheckpointSequence,
) -> None:
    protector = _protector()
    reference, ciphertext = protector.protect(
        run_id=RUN_ID,
        checkpoint_id=CHECKPOINT_ID,
        sequence=SEQUENCE,
        plaintext=b"context-bound payload",
    )

    with pytest.raises(
        AgentCodecError,
        match="reference does not match its context",
    ):
        protector.unprotect(
            run_id=run_id,
            checkpoint_id=checkpoint_id,
            sequence=sequence,
            reference=reference,
            ciphertext=ciphertext,
        )


def test_unprotect_rejects_reference_with_wrong_key_version() -> None:
    protector = _protector()
    reference, ciphertext = protector.protect(
        run_id=RUN_ID,
        checkpoint_id=CHECKPOINT_ID,
        sequence=SEQUENCE,
        plaintext=b"protected payload",
    )
    wrong_reference = replace(reference, key_version="test-key-v2")

    with pytest.raises(
        AgentCodecError,
        match="key version is unavailable",
    ):
        protector.unprotect(
            run_id=RUN_ID,
            checkpoint_id=CHECKPOINT_ID,
            sequence=SEQUENCE,
            reference=wrong_reference,
            ciphertext=ciphertext,
        )


def test_unprotect_rejects_reference_with_wrong_size_or_digest() -> None:
    protector = _protector()
    reference, ciphertext = protector.protect(
        run_id=RUN_ID,
        checkpoint_id=CHECKPOINT_ID,
        sequence=SEQUENCE,
        plaintext=b"protected payload",
    )

    wrong_size = replace(reference, ciphertext_bytes=reference.ciphertext_bytes + 1)
    with pytest.raises(
        AgentCodecError,
        match="ciphertext length is invalid",
    ):
        protector.unprotect(
            run_id=RUN_ID,
            checkpoint_id=CHECKPOINT_ID,
            sequence=SEQUENCE,
            reference=wrong_size,
            ciphertext=ciphertext,
        )

    wrong_digest = replace(
        reference,
        ciphertext_digest=replace(
            reference.ciphertext_digest,
            value="0" * 64,
        ),
    )
    with pytest.raises(
        AgentCodecError,
        match="ciphertext digest is invalid",
    ):
        protector.unprotect(
            run_id=RUN_ID,
            checkpoint_id=CHECKPOINT_ID,
            sequence=SEQUENCE,
            reference=wrong_digest,
            ciphertext=ciphertext,
        )


def test_unprotect_with_another_secret_fails_closed() -> None:
    producer = _protector()
    consumer = _protector(secret=b"fedcba9876543210fedcba9876543210")
    reference, ciphertext = producer.protect(
        run_id=RUN_ID,
        checkpoint_id=CHECKPOINT_ID,
        sequence=SEQUENCE,
        plaintext=b"secret-bound payload",
    )

    with pytest.raises(
        AgentCodecError,
        match="reference does not match its context",
    ):
        consumer.unprotect(
            run_id=RUN_ID,
            checkpoint_id=CHECKPOINT_ID,
            sequence=SEQUENCE,
            reference=reference,
            ciphertext=ciphertext,
        )


def test_empty_payload_round_trips() -> None:
    protector = _protector()

    reference, ciphertext = protector.protect(
        run_id=RUN_ID,
        checkpoint_id=CHECKPOINT_ID,
        sequence=SEQUENCE,
        plaintext=b"",
    )
    restored = protector.unprotect(
        run_id=RUN_ID,
        checkpoint_id=CHECKPOINT_ID,
        sequence=SEQUENCE,
        reference=reference,
        ciphertext=ciphertext,
    )

    assert restored == b""
    assert reference.plaintext_bytes == 0
    assert reference.ciphertext_bytes == len(ciphertext)


@pytest.mark.parametrize(
    "secret",
    [
        b"",
        b"short",
        b"x" * 15,
        b"x" * 4_097,
    ],
)
def test_secret_bounds_are_enforced(secret: bytes) -> None:
    with pytest.raises(ValueError):
        DeterministicCheckpointProtector(secret)


@pytest.mark.parametrize(
    ("protector_id", "key_version"),
    [
        ("", "test-key-v1"),
        ("UPPERCASE", "test-key-v1"),
        ("protector id", "test-key-v1"),
        ("valid-protector", ""),
        ("valid-protector", "KEY-V1"),
        ("valid-protector", "key version"),
    ],
)
def test_identifiers_are_strict(
    protector_id: str,
    key_version: str,
) -> None:
    with pytest.raises(ValueError):
        DeterministicCheckpointProtector(
            SECRET,
            protector_id=protector_id,
            key_version=key_version,
        )


def test_naive_clock_result_is_rejected_before_reference_creation() -> None:
    protector = DeterministicCheckpointProtector(
        SECRET,
        clock=lambda: datetime(2026, 7, 29, 12, 0),
    )

    with pytest.raises(
        ValueError,
        match="clock result must be timezone-aware",
    ):
        protector.protect(
            run_id=RUN_ID,
            checkpoint_id=CHECKPOINT_ID,
            sequence=SEQUENCE,
            plaintext=b"payload",
        )

    assert protector.protect_observations == ()


@pytest.mark.parametrize(
    ("argument", "value", "message"),
    [
        ("run_id", "not-a-run", "run_id must be DurableAgentRunId"),
        ("checkpoint_id", "not-a-checkpoint", "checkpoint_id must be CheckpointId"),
        ("sequence", 1, "sequence must be CheckpointSequence"),
        ("plaintext", bytearray(b"payload"), "plaintext must be bytes"),
    ],
)
def test_protect_rejects_wrong_argument_types(
    argument: str,
    value: object,
    message: str,
) -> None:
    protector = _protector()
    arguments: dict[str, object] = {
        "run_id": RUN_ID,
        "checkpoint_id": CHECKPOINT_ID,
        "sequence": SEQUENCE,
        "plaintext": b"payload",
    }
    arguments[argument] = value

    with pytest.raises(TypeError, match=message):
        protector.protect(**arguments)  # type: ignore[arg-type]
