"""Deterministic protected-payload fake for durable agent tests.

This adapter is intentionally not production cryptography. It provides deterministic
round trips, context binding, tamper detection, and content-free call observations for
network-free tests.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime

from phoenix_os.agent.durable_contracts import (
    MAX_PROTECTED_PAYLOAD_BYTES,
    CheckpointDigest,
    CheckpointId,
    CheckpointProtector,
    CheckpointSequence,
    DurableAgentRunId,
    ProtectedPayloadReference,
)
from phoenix_os.agent.errors import AgentCodecError, AgentLimitExceededError

_FAKE_MAGIC = b"PHX-DURABLE-FAKE-PROTECTOR-V1\x00"
_FAKE_TAG_BYTES = hashlib.sha256().digest_size
_MIN_SECRET_BYTES = 16
_MAX_SECRET_BYTES = 4_096
_PROTECTOR_ID_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,127})$")


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _normalize_identifier(value: str, *, label: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{label} must be a string")
    normalized = value.strip()
    if not _PROTECTOR_ID_PATTERN.fullmatch(normalized):
        raise ValueError(f"{label} is invalid")
    return normalized


def _require_clock(value: Callable[[], datetime]) -> Callable[[], datetime]:
    if not callable(value):
        raise TypeError("clock must be callable")
    return value


def _require_aware(value: datetime, *, label: str) -> None:
    if not isinstance(value, datetime):
        raise TypeError(f"{label} must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")


def _require_bytes(value: bytes, *, label: str) -> bytes:
    if not isinstance(value, bytes):
        raise TypeError(f"{label} must be bytes")
    return value


def _require_context(
    *,
    run_id: DurableAgentRunId,
    checkpoint_id: CheckpointId,
    sequence: CheckpointSequence,
) -> None:
    if not isinstance(run_id, DurableAgentRunId):
        raise TypeError("run_id must be DurableAgentRunId")
    if not isinstance(checkpoint_id, CheckpointId):
        raise TypeError("checkpoint_id must be CheckpointId")
    if not isinstance(sequence, CheckpointSequence):
        raise TypeError("sequence must be CheckpointSequence")


def _sha256_digest(payload: bytes) -> CheckpointDigest:
    return CheckpointDigest(hashlib.sha256(payload).hexdigest())


@dataclass(frozen=True, slots=True)
class DeterministicProtectObservation:
    """Content-free record of one fake protection operation."""

    run_id: DurableAgentRunId
    checkpoint_id: CheckpointId
    sequence: CheckpointSequence
    plaintext_bytes: int
    ciphertext_bytes: int
    ciphertext_digest: CheckpointDigest


@dataclass(frozen=True, slots=True)
class DeterministicUnprotectObservation:
    """Content-free record of one fake unprotection operation."""

    run_id: DurableAgentRunId
    checkpoint_id: CheckpointId
    sequence: CheckpointSequence
    ciphertext_bytes: int
    ciphertext_digest: CheckpointDigest
    plaintext_bytes: int


class DeterministicCheckpointProtector(CheckpointProtector):
    """Deterministic, tamper-evident fake implementing CheckpointProtector.

    The construction is suitable only for tests. Production composition must replace
    it with an authenticated encryption adapter backed by managed key material.
    """

    def __init__(
        self,
        secret: bytes,
        *,
        protector_id: str = "deterministic-checkpoint-protector",
        key_version: str = "test-key-v1",
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        normalized_secret = _require_bytes(secret, label="secret")
        if len(normalized_secret) < _MIN_SECRET_BYTES:
            raise ValueError("secret is shorter than the deterministic fake minimum")
        if len(normalized_secret) > _MAX_SECRET_BYTES:
            raise ValueError("secret exceeds the deterministic fake maximum")
        self._secret = normalized_secret
        self._protector_id = _normalize_identifier(
            protector_id,
            label="protector_id",
        )
        self._key_version = _normalize_identifier(
            key_version,
            label="key_version",
        )
        self._clock = _require_clock(clock)
        self._protect_observations: list[DeterministicProtectObservation] = []
        self._unprotect_observations: list[DeterministicUnprotectObservation] = []

    @property
    def protector_id(self) -> str:
        return self._protector_id

    @property
    def key_version(self) -> str:
        return self._key_version

    @property
    def protect_observations(self) -> tuple[DeterministicProtectObservation, ...]:
        return tuple(self._protect_observations)

    @property
    def unprotect_observations(
        self,
    ) -> tuple[DeterministicUnprotectObservation, ...]:
        return tuple(self._unprotect_observations)

    def protect(
        self,
        *,
        run_id: DurableAgentRunId,
        checkpoint_id: CheckpointId,
        sequence: CheckpointSequence,
        plaintext: bytes,
    ) -> tuple[ProtectedPayloadReference, bytes]:
        _require_context(
            run_id=run_id,
            checkpoint_id=checkpoint_id,
            sequence=sequence,
        )
        normalized_plaintext = _require_bytes(plaintext, label="plaintext")
        if len(normalized_plaintext) > MAX_PROTECTED_PAYLOAD_BYTES:
            raise AgentLimitExceededError()

        associated_data = self._associated_data(
            run_id=run_id,
            checkpoint_id=checkpoint_id,
            sequence=sequence,
        )
        encrypted = self._xor_stream(
            normalized_plaintext,
            associated_data=associated_data,
        )
        tag = hmac.digest(
            self._secret,
            b"tag\x00" + associated_data + encrypted,
            "sha256",
        )
        ciphertext = _FAKE_MAGIC + tag + encrypted
        digest = _sha256_digest(ciphertext)
        created_at = self._clock()
        _require_aware(created_at, label="clock result")

        reference = ProtectedPayloadReference(
            reference=self._reference_value(
                run_id=run_id,
                checkpoint_id=checkpoint_id,
                sequence=sequence,
                ciphertext_digest=digest,
            ),
            key_version=self._key_version,
            plaintext_bytes=len(normalized_plaintext),
            ciphertext_bytes=len(ciphertext),
            ciphertext_digest=digest,
            created_at=created_at,
        )
        self._protect_observations.append(
            DeterministicProtectObservation(
                run_id=run_id,
                checkpoint_id=checkpoint_id,
                sequence=sequence,
                plaintext_bytes=len(normalized_plaintext),
                ciphertext_bytes=len(ciphertext),
                ciphertext_digest=digest,
            )
        )
        return reference, ciphertext

    def unprotect(
        self,
        *,
        run_id: DurableAgentRunId,
        checkpoint_id: CheckpointId,
        sequence: CheckpointSequence,
        reference: ProtectedPayloadReference,
        ciphertext: bytes,
    ) -> bytes:
        _require_context(
            run_id=run_id,
            checkpoint_id=checkpoint_id,
            sequence=sequence,
        )
        if not isinstance(reference, ProtectedPayloadReference):
            raise TypeError("reference must be ProtectedPayloadReference")
        normalized_ciphertext = _require_bytes(ciphertext, label="ciphertext")
        self._validate_reference(
            run_id=run_id,
            checkpoint_id=checkpoint_id,
            sequence=sequence,
            reference=reference,
            ciphertext=normalized_ciphertext,
        )

        prefix_bytes = len(_FAKE_MAGIC) + _FAKE_TAG_BYTES
        if len(normalized_ciphertext) < prefix_bytes:
            raise AgentCodecError("protected payload is truncated")
        if not normalized_ciphertext.startswith(_FAKE_MAGIC):
            raise AgentCodecError("protected payload has an invalid fake envelope")

        tag_start = len(_FAKE_MAGIC)
        tag_end = tag_start + _FAKE_TAG_BYTES
        supplied_tag = normalized_ciphertext[tag_start:tag_end]
        encrypted = normalized_ciphertext[tag_end:]
        associated_data = self._associated_data(
            run_id=run_id,
            checkpoint_id=checkpoint_id,
            sequence=sequence,
        )
        expected_tag = hmac.digest(
            self._secret,
            b"tag\x00" + associated_data + encrypted,
            "sha256",
        )
        if not hmac.compare_digest(supplied_tag, expected_tag):
            raise AgentCodecError("protected payload authentication failed")

        plaintext = self._xor_stream(
            encrypted,
            associated_data=associated_data,
        )
        if len(plaintext) != reference.plaintext_bytes:
            raise AgentCodecError("protected payload plaintext length is invalid")
        if len(plaintext) > MAX_PROTECTED_PAYLOAD_BYTES:
            raise AgentLimitExceededError()

        self._unprotect_observations.append(
            DeterministicUnprotectObservation(
                run_id=run_id,
                checkpoint_id=checkpoint_id,
                sequence=sequence,
                ciphertext_bytes=len(normalized_ciphertext),
                ciphertext_digest=reference.ciphertext_digest,
                plaintext_bytes=len(plaintext),
            )
        )
        return plaintext

    def _validate_reference(
        self,
        *,
        run_id: DurableAgentRunId,
        checkpoint_id: CheckpointId,
        sequence: CheckpointSequence,
        reference: ProtectedPayloadReference,
        ciphertext: bytes,
    ) -> None:
        if reference.key_version != self._key_version:
            raise AgentCodecError("protected payload key version is unavailable")
        if reference.ciphertext_bytes != len(ciphertext):
            raise AgentCodecError("protected payload ciphertext length is invalid")
        actual_digest = _sha256_digest(ciphertext)
        if not hmac.compare_digest(
            actual_digest.value,
            reference.ciphertext_digest.value,
        ):
            raise AgentCodecError("protected payload ciphertext digest is invalid")
        expected_reference = self._reference_value(
            run_id=run_id,
            checkpoint_id=checkpoint_id,
            sequence=sequence,
            ciphertext_digest=actual_digest,
        )
        if not hmac.compare_digest(reference.reference, expected_reference):
            raise AgentCodecError("protected payload reference does not match its context")

    def _associated_data(
        self,
        *,
        run_id: DurableAgentRunId,
        checkpoint_id: CheckpointId,
        sequence: CheckpointSequence,
    ) -> bytes:
        fields = (
            "phoenix-durable-fake-v1",
            self._protector_id,
            self._key_version,
            str(run_id),
            str(checkpoint_id),
            str(sequence.value),
        )
        return "\x00".join(fields).encode("ascii")

    def _reference_value(
        self,
        *,
        run_id: DurableAgentRunId,
        checkpoint_id: CheckpointId,
        sequence: CheckpointSequence,
        ciphertext_digest: CheckpointDigest,
    ) -> str:
        context = self._associated_data(
            run_id=run_id,
            checkpoint_id=checkpoint_id,
            sequence=sequence,
        )
        token = hmac.digest(
            self._secret,
            b"reference\x00" + context + ciphertext_digest.value.encode("ascii"),
            "sha256",
        ).hex()
        return f"fake-protected:{self._protector_id}:{self._key_version}:{token}"

    def _xor_stream(
        self,
        payload: bytes,
        *,
        associated_data: bytes,
    ) -> bytes:
        output = bytearray(len(payload))
        offset = 0
        counter = 0
        while offset < len(payload):
            block = hmac.digest(
                self._secret,
                b"stream\x00" + associated_data + counter.to_bytes(8, "big"),
                "sha256",
            )
            take = min(len(block), len(payload) - offset)
            for index in range(take):
                output[offset + index] = payload[offset + index] ^ block[index]
            offset += take
            counter += 1
        return bytes(output)
