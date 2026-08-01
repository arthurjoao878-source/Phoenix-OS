"""Protected-payload helpers for RFC-0028 durable agent checkpoints."""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Awaitable
from datetime import datetime
from typing import Final, Protocol, runtime_checkable

from phoenix_os.agent.durable_contracts import (
    CheckpointEnvelope,
    CheckpointId,
    CheckpointPayloadProfile,
    CheckpointSchemaVersion,
    CheckpointSequence,
    DurableAgentRunId,
    DurableLease,
    DurableRunLimits,
    DurableRunStore,
    DurableRunVersion,
)
from phoenix_os.agent.errors import (
    AgentCodecError,
    AgentLimitExceededError,
    AgentStateConflictError,
)

DURABLE_PROTECTED_PAYLOAD_CONTEXT_VERSION: Final = 1
_PROTECTED_PAYLOAD_CONTEXT_KIND: Final = "phoenix.agent.durable-protected-payload"


@runtime_checkable
class DurableProtectedPayloadStore(DurableRunStore, Protocol):
    """Optional durable-store capability for atomic protected-payload persistence."""

    def create_protected(
        self,
        checkpoint: CheckpointEnvelope,
        *,
        protected_payload: bytes,
    ) -> Awaitable[None]: ...

    def append_protected(
        self,
        checkpoint: CheckpointEnvelope,
        *,
        expected_version: DurableRunVersion,
        lease: DurableLease,
        now: datetime,
        protected_payload: bytes,
    ) -> Awaitable[CheckpointEnvelope]: ...

    def get_protected_payload(
        self,
        checkpoint: CheckpointEnvelope,
        *,
        lease: DurableLease,
        now: datetime,
    ) -> Awaitable[bytes]: ...


def protected_payload_associated_data(
    *,
    run_id: DurableAgentRunId,
    checkpoint_id: CheckpointId,
    sequence: CheckpointSequence,
    schema_version: CheckpointSchemaVersion | None = None,
    profile: CheckpointPayloadProfile = CheckpointPayloadProfile.PROTECTED_CONTENT,
) -> bytes:
    """Return canonical content-free associated data for payload protection."""

    if not isinstance(run_id, DurableAgentRunId):
        raise TypeError("run_id must be DurableAgentRunId")
    if not isinstance(checkpoint_id, CheckpointId):
        raise TypeError("checkpoint_id must be CheckpointId")
    if not isinstance(sequence, CheckpointSequence):
        raise TypeError("sequence must be CheckpointSequence")
    selected_schema = CheckpointSchemaVersion() if schema_version is None else schema_version
    if not isinstance(selected_schema, CheckpointSchemaVersion):
        raise TypeError("schema_version must be CheckpointSchemaVersion or None")
    if not isinstance(profile, CheckpointPayloadProfile):
        raise TypeError("profile must be CheckpointPayloadProfile")
    if profile is not CheckpointPayloadProfile.PROTECTED_CONTENT:
        raise ValueError("protected payload profile must be protected_content")

    document = {
        "checkpoint_id": str(checkpoint_id),
        "kind": _PROTECTED_PAYLOAD_CONTEXT_KIND,
        "profile": profile.value,
        "run_id": str(run_id),
        "schema_version": selected_schema.value,
        "sequence": sequence.value,
        "version": DURABLE_PROTECTED_PAYLOAD_CONTEXT_VERSION,
    }
    return json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def validate_protected_payload_for_checkpoint(
    checkpoint: CheckpointEnvelope,
    protected_payload: bytes | None,
    *,
    limits: DurableRunLimits,
) -> bytes | None:
    """Validate ciphertext against one checkpoint's protected-payload reference."""

    if not isinstance(checkpoint, CheckpointEnvelope):
        raise TypeError("checkpoint must be CheckpointEnvelope")
    if not isinstance(limits, DurableRunLimits):
        raise TypeError("limits must be DurableRunLimits")
    if protected_payload is not None and not isinstance(protected_payload, bytes):
        raise TypeError("protected_payload must be bytes or None")

    reference = checkpoint.metadata.payload_reference
    if reference is None:
        if protected_payload is not None:
            raise AgentStateConflictError()
        return None

    if checkpoint.metadata.payload_profile is not CheckpointPayloadProfile.PROTECTED_CONTENT:
        raise AgentStateConflictError()
    if checkpoint.metadata.compatibility.payload_codec is None:
        raise AgentStateConflictError()
    if protected_payload is None:
        raise AgentStateConflictError()

    if reference.plaintext_bytes > limits.max_protected_payload_bytes:
        raise AgentLimitExceededError()

    maximum_ciphertext_bytes = limits.max_protected_payload_bytes + 65_536
    if (
        reference.ciphertext_bytes > maximum_ciphertext_bytes
        or len(protected_payload) > maximum_ciphertext_bytes
    ):
        raise AgentLimitExceededError()
    if reference.ciphertext_bytes != len(protected_payload):
        raise AgentCodecError("protected payload ciphertext length is invalid")

    actual_digest = hashlib.sha256(protected_payload).hexdigest()
    if not hmac.compare_digest(actual_digest, reference.ciphertext_digest.value):
        raise AgentCodecError("protected payload ciphertext digest is invalid")
    if reference.created_at >= checkpoint.metadata.retention_deadline:
        raise AgentStateConflictError()

    return bytes(protected_payload)
