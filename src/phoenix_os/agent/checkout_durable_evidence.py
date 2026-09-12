"""Content-free durable evidence for successful RFC-0039 development-checkout reads."""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from uuid import UUID

from phoenix_os.agent.checkout_agent_tools import (
    CHECKOUT_READ_BASE64_CHUNK_CHARS,
    CHECKOUT_READ_TOOL_ID,
    CHECKOUT_TOOL_ADAPTER_ID,
    CHECKOUT_TOOL_RESOLVER_ID,
    MAX_CHECKOUT_READ_BASE64_CHUNKS,
)
from phoenix_os.agent.checkout_workspace import MAX_CHECKOUT_TEXT_READ_BYTES
from phoenix_os.agent.contracts import (
    AgentRunId,
    AgentStepId,
    ToolCallId,
    ToolEffect,
    ToolInvocationRequest,
    ToolInvocationResult,
    ToolResultStatus,
)
from phoenix_os.agent.durable_contracts import (
    CheckpointEnvelope,
    CheckpointId,
    CheckpointNextOperation,
    DurableRunStatus,
    ExecutionAttempt,
    ExecutionAttemptKind,
    ExecutionAttemptStatus,
)
from phoenix_os.agent.durable_metadata import (
    DurableCheckpointHistoryValidator,
    DurableCheckpointMetadataProjector,
)
from phoenix_os.agent.durable_tool import DurableToolAttemptBinding
from phoenix_os.agent.durable_tool_execution import DurableToolResultMetadataProjectorFactory
from phoenix_os.agent.errors import (
    AgentCodecError,
    AgentLimitExceededError,
    AgentStateConflictError,
)

_CHECKOUT_RESOURCE_PATTERN = re.compile(
    r"^development-checkout:"
    r"(?P<workspace_id>[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"
    r"/generation:(?P<generation>[1-9][0-9]*)$"
)
_DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
_DECIMAL_PATTERN = re.compile(r"^(0|[1-9][0-9]*)$")

_EVIDENCE_PREFIX = "rfc0039.checkout.read."
_COUNT_KEY = _EVIDENCE_PREFIX + "count"
_BYTES_KEY = _EVIDENCE_PREFIX + "bytes"
_LAST_WORKSPACE_KEY = _EVIDENCE_PREFIX + "last.workspace_id"
_LAST_GENERATION_KEY = _EVIDENCE_PREFIX + "last.registration_generation"
_LAST_ROOT_IDENTITY_KEY = _EVIDENCE_PREFIX + "last.root_identity"
_LAST_FILE_IDENTITY_KEY = _EVIDENCE_PREFIX + "last.file_identity"
_LAST_CONTENT_DIGEST_KEY = _EVIDENCE_PREFIX + "last.content_digest"
_LAST_BYTE_LENGTH_KEY = _EVIDENCE_PREFIX + "last.byte_length"
_EVIDENCE_KEYS = frozenset(
    {
        _COUNT_KEY,
        _BYTES_KEY,
        _LAST_WORKSPACE_KEY,
        _LAST_GENERATION_KEY,
        _LAST_ROOT_IDENTITY_KEY,
        _LAST_FILE_IDENTITY_KEY,
        _LAST_CONTENT_DIGEST_KEY,
        _LAST_BYTE_LENGTH_KEY,
    }
)


@dataclass(frozen=True, slots=True)
class CheckoutReadDurableEvidence:
    """Validated content-free identity for one successful checkout read."""

    run_id: AgentRunId
    step_id: AgentStepId
    call_id: ToolCallId
    workspace_id: str
    registration_generation: int
    root_identity: str
    file_identity: str
    content_digest: str
    byte_length: int


def is_checkout_read_durable_binding(binding: DurableToolAttemptBinding) -> bool:
    """Return whether one durable binding is the exact isolated checkout read descriptor."""

    if not isinstance(binding, DurableToolAttemptBinding):
        raise TypeError("binding must be DurableToolAttemptBinding")
    descriptor = binding.descriptor
    return (
        descriptor.tool_id == CHECKOUT_READ_TOOL_ID
        and descriptor.resolver_id == CHECKOUT_TOOL_RESOLVER_ID
        and descriptor.adapter_id == CHECKOUT_TOOL_ADAPTER_ID
    )


def checkout_read_durable_usage(metadata: Mapping[str, str]) -> tuple[int, int]:
    """Return validated authoritative checkout read count and cumulative bytes."""

    if not isinstance(metadata, Mapping):
        raise TypeError("metadata must be a mapping")
    return _validate_prior_evidence(metadata)


class CheckoutReadCumulativeByteBudget:
    """Derive one-use checkout read caps from admitted policy and durable evidence."""

    def __init__(self, run_id: AgentRunId, *, max_bytes: int) -> None:
        if not isinstance(run_id, AgentRunId):
            raise TypeError("run_id must be AgentRunId")
        if isinstance(max_bytes, bool) or not isinstance(max_bytes, int):
            raise TypeError("max_bytes must be an int")
        if max_bytes < 1:
            raise ValueError("max_bytes must be positive")
        self._run_id = run_id
        self._max_bytes = max_bytes
        self._permits: dict[ToolCallId, int] = {}

    @property
    def max_bytes(self) -> int:
        return self._max_bytes

    def validate_submission(
        self,
        binding: DurableToolAttemptBinding,
        prepared_checkpoint: CheckpointEnvelope,
        *,
        now: object,
    ) -> None:
        del now
        if not is_checkout_read_durable_binding(binding):
            return
        if (
            binding.invocation.run_id != self._run_id
            or prepared_checkpoint.agent_run_id != self._run_id
        ):
            raise AgentStateConflictError()

        _count, prior_bytes = checkout_read_durable_usage(prepared_checkpoint.metadata.metadata)
        remaining = self._max_bytes - prior_bytes
        if remaining <= 0:
            raise AgentLimitExceededError()

        call_id = binding.invocation.call_id
        if call_id in self._permits:
            raise AgentStateConflictError()
        self._permits[call_id] = min(MAX_CHECKOUT_TEXT_READ_BYTES, remaining)

    def take_read_byte_limit(self, request: ToolInvocationRequest) -> int:
        if not isinstance(request, ToolInvocationRequest):
            raise TypeError("request must be ToolInvocationRequest")
        if request.run_id != self._run_id or request.tool_id != CHECKOUT_READ_TOOL_ID:
            raise AgentStateConflictError()
        try:
            return self._permits.pop(request.call_id)
        except KeyError as exception:
            raise AgentStateConflictError() from exception

    def discard_read_byte_limit(self, request: ToolInvocationRequest) -> None:
        if not isinstance(request, ToolInvocationRequest):
            raise TypeError("request must be ToolInvocationRequest")
        if request.run_id == self._run_id:
            self._permits.pop(request.call_id, None)


class CheckoutReadDurableResultMetadataProjectorFactory:
    """Convert exact checkout read results into one-use content-free checkpoint projectors."""

    def create_projector(
        self,
        binding: DurableToolAttemptBinding,
        result: ToolInvocationResult,
    ) -> DurableCheckpointMetadataProjector | None:
        if not isinstance(binding, DurableToolAttemptBinding):
            raise TypeError("binding must be DurableToolAttemptBinding")
        if not isinstance(result, ToolInvocationResult):
            raise TypeError("result must be ToolInvocationResult")

        if not is_checkout_read_durable_binding(binding):
            return None

        evidence = _extract_checkout_read_evidence(binding, result)
        return _CheckoutReadDurableMetadataProjector(evidence)


@dataclass(frozen=True, slots=True)
class _CheckoutReadDurableMetadataProjector:
    evidence: CheckoutReadDurableEvidence

    def project_metadata(
        self,
        current: CheckpointEnvelope,
        *,
        checkpoint_id: CheckpointId,
        status: DurableRunStatus,
        step_id: AgentStepId | None,
        next_operation: CheckpointNextOperation,
        active_attempt: ExecutionAttempt | None,
        metadata: Mapping[str, str],
    ) -> Mapping[str, str]:
        del checkpoint_id
        evidence = self.evidence
        if (
            current.agent_run_id != evidence.run_id
            or step_id != evidence.step_id
            or status is not DurableRunStatus.ACTIVE
            or next_operation is not CheckpointNextOperation.VALIDATE_RESULT
            or active_attempt is None
            or active_attempt.status is not ExecutionAttemptStatus.SUCCEEDED
            or active_attempt.agent_run_id != evidence.run_id
            or active_attempt.step_id != evidence.step_id
            or active_attempt.tool_call_id != evidence.call_id
        ):
            raise AgentStateConflictError()

        prior_count, prior_bytes = _validate_prior_evidence(metadata)
        projected = dict(metadata)
        projected.update(
            {
                _COUNT_KEY: str(prior_count + 1),
                _BYTES_KEY: str(prior_bytes + evidence.byte_length),
                _LAST_WORKSPACE_KEY: evidence.workspace_id,
                _LAST_GENERATION_KEY: str(evidence.registration_generation),
                _LAST_ROOT_IDENTITY_KEY: evidence.root_identity,
                _LAST_FILE_IDENTITY_KEY: evidence.file_identity,
                _LAST_CONTENT_DIGEST_KEY: evidence.content_digest,
                _LAST_BYTE_LENGTH_KEY: str(evidence.byte_length),
            }
        )
        return projected


def _extract_checkout_read_evidence(
    binding: DurableToolAttemptBinding,
    result: ToolInvocationResult,
) -> CheckoutReadDurableEvidence:
    invocation = binding.invocation
    if (
        result.status is not ToolResultStatus.SUCCEEDED
        or result.run_id != invocation.run_id
        or result.step_id != invocation.step_id
        or result.call_id != invocation.call_id
        or result.tool_id != invocation.tool_id
    ):
        raise AgentStateConflictError()

    resource_match = _CHECKOUT_RESOURCE_PATTERN.fullmatch(invocation.resolved_resource)
    if resource_match is None:
        raise AgentStateConflictError()
    resource_workspace = _canonical_uuid(resource_match.group("workspace_id"))
    resource_generation = _positive_int_text(resource_match.group("generation"))

    logical_path = invocation.arguments.get("logical_path")
    if not isinstance(logical_path, str) or not logical_path:
        raise AgentStateConflictError()

    output = result.output
    if not isinstance(output, Mapping):
        raise AgentStateConflictError()
    expected_output_keys = {"snapshot", "content_encoding", "content_base64_chunks"}
    if set(output) != expected_output_keys:
        raise AgentStateConflictError()
    if output["content_encoding"] != "base64-utf8":
        raise AgentStateConflictError()

    snapshot = output["snapshot"]
    if not isinstance(snapshot, Mapping):
        raise AgentStateConflictError()
    expected_snapshot_keys = {
        "run_id",
        "workspace_id",
        "registration_generation",
        "logical_path",
        "root_identity",
        "file_identity",
        "content_digest",
        "byte_length",
    }
    if set(snapshot) != expected_snapshot_keys:
        raise AgentStateConflictError()

    snapshot_run = snapshot["run_id"]
    workspace_id = snapshot["workspace_id"]
    generation = snapshot["registration_generation"]
    snapshot_path = snapshot["logical_path"]
    root_identity = snapshot["root_identity"]
    file_identity = snapshot["file_identity"]
    content_digest = snapshot["content_digest"]
    byte_length = snapshot["byte_length"]

    if snapshot_run != str(invocation.run_id):
        raise AgentStateConflictError()
    if not isinstance(workspace_id, str) or _canonical_uuid(workspace_id) != resource_workspace:
        raise AgentStateConflictError()
    if (
        isinstance(generation, bool)
        or not isinstance(generation, int)
        or generation != resource_generation
    ):
        raise AgentStateConflictError()
    if snapshot_path != logical_path:
        raise AgentStateConflictError()
    if (
        not isinstance(root_identity, str)
        or not _is_digest(root_identity)
        or not isinstance(file_identity, str)
        or not _is_digest(file_identity)
        or not isinstance(content_digest, str)
        or not _is_digest(content_digest)
    ):
        raise AgentStateConflictError()
    if (
        isinstance(byte_length, bool)
        or not isinstance(byte_length, int)
        or byte_length < 0
        or byte_length > MAX_CHECKOUT_TEXT_READ_BYTES
    ):
        raise AgentStateConflictError()

    chunks = output["content_base64_chunks"]
    if not isinstance(chunks, tuple) or len(chunks) > MAX_CHECKOUT_READ_BASE64_CHUNKS:
        raise AgentStateConflictError()
    if any(
        not isinstance(chunk, str) or len(chunk) > CHECKOUT_READ_BASE64_CHUNK_CHARS
        for chunk in chunks
    ):
        raise AgentStateConflictError()
    try:
        payload = base64.b64decode("".join(chunks), validate=True)
    except (binascii.Error, ValueError) as exception:
        raise AgentStateConflictError() from exception
    if len(payload) != byte_length:
        raise AgentStateConflictError()
    if "sha256:" + hashlib.sha256(payload).hexdigest() != content_digest:
        raise AgentStateConflictError()

    return CheckoutReadDurableEvidence(
        run_id=invocation.run_id,
        step_id=invocation.step_id,
        call_id=invocation.call_id,
        workspace_id=workspace_id,
        registration_generation=generation,
        root_identity=root_identity,
        file_identity=file_identity,
        content_digest=content_digest,
        byte_length=byte_length,
    )


def _validate_prior_evidence(metadata: Mapping[str, str]) -> tuple[int, int]:
    present = frozenset(key for key in metadata if key.startswith(_EVIDENCE_PREFIX))
    if not present:
        return 0, 0
    if present != _EVIDENCE_KEYS:
        raise AgentStateConflictError()

    count = _non_negative_decimal(metadata[_COUNT_KEY])
    total_bytes = _non_negative_decimal(metadata[_BYTES_KEY])
    generation = _positive_int_text(metadata[_LAST_GENERATION_KEY])
    last_length = _non_negative_decimal(metadata[_LAST_BYTE_LENGTH_KEY])
    if count < 1 or generation < 1 or last_length > MAX_CHECKOUT_TEXT_READ_BYTES:
        raise AgentStateConflictError()
    if last_length > total_bytes:
        raise AgentStateConflictError()

    _canonical_uuid(metadata[_LAST_WORKSPACE_KEY])
    for key in (
        _LAST_ROOT_IDENTITY_KEY,
        _LAST_FILE_IDENTITY_KEY,
        _LAST_CONTENT_DIGEST_KEY,
    ):
        if not _is_digest(metadata[key]):
            raise AgentStateConflictError()
    return count, total_bytes


def _canonical_uuid(value: str) -> str:
    if not isinstance(value, str):
        raise AgentStateConflictError()
    try:
        parsed = UUID(value)
    except (ValueError, AttributeError) as exception:
        raise AgentStateConflictError() from exception
    canonical = str(parsed)
    if canonical != value:
        raise AgentStateConflictError()
    return canonical


def _positive_int_text(value: str) -> int:
    parsed = _non_negative_decimal(value)
    if parsed < 1:
        raise AgentStateConflictError()
    return parsed


def _non_negative_decimal(value: str) -> int:
    if not isinstance(value, str) or _DECIMAL_PATTERN.fullmatch(value) is None:
        raise AgentStateConflictError()
    return int(value)


def _is_digest(value: object) -> bool:
    return isinstance(value, str) and _DIGEST_PATTERN.fullmatch(value) is not None


@dataclass(frozen=True, slots=True)
class _CheckoutReadDurableHistoryEvidence:
    count: int
    total_bytes: int
    workspace_id: str
    registration_generation: int
    root_identity: str
    file_identity: str
    content_digest: str
    last_byte_length: int


class CheckoutReadDurableEvidenceHistoryValidator:
    """Validate content-free checkout-read evidence continuity over durable history."""

    def validate_history(
        self,
        current: CheckpointEnvelope,
        history: tuple[CheckpointEnvelope, ...],
    ) -> None:
        if not isinstance(current, CheckpointEnvelope):
            raise TypeError("current must be CheckpointEnvelope")
        if not isinstance(history, tuple):
            raise TypeError("history must be a tuple")
        if not history or history[-1] != current:
            raise AgentCodecError("checkout read durable history is not authoritative")
        if any(not isinstance(checkpoint, CheckpointEnvelope) for checkpoint in history):
            raise AgentCodecError("checkout read durable history contains an invalid checkpoint")

        previous: _CheckoutReadDurableHistoryEvidence | None = None
        evidence_seen = False
        for index, checkpoint in enumerate(history):
            evidence = _decode_checkout_read_history_evidence(checkpoint)
            if evidence is None:
                if evidence_seen:
                    raise AgentCodecError("checkout read durable evidence disappeared from history")
                continue

            if not evidence_seen:
                if index == 0:
                    raise AgentCodecError(
                        "checkout read durable evidence cannot exist at run creation"
                    )
                if evidence.count != 1 or evidence.total_bytes != evidence.last_byte_length:
                    raise AgentCodecError("first checkout read durable evidence is inconsistent")
                _require_checkout_read_evidence_increment_transition(checkpoint)
                evidence_seen = True
                previous = evidence
                continue

            if previous is None:
                raise AgentCodecError("checkout read durable evidence history is inconsistent")
            if evidence == previous:
                continue
            if (
                evidence.count != previous.count + 1
                or evidence.total_bytes != previous.total_bytes + evidence.last_byte_length
            ):
                raise AgentCodecError("checkout read durable evidence counters are not monotonic")
            _require_checkout_read_evidence_increment_transition(checkpoint)
            previous = evidence


def _decode_checkout_read_history_evidence(
    checkpoint: CheckpointEnvelope,
) -> _CheckoutReadDurableHistoryEvidence | None:
    metadata = checkpoint.metadata.metadata
    present = frozenset(key for key in metadata if key.startswith(_EVIDENCE_PREFIX))
    if not present:
        return None
    try:
        count, total_bytes = _validate_prior_evidence(metadata)
        workspace_id = _canonical_uuid(metadata[_LAST_WORKSPACE_KEY])
        generation = _positive_int_text(metadata[_LAST_GENERATION_KEY])
        last_byte_length = _non_negative_decimal(metadata[_LAST_BYTE_LENGTH_KEY])
    except AgentStateConflictError as exception:
        raise AgentCodecError("checkout read durable evidence metadata is invalid") from exception

    return _CheckoutReadDurableHistoryEvidence(
        count=count,
        total_bytes=total_bytes,
        workspace_id=workspace_id,
        registration_generation=generation,
        root_identity=metadata[_LAST_ROOT_IDENTITY_KEY],
        file_identity=metadata[_LAST_FILE_IDENTITY_KEY],
        content_digest=metadata[_LAST_CONTENT_DIGEST_KEY],
        last_byte_length=last_byte_length,
    )


def _require_checkout_read_evidence_increment_transition(
    checkpoint: CheckpointEnvelope,
) -> None:
    attempt = checkpoint.metadata.active_attempt
    if (
        checkpoint.status is not DurableRunStatus.ACTIVE
        or checkpoint.metadata.next_operation is not CheckpointNextOperation.VALIDATE_RESULT
        or checkpoint.step_id is None
        or attempt is None
        or attempt.kind is not ExecutionAttemptKind.TOOL_INVOCATION
        or attempt.status is not ExecutionAttemptStatus.SUCCEEDED
        or attempt.tool_effect is not ToolEffect.READ_ONLY
        or attempt.agent_run_id != checkpoint.agent_run_id
        or attempt.step_id != checkpoint.step_id
    ):
        raise AgentCodecError(
            "checkout read durable evidence changed outside a successful read-only tool result"
        )


assert isinstance(
    CheckoutReadDurableEvidenceHistoryValidator(),
    DurableCheckpointHistoryValidator,
)

assert isinstance(
    CheckoutReadDurableResultMetadataProjectorFactory(),
    DurableToolResultMetadataProjectorFactory,
)
