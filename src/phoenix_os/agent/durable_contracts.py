"""Immutable contracts for durable agent checkpoints and controlled recovery."""

from __future__ import annotations

import re
from collections.abc import Awaitable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from types import MappingProxyType
from typing import Protocol, runtime_checkable
from uuid import UUID, uuid4

from phoenix_os.agent.contracts import (
    AgentId,
    AgentRunId,
    AgentStepId,
    ToolCallId,
    ToolEffect,
)
from phoenix_os.agent.state import AgentBudgetSnapshot

CURRENT_CHECKPOINT_SCHEMA_VERSION = 1

MAX_DURABLE_IDENTIFIER_LENGTH = 128
MAX_DURABLE_REFERENCE_LENGTH = 1_024
MAX_DURABLE_REASON_LENGTH = 1_024
MAX_DURABLE_METADATA_ITEMS = 64
MAX_DURABLE_METADATA_KEY_LENGTH = 128
MAX_DURABLE_METADATA_VALUE_LENGTH = 1_024
MAX_CHECKPOINTS_PER_RUN = 4_096
MAX_CHECKPOINT_ENVELOPE_BYTES = 1_048_576
MAX_PROTECTED_PAYLOAD_BYTES = 4_194_304
MAX_CHECKPOINT_HISTORY_BYTES = 67_108_864
MAX_RECOVERY_CANDIDATE_PAGE = 1_024
MAX_RECOVERY_ATTEMPTS = 128
MAX_RECONCILIATION_ATTEMPTS = 64
MAX_PAUSE_DURATION = timedelta(days=30)
MAX_DURABLE_LIFETIME = timedelta(days=365)
MAX_LEASE_DURATION = timedelta(minutes=10)
MAX_LEASE_RENEWAL_INTERVAL = timedelta(minutes=5)
MAX_METADATA_RETENTION = timedelta(days=365)
MAX_PAYLOAD_RETENTION = timedelta(days=90)
MAX_TOMBSTONE_RETENTION = timedelta(days=3_650)

_IDENTIFIER_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,127})$")
_REFERENCE_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9._:/-]{0,1023})$")
_DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")


def _normalize_identifier(value: str, *, label: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{label} must be a string")
    normalized = value.strip()
    if not _IDENTIFIER_PATTERN.fullmatch(normalized):
        raise ValueError(
            f"{label} must use lowercase ASCII letters, digits, dot, underscore, or hyphen"
        )
    return normalized


def _normalize_reference(value: str, *, label: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{label} must be a string")
    normalized = value.strip()
    if not _REFERENCE_PATTERN.fullmatch(normalized):
        raise ValueError(f"{label} is invalid")
    return normalized


def _normalize_text(value: str, *, label: str, maximum: int) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{label} must be a string")
    normalized = value.strip()
    if not normalized:
        raise ValueError(f"{label} must not be blank")
    if len(normalized) > maximum:
        raise ValueError(f"{label} exceeds the maximum length")
    return normalized


def _require_timezone_aware(value: datetime, *, label: str) -> None:
    if not isinstance(value, datetime):
        raise TypeError(f"{label} must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")


def _require_positive_integer(value: int, *, label: str, maximum: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{label} must be an integer")
    if value <= 0:
        raise ValueError(f"{label} must be greater than zero")
    if value > maximum:
        raise ValueError(f"{label} exceeds the global maximum")


def _require_non_negative_integer(value: int, *, label: str, maximum: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{label} must be an integer")
    if value < 0:
        raise ValueError(f"{label} must not be negative")
    if value > maximum:
        raise ValueError(f"{label} exceeds the global maximum")


def _require_positive_duration(
    value: timedelta,
    *,
    label: str,
    maximum: timedelta,
) -> None:
    if not isinstance(value, timedelta):
        raise TypeError(f"{label} must be a timedelta")
    if value <= timedelta(0):
        raise ValueError(f"{label} must be greater than zero")
    if value > maximum:
        raise ValueError(f"{label} exceeds the global maximum")


def _freeze_metadata(value: Mapping[str, str]) -> Mapping[str, str]:
    if not isinstance(value, Mapping):
        raise TypeError("metadata must be a mapping")
    if len(value) > MAX_DURABLE_METADATA_ITEMS:
        raise ValueError("metadata exceeds the maximum item count")
    frozen: dict[str, str] = {}
    for key, item in value.items():
        normalized_key = _normalize_identifier(key, label="metadata key")
        normalized_value = _normalize_text(
            item,
            label="metadata value",
            maximum=MAX_DURABLE_METADATA_VALUE_LENGTH,
        )
        if len(normalized_key) > MAX_DURABLE_METADATA_KEY_LENGTH:
            raise ValueError("metadata key exceeds the maximum length")
        if normalized_key in frozen:
            raise ValueError("metadata contains duplicate normalized keys")
        frozen[normalized_key] = normalized_value
    return MappingProxyType(frozen)


class DurableRunStatus(StrEnum):
    """Stable durable lifecycle states for one RFC-0027 run."""

    CREATED = "created"
    ACTIVE = "active"
    CHECKPOINTING = "checkpointing"
    PAUSED_APPROVAL = "paused_approval"
    PAUSED_OPERATOR = "paused_operator"
    PAUSED_SHUTDOWN = "paused_shutdown"
    RECOVERING = "recovering"
    RECONCILING = "reconciling"
    INDETERMINATE_MODEL = "indeterminate_model"
    INDETERMINATE_TOOL = "indeterminate_tool"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    EXPIRED = "expired"

    @property
    def terminal(self) -> bool:
        return self in {
            self.COMPLETED,
            self.FAILED,
            self.CANCELLED,
            self.EXPIRED,
        }

    @property
    def indeterminate(self) -> bool:
        return self in {
            self.INDETERMINATE_MODEL,
            self.INDETERMINATE_TOOL,
        }


class CheckpointPayloadProfile(StrEnum):
    """Persisted continuation-content policy for one durable run."""

    METADATA_ONLY = "metadata_only"
    PROTECTED_CONTENT = "protected_content"


class CheckpointNextOperation(StrEnum):
    """The only reviewed operation category allowed after one checkpoint."""

    NONE = "none"
    MODEL_TURN = "model_turn"
    VALIDATE_PROPOSAL = "validate_proposal"
    AUTHORIZE_TOOL = "authorize_tool"
    WAIT_APPROVAL = "wait_approval"
    TOOL_INVOCATION = "tool_invocation"
    VALIDATE_RESULT = "validate_result"
    COMPLETE = "complete"
    OPERATOR_REVIEW = "operator_review"


class RecoveryPoint(StrEnum):
    """Classification produced after validating one persisted checkpoint."""

    SAFE_BOUNDARY = "safe_boundary"
    AWAITING_APPROVAL = "awaiting_approval"
    OPERATOR_PAUSE = "operator_pause"
    SHUTDOWN_PAUSE = "shutdown_pause"
    ACTIVE_MODEL_ATTEMPT = "active_model_attempt"
    ACTIVE_TOOL_ATTEMPT = "active_tool_attempt"


class RecoveryDisposition(StrEnum):
    """Fail-closed outcome selected by the recovery coordinator."""

    RESUME = "resume"
    PAUSE_OPERATOR = "pause_operator"
    MARK_INDETERMINATE_MODEL = "mark_indeterminate_model"
    MARK_INDETERMINATE_TOOL = "mark_indeterminate_tool"
    TERMINATE_FAILED = "terminate_failed"
    TERMINATE_EXPIRED = "terminate_expired"


class ExecutionAttemptKind(StrEnum):
    MODEL_TURN = "model_turn"
    TOOL_INVOCATION = "tool_invocation"


class ExecutionAttemptStatus(StrEnum):
    PREPARED = "prepared"
    STARTED = "started"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"
    INDETERMINATE = "indeterminate"

    @property
    def terminal(self) -> bool:
        return self in {
            self.SUCCEEDED,
            self.FAILED,
            self.CANCELLED,
            self.TIMED_OUT,
            self.INDETERMINATE,
        }


class IndeterminateReason(StrEnum):
    PROCESS_LOSS = "process_loss"
    STORE_COMMIT_UNKNOWN = "store_commit_unknown"
    PROVIDER_STATUS_UNKNOWN = "provider_status_unknown"
    TOOL_STATUS_UNKNOWN = "tool_status_unknown"
    LEASE_LOST = "lease_lost"
    SHUTDOWN_TIMEOUT = "shutdown_timeout"


class ResumeReason(StrEnum):
    STARTUP_RECOVERY = "startup_recovery"
    OPERATOR_REQUEST = "operator_request"
    APPROVAL_AVAILABLE = "approval_available"
    SHUTDOWN_RECOVERY = "shutdown_recovery"


class ResumeDecision(StrEnum):
    RESUME = "resume"
    PAUSE = "pause"
    DENY = "deny"
    FAIL = "fail"


class ReconciliationDecision(StrEnum):
    CONFIRM_SUCCEEDED = "confirm_succeeded"
    CONFIRM_FAILED = "confirm_failed"
    CONFIRM_NOT_STARTED = "confirm_not_started"
    REMAIN_INDETERMINATE = "remain_indeterminate"
    CANCEL_RUN = "cancel_run"
    FAIL_RUN = "fail_run"


@dataclass(frozen=True, slots=True, order=True)
class DurableAgentRunId:
    """Phoenix-owned stable identifier for one durable agent run."""

    value: UUID = field(default_factory=uuid4)

    def __post_init__(self) -> None:
        if not isinstance(self.value, UUID):
            raise TypeError("durable agent run id must be UUID")

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True, order=True)
class CheckpointId:
    value: UUID = field(default_factory=uuid4)

    def __post_init__(self) -> None:
        if not isinstance(self.value, UUID):
            raise TypeError("checkpoint id must be UUID")

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True, order=True)
class ExecutionAttemptId:
    value: UUID = field(default_factory=uuid4)

    def __post_init__(self) -> None:
        if not isinstance(self.value, UUID):
            raise TypeError("execution attempt id must be UUID")

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True, order=True)
class DurableLeaseId:
    value: UUID = field(default_factory=uuid4)

    def __post_init__(self) -> None:
        if not isinstance(self.value, UUID):
            raise TypeError("durable lease id must be UUID")

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True, order=True)
class DurableRunVersion:
    value: int = 1

    def __post_init__(self) -> None:
        _require_positive_integer(
            self.value,
            label="durable run version",
            maximum=2_147_483_647,
        )

    def next(self) -> DurableRunVersion:
        return DurableRunVersion(self.value + 1)


@dataclass(frozen=True, slots=True, order=True)
class CheckpointSequence:
    value: int = 1

    def __post_init__(self) -> None:
        _require_positive_integer(
            self.value,
            label="checkpoint sequence",
            maximum=MAX_CHECKPOINTS_PER_RUN,
        )

    def next(self) -> CheckpointSequence:
        return CheckpointSequence(self.value + 1)


@dataclass(frozen=True, slots=True, order=True)
class CheckpointSchemaVersion:
    value: int = CURRENT_CHECKPOINT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        _require_positive_integer(
            self.value,
            label="checkpoint schema version",
            maximum=65_535,
        )


@dataclass(frozen=True, slots=True, order=True)
class FencingGeneration:
    value: int = 1

    def __post_init__(self) -> None:
        _require_positive_integer(
            self.value,
            label="fencing generation",
            maximum=2_147_483_647,
        )

    def next(self) -> FencingGeneration:
        return FencingGeneration(self.value + 1)


@dataclass(frozen=True, slots=True, order=True)
class CheckpointDigest:
    """Canonical lowercase SHA-256 digest."""

    value: str

    def __post_init__(self) -> None:
        if not isinstance(self.value, str):
            raise TypeError("checkpoint digest must be a string")
        if not _DIGEST_PATTERN.fullmatch(self.value):
            raise ValueError("checkpoint digest must be 64 lowercase hexadecimal characters")

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class DurableRunLimits:
    """Finite global bounds applied to one durable run."""

    max_checkpoints: int = 256
    max_checkpoint_envelope_bytes: int = 262_144
    max_protected_payload_bytes: int = 1_048_576
    max_checkpoint_history_bytes: int = 8_388_608
    max_recovery_attempts: int = 8
    max_reconciliation_attempts: int = 4
    max_pause_duration: timedelta = timedelta(days=1)
    max_total_lifetime: timedelta = timedelta(days=7)
    lease_duration: timedelta = timedelta(seconds=30)
    lease_renewal_interval: timedelta = timedelta(seconds=10)

    def __post_init__(self) -> None:
        integer_limits = (
            ("max_checkpoints", self.max_checkpoints, MAX_CHECKPOINTS_PER_RUN),
            (
                "max_checkpoint_envelope_bytes",
                self.max_checkpoint_envelope_bytes,
                MAX_CHECKPOINT_ENVELOPE_BYTES,
            ),
            (
                "max_protected_payload_bytes",
                self.max_protected_payload_bytes,
                MAX_PROTECTED_PAYLOAD_BYTES,
            ),
            (
                "max_checkpoint_history_bytes",
                self.max_checkpoint_history_bytes,
                MAX_CHECKPOINT_HISTORY_BYTES,
            ),
            (
                "max_recovery_attempts",
                self.max_recovery_attempts,
                MAX_RECOVERY_ATTEMPTS,
            ),
            (
                "max_reconciliation_attempts",
                self.max_reconciliation_attempts,
                MAX_RECONCILIATION_ATTEMPTS,
            ),
        )
        for label, value, maximum in integer_limits:
            _require_positive_integer(value, label=label, maximum=maximum)

        _require_positive_duration(
            self.max_pause_duration,
            label="max_pause_duration",
            maximum=MAX_PAUSE_DURATION,
        )
        _require_positive_duration(
            self.max_total_lifetime,
            label="max_total_lifetime",
            maximum=MAX_DURABLE_LIFETIME,
        )
        _require_positive_duration(
            self.lease_duration,
            label="lease_duration",
            maximum=MAX_LEASE_DURATION,
        )
        _require_positive_duration(
            self.lease_renewal_interval,
            label="lease_renewal_interval",
            maximum=MAX_LEASE_RENEWAL_INTERVAL,
        )
        if self.lease_renewal_interval >= self.lease_duration:
            raise ValueError("lease renewal interval must be shorter than lease duration")


@dataclass(frozen=True, slots=True)
class CompatibilityDigests:
    """Content-free compatibility evidence for deterministic recovery."""

    configuration: CheckpointDigest
    tool_registry: CheckpointDigest
    model_provider: CheckpointDigest
    checkpoint_codec: CheckpointDigest
    payload_codec: CheckpointDigest | None = None

    def __post_init__(self) -> None:
        required = (
            ("configuration", self.configuration),
            ("tool_registry", self.tool_registry),
            ("model_provider", self.model_provider),
            ("checkpoint_codec", self.checkpoint_codec),
        )
        for label, value in required:
            if not isinstance(value, CheckpointDigest):
                raise TypeError(f"{label} must be CheckpointDigest")
        if self.payload_codec is not None and not isinstance(
            self.payload_codec,
            CheckpointDigest,
        ):
            raise TypeError("payload_codec must be CheckpointDigest or None")


@dataclass(frozen=True, slots=True)
class ProtectedPayloadReference:
    """Opaque reference and bounded safe metadata for protected continuation data."""

    reference: str
    key_version: str
    plaintext_bytes: int
    ciphertext_bytes: int
    ciphertext_digest: CheckpointDigest
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "reference",
            _normalize_reference(self.reference, label="protected payload reference"),
        )
        object.__setattr__(
            self,
            "key_version",
            _normalize_identifier(self.key_version, label="protection key version"),
        )
        _require_non_negative_integer(
            self.plaintext_bytes,
            label="plaintext_bytes",
            maximum=MAX_PROTECTED_PAYLOAD_BYTES,
        )
        _require_positive_integer(
            self.ciphertext_bytes,
            label="ciphertext_bytes",
            maximum=MAX_PROTECTED_PAYLOAD_BYTES + 65_536,
        )
        if not isinstance(self.ciphertext_digest, CheckpointDigest):
            raise TypeError("ciphertext_digest must be CheckpointDigest")
        _require_timezone_aware(self.created_at, label="created_at")


@dataclass(frozen=True, slots=True)
class ExecutionAttempt:
    """Content-free durable record for one external model or tool attempt."""

    attempt_id: ExecutionAttemptId
    kind: ExecutionAttemptKind
    status: ExecutionAttemptStatus
    agent_run_id: AgentRunId
    step_id: AgentStepId
    prepared_at: datetime
    tool_call_id: ToolCallId | None = None
    tool_effect: ToolEffect | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    external_request_digest: CheckpointDigest | None = None
    indeterminate_reason: IndeterminateReason | None = None
    error_code: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.attempt_id, ExecutionAttemptId):
            raise TypeError("attempt_id must be ExecutionAttemptId")
        if not isinstance(self.kind, ExecutionAttemptKind):
            raise TypeError("kind must be ExecutionAttemptKind")
        if not isinstance(self.status, ExecutionAttemptStatus):
            raise TypeError("status must be ExecutionAttemptStatus")
        if not isinstance(self.agent_run_id, AgentRunId):
            raise TypeError("agent_run_id must be AgentRunId")
        if not isinstance(self.step_id, AgentStepId):
            raise TypeError("step_id must be AgentStepId")
        _require_timezone_aware(self.prepared_at, label="prepared_at")

        if self.kind is ExecutionAttemptKind.MODEL_TURN:
            if self.tool_call_id is not None or self.tool_effect is not None:
                raise ValueError("model attempts cannot contain tool identity or effect")
        else:
            if not isinstance(self.tool_call_id, ToolCallId):
                raise ValueError("tool attempts require tool_call_id")
            if not isinstance(self.tool_effect, ToolEffect):
                raise ValueError("tool attempts require tool_effect")

        if self.started_at is not None:
            _require_timezone_aware(self.started_at, label="started_at")
            if self.started_at < self.prepared_at:
                raise ValueError("started_at cannot precede prepared_at")
        if self.completed_at is not None:
            _require_timezone_aware(self.completed_at, label="completed_at")
            if self.completed_at < self.prepared_at:
                raise ValueError("completed_at cannot precede prepared_at")
            if self.started_at is not None and self.completed_at < self.started_at:
                raise ValueError("completed_at cannot precede started_at")

        if self.external_request_digest is not None and not isinstance(
            self.external_request_digest,
            CheckpointDigest,
        ):
            raise TypeError("external_request_digest must be CheckpointDigest or None")

        if self.status is ExecutionAttemptStatus.PREPARED:
            if self.started_at is not None or self.completed_at is not None:
                raise ValueError("prepared attempts cannot contain start or completion time")
        elif self.status is ExecutionAttemptStatus.STARTED:
            if self.started_at is None or self.completed_at is not None:
                raise ValueError("started attempts require started_at and no completed_at")
        else:
            if self.completed_at is None:
                raise ValueError("terminal attempts require completed_at")

        if self.status is ExecutionAttemptStatus.INDETERMINATE:
            if not isinstance(self.indeterminate_reason, IndeterminateReason):
                raise ValueError("indeterminate attempts require indeterminate_reason")
        elif self.indeterminate_reason is not None:
            raise ValueError("only indeterminate attempts may contain indeterminate_reason")

        if self.status is ExecutionAttemptStatus.SUCCEEDED:
            if self.error_code is not None:
                raise ValueError("successful attempts cannot contain error_code")
        elif self.status in {
            ExecutionAttemptStatus.FAILED,
            ExecutionAttemptStatus.TIMED_OUT,
        }:
            if self.error_code is None:
                raise ValueError("failed or timed-out attempts require error_code")

        if self.error_code is not None:
            object.__setattr__(
                self,
                "error_code",
                _normalize_identifier(self.error_code, label="attempt error code"),
            )


@dataclass(frozen=True, slots=True)
class CheckpointMetadata:
    """Bounded Phoenix-owned continuation metadata with no implicit authority."""

    agent_id: AgentId
    actor_id: str
    next_operation: CheckpointNextOperation
    budget: AgentBudgetSnapshot
    compatibility: CompatibilityDigests
    payload_profile: CheckpointPayloadProfile
    retention_deadline: datetime
    active_attempt: ExecutionAttempt | None = None
    payload_reference: ProtectedPayloadReference | None = None
    metadata: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.agent_id, AgentId):
            raise TypeError("agent_id must be AgentId")
        object.__setattr__(
            self,
            "actor_id",
            _normalize_identifier(self.actor_id, label="durable actor id"),
        )
        if not isinstance(self.next_operation, CheckpointNextOperation):
            raise TypeError("next_operation must be CheckpointNextOperation")
        if not isinstance(self.budget, AgentBudgetSnapshot):
            raise TypeError("budget must be AgentBudgetSnapshot")
        if not isinstance(self.compatibility, CompatibilityDigests):
            raise TypeError("compatibility must be CompatibilityDigests")
        if not isinstance(self.payload_profile, CheckpointPayloadProfile):
            raise TypeError("payload_profile must be CheckpointPayloadProfile")
        _require_timezone_aware(self.retention_deadline, label="retention_deadline")
        if self.retention_deadline <= self.budget.started_at:
            raise ValueError("retention_deadline must follow the original run start")
        if self.active_attempt is not None and not isinstance(
            self.active_attempt,
            ExecutionAttempt,
        ):
            raise TypeError("active_attempt must be ExecutionAttempt or None")
        if self.payload_reference is not None and not isinstance(
            self.payload_reference,
            ProtectedPayloadReference,
        ):
            raise TypeError("payload_reference must be ProtectedPayloadReference or None")
        if (
            self.payload_profile is CheckpointPayloadProfile.METADATA_ONLY
            and self.payload_reference is not None
        ):
            raise ValueError("metadata-only checkpoints cannot reference protected payloads")
        object.__setattr__(self, "metadata", _freeze_metadata(self.metadata))


@dataclass(frozen=True, slots=True)
class CheckpointEnvelope:
    """Immutable checkpoint envelope whose digest is verified by the codec."""

    schema_version: CheckpointSchemaVersion
    durable_run_id: DurableAgentRunId
    checkpoint_id: CheckpointId
    sequence: CheckpointSequence
    previous_digest: CheckpointDigest | None
    run_version: DurableRunVersion
    status: DurableRunStatus
    agent_run_id: AgentRunId
    step_id: AgentStepId | None
    metadata: CheckpointMetadata
    created_at: datetime
    digest: CheckpointDigest

    def __post_init__(self) -> None:
        if not isinstance(self.schema_version, CheckpointSchemaVersion):
            raise TypeError("schema_version must be CheckpointSchemaVersion")
        if not isinstance(self.durable_run_id, DurableAgentRunId):
            raise TypeError("durable_run_id must be DurableAgentRunId")
        if not isinstance(self.checkpoint_id, CheckpointId):
            raise TypeError("checkpoint_id must be CheckpointId")
        if not isinstance(self.sequence, CheckpointSequence):
            raise TypeError("sequence must be CheckpointSequence")
        if not isinstance(self.run_version, DurableRunVersion):
            raise TypeError("run_version must be DurableRunVersion")
        if not isinstance(self.status, DurableRunStatus):
            raise TypeError("status must be DurableRunStatus")
        if not isinstance(self.agent_run_id, AgentRunId):
            raise TypeError("agent_run_id must be AgentRunId")
        if self.step_id is not None and not isinstance(self.step_id, AgentStepId):
            raise TypeError("step_id must be AgentStepId or None")
        if not isinstance(self.metadata, CheckpointMetadata):
            raise TypeError("metadata must be CheckpointMetadata")
        if not isinstance(self.digest, CheckpointDigest):
            raise TypeError("digest must be CheckpointDigest")
        _require_timezone_aware(self.created_at, label="created_at")

        if self.sequence.value == 1:
            if self.previous_digest is not None:
                raise ValueError("the first checkpoint cannot have previous_digest")
        elif not isinstance(self.previous_digest, CheckpointDigest):
            raise ValueError("later checkpoints require previous_digest")

        if self.created_at < self.metadata.budget.started_at:
            raise ValueError("checkpoint cannot precede the original run start")
        if self.created_at >= self.metadata.retention_deadline:
            raise ValueError("checkpoint must precede its retention deadline")

        if self.status.terminal:
            if self.metadata.next_operation is not CheckpointNextOperation.NONE:
                raise ValueError("terminal checkpoints cannot contain a next operation")
            if self.metadata.active_attempt is not None:
                raise ValueError("terminal checkpoints cannot contain an active attempt")

        if self.status is DurableRunStatus.PAUSED_APPROVAL:
            if self.metadata.next_operation is not CheckpointNextOperation.WAIT_APPROVAL:
                raise ValueError("approval pauses must wait for approval")

        attempt = self.metadata.active_attempt
        if self.status is DurableRunStatus.INDETERMINATE_MODEL:
            if attempt is None:
                raise ValueError("indeterminate model checkpoints require an attempt")
            if attempt.kind is not ExecutionAttemptKind.MODEL_TURN:
                raise ValueError("indeterminate model checkpoints require a model attempt")
            if attempt.status is not ExecutionAttemptStatus.INDETERMINATE:
                raise ValueError("indeterminate checkpoints require an indeterminate attempt")
        elif self.status is DurableRunStatus.INDETERMINATE_TOOL:
            if attempt is None:
                raise ValueError("indeterminate tool checkpoints require an attempt")
            if attempt.kind is not ExecutionAttemptKind.TOOL_INVOCATION:
                raise ValueError("indeterminate tool checkpoints require a tool attempt")
            if attempt.status is not ExecutionAttemptStatus.INDETERMINATE:
                raise ValueError("indeterminate checkpoints require an indeterminate attempt")

        if attempt is not None:
            if attempt.agent_run_id != self.agent_run_id:
                raise ValueError("active attempt does not belong to the checkpoint run")
            if self.step_id is None or attempt.step_id != self.step_id:
                raise ValueError("active attempt does not match the checkpoint step")


@dataclass(frozen=True, slots=True)
class DurableLease:
    """Time-bounded ownership with a monotonic fencing generation."""

    run_id: DurableAgentRunId
    lease_id: DurableLeaseId
    owner_id: str
    generation: FencingGeneration
    acquired_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        if not isinstance(self.run_id, DurableAgentRunId):
            raise TypeError("run_id must be DurableAgentRunId")
        if not isinstance(self.lease_id, DurableLeaseId):
            raise TypeError("lease_id must be DurableLeaseId")
        object.__setattr__(
            self,
            "owner_id",
            _normalize_identifier(self.owner_id, label="lease owner id"),
        )
        if not isinstance(self.generation, FencingGeneration):
            raise TypeError("generation must be FencingGeneration")
        _require_timezone_aware(self.acquired_at, label="acquired_at")
        _require_timezone_aware(self.expires_at, label="expires_at")
        if self.expires_at <= self.acquired_at:
            raise ValueError("lease expiry must follow acquisition")
        if self.expires_at - self.acquired_at > MAX_LEASE_DURATION:
            raise ValueError("lease duration exceeds the global maximum")

    def active_at(self, now: datetime) -> bool:
        _require_timezone_aware(now, label="now")
        return self.acquired_at <= now < self.expires_at


@dataclass(frozen=True, slots=True)
class ResumeRequest:
    run_id: DurableAgentRunId
    actor_id: str
    reason: ResumeReason
    expected_version: DurableRunVersion
    requested_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        if not isinstance(self.run_id, DurableAgentRunId):
            raise TypeError("run_id must be DurableAgentRunId")
        object.__setattr__(
            self,
            "actor_id",
            _normalize_identifier(self.actor_id, label="resume actor id"),
        )
        if not isinstance(self.reason, ResumeReason):
            raise TypeError("reason must be ResumeReason")
        if not isinstance(self.expected_version, DurableRunVersion):
            raise TypeError("expected_version must be DurableRunVersion")
        _require_timezone_aware(self.requested_at, label="requested_at")


@dataclass(frozen=True, slots=True)
class ReconciliationEvidence:
    evidence_type: str
    evidence_digest: CheckpointDigest
    observed_at: datetime
    metadata: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "evidence_type",
            _normalize_identifier(self.evidence_type, label="evidence type"),
        )
        if not isinstance(self.evidence_digest, CheckpointDigest):
            raise TypeError("evidence_digest must be CheckpointDigest")
        _require_timezone_aware(self.observed_at, label="observed_at")
        object.__setattr__(self, "metadata", _freeze_metadata(self.metadata))


@dataclass(frozen=True, slots=True)
class ReconciliationRequest:
    run_id: DurableAgentRunId
    attempt_id: ExecutionAttemptId
    actor_id: str
    expected_version: DurableRunVersion
    generation: FencingGeneration
    decision: ReconciliationDecision
    evidence: ReconciliationEvidence | None = None
    requested_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        if not isinstance(self.run_id, DurableAgentRunId):
            raise TypeError("run_id must be DurableAgentRunId")
        if not isinstance(self.attempt_id, ExecutionAttemptId):
            raise TypeError("attempt_id must be ExecutionAttemptId")
        object.__setattr__(
            self,
            "actor_id",
            _normalize_identifier(self.actor_id, label="reconciliation actor id"),
        )
        if not isinstance(self.expected_version, DurableRunVersion):
            raise TypeError("expected_version must be DurableRunVersion")
        if not isinstance(self.generation, FencingGeneration):
            raise TypeError("generation must be FencingGeneration")
        if not isinstance(self.decision, ReconciliationDecision):
            raise TypeError("decision must be ReconciliationDecision")
        if self.evidence is not None and not isinstance(
            self.evidence,
            ReconciliationEvidence,
        ):
            raise TypeError("evidence must be ReconciliationEvidence or None")
        if (
            self.decision
            in {
                ReconciliationDecision.CONFIRM_SUCCEEDED,
                ReconciliationDecision.CONFIRM_NOT_STARTED,
            }
            and self.evidence is None
        ):
            raise ValueError("the selected reconciliation decision requires evidence")
        _require_timezone_aware(self.requested_at, label="requested_at")


@dataclass(frozen=True, slots=True)
class RetentionPolicy:
    metadata_retention: timedelta = timedelta(days=30)
    payload_retention: timedelta = timedelta(days=7)
    tombstone_retention: timedelta = timedelta(days=90)

    def __post_init__(self) -> None:
        _require_positive_duration(
            self.metadata_retention,
            label="metadata_retention",
            maximum=MAX_METADATA_RETENTION,
        )
        _require_positive_duration(
            self.payload_retention,
            label="payload_retention",
            maximum=MAX_PAYLOAD_RETENTION,
        )
        _require_positive_duration(
            self.tombstone_retention,
            label="tombstone_retention",
            maximum=MAX_TOMBSTONE_RETENTION,
        )
        if self.payload_retention > self.metadata_retention:
            raise ValueError("payload retention cannot exceed metadata retention")
        if self.metadata_retention > self.tombstone_retention:
            raise ValueError("metadata retention cannot exceed tombstone retention")


@dataclass(frozen=True, slots=True)
class DurableRunTombstone:
    run_id: DurableAgentRunId
    terminal_status: DurableRunStatus
    terminal_version: DurableRunVersion
    final_checkpoint_digest: CheckpointDigest
    deletion_generation: FencingGeneration
    terminal_at: datetime
    retain_until: datetime

    def __post_init__(self) -> None:
        if not isinstance(self.run_id, DurableAgentRunId):
            raise TypeError("run_id must be DurableAgentRunId")
        if not isinstance(self.terminal_status, DurableRunStatus):
            raise TypeError("terminal_status must be DurableRunStatus")
        if not self.terminal_status.terminal:
            raise ValueError("tombstones require a terminal durable status")
        if not isinstance(self.terminal_version, DurableRunVersion):
            raise TypeError("terminal_version must be DurableRunVersion")
        if not isinstance(self.final_checkpoint_digest, CheckpointDigest):
            raise TypeError("final_checkpoint_digest must be CheckpointDigest")
        if not isinstance(self.deletion_generation, FencingGeneration):
            raise TypeError("deletion_generation must be FencingGeneration")
        _require_timezone_aware(self.terminal_at, label="terminal_at")
        _require_timezone_aware(self.retain_until, label="retain_until")
        if self.retain_until <= self.terminal_at:
            raise ValueError("retain_until must follow terminal_at")


@runtime_checkable
class CheckpointCodec(Protocol):
    """Strict canonical serializer for durable checkpoint envelopes."""

    def encode(self, envelope: CheckpointEnvelope) -> bytes: ...

    def decode(self, payload: bytes) -> CheckpointEnvelope: ...

    def digest(self, envelope: CheckpointEnvelope) -> CheckpointDigest: ...


@runtime_checkable
class CheckpointProtector(Protocol):
    """Authenticated protected-payload boundary configured by trusted composition."""

    @property
    def protector_id(self) -> str: ...

    @property
    def key_version(self) -> str: ...

    def protect(
        self,
        *,
        run_id: DurableAgentRunId,
        checkpoint_id: CheckpointId,
        sequence: CheckpointSequence,
        plaintext: bytes,
    ) -> tuple[ProtectedPayloadReference, bytes]: ...

    def unprotect(
        self,
        *,
        run_id: DurableAgentRunId,
        checkpoint_id: CheckpointId,
        sequence: CheckpointSequence,
        reference: ProtectedPayloadReference,
        ciphertext: bytes,
    ) -> bytes: ...


@runtime_checkable
class DurableRunStore(Protocol):
    """Atomic checkpoint persistence boundary for one durable run history."""

    @property
    def closed(self) -> bool: ...

    def create(self, checkpoint: CheckpointEnvelope) -> Awaitable[None]: ...

    def get_current(
        self,
        run_id: DurableAgentRunId,
    ) -> Awaitable[CheckpointEnvelope | None]: ...

    def list_history(
        self,
        run_id: DurableAgentRunId,
        *,
        limit: int,
    ) -> Awaitable[tuple[CheckpointEnvelope, ...]]: ...

    def list_recovery_candidates(
        self,
        *,
        limit: int,
        after: DurableAgentRunId | None = None,
    ) -> Awaitable[tuple[DurableAgentRunId, ...]]: ...

    def append(
        self,
        checkpoint: CheckpointEnvelope,
        *,
        expected_version: DurableRunVersion,
        lease: DurableLease,
        now: datetime,
    ) -> Awaitable[CheckpointEnvelope]: ...

    def close(self) -> Awaitable[None]: ...
