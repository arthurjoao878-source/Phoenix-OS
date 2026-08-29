"""Fenced operator reconciliation dispositions for indeterminate durable attempts."""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from datetime import datetime
from types import MappingProxyType
from typing import Protocol, Self, runtime_checkable
from uuid import UUID, uuid4

from phoenix_os.agent.durable_authorization import DurableReconciliationAuthorizer
from phoenix_os.agent.durable_codec import seal_checkpoint_envelope
from phoenix_os.agent.durable_contracts import (
    MAX_RECONCILIATION_ATTEMPTS,
    CheckpointDigest,
    CheckpointEnvelope,
    CheckpointId,
    CheckpointNextOperation,
    DurableAgentRunId,
    DurableLease,
    DurableRunStatus,
    DurableRunStore,
    DurableRunVersion,
    ExecutionAttempt,
    ExecutionAttemptId,
    ExecutionAttemptKind,
    ExecutionAttemptStatus,
    FencingGeneration,
    ReconciliationDecision,
    ReconciliationRequest,
)
from phoenix_os.agent.durable_metadata import (
    DurableCheckpointMetadataProjector,
    project_durable_checkpoint_metadata,
)
from phoenix_os.agent.durable_status_lookup import (
    DurableAttemptExternalStatus,
    DurableAttemptStatusLookupOutcome,
    DurableAttemptStatusLookupResult,
)
from phoenix_os.agent.errors import AgentLimitExceededError, AgentStateConflictError
from phoenix_os.policy import SecurityContext

DEFAULT_DURABLE_RECONCILIATION_ATTEMPTS = 4

_RECONCILIATION_SCHEMA_VERSION = "1"
_RECONCILIATION_PREFIX = "reconciliation."
_NONE = "none"
_IDENTIFIER_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,127})$")

_SCHEMA_KEY = "reconciliation.schema"
_ID_KEY = "reconciliation.id"
_RUN_KEY = "reconciliation.run"
_SOURCE_CHECKPOINT_KEY = "reconciliation.source-checkpoint"
_SOURCE_DIGEST_KEY = "reconciliation.source-digest"
_SOURCE_VERSION_KEY = "reconciliation.source-version"
_SOURCE_STATUS_KEY = "reconciliation.source-status"
_ATTEMPT_KEY = "reconciliation.attempt"
_ACTOR_KEY = "reconciliation.actor"
_GENERATION_KEY = "reconciliation.generation"
_DECISION_KEY = "reconciliation.decision"
_LOOKUP_ID_KEY = "reconciliation.lookup-id"
_LOOKUP_OUTCOME_KEY = "reconciliation.lookup-outcome"
_LOOKUP_ADAPTER_KEY = "reconciliation.lookup-adapter"
_EXTERNAL_STATUS_KEY = "reconciliation.external-status"
_EXTERNAL_REQUEST_DIGEST_KEY = "reconciliation.external-request-digest"
_EVIDENCE_TYPE_KEY = "reconciliation.evidence-type"
_EVIDENCE_DIGEST_KEY = "reconciliation.evidence-digest"
_EVIDENCE_OBSERVED_AT_KEY = "reconciliation.evidence-observed-at"
_REQUESTED_AT_KEY = "reconciliation.requested-at"
_APPLIED_AT_KEY = "reconciliation.applied-at"
_RESULT_STATUS_KEY = "reconciliation.result-status"
_RESULT_ATTEMPT_STATUS_KEY = "reconciliation.result-attempt-status"

_RECONCILIATION_KEYS = frozenset(
    {
        _SCHEMA_KEY,
        _ID_KEY,
        _RUN_KEY,
        _SOURCE_CHECKPOINT_KEY,
        _SOURCE_DIGEST_KEY,
        _SOURCE_VERSION_KEY,
        _SOURCE_STATUS_KEY,
        _ATTEMPT_KEY,
        _ACTOR_KEY,
        _GENERATION_KEY,
        _DECISION_KEY,
        _LOOKUP_ID_KEY,
        _LOOKUP_OUTCOME_KEY,
        _LOOKUP_ADAPTER_KEY,
        _EXTERNAL_STATUS_KEY,
        _EXTERNAL_REQUEST_DIGEST_KEY,
        _EVIDENCE_TYPE_KEY,
        _EVIDENCE_DIGEST_KEY,
        _EVIDENCE_OBSERVED_AT_KEY,
        _REQUESTED_AT_KEY,
        _APPLIED_AT_KEY,
        _RESULT_STATUS_KEY,
        _RESULT_ATTEMPT_STATUS_KEY,
    }
)

_CONFIRM_DECISIONS = frozenset(
    {
        ReconciliationDecision.CONFIRM_SUCCEEDED,
        ReconciliationDecision.CONFIRM_FAILED,
        ReconciliationDecision.CONFIRM_NOT_STARTED,
    }
)
_FAILED_EXTERNAL_STATUSES = frozenset(
    {
        DurableAttemptExternalStatus.FAILED,
        DurableAttemptExternalStatus.CANCELLED,
        DurableAttemptExternalStatus.TIMED_OUT,
    }
)


def _normalize_identifier(value: str, *, label: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{label} must be a string")
    normalized = value.strip()
    if not _IDENTIFIER_PATTERN.fullmatch(normalized):
        raise ValueError(f"{label} is invalid")
    return normalized


def _require_timezone_aware(value: datetime, *, label: str) -> None:
    if not isinstance(value, datetime):
        raise TypeError(f"{label} must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")


@dataclass(frozen=True, slots=True)
class DurableReconciliationDispositionRecord:
    """Immutable content-free audit record for one applied reconciliation."""

    reconciliation_id: UUID
    run_id: DurableAgentRunId
    source_checkpoint_id: CheckpointId
    source_checkpoint_digest: CheckpointDigest
    source_version: DurableRunVersion
    source_status: DurableRunStatus
    attempt_id: ExecutionAttemptId
    actor_id: str
    generation: FencingGeneration
    decision: ReconciliationDecision
    external_request_digest: CheckpointDigest
    requested_at: datetime
    applied_at: datetime
    result_status: DurableRunStatus
    result_attempt_status: ExecutionAttemptStatus | None
    lookup_id: UUID | None = None
    lookup_outcome: DurableAttemptStatusLookupOutcome | None = None
    lookup_adapter_id: str | None = None
    external_status: DurableAttemptExternalStatus | None = None
    evidence_type: str | None = None
    evidence_digest: CheckpointDigest | None = None
    evidence_observed_at: datetime | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.reconciliation_id, UUID):
            raise TypeError("reconciliation_id must be UUID")
        if not isinstance(self.run_id, DurableAgentRunId):
            raise TypeError("run_id must be DurableAgentRunId")
        if not isinstance(self.source_checkpoint_id, CheckpointId):
            raise TypeError("source_checkpoint_id must be CheckpointId")
        if not isinstance(self.source_checkpoint_digest, CheckpointDigest):
            raise TypeError("source_checkpoint_digest must be CheckpointDigest")
        if not isinstance(self.source_version, DurableRunVersion):
            raise TypeError("source_version must be DurableRunVersion")
        if not isinstance(self.source_status, DurableRunStatus):
            raise TypeError("source_status must be DurableRunStatus")
        if self.source_status not in {
            DurableRunStatus.INDETERMINATE_MODEL,
            DurableRunStatus.INDETERMINATE_TOOL,
        }:
            raise ValueError("source_status must be indeterminate")
        if not isinstance(self.attempt_id, ExecutionAttemptId):
            raise TypeError("attempt_id must be ExecutionAttemptId")
        object.__setattr__(
            self,
            "actor_id",
            _normalize_identifier(self.actor_id, label="reconciliation actor id"),
        )
        if not isinstance(self.generation, FencingGeneration):
            raise TypeError("generation must be FencingGeneration")
        if not isinstance(self.decision, ReconciliationDecision):
            raise TypeError("decision must be ReconciliationDecision")
        if not isinstance(self.external_request_digest, CheckpointDigest):
            raise TypeError("external_request_digest must be CheckpointDigest")
        _require_timezone_aware(self.requested_at, label="requested_at")
        _require_timezone_aware(self.applied_at, label="applied_at")
        if self.applied_at < self.requested_at:
            raise ValueError("applied_at cannot precede requested_at")
        if not isinstance(self.result_status, DurableRunStatus):
            raise TypeError("result_status must be DurableRunStatus")
        if self.result_attempt_status is not None and not isinstance(
            self.result_attempt_status,
            ExecutionAttemptStatus,
        ):
            raise TypeError("result_attempt_status must be ExecutionAttemptStatus or None")

        self._validate_lookup()
        self._validate_evidence()
        self._validate_disposition()

    def _validate_lookup(self) -> None:
        lookup_values = (
            self.lookup_id,
            self.lookup_outcome,
            self.external_status,
        )
        if all(value is None for value in lookup_values):
            if self.lookup_adapter_id is not None:
                raise ValueError("lookup adapter requires lookup metadata")
            return
        if (
            not isinstance(self.lookup_id, UUID)
            or not isinstance(self.lookup_outcome, DurableAttemptStatusLookupOutcome)
            or not isinstance(self.external_status, DurableAttemptExternalStatus)
        ):
            raise ValueError("lookup metadata must be complete")
        if self.lookup_adapter_id is not None:
            object.__setattr__(
                self,
                "lookup_adapter_id",
                _normalize_identifier(self.lookup_adapter_id, label="lookup adapter id"),
            )
        if self.lookup_outcome is DurableAttemptStatusLookupOutcome.UNSUPPORTED:
            if self.lookup_adapter_id is not None:
                raise ValueError("unsupported lookup cannot identify an adapter")
        elif self.lookup_adapter_id is None:
            raise ValueError("lookup outcome requires an adapter id")
        if (
            self.lookup_outcome is not DurableAttemptStatusLookupOutcome.OBSERVED
            and self.external_status is not DurableAttemptExternalStatus.UNKNOWN
        ):
            raise ValueError("non-observed lookup cannot prove external status")

    def _validate_evidence(self) -> None:
        evidence_values = (
            self.evidence_type,
            self.evidence_digest,
            self.evidence_observed_at,
        )
        evidence_present = not all(value is None for value in evidence_values)
        if (
            self.lookup_outcome is DurableAttemptStatusLookupOutcome.OBSERVED
            and self.external_status is DurableAttemptExternalStatus.UNKNOWN
            and evidence_present
        ):
            raise ValueError("unknown external status cannot contain evidence")
        if (
            self.lookup_outcome is DurableAttemptStatusLookupOutcome.OBSERVED
            and self.external_status is not DurableAttemptExternalStatus.UNKNOWN
            and not evidence_present
        ):
            raise ValueError("proved external status requires evidence")
        if (
            self.lookup_outcome is not None
            and self.lookup_outcome is not DurableAttemptStatusLookupOutcome.OBSERVED
            and evidence_present
        ):
            raise ValueError("non-observed lookup cannot contain evidence")
        if not evidence_present:
            return
        if (
            not isinstance(self.evidence_type, str)
            or not isinstance(self.evidence_digest, CheckpointDigest)
            or not isinstance(self.evidence_observed_at, datetime)
        ):
            raise ValueError("reconciliation evidence metadata must be complete")
        object.__setattr__(
            self,
            "evidence_type",
            _normalize_identifier(self.evidence_type, label="evidence type"),
        )
        _require_timezone_aware(self.evidence_observed_at, label="evidence_observed_at")
        if self.evidence_observed_at > self.requested_at:
            raise ValueError("evidence cannot follow the reconciliation request")

    def _validate_disposition(self) -> None:
        expected_status: DurableRunStatus
        expected_attempt_statuses: frozenset[ExecutionAttemptStatus | None]
        if self.decision is ReconciliationDecision.CONFIRM_SUCCEEDED:
            expected_status = DurableRunStatus.PAUSED_OPERATOR
            expected_attempt_statuses = frozenset({ExecutionAttemptStatus.SUCCEEDED})
            if (
                self.lookup_outcome is not DurableAttemptStatusLookupOutcome.OBSERVED
                or self.external_status is not DurableAttemptExternalStatus.SUCCEEDED
                or self.evidence_digest is None
            ):
                raise ValueError("confirmed success requires proved successful evidence")
        elif self.decision is ReconciliationDecision.CONFIRM_FAILED:
            expected_status = DurableRunStatus.PAUSED_OPERATOR
            expected_attempt_statuses = frozenset(
                {
                    ExecutionAttemptStatus.FAILED,
                    ExecutionAttemptStatus.CANCELLED,
                    ExecutionAttemptStatus.TIMED_OUT,
                }
            )
            if (
                self.lookup_outcome is not DurableAttemptStatusLookupOutcome.OBSERVED
                or self.external_status not in _FAILED_EXTERNAL_STATUSES
                or self.evidence_digest is None
            ):
                raise ValueError("confirmed failure requires proved terminal evidence")
        elif self.decision is ReconciliationDecision.CONFIRM_NOT_STARTED:
            expected_status = DurableRunStatus.PAUSED_OPERATOR
            expected_attempt_statuses = frozenset({ExecutionAttemptStatus.CANCELLED})
            if (
                self.lookup_outcome is not DurableAttemptStatusLookupOutcome.OBSERVED
                or self.external_status is not DurableAttemptExternalStatus.NOT_STARTED
                or self.evidence_digest is None
            ):
                raise ValueError("confirmed non-start requires proved evidence")
        elif self.decision is ReconciliationDecision.REMAIN_INDETERMINATE:
            expected_status = self.source_status
            expected_attempt_statuses = frozenset({ExecutionAttemptStatus.INDETERMINATE})
        elif self.decision is ReconciliationDecision.CANCEL_RUN:
            expected_status = DurableRunStatus.CANCELLED
            expected_attempt_statuses = frozenset({None})
        else:
            expected_status = DurableRunStatus.FAILED
            expected_attempt_statuses = frozenset({None})

        if self.result_status is not expected_status:
            raise ValueError("result_status does not match reconciliation decision")
        if self.result_attempt_status not in expected_attempt_statuses:
            raise ValueError("result attempt status does not match reconciliation decision")

    def to_metadata(self) -> Mapping[str, str]:
        """Return the exact fixed metadata fields persisted for this record."""

        return MappingProxyType(
            {
                _SCHEMA_KEY: _RECONCILIATION_SCHEMA_VERSION,
                _ID_KEY: str(self.reconciliation_id),
                _RUN_KEY: str(self.run_id),
                _SOURCE_CHECKPOINT_KEY: str(self.source_checkpoint_id),
                _SOURCE_DIGEST_KEY: str(self.source_checkpoint_digest),
                _SOURCE_VERSION_KEY: str(self.source_version.value),
                _SOURCE_STATUS_KEY: self.source_status.value,
                _ATTEMPT_KEY: str(self.attempt_id),
                _ACTOR_KEY: self.actor_id,
                _GENERATION_KEY: str(self.generation.value),
                _DECISION_KEY: self.decision.value,
                _LOOKUP_ID_KEY: _optional_uuid_text(self.lookup_id),
                _LOOKUP_OUTCOME_KEY: _optional_enum_text(self.lookup_outcome),
                _LOOKUP_ADAPTER_KEY: self.lookup_adapter_id or _NONE,
                _EXTERNAL_STATUS_KEY: _optional_enum_text(self.external_status),
                _EXTERNAL_REQUEST_DIGEST_KEY: str(self.external_request_digest),
                _EVIDENCE_TYPE_KEY: self.evidence_type or _NONE,
                _EVIDENCE_DIGEST_KEY: (
                    str(self.evidence_digest) if self.evidence_digest is not None else _NONE
                ),
                _EVIDENCE_OBSERVED_AT_KEY: _optional_datetime_text(self.evidence_observed_at),
                _REQUESTED_AT_KEY: self.requested_at.isoformat(),
                _APPLIED_AT_KEY: self.applied_at.isoformat(),
                _RESULT_STATUS_KEY: self.result_status.value,
                _RESULT_ATTEMPT_STATUS_KEY: _optional_enum_text(self.result_attempt_status),
            }
        )

    @classmethod
    def from_metadata(cls, metadata: Mapping[str, str]) -> Self:
        """Parse one exact record from bounded checkpoint metadata."""

        if not isinstance(metadata, Mapping):
            raise TypeError("metadata must be a mapping")
        prefixed = frozenset(key for key in metadata if key.startswith(_RECONCILIATION_PREFIX))
        if prefixed != _RECONCILIATION_KEYS:
            raise ValueError("reconciliation metadata fields are invalid")
        if _metadata_value(metadata, _SCHEMA_KEY) != _RECONCILIATION_SCHEMA_VERSION:
            raise ValueError("unsupported reconciliation metadata schema")

        return cls(
            reconciliation_id=_metadata_uuid(metadata, _ID_KEY),
            run_id=DurableAgentRunId(_metadata_uuid(metadata, _RUN_KEY)),
            source_checkpoint_id=CheckpointId(_metadata_uuid(metadata, _SOURCE_CHECKPOINT_KEY)),
            source_checkpoint_digest=CheckpointDigest(
                _metadata_value(metadata, _SOURCE_DIGEST_KEY)
            ),
            source_version=DurableRunVersion(
                _metadata_positive_integer(metadata, _SOURCE_VERSION_KEY)
            ),
            source_status=DurableRunStatus(_metadata_value(metadata, _SOURCE_STATUS_KEY)),
            attempt_id=ExecutionAttemptId(_metadata_uuid(metadata, _ATTEMPT_KEY)),
            actor_id=_metadata_value(metadata, _ACTOR_KEY),
            generation=FencingGeneration(_metadata_positive_integer(metadata, _GENERATION_KEY)),
            decision=ReconciliationDecision(_metadata_value(metadata, _DECISION_KEY)),
            lookup_id=_metadata_optional_uuid(metadata, _LOOKUP_ID_KEY),
            lookup_outcome=_metadata_optional_lookup_outcome(
                metadata,
                _LOOKUP_OUTCOME_KEY,
            ),
            lookup_adapter_id=_metadata_optional_text(metadata, _LOOKUP_ADAPTER_KEY),
            external_status=_metadata_optional_external_status(
                metadata,
                _EXTERNAL_STATUS_KEY,
            ),
            external_request_digest=CheckpointDigest(
                _metadata_value(metadata, _EXTERNAL_REQUEST_DIGEST_KEY)
            ),
            evidence_type=_metadata_optional_text(metadata, _EVIDENCE_TYPE_KEY),
            evidence_digest=_metadata_optional_digest(metadata, _EVIDENCE_DIGEST_KEY),
            evidence_observed_at=_metadata_optional_datetime(
                metadata,
                _EVIDENCE_OBSERVED_AT_KEY,
            ),
            requested_at=_metadata_datetime(metadata, _REQUESTED_AT_KEY),
            applied_at=_metadata_datetime(metadata, _APPLIED_AT_KEY),
            result_status=DurableRunStatus(_metadata_value(metadata, _RESULT_STATUS_KEY)),
            result_attempt_status=_metadata_optional_attempt_status(
                metadata,
                _RESULT_ATTEMPT_STATUS_KEY,
            ),
        )

    @classmethod
    def from_checkpoint(cls, checkpoint: CheckpointEnvelope) -> Self:
        """Parse and bind the record from the exact checkpoint that applied it."""

        if not isinstance(checkpoint, CheckpointEnvelope):
            raise TypeError("checkpoint must be CheckpointEnvelope")
        record = cls.from_metadata(checkpoint.metadata.metadata)
        attempt = checkpoint.metadata.active_attempt
        if (
            record.run_id != checkpoint.durable_run_id
            or record.applied_at != checkpoint.created_at
            or record.result_status is not checkpoint.status
            or record.source_version.value + 1 != checkpoint.run_version.value
            or record.source_checkpoint_digest != checkpoint.previous_digest
        ):
            raise ValueError("reconciliation record does not bind to checkpoint")
        if record.result_attempt_status is None:
            if attempt is not None:
                raise ValueError("recorded terminal disposition retained an attempt")
        elif (
            attempt is None
            or attempt.attempt_id != record.attempt_id
            or attempt.status is not record.result_attempt_status
        ):
            raise ValueError("recorded attempt outcome does not match checkpoint")
        return record


@runtime_checkable
class DurableReconciliationDispositionApplier(Protocol):
    """Authorize and atomically checkpoint one reviewed reconciliation disposition."""

    async def apply(
        self,
        request: ReconciliationRequest,
        *,
        lease: DurableLease,
        context: SecurityContext,
        now: datetime,
        lookup_result: DurableAttemptStatusLookupResult | None = None,
    ) -> CheckpointEnvelope: ...


class StoreBackedDurableReconciliationDispositionApplier:
    """Apply exact operator dispositions without invoking or retrying external work."""

    def __init__(
        self,
        *,
        store: DurableRunStore,
        authorizer: DurableReconciliationAuthorizer,
        checkpoint_id_factory: Callable[[], CheckpointId] = CheckpointId,
        reconciliation_id_factory: Callable[[], UUID] = uuid4,
        max_reconciliation_attempts: int = DEFAULT_DURABLE_RECONCILIATION_ATTEMPTS,
        metadata_projector: DurableCheckpointMetadataProjector | None = None,
    ) -> None:
        if not isinstance(store, DurableRunStore):
            raise TypeError("store must implement DurableRunStore")
        if not isinstance(authorizer, DurableReconciliationAuthorizer):
            raise TypeError("authorizer must implement DurableReconciliationAuthorizer")
        if not callable(checkpoint_id_factory):
            raise TypeError("checkpoint_id_factory must be callable")
        if not callable(reconciliation_id_factory):
            raise TypeError("reconciliation_id_factory must be callable")
        if isinstance(max_reconciliation_attempts, bool) or not isinstance(
            max_reconciliation_attempts,
            int,
        ):
            raise TypeError("max_reconciliation_attempts must be an integer")
        if max_reconciliation_attempts <= 0:
            raise ValueError("max_reconciliation_attempts must be greater than zero")
        if max_reconciliation_attempts > MAX_RECONCILIATION_ATTEMPTS:
            raise ValueError("max_reconciliation_attempts exceeds the global maximum")
        if metadata_projector is not None and not isinstance(
            metadata_projector,
            DurableCheckpointMetadataProjector,
        ):
            raise TypeError("metadata_projector must implement DurableCheckpointMetadataProjector")
        self._store = store
        self._authorizer = authorizer
        self._checkpoint_id_factory = checkpoint_id_factory
        self._reconciliation_id_factory = reconciliation_id_factory
        self._max_reconciliation_attempts = max_reconciliation_attempts
        self._metadata_projector = metadata_projector

    async def apply(
        self,
        request: ReconciliationRequest,
        *,
        lease: DurableLease,
        context: SecurityContext,
        now: datetime,
        lookup_result: DurableAttemptStatusLookupResult | None = None,
    ) -> CheckpointEnvelope:
        """Authorize, validate evidence, and append one immutable disposition."""

        if not isinstance(request, ReconciliationRequest):
            raise TypeError("request must be ReconciliationRequest")
        if not isinstance(lease, DurableLease):
            raise TypeError("lease must be DurableLease")
        if not isinstance(context, SecurityContext):
            raise TypeError("context must be SecurityContext")
        if lookup_result is not None and not isinstance(
            lookup_result,
            DurableAttemptStatusLookupResult,
        ):
            raise TypeError("lookup_result must be DurableAttemptStatusLookupResult or None")
        _require_timezone_aware(now, label="now")
        if now < request.requested_at:
            raise AgentStateConflictError()
        if (
            lease.run_id != request.run_id
            or lease.generation != request.generation
            or not lease.active_at(request.requested_at)
            or not lease.active_at(now)
        ):
            raise AgentStateConflictError()

        current = await self._store.get_current(request.run_id)
        if current is None:
            raise AgentStateConflictError()
        attempt = _require_source(current, request=request, now=now)

        await self._authorizer.authorize(request, current, lease, context)
        _validate_lookup_result(
            request,
            current=current,
            attempt=attempt,
            lookup_result=lookup_result,
        )
        await self._require_reconciliation_capacity(current)

        result_status, next_operation, result_attempt = _disposition(
            request,
            current=current,
            attempt=attempt,
            lookup_result=lookup_result,
        )
        record = self._record(
            request,
            current=current,
            attempt=attempt,
            result_status=result_status,
            result_attempt=result_attempt,
            lookup_result=lookup_result,
            now=now,
        )
        return await self._append(
            current,
            lease=lease,
            record=record,
            status=result_status,
            next_operation=next_operation,
            attempt=result_attempt,
            now=now,
        )

    async def _require_reconciliation_capacity(
        self,
        current: CheckpointEnvelope,
    ) -> None:
        history = await self._store.list_history(
            current.durable_run_id,
            limit=current.sequence.value,
        )
        if len(history) != current.sequence.value or not history or history[-1] != current:
            raise AgentStateConflictError()

        records: dict[UUID, DurableReconciliationDispositionRecord] = {}
        for checkpoint in history:
            metadata = checkpoint.metadata.metadata
            prefixed = frozenset(key for key in metadata if key.startswith(_RECONCILIATION_PREFIX))
            if not prefixed:
                continue
            try:
                record = DurableReconciliationDispositionRecord.from_metadata(metadata)
            except (TypeError, ValueError, OverflowError) as exception:
                raise AgentStateConflictError() from exception
            if (
                record.run_id != current.durable_run_id
                or record.applied_at > checkpoint.created_at
                or record.source_version.value >= checkpoint.run_version.value
            ):
                raise AgentStateConflictError()
            previous = records.get(record.reconciliation_id)
            if previous is not None and previous != record:
                raise AgentStateConflictError()
            records[record.reconciliation_id] = record

        if len(records) >= self._max_reconciliation_attempts:
            raise AgentLimitExceededError()

    def _record(
        self,
        request: ReconciliationRequest,
        *,
        current: CheckpointEnvelope,
        attempt: ExecutionAttempt,
        result_status: DurableRunStatus,
        result_attempt: ExecutionAttempt | None,
        lookup_result: DurableAttemptStatusLookupResult | None,
        now: datetime,
    ) -> DurableReconciliationDispositionRecord:
        reconciliation_id = self._reconciliation_id_factory()
        if not isinstance(reconciliation_id, UUID):
            raise TypeError("reconciliation_id_factory must return UUID")
        evidence = request.evidence
        return DurableReconciliationDispositionRecord(
            reconciliation_id=reconciliation_id,
            run_id=current.durable_run_id,
            source_checkpoint_id=current.checkpoint_id,
            source_checkpoint_digest=current.digest,
            source_version=current.run_version,
            source_status=current.status,
            attempt_id=attempt.attempt_id,
            actor_id=request.actor_id,
            generation=request.generation,
            decision=request.decision,
            lookup_id=(lookup_result.query.lookup_id if lookup_result is not None else None),
            lookup_outcome=(lookup_result.outcome if lookup_result is not None else None),
            lookup_adapter_id=(lookup_result.adapter_id if lookup_result is not None else None),
            external_status=(lookup_result.status if lookup_result is not None else None),
            external_request_digest=_require_external_request_digest(attempt),
            evidence_type=evidence.evidence_type if evidence is not None else None,
            evidence_digest=evidence.evidence_digest if evidence is not None else None,
            evidence_observed_at=evidence.observed_at if evidence is not None else None,
            requested_at=request.requested_at,
            applied_at=now,
            result_status=result_status,
            result_attempt_status=(result_attempt.status if result_attempt is not None else None),
        )

    async def _append(
        self,
        current: CheckpointEnvelope,
        *,
        lease: DurableLease,
        record: DurableReconciliationDispositionRecord,
        status: DurableRunStatus,
        next_operation: CheckpointNextOperation,
        attempt: ExecutionAttempt | None,
        now: datetime,
    ) -> CheckpointEnvelope:
        checkpoint_id = self._checkpoint_id_factory()
        if not isinstance(checkpoint_id, CheckpointId):
            raise TypeError("checkpoint_id_factory must return CheckpointId")
        try:
            metadata_values: Mapping[str, str] = _metadata_with_record(
                current.metadata.metadata,
                record,
            )
            metadata_values = project_durable_checkpoint_metadata(
                self._metadata_projector,
                current,
                checkpoint_id=checkpoint_id,
                status=status,
                step_id=current.step_id,
                next_operation=next_operation,
                active_attempt=attempt,
                metadata=metadata_values,
            )
            metadata = replace(
                current.metadata,
                next_operation=next_operation,
                active_attempt=attempt,
                metadata=metadata_values,
            )
            candidate = seal_checkpoint_envelope(
                replace(
                    current,
                    checkpoint_id=checkpoint_id,
                    sequence=current.sequence.next(),
                    previous_digest=current.digest,
                    run_version=current.run_version.next(),
                    status=status,
                    metadata=metadata,
                    created_at=now,
                    digest=CheckpointDigest("0" * 64),
                )
            )
        except (TypeError, ValueError, OverflowError) as exception:
            raise AgentStateConflictError() from exception
        return await self._store.append(
            candidate,
            expected_version=current.run_version,
            lease=lease,
            now=now,
        )


def reconciliation_disposition_record(
    checkpoint: CheckpointEnvelope,
) -> DurableReconciliationDispositionRecord:
    """Return the exact disposition record applied by one checkpoint."""

    return DurableReconciliationDispositionRecord.from_checkpoint(checkpoint)


def _require_source(
    current: CheckpointEnvelope,
    *,
    request: ReconciliationRequest,
    now: datetime,
) -> ExecutionAttempt:
    attempt = current.metadata.active_attempt
    expected_kind: ExecutionAttemptKind
    if current.status is DurableRunStatus.INDETERMINATE_MODEL:
        expected_kind = ExecutionAttemptKind.MODEL_TURN
    elif current.status is DurableRunStatus.INDETERMINATE_TOOL:
        expected_kind = ExecutionAttemptKind.TOOL_INVOCATION
    else:
        raise AgentStateConflictError()

    if (
        current.durable_run_id != request.run_id
        or current.run_version != request.expected_version
        or current.metadata.next_operation is not CheckpointNextOperation.OPERATOR_REVIEW
        or attempt is None
        or attempt.attempt_id != request.attempt_id
        or attempt.kind is not expected_kind
        or attempt.status is not ExecutionAttemptStatus.INDETERMINATE
        or attempt.agent_run_id != current.agent_run_id
        or current.step_id is None
        or attempt.step_id != current.step_id
        or attempt.external_request_digest is None
        or request.requested_at < current.created_at
        or now >= current.metadata.retention_deadline
    ):
        raise AgentStateConflictError()
    return attempt


def _validate_lookup_result(
    request: ReconciliationRequest,
    *,
    current: CheckpointEnvelope,
    attempt: ExecutionAttempt,
    lookup_result: DurableAttemptStatusLookupResult | None,
) -> None:
    if lookup_result is None:
        if request.decision in _CONFIRM_DECISIONS:
            raise AgentStateConflictError()
        return

    query = lookup_result.query
    if (
        query.durable_run_id != current.durable_run_id
        or query.checkpoint_id != current.checkpoint_id
        or query.checkpoint_digest != current.digest
        or query.run_version != current.run_version
        or query.attempt_id != attempt.attempt_id
        or query.kind is not attempt.kind
        or query.agent_run_id != attempt.agent_run_id
        or query.step_id != attempt.step_id
        or query.external_request_digest != attempt.external_request_digest
        or query.tool_call_id != attempt.tool_call_id
        or query.tool_effect is not attempt.tool_effect
        or query.requested_at < current.created_at
        or query.requested_at > request.requested_at
        or query.deadline > current.metadata.retention_deadline
    ):
        raise AgentStateConflictError()

    if request.evidence != lookup_result.evidence:
        raise AgentStateConflictError()
    evidence = request.evidence
    if evidence is not None and evidence.observed_at > request.requested_at:
        raise AgentStateConflictError()

    if request.decision is ReconciliationDecision.CONFIRM_SUCCEEDED:
        _require_observed_status(
            lookup_result,
            DurableAttemptExternalStatus.SUCCEEDED,
        )
    elif request.decision is ReconciliationDecision.CONFIRM_FAILED:
        if (
            lookup_result.outcome is not DurableAttemptStatusLookupOutcome.OBSERVED
            or lookup_result.status not in _FAILED_EXTERNAL_STATUSES
            or lookup_result.evidence is None
        ):
            raise AgentStateConflictError()
    elif request.decision is ReconciliationDecision.CONFIRM_NOT_STARTED:
        _require_observed_status(
            lookup_result,
            DurableAttemptExternalStatus.NOT_STARTED,
        )


def _require_observed_status(
    lookup_result: DurableAttemptStatusLookupResult,
    status: DurableAttemptExternalStatus,
) -> None:
    if (
        lookup_result.outcome is not DurableAttemptStatusLookupOutcome.OBSERVED
        or lookup_result.status is not status
        or lookup_result.evidence is None
    ):
        raise AgentStateConflictError()


def _disposition(
    request: ReconciliationRequest,
    *,
    current: CheckpointEnvelope,
    attempt: ExecutionAttempt,
    lookup_result: DurableAttemptStatusLookupResult | None,
) -> tuple[DurableRunStatus, CheckpointNextOperation, ExecutionAttempt | None]:
    decision = request.decision
    if decision is ReconciliationDecision.REMAIN_INDETERMINATE:
        return current.status, CheckpointNextOperation.OPERATOR_REVIEW, attempt
    if decision is ReconciliationDecision.CANCEL_RUN:
        return DurableRunStatus.CANCELLED, CheckpointNextOperation.NONE, None
    if decision is ReconciliationDecision.FAIL_RUN:
        return DurableRunStatus.FAILED, CheckpointNextOperation.NONE, None

    if lookup_result is None or request.evidence is None:
        raise AgentStateConflictError()
    completed_at = request.evidence.observed_at

    try:
        if decision is ReconciliationDecision.CONFIRM_SUCCEEDED:
            result_attempt = replace(
                attempt,
                status=ExecutionAttemptStatus.SUCCEEDED,
                completed_at=completed_at,
                indeterminate_reason=None,
                error_code=None,
            )
            return (
                DurableRunStatus.PAUSED_OPERATOR,
                CheckpointNextOperation.OPERATOR_REVIEW,
                result_attempt,
            )

        if decision is ReconciliationDecision.CONFIRM_NOT_STARTED:
            result_attempt = replace(
                attempt,
                status=ExecutionAttemptStatus.CANCELLED,
                completed_at=completed_at,
                indeterminate_reason=None,
                error_code=None,
            )
            next_operation = (
                CheckpointNextOperation.MODEL_TURN
                if attempt.kind is ExecutionAttemptKind.MODEL_TURN
                else CheckpointNextOperation.TOOL_INVOCATION
            )
            return DurableRunStatus.PAUSED_OPERATOR, next_operation, result_attempt

        external_status = lookup_result.status
        if external_status is DurableAttemptExternalStatus.FAILED:
            attempt_status = ExecutionAttemptStatus.FAILED
            error_code = "reconciled-failed"
        elif external_status is DurableAttemptExternalStatus.CANCELLED:
            attempt_status = ExecutionAttemptStatus.CANCELLED
            error_code = None
        elif external_status is DurableAttemptExternalStatus.TIMED_OUT:
            attempt_status = ExecutionAttemptStatus.TIMED_OUT
            error_code = "reconciled-timed-out"
        else:
            raise AgentStateConflictError()
        result_attempt = replace(
            attempt,
            status=attempt_status,
            completed_at=completed_at,
            indeterminate_reason=None,
            error_code=error_code,
        )
        return (
            DurableRunStatus.PAUSED_OPERATOR,
            CheckpointNextOperation.OPERATOR_REVIEW,
            result_attempt,
        )
    except (TypeError, ValueError, OverflowError) as exception:
        raise AgentStateConflictError() from exception


def _metadata_with_record(
    metadata: Mapping[str, str],
    record: DurableReconciliationDispositionRecord,
) -> dict[str, str]:
    prefixed = frozenset(key for key in metadata if key.startswith(_RECONCILIATION_PREFIX))
    if prefixed and prefixed != _RECONCILIATION_KEYS:
        raise AgentStateConflictError()
    values = {key: value for key, value in metadata.items() if key not in _RECONCILIATION_KEYS}
    values.update(record.to_metadata())
    return values


def _require_external_request_digest(attempt: ExecutionAttempt) -> CheckpointDigest:
    digest = attempt.external_request_digest
    if not isinstance(digest, CheckpointDigest):
        raise AgentStateConflictError()
    return digest


def _optional_uuid_text(value: UUID | None) -> str:
    return str(value) if value is not None else _NONE


def _optional_enum_text(
    value: (
        DurableAttemptStatusLookupOutcome
        | DurableAttemptExternalStatus
        | ExecutionAttemptStatus
        | None
    ),
) -> str:
    return value.value if value is not None else _NONE


def _optional_datetime_text(value: datetime | None) -> str:
    return value.isoformat() if value is not None else _NONE


def _metadata_value(metadata: Mapping[str, str], key: str) -> str:
    value = metadata.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError("reconciliation metadata is incomplete")
    return value


def _metadata_uuid(metadata: Mapping[str, str], key: str) -> UUID:
    raw = _metadata_value(metadata, key)
    value = UUID(raw)
    if str(value) != raw:
        raise ValueError("reconciliation UUID is not canonical")
    return value


def _metadata_positive_integer(metadata: Mapping[str, str], key: str) -> int:
    raw = _metadata_value(metadata, key)
    value = int(raw)
    if value <= 0 or str(value) != raw:
        raise ValueError("reconciliation integer is not canonical")
    return value


def _metadata_datetime(metadata: Mapping[str, str], key: str) -> datetime:
    raw = _metadata_value(metadata, key)
    value = datetime.fromisoformat(raw)
    _require_timezone_aware(value, label="reconciliation timestamp")
    if value.isoformat() != raw:
        raise ValueError("reconciliation timestamp is not canonical")
    return value


def _metadata_optional_text(metadata: Mapping[str, str], key: str) -> str | None:
    raw = _metadata_value(metadata, key)
    return None if raw == _NONE else raw


def _metadata_optional_uuid(metadata: Mapping[str, str], key: str) -> UUID | None:
    raw = _metadata_value(metadata, key)
    if raw == _NONE:
        return None
    value = UUID(raw)
    if str(value) != raw:
        raise ValueError("reconciliation UUID is not canonical")
    return value


def _metadata_optional_datetime(
    metadata: Mapping[str, str],
    key: str,
) -> datetime | None:
    raw = _metadata_value(metadata, key)
    if raw == _NONE:
        return None
    value = datetime.fromisoformat(raw)
    _require_timezone_aware(value, label="reconciliation timestamp")
    if value.isoformat() != raw:
        raise ValueError("reconciliation timestamp is not canonical")
    return value


def _metadata_optional_digest(
    metadata: Mapping[str, str],
    key: str,
) -> CheckpointDigest | None:
    raw = _metadata_value(metadata, key)
    return None if raw == _NONE else CheckpointDigest(raw)


def _metadata_optional_lookup_outcome(
    metadata: Mapping[str, str],
    key: str,
) -> DurableAttemptStatusLookupOutcome | None:
    raw = _metadata_value(metadata, key)
    return None if raw == _NONE else DurableAttemptStatusLookupOutcome(raw)


def _metadata_optional_external_status(
    metadata: Mapping[str, str],
    key: str,
) -> DurableAttemptExternalStatus | None:
    raw = _metadata_value(metadata, key)
    return None if raw == _NONE else DurableAttemptExternalStatus(raw)


def _metadata_optional_attempt_status(
    metadata: Mapping[str, str],
    key: str,
) -> ExecutionAttemptStatus | None:
    raw = _metadata_value(metadata, key)
    return None if raw == _NONE else ExecutionAttemptStatus(raw)
