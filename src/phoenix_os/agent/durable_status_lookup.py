"""Reviewed content-free status lookup for indeterminate durable attempts."""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Protocol, runtime_checkable
from uuid import UUID, uuid4

from phoenix_os.agent.contracts import (
    AgentRunId,
    AgentStepId,
    ToolCallId,
    ToolEffect,
)
from phoenix_os.agent.durable_contracts import (
    CheckpointDigest,
    CheckpointEnvelope,
    CheckpointId,
    CheckpointNextOperation,
    DurableAgentRunId,
    DurableRunStatus,
    DurableRunVersion,
    ExecutionAttemptId,
    ExecutionAttemptKind,
    ExecutionAttemptStatus,
    ReconciliationEvidence,
)

DURABLE_STATUS_LOOKUP_DEFAULT_TIMEOUT = timedelta(seconds=5)
MAX_DURABLE_STATUS_LOOKUP_TIMEOUT = timedelta(seconds=30)

_ADAPTER_ID_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,127})$")


def _normalize_adapter_id(value: str) -> str:
    if not isinstance(value, str):
        raise TypeError("adapter_id must be a string")
    normalized = value.strip()
    if not _ADAPTER_ID_PATTERN.fullmatch(normalized):
        raise ValueError("adapter_id is invalid")
    return normalized


def _require_timezone_aware(value: datetime, *, label: str) -> None:
    if not isinstance(value, datetime):
        raise TypeError(f"{label} must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")


def _require_lookup_timeout(value: timedelta) -> None:
    if not isinstance(value, timedelta):
        raise TypeError("timeout must be a timedelta")
    if value <= timedelta(0):
        raise ValueError("timeout must be greater than zero")
    if value > MAX_DURABLE_STATUS_LOOKUP_TIMEOUT:
        raise ValueError("timeout exceeds the global maximum")


class DurableAttemptExternalStatus(StrEnum):
    """Bounded external states a reviewed adapter may prove."""

    UNKNOWN = "unknown"
    NOT_STARTED = "not_started"
    IN_PROGRESS = "in_progress"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"


class DurableAttemptStatusLookupOutcome(StrEnum):
    """Content-free result category for one lookup boundary call."""

    OBSERVED = "observed"
    UNSUPPORTED = "unsupported"
    TIMED_OUT = "timed_out"
    ADAPTER_ERROR = "adapter_error"
    INVALID_RESPONSE = "invalid_response"


@dataclass(frozen=True, slots=True)
class DurableAttemptStatusQuery:
    """Exact content-free question sent to one reviewed adapter capability."""

    durable_run_id: DurableAgentRunId
    checkpoint_id: CheckpointId
    checkpoint_digest: CheckpointDigest
    run_version: DurableRunVersion
    attempt_id: ExecutionAttemptId
    kind: ExecutionAttemptKind
    agent_run_id: AgentRunId
    step_id: AgentStepId
    external_request_digest: CheckpointDigest
    tool_call_id: ToolCallId | None
    tool_effect: ToolEffect | None
    requested_at: datetime
    deadline: datetime
    lookup_id: UUID = field(default_factory=uuid4)

    def __post_init__(self) -> None:
        if not isinstance(self.durable_run_id, DurableAgentRunId):
            raise TypeError("durable_run_id must be DurableAgentRunId")
        if not isinstance(self.checkpoint_id, CheckpointId):
            raise TypeError("checkpoint_id must be CheckpointId")
        if not isinstance(self.checkpoint_digest, CheckpointDigest):
            raise TypeError("checkpoint_digest must be CheckpointDigest")
        if not isinstance(self.run_version, DurableRunVersion):
            raise TypeError("run_version must be DurableRunVersion")
        if not isinstance(self.attempt_id, ExecutionAttemptId):
            raise TypeError("attempt_id must be ExecutionAttemptId")
        if not isinstance(self.kind, ExecutionAttemptKind):
            raise TypeError("kind must be ExecutionAttemptKind")
        if not isinstance(self.agent_run_id, AgentRunId):
            raise TypeError("agent_run_id must be AgentRunId")
        if not isinstance(self.step_id, AgentStepId):
            raise TypeError("step_id must be AgentStepId")
        if not isinstance(self.external_request_digest, CheckpointDigest):
            raise TypeError("external_request_digest must be CheckpointDigest")
        if not isinstance(self.lookup_id, UUID):
            raise TypeError("lookup_id must be UUID")
        _require_timezone_aware(self.requested_at, label="requested_at")
        _require_timezone_aware(self.deadline, label="deadline")
        if self.deadline <= self.requested_at:
            raise ValueError("deadline must follow requested_at")
        if self.deadline - self.requested_at > MAX_DURABLE_STATUS_LOOKUP_TIMEOUT:
            raise ValueError("lookup deadline exceeds the global maximum")

        if self.kind is ExecutionAttemptKind.MODEL_TURN:
            if self.tool_call_id is not None or self.tool_effect is not None:
                raise ValueError("model status queries cannot contain tool identity or effect")
        else:
            if not isinstance(self.tool_call_id, ToolCallId):
                raise ValueError("tool status queries require tool_call_id")
            if not isinstance(self.tool_effect, ToolEffect):
                raise ValueError("tool status queries require tool_effect")


@dataclass(frozen=True, slots=True)
class DurableAttemptStatusObservation:
    """One typed, content-free adapter observation bound to an exact query."""

    lookup_id: UUID
    durable_run_id: DurableAgentRunId
    attempt_id: ExecutionAttemptId
    external_request_digest: CheckpointDigest
    adapter_id: str
    status: DurableAttemptExternalStatus
    observed_at: datetime
    evidence: ReconciliationEvidence | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.lookup_id, UUID):
            raise TypeError("lookup_id must be UUID")
        if not isinstance(self.durable_run_id, DurableAgentRunId):
            raise TypeError("durable_run_id must be DurableAgentRunId")
        if not isinstance(self.attempt_id, ExecutionAttemptId):
            raise TypeError("attempt_id must be ExecutionAttemptId")
        if not isinstance(self.external_request_digest, CheckpointDigest):
            raise TypeError("external_request_digest must be CheckpointDigest")
        if not isinstance(self.status, DurableAttemptExternalStatus):
            raise TypeError("status must be DurableAttemptExternalStatus")
        _require_timezone_aware(self.observed_at, label="observed_at")
        object.__setattr__(self, "adapter_id", _normalize_adapter_id(self.adapter_id))

        if self.status is DurableAttemptExternalStatus.UNKNOWN:
            if self.evidence is not None:
                raise ValueError("unknown observations cannot contain evidence")
        else:
            if not isinstance(self.evidence, ReconciliationEvidence):
                raise ValueError("proved observations require reconciliation evidence")
            if self.evidence.observed_at != self.observed_at:
                raise ValueError("evidence time must match observation time")
            if self.evidence.metadata:
                raise ValueError("adapter status evidence metadata must be empty")


@dataclass(frozen=True, slots=True)
class DurableAttemptStatusLookupResult:
    """Safe boundary result with no raw adapter exception or external payload."""

    query: DurableAttemptStatusQuery
    outcome: DurableAttemptStatusLookupOutcome
    adapter_id: str | None = None
    observation: DurableAttemptStatusObservation | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.query, DurableAttemptStatusQuery):
            raise TypeError("query must be DurableAttemptStatusQuery")
        if not isinstance(self.outcome, DurableAttemptStatusLookupOutcome):
            raise TypeError("outcome must be DurableAttemptStatusLookupOutcome")
        if self.adapter_id is not None:
            object.__setattr__(self, "adapter_id", _normalize_adapter_id(self.adapter_id))

        if self.outcome is DurableAttemptStatusLookupOutcome.OBSERVED:
            if not isinstance(self.observation, DurableAttemptStatusObservation):
                raise ValueError("observed lookup results require an observation")
            if self.adapter_id != self.observation.adapter_id:
                raise ValueError("lookup adapter identity does not match the observation")
        elif self.observation is not None:
            raise ValueError("non-observed lookup results cannot contain an observation")

        if (
            self.outcome is DurableAttemptStatusLookupOutcome.UNSUPPORTED
            and self.adapter_id is not None
        ):
            raise ValueError("unsupported lookup results cannot identify an adapter")

    @property
    def status(self) -> DurableAttemptExternalStatus:
        if self.observation is None:
            return DurableAttemptExternalStatus.UNKNOWN
        return self.observation.status

    @property
    def evidence(self) -> ReconciliationEvidence | None:
        if self.observation is None:
            return None
        return self.observation.evidence


@runtime_checkable
class DurableModelAttemptStatusAdapter(Protocol):
    """Optional reviewed capability for querying one model attempt."""

    @property
    def adapter_id(self) -> str: ...

    async def lookup_model_attempt_status(
        self,
        query: DurableAttemptStatusQuery,
    ) -> DurableAttemptStatusObservation: ...


@runtime_checkable
class DurableToolAttemptStatusAdapter(Protocol):
    """Optional reviewed capability for querying one tool attempt."""

    @property
    def adapter_id(self) -> str: ...

    async def lookup_tool_attempt_status(
        self,
        query: DurableAttemptStatusQuery,
    ) -> DurableAttemptStatusObservation: ...


def durable_attempt_status_query(
    checkpoint: CheckpointEnvelope,
    *,
    requested_at: datetime,
    timeout: timedelta = DURABLE_STATUS_LOOKUP_DEFAULT_TIMEOUT,
) -> DurableAttemptStatusQuery:
    """Build one exact lookup query from a persisted indeterminate checkpoint."""

    if not isinstance(checkpoint, CheckpointEnvelope):
        raise TypeError("checkpoint must be CheckpointEnvelope")
    _require_timezone_aware(requested_at, label="requested_at")
    _require_lookup_timeout(timeout)

    attempt = checkpoint.metadata.active_attempt
    expected_kind: ExecutionAttemptKind
    if checkpoint.status is DurableRunStatus.INDETERMINATE_MODEL:
        expected_kind = ExecutionAttemptKind.MODEL_TURN
    elif checkpoint.status is DurableRunStatus.INDETERMINATE_TOOL:
        expected_kind = ExecutionAttemptKind.TOOL_INVOCATION
    else:
        raise ValueError("status lookup requires an indeterminate checkpoint")

    if (
        checkpoint.metadata.next_operation is not CheckpointNextOperation.OPERATOR_REVIEW
        or attempt is None
        or attempt.kind is not expected_kind
        or attempt.status is not ExecutionAttemptStatus.INDETERMINATE
        or attempt.external_request_digest is None
        or checkpoint.step_id is None
        or attempt.agent_run_id != checkpoint.agent_run_id
        or attempt.step_id != checkpoint.step_id
        or requested_at < checkpoint.created_at
        or requested_at >= checkpoint.metadata.retention_deadline
    ):
        raise ValueError("checkpoint is not eligible for adapter status lookup")

    deadline = min(requested_at + timeout, checkpoint.metadata.retention_deadline)
    if deadline <= requested_at:
        raise ValueError("no lookup time remains before retention expiry")

    return DurableAttemptStatusQuery(
        durable_run_id=checkpoint.durable_run_id,
        checkpoint_id=checkpoint.checkpoint_id,
        checkpoint_digest=checkpoint.digest,
        run_version=checkpoint.run_version,
        attempt_id=attempt.attempt_id,
        kind=attempt.kind,
        agent_run_id=attempt.agent_run_id,
        step_id=attempt.step_id,
        external_request_digest=attempt.external_request_digest,
        tool_call_id=attempt.tool_call_id,
        tool_effect=attempt.tool_effect,
        requested_at=requested_at,
        deadline=deadline,
    )


class ReviewedDurableAttemptStatusLookup:
    """Dispatch one bounded read-only query to an explicitly reviewed capability."""

    def __init__(
        self,
        *,
        model_adapter: DurableModelAttemptStatusAdapter | None = None,
        tool_adapter: DurableToolAttemptStatusAdapter | None = None,
        timeout: timedelta = DURABLE_STATUS_LOOKUP_DEFAULT_TIMEOUT,
    ) -> None:
        _require_lookup_timeout(timeout)
        self._model_adapter = model_adapter
        self._tool_adapter = tool_adapter
        self._timeout = timeout
        self._model_adapter_id = _adapter_id(
            model_adapter,
            method_name="lookup_model_attempt_status",
        )
        self._tool_adapter_id = _adapter_id(
            tool_adapter,
            method_name="lookup_tool_attempt_status",
        )

    async def lookup(
        self,
        checkpoint: CheckpointEnvelope,
        *,
        requested_at: datetime,
    ) -> DurableAttemptStatusLookupResult:
        query = durable_attempt_status_query(
            checkpoint,
            requested_at=requested_at,
            timeout=self._timeout,
        )

        if query.kind is ExecutionAttemptKind.MODEL_TURN:
            adapter = self._model_adapter
            adapter_id = self._model_adapter_id
            if adapter is None or adapter_id is None:
                return DurableAttemptStatusLookupResult(
                    query=query,
                    outcome=DurableAttemptStatusLookupOutcome.UNSUPPORTED,
                )
            try:
                async with asyncio.timeout((query.deadline - query.requested_at).total_seconds()):
                    observation = await adapter.lookup_model_attempt_status(query)
            except TimeoutError:
                return _empty_result(
                    query,
                    DurableAttemptStatusLookupOutcome.TIMED_OUT,
                    adapter_id,
                )
            except Exception:
                return _empty_result(
                    query,
                    DurableAttemptStatusLookupOutcome.ADAPTER_ERROR,
                    adapter_id,
                )
        else:
            tool_adapter = self._tool_adapter
            adapter_id = self._tool_adapter_id
            if tool_adapter is None or adapter_id is None:
                return DurableAttemptStatusLookupResult(
                    query=query,
                    outcome=DurableAttemptStatusLookupOutcome.UNSUPPORTED,
                )
            try:
                async with asyncio.timeout((query.deadline - query.requested_at).total_seconds()):
                    observation = await tool_adapter.lookup_tool_attempt_status(query)
            except TimeoutError:
                return _empty_result(
                    query,
                    DurableAttemptStatusLookupOutcome.TIMED_OUT,
                    adapter_id,
                )
            except Exception:
                return _empty_result(
                    query,
                    DurableAttemptStatusLookupOutcome.ADAPTER_ERROR,
                    adapter_id,
                )

        if not _observation_matches(query, adapter_id, observation):
            return _empty_result(
                query,
                DurableAttemptStatusLookupOutcome.INVALID_RESPONSE,
                adapter_id,
            )
        return DurableAttemptStatusLookupResult(
            query=query,
            outcome=DurableAttemptStatusLookupOutcome.OBSERVED,
            adapter_id=adapter_id,
            observation=observation,
        )


def _adapter_id(
    adapter: DurableModelAttemptStatusAdapter | DurableToolAttemptStatusAdapter | None,
    *,
    method_name: str,
) -> str | None:
    if adapter is None:
        return None
    if not callable(getattr(adapter, method_name, None)):
        raise TypeError(f"adapter must provide {method_name}")
    raw_adapter_id = getattr(adapter, "adapter_id", None)
    if not isinstance(raw_adapter_id, str):
        raise TypeError("adapter.adapter_id must be a string")
    return _normalize_adapter_id(raw_adapter_id)


def _empty_result(
    query: DurableAttemptStatusQuery,
    outcome: DurableAttemptStatusLookupOutcome,
    adapter_id: str,
) -> DurableAttemptStatusLookupResult:
    return DurableAttemptStatusLookupResult(
        query=query,
        outcome=outcome,
        adapter_id=adapter_id,
    )


def _observation_matches(
    query: DurableAttemptStatusQuery,
    adapter_id: str,
    observation: object,
) -> bool:
    if not isinstance(observation, DurableAttemptStatusObservation):
        return False
    return (
        observation.lookup_id == query.lookup_id
        and observation.durable_run_id == query.durable_run_id
        and observation.attempt_id == query.attempt_id
        and observation.external_request_digest == query.external_request_digest
        and observation.adapter_id == adapter_id
        and query.requested_at <= observation.observed_at <= query.deadline
    )
