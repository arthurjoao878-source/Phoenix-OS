from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import fields, replace
from datetime import UTC, datetime, timedelta
from typing import cast
from uuid import UUID

import pytest

from phoenix_os.agent import (
    DURABLE_STATUS_LOOKUP_DEFAULT_TIMEOUT,
    MAX_DURABLE_STATUS_LOOKUP_TIMEOUT,
    AgentId,
    AgentRunId,
    AgentStepId,
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
    DurableAttemptExternalStatus,
    DurableAttemptStatusLookupOutcome,
    DurableAttemptStatusLookupResult,
    DurableAttemptStatusObservation,
    DurableAttemptStatusQuery,
    DurableModelAttemptStatusAdapter,
    DurableRunStatus,
    DurableRunVersion,
    DurableToolAttemptStatusAdapter,
    ExecutionAttempt,
    ExecutionAttemptId,
    ExecutionAttemptKind,
    ExecutionAttemptStatus,
    IndeterminateReason,
    ReconciliationEvidence,
    ReviewedDurableAttemptStatusLookup,
    ToolCallId,
    ToolEffect,
    durable_attempt_status_query,
)
from phoenix_os.agent.durable_codec import seal_checkpoint_envelope
from phoenix_os.agent.state import AgentBudgetSnapshot

NOW = datetime(2026, 8, 1, 3, tzinfo=UTC)
REQUEST_TIME = NOW + timedelta(minutes=10)
DURABLE_RUN_ID = DurableAgentRunId(UUID("10000000-0000-0000-0000-000000000001"))
OTHER_RUN_ID = DurableAgentRunId(UUID("10000000-0000-0000-0000-000000000002"))
AGENT_RUN_ID = AgentRunId(UUID("20000000-0000-0000-0000-000000000002"))
STEP_ID = AgentStepId(UUID("30000000-0000-0000-0000-000000000003"))
ATTEMPT_ID = ExecutionAttemptId(UUID("40000000-0000-0000-0000-000000000004"))
OTHER_ATTEMPT_ID = ExecutionAttemptId(UUID("40000000-0000-0000-0000-000000000005"))
TOOL_CALL_ID = ToolCallId(UUID("50000000-0000-0000-0000-000000000005"))
OTHER_LOOKUP_ID = UUID("60000000-0000-0000-0000-000000000006")


def _digest(character: str) -> CheckpointDigest:
    return CheckpointDigest(character * 64)


def _compatibility() -> CompatibilityDigests:
    return CompatibilityDigests(
        configuration=_digest("a"),
        tool_registry=_digest("b"),
        model_provider=_digest("c"),
        checkpoint_codec=_digest("d"),
    )


def _budget(*, deadline: datetime | None = None) -> AgentBudgetSnapshot:
    return AgentBudgetSnapshot(
        steps=1,
        model_turns=1,
        tool_calls=1,
        model_output_bytes=64,
        tool_result_bytes=64,
        input_tokens=8,
        output_tokens=8,
        started_at=NOW - timedelta(minutes=1),
        deadline=deadline or NOW + timedelta(hours=1),
    )


def _attempt(
    kind: ExecutionAttemptKind,
    *,
    attempt_id: ExecutionAttemptId = ATTEMPT_ID,
    external_request_digest: CheckpointDigest | None = None,
) -> ExecutionAttempt:
    return ExecutionAttempt(
        attempt_id=attempt_id,
        kind=kind,
        status=ExecutionAttemptStatus.INDETERMINATE,
        agent_run_id=AGENT_RUN_ID,
        step_id=STEP_ID,
        prepared_at=NOW,
        tool_call_id=TOOL_CALL_ID if kind is ExecutionAttemptKind.TOOL_INVOCATION else None,
        tool_effect=(
            ToolEffect.EXTERNAL_COMMUNICATION
            if kind is ExecutionAttemptKind.TOOL_INVOCATION
            else None
        ),
        started_at=NOW + timedelta(minutes=1),
        completed_at=NOW + timedelta(minutes=2),
        external_request_digest=external_request_digest or _digest("e"),
        indeterminate_reason=IndeterminateReason.PROCESS_LOSS,
    )


def _checkpoint(
    kind: ExecutionAttemptKind = ExecutionAttemptKind.MODEL_TURN,
    *,
    status: DurableRunStatus | None = None,
    next_operation: CheckpointNextOperation = CheckpointNextOperation.OPERATOR_REVIEW,
    active_attempt: ExecutionAttempt | None | object = ...,
    created_at: datetime = NOW,
    retention_deadline: datetime | None = None,
    budget_deadline: datetime | None = None,
) -> CheckpointEnvelope:
    resolved_status = status or (
        DurableRunStatus.INDETERMINATE_MODEL
        if kind is ExecutionAttemptKind.MODEL_TURN
        else DurableRunStatus.INDETERMINATE_TOOL
    )
    resolved_attempt = _attempt(kind) if active_attempt is ... else active_attempt
    if resolved_status.terminal:
        next_operation = CheckpointNextOperation.NONE
        resolved_attempt = None
    if resolved_attempt is not None and not isinstance(resolved_attempt, ExecutionAttempt):
        raise TypeError("active_attempt helper value is invalid")
    return seal_checkpoint_envelope(
        CheckpointEnvelope(
            schema_version=CheckpointSchemaVersion(),
            durable_run_id=DURABLE_RUN_ID,
            checkpoint_id=CheckpointId(UUID("70000000-0000-0000-0000-000000000007")),
            sequence=CheckpointSequence(3),
            previous_digest=_digest("f"),
            run_version=DurableRunVersion(3),
            status=resolved_status,
            agent_run_id=AGENT_RUN_ID,
            step_id=STEP_ID,
            metadata=CheckpointMetadata(
                agent_id=AgentId("assistant"),
                actor_id="origin-worker",
                next_operation=next_operation,
                budget=_budget(deadline=budget_deadline),
                compatibility=_compatibility(),
                payload_profile=CheckpointPayloadProfile.METADATA_ONLY,
                retention_deadline=retention_deadline or NOW + timedelta(days=7),
                active_attempt=resolved_attempt,
                metadata={"tenant": "demo"},
            ),
            created_at=created_at,
            digest=_digest("0"),
        )
    )


def _evidence(observed_at: datetime) -> ReconciliationEvidence:
    return ReconciliationEvidence(
        evidence_type="adapter-status-receipt",
        evidence_digest=_digest("9"),
        observed_at=observed_at,
        metadata={},
    )


def _observation(
    query: DurableAttemptStatusQuery,
    *,
    adapter_id: str = "reviewed-model-status",
    status: DurableAttemptExternalStatus = DurableAttemptExternalStatus.SUCCEEDED,
    lookup_id: UUID | None = None,
    run_id: DurableAgentRunId | None = None,
    attempt_id: ExecutionAttemptId | None = None,
    digest: CheckpointDigest | None = None,
    observed_at: datetime | None = None,
) -> DurableAttemptStatusObservation:
    observation_time = observed_at or query.requested_at + timedelta(seconds=1)
    return DurableAttemptStatusObservation(
        lookup_id=query.lookup_id if lookup_id is None else lookup_id,
        durable_run_id=query.durable_run_id if run_id is None else run_id,
        attempt_id=query.attempt_id if attempt_id is None else attempt_id,
        external_request_digest=query.external_request_digest if digest is None else digest,
        adapter_id=adapter_id,
        status=status,
        observed_at=observation_time,
        evidence=(
            None if status is DurableAttemptExternalStatus.UNKNOWN else _evidence(observation_time)
        ),
    )


class _ModelAdapter:
    adapter_id = "reviewed-model-status"

    def __init__(
        self,
        factory: Callable[[DurableAttemptStatusQuery], DurableAttemptStatusObservation],
    ) -> None:
        self.factory = factory
        self.queries: list[DurableAttemptStatusQuery] = []

    async def lookup_model_attempt_status(
        self,
        query: DurableAttemptStatusQuery,
    ) -> DurableAttemptStatusObservation:
        self.queries.append(query)
        return self.factory(query)


class _ToolAdapter:
    adapter_id = "reviewed-tool-status"

    def __init__(
        self,
        factory: Callable[[DurableAttemptStatusQuery], DurableAttemptStatusObservation],
    ) -> None:
        self.factory = factory
        self.queries: list[DurableAttemptStatusQuery] = []

    async def lookup_tool_attempt_status(
        self,
        query: DurableAttemptStatusQuery,
    ) -> DurableAttemptStatusObservation:
        self.queries.append(query)
        return self.factory(query)


class _ErrorModelAdapter:
    adapter_id = "reviewed-model-status"

    def __init__(self) -> None:
        self.calls = 0

    async def lookup_model_attempt_status(
        self,
        query: DurableAttemptStatusQuery,
    ) -> DurableAttemptStatusObservation:
        del query
        self.calls += 1
        raise RuntimeError("raw provider secret must not escape")


class _SlowModelAdapter:
    adapter_id = "reviewed-model-status"

    async def lookup_model_attempt_status(
        self,
        query: DurableAttemptStatusQuery,
    ) -> DurableAttemptStatusObservation:
        await asyncio.sleep(1)
        return _observation(query)


class _CancelledModelAdapter:
    adapter_id = "reviewed-model-status"

    async def lookup_model_attempt_status(
        self,
        query: DurableAttemptStatusQuery,
    ) -> DurableAttemptStatusObservation:
        del query
        raise asyncio.CancelledError


class _WrongTypeModelAdapter:
    adapter_id = "reviewed-model-status"

    async def lookup_model_attempt_status(
        self,
        query: DurableAttemptStatusQuery,
    ) -> DurableAttemptStatusObservation:
        del query
        return cast(DurableAttemptStatusObservation, object())


def test_constants_are_bounded() -> None:
    assert DURABLE_STATUS_LOOKUP_DEFAULT_TIMEOUT == timedelta(seconds=5)
    assert MAX_DURABLE_STATUS_LOOKUP_TIMEOUT == timedelta(seconds=30)
    assert DURABLE_STATUS_LOOKUP_DEFAULT_TIMEOUT <= MAX_DURABLE_STATUS_LOOKUP_TIMEOUT


def test_reviewed_adapters_implement_separate_protocols() -> None:
    model = _ModelAdapter(_observation)
    tool = _ToolAdapter(lambda query: _observation(query, adapter_id="reviewed-tool-status"))
    assert isinstance(model, DurableModelAttemptStatusAdapter)
    assert isinstance(tool, DurableToolAttemptStatusAdapter)
    assert not isinstance(model, DurableToolAttemptStatusAdapter)
    assert not isinstance(tool, DurableModelAttemptStatusAdapter)


@pytest.mark.parametrize(
    "kind",
    (ExecutionAttemptKind.MODEL_TURN, ExecutionAttemptKind.TOOL_INVOCATION),
)
def test_query_is_exact_and_content_free(kind: ExecutionAttemptKind) -> None:
    checkpoint = _checkpoint(kind)
    query = durable_attempt_status_query(
        checkpoint,
        requested_at=REQUEST_TIME,
    )
    attempt = checkpoint.metadata.active_attempt
    assert attempt is not None

    assert query.durable_run_id == checkpoint.durable_run_id
    assert query.checkpoint_id == checkpoint.checkpoint_id
    assert query.checkpoint_digest == checkpoint.digest
    assert query.run_version == checkpoint.run_version
    assert query.attempt_id == attempt.attempt_id
    assert query.kind is kind
    assert query.agent_run_id == checkpoint.agent_run_id
    assert query.step_id == checkpoint.step_id
    assert query.external_request_digest == attempt.external_request_digest
    assert query.requested_at == REQUEST_TIME
    assert query.deadline == REQUEST_TIME + DURABLE_STATUS_LOOKUP_DEFAULT_TIMEOUT
    assert query.tool_call_id == attempt.tool_call_id
    assert query.tool_effect == attempt.tool_effect

    names = {item.name for item in fields(DurableAttemptStatusQuery)}
    assert names.isdisjoint(
        {
            "arguments",
            "messages",
            "output",
            "payload",
            "prompt",
            "response",
            "result",
            "text",
        }
    )


def test_query_deadline_is_clamped_to_retention() -> None:
    retention_deadline = REQUEST_TIME + timedelta(seconds=2)
    query = durable_attempt_status_query(
        _checkpoint(retention_deadline=retention_deadline),
        requested_at=REQUEST_TIME,
        timeout=timedelta(seconds=10),
    )
    assert query.deadline == retention_deadline


def test_status_lookup_remains_available_after_execution_budget_expiry() -> None:
    query = durable_attempt_status_query(
        _checkpoint(budget_deadline=REQUEST_TIME - timedelta(seconds=1)),
        requested_at=REQUEST_TIME,
    )
    assert query.requested_at == REQUEST_TIME


@pytest.mark.parametrize(
    "checkpoint",
    (
        _checkpoint(
            status=DurableRunStatus.PAUSED_OPERATOR,
            next_operation=CheckpointNextOperation.OPERATOR_REVIEW,
            active_attempt=None,
        ),
        _checkpoint(
            status=DurableRunStatus.PAUSED_SHUTDOWN,
            next_operation=CheckpointNextOperation.MODEL_TURN,
            active_attempt=None,
        ),
    ),
)
def test_query_requires_persisted_indeterminate_state(
    checkpoint: CheckpointEnvelope,
) -> None:
    with pytest.raises(ValueError, match="indeterminate checkpoint"):
        durable_attempt_status_query(checkpoint, requested_at=REQUEST_TIME)


def test_query_rejects_wrong_next_operation() -> None:
    checkpoint = _checkpoint(next_operation=CheckpointNextOperation.MODEL_TURN)
    with pytest.raises(ValueError, match="not eligible"):
        durable_attempt_status_query(checkpoint, requested_at=REQUEST_TIME)


@pytest.mark.parametrize(
    "requested_at",
    (
        NOW - timedelta(seconds=1),
        NOW + timedelta(days=7),
    ),
)
def test_query_rejects_invalid_lookup_time(requested_at: datetime) -> None:
    with pytest.raises(ValueError):
        durable_attempt_status_query(
            _checkpoint(),
            requested_at=requested_at,
        )


@pytest.mark.parametrize(
    "timeout",
    (
        timedelta(0),
        timedelta(seconds=-1),
        MAX_DURABLE_STATUS_LOOKUP_TIMEOUT + timedelta(microseconds=1),
    ),
)
def test_query_rejects_invalid_timeout(timeout: timedelta) -> None:
    with pytest.raises(ValueError):
        durable_attempt_status_query(
            _checkpoint(),
            requested_at=REQUEST_TIME,
            timeout=timeout,
        )


def test_query_rejects_wrong_types() -> None:
    with pytest.raises(TypeError):
        durable_attempt_status_query(
            cast(CheckpointEnvelope, object()),
            requested_at=REQUEST_TIME,
        )
    with pytest.raises(TypeError):
        durable_attempt_status_query(
            _checkpoint(),
            requested_at=cast(datetime, "now"),
        )
    with pytest.raises(TypeError):
        durable_attempt_status_query(
            _checkpoint(),
            requested_at=REQUEST_TIME,
            timeout=cast(timedelta, 1),
        )


def test_query_contract_rejects_tool_identity_on_model_query() -> None:
    query = durable_attempt_status_query(_checkpoint(), requested_at=REQUEST_TIME)
    with pytest.raises(ValueError, match="model status queries"):
        replace(
            query,
            tool_call_id=TOOL_CALL_ID,
            tool_effect=ToolEffect.READ_ONLY,
        )


def test_query_contract_requires_tool_identity_on_tool_query() -> None:
    query = durable_attempt_status_query(
        _checkpoint(ExecutionAttemptKind.TOOL_INVOCATION),
        requested_at=REQUEST_TIME,
    )
    with pytest.raises(ValueError, match="tool status queries"):
        replace(query, tool_call_id=None)


@pytest.mark.parametrize(
    "status",
    tuple(DurableAttemptExternalStatus),
)
def test_observation_contract_is_bounded(
    status: DurableAttemptExternalStatus,
) -> None:
    query = durable_attempt_status_query(_checkpoint(), requested_at=REQUEST_TIME)
    observation = _observation(query, status=status)
    assert observation.status is status
    if status is DurableAttemptExternalStatus.UNKNOWN:
        assert observation.evidence is None
    else:
        assert observation.evidence is not None
        assert observation.evidence.observed_at == observation.observed_at


def test_unknown_observation_rejects_evidence() -> None:
    query = durable_attempt_status_query(_checkpoint(), requested_at=REQUEST_TIME)
    with pytest.raises(ValueError, match="unknown observations"):
        DurableAttemptStatusObservation(
            lookup_id=query.lookup_id,
            durable_run_id=query.durable_run_id,
            attempt_id=query.attempt_id,
            external_request_digest=query.external_request_digest,
            adapter_id="reviewed-model-status",
            status=DurableAttemptExternalStatus.UNKNOWN,
            observed_at=REQUEST_TIME,
            evidence=_evidence(REQUEST_TIME),
        )


def test_proved_observation_requires_matching_evidence() -> None:
    query = durable_attempt_status_query(_checkpoint(), requested_at=REQUEST_TIME)
    with pytest.raises(ValueError, match="require reconciliation evidence"):
        DurableAttemptStatusObservation(
            lookup_id=query.lookup_id,
            durable_run_id=query.durable_run_id,
            attempt_id=query.attempt_id,
            external_request_digest=query.external_request_digest,
            adapter_id="reviewed-model-status",
            status=DurableAttemptExternalStatus.SUCCEEDED,
            observed_at=REQUEST_TIME,
        )
    with pytest.raises(ValueError, match="evidence time"):
        DurableAttemptStatusObservation(
            lookup_id=query.lookup_id,
            durable_run_id=query.durable_run_id,
            attempt_id=query.attempt_id,
            external_request_digest=query.external_request_digest,
            adapter_id="reviewed-model-status",
            status=DurableAttemptExternalStatus.SUCCEEDED,
            observed_at=REQUEST_TIME,
            evidence=_evidence(REQUEST_TIME - timedelta(seconds=1)),
        )
    with pytest.raises(ValueError, match="metadata must be empty"):
        DurableAttemptStatusObservation(
            lookup_id=query.lookup_id,
            durable_run_id=query.durable_run_id,
            attempt_id=query.attempt_id,
            external_request_digest=query.external_request_digest,
            adapter_id="reviewed-model-status",
            status=DurableAttemptExternalStatus.SUCCEEDED,
            observed_at=REQUEST_TIME,
            evidence=ReconciliationEvidence(
                evidence_type="adapter-status-receipt",
                evidence_digest=_digest("9"),
                observed_at=REQUEST_TIME,
                metadata={"raw": "forbidden"},
            ),
        )


def test_constructor_validates_reviewed_capabilities_and_timeout() -> None:
    with pytest.raises(TypeError, match="lookup_model_attempt_status"):
        ReviewedDurableAttemptStatusLookup(
            model_adapter=cast(DurableModelAttemptStatusAdapter, object())
        )
    with pytest.raises(ValueError, match="adapter_id"):
        bad = _ModelAdapter(_observation)
        bad.adapter_id = "INVALID ID"
        ReviewedDurableAttemptStatusLookup(model_adapter=bad)
    with pytest.raises(ValueError, match="timeout"):
        ReviewedDurableAttemptStatusLookup(timeout=timedelta(0))


@pytest.mark.asyncio
async def test_model_lookup_dispatches_once_to_exact_capability() -> None:
    adapter = _ModelAdapter(_observation)
    boundary = ReviewedDurableAttemptStatusLookup(model_adapter=adapter)
    checkpoint = _checkpoint()
    result = await boundary.lookup(checkpoint, requested_at=REQUEST_TIME)

    assert result.outcome is DurableAttemptStatusLookupOutcome.OBSERVED
    assert result.status is DurableAttemptExternalStatus.SUCCEEDED
    assert result.evidence is not None
    assert result.adapter_id == adapter.adapter_id
    assert len(adapter.queries) == 1
    assert adapter.queries[0] == result.query


@pytest.mark.asyncio
async def test_tool_lookup_dispatches_once_to_exact_capability() -> None:
    adapter = _ToolAdapter(lambda query: _observation(query, adapter_id="reviewed-tool-status"))
    boundary = ReviewedDurableAttemptStatusLookup(tool_adapter=adapter)
    result = await boundary.lookup(
        _checkpoint(ExecutionAttemptKind.TOOL_INVOCATION),
        requested_at=REQUEST_TIME,
    )

    assert result.outcome is DurableAttemptStatusLookupOutcome.OBSERVED
    assert result.status is DurableAttemptExternalStatus.SUCCEEDED
    assert result.adapter_id == adapter.adapter_id
    assert len(adapter.queries) == 1
    assert result.query.kind is ExecutionAttemptKind.TOOL_INVOCATION


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "kind",
    (ExecutionAttemptKind.MODEL_TURN, ExecutionAttemptKind.TOOL_INVOCATION),
)
async def test_missing_capability_is_safe_and_unsupported(
    kind: ExecutionAttemptKind,
) -> None:
    result = await ReviewedDurableAttemptStatusLookup().lookup(
        _checkpoint(kind),
        requested_at=REQUEST_TIME,
    )
    assert result.outcome is DurableAttemptStatusLookupOutcome.UNSUPPORTED
    assert result.adapter_id is None
    assert result.observation is None
    assert result.status is DurableAttemptExternalStatus.UNKNOWN
    assert result.evidence is None


@pytest.mark.asyncio
async def test_adapter_unknown_is_a_valid_observation_without_evidence() -> None:
    adapter = _ModelAdapter(
        lambda query: _observation(
            query,
            status=DurableAttemptExternalStatus.UNKNOWN,
        )
    )
    result = await ReviewedDurableAttemptStatusLookup(model_adapter=adapter).lookup(
        _checkpoint(), requested_at=REQUEST_TIME
    )

    assert result.outcome is DurableAttemptStatusLookupOutcome.OBSERVED
    assert result.status is DurableAttemptExternalStatus.UNKNOWN
    assert result.evidence is None


@pytest.mark.asyncio
async def test_adapter_error_is_bounded_and_not_retried() -> None:
    adapter = _ErrorModelAdapter()
    result = await ReviewedDurableAttemptStatusLookup(model_adapter=adapter).lookup(
        _checkpoint(), requested_at=REQUEST_TIME
    )

    assert result.outcome is DurableAttemptStatusLookupOutcome.ADAPTER_ERROR
    assert result.status is DurableAttemptExternalStatus.UNKNOWN
    assert result.observation is None
    assert adapter.calls == 1
    assert "secret" not in repr(result)


@pytest.mark.asyncio
async def test_adapter_timeout_is_bounded() -> None:
    result = await ReviewedDurableAttemptStatusLookup(
        model_adapter=_SlowModelAdapter(),
        timeout=timedelta(milliseconds=1),
    ).lookup(_checkpoint(), requested_at=REQUEST_TIME)

    assert result.outcome is DurableAttemptStatusLookupOutcome.TIMED_OUT
    assert result.status is DurableAttemptExternalStatus.UNKNOWN
    assert result.observation is None


@pytest.mark.asyncio
async def test_cancellation_is_not_swallowed() -> None:
    with pytest.raises(asyncio.CancelledError):
        await ReviewedDurableAttemptStatusLookup(model_adapter=_CancelledModelAdapter()).lookup(
            _checkpoint(), requested_at=REQUEST_TIME
        )


@pytest.mark.asyncio
async def test_wrong_response_type_is_rejected_safely() -> None:
    result = await ReviewedDurableAttemptStatusLookup(
        model_adapter=_WrongTypeModelAdapter()
    ).lookup(_checkpoint(), requested_at=REQUEST_TIME)

    assert result.outcome is DurableAttemptStatusLookupOutcome.INVALID_RESPONSE
    assert result.status is DurableAttemptExternalStatus.UNKNOWN
    assert result.observation is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "factory",
    (
        lambda query: _observation(query, lookup_id=OTHER_LOOKUP_ID),
        lambda query: _observation(query, run_id=OTHER_RUN_ID),
        lambda query: _observation(query, attempt_id=OTHER_ATTEMPT_ID),
        lambda query: _observation(query, digest=_digest("8")),
        lambda query: _observation(query, adapter_id="other-reviewed-adapter"),
        lambda query: _observation(
            query,
            observed_at=query.requested_at - timedelta(microseconds=1),
        ),
        lambda query: _observation(
            query,
            observed_at=query.deadline + timedelta(microseconds=1),
        ),
    ),
)
async def test_substituted_or_out_of_window_observation_is_rejected(
    factory: Callable[[DurableAttemptStatusQuery], DurableAttemptStatusObservation],
) -> None:
    result = await ReviewedDurableAttemptStatusLookup(model_adapter=_ModelAdapter(factory)).lookup(
        _checkpoint(), requested_at=REQUEST_TIME
    )

    assert result.outcome is DurableAttemptStatusLookupOutcome.INVALID_RESPONSE
    assert result.status is DurableAttemptExternalStatus.UNKNOWN
    assert result.observation is None


def test_lookup_result_contract_rejects_inconsistent_shapes() -> None:
    query = durable_attempt_status_query(_checkpoint(), requested_at=REQUEST_TIME)
    observation = _observation(query)

    with pytest.raises(ValueError, match="require an observation"):
        DurableAttemptStatusLookupResult(
            query=query,
            outcome=DurableAttemptStatusLookupOutcome.OBSERVED,
            adapter_id="reviewed-model-status",
        )
    with pytest.raises(ValueError, match="cannot contain an observation"):
        DurableAttemptStatusLookupResult(
            query=query,
            outcome=DurableAttemptStatusLookupOutcome.ADAPTER_ERROR,
            adapter_id="reviewed-model-status",
            observation=observation,
        )
    with pytest.raises(ValueError, match="cannot identify an adapter"):
        DurableAttemptStatusLookupResult(
            query=query,
            outcome=DurableAttemptStatusLookupOutcome.UNSUPPORTED,
            adapter_id="reviewed-model-status",
        )
    with pytest.raises(ValueError, match="does not match"):
        DurableAttemptStatusLookupResult(
            query=query,
            outcome=DurableAttemptStatusLookupOutcome.OBSERVED,
            adapter_id="other-reviewed-adapter",
            observation=observation,
        )


@pytest.mark.asyncio
async def test_lookup_does_not_mutate_checkpoint_or_attempt() -> None:
    checkpoint = _checkpoint()
    attempt = checkpoint.metadata.active_attempt
    before_checkpoint = checkpoint
    before_attempt = attempt
    adapter = _ModelAdapter(_observation)

    result = await ReviewedDurableAttemptStatusLookup(model_adapter=adapter).lookup(
        checkpoint, requested_at=REQUEST_TIME
    )

    assert result.outcome is DurableAttemptStatusLookupOutcome.OBSERVED
    assert checkpoint == before_checkpoint
    assert checkpoint.metadata.active_attempt == before_attempt
    assert checkpoint.metadata.active_attempt is attempt
