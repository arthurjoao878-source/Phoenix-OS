from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from phoenix_os.agent.contracts import AgentId, AgentRunId, AgentStepId, ToolCallId, ToolEffect
from phoenix_os.agent.durable_attempts import (
    DurableTerminalMetadataProjectingAttemptRecorder,
    StoreBackedDurableExecutionAttemptRecorder,
)
from phoenix_os.agent.durable_codec import seal_checkpoint_envelope
from phoenix_os.agent.durable_contracts import (
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
    DurableLease,
    DurableRunStatus,
    DurableRunVersion,
    ExecutionAttempt,
    ExecutionAttemptId,
    ExecutionAttemptKind,
    ExecutionAttemptStatus,
)
from phoenix_os.agent.durable_memory import InMemoryDurableRunStore
from phoenix_os.agent.errors import AgentStateConflictError
from phoenix_os.agent.state import AgentBudgetSnapshot

NOW = datetime(2026, 9, 6, 20, tzinfo=UTC)
LEASE_TIME = NOW + timedelta(seconds=1)
TERMINAL_TIME = NOW + timedelta(seconds=2)

DURABLE_RUN_ID = DurableAgentRunId(UUID("13000000-0000-0000-0000-000000000039"))
AGENT_RUN_ID = AgentRunId(UUID("23000000-0000-0000-0000-000000000039"))
STEP_ID = AgentStepId(UUID("33000000-0000-0000-0000-000000000039"))
CALL_ID = ToolCallId(UUID("43000000-0000-0000-0000-000000000039"))
ATTEMPT_ID = ExecutionAttemptId(UUID("53000000-0000-0000-0000-000000000039"))


def _digest(character: str) -> CheckpointDigest:
    return CheckpointDigest(character * 64)


def _compatibility() -> CompatibilityDigests:
    return CompatibilityDigests(
        configuration=_digest("a"),
        tool_registry=_digest("b"),
        model_provider=_digest("c"),
        checkpoint_codec=_digest("d"),
    )


def _budget() -> AgentBudgetSnapshot:
    return AgentBudgetSnapshot(
        steps=1,
        model_turns=1,
        tool_calls=1,
        model_output_bytes=64,
        tool_result_bytes=0,
        input_tokens=8,
        output_tokens=8,
        started_at=NOW - timedelta(minutes=1),
        deadline=NOW + timedelta(minutes=10),
    )


def _started_attempt() -> ExecutionAttempt:
    return ExecutionAttempt(
        attempt_id=ATTEMPT_ID,
        kind=ExecutionAttemptKind.TOOL_INVOCATION,
        status=ExecutionAttemptStatus.STARTED,
        agent_run_id=AGENT_RUN_ID,
        step_id=STEP_ID,
        prepared_at=NOW - timedelta(seconds=2),
        started_at=NOW - timedelta(seconds=1),
        tool_call_id=CALL_ID,
        tool_effect=ToolEffect.READ_ONLY,
        external_request_digest=_digest("e"),
    )


def _checkpoint() -> CheckpointEnvelope:
    return seal_checkpoint_envelope(
        CheckpointEnvelope(
            schema_version=CheckpointSchemaVersion(),
            durable_run_id=DURABLE_RUN_ID,
            checkpoint_id=CheckpointId(UUID("63000000-0000-0000-0000-000000000039")),
            sequence=CheckpointSequence(1),
            previous_digest=None,
            run_version=DurableRunVersion(1),
            status=DurableRunStatus.ACTIVE,
            agent_run_id=AGENT_RUN_ID,
            step_id=STEP_ID,
            metadata=CheckpointMetadata(
                agent_id=AgentId("assistant"),
                actor_id="rfc0039-terminal-metadata-test",
                next_operation=CheckpointNextOperation.TOOL_INVOCATION,
                budget=_budget(),
                compatibility=_compatibility(),
                payload_profile=CheckpointPayloadProfile.METADATA_ONLY,
                retention_deadline=NOW + timedelta(days=1),
                active_attempt=_started_attempt(),
                metadata={"fixture": "base"},
            ),
            created_at=NOW,
            digest=_digest("0"),
        )
    )


class _Projector:
    def __init__(
        self,
        name: str,
        calls: list[str],
        *,
        require_key: tuple[str, str] | None = None,
    ) -> None:
        self._name = name
        self._calls = calls
        self._require_key = require_key

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
        assert current.durable_run_id == DURABLE_RUN_ID
        assert isinstance(checkpoint_id, CheckpointId)
        assert status is DurableRunStatus.ACTIVE
        assert step_id == STEP_ID
        assert next_operation is CheckpointNextOperation.VALIDATE_RESULT
        assert active_attempt is not None
        assert active_attempt.status is ExecutionAttemptStatus.SUCCEEDED
        if self._require_key is not None:
            key, value = self._require_key
            assert metadata[key] == value
        self._calls.append(self._name)
        projected = dict(metadata)
        projected[f"projector.{self._name}"] = "applied"
        return projected


class _FailingProjector:
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
        del current, checkpoint_id, status, step_id, next_operation, active_attempt, metadata
        raise ValueError("private projector failure")


async def _environment(
    *,
    configured_projector: _Projector | None = None,
) -> tuple[
    InMemoryDurableRunStore,
    DurableLease,
    StoreBackedDurableExecutionAttemptRecorder,
]:
    store = InMemoryDurableRunStore()
    await store.create(_checkpoint())
    lease = await store.lease_manager.acquire(
        DURABLE_RUN_ID,
        owner_id="rfc0039-terminal-metadata-test",
        now=LEASE_TIME,
    )
    recorder = StoreBackedDurableExecutionAttemptRecorder(
        store=store,
        metadata_projector=configured_projector,
    )
    return store, lease, recorder


@pytest.mark.asyncio
async def test_projected_terminal_applies_transition_then_configured_projector() -> None:
    calls: list[str] = []
    transition = _Projector("transition", calls)
    configured = _Projector(
        "configured",
        calls,
        require_key=("projector.transition", "applied"),
    )
    store, lease, recorder = await _environment(configured_projector=configured)
    try:
        assert isinstance(recorder, DurableTerminalMetadataProjectingAttemptRecorder)

        terminal = await recorder.mark_terminal_projected(
            DURABLE_RUN_ID,
            ATTEMPT_ID,
            expected_version=DurableRunVersion(1),
            lease=lease,
            status=ExecutionAttemptStatus.SUCCEEDED,
            now=TERMINAL_TIME,
            metadata_projector=transition,
            next_operation=CheckpointNextOperation.VALIDATE_RESULT,
        )

        assert calls == ["transition", "configured"]
        assert terminal.metadata.metadata == {
            "fixture": "base",
            "projector.transition": "applied",
            "projector.configured": "applied",
        }
        assert terminal.metadata.next_operation is CheckpointNextOperation.VALIDATE_RESULT
        assert terminal.metadata.active_attempt is not None
        assert terminal.metadata.active_attempt.status is ExecutionAttemptStatus.SUCCEEDED
    finally:
        await store.close()


@pytest.mark.asyncio
async def test_normal_terminal_keeps_existing_configured_projector_semantics() -> None:
    calls: list[str] = []
    configured = _Projector("configured", calls)
    store, lease, recorder = await _environment(configured_projector=configured)
    try:
        terminal = await recorder.mark_terminal(
            DURABLE_RUN_ID,
            ATTEMPT_ID,
            expected_version=DurableRunVersion(1),
            lease=lease,
            status=ExecutionAttemptStatus.SUCCEEDED,
            now=TERMINAL_TIME,
            next_operation=CheckpointNextOperation.VALIDATE_RESULT,
        )

        assert calls == ["configured"]
        assert terminal.metadata.metadata == {
            "fixture": "base",
            "projector.configured": "applied",
        }
    finally:
        await store.close()


@pytest.mark.asyncio
async def test_projected_terminal_fails_closed_without_persisting_on_projector_error() -> None:
    store, lease, recorder = await _environment()
    try:
        with pytest.raises(AgentStateConflictError):
            await recorder.mark_terminal_projected(
                DURABLE_RUN_ID,
                ATTEMPT_ID,
                expected_version=DurableRunVersion(1),
                lease=lease,
                status=ExecutionAttemptStatus.SUCCEEDED,
                now=TERMINAL_TIME,
                metadata_projector=_FailingProjector(),
                next_operation=CheckpointNextOperation.VALIDATE_RESULT,
            )

        current = await store.get_current(DURABLE_RUN_ID)
        assert current is not None
        assert current.run_version == DurableRunVersion(1)
        assert current.metadata.next_operation is CheckpointNextOperation.TOOL_INVOCATION
        assert current.metadata.active_attempt is not None
        assert current.metadata.active_attempt.status is ExecutionAttemptStatus.STARTED
        assert current.metadata.metadata == {"fixture": "base"}
    finally:
        await store.close()


@pytest.mark.asyncio
async def test_projected_terminal_rejects_invalid_projector_before_mutation() -> None:
    store, lease, recorder = await _environment()
    try:
        with pytest.raises(TypeError, match="metadata_projector"):
            await recorder.mark_terminal_projected(
                DURABLE_RUN_ID,
                ATTEMPT_ID,
                expected_version=DurableRunVersion(1),
                lease=lease,
                status=ExecutionAttemptStatus.SUCCEEDED,
                now=TERMINAL_TIME,
                metadata_projector=object(),  # type: ignore[arg-type]
                next_operation=CheckpointNextOperation.VALIDATE_RESULT,
            )

        current = await store.get_current(DURABLE_RUN_ID)
        assert current is not None
        assert current.run_version == DurableRunVersion(1)
    finally:
        await store.close()
