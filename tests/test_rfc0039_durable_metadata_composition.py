from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from phoenix_os.agent.contracts import AgentId, AgentRunId, AgentStepId
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
    DurableRunStatus,
    DurableRunVersion,
    ExecutionAttempt,
)
from phoenix_os.agent.durable_metadata import (
    ChainedDurableCheckpointHistoryValidator,
    ChainedDurableCheckpointMetadataProjector,
    DurableCheckpointHistoryValidator,
    DurableCheckpointMetadataProjector,
    project_durable_checkpoint_metadata,
    validate_durable_checkpoint_history,
)
from phoenix_os.agent.errors import AgentCodecError, AgentStateConflictError
from phoenix_os.agent.state import AgentBudgetSnapshot

_NOW = datetime(2026, 9, 6, 12, tzinfo=UTC)
_RUN_ID = DurableAgentRunId(UUID("10000000-0000-4000-8000-000000000001"))
_AGENT_RUN_ID = AgentRunId(UUID("20000000-0000-4000-8000-000000000002"))
_STEP_ID = AgentStepId(UUID("30000000-0000-4000-8000-000000000003"))
_CURRENT_CHECKPOINT_ID = CheckpointId(UUID("40000000-0000-4000-8000-000000000004"))
_NEXT_CHECKPOINT_ID = CheckpointId(UUID("50000000-0000-4000-8000-000000000005"))


def _digest(character: str) -> CheckpointDigest:
    return CheckpointDigest(character * 64)


def _checkpoint() -> CheckpointEnvelope:
    budget = AgentBudgetSnapshot(
        steps=1,
        model_turns=0,
        tool_calls=0,
        model_output_bytes=0,
        tool_result_bytes=0,
        input_tokens=8,
        output_tokens=0,
        started_at=_NOW - timedelta(minutes=1),
        deadline=_NOW + timedelta(hours=1),
    )
    compatibility = CompatibilityDigests(
        configuration=_digest("a"),
        tool_registry=_digest("b"),
        model_provider=_digest("c"),
        checkpoint_codec=_digest("d"),
    )
    return seal_checkpoint_envelope(
        CheckpointEnvelope(
            schema_version=CheckpointSchemaVersion(),
            durable_run_id=_RUN_ID,
            checkpoint_id=_CURRENT_CHECKPOINT_ID,
            sequence=CheckpointSequence(1),
            previous_digest=None,
            run_version=DurableRunVersion(1),
            status=DurableRunStatus.ACTIVE,
            agent_run_id=_AGENT_RUN_ID,
            step_id=_STEP_ID,
            metadata=CheckpointMetadata(
                agent_id=AgentId("assistant"),
                actor_id="worker-1",
                next_operation=CheckpointNextOperation.MODEL_TURN,
                budget=budget,
                compatibility=compatibility,
                payload_profile=CheckpointPayloadProfile.METADATA_ONLY,
                retention_deadline=_NOW + timedelta(days=1),
                metadata={"base": "keep"},
            ),
            created_at=_NOW,
            digest=_digest("0"),
        )
    )


class _RecordingProjector:
    def __init__(
        self,
        name: str,
        calls: list[tuple[str, dict[str, str]]],
        *,
        fail: bool = False,
    ) -> None:
        self._name = name
        self._calls = calls
        self._fail = fail

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
        del current, checkpoint_id, status, step_id, next_operation, active_attempt
        self._calls.append((self._name, dict(metadata)))
        if self._fail:
            raise ValueError(f"{self._name} failed")
        projected = dict(metadata)
        projected[f"extension.{self._name}"] = self._name
        return projected


class _RecordingValidator:
    def __init__(
        self,
        name: str,
        calls: list[str],
        *,
        fail: bool = False,
    ) -> None:
        self._name = name
        self._calls = calls
        self._fail = fail

    def validate_history(
        self,
        current: CheckpointEnvelope,
        history: tuple[CheckpointEnvelope, ...],
    ) -> None:
        assert history[-1] == current
        self._calls.append(self._name)
        if self._fail:
            raise ValueError(f"{self._name} failed")


def _project(
    projector: DurableCheckpointMetadataProjector,
    *,
    metadata: Mapping[str, str],
) -> Mapping[str, str]:
    current = _checkpoint()
    return project_durable_checkpoint_metadata(
        projector,
        current,
        checkpoint_id=_NEXT_CHECKPOINT_ID,
        status=current.status,
        step_id=current.step_id,
        next_operation=current.metadata.next_operation,
        active_attempt=current.metadata.active_attempt,
        metadata=metadata,
    )


def test_projector_chain_is_ordered_immutable_and_protocol_compatible() -> None:
    calls: list[tuple[str, dict[str, str]]] = []
    first = _RecordingProjector("first", calls)
    second = _RecordingProjector("second", calls)
    chain = ChainedDurableCheckpointMetadataProjector((first, second))
    original = {"base": "keep"}

    assert isinstance(chain, DurableCheckpointMetadataProjector)
    assert chain.projectors == (first, second)

    projected = _project(chain, metadata=original)

    assert original == {"base": "keep"}
    assert projected == {
        "base": "keep",
        "extension.first": "first",
        "extension.second": "second",
    }
    assert calls == [
        ("first", {"base": "keep"}),
        (
            "second",
            {
                "base": "keep",
                "extension.first": "first",
            },
        ),
    ]


def test_projector_chain_fails_closed_and_stops_after_first_failure() -> None:
    calls: list[tuple[str, dict[str, str]]] = []
    chain = ChainedDurableCheckpointMetadataProjector(
        (
            _RecordingProjector("first", calls),
            _RecordingProjector("broken", calls, fail=True),
            _RecordingProjector("never", calls),
        )
    )

    with pytest.raises(AgentStateConflictError):
        _project(chain, metadata={"base": "keep"})

    assert [name for name, _metadata in calls] == ["first", "broken"]


def test_projector_chain_rejects_empty_non_tuple_and_non_projector_members() -> None:
    with pytest.raises(ValueError, match="must not be empty"):
        ChainedDurableCheckpointMetadataProjector(())
    with pytest.raises(TypeError, match="must be a tuple"):
        ChainedDurableCheckpointMetadataProjector([])  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="must implement"):
        ChainedDurableCheckpointMetadataProjector((object(),))  # type: ignore[arg-type]


def test_history_validator_chain_is_ordered_and_protocol_compatible() -> None:
    calls: list[str] = []
    first = _RecordingValidator("first", calls)
    second = _RecordingValidator("second", calls)
    chain = ChainedDurableCheckpointHistoryValidator((first, second))
    current = _checkpoint()
    history = (current,)

    assert isinstance(chain, DurableCheckpointHistoryValidator)
    assert chain.validators == (first, second)

    validate_durable_checkpoint_history(chain, current, history)

    assert calls == ["first", "second"]


def test_history_validator_chain_fails_closed_and_stops_after_first_failure() -> None:
    calls: list[str] = []
    chain = ChainedDurableCheckpointHistoryValidator(
        (
            _RecordingValidator("first", calls),
            _RecordingValidator("broken", calls, fail=True),
            _RecordingValidator("never", calls),
        )
    )
    current = _checkpoint()

    with pytest.raises(AgentCodecError, match="extension history is invalid"):
        validate_durable_checkpoint_history(chain, current, (current,))

    assert calls == ["first", "broken"]


def test_history_validator_chain_rejects_empty_non_tuple_and_non_validator_members() -> None:
    with pytest.raises(ValueError, match="must not be empty"):
        ChainedDurableCheckpointHistoryValidator(())
    with pytest.raises(TypeError, match="must be a tuple"):
        ChainedDurableCheckpointHistoryValidator([])  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="must implement"):
        ChainedDurableCheckpointHistoryValidator((object(),))  # type: ignore[arg-type]
