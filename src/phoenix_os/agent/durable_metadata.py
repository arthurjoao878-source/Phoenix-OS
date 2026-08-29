"""Optional metadata extension seams for RFC-0028 durable checkpoints."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Protocol, runtime_checkable

from phoenix_os.agent.contracts import AgentStepId
from phoenix_os.agent.durable_contracts import (
    CheckpointEnvelope,
    CheckpointId,
    CheckpointNextOperation,
    DurableRunStatus,
    ExecutionAttempt,
)
from phoenix_os.agent.errors import AgentCodecError, AgentStateConflictError


@runtime_checkable
class DurableCheckpointMetadataProjector(Protocol):
    """Project extension metadata for one already-authorized checkpoint transition."""

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
    ) -> Mapping[str, str]: ...


@runtime_checkable
class DurableCheckpointHistoryValidator(Protocol):
    """Validate extension invariants over one authoritative checkpoint history."""

    def validate_history(
        self,
        current: CheckpointEnvelope,
        history: tuple[CheckpointEnvelope, ...],
    ) -> None: ...


def project_durable_checkpoint_metadata(
    projector: DurableCheckpointMetadataProjector | None,
    current: CheckpointEnvelope,
    *,
    checkpoint_id: CheckpointId,
    status: DurableRunStatus,
    step_id: AgentStepId | None,
    next_operation: CheckpointNextOperation,
    active_attempt: ExecutionAttempt | None,
    metadata: Mapping[str, str],
) -> Mapping[str, str]:
    """Apply one optional server-owned projector and fail closed on invalid output."""

    if projector is None:
        return metadata
    try:
        projected = projector.project_metadata(
            current,
            checkpoint_id=checkpoint_id,
            status=status,
            step_id=step_id,
            next_operation=next_operation,
            active_attempt=active_attempt,
            metadata=metadata,
        )
    except AgentStateConflictError:
        raise
    except Exception as exception:
        raise AgentStateConflictError() from exception
    if not isinstance(projected, Mapping):
        raise AgentStateConflictError()
    normalized: dict[str, str] = {}
    for key, value in projected.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise AgentStateConflictError()
        normalized[key] = value
    return normalized


def validate_durable_checkpoint_history(
    validator: DurableCheckpointHistoryValidator | None,
    current: CheckpointEnvelope,
    history: tuple[CheckpointEnvelope, ...],
) -> None:
    """Run one optional extension validator after RFC-0028 validates the base chain."""

    if validator is None:
        return
    try:
        validator.validate_history(current, history)
    except AgentCodecError:
        raise
    except Exception as exception:
        raise AgentCodecError("durable checkpoint extension history is invalid") from exception
