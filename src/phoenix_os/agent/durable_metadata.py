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


class ChainedDurableCheckpointMetadataProjector:
    """Apply multiple durable metadata projectors in one deterministic fail-closed chain."""

    def __init__(
        self,
        projectors: tuple[DurableCheckpointMetadataProjector, ...],
    ) -> None:
        if not isinstance(projectors, tuple):
            raise TypeError("projectors must be a tuple")
        if not projectors:
            raise ValueError("projectors must not be empty")
        if any(
            not isinstance(projector, DurableCheckpointMetadataProjector)
            for projector in projectors
        ):
            raise TypeError("projectors must implement DurableCheckpointMetadataProjector")
        self._projectors = projectors

    @property
    def projectors(self) -> tuple[DurableCheckpointMetadataProjector, ...]:
        return self._projectors

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
        if not isinstance(metadata, Mapping):
            raise TypeError("metadata must be a mapping")
        projected: Mapping[str, str] = dict(metadata)
        for projector in self._projectors:
            projected = project_durable_checkpoint_metadata(
                projector,
                current,
                checkpoint_id=checkpoint_id,
                status=status,
                step_id=step_id,
                next_operation=next_operation,
                active_attempt=active_attempt,
                metadata=projected,
            )
        return projected


class ChainedDurableCheckpointHistoryValidator:
    """Run multiple durable history validators in one deterministic fail-closed chain."""

    def __init__(
        self,
        validators: tuple[DurableCheckpointHistoryValidator, ...],
    ) -> None:
        if not isinstance(validators, tuple):
            raise TypeError("validators must be a tuple")
        if not validators:
            raise ValueError("validators must not be empty")
        if any(
            not isinstance(validator, DurableCheckpointHistoryValidator) for validator in validators
        ):
            raise TypeError("validators must implement DurableCheckpointHistoryValidator")
        self._validators = validators

    @property
    def validators(self) -> tuple[DurableCheckpointHistoryValidator, ...]:
        return self._validators

    def validate_history(
        self,
        current: CheckpointEnvelope,
        history: tuple[CheckpointEnvelope, ...],
    ) -> None:
        for validator in self._validators:
            validate_durable_checkpoint_history(validator, current, history)
