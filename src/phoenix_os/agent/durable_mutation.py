"""Exact durable checkpoint mutation outcome resolution for RFC-0037."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from phoenix_os.agent.durable_contracts import (
    CheckpointEnvelope,
    DurableLease,
    DurableRunStore,
)
from phoenix_os.agent.durable_reliability import DurableMutationOutcome
from phoenix_os.agent.errors import AgentServiceUnavailableError, AgentStateConflictError


@dataclass(frozen=True, slots=True)
class DurableCheckpointMutationResolution:
    """Content-free authoritative result of one attempted checkpoint append."""

    outcome: DurableMutationOutcome
    authoritative: CheckpointEnvelope | None
    append_acknowledged: bool

    def __post_init__(self) -> None:
        if not isinstance(self.outcome, DurableMutationOutcome):
            raise TypeError("outcome must be DurableMutationOutcome")
        if self.authoritative is not None and not isinstance(
            self.authoritative,
            CheckpointEnvelope,
        ):
            raise TypeError("authoritative must be CheckpointEnvelope or None")
        if type(self.append_acknowledged) is not bool:
            raise TypeError("append_acknowledged must be bool")
        if (
            self.outcome
            in {
                DurableMutationOutcome.CONFIRMED_COMMITTED,
                DurableMutationOutcome.CONFIRMED_NOT_COMMITTED,
            }
            and self.authoritative is None
        ):
            raise ValueError("confirmed mutation outcome requires authoritative state")


def classify_durable_checkpoint_mutation(
    current: CheckpointEnvelope,
    intended: CheckpointEnvelope,
    authoritative: CheckpointEnvelope | None,
) -> DurableMutationOutcome:
    """Classify one mutation only from an exact authoritative durable re-read."""

    if not isinstance(current, CheckpointEnvelope):
        raise TypeError("current must be CheckpointEnvelope")
    if not isinstance(intended, CheckpointEnvelope):
        raise TypeError("intended must be CheckpointEnvelope")
    if authoritative is not None and not isinstance(authoritative, CheckpointEnvelope):
        raise TypeError("authoritative must be CheckpointEnvelope or None")

    _require_exact_successor(current, intended)

    if authoritative == intended:
        return DurableMutationOutcome.CONFIRMED_COMMITTED
    if authoritative == current:
        return DurableMutationOutcome.CONFIRMED_NOT_COMMITTED
    return DurableMutationOutcome.COMMIT_OUTCOME_UNKNOWN


async def resolve_durable_checkpoint_append(
    store: DurableRunStore,
    *,
    current: CheckpointEnvelope,
    intended: CheckpointEnvelope,
    lease: DurableLease,
    now: datetime,
) -> DurableCheckpointMutationResolution:
    """Attempt once, then always re-read; never infer commit state from the call result."""

    if not isinstance(store, DurableRunStore):
        raise TypeError("store must implement DurableRunStore")
    if not isinstance(lease, DurableLease):
        raise TypeError("lease must be DurableLease")
    _require_timezone_aware(now, label="now")
    _require_exact_successor(current, intended)
    if lease.run_id != current.durable_run_id:
        raise AgentStateConflictError()

    try:
        await store.append(
            intended,
            expected_version=current.run_version,
            lease=lease,
            now=now,
        )
    except Exception:
        append_acknowledged = False
    else:
        append_acknowledged = True

    try:
        authoritative = await store.get_current(current.durable_run_id)
    except Exception:
        return DurableCheckpointMutationResolution(
            outcome=DurableMutationOutcome.COMMIT_OUTCOME_UNKNOWN,
            authoritative=None,
            append_acknowledged=append_acknowledged,
        )

    outcome = classify_durable_checkpoint_mutation(
        current,
        intended,
        authoritative,
    )
    return DurableCheckpointMutationResolution(
        outcome=outcome,
        authoritative=authoritative,
        append_acknowledged=append_acknowledged,
    )


async def append_durable_checkpoint_confirmed(
    store: DurableRunStore,
    *,
    current: CheckpointEnvelope,
    intended: CheckpointEnvelope,
    lease: DurableLease,
    now: datetime,
) -> CheckpointEnvelope:
    """Return only an exactly re-read committed checkpoint; otherwise fail closed."""

    resolution = await resolve_durable_checkpoint_append(
        store,
        current=current,
        intended=intended,
        lease=lease,
        now=now,
    )
    if resolution.outcome is DurableMutationOutcome.CONFIRMED_COMMITTED:
        authoritative = resolution.authoritative
        if authoritative is None:
            raise AgentServiceUnavailableError()
        return authoritative
    if resolution.outcome is DurableMutationOutcome.CONFIRMED_NOT_COMMITTED:
        raise AgentStateConflictError()
    if resolution.authoritative is None:
        raise AgentServiceUnavailableError()
    raise AgentStateConflictError()


def _require_exact_successor(
    current: CheckpointEnvelope,
    intended: CheckpointEnvelope,
) -> None:
    if not isinstance(current, CheckpointEnvelope):
        raise TypeError("current must be CheckpointEnvelope")
    if not isinstance(intended, CheckpointEnvelope):
        raise TypeError("intended must be CheckpointEnvelope")
    if (
        intended.durable_run_id != current.durable_run_id
        or intended.agent_run_id != current.agent_run_id
        or intended.schema_version != current.schema_version
        or intended.checkpoint_id == current.checkpoint_id
        or intended.sequence.value != current.sequence.value + 1
        or intended.run_version.value != current.run_version.value + 1
        or intended.previous_digest != current.digest
        or intended.created_at < current.created_at
    ):
        raise AgentStateConflictError()


def _require_timezone_aware(value: datetime, *, label: str) -> None:
    if not isinstance(value, datetime):
        raise TypeError(f"{label} must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")
