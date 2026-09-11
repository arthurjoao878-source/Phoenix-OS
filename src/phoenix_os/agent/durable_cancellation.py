"""Fenced durable-run cancellation without claiming uncertain external effects."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import replace
from datetime import datetime
from typing import Protocol, runtime_checkable
from uuid import UUID, uuid4

from phoenix_os.agent.durable_authorization import DurableCancellationAuthorizer
from phoenix_os.agent.durable_codec import seal_checkpoint_envelope
from phoenix_os.agent.durable_contracts import (
    CheckpointDigest,
    CheckpointEnvelope,
    CheckpointId,
    CheckpointNextOperation,
    DurableCancellationRequest,
    DurableLease,
    DurableRunStatus,
    DurableRunStore,
    ExecutionAttempt,
    ExecutionAttemptKind,
    ExecutionAttemptStatus,
    IndeterminateReason,
)
from phoenix_os.agent.durable_lease import DurableLeaseManager
from phoenix_os.agent.durable_metadata import (
    DurableCheckpointMetadataProjector,
    project_durable_checkpoint_metadata,
)
from phoenix_os.agent.durable_mutation import append_durable_checkpoint_confirmed
from phoenix_os.agent.errors import AgentStateConflictError
from phoenix_os.policy import SecurityContext

_CANCELLATION_PREFIX = "cancellation."
_CANCELLATION_SCHEMA_KEY = "cancellation.schema"
_CANCELLATION_SCHEMA_VERSION = "1"
_CANCELLATION_KEYS = frozenset(
    {
        _CANCELLATION_SCHEMA_KEY,
        "cancellation.id",
        "cancellation.run_id",
        "cancellation.source_checkpoint_id",
        "cancellation.source_checkpoint_digest",
        "cancellation.source_version",
        "cancellation.source_status",
        "cancellation.actor_id",
        "cancellation.generation",
        "cancellation.requested_at",
        "cancellation.applied_at",
        "cancellation.result_status",
        "cancellation.result_attempt_status",
    }
)
_SAFE_ACTOR_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,127})$")


def _require_timezone_aware(value: datetime, *, label: str) -> None:
    if not isinstance(value, datetime):
        raise TypeError(f"{label} must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")


@runtime_checkable
class DurableCancellationCoordinator(Protocol):
    """Apply one authorized cancellation under caller-owned fenced lease authority."""

    async def cancel(
        self,
        request: DurableCancellationRequest,
        *,
        lease: DurableLease,
        context: SecurityContext,
        now: datetime,
    ) -> CheckpointEnvelope: ...


class StoreBackedDurableCancellationCoordinator:
    """Persist RFC-0028 cancellation without turning uncertainty into false success."""

    def __init__(
        self,
        *,
        store: DurableRunStore,
        lease_manager: DurableLeaseManager,
        authorizer: DurableCancellationAuthorizer,
        metadata_projector: DurableCheckpointMetadataProjector | None = None,
    ) -> None:
        if not isinstance(store, DurableRunStore):
            raise TypeError("store must implement DurableRunStore")
        if not isinstance(lease_manager, DurableLeaseManager):
            raise TypeError("lease_manager must implement DurableLeaseManager")
        if not isinstance(authorizer, DurableCancellationAuthorizer):
            raise TypeError("authorizer must implement DurableCancellationAuthorizer")
        if metadata_projector is not None and not isinstance(
            metadata_projector,
            DurableCheckpointMetadataProjector,
        ):
            raise TypeError("metadata_projector must implement DurableCheckpointMetadataProjector")
        bound_lease_manager = getattr(store, "lease_manager", None)
        if bound_lease_manager is not None and bound_lease_manager is not lease_manager:
            raise ValueError("lease_manager must match the durable store lease manager")
        self._store = store
        self._lease_manager = lease_manager
        self._authorizer = authorizer
        self._metadata_projector = metadata_projector

    async def cancel(
        self,
        request: DurableCancellationRequest,
        *,
        lease: DurableLease,
        context: SecurityContext,
        now: datetime,
    ) -> CheckpointEnvelope:
        if not isinstance(request, DurableCancellationRequest):
            raise TypeError("request must be DurableCancellationRequest")
        if not isinstance(lease, DurableLease):
            raise TypeError("lease must be DurableLease")
        if not isinstance(context, SecurityContext):
            raise TypeError("context must be SecurityContext")
        _require_timezone_aware(now, label="now")
        if now < request.requested_at:
            raise AgentStateConflictError()

        await self._lease_manager.require_current(lease, now=now)
        current = await self._store.get_current(request.run_id)
        if current is None:
            raise AgentStateConflictError()
        _require_exact_request_source(request, current=current, lease=lease, now=now)

        await self._authorizer.authorize(request, current, lease, context)
        await self._lease_manager.require_current(lease, now=now)

        if current.status is DurableRunStatus.CANCELLED:
            return current
        if current.status.terminal:
            raise AgentStateConflictError()

        existing = _cancellation_metadata_state(current)
        if existing is False:
            raise AgentStateConflictError()
        if existing is True:
            if current.status.indeterminate:
                return current
            raise AgentStateConflictError()

        result_status, result_attempt = _cancellation_result(current, now=now)
        next_operation = (
            CheckpointNextOperation.OPERATOR_REVIEW
            if result_status.indeterminate
            else CheckpointNextOperation.NONE
        )
        return await self._append(
            current,
            request=request,
            lease=lease,
            status=result_status,
            next_operation=next_operation,
            attempt=result_attempt,
            now=now,
        )

    async def _append(
        self,
        current: CheckpointEnvelope,
        *,
        request: DurableCancellationRequest,
        lease: DurableLease,
        status: DurableRunStatus,
        next_operation: CheckpointNextOperation,
        attempt: ExecutionAttempt | None,
        now: datetime,
    ) -> CheckpointEnvelope:
        checkpoint_id = CheckpointId()
        metadata_values: Mapping[str, str] = _metadata_with_cancellation(
            current,
            request=request,
            status=status,
            attempt=attempt,
            now=now,
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
        try:
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
        return await append_durable_checkpoint_confirmed(
            self._store,
            current=current,
            intended=candidate,
            lease=lease,
            now=now,
        )


def durable_cancellation_requested(checkpoint: CheckpointEnvelope) -> bool:
    """Return whether this checkpoint carries a valid Phoenix cancellation record."""

    if not isinstance(checkpoint, CheckpointEnvelope):
        raise TypeError("checkpoint must be CheckpointEnvelope")
    return _cancellation_metadata_state(checkpoint) is True


def _require_exact_request_source(
    request: DurableCancellationRequest,
    *,
    current: CheckpointEnvelope,
    lease: DurableLease,
    now: datetime,
) -> None:
    if (
        request.run_id != current.durable_run_id
        or request.expected_version != current.run_version
        or request.generation != lease.generation
        or lease.run_id != request.run_id
        or not lease.active_at(request.requested_at)
        or not lease.active_at(now)
        or request.requested_at < current.created_at
        or request.requested_at >= current.metadata.retention_deadline
        or now >= current.metadata.retention_deadline
    ):
        raise AgentStateConflictError()


def _cancellation_result(
    current: CheckpointEnvelope,
    *,
    now: datetime,
) -> tuple[DurableRunStatus, ExecutionAttempt | None]:
    attempt = current.metadata.active_attempt
    if current.status.indeterminate:
        if attempt is None or attempt.status is not ExecutionAttemptStatus.INDETERMINATE:
            raise AgentStateConflictError()
        expected_kind = (
            ExecutionAttemptKind.MODEL_TURN
            if current.status is DurableRunStatus.INDETERMINATE_MODEL
            else ExecutionAttemptKind.TOOL_INVOCATION
        )
        if attempt.kind is not expected_kind:
            raise AgentStateConflictError()
        return current.status, attempt

    if attempt is None:
        return DurableRunStatus.CANCELLED, None

    if attempt.status is ExecutionAttemptStatus.INDETERMINATE:
        raise AgentStateConflictError()

    if attempt.status is ExecutionAttemptStatus.STARTED:
        reason = (
            IndeterminateReason.PROVIDER_STATUS_UNKNOWN
            if attempt.kind is ExecutionAttemptKind.MODEL_TURN
            else IndeterminateReason.TOOL_STATUS_UNKNOWN
        )
        status = (
            DurableRunStatus.INDETERMINATE_MODEL
            if attempt.kind is ExecutionAttemptKind.MODEL_TURN
            else DurableRunStatus.INDETERMINATE_TOOL
        )
        return (
            status,
            replace(
                attempt,
                status=ExecutionAttemptStatus.INDETERMINATE,
                completed_at=now,
                indeterminate_reason=reason,
                error_code=None,
            ),
        )

    return DurableRunStatus.CANCELLED, None


def _metadata_with_cancellation(
    current: CheckpointEnvelope,
    *,
    request: DurableCancellationRequest,
    status: DurableRunStatus,
    attempt: ExecutionAttempt | None,
    now: datetime,
) -> Mapping[str, str]:
    values = dict(current.metadata.metadata)
    if any(key.startswith(_CANCELLATION_PREFIX) for key in values):
        raise AgentStateConflictError()
    actor = request.actor_id
    if _SAFE_ACTOR_PATTERN.fullmatch(actor) is None:
        raise AgentStateConflictError()
    values.update(
        {
            _CANCELLATION_SCHEMA_KEY: _CANCELLATION_SCHEMA_VERSION,
            "cancellation.id": str(uuid4()),
            "cancellation.run_id": str(current.durable_run_id),
            "cancellation.source_checkpoint_id": str(current.checkpoint_id),
            "cancellation.source_checkpoint_digest": str(current.digest),
            "cancellation.source_version": str(current.run_version.value),
            "cancellation.source_status": current.status.value,
            "cancellation.actor_id": actor,
            "cancellation.generation": str(request.generation.value),
            "cancellation.requested_at": request.requested_at.isoformat(),
            "cancellation.applied_at": now.isoformat(),
            "cancellation.result_status": status.value,
            "cancellation.result_attempt_status": (
                attempt.status.value if attempt is not None else "none"
            ),
        }
    )
    return values


def _cancellation_metadata_state(checkpoint: CheckpointEnvelope) -> bool | None:
    metadata = checkpoint.metadata.metadata
    prefixed = {key for key in metadata if key.startswith(_CANCELLATION_PREFIX)}
    if not prefixed:
        return None
    if prefixed != _CANCELLATION_KEYS:
        return False
    if metadata.get(_CANCELLATION_SCHEMA_KEY) != _CANCELLATION_SCHEMA_VERSION:
        return False
    if metadata.get("cancellation.run_id") != str(checkpoint.durable_run_id):
        return False
    if metadata.get("cancellation.result_status") != checkpoint.status.value:
        return False
    if metadata.get("cancellation.result_attempt_status") != (
        checkpoint.metadata.active_attempt.status.value
        if checkpoint.metadata.active_attempt is not None
        else "none"
    ):
        return False
    try:
        UUID(metadata["cancellation.id"])
        UUID(metadata["cancellation.source_checkpoint_id"])
        int(metadata["cancellation.source_version"])
        int(metadata["cancellation.generation"])
        requested_at = datetime.fromisoformat(metadata["cancellation.requested_at"])
        applied_at = datetime.fromisoformat(metadata["cancellation.applied_at"])
    except (KeyError, TypeError, ValueError):
        return False
    if (
        requested_at.tzinfo is None
        or requested_at.utcoffset() is None
        or applied_at.tzinfo is None
        or applied_at.utcoffset() is None
        or applied_at < requested_at
    ):
        return False
    return True
