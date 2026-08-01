"""Deterministic in-memory checkpoint store for durable agent runs."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime
from itertools import pairwise

from phoenix_os.agent.durable_codec import CanonicalCheckpointCodec
from phoenix_os.agent.durable_contracts import (
    MAX_RECOVERY_CANDIDATE_PAGE,
    CheckpointCodec,
    CheckpointEnvelope,
    CheckpointId,
    DurableAgentRunId,
    DurableLease,
    DurableRunLimits,
    DurableRunStore,
    DurableRunVersion,
)
from phoenix_os.agent.durable_lease import (
    DurableLeaseManager,
    InMemoryDurableLeaseManager,
)
from phoenix_os.agent.durable_payload import validate_protected_payload_for_checkpoint
from phoenix_os.agent.errors import (
    AgentCodecError,
    AgentLimitExceededError,
    AgentStateConflictError,
)


@dataclass(frozen=True, slots=True)
class _StoredRun:
    payloads: tuple[bytes, ...]
    checkpoint_ids: frozenset[CheckpointId]
    total_bytes: int
    protected_payloads: tuple[bytes | None, ...]


class InMemoryDurableRunStore(DurableRunStore):
    """Atomic per-run checkpoint history backed by canonical encoded bytes."""

    def __init__(
        self,
        *,
        codec: CheckpointCodec | None = None,
        limits: DurableRunLimits | None = None,
        lease_manager: DurableLeaseManager | None = None,
    ) -> None:
        selected_codec = CanonicalCheckpointCodec() if codec is None else codec
        selected_limits = DurableRunLimits() if limits is None else limits
        if not isinstance(selected_limits, DurableRunLimits):
            raise TypeError("limits must be DurableRunLimits")
        selected_lease_manager = (
            InMemoryDurableLeaseManager(limits=selected_limits)
            if lease_manager is None
            else lease_manager
        )
        if not isinstance(selected_lease_manager, DurableLeaseManager):
            raise TypeError("lease_manager must be DurableLeaseManager")
        self._codec = selected_codec
        self._limits = selected_limits
        self._lease_manager = selected_lease_manager
        self._owns_lease_manager = lease_manager is None
        self._runs: dict[DurableAgentRunId, _StoredRun] = {}
        self._closed = False
        self._lock = asyncio.Lock()

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def limits(self) -> DurableRunLimits:
        return self._limits

    @property
    def lease_manager(self) -> DurableLeaseManager:
        return self._lease_manager

    @property
    def run_count(self) -> int:
        return len(self._runs)

    async def create(self, checkpoint: CheckpointEnvelope) -> None:
        """Create one metadata-only run checkpoint."""

        await self._create(checkpoint, protected_payload=None)

    async def create_protected(
        self,
        checkpoint: CheckpointEnvelope,
        *,
        protected_payload: bytes,
    ) -> None:
        """Atomically create one run checkpoint and its protected ciphertext."""

        await self._create(checkpoint, protected_payload=protected_payload)

    async def _create(
        self,
        checkpoint: CheckpointEnvelope,
        *,
        protected_payload: bytes | None,
    ) -> None:
        encoded, decoded = self._prepare_checkpoint(checkpoint)
        protected = validate_protected_payload_for_checkpoint(
            decoded,
            protected_payload,
            limits=self._limits,
        )
        if decoded.sequence.value != 1:
            raise AgentStateConflictError()
        if decoded.run_version.value != 1:
            raise AgentStateConflictError()
        if decoded.previous_digest is not None:
            raise AgentStateConflictError()
        self._require_history_bounds(checkpoint_count=1, total_bytes=len(encoded))

        async with self._lock:
            self._ensure_open()
            if decoded.durable_run_id in self._runs:
                raise AgentStateConflictError()
            self._runs[decoded.durable_run_id] = _StoredRun(
                payloads=(encoded,),
                checkpoint_ids=frozenset({decoded.checkpoint_id}),
                total_bytes=len(encoded),
                protected_payloads=(protected,),
            )

    async def get_current(
        self,
        run_id: DurableAgentRunId,
    ) -> CheckpointEnvelope | None:
        """Read and validate the current checkpoint for one run."""

        self._require_run_id(run_id)
        async with self._lock:
            self._ensure_open()
            stored = self._runs.get(run_id)
            if stored is None:
                return None
            return self._decode_stored(stored.payloads[-1])

    async def list_history(
        self,
        run_id: DurableAgentRunId,
        *,
        limit: int,
    ) -> tuple[CheckpointEnvelope, ...]:
        """Return the newest bounded history segment in ascending sequence order."""

        self._require_run_id(run_id)
        self._require_history_limit(limit)
        async with self._lock:
            self._ensure_open()
            stored = self._runs.get(run_id)
            if stored is None:
                return ()
            payloads = stored.payloads[-limit:]
            checkpoints = tuple(self._decode_stored(payload) for payload in payloads)
            self._validate_history_segment(checkpoints)
            return checkpoints

    async def list_recovery_candidates(
        self,
        *,
        limit: int,
        after: DurableAgentRunId | None = None,
    ) -> tuple[DurableAgentRunId, ...]:
        """Return one deterministic bounded page of non-terminal run identifiers."""

        self._require_recovery_limit(limit)
        if after is not None:
            self._require_run_id(after)

        async with self._lock:
            self._ensure_open()
            candidates: list[DurableAgentRunId] = []
            for run_id in sorted(self._runs):
                if after is not None and run_id <= after:
                    continue
                current = self._decode_stored(self._runs[run_id].payloads[-1])
                if current.status.terminal:
                    continue
                candidates.append(run_id)
                if len(candidates) == limit:
                    break
            return tuple(candidates)

    async def append(
        self,
        checkpoint: CheckpointEnvelope,
        *,
        expected_version: DurableRunVersion,
        lease: DurableLease,
        now: datetime,
    ) -> CheckpointEnvelope:
        """Append one metadata-only checkpoint under current fenced lease authority."""

        return await self._append(
            checkpoint,
            expected_version=expected_version,
            lease=lease,
            now=now,
            protected_payload=None,
        )

    async def append_protected(
        self,
        checkpoint: CheckpointEnvelope,
        *,
        expected_version: DurableRunVersion,
        lease: DurableLease,
        now: datetime,
        protected_payload: bytes,
    ) -> CheckpointEnvelope:
        """Atomically append one checkpoint and its protected ciphertext."""

        return await self._append(
            checkpoint,
            expected_version=expected_version,
            lease=lease,
            now=now,
            protected_payload=protected_payload,
        )

    async def _append(
        self,
        checkpoint: CheckpointEnvelope,
        *,
        expected_version: DurableRunVersion,
        lease: DurableLease,
        now: datetime,
        protected_payload: bytes | None,
    ) -> CheckpointEnvelope:
        if not isinstance(expected_version, DurableRunVersion):
            raise TypeError("expected_version must be DurableRunVersion")
        if not isinstance(lease, DurableLease):
            raise TypeError("lease must be DurableLease")
        encoded, decoded = self._prepare_checkpoint(checkpoint)
        protected = validate_protected_payload_for_checkpoint(
            decoded,
            protected_payload,
            limits=self._limits,
        )
        if lease.run_id != decoded.durable_run_id:
            raise AgentStateConflictError()

        async with self._lease_manager.guard_current(lease, now=now):
            async with self._lock:
                self._ensure_open()
                stored = self._runs.get(decoded.durable_run_id)
                if stored is None:
                    raise AgentStateConflictError()

                current = self._decode_stored(stored.payloads[-1])
                self._validate_append(
                    current=current,
                    candidate=decoded,
                    expected_version=expected_version,
                    checkpoint_ids=stored.checkpoint_ids,
                )

                next_count = len(stored.payloads) + 1
                next_total_bytes = stored.total_bytes + len(encoded)
                self._require_history_bounds(
                    checkpoint_count=next_count,
                    total_bytes=next_total_bytes,
                )

                self._runs[decoded.durable_run_id] = _StoredRun(
                    payloads=(*stored.payloads, encoded),
                    checkpoint_ids=stored.checkpoint_ids | {decoded.checkpoint_id},
                    total_bytes=next_total_bytes,
                    protected_payloads=(*stored.protected_payloads, protected),
                )
                return decoded

    async def get_protected_payload(
        self,
        checkpoint: CheckpointEnvelope,
        *,
        lease: DurableLease,
        now: datetime,
    ) -> bytes:
        """Read current ciphertext only under the exact current fenced lease."""

        _, decoded = self._prepare_checkpoint(checkpoint)
        if not isinstance(lease, DurableLease):
            raise TypeError("lease must be DurableLease")
        if lease.run_id != decoded.durable_run_id:
            raise AgentStateConflictError()

        async with self._lease_manager.guard_current(lease, now=now):
            async with self._lock:
                self._ensure_open()
                stored = self._runs.get(decoded.durable_run_id)
                if stored is None:
                    raise AgentStateConflictError()
                if len(stored.protected_payloads) != len(stored.payloads):
                    raise AgentCodecError("stored protected payload history is inconsistent")
                current = self._decode_stored(stored.payloads[-1])
                if current != decoded:
                    raise AgentStateConflictError()
                protected = validate_protected_payload_for_checkpoint(
                    decoded,
                    stored.protected_payloads[-1],
                    limits=self._limits,
                )
                if protected is None:
                    raise AgentStateConflictError()
                return protected

    async def close(self) -> None:
        """Close the adapter without mutating retained in-memory history."""

        async with self._lock:
            self._closed = True
        if self._owns_lease_manager:
            await self._lease_manager.close()

    def _prepare_checkpoint(
        self,
        checkpoint: CheckpointEnvelope,
    ) -> tuple[bytes, CheckpointEnvelope]:
        if not isinstance(checkpoint, CheckpointEnvelope):
            raise TypeError("checkpoint must be CheckpointEnvelope")
        computed_digest = self._codec.digest(checkpoint)
        if computed_digest != checkpoint.digest:
            raise AgentCodecError("checkpoint digest does not match canonical content")
        encoded = self._codec.encode(checkpoint)
        if not isinstance(encoded, bytes):
            raise TypeError("checkpoint codec must return bytes")
        if len(encoded) > self._limits.max_checkpoint_envelope_bytes:
            raise AgentLimitExceededError()
        decoded = self._codec.decode(encoded)
        if not isinstance(decoded, CheckpointEnvelope):
            raise TypeError("checkpoint codec must decode CheckpointEnvelope")
        if decoded != checkpoint:
            raise AgentCodecError("checkpoint codec round-trip changed the checkpoint")
        return encoded, decoded

    def _decode_stored(self, payload: bytes) -> CheckpointEnvelope:
        if len(payload) > self._limits.max_checkpoint_envelope_bytes:
            raise AgentCodecError("stored checkpoint exceeds the configured bound")
        decoded = self._codec.decode(payload)
        if not isinstance(decoded, CheckpointEnvelope):
            raise AgentCodecError("stored checkpoint decoded to an invalid type")
        if self._codec.digest(decoded) != decoded.digest:
            raise AgentCodecError("stored checkpoint digest is invalid")
        return decoded

    def _validate_append(
        self,
        *,
        current: CheckpointEnvelope,
        candidate: CheckpointEnvelope,
        expected_version: DurableRunVersion,
        checkpoint_ids: frozenset[CheckpointId],
    ) -> None:
        if current.status.terminal:
            raise AgentStateConflictError()
        if expected_version != current.run_version:
            raise AgentStateConflictError()
        if candidate.durable_run_id != current.durable_run_id:
            raise AgentStateConflictError()
        if candidate.agent_run_id != current.agent_run_id:
            raise AgentStateConflictError()
        if candidate.schema_version != current.schema_version:
            raise AgentStateConflictError()

        self._validate_immutable_run_metadata(
            current=current,
            candidate=candidate,
        )
        self._validate_budget_progression(
            current=current,
            candidate=candidate,
        )

        if candidate.checkpoint_id in checkpoint_ids:
            raise AgentStateConflictError()
        if current.sequence.value >= self._limits.max_checkpoints:
            raise AgentLimitExceededError()
        if candidate.sequence.value != current.sequence.value + 1:
            raise AgentStateConflictError()
        if candidate.run_version.value != current.run_version.value + 1:
            raise AgentStateConflictError()
        if candidate.previous_digest != current.digest:
            raise AgentStateConflictError()
        if candidate.created_at < current.created_at:
            raise AgentStateConflictError()

    @staticmethod
    def _validate_immutable_run_metadata(
        *,
        current: CheckpointEnvelope,
        candidate: CheckpointEnvelope,
    ) -> None:
        current_metadata = current.metadata
        candidate_metadata = candidate.metadata
        if candidate_metadata.agent_id != current_metadata.agent_id:
            raise AgentStateConflictError()
        if candidate_metadata.actor_id != current_metadata.actor_id:
            raise AgentStateConflictError()
        if candidate_metadata.payload_profile is not current_metadata.payload_profile:
            raise AgentStateConflictError()
        if candidate_metadata.budget.started_at != current_metadata.budget.started_at:
            raise AgentStateConflictError()
        if candidate_metadata.budget.deadline != current_metadata.budget.deadline:
            raise AgentStateConflictError()
        if candidate_metadata.retention_deadline != current_metadata.retention_deadline:
            raise AgentStateConflictError()

    @staticmethod
    def _validate_budget_progression(
        *,
        current: CheckpointEnvelope,
        candidate: CheckpointEnvelope,
    ) -> None:
        current_budget = current.metadata.budget
        candidate_budget = candidate.metadata.budget
        current_counters = (
            current_budget.steps,
            current_budget.model_turns,
            current_budget.tool_calls,
            current_budget.model_output_bytes,
            current_budget.tool_result_bytes,
            current_budget.input_tokens,
            current_budget.output_tokens,
        )
        candidate_counters = (
            candidate_budget.steps,
            candidate_budget.model_turns,
            candidate_budget.tool_calls,
            candidate_budget.model_output_bytes,
            candidate_budget.tool_result_bytes,
            candidate_budget.input_tokens,
            candidate_budget.output_tokens,
        )
        if any(
            candidate_value < current_value
            for current_value, candidate_value in zip(
                current_counters,
                candidate_counters,
                strict=True,
            )
        ):
            raise AgentStateConflictError()

    def _require_history_bounds(
        self,
        *,
        checkpoint_count: int,
        total_bytes: int,
    ) -> None:
        if checkpoint_count > self._limits.max_checkpoints:
            raise AgentLimitExceededError()
        if total_bytes > self._limits.max_checkpoint_history_bytes:
            raise AgentLimitExceededError()

    def _require_history_limit(self, limit: int) -> None:
        if isinstance(limit, bool) or not isinstance(limit, int):
            raise TypeError("limit must be an integer")
        if limit <= 0:
            raise ValueError("limit must be greater than zero")
        if limit > self._limits.max_checkpoints:
            raise AgentLimitExceededError()

    @staticmethod
    def _require_recovery_limit(limit: int) -> None:
        if isinstance(limit, bool) or not isinstance(limit, int):
            raise TypeError("limit must be an integer")
        if limit <= 0:
            raise ValueError("limit must be greater than zero")
        if limit > MAX_RECOVERY_CANDIDATE_PAGE:
            raise AgentLimitExceededError()

    @staticmethod
    def _require_run_id(run_id: DurableAgentRunId) -> None:
        if not isinstance(run_id, DurableAgentRunId):
            raise TypeError("run_id must be DurableAgentRunId")

    @staticmethod
    def _validate_history_segment(
        checkpoints: tuple[CheckpointEnvelope, ...],
    ) -> None:
        for previous, current in pairwise(checkpoints):
            if current.durable_run_id != previous.durable_run_id:
                raise AgentCodecError("stored checkpoint history changed run identity")
            if current.sequence.value != previous.sequence.value + 1:
                raise AgentCodecError("stored checkpoint history has a sequence gap")
            if current.run_version.value != previous.run_version.value + 1:
                raise AgentCodecError("stored checkpoint history has a version gap")
            if current.previous_digest != previous.digest:
                raise AgentCodecError("stored checkpoint history has a broken digest chain")

    def _ensure_open(self) -> None:
        if self._closed:
            raise RuntimeError("durable run store is closed")
