from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from phoenix_os.agent.contracts import AgentId, AgentRunId, AgentStepId
from phoenix_os.agent.durable_codec import seal_checkpoint_envelope
from phoenix_os.agent.durable_contracts import (
    MAX_RECOVERY_CANDIDATE_PAGE,
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
    DurableRunLimits,
    DurableRunStatus,
    DurableRunVersion,
    ProtectedPayloadReference,
    RetentionPolicy,
)
from phoenix_os.agent.durable_fake import DeterministicCheckpointProtector
from phoenix_os.agent.durable_memory import InMemoryDurableRunStore
from phoenix_os.agent.durable_retention import DurableRetentionStore
from phoenix_os.agent.durable_retention_worker import BoundedDurableRetentionWorker
from phoenix_os.agent.errors import (
    AgentLimitExceededError,
    AgentStateConflictError,
)
from phoenix_os.agent.state import AgentBudgetSnapshot

NOW = datetime(2026, 8, 2, 12, tzinfo=UTC)
AGENT_RUN_ID = AgentRunId(UUID("20000000-0000-0000-0000-000000000002"))
STEP_ID = AgentStepId(UUID("30000000-0000-0000-0000-000000000003"))
SECRET = b"0123456789abcdef0123456789abcdef"

POLICY = RetentionPolicy(
    payload_retention=timedelta(seconds=10),
    metadata_retention=timedelta(seconds=20),
    tombstone_retention=timedelta(seconds=30),
)


def _digest(character: str) -> CheckpointDigest:
    return CheckpointDigest(character * 64)


def _limits() -> DurableRunLimits:
    return replace(
        DurableRunLimits(),
        lease_duration=timedelta(minutes=5),
        lease_renewal_interval=timedelta(minutes=1),
    )


def _compatibility(*, protected: bool) -> CompatibilityDigests:
    return CompatibilityDigests(
        configuration=_digest("a"),
        tool_registry=_digest("b"),
        model_provider=_digest("c"),
        checkpoint_codec=_digest("d"),
        payload_codec=_digest("e") if protected else None,
    )


def _budget(*, steps: int) -> AgentBudgetSnapshot:
    return AgentBudgetSnapshot(
        steps=steps,
        model_turns=steps,
        tool_calls=0,
        model_output_bytes=0,
        tool_result_bytes=0,
        input_tokens=0,
        output_tokens=0,
        started_at=NOW,
        deadline=NOW + timedelta(hours=2),
    )


def _checkpoint(
    run_id: DurableAgentRunId,
    sequence: int,
    *,
    previous_digest: CheckpointDigest | None = None,
    status: DurableRunStatus = DurableRunStatus.ACTIVE,
    next_operation: CheckpointNextOperation = CheckpointNextOperation.MODEL_TURN,
    created_at: datetime | None = None,
    retention_deadline: datetime | None = None,
    payload_profile: CheckpointPayloadProfile = CheckpointPayloadProfile.METADATA_ONLY,
    payload_reference: ProtectedPayloadReference | None = None,
) -> CheckpointEnvelope:
    protected = payload_profile is CheckpointPayloadProfile.PROTECTED_CONTENT
    return seal_checkpoint_envelope(
        CheckpointEnvelope(
            schema_version=CheckpointSchemaVersion(),
            durable_run_id=run_id,
            checkpoint_id=CheckpointId(UUID(int=10_000 + sequence)),
            sequence=CheckpointSequence(sequence),
            previous_digest=previous_digest,
            run_version=DurableRunVersion(sequence),
            status=status,
            agent_run_id=AGENT_RUN_ID,
            step_id=STEP_ID,
            metadata=CheckpointMetadata(
                agent_id=AgentId("assistant"),
                actor_id="worker-1",
                next_operation=next_operation,
                budget=_budget(steps=sequence - 1),
                compatibility=_compatibility(protected=protected),
                payload_profile=payload_profile,
                retention_deadline=(
                    NOW + timedelta(hours=1) if retention_deadline is None else retention_deadline
                ),
                payload_reference=payload_reference,
                metadata={"tenant": "demo"},
            ),
            created_at=(NOW + timedelta(seconds=sequence) if created_at is None else created_at),
            digest=_digest("0"),
        )
    )


def _protector() -> DeterministicCheckpointProtector:
    return DeterministicCheckpointProtector(
        SECRET,
        protector_id="retention-test-protector",
        key_version="payload-key-v1",
        clock=lambda: NOW,
    )


def _protected_checkpoint(
    run_id: DurableAgentRunId,
    sequence: int,
    plaintext: bytes,
    *,
    previous_digest: CheckpointDigest | None = None,
    status: DurableRunStatus = DurableRunStatus.ACTIVE,
    next_operation: CheckpointNextOperation = CheckpointNextOperation.MODEL_TURN,
    created_at: datetime | None = None,
) -> tuple[CheckpointEnvelope, bytes]:
    unprotected = _checkpoint(
        run_id,
        sequence,
        previous_digest=previous_digest,
        status=status,
        next_operation=next_operation,
        created_at=created_at,
        payload_profile=CheckpointPayloadProfile.PROTECTED_CONTENT,
    )
    reference, ciphertext = _protector().protect(
        run_id=unprotected.durable_run_id,
        checkpoint_id=unprotected.checkpoint_id,
        sequence=unprotected.sequence,
        schema_version=unprotected.schema_version,
        profile=unprotected.metadata.payload_profile,
        plaintext=plaintext,
    )
    checkpoint = seal_checkpoint_envelope(
        replace(
            unprotected,
            metadata=replace(
                unprotected.metadata,
                payload_reference=reference,
            ),
        )
    )
    return checkpoint, ciphertext


async def _terminal_metadata_run(
    store: InMemoryDurableRunStore,
    run_id: DurableAgentRunId,
) -> tuple[CheckpointEnvelope, DurableLease]:
    first = _checkpoint(
        run_id,
        1,
        created_at=NOW + timedelta(seconds=1),
    )
    terminal = _checkpoint(
        run_id,
        2,
        previous_digest=first.digest,
        status=DurableRunStatus.FAILED,
        next_operation=CheckpointNextOperation.NONE,
        created_at=NOW + timedelta(seconds=4),
    )
    await store.create(first)
    lease = await store.lease_manager.acquire(
        run_id,
        owner_id="cleanup-test",
        now=NOW + timedelta(seconds=2),
    )
    await store.append(
        terminal,
        expected_version=first.run_version,
        lease=lease,
        now=NOW + timedelta(seconds=5),
    )
    return terminal, lease


async def _terminal_protected_run(
    store: InMemoryDurableRunStore,
    run_id: DurableAgentRunId,
) -> tuple[CheckpointEnvelope, DurableLease]:
    first, first_ciphertext = _protected_checkpoint(
        run_id,
        1,
        b"first protected payload",
        created_at=NOW + timedelta(seconds=1),
    )
    terminal, terminal_ciphertext = _protected_checkpoint(
        run_id,
        2,
        b"terminal protected payload",
        previous_digest=first.digest,
        status=DurableRunStatus.FAILED,
        next_operation=CheckpointNextOperation.NONE,
        created_at=NOW + timedelta(seconds=4),
    )
    await store.create_protected(
        first,
        protected_payload=first_ciphertext,
    )
    lease = await store.lease_manager.acquire(
        run_id,
        owner_id="cleanup-test",
        now=NOW + timedelta(seconds=2),
    )
    await store.append_protected(
        terminal,
        expected_version=first.run_version,
        lease=lease,
        now=NOW + timedelta(seconds=5),
        protected_payload=terminal_ciphertext,
    )
    return terminal, lease


async def test_memory_store_implements_retention_capability() -> None:
    store = InMemoryDurableRunStore(limits=_limits())

    assert isinstance(store, DurableRetentionStore)


async def test_nonterminal_expired_run_is_never_cleanup_candidate() -> None:
    run_id = DurableAgentRunId(UUID(int=101))
    store = InMemoryDurableRunStore(limits=_limits())
    active = _checkpoint(
        run_id,
        1,
        created_at=NOW + timedelta(seconds=1),
        retention_deadline=NOW + timedelta(seconds=6),
    )
    await store.create(active)

    candidates = await store.list_cleanup_candidates(
        policy=POLICY,
        now=NOW + timedelta(minutes=1),
        limit=10,
    )

    assert run_id not in candidates
    assert await store.get_current(run_id) == active
    assert await store.get_tombstone(run_id) is None


async def test_terminal_payload_cleanup_is_bounded_from_terminal_time() -> None:
    run_id = DurableAgentRunId(UUID(int=102))
    store = InMemoryDurableRunStore(limits=_limits())
    terminal, lease = await _terminal_protected_run(store, run_id)
    due = terminal.created_at + POLICY.payload_retention

    with pytest.raises(AgentStateConflictError):
        await store.delete_expired_protected_payloads(
            run_id,
            policy=POLICY,
            lease=lease,
            now=due - timedelta(microseconds=1),
        )

    assert (
        await store.delete_expired_protected_payloads(
            run_id,
            policy=POLICY,
            lease=lease,
            now=due,
        )
        is True
    )
    assert await store.get_current(run_id) == terminal

    with pytest.raises(AgentStateConflictError):
        await store.get_protected_payload(
            terminal,
            lease=lease,
            now=due,
        )

    assert (
        await store.delete_expired_protected_payloads(
            run_id,
            policy=POLICY,
            lease=lease,
            now=due,
        )
        is False
    )


async def test_terminal_metadata_cleanup_creates_content_free_tombstone() -> None:
    run_id = DurableAgentRunId(UUID(int=103))
    store = InMemoryDurableRunStore(limits=_limits())
    terminal, lease = await _terminal_metadata_run(store, run_id)
    due = terminal.created_at + POLICY.metadata_retention

    with pytest.raises(AgentStateConflictError):
        await store.tombstone_terminal_run(
            run_id,
            policy=POLICY,
            lease=lease,
            now=due - timedelta(microseconds=1),
        )

    tombstone = await store.tombstone_terminal_run(
        run_id,
        policy=POLICY,
        lease=lease,
        now=due,
    )

    assert tombstone.run_id == run_id
    assert tombstone.terminal_status is DurableRunStatus.FAILED
    assert tombstone.terminal_version == terminal.run_version
    assert tombstone.final_checkpoint_digest == terminal.digest
    assert tombstone.deletion_generation == lease.generation
    assert tombstone.terminal_at == terminal.created_at
    assert tombstone.retain_until == (terminal.created_at + POLICY.tombstone_retention)

    assert await store.get_current(run_id) is None
    assert await store.list_history(run_id, limit=10) == ()
    assert await store.get_tombstone(run_id) == tombstone


async def test_retained_tombstone_blocks_same_run_id_recreation() -> None:
    run_id = DurableAgentRunId(UUID(int=104))
    store = InMemoryDurableRunStore(limits=_limits())
    terminal, lease = await _terminal_metadata_run(store, run_id)
    due = terminal.created_at + POLICY.metadata_retention

    await store.tombstone_terminal_run(
        run_id,
        policy=POLICY,
        lease=lease,
        now=due,
    )

    replacement = _checkpoint(
        run_id,
        1,
        created_at=NOW + timedelta(seconds=1),
    )
    with pytest.raises(AgentStateConflictError):
        await store.create(replacement)


async def test_expired_tombstone_is_removed_only_at_retain_until() -> None:
    run_id = DurableAgentRunId(UUID(int=105))
    store = InMemoryDurableRunStore(limits=_limits())
    terminal, lease = await _terminal_metadata_run(store, run_id)
    tombstone = await store.tombstone_terminal_run(
        run_id,
        policy=POLICY,
        lease=lease,
        now=terminal.created_at + POLICY.metadata_retention,
    )

    with pytest.raises(AgentStateConflictError):
        await store.purge_expired_tombstone(
            run_id,
            lease=lease,
            now=tombstone.retain_until - timedelta(microseconds=1),
        )

    assert (
        await store.purge_expired_tombstone(
            run_id,
            lease=lease,
            now=tombstone.retain_until,
        )
        is True
    )
    assert await store.get_tombstone(run_id) is None

    assert (
        await store.purge_expired_tombstone(
            run_id,
            lease=lease,
            now=tombstone.retain_until,
        )
        is False
    )


async def test_cleanup_candidates_are_deterministic_bounded_pages() -> None:
    first_id = DurableAgentRunId(UUID(int=201))
    second_id = DurableAgentRunId(UUID(int=202))
    store = InMemoryDurableRunStore(limits=_limits())

    first_terminal, first_lease = await _terminal_metadata_run(store, first_id)
    second_terminal, second_lease = await _terminal_metadata_run(store, second_id)

    await store.lease_manager.release(
        first_lease,
        now=NOW + timedelta(seconds=6),
    )
    await store.lease_manager.release(
        second_lease,
        now=NOW + timedelta(seconds=6),
    )

    due = (
        max(
            first_terminal.created_at,
            second_terminal.created_at,
        )
        + POLICY.payload_retention
    )

    first_page = await store.list_cleanup_candidates(
        policy=POLICY,
        now=due,
        limit=1,
    )
    second_page = await store.list_cleanup_candidates(
        policy=POLICY,
        now=due,
        limit=1,
        after=first_id,
    )

    assert first_page == (first_id,)
    assert second_page == (second_id,)


async def test_cleanup_candidates_skip_active_lease_until_release() -> None:
    run_id = DurableAgentRunId(UUID(int=301))
    store = InMemoryDurableRunStore(limits=_limits())
    terminal, lease = await _terminal_metadata_run(store, run_id)
    due = terminal.created_at + POLICY.payload_retention

    assert (
        await store.list_cleanup_candidates(
            policy=POLICY,
            now=due,
            limit=10,
        )
        == ()
    )

    await store.lease_manager.release(
        lease,
        now=due,
    )

    assert await store.list_cleanup_candidates(
        policy=POLICY,
        now=due,
        limit=10,
    ) == (run_id,)


async def test_stale_cleanup_lease_is_rejected_by_fencing() -> None:
    run_id = DurableAgentRunId(UUID(int=302))
    store = InMemoryDurableRunStore(limits=_limits())
    terminal, stale_lease = await _terminal_metadata_run(store, run_id)

    await store.lease_manager.release(
        stale_lease,
        now=NOW + timedelta(seconds=6),
    )
    current_lease = await store.lease_manager.acquire(
        run_id,
        owner_id="cleanup-current",
        now=NOW + timedelta(seconds=7),
    )

    assert current_lease.generation.value > stale_lease.generation.value

    due = terminal.created_at + POLICY.metadata_retention

    with pytest.raises(AgentStateConflictError):
        await store.tombstone_terminal_run(
            run_id,
            policy=POLICY,
            lease=stale_lease,
            now=due,
        )

    tombstone = await store.tombstone_terminal_run(
        run_id,
        policy=POLICY,
        lease=current_lease,
        now=due,
    )

    assert tombstone.deletion_generation == current_lease.generation


async def test_repeated_tombstoning_is_idempotent_under_same_fence() -> None:
    run_id = DurableAgentRunId(UUID(int=303))
    store = InMemoryDurableRunStore(limits=_limits())
    terminal, lease = await _terminal_metadata_run(store, run_id)
    due = terminal.created_at + POLICY.metadata_retention

    first = await store.tombstone_terminal_run(
        run_id,
        policy=POLICY,
        lease=lease,
        now=due,
    )
    second = await store.tombstone_terminal_run(
        run_id,
        policy=POLICY,
        lease=lease,
        now=due,
    )

    assert second == first
    assert await store.get_tombstone(run_id) == first
    assert await store.get_current(run_id) is None
    assert store.run_count == 0


async def test_destructive_cleanup_rejects_nonterminal_run() -> None:
    run_id = DurableAgentRunId(UUID(int=304))
    store = InMemoryDurableRunStore(limits=_limits())
    active = _checkpoint(
        run_id,
        1,
        created_at=NOW + timedelta(seconds=1),
    )
    await store.create(active)
    lease = await store.lease_manager.acquire(
        run_id,
        owner_id="cleanup-active",
        now=NOW + timedelta(seconds=2),
    )
    now = NOW + timedelta(minutes=1)

    with pytest.raises(AgentStateConflictError):
        await store.delete_expired_protected_payloads(
            run_id,
            policy=POLICY,
            lease=lease,
            now=now,
        )

    with pytest.raises(AgentStateConflictError):
        await store.tombstone_terminal_run(
            run_id,
            policy=POLICY,
            lease=lease,
            now=now,
        )

    with pytest.raises(AgentStateConflictError):
        await store.purge_expired_tombstone(
            run_id,
            lease=lease,
            now=now,
        )

    assert await store.get_current(run_id) == active
    assert await store.get_tombstone(run_id) is None


async def test_cleanup_candidate_validation_fails_closed() -> None:
    store = InMemoryDurableRunStore(limits=_limits())

    with pytest.raises(ValueError, match="greater than zero"):
        await store.list_cleanup_candidates(
            policy=POLICY,
            now=NOW,
            limit=0,
        )

    with pytest.raises(TypeError, match="integer"):
        await store.list_cleanup_candidates(
            policy=POLICY,
            now=NOW,
            limit=True,
        )

    with pytest.raises(AgentLimitExceededError):
        await store.list_cleanup_candidates(
            policy=POLICY,
            now=NOW,
            limit=MAX_RECOVERY_CANDIDATE_PAGE + 1,
        )

    with pytest.raises(ValueError, match="timezone-aware"):
        await store.list_cleanup_candidates(
            policy=POLICY,
            now=NOW.replace(tzinfo=None),
            limit=1,
        )


async def test_retention_worker_runs_real_memory_cleanup_end_to_end() -> None:
    run_id = DurableAgentRunId(UUID(int=401))
    store = InMemoryDurableRunStore(limits=_limits())

    terminal, setup_lease = await _terminal_protected_run(
        store,
        run_id,
    )

    await store.lease_manager.release(
        setup_lease,
        now=NOW + timedelta(seconds=6),
    )

    cleanup_now = terminal.created_at + POLICY.metadata_retention

    worker = BoundedDurableRetentionWorker(
        store=store,
        lease_manager=store.lease_manager,
        policy=POLICY,
        clock=lambda: cleanup_now,
    )

    await worker.start()

    try:
        report = await worker.run_once()

        assert report.admitted == 1
        assert report.payloads_deleted == 1
        assert report.tombstoned == 1

        tombstone = await store.get_tombstone(run_id)

        assert tombstone is not None
        assert tombstone.run_id == run_id
        assert tombstone.terminal_status is DurableRunStatus.FAILED
        assert tombstone.terminal_version == terminal.run_version
        assert tombstone.final_checkpoint_digest == terminal.digest
        assert tombstone.terminal_at == terminal.created_at
        assert tombstone.retain_until == (terminal.created_at + POLICY.tombstone_retention)

        assert await store.get_current(run_id) is None

        assert (
            await store.list_history(
                run_id,
                limit=10,
            )
            == ()
        )

        assert (
            await store.lease_manager.get_current(
                run_id,
                now=cleanup_now,
            )
            is None
        )
    finally:
        await worker.close()
        await store.close()
