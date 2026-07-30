import asyncio
from datetime import UTC, datetime, timedelta
from typing import cast
from uuid import UUID

import pytest

from phoenix_os.agent.durable_contracts import (
    DurableAgentRunId,
    DurableLease,
    DurableLeaseId,
    DurableRunLimits,
    FencingGeneration,
)
from phoenix_os.agent.durable_lease import (
    DurableLeaseManager,
    InMemoryDurableLeaseManager,
)
from phoenix_os.agent.errors import AgentStateConflictError

NOW = datetime(2026, 7, 29, 21, tzinfo=UTC)
RUN_ID = DurableAgentRunId(UUID("10000000-0000-0000-0000-000000000001"))
OTHER_RUN_ID = DurableAgentRunId(UUID("10000000-0000-0000-0000-000000000002"))
LEASE_ID = DurableLeaseId(UUID("20000000-0000-0000-0000-000000000001"))


def _limits() -> DurableRunLimits:
    return DurableRunLimits(
        lease_duration=timedelta(seconds=30),
        lease_renewal_interval=timedelta(seconds=10),
    )


def _manager() -> InMemoryDurableLeaseManager:
    return InMemoryDurableLeaseManager(limits=_limits())


def _forged_lease(
    current: DurableLease,
    *,
    lease_id: DurableLeaseId | None = None,
    owner_id: str | None = None,
    generation: FencingGeneration | None = None,
) -> DurableLease:
    return DurableLease(
        run_id=current.run_id,
        lease_id=lease_id or current.lease_id,
        owner_id=owner_id or current.owner_id,
        generation=generation or current.generation,
        acquired_at=current.acquired_at,
        expires_at=current.expires_at,
    )


def test_manager_uses_finite_default_limits_and_matches_protocol() -> None:
    manager = InMemoryDurableLeaseManager()

    assert isinstance(manager, DurableLeaseManager)
    assert manager.limits == DurableRunLimits()
    assert not manager.closed
    assert manager.active_count == 0


def test_manager_rejects_invalid_limits_type() -> None:
    with pytest.raises(TypeError, match="limits"):
        InMemoryDurableLeaseManager(
            limits=cast(DurableRunLimits, object()),
        )


@pytest.mark.asyncio
async def test_acquire_creates_generation_one_with_finite_expiry() -> None:
    manager = _manager()

    lease = await manager.acquire(
        RUN_ID,
        owner_id="worker-a",
        now=NOW,
    )

    assert lease.run_id == RUN_ID
    assert lease.owner_id == "worker-a"
    assert lease.generation == FencingGeneration(1)
    assert lease.acquired_at == NOW
    assert lease.expires_at == NOW + timedelta(seconds=30)
    assert lease.active_at(NOW)
    assert manager.active_count == 1
    assert await manager.get_current(RUN_ID, now=NOW) == lease


@pytest.mark.asyncio
async def test_acquire_rejects_invalid_run_identity_and_naive_time() -> None:
    manager = _manager()

    with pytest.raises(TypeError, match="run_id"):
        await manager.acquire(
            cast(DurableAgentRunId, object()),
            owner_id="worker-a",
            now=NOW,
        )

    with pytest.raises(ValueError, match="timezone-aware"):
        await manager.acquire(
            RUN_ID,
            owner_id="worker-a",
            now=NOW.replace(tzinfo=None),
        )

    assert manager.active_count == 0


@pytest.mark.asyncio
async def test_invalid_owner_does_not_consume_generation_or_create_lease() -> None:
    manager = _manager()

    with pytest.raises(ValueError, match="lease owner id"):
        await manager.acquire(
            RUN_ID,
            owner_id="Worker A",
            now=NOW,
        )

    assert manager.active_count == 0

    lease = await manager.acquire(
        RUN_ID,
        owner_id="worker-a",
        now=NOW,
    )
    assert lease.generation == FencingGeneration(1)


@pytest.mark.asyncio
async def test_active_lease_blocks_same_and_different_owners() -> None:
    manager = _manager()
    current = await manager.acquire(
        RUN_ID,
        owner_id="worker-a",
        now=NOW,
    )

    with pytest.raises(AgentStateConflictError):
        await manager.acquire(
            RUN_ID,
            owner_id="worker-a",
            now=NOW + timedelta(seconds=1),
        )

    with pytest.raises(AgentStateConflictError):
        await manager.acquire(
            RUN_ID,
            owner_id="worker-b",
            now=NOW + timedelta(seconds=1),
        )

    assert (
        await manager.get_current(
            RUN_ID,
            now=NOW + timedelta(seconds=1),
        )
        == current
    )
    assert manager.active_count == 1


@pytest.mark.asyncio
async def test_different_runs_receive_independent_generation_one_leases() -> None:
    manager = _manager()

    first = await manager.acquire(
        RUN_ID,
        owner_id="worker-a",
        now=NOW,
    )
    second = await manager.acquire(
        OTHER_RUN_ID,
        owner_id="worker-b",
        now=NOW,
    )

    assert first.generation == FencingGeneration(1)
    assert second.generation == FencingGeneration(1)
    assert first.lease_id != second.lease_id
    assert manager.active_count == 2


@pytest.mark.asyncio
async def test_get_current_returns_none_for_unknown_run() -> None:
    manager = _manager()

    assert await manager.get_current(RUN_ID, now=NOW) is None


@pytest.mark.asyncio
async def test_get_current_rejects_invalid_inputs() -> None:
    manager = _manager()

    with pytest.raises(TypeError, match="run_id"):
        await manager.get_current(
            cast(DurableAgentRunId, object()),
            now=NOW,
        )

    with pytest.raises(ValueError, match="timezone-aware"):
        await manager.get_current(
            RUN_ID,
            now=NOW.replace(tzinfo=None),
        )


@pytest.mark.asyncio
async def test_get_current_prunes_lease_at_exact_expiry() -> None:
    manager = _manager()
    lease = await manager.acquire(
        RUN_ID,
        owner_id="worker-a",
        now=NOW,
    )

    assert (
        await manager.get_current(
            RUN_ID,
            now=lease.expires_at - timedelta(microseconds=1),
        )
        == lease
    )
    assert (
        await manager.get_current(
            RUN_ID,
            now=lease.expires_at,
        )
        is None
    )
    assert manager.active_count == 0


@pytest.mark.asyncio
async def test_expired_reacquisition_increments_generation_and_changes_identity() -> None:
    manager = _manager()
    first = await manager.acquire(
        RUN_ID,
        owner_id="worker-a",
        now=NOW,
    )

    second = await manager.acquire(
        RUN_ID,
        owner_id="worker-b",
        now=first.expires_at,
    )

    assert second.owner_id == "worker-b"
    assert second.generation == FencingGeneration(2)
    assert second.lease_id != first.lease_id
    assert second.acquired_at == first.expires_at
    assert manager.active_count == 1


@pytest.mark.asyncio
async def test_multiple_expiry_cycles_keep_generation_monotonic() -> None:
    manager = _manager()
    first = await manager.acquire(
        RUN_ID,
        owner_id="worker-a",
        now=NOW,
    )
    second = await manager.acquire(
        RUN_ID,
        owner_id="worker-b",
        now=first.expires_at,
    )
    third = await manager.acquire(
        RUN_ID,
        owner_id="worker-c",
        now=second.expires_at,
    )

    assert first.generation == FencingGeneration(1)
    assert second.generation == FencingGeneration(2)
    assert third.generation == FencingGeneration(3)


@pytest.mark.asyncio
async def test_clock_rollback_during_acquire_fails_closed_without_pruning() -> None:
    manager = _manager()
    current = await manager.acquire(
        RUN_ID,
        owner_id="worker-a",
        now=NOW,
    )

    with pytest.raises(AgentStateConflictError):
        await manager.acquire(
            RUN_ID,
            owner_id="worker-b",
            now=NOW - timedelta(seconds=1),
        )

    assert await manager.get_current(RUN_ID, now=NOW) == current
    assert manager.active_count == 1


@pytest.mark.asyncio
async def test_get_current_clock_rollback_fails_closed_without_pruning() -> None:
    manager = _manager()
    current = await manager.acquire(
        RUN_ID,
        owner_id="worker-a",
        now=NOW,
    )

    with pytest.raises(AgentStateConflictError):
        await manager.get_current(
            RUN_ID,
            now=NOW - timedelta(microseconds=1),
        )

    assert await manager.get_current(RUN_ID, now=NOW) == current


@pytest.mark.asyncio
async def test_renew_preserves_identity_and_generation_while_extending_expiry() -> None:
    manager = _manager()
    original = await manager.acquire(
        RUN_ID,
        owner_id="worker-a",
        now=NOW,
    )
    renewed_at = NOW + timedelta(seconds=10)

    renewed = await manager.renew(
        original,
        now=renewed_at,
    )

    assert renewed.run_id == original.run_id
    assert renewed.lease_id == original.lease_id
    assert renewed.owner_id == original.owner_id
    assert renewed.generation == original.generation
    assert renewed.acquired_at == renewed_at
    assert renewed.expires_at == renewed_at + timedelta(seconds=30)
    assert renewed.expires_at > original.expires_at
    assert await manager.get_current(RUN_ID, now=renewed_at) == renewed


@pytest.mark.asyncio
async def test_stable_lease_identity_can_validate_after_renewal() -> None:
    manager = _manager()
    original = await manager.acquire(
        RUN_ID,
        owner_id="worker-a",
        now=NOW,
    )
    renewed = await manager.renew(
        original,
        now=NOW + timedelta(seconds=10),
    )

    authoritative = await manager.require_current(
        original,
        now=NOW + timedelta(seconds=11),
    )

    assert authoritative == renewed


@pytest.mark.asyncio
async def test_renew_rejects_expired_lease_and_prunes_it() -> None:
    manager = _manager()
    expired = await manager.acquire(
        RUN_ID,
        owner_id="worker-a",
        now=NOW,
    )

    with pytest.raises(AgentStateConflictError):
        await manager.renew(
            expired,
            now=expired.expires_at,
        )

    assert manager.active_count == 0

    replacement = await manager.acquire(
        RUN_ID,
        owner_id="worker-b",
        now=expired.expires_at,
    )
    assert replacement.generation == FencingGeneration(2)


@pytest.mark.asyncio
async def test_renew_rejects_clock_rollback_without_pruning() -> None:
    manager = _manager()
    current = await manager.acquire(
        RUN_ID,
        owner_id="worker-a",
        now=NOW,
    )

    with pytest.raises(AgentStateConflictError):
        await manager.renew(
            current,
            now=NOW - timedelta(microseconds=1),
        )

    assert await manager.get_current(RUN_ID, now=NOW) == current


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "forged",
    [
        "lease_id",
        "owner_id",
        "generation",
    ],
)
async def test_renew_rejects_replaced_or_forged_lease_identity(
    forged: str,
) -> None:
    manager = _manager()
    current = await manager.acquire(
        RUN_ID,
        owner_id="worker-a",
        now=NOW,
    )

    candidate = current
    if forged == "lease_id":
        candidate = _forged_lease(
            current,
            lease_id=LEASE_ID,
        )
    elif forged == "owner_id":
        candidate = _forged_lease(
            current,
            owner_id="worker-b",
        )
    else:
        candidate = _forged_lease(
            current,
            generation=FencingGeneration(2),
        )

    with pytest.raises(AgentStateConflictError):
        await manager.renew(
            candidate,
            now=NOW + timedelta(seconds=1),
        )

    assert (
        await manager.get_current(
            RUN_ID,
            now=NOW + timedelta(seconds=1),
        )
        == current
    )


@pytest.mark.asyncio
async def test_require_current_returns_authoritative_lease() -> None:
    manager = _manager()
    current = await manager.acquire(
        RUN_ID,
        owner_id="worker-a",
        now=NOW,
    )

    assert (
        await manager.require_current(
            current,
            now=NOW + timedelta(seconds=1),
        )
        == current
    )


@pytest.mark.asyncio
async def test_require_current_rejects_wrong_type_naive_time_and_unknown_lease() -> None:
    manager = _manager()

    with pytest.raises(TypeError, match="lease"):
        await manager.require_current(
            cast(DurableLease, object()),
            now=NOW,
        )

    unknown = DurableLease(
        run_id=RUN_ID,
        lease_id=LEASE_ID,
        owner_id="worker-a",
        generation=FencingGeneration(1),
        acquired_at=NOW,
        expires_at=NOW + timedelta(seconds=30),
    )

    with pytest.raises(ValueError, match="timezone-aware"):
        await manager.require_current(
            unknown,
            now=NOW.replace(tzinfo=None),
        )

    with pytest.raises(AgentStateConflictError):
        await manager.require_current(
            unknown,
            now=NOW,
        )


@pytest.mark.asyncio
async def test_stale_worker_is_fenced_after_expiry_and_reacquisition() -> None:
    manager = _manager()
    stale = await manager.acquire(
        RUN_ID,
        owner_id="worker-a",
        now=NOW,
    )
    current = await manager.acquire(
        RUN_ID,
        owner_id="worker-b",
        now=stale.expires_at,
    )

    with pytest.raises(AgentStateConflictError):
        await manager.require_current(
            stale,
            now=current.acquired_at,
        )

    with pytest.raises(AgentStateConflictError):
        await manager.release(
            stale,
            now=current.acquired_at,
        )

    assert (
        await manager.require_current(
            current,
            now=current.acquired_at,
        )
        == current
    )
    assert manager.active_count == 1


@pytest.mark.asyncio
async def test_release_removes_only_current_active_lease() -> None:
    manager = _manager()
    current = await manager.acquire(
        RUN_ID,
        owner_id="worker-a",
        now=NOW,
    )

    await manager.release(
        current,
        now=NOW + timedelta(seconds=1),
    )

    assert manager.active_count == 0
    assert (
        await manager.get_current(
            RUN_ID,
            now=NOW + timedelta(seconds=1),
        )
        is None
    )


@pytest.mark.asyncio
async def test_release_rejects_expired_lease_and_allows_fenced_reacquisition() -> None:
    manager = _manager()
    expired = await manager.acquire(
        RUN_ID,
        owner_id="worker-a",
        now=NOW,
    )

    with pytest.raises(AgentStateConflictError):
        await manager.release(
            expired,
            now=expired.expires_at,
        )

    replacement = await manager.acquire(
        RUN_ID,
        owner_id="worker-b",
        now=expired.expires_at,
    )
    assert replacement.generation == FencingGeneration(2)


@pytest.mark.asyncio
async def test_release_rejects_invalid_lease_type_and_naive_time() -> None:
    manager = _manager()
    current = await manager.acquire(
        RUN_ID,
        owner_id="worker-a",
        now=NOW,
    )

    with pytest.raises(TypeError, match="lease"):
        await manager.release(
            cast(DurableLease, object()),
            now=NOW,
        )

    with pytest.raises(ValueError, match="timezone-aware"):
        await manager.release(
            current,
            now=NOW.replace(tzinfo=None),
        )

    assert await manager.get_current(RUN_ID, now=NOW) == current


@pytest.mark.asyncio
async def test_concurrent_acquisition_has_exactly_one_winner() -> None:
    manager = _manager()

    async def acquire(owner_id: str) -> DurableLease | None:
        try:
            return await manager.acquire(
                RUN_ID,
                owner_id=owner_id,
                now=NOW,
            )
        except AgentStateConflictError:
            return None

    results = await asyncio.gather(
        acquire("worker-a"),
        acquire("worker-b"),
        acquire("worker-c"),
    )
    winners = [lease for lease in results if lease is not None]

    assert len(winners) == 1
    assert winners[0].generation == FencingGeneration(1)
    assert await manager.get_current(RUN_ID, now=NOW) == winners[0]
    assert manager.active_count == 1


@pytest.mark.asyncio
async def test_close_invalidates_active_leases_and_is_idempotent() -> None:
    manager = _manager()
    await manager.acquire(
        RUN_ID,
        owner_id="worker-a",
        now=NOW,
    )

    await manager.close()
    await manager.close()

    assert manager.closed
    assert manager.active_count == 0


@pytest.mark.asyncio
async def test_closed_manager_rejects_all_operations() -> None:
    manager = _manager()
    lease = await manager.acquire(
        RUN_ID,
        owner_id="worker-a",
        now=NOW,
    )
    await manager.close()

    with pytest.raises(RuntimeError, match="closed"):
        await manager.acquire(
            OTHER_RUN_ID,
            owner_id="worker-b",
            now=NOW,
        )

    with pytest.raises(RuntimeError, match="closed"):
        await manager.get_current(RUN_ID, now=NOW)

    with pytest.raises(RuntimeError, match="closed"):
        await manager.renew(lease, now=NOW)

    with pytest.raises(RuntimeError, match="closed"):
        await manager.require_current(lease, now=NOW)

    with pytest.raises(RuntimeError, match="closed"):
        async with manager.guard_current(lease, now=NOW):
            raise AssertionError("closed guard entered")

    with pytest.raises(RuntimeError, match="closed"):
        await manager.release(lease, now=NOW)


@pytest.mark.asyncio
async def test_guard_current_blocks_renewal_until_context_exit() -> None:
    manager = _manager()
    lease = await manager.acquire(
        RUN_ID,
        owner_id="worker-a",
        now=NOW,
    )
    entered = asyncio.Event()
    release_guard = asyncio.Event()

    async def hold_guard() -> None:
        async with manager.guard_current(
            lease,
            now=NOW + timedelta(seconds=1),
        ):
            entered.set()
            await release_guard.wait()

    guard_task = asyncio.create_task(hold_guard())
    await entered.wait()

    renew_task = asyncio.create_task(
        manager.renew(
            lease,
            now=NOW + timedelta(seconds=2),
        )
    )
    await asyncio.sleep(0)
    assert not renew_task.done()

    release_guard.set()
    await guard_task
    renewed = await renew_task

    assert renewed.lease_id == lease.lease_id
    assert renewed.generation == lease.generation
    assert renewed.acquired_at == NOW + timedelta(seconds=2)


@pytest.mark.asyncio
async def test_guard_current_rejects_stale_identity_after_reacquisition() -> None:
    manager = _manager()
    stale = await manager.acquire(
        RUN_ID,
        owner_id="worker-a",
        now=NOW,
    )
    current = await manager.acquire(
        RUN_ID,
        owner_id="worker-b",
        now=stale.expires_at,
    )

    with pytest.raises(AgentStateConflictError):
        async with manager.guard_current(
            stale,
            now=current.acquired_at,
        ):
            raise AssertionError("stale lease entered guarded mutation")
