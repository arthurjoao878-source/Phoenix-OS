from __future__ import annotations

import asyncio
from datetime import timedelta

import pytest

from phoenix_os.agent import (
    AgentAdmissionController,
    AgentCancellationToken,
    AgentCancelledError,
    AgentLimitExceededError,
    AgentLimits,
    AgentServiceUnavailableError,
    AgentTimeoutError,
)


def _limits(
    *,
    queue: int = 1,
    runs: int = 1,
    models: int = 1,
    tools: int = 1,
) -> AgentLimits:
    return AgentLimits(
        max_queue_depth=queue,
        max_concurrent_runs=runs,
        max_concurrent_model_calls=models,
        max_concurrent_tool_calls=tools,
        model_turn_timeout=timedelta(seconds=1),
        tool_call_timeout=timedelta(seconds=1),
        approval_wait_timeout=timedelta(seconds=1),
        total_duration=timedelta(seconds=2),
    )


async def _wait_for_queue(
    controller: AgentAdmissionController,
    expected: int,
) -> None:
    for _ in range(100):
        if (await controller.snapshot()).queued == expected:
            return
        await asyncio.sleep(0)
    raise AssertionError(f"queue did not reach {expected}")


@pytest.mark.asyncio
async def test_admission_rejects_work_beyond_finite_queue_capacity() -> None:
    controller = AgentAdmissionController(_limits())
    first = await controller.acquire_run(
        timeout_seconds=1,
        cancellation=AgentCancellationToken(),
    )
    queued = asyncio.create_task(
        controller.acquire_run(
            timeout_seconds=1,
            cancellation=AgentCancellationToken(),
        )
    )
    await _wait_for_queue(controller, 1)

    with pytest.raises(AgentLimitExceededError):
        await controller.acquire_run(
            timeout_seconds=1,
            cancellation=AgentCancellationToken(),
        )

    await first.release()
    second = await queued
    await second.release()
    snapshot = await controller.snapshot()
    assert snapshot.active_runs == 0
    assert snapshot.queued == 0


@pytest.mark.asyncio
async def test_admission_release_is_idempotent_and_wakes_one_waiter() -> None:
    controller = AgentAdmissionController(_limits())
    first = await controller.acquire_model(
        timeout_seconds=1,
        cancellation=AgentCancellationToken(),
    )
    queued = asyncio.create_task(
        controller.acquire_model(
            timeout_seconds=1,
            cancellation=AgentCancellationToken(),
        )
    )
    await _wait_for_queue(controller, 1)

    await first.release()
    await first.release()
    second = await queued
    snapshot = await controller.snapshot()
    assert snapshot.active_model_calls == 1
    assert snapshot.queued == 0

    await second.release()
    assert (await controller.snapshot()).active_model_calls == 0


@pytest.mark.asyncio
async def test_admission_cancellation_wins_release_race_and_cleans_queue() -> None:
    controller = AgentAdmissionController(_limits())
    first = await controller.acquire_tool(
        timeout_seconds=1,
        cancellation=AgentCancellationToken(),
    )
    cancellation = AgentCancellationToken()
    queued = asyncio.create_task(
        controller.acquire_tool(
            timeout_seconds=1,
            cancellation=cancellation,
        )
    )
    await _wait_for_queue(controller, 1)

    cancellation.cancel()
    await first.release()
    with pytest.raises(AgentCancelledError):
        await queued

    snapshot = await controller.snapshot()
    assert snapshot.active_tool_calls == 0
    assert snapshot.queued == 0


@pytest.mark.asyncio
async def test_admission_timeout_cleans_queued_capacity() -> None:
    controller = AgentAdmissionController(_limits())
    first = await controller.acquire_run(
        timeout_seconds=1,
        cancellation=AgentCancellationToken(),
    )

    with pytest.raises(AgentTimeoutError):
        await controller.acquire_run(
            timeout_seconds=0.01,
            cancellation=AgentCancellationToken(),
        )

    snapshot = await controller.snapshot()
    assert snapshot.active_runs == 1
    assert snapshot.queued == 0
    await first.release()


@pytest.mark.asyncio
async def test_admission_close_wakes_waiters_and_rejects_new_work() -> None:
    controller = AgentAdmissionController(_limits())
    first = await controller.acquire_model(
        timeout_seconds=1,
        cancellation=AgentCancellationToken(),
    )
    queued = asyncio.create_task(
        controller.acquire_model(
            timeout_seconds=1,
            cancellation=AgentCancellationToken(),
        )
    )
    await _wait_for_queue(controller, 1)

    await controller.close()
    with pytest.raises(AgentServiceUnavailableError):
        await queued
    with pytest.raises(AgentServiceUnavailableError):
        await controller.acquire_model(
            timeout_seconds=1,
            cancellation=AgentCancellationToken(),
        )

    await first.release()
    snapshot = await controller.snapshot()
    assert snapshot.closed is True
    assert snapshot.active_model_calls == 0
    assert snapshot.queued == 0


@pytest.mark.asyncio
async def test_admission_applies_most_restrictive_request_capacity() -> None:
    controller = AgentAdmissionController(_limits(queue=4, runs=4, models=4, tools=4))
    restrictive = _limits(queue=1, runs=1, models=1, tools=1)
    first = await controller.acquire_run(
        restrictive,
        timeout_seconds=1,
        cancellation=AgentCancellationToken(),
    )
    cancellation = AgentCancellationToken()
    queued = asyncio.create_task(
        controller.acquire_run(
            restrictive,
            timeout_seconds=1,
            cancellation=cancellation,
        )
    )
    await _wait_for_queue(controller, 1)

    snapshot = await controller.snapshot()
    assert snapshot.active_runs == 1
    assert snapshot.max_concurrent_runs == 4

    cancellation.cancel()
    with pytest.raises(AgentCancelledError):
        await queued
    await first.release()
