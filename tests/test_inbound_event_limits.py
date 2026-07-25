from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from phoenix_os.inbound_events import (
    InboundAdmissionLimiter,
    InboundAdmissionLimiterClosedError,
    InboundAdmissionLimitPolicy,
    InboundAdmissionRejectedError,
    InboundEventSource,
    InboundHmacPolicy,
)
from phoenix_os.secrets import SecretRef

_NOW = datetime(2026, 7, 25, 12, 0, tzinfo=UTC)


def _source(
    source_id: int,
    *,
    max_concurrency: int = 2,
    requests_per_minute: int = 3,
) -> InboundEventSource:
    return InboundEventSource(
        id=UUID(f"00000000-0000-4000-8000-{source_id:012d}"),
        name=f"source.{source_id}",
        display_name=f"Source {source_id}",
        authentication=InboundHmacPolicy(SecretRef(f"secret-{source_id}", "integrations", 1)),
        event_types=frozenset({"event.created"}),
        created_at=_NOW,
        updated_at=_NOW,
        created_by="maintainer:test",
        max_concurrency=max_concurrency,
        requests_per_minute=requests_per_minute,
    )


@pytest.mark.asyncio
async def test_limiter_enforces_per_source_concurrency_and_releases() -> None:
    source = _source(1, max_concurrency=1)
    limiter = InboundAdmissionLimiter(InboundAdmissionLimitPolicy(global_max_concurrency=4))
    lease = await limiter.acquire(source)

    with pytest.raises(
        InboundAdmissionRejectedError,
        match="inbound admission limit exceeded",
    ):
        await limiter.acquire(source)

    await lease.close()
    replacement = await limiter.acquire(source)
    await replacement.close()

    snapshot = await limiter.snapshot()
    assert snapshot.active == 0
    assert snapshot.admitted == 2
    assert snapshot.rejected == 1


@pytest.mark.asyncio
async def test_limiter_enforces_global_concurrency_across_sources() -> None:
    limiter = InboundAdmissionLimiter(InboundAdmissionLimitPolicy(global_max_concurrency=1))
    first = await limiter.acquire(_source(1))

    with pytest.raises(InboundAdmissionRejectedError):
        await limiter.acquire(_source(2))

    await first.close()


@pytest.mark.asyncio
async def test_limiter_enforces_and_resets_per_source_rate() -> None:
    now = [_NOW]
    source = _source(1, requests_per_minute=1)
    limiter = InboundAdmissionLimiter(clock=lambda: now[0])

    first = await limiter.acquire(source)
    await first.close()
    with pytest.raises(InboundAdmissionRejectedError):
        await limiter.acquire(source)

    now[0] += timedelta(seconds=61)
    second = await limiter.acquire(source)
    await second.close()


@pytest.mark.asyncio
async def test_limiter_enforces_global_rate_across_sources() -> None:
    limiter = InboundAdmissionLimiter(InboundAdmissionLimitPolicy(global_requests_per_minute=1))
    first = await limiter.acquire(_source(1))
    await first.close()

    with pytest.raises(InboundAdmissionRejectedError):
        await limiter.acquire(_source(2))


@pytest.mark.asyncio
async def test_limiter_snapshot_is_aggregate_and_close_fails_closed() -> None:
    limiter = InboundAdmissionLimiter()
    lease = await limiter.acquire(_source(1))
    snapshot = await limiter.snapshot()

    assert snapshot.active == 1
    assert snapshot.tracked_sources == 1
    assert "00000000" not in repr(snapshot)

    await limiter.close()
    with pytest.raises(InboundAdmissionLimiterClosedError, match="closed"):
        await limiter.acquire(_source(2))
    await lease.close()
    assert (await limiter.snapshot()).active == 0
