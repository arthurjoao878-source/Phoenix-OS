"""Deterministic scheduler that executes only registered Phoenix capabilities."""

from __future__ import annotations

import asyncio
from collections import Counter
from datetime import UTC, datetime, timedelta

from phoenix_os.capabilities import CapabilityRegistry
from phoenix_os.events import EventBus
from phoenix_os.jobs.contracts import (
    JobId,
    JobRecord,
    JobRepository,
    JobRun,
    JobSchedulerSnapshot,
    JobSpec,
    JobStatus,
)
from phoenix_os.jobs.errors import JobSchedulerClosedError


class JobScheduler:
    """Schedule, claim, and execute capability-backed jobs in deterministic ticks."""

    def __init__(
        self,
        repository: JobRepository,
        capabilities: CapabilityRegistry,
        *,
        events: EventBus | None = None,
        source: str = "phoenix.jobs",
    ) -> None:
        normalized_source = source.strip()
        if not normalized_source:
            raise ValueError("source must not be blank")
        self._repository = repository
        self._capabilities = capabilities
        self._events = events
        self._source = normalized_source
        self._closed = False
        self._runs = 0
        self._lock = asyncio.Lock()

    @property
    def closed(self) -> bool:
        return self._closed

    async def schedule(
        self,
        spec: JobSpec,
        *,
        job_id: JobId | None = None,
        now: datetime | None = None,
    ) -> JobRecord:
        self._ensure_open()
        created_at = datetime.now(UTC) if now is None else now
        if created_at.tzinfo is None:
            raise ValueError("now must be timezone-aware")
        if job_id is None:
            record = JobRecord(
                spec=spec,
                status=JobStatus.SCHEDULED,
                created_at=created_at,
                updated_at=created_at,
                next_run_at=spec.schedule.run_at,
            )
        else:
            record = JobRecord(
                id=job_id,
                spec=spec,
                status=JobStatus.SCHEDULED,
                created_at=created_at,
                updated_at=created_at,
                next_run_at=spec.schedule.run_at,
            )
        await self._repository.add(record)
        await self._emit("job.scheduled", record)
        return record

    async def get(self, job_id: JobId) -> JobRecord | None:
        self._ensure_open()
        return await self._repository.get(job_id)

    async def cancel(self, job_id: JobId, *, now: datetime | None = None) -> bool:
        self._ensure_open()
        cancelled_at = datetime.now(UTC) if now is None else now
        result = await self._repository.cancel(job_id, now=cancelled_at)
        record = await self._repository.get(job_id)
        if result and record is not None:
            await self._emit("job.cancelled", record)
        return result

    async def run_due(
        self,
        *,
        now: datetime | None = None,
        worker: str = "phoenix.scheduler",
        lease_ttl: timedelta = timedelta(seconds=30),
        limit: int = 100,
    ) -> tuple[JobRun, ...]:
        self._ensure_open()
        tick_at = datetime.now(UTC) if now is None else now
        if tick_at.tzinfo is None:
            raise ValueError("now must be timezone-aware")
        async with self._lock:
            self._ensure_open()
            due = await self._repository.list_due(tick_at, limit=limit)
            runs: list[JobRun] = []
            for candidate in due:
                lease = await self._repository.claim(
                    candidate.id,
                    owner=worker,
                    now=tick_at,
                    lease_ttl=lease_ttl,
                )
                if lease is None:
                    continue
                started_at = tick_at
                claimed = await self._repository.get(candidate.id)
                if claimed is None:
                    continue
                await self._emit("job.started", claimed, attempt=lease.attempt)
                try:
                    result = await self._capabilities.invoke(
                        candidate.spec.capability,
                        candidate.spec.arguments,
                        context=candidate.spec.context,
                        deadline=candidate.spec.deadline,
                    )
                except asyncio.CancelledError:
                    raise
                except Exception as exception:
                    finished_at = datetime.now(UTC) if now is None else tick_at
                    updated = await self._repository.fail(
                        lease,
                        _safe_error(exception),
                        now=finished_at,
                    )
                    run = JobRun(
                        job_id=updated.id,
                        attempt=lease.attempt,
                        status=updated.status,
                        started_at=started_at,
                        finished_at=finished_at,
                        error=updated.error,
                    )
                    await self._emit(
                        "job.retrying"
                        if updated.status is JobStatus.RETRYING
                        else "job.dead_lettered",
                        updated,
                        attempt=lease.attempt,
                    )
                else:
                    finished_at = datetime.now(UTC) if now is None else tick_at
                    updated = await self._repository.complete(
                        lease,
                        result.output,
                        now=finished_at,
                    )
                    run = JobRun(
                        job_id=updated.id,
                        attempt=lease.attempt,
                        status=updated.status,
                        started_at=started_at,
                        finished_at=finished_at,
                        output=result.output,
                    )
                    await self._emit("job.completed", updated, attempt=lease.attempt)
                runs.append(run)
                self._runs += 1
            return tuple(runs)

    async def snapshot(self) -> JobSchedulerSnapshot:
        records = await self._repository.list_all()
        counts = Counter(record.status for record in records)
        return JobSchedulerSnapshot(
            closed=self._closed,
            jobs=len(records),
            scheduled=counts[JobStatus.SCHEDULED],
            running=counts[JobStatus.RUNNING],
            retrying=counts[JobStatus.RETRYING],
            succeeded=counts[JobStatus.SUCCEEDED],
            cancelled=counts[JobStatus.CANCELLED],
            dead_letter=counts[JobStatus.DEAD_LETTER],
            runs=self._runs,
        )

    async def close(self) -> None:
        async with self._lock:
            if self._closed:
                return
            self._closed = True
            await self._repository.close()

    async def _emit(
        self,
        name: str,
        record: JobRecord,
        *,
        attempt: int | None = None,
    ) -> None:
        if self._events is None:
            return
        payload: dict[str, object] = {
            "job_id": str(record.id),
            "capability": record.spec.capability,
            "status": record.status.value,
        }
        if attempt is not None:
            payload["attempt"] = attempt
        await self._events.emit(
            name,
            source=self._source,
            payload=payload,
            correlation_id=record.spec.context.correlation_id,
            causation_id=record.spec.context.request_id,
        )

    def _ensure_open(self) -> None:
        if self._closed:
            raise JobSchedulerClosedError("job scheduler is closed")


def _safe_error(exception: Exception) -> str:
    """Return a stable non-sensitive failure category."""

    return type(exception).__name__
