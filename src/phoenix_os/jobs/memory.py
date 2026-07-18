"""Deterministic in-memory job repository with atomic lease fencing."""

from __future__ import annotations

import asyncio
from collections.abc import Iterable, Mapping
from dataclasses import replace
from datetime import datetime, timedelta
from uuid import uuid4

from phoenix_os.jobs.contracts import JobId, JobLease, JobRecord, JobStatus
from phoenix_os.jobs.errors import (
    JobAlreadyExistsError,
    JobLeaseLostError,
    JobNotFoundError,
    JobRepositoryClosedError,
)


class InMemoryJobRepository:
    """Process-local reference repository for deterministic scheduler tests."""

    def __init__(self) -> None:
        self._records: dict[JobId, JobRecord] = {}
        self._closed = False
        self._lock = asyncio.Lock()

    @property
    def closed(self) -> bool:
        return self._closed

    async def add(self, record: JobRecord) -> None:
        async with self._lock:
            self._ensure_open()
            if record.id in self._records:
                raise JobAlreadyExistsError(f"job already exists: {record.id}")
            self._records[record.id] = record

    async def get(self, job_id: JobId) -> JobRecord | None:
        async with self._lock:
            self._ensure_open()
            return self._records.get(job_id)

    async def list_all(self) -> tuple[JobRecord, ...]:
        async with self._lock:
            self._ensure_open()
            return _sort_records(self._records.values())

    async def list_due(self, now: datetime, *, limit: int) -> tuple[JobRecord, ...]:
        _validate_now(now)
        if limit <= 0 or limit > 1000:
            raise ValueError("limit must be between 1 and 1000")
        async with self._lock:
            self._ensure_open()
            due = [record for record in self._records.values() if _due(record, now)]
            return _sort_records(due)[:limit]

    async def claim(
        self,
        job_id: JobId,
        *,
        owner: str,
        now: datetime,
        lease_ttl: timedelta,
    ) -> JobLease | None:
        _validate_now(now)
        normalized_owner = owner.strip()
        if not normalized_owner:
            raise ValueError("owner must not be blank")
        if lease_ttl <= timedelta(0):
            raise ValueError("lease_ttl must be positive")
        async with self._lock:
            self._ensure_open()
            record = self._records.get(job_id)
            if record is None:
                raise JobNotFoundError(f"job not found: {job_id}")
            if not _due(record, now):
                return None
            attempt = record.attempts + 1
            if attempt > record.spec.retry.max_attempts:
                self._records[job_id] = replace(
                    record,
                    status=JobStatus.DEAD_LETTER,
                    updated_at=now,
                    lease=None,
                    error="JobLeaseExpired",
                )
                return None
            lease = JobLease(
                job_id=record.id,
                token=uuid4(),
                owner=normalized_owner,
                acquired_at=now,
                expires_at=now + lease_ttl,
                attempt=attempt,
            )
            self._records[job_id] = replace(
                record,
                status=JobStatus.RUNNING,
                updated_at=now,
                attempts=attempt,
                lease=lease,
                error=None,
            )
            return lease

    async def complete(
        self,
        lease: JobLease,
        output: Mapping[str, object],
        *,
        now: datetime,
    ) -> JobRecord:
        _validate_now(now)
        async with self._lock:
            self._ensure_open()
            record = self._require_lease(lease, now)
            interval = record.spec.schedule.interval
            if interval is None:
                completed = replace(
                    record,
                    status=JobStatus.SUCCEEDED,
                    updated_at=now,
                    lease=None,
                    output=output,
                    error=None,
                )
            else:
                next_run_at = record.spec.schedule.next_after(record.next_run_at, now)
                completed = replace(
                    record,
                    status=JobStatus.SCHEDULED,
                    updated_at=now,
                    next_run_at=next_run_at,
                    attempts=0,
                    lease=None,
                    output=output,
                    error=None,
                )
            self._records[record.id] = completed
            return completed

    async def fail(self, lease: JobLease, error: str, *, now: datetime) -> JobRecord:
        _validate_now(now)
        normalized = error.strip()
        if not normalized:
            raise ValueError("error must not be blank")
        async with self._lock:
            self._ensure_open()
            record = self._require_lease(lease, now)
            if record.attempts < record.spec.retry.max_attempts:
                failed = replace(
                    record,
                    status=JobStatus.RETRYING,
                    updated_at=now,
                    next_run_at=now + record.spec.retry.delay_after(record.attempts),
                    lease=None,
                    error=normalized,
                )
            else:
                failed = replace(
                    record,
                    status=JobStatus.DEAD_LETTER,
                    updated_at=now,
                    lease=None,
                    error=normalized,
                )
            self._records[record.id] = failed
            return failed

    async def cancel(self, job_id: JobId, *, now: datetime) -> bool:
        _validate_now(now)
        async with self._lock:
            self._ensure_open()
            record = self._records.get(job_id)
            if record is None:
                raise JobNotFoundError(f"job not found: {job_id}")
            if record.status.terminal:
                return False
            self._records[job_id] = replace(
                record,
                status=JobStatus.CANCELLED,
                updated_at=now,
                lease=None,
                error=None,
            )
            return True

    async def close(self) -> None:
        async with self._lock:
            self._records.clear()
            self._closed = True

    def _require_lease(self, lease: JobLease, now: datetime) -> JobRecord:
        record = self._records.get(lease.job_id)
        if record is None:
            raise JobNotFoundError(f"job not found: {lease.job_id}")
        if record.status is not JobStatus.RUNNING or record.lease != lease:
            raise JobLeaseLostError("job lease is stale or no longer owned")
        if not lease.active_at(now):
            raise JobLeaseLostError("job lease has expired")
        return record

    def _ensure_open(self) -> None:
        if self._closed:
            raise JobRepositoryClosedError("job repository is closed")


def _due(record: JobRecord, now: datetime) -> bool:
    if record.status in {JobStatus.SCHEDULED, JobStatus.RETRYING}:
        return record.next_run_at <= now
    return (
        record.status is JobStatus.RUNNING
        and record.lease is not None
        and not record.lease.active_at(now)
    )


def _sort_records(records: Iterable[JobRecord]) -> tuple[JobRecord, ...]:
    return tuple(
        sorted(records, key=lambda item: (item.next_run_at, item.created_at, str(item.id)))
    )


def _validate_now(now: datetime) -> None:
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
