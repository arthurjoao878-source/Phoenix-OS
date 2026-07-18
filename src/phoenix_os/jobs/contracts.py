"""Immutable contracts for durable Phoenix jobs and deterministic scheduling."""

from __future__ import annotations

from collections.abc import Awaitable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum
from types import MappingProxyType
from typing import Protocol
from uuid import UUID, uuid4

from phoenix_os.capabilities import CapabilityContext

type JobId = UUID
type JobArguments = Mapping[str, object]
type JobOutput = Mapping[str, object]


def _freeze_mapping(value: Mapping[str, object]) -> Mapping[str, object]:
    return MappingProxyType(dict(value))


def _aware(value: datetime, label: str) -> datetime:
    if value.tzinfo is None:
        raise ValueError(f"{label} must be timezone-aware")
    return value


class JobStatus(StrEnum):
    """Stable lifecycle states for one scheduled job."""

    SCHEDULED = "scheduled"
    RUNNING = "running"
    RETRYING = "retrying"
    SUCCEEDED = "succeeded"
    CANCELLED = "cancelled"
    DEAD_LETTER = "dead_letter"

    @property
    def terminal(self) -> bool:
        return self in {self.SUCCEEDED, self.CANCELLED, self.DEAD_LETTER}


@dataclass(frozen=True, slots=True)
class RetryPolicy:
    """Deterministic bounded exponential retry policy."""

    max_attempts: int = 1
    initial_delay: timedelta = timedelta(0)
    multiplier: float = 2.0
    max_delay: timedelta | None = None

    def __post_init__(self) -> None:
        if self.max_attempts <= 0:
            raise ValueError("max_attempts must be positive")
        if self.initial_delay < timedelta(0):
            raise ValueError("initial_delay cannot be negative")
        if self.multiplier < 1:
            raise ValueError("multiplier must be at least one")
        if self.max_delay is not None and self.max_delay < timedelta(0):
            raise ValueError("max_delay cannot be negative")

    def delay_after(self, attempts: int) -> timedelta:
        """Return the delay after the given completed attempt count."""

        if attempts <= 0:
            raise ValueError("attempts must be positive")
        seconds = self.initial_delay.total_seconds() * (self.multiplier ** (attempts - 1))
        delay = timedelta(seconds=seconds)
        if self.max_delay is not None:
            return min(delay, self.max_delay)
        return delay


@dataclass(frozen=True, slots=True)
class JobSchedule:
    """One-time or fixed-interval execution schedule."""

    run_at: datetime
    interval: timedelta | None = None

    def __post_init__(self) -> None:
        _aware(self.run_at, "run_at")
        if self.interval is not None and self.interval <= timedelta(0):
            raise ValueError("interval must be positive")

    @property
    def recurring(self) -> bool:
        return self.interval is not None

    def next_after(self, previous: datetime, now: datetime) -> datetime:
        """Return the first fixed-rate occurrence strictly after now."""

        _aware(previous, "previous")
        _aware(now, "now")
        if self.interval is None:
            raise ValueError("one-time schedule has no next occurrence")
        candidate = previous + self.interval
        while candidate <= now:
            candidate += self.interval
        return candidate


@dataclass(frozen=True, slots=True)
class JobSpec:
    """Immutable capability invocation and scheduling policy."""

    capability: str
    schedule: JobSchedule
    arguments: JobArguments = field(default_factory=dict)
    context: CapabilityContext = field(default_factory=CapabilityContext)
    retry: RetryPolicy = field(default_factory=RetryPolicy)
    deadline: float | None = None
    metadata: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        capability = self.capability.strip()
        if not capability:
            raise ValueError("capability must not be blank")
        if self.deadline is not None and self.deadline <= 0:
            raise ValueError("deadline must be positive")
        metadata = {str(key).strip(): str(value) for key, value in self.metadata.items()}
        if any(not key for key in metadata):
            raise ValueError("metadata keys must not be blank")
        object.__setattr__(self, "capability", capability)
        object.__setattr__(self, "arguments", _freeze_mapping(self.arguments))
        object.__setattr__(self, "metadata", MappingProxyType(metadata))


@dataclass(frozen=True, slots=True)
class JobLease:
    """Opaque fencing token for one claimed execution attempt."""

    job_id: JobId
    token: UUID
    owner: str
    acquired_at: datetime
    expires_at: datetime
    attempt: int

    def __post_init__(self) -> None:
        owner = self.owner.strip()
        if not owner:
            raise ValueError("lease owner must not be blank")
        _aware(self.acquired_at, "acquired_at")
        _aware(self.expires_at, "expires_at")
        if self.expires_at <= self.acquired_at:
            raise ValueError("lease expiry must be after acquisition")
        if self.attempt <= 0:
            raise ValueError("lease attempt must be positive")
        object.__setattr__(self, "owner", owner)

    def active_at(self, now: datetime) -> bool:
        _aware(now, "now")
        return now < self.expires_at


@dataclass(frozen=True, slots=True)
class JobRecord:
    """Complete immutable repository state for one job."""

    spec: JobSpec
    status: JobStatus
    created_at: datetime
    updated_at: datetime
    next_run_at: datetime
    id: JobId = field(default_factory=uuid4)
    attempts: int = 0
    lease: JobLease | None = None
    output: JobOutput = field(default_factory=dict)
    error: str | None = None

    def __post_init__(self) -> None:
        _aware(self.created_at, "created_at")
        _aware(self.updated_at, "updated_at")
        _aware(self.next_run_at, "next_run_at")
        if self.updated_at < self.created_at:
            raise ValueError("updated_at cannot precede created_at")
        if self.attempts < 0 or self.attempts > self.spec.retry.max_attempts:
            raise ValueError("attempts must be within retry policy bounds")
        if self.status is JobStatus.RUNNING and self.lease is None:
            raise ValueError("running job requires a lease")
        if self.status is not JobStatus.RUNNING and self.lease is not None:
            raise ValueError("only running jobs may hold a lease")
        if self.lease is not None:
            if self.lease.job_id != self.id or self.lease.attempt != self.attempts:
                raise ValueError("lease does not match job state")
        error = None if self.error is None else self.error.strip()
        if self.status in {JobStatus.RETRYING, JobStatus.DEAD_LETTER} and not error:
            raise ValueError("failed job state requires an error")
        object.__setattr__(self, "status", JobStatus(self.status))
        object.__setattr__(self, "output", _freeze_mapping(self.output))
        object.__setattr__(self, "error", error)


@dataclass(frozen=True, slots=True)
class JobRun:
    """Result of one scheduler claim and execution attempt."""

    job_id: JobId
    attempt: int
    status: JobStatus
    started_at: datetime
    finished_at: datetime
    output: JobOutput = field(default_factory=dict)
    error: str | None = None

    def __post_init__(self) -> None:
        _aware(self.started_at, "started_at")
        _aware(self.finished_at, "finished_at")
        if self.finished_at < self.started_at:
            raise ValueError("finished_at cannot precede started_at")
        if self.attempt <= 0:
            raise ValueError("attempt must be positive")
        object.__setattr__(self, "status", JobStatus(self.status))
        object.__setattr__(self, "output", _freeze_mapping(self.output))
        if self.error is not None:
            normalized = self.error.strip()
            object.__setattr__(self, "error", normalized or None)


@dataclass(frozen=True, slots=True)
class JobSchedulerSnapshot:
    """Non-sensitive deterministic scheduler diagnostics."""

    closed: bool
    jobs: int
    scheduled: int
    running: int
    retrying: int
    succeeded: int
    cancelled: int
    dead_letter: int
    runs: int

    def __post_init__(self) -> None:
        counts = (
            self.jobs,
            self.scheduled,
            self.running,
            self.retrying,
            self.succeeded,
            self.cancelled,
            self.dead_letter,
            self.runs,
        )
        if any(value < 0 for value in counts):
            raise ValueError("scheduler counts cannot be negative")
        states = (
            self.scheduled
            + self.running
            + self.retrying
            + self.succeeded
            + self.cancelled
            + self.dead_letter
        )
        if states != self.jobs:
            raise ValueError("scheduler state counts must equal jobs")


class JobRepository(Protocol):
    """Atomic persistence boundary for scheduler state and lease fencing."""

    @property
    def closed(self) -> bool: ...

    def add(self, record: JobRecord) -> Awaitable[None]: ...

    def get(self, job_id: JobId) -> Awaitable[JobRecord | None]: ...

    def list_all(self) -> Awaitable[tuple[JobRecord, ...]]: ...

    def list_due(self, now: datetime, *, limit: int) -> Awaitable[tuple[JobRecord, ...]]: ...

    def claim(
        self,
        job_id: JobId,
        *,
        owner: str,
        now: datetime,
        lease_ttl: timedelta,
    ) -> Awaitable[JobLease | None]: ...

    def complete(
        self,
        lease: JobLease,
        output: JobOutput,
        *,
        now: datetime,
    ) -> Awaitable[JobRecord]: ...

    def fail(self, lease: JobLease, error: str, *, now: datetime) -> Awaitable[JobRecord]: ...

    def cancel(self, job_id: JobId, *, now: datetime) -> Awaitable[bool]: ...

    def close(self) -> Awaitable[None]: ...
