"""Durable job repository backed by the provider-neutral Phoenix StateStore."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import replace
from datetime import datetime, timedelta
from typing import cast
from uuid import UUID, uuid4

from phoenix_os.capabilities import CapabilityContext
from phoenix_os.jobs.contracts import (
    JobId,
    JobLease,
    JobRecord,
    JobSchedule,
    JobSpec,
    JobStatus,
    RetryPolicy,
)
from phoenix_os.jobs.errors import (
    JobAlreadyExistsError,
    JobLeaseLostError,
    JobNotFoundError,
    JobPersistenceError,
    JobRepositoryClosedError,
)
from phoenix_os.policy import PrincipalType
from phoenix_os.state import (
    ABSENT_VERSION,
    StateConflictError,
    StateKey,
    StateOperationContext,
    StateStore,
)
from phoenix_os.state import (
    StateRecord as PersistedStateRecord,
)

_SCHEMA_VERSION = 1


class StateJobRepository:
    """Persist complete job records through serializable StateStore transactions."""

    def __init__(
        self,
        store: StateStore,
        *,
        namespace: str = "jobs",
        context: StateOperationContext | None = None,
    ) -> None:
        probe = StateKey(namespace, "job", dict)
        self._store = store
        self._namespace = probe.namespace
        self._context = context or StateOperationContext(
            metadata={
                "principal": "phoenix.jobs",
                "principal_type": PrincipalType.SYSTEM.value,
                "authenticated": "true",
            }
        )
        self._closed = False

    @property
    def closed(self) -> bool:
        return self._closed

    async def add(self, record: JobRecord) -> None:
        self._ensure_open()
        try:
            await self._store.put(
                self._key(record.id),
                _encode_record(record),
                expected_version=ABSENT_VERSION,
                context=self._context,
            )
        except StateConflictError as exception:
            raise JobAlreadyExistsError(f"job already exists: {record.id}") from exception

    async def get(self, job_id: JobId) -> JobRecord | None:
        self._ensure_open()
        stored = await self._store.get(self._key(job_id), context=self._context)
        return None if stored is None else _decode_record(stored.value)

    async def list_all(self) -> tuple[JobRecord, ...]:
        self._ensure_open()
        stored = await self._store.list(namespace=self._namespace, context=self._context)
        records = [_decode_record(_object_mapping(item.value, "record")) for item in stored]
        return _sort_records(records)

    async def list_due(self, now: datetime, *, limit: int) -> tuple[JobRecord, ...]:
        _validate_now(now)
        if limit <= 0 or limit > 1000:
            raise ValueError("limit must be between 1 and 1000")
        return tuple(record for record in await self.list_all() if _due(record, now))[:limit]

    async def claim(
        self,
        job_id: JobId,
        *,
        owner: str,
        now: datetime,
        lease_ttl: timedelta,
    ) -> JobLease | None:
        self._ensure_open()
        _validate_now(now)
        normalized_owner = owner.strip()
        if not normalized_owner:
            raise ValueError("owner must not be blank")
        if lease_ttl <= timedelta(0):
            raise ValueError("lease_ttl must be positive")

        key = self._key(job_id)
        async with self._store.transaction(context=self._context) as transaction:
            stored = await transaction.get(key)
            if stored is None:
                raise JobNotFoundError(f"job not found: {job_id}")
            record = _decode_record(stored.value)
            if not _due(record, now):
                return None
            attempt = record.attempts + 1
            if attempt > record.spec.retry.max_attempts:
                exhausted = replace(
                    record,
                    status=JobStatus.DEAD_LETTER,
                    updated_at=now,
                    lease=None,
                    error="JobLeaseExpired",
                )
                await transaction.put(
                    key,
                    _encode_record(exhausted),
                    expected_version=stored.version,
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
            claimed = replace(
                record,
                status=JobStatus.RUNNING,
                updated_at=now,
                attempts=attempt,
                lease=lease,
                error=None,
            )
            await transaction.put(
                key,
                _encode_record(claimed),
                expected_version=stored.version,
            )
            return lease

    async def complete(
        self,
        lease: JobLease,
        output: Mapping[str, object],
        *,
        now: datetime,
    ) -> JobRecord:
        self._ensure_open()
        _validate_now(now)
        key = self._key(lease.job_id)
        async with self._store.transaction(context=self._context) as transaction:
            stored = await transaction.get(key)
            record = self._require_lease(stored, lease, now)
            assert stored is not None
            if record.spec.schedule.interval is None:
                completed = replace(
                    record,
                    status=JobStatus.SUCCEEDED,
                    updated_at=now,
                    lease=None,
                    output=output,
                    error=None,
                )
            else:
                completed = replace(
                    record,
                    status=JobStatus.SCHEDULED,
                    updated_at=now,
                    next_run_at=record.spec.schedule.next_after(record.next_run_at, now),
                    attempts=0,
                    lease=None,
                    output=output,
                    error=None,
                )
            await transaction.put(
                key,
                _encode_record(completed),
                expected_version=stored.version,
            )
            return completed

    async def fail(self, lease: JobLease, error: str, *, now: datetime) -> JobRecord:
        self._ensure_open()
        _validate_now(now)
        normalized = error.strip()
        if not normalized:
            raise ValueError("error must not be blank")
        key = self._key(lease.job_id)
        async with self._store.transaction(context=self._context) as transaction:
            stored = await transaction.get(key)
            record = self._require_lease(stored, lease, now)
            assert stored is not None
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
            await transaction.put(
                key,
                _encode_record(failed),
                expected_version=stored.version,
            )
            return failed

    async def cancel(self, job_id: JobId, *, now: datetime) -> bool:
        self._ensure_open()
        _validate_now(now)
        key = self._key(job_id)
        async with self._store.transaction(context=self._context) as transaction:
            stored = await transaction.get(key)
            if stored is None:
                raise JobNotFoundError(f"job not found: {job_id}")
            record = _decode_record(stored.value)
            if record.status.terminal:
                return False
            cancelled = replace(
                record,
                status=JobStatus.CANCELLED,
                updated_at=now,
                lease=None,
                error=None,
            )
            await transaction.put(
                key,
                _encode_record(cancelled),
                expected_version=stored.version,
            )
            return True

    async def close(self) -> None:
        # The repository borrows the StateStore; Runtime owns the store lifecycle.
        self._closed = True

    def _key(self, job_id: JobId) -> StateKey[dict[str, object]]:
        return StateKey(self._namespace, f"j_{job_id.hex}", dict)

    def _require_lease(
        self,
        stored: PersistedStateRecord[dict[str, object]] | None,
        lease: JobLease,
        now: datetime,
    ) -> JobRecord:
        if stored is None:
            raise JobNotFoundError(f"job not found: {lease.job_id}")
        record = _decode_record(stored.value)
        if record.status is not JobStatus.RUNNING or record.lease != lease:
            raise JobLeaseLostError("job lease is stale or no longer owned")
        if not lease.active_at(now):
            raise JobLeaseLostError("job lease has expired")
        return record

    def _ensure_open(self) -> None:
        if self._closed:
            raise JobRepositoryClosedError("job repository is closed")


def _encode_record(record: JobRecord) -> dict[str, object]:
    context = record.spec.context
    retry = record.spec.retry
    schedule = record.spec.schedule
    lease = record.lease
    return {
        "schema_version": _SCHEMA_VERSION,
        "id": str(record.id),
        "status": record.status.value,
        "created_at": record.created_at.isoformat(),
        "updated_at": record.updated_at.isoformat(),
        "next_run_at": record.next_run_at.isoformat(),
        "attempts": record.attempts,
        "error": record.error,
        "output": dict(record.output),
        "lease": None
        if lease is None
        else {
            "job_id": str(lease.job_id),
            "token": str(lease.token),
            "owner": lease.owner,
            "acquired_at": lease.acquired_at.isoformat(),
            "expires_at": lease.expires_at.isoformat(),
            "attempt": lease.attempt,
        },
        "spec": {
            "capability": record.spec.capability,
            "arguments": dict(record.spec.arguments),
            "deadline": record.spec.deadline,
            "metadata": dict(record.spec.metadata),
            "schedule": {
                "run_at": schedule.run_at.isoformat(),
                "interval_seconds": (
                    None if schedule.interval is None else schedule.interval.total_seconds()
                ),
            },
            "retry": {
                "max_attempts": retry.max_attempts,
                "initial_delay_seconds": retry.initial_delay.total_seconds(),
                "multiplier": retry.multiplier,
                "max_delay_seconds": (
                    None if retry.max_delay is None else retry.max_delay.total_seconds()
                ),
            },
            "context": {
                "principal": context.principal,
                "request_id": None if context.request_id is None else str(context.request_id),
                "correlation_id": context.correlation_id,
                "confirmed": context.confirmed,
                "permissions": sorted(context.permissions),
                "metadata": dict(context.metadata),
            },
        },
    }


def _decode_record(value: Mapping[str, object]) -> JobRecord:
    try:
        if _integer(value, "schema_version") != _SCHEMA_VERSION:
            raise ValueError("unsupported persisted job schema version")
        spec_data = _mapping(value, "spec")
        schedule_data = _mapping(spec_data, "schedule")
        retry_data = _mapping(spec_data, "retry")
        context_data = _mapping(spec_data, "context")
        interval_seconds = _optional_number(schedule_data, "interval_seconds")
        max_delay_seconds = _optional_number(retry_data, "max_delay_seconds")
        request_id = _optional_string(context_data, "request_id")
        lease_data = value.get("lease")
        lease = None
        if lease_data is not None:
            lease_mapping = _object_mapping(lease_data, "lease")
            lease = JobLease(
                job_id=UUID(_string(lease_mapping, "job_id")),
                token=UUID(_string(lease_mapping, "token")),
                owner=_string(lease_mapping, "owner"),
                acquired_at=_datetime(lease_mapping, "acquired_at"),
                expires_at=_datetime(lease_mapping, "expires_at"),
                attempt=_integer(lease_mapping, "attempt"),
            )
        context = CapabilityContext(
            principal=_string(context_data, "principal"),
            request_id=None if request_id is None else UUID(request_id),
            correlation_id=_optional_string(context_data, "correlation_id"),
            confirmed=_boolean(context_data, "confirmed"),
            permissions=frozenset(_string_list(context_data, "permissions")),
            metadata=_string_mapping(context_data, "metadata"),
        )
        schedule = JobSchedule(
            run_at=_datetime(schedule_data, "run_at"),
            interval=(None if interval_seconds is None else timedelta(seconds=interval_seconds)),
        )
        retry = RetryPolicy(
            max_attempts=_integer(retry_data, "max_attempts"),
            initial_delay=timedelta(seconds=_number(retry_data, "initial_delay_seconds")),
            multiplier=_number(retry_data, "multiplier"),
            max_delay=(None if max_delay_seconds is None else timedelta(seconds=max_delay_seconds)),
        )
        spec = JobSpec(
            capability=_string(spec_data, "capability"),
            schedule=schedule,
            arguments=_mapping(spec_data, "arguments"),
            context=context,
            retry=retry,
            deadline=_optional_number(spec_data, "deadline"),
            metadata=_string_mapping(spec_data, "metadata"),
        )
        return JobRecord(
            id=UUID(_string(value, "id")),
            spec=spec,
            status=JobStatus(_string(value, "status")),
            created_at=_datetime(value, "created_at"),
            updated_at=_datetime(value, "updated_at"),
            next_run_at=_datetime(value, "next_run_at"),
            attempts=_integer(value, "attempts"),
            lease=lease,
            output=_mapping(value, "output"),
            error=_optional_string(value, "error"),
        )
    except (TypeError, ValueError) as exception:
        raise JobPersistenceError("persisted job record is invalid") from exception


def _mapping(value: Mapping[str, object], key: str) -> Mapping[str, object]:
    return _object_mapping(value.get(key), key)


def _object_mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise ValueError(f"invalid persisted job field: {label}")
    return cast(Mapping[str, object], value)


def _string(value: Mapping[str, object], key: str) -> str:
    result = value.get(key)
    if not isinstance(result, str):
        raise ValueError(f"invalid persisted job field: {key}")
    return result


def _optional_string(value: Mapping[str, object], key: str) -> str | None:
    result = value.get(key)
    if result is None:
        return None
    if not isinstance(result, str):
        raise ValueError(f"invalid persisted job field: {key}")
    return result


def _integer(value: Mapping[str, object], key: str) -> int:
    result = value.get(key)
    if not isinstance(result, int) or isinstance(result, bool):
        raise ValueError(f"invalid persisted job field: {key}")
    return result


def _number(value: Mapping[str, object], key: str) -> float:
    result = value.get(key)
    if not isinstance(result, (int, float)) or isinstance(result, bool):
        raise ValueError(f"invalid persisted job field: {key}")
    return float(result)


def _optional_number(value: Mapping[str, object], key: str) -> float | None:
    result = value.get(key)
    if result is None:
        return None
    if not isinstance(result, (int, float)) or isinstance(result, bool):
        raise ValueError(f"invalid persisted job field: {key}")
    return float(result)


def _boolean(value: Mapping[str, object], key: str) -> bool:
    result = value.get(key)
    if not isinstance(result, bool):
        raise ValueError(f"invalid persisted job field: {key}")
    return result


def _string_list(value: Mapping[str, object], key: str) -> tuple[str, ...]:
    result = value.get(key)
    if not isinstance(result, list) or not all(isinstance(item, str) for item in result):
        raise ValueError(f"invalid persisted job field: {key}")
    return tuple(cast(list[str], result))


def _string_mapping(value: Mapping[str, object], key: str) -> Mapping[str, str]:
    result = _mapping(value, key)
    if not all(isinstance(item, str) for item in result.values()):
        raise ValueError(f"invalid persisted job field: {key}")
    return cast(Mapping[str, str], result)


def _datetime(value: Mapping[str, object], key: str) -> datetime:
    return datetime.fromisoformat(_string(value, key))


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
