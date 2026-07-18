"""Durable workflow repository backed by the provider-neutral Phoenix StateStore."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta
from typing import cast
from uuid import UUID

from phoenix_os.capabilities import CapabilityContext
from phoenix_os.jobs import RetryPolicy
from phoenix_os.policy import PrincipalType
from phoenix_os.state import (
    ABSENT_VERSION,
    StateConflictError,
    StateKey,
    StateOperationContext,
    StateStore,
)
from phoenix_os.workflows.contracts import (
    WorkflowDefinition,
    WorkflowId,
    WorkflowRecord,
    WorkflowStatus,
    WorkflowStep,
    WorkflowStepRecord,
    WorkflowStepStatus,
)
from phoenix_os.workflows.errors import (
    WorkflowAlreadyExistsError,
    WorkflowConflictError,
    WorkflowNotFoundError,
    WorkflowPersistenceError,
    WorkflowRepositoryClosedError,
)

_SCHEMA_VERSION = 1


class StateWorkflowRepository:
    """Persist immutable workflow records through optimistic StateStore writes."""

    def __init__(
        self,
        store: StateStore,
        *,
        namespace: str = "workflows",
        context: StateOperationContext | None = None,
    ) -> None:
        probe = StateKey(namespace, "workflow", dict)
        self._store = store
        self._namespace = probe.namespace
        self._context = context or StateOperationContext(
            metadata={
                "principal": "phoenix.workflows",
                "principal_type": PrincipalType.SYSTEM.value,
                "authenticated": "true",
            }
        )
        self._closed = False

    @property
    def closed(self) -> bool:
        return self._closed

    async def add(self, record: WorkflowRecord) -> None:
        self._ensure_open()
        try:
            await self._store.put(
                self._key(record.id),
                _encode_record(record),
                expected_version=ABSENT_VERSION,
                context=self._context,
            )
        except StateConflictError as exception:
            raise WorkflowAlreadyExistsError(f"workflow already exists: {record.id}") from exception

    async def get(self, workflow_id: WorkflowId) -> WorkflowRecord | None:
        self._ensure_open()
        stored = await self._store.get(self._key(workflow_id), context=self._context)
        return None if stored is None else _decode_record(stored.value)

    async def list_all(self) -> tuple[WorkflowRecord, ...]:
        self._ensure_open()
        stored = await self._store.list(namespace=self._namespace, context=self._context)
        records = [_decode_record(_object_mapping(item.value, "record")) for item in stored]
        return _sort_records(records)

    async def replace(
        self,
        record: WorkflowRecord,
        *,
        expected_revision: int,
    ) -> WorkflowRecord:
        self._ensure_open()
        if expected_revision < 0:
            raise ValueError("expected_revision cannot be negative")
        key = self._key(record.id)
        try:
            async with self._store.transaction(context=self._context) as transaction:
                stored = await transaction.get(key)
                if stored is None:
                    raise WorkflowNotFoundError(f"workflow not found: {record.id}")
                current = _decode_record(stored.value)
                if current.revision != expected_revision:
                    raise WorkflowConflictError(
                        f"workflow revision conflict: expected {expected_revision}, "
                        f"found {current.revision}"
                    )
                _validate_replacement(current, record, expected_revision)
                await transaction.put(
                    key,
                    _encode_record(record),
                    expected_version=stored.version,
                )
        except StateConflictError as exception:
            raise WorkflowConflictError("workflow state changed concurrently") from exception
        return record

    async def close(self) -> None:
        # The repository borrows the StateStore; Runtime owns the store lifecycle.
        self._closed = True

    def _key(self, workflow_id: WorkflowId) -> StateKey[dict[str, object]]:
        return StateKey(self._namespace, f"w_{workflow_id.hex}", dict)

    def _ensure_open(self) -> None:
        if self._closed:
            raise WorkflowRepositoryClosedError("workflow repository is closed")


def _validate_replacement(
    current: WorkflowRecord,
    replacement: WorkflowRecord,
    expected_revision: int,
) -> None:
    if replacement.revision != expected_revision + 1:
        raise ValueError("replacement workflow revision must increment by one")
    if replacement.definition != current.definition:
        raise ValueError("workflow definition is immutable")
    if replacement.created_at != current.created_at:
        raise ValueError("workflow creation time is immutable")


def _encode_record(record: WorkflowRecord) -> dict[str, object]:
    return {
        "schema_version": _SCHEMA_VERSION,
        "id": str(record.id),
        "status": record.status.value,
        "created_at": record.created_at.isoformat(),
        "updated_at": record.updated_at.isoformat(),
        "finished_at": None if record.finished_at is None else record.finished_at.isoformat(),
        "revision": record.revision,
        "error": record.error,
        "definition": _encode_definition(record.definition),
        "steps": [_encode_step_record(record.steps[step.id]) for step in record.definition.steps],
    }


def _encode_definition(definition: WorkflowDefinition) -> dict[str, object]:
    return {
        "name": definition.name,
        "version": definition.version,
        "metadata": dict(definition.metadata),
        "steps": [_encode_step(step) for step in definition.steps],
    }


def _encode_step(step: WorkflowStep) -> dict[str, object]:
    context = step.context
    retry = step.retry
    return {
        "id": step.id,
        "capability": step.capability,
        "dependencies": sorted(step.dependencies),
        "arguments": dict(step.arguments),
        "deadline": step.deadline,
        "metadata": dict(step.metadata),
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
    }


def _encode_step_record(record: WorkflowStepRecord) -> dict[str, object]:
    return {
        "step_id": record.step_id,
        "status": record.status.value,
        "job_id": None if record.job_id is None else str(record.job_id),
        "started_at": None if record.started_at is None else record.started_at.isoformat(),
        "finished_at": None if record.finished_at is None else record.finished_at.isoformat(),
        "output": dict(record.output),
        "error": record.error,
    }


def _decode_record(value: Mapping[str, object]) -> WorkflowRecord:
    try:
        if _integer(value, "schema_version") != _SCHEMA_VERSION:
            raise ValueError("unsupported persisted workflow schema version")
        definition = _decode_definition(_mapping(value, "definition"))
        step_values = _mapping_list(value, "steps")
        step_records = tuple(_decode_step_record(item) for item in step_values)
        steps = {record.step_id: record for record in step_records}
        return WorkflowRecord(
            id=UUID(_string(value, "id")),
            definition=definition,
            status=WorkflowStatus(_string(value, "status")),
            created_at=_datetime(value, "created_at"),
            updated_at=_datetime(value, "updated_at"),
            finished_at=_optional_datetime(value, "finished_at"),
            revision=_integer(value, "revision"),
            error=_optional_string(value, "error"),
            steps=steps,
        )
    except (TypeError, ValueError) as exception:
        raise WorkflowPersistenceError("persisted workflow record is invalid") from exception


def _decode_definition(value: Mapping[str, object]) -> WorkflowDefinition:
    steps = tuple(_decode_step(item) for item in _mapping_list(value, "steps"))
    return WorkflowDefinition(
        name=_string(value, "name"),
        version=_string(value, "version"),
        metadata=_string_mapping(value, "metadata"),
        steps=steps,
    )


def _decode_step(value: Mapping[str, object]) -> WorkflowStep:
    retry_data = _mapping(value, "retry")
    context_data = _mapping(value, "context")
    max_delay_seconds = _optional_number(retry_data, "max_delay_seconds")
    request_id = _optional_string(context_data, "request_id")
    context = CapabilityContext(
        principal=_string(context_data, "principal"),
        request_id=None if request_id is None else UUID(request_id),
        correlation_id=_optional_string(context_data, "correlation_id"),
        confirmed=_boolean(context_data, "confirmed"),
        permissions=frozenset(_string_list(context_data, "permissions")),
        metadata=_string_mapping(context_data, "metadata"),
    )
    retry = RetryPolicy(
        max_attempts=_integer(retry_data, "max_attempts"),
        initial_delay=timedelta(seconds=_number(retry_data, "initial_delay_seconds")),
        multiplier=_number(retry_data, "multiplier"),
        max_delay=(None if max_delay_seconds is None else timedelta(seconds=max_delay_seconds)),
    )
    return WorkflowStep(
        id=_string(value, "id"),
        capability=_string(value, "capability"),
        dependencies=frozenset(_string_list(value, "dependencies")),
        arguments=_mapping(value, "arguments"),
        context=context,
        retry=retry,
        deadline=_optional_number(value, "deadline"),
        metadata=_string_mapping(value, "metadata"),
    )


def _decode_step_record(value: Mapping[str, object]) -> WorkflowStepRecord:
    job_id = _optional_string(value, "job_id")
    return WorkflowStepRecord(
        step_id=_string(value, "step_id"),
        status=WorkflowStepStatus(_string(value, "status")),
        job_id=None if job_id is None else UUID(job_id),
        started_at=_optional_datetime(value, "started_at"),
        finished_at=_optional_datetime(value, "finished_at"),
        output=_mapping(value, "output"),
        error=_optional_string(value, "error"),
    )


def _mapping(value: Mapping[str, object], key: str) -> Mapping[str, object]:
    return _object_mapping(value.get(key), key)


def _object_mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise ValueError(f"invalid persisted workflow field: {label}")
    return cast(Mapping[str, object], value)


def _mapping_list(
    value: Mapping[str, object],
    key: str,
) -> tuple[Mapping[str, object], ...]:
    result = value.get(key)
    if not isinstance(result, list):
        raise ValueError(f"invalid persisted workflow field: {key}")
    return tuple(_object_mapping(item, key) for item in result)


def _string(value: Mapping[str, object], key: str) -> str:
    result = value.get(key)
    if not isinstance(result, str):
        raise ValueError(f"invalid persisted workflow field: {key}")
    return result


def _optional_string(value: Mapping[str, object], key: str) -> str | None:
    result = value.get(key)
    if result is None:
        return None
    if not isinstance(result, str):
        raise ValueError(f"invalid persisted workflow field: {key}")
    return result


def _integer(value: Mapping[str, object], key: str) -> int:
    result = value.get(key)
    if not isinstance(result, int) or isinstance(result, bool):
        raise ValueError(f"invalid persisted workflow field: {key}")
    return result


def _number(value: Mapping[str, object], key: str) -> float:
    result = value.get(key)
    if not isinstance(result, (int, float)) or isinstance(result, bool):
        raise ValueError(f"invalid persisted workflow field: {key}")
    return float(result)


def _optional_number(value: Mapping[str, object], key: str) -> float | None:
    result = value.get(key)
    if result is None:
        return None
    if not isinstance(result, (int, float)) or isinstance(result, bool):
        raise ValueError(f"invalid persisted workflow field: {key}")
    return float(result)


def _boolean(value: Mapping[str, object], key: str) -> bool:
    result = value.get(key)
    if not isinstance(result, bool):
        raise ValueError(f"invalid persisted workflow field: {key}")
    return result


def _string_list(value: Mapping[str, object], key: str) -> tuple[str, ...]:
    result = value.get(key)
    if not isinstance(result, list) or not all(isinstance(item, str) for item in result):
        raise ValueError(f"invalid persisted workflow field: {key}")
    return tuple(cast(list[str], result))


def _string_mapping(value: Mapping[str, object], key: str) -> Mapping[str, str]:
    result = _mapping(value, key)
    if not all(isinstance(item, str) for item in result.values()):
        raise ValueError(f"invalid persisted workflow field: {key}")
    return cast(Mapping[str, str], result)


def _datetime(value: Mapping[str, object], key: str) -> datetime:
    return datetime.fromisoformat(_string(value, key))


def _optional_datetime(value: Mapping[str, object], key: str) -> datetime | None:
    raw = _optional_string(value, key)
    return None if raw is None else datetime.fromisoformat(raw)


def _sort_records(records: Iterable[WorkflowRecord]) -> tuple[WorkflowRecord, ...]:
    return tuple(sorted(records, key=lambda item: (item.created_at, str(item.id))))
