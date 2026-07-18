"""Deterministic in-memory repository for immutable workflow records."""

from __future__ import annotations

import asyncio
from collections.abc import Iterable

from phoenix_os.workflows.contracts import WorkflowId, WorkflowRecord
from phoenix_os.workflows.errors import (
    WorkflowAlreadyExistsError,
    WorkflowConflictError,
    WorkflowNotFoundError,
    WorkflowRepositoryClosedError,
)


class InMemoryWorkflowRepository:
    """Process-local optimistic workflow repository for tests and ephemeral hosts."""

    def __init__(self) -> None:
        self._records: dict[WorkflowId, WorkflowRecord] = {}
        self._closed = False
        self._lock = asyncio.Lock()

    @property
    def closed(self) -> bool:
        return self._closed

    async def add(self, record: WorkflowRecord) -> None:
        async with self._lock:
            self._ensure_open()
            if record.id in self._records:
                raise WorkflowAlreadyExistsError(f"workflow already exists: {record.id}")
            self._records[record.id] = record

    async def get(self, workflow_id: WorkflowId) -> WorkflowRecord | None:
        async with self._lock:
            self._ensure_open()
            return self._records.get(workflow_id)

    async def list_all(self) -> tuple[WorkflowRecord, ...]:
        async with self._lock:
            self._ensure_open()
            return _sort_records(self._records.values())

    async def replace(
        self,
        record: WorkflowRecord,
        *,
        expected_revision: int,
    ) -> WorkflowRecord:
        if expected_revision < 0:
            raise ValueError("expected_revision cannot be negative")
        async with self._lock:
            self._ensure_open()
            current = self._records.get(record.id)
            if current is None:
                raise WorkflowNotFoundError(f"workflow not found: {record.id}")
            if current.revision != expected_revision:
                raise WorkflowConflictError(
                    f"workflow revision conflict: expected {expected_revision}, "
                    f"found {current.revision}"
                )
            if record.revision != expected_revision + 1:
                raise ValueError("replacement workflow revision must increment by one")
            if record.definition != current.definition or record.created_at != current.created_at:
                raise ValueError("workflow definition and creation time are immutable")
            self._records[record.id] = record
            return record

    async def close(self) -> None:
        async with self._lock:
            self._records.clear()
            self._closed = True

    def _ensure_open(self) -> None:
        if self._closed:
            raise WorkflowRepositoryClosedError("workflow repository is closed")


def _sort_records(records: Iterable[WorkflowRecord]) -> tuple[WorkflowRecord, ...]:
    return tuple(sorted(records, key=lambda item: (item.created_at, str(item.id))))
