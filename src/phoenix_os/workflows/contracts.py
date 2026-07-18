"""Immutable contracts for durable Phoenix workflow graphs."""

from __future__ import annotations

from collections.abc import Awaitable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from types import MappingProxyType
from typing import Protocol
from uuid import UUID, uuid4

from phoenix_os.capabilities import CapabilityContext
from phoenix_os.jobs.contracts import JobId, RetryPolicy
from phoenix_os.workflows.errors import (
    WorkflowCycleError,
    WorkflowDependencyError,
    WorkflowDuplicateStepError,
)

type WorkflowId = UUID
type WorkflowArguments = Mapping[str, object]
type WorkflowOutput = Mapping[str, object]


def _freeze_object_mapping(value: Mapping[str, object]) -> Mapping[str, object]:
    return MappingProxyType(dict(value))


def _freeze_string_mapping(value: Mapping[str, str]) -> Mapping[str, str]:
    normalized = {str(key).strip(): str(item) for key, item in value.items()}
    if any(not key for key in normalized):
        raise ValueError("metadata keys must not be blank")
    return MappingProxyType(normalized)


def _aware(value: datetime, label: str) -> datetime:
    if value.tzinfo is None:
        raise ValueError(f"{label} must be timezone-aware")
    return value


class WorkflowStatus(StrEnum):
    """Stable lifecycle states for one workflow instance."""

    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"

    @property
    def terminal(self) -> bool:
        return self in {self.SUCCEEDED, self.FAILED, self.CANCELLED}


class WorkflowStepStatus(StrEnum):
    """Stable lifecycle states for one workflow step."""

    BLOCKED = "blocked"
    READY = "ready"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"

    @property
    def terminal(self) -> bool:
        return self in {self.SUCCEEDED, self.FAILED, self.CANCELLED}


@dataclass(frozen=True, slots=True)
class WorkflowStep:
    """One capability-backed node in a workflow dependency graph."""

    id: str
    capability: str
    dependencies: frozenset[str] = field(default_factory=frozenset)
    arguments: WorkflowArguments = field(default_factory=dict)
    context: CapabilityContext = field(default_factory=CapabilityContext)
    retry: RetryPolicy = field(default_factory=RetryPolicy)
    deadline: float | None = None
    metadata: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        step_id = self.id.strip()
        capability = self.capability.strip()
        dependencies = frozenset(item.strip() for item in self.dependencies)
        if not step_id:
            raise ValueError("workflow step id must not be blank")
        if not capability:
            raise ValueError("workflow step capability must not be blank")
        if "" in dependencies:
            raise ValueError("workflow dependencies must not contain blank values")
        if step_id in dependencies:
            raise WorkflowDependencyError("workflow step cannot depend on itself")
        if self.deadline is not None and self.deadline <= 0:
            raise ValueError("workflow step deadline must be positive")
        object.__setattr__(self, "id", step_id)
        object.__setattr__(self, "capability", capability)
        object.__setattr__(self, "dependencies", dependencies)
        object.__setattr__(self, "arguments", _freeze_object_mapping(self.arguments))
        object.__setattr__(self, "metadata", _freeze_string_mapping(self.metadata))


@dataclass(frozen=True, slots=True)
class WorkflowDefinition:
    """Immutable validated directed acyclic workflow definition."""

    name: str
    steps: tuple[WorkflowStep, ...]
    version: str = "1"
    metadata: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        name = self.name.strip()
        version = self.version.strip()
        if not name:
            raise ValueError("workflow name must not be blank")
        if not version:
            raise ValueError("workflow version must not be blank")
        if not self.steps:
            raise ValueError("workflow must contain at least one step")
        _validate_graph(self.steps)
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "version", version)
        object.__setattr__(self, "metadata", _freeze_string_mapping(self.metadata))

    def step(self, step_id: str) -> WorkflowStep:
        normalized = step_id.strip()
        for step in self.steps:
            if step.id == normalized:
                return step
        raise WorkflowDependencyError(f"workflow step not found: {normalized}")


@dataclass(frozen=True, slots=True)
class WorkflowStepRecord:
    """Immutable execution state for one workflow step."""

    step_id: str
    status: WorkflowStepStatus
    job_id: JobId | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    output: WorkflowOutput = field(default_factory=dict)
    error: str | None = None

    def __post_init__(self) -> None:
        step_id = self.step_id.strip()
        if not step_id:
            raise ValueError("workflow step record id must not be blank")
        status = WorkflowStepStatus(self.status)
        if self.started_at is not None:
            _aware(self.started_at, "started_at")
        if self.finished_at is not None:
            _aware(self.finished_at, "finished_at")
        if (
            self.started_at is not None
            and self.finished_at is not None
            and self.finished_at < self.started_at
        ):
            raise ValueError("finished_at cannot precede started_at")
        error = None if self.error is None else self.error.strip() or None
        if status is WorkflowStepStatus.RUNNING:
            if self.job_id is None or self.started_at is None or self.finished_at is not None:
                raise ValueError("running workflow step requires job_id and started_at")
        elif status in {WorkflowStepStatus.SUCCEEDED, WorkflowStepStatus.CANCELLED}:
            if self.finished_at is None:
                raise ValueError("terminal workflow step requires finished_at")
        elif status is WorkflowStepStatus.FAILED:
            if self.finished_at is None or error is None:
                raise ValueError("failed workflow step requires finished_at and error")
        elif any(
            value is not None for value in (self.job_id, self.started_at, self.finished_at, error)
        ):
            raise ValueError("blocked and ready workflow steps cannot contain execution state")
        object.__setattr__(self, "step_id", step_id)
        object.__setattr__(self, "status", status)
        object.__setattr__(self, "output", _freeze_object_mapping(self.output))
        object.__setattr__(self, "error", error)


@dataclass(frozen=True, slots=True)
class WorkflowRecord:
    """Complete immutable repository state for one workflow instance."""

    definition: WorkflowDefinition
    status: WorkflowStatus
    created_at: datetime
    updated_at: datetime
    steps: Mapping[str, WorkflowStepRecord]
    id: WorkflowId = field(default_factory=uuid4)
    revision: int = 0
    finished_at: datetime | None = None
    error: str | None = None

    def __post_init__(self) -> None:
        _aware(self.created_at, "created_at")
        _aware(self.updated_at, "updated_at")
        if self.updated_at < self.created_at:
            raise ValueError("updated_at cannot precede created_at")
        if self.finished_at is not None:
            _aware(self.finished_at, "finished_at")
            if self.finished_at < self.created_at:
                raise ValueError("finished_at cannot precede created_at")
        if self.revision < 0:
            raise ValueError("workflow revision cannot be negative")
        status = WorkflowStatus(self.status)
        records = dict(self.steps)
        expected = {step.id for step in self.definition.steps}
        if set(records) != expected:
            raise ValueError("workflow step records must exactly match the definition")
        if any(key != record.step_id for key, record in records.items()):
            raise ValueError("workflow step record key must match its step id")
        error = None if self.error is None else self.error.strip() or None
        if status.terminal and self.finished_at is None:
            raise ValueError("terminal workflow requires finished_at")
        if not status.terminal and self.finished_at is not None:
            raise ValueError("non-terminal workflow cannot have finished_at")
        if status is WorkflowStatus.SUCCEEDED and any(
            record.status is not WorkflowStepStatus.SUCCEEDED for record in records.values()
        ):
            raise ValueError("succeeded workflow requires every step to succeed")
        if status is WorkflowStatus.FAILED:
            if error is None or not any(
                record.status is WorkflowStepStatus.FAILED for record in records.values()
            ):
                raise ValueError("failed workflow requires a failed step and error")
        object.__setattr__(self, "status", status)
        object.__setattr__(self, "steps", MappingProxyType(records))
        object.__setattr__(self, "error", error)


@dataclass(frozen=True, slots=True)
class WorkflowPlan:
    """Deterministic topological ordering grouped into parallel execution levels."""

    ordered_steps: tuple[str, ...]
    levels: tuple[tuple[str, ...], ...]

    def __post_init__(self) -> None:
        flattened = tuple(step_id for level in self.levels for step_id in level)
        if not self.levels or any(not level for level in self.levels):
            raise ValueError("workflow plan levels must not be empty")
        if flattened != self.ordered_steps:
            raise ValueError("workflow plan levels must match ordered_steps")
        if len(set(flattened)) != len(flattened):
            raise ValueError("workflow plan cannot contain duplicate steps")


class WorkflowRepository(Protocol):
    """Optimistic persistence boundary for immutable workflow records."""

    @property
    def closed(self) -> bool: ...

    def add(self, record: WorkflowRecord) -> Awaitable[None]: ...

    def get(self, workflow_id: WorkflowId) -> Awaitable[WorkflowRecord | None]: ...

    def list_all(self) -> Awaitable[tuple[WorkflowRecord, ...]]: ...

    def replace(
        self,
        record: WorkflowRecord,
        *,
        expected_revision: int,
    ) -> Awaitable[WorkflowRecord]: ...

    def close(self) -> Awaitable[None]: ...


def _validate_graph(steps: tuple[WorkflowStep, ...]) -> None:
    identifiers = [step.id for step in steps]
    if len(set(identifiers)) != len(identifiers):
        raise WorkflowDuplicateStepError("workflow step ids must be unique")
    known = set(identifiers)
    for step in steps:
        missing = step.dependencies - known
        if missing:
            raise WorkflowDependencyError(
                f"workflow step {step.id} has missing dependencies: {', '.join(sorted(missing))}"
            )

    remaining = {step.id: set(step.dependencies) for step in steps}
    resolved: set[str] = set()
    while len(resolved) < len(steps):
        ready = [step.id for step in steps if step.id not in resolved and not remaining[step.id]]
        if not ready:
            cyclic = sorted(set(identifiers) - resolved)
            raise WorkflowCycleError(f"workflow dependency cycle: {', '.join(cyclic)}")
        resolved.update(ready)
        for dependencies in remaining.values():
            dependencies.difference_update(ready)
