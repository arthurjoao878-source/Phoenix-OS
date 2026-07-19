"""Immutable contracts for the read-only Phoenix control plane."""

from __future__ import annotations

from collections import Counter
from collections.abc import Awaitable, Iterable
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Protocol
from uuid import UUID

from phoenix_os.audit import AuditLedgerSnapshot
from phoenix_os.capabilities import CapabilityDescriptor, RiskLevel
from phoenix_os.control_plane.journal_contracts import ControlPlaneCommandJournalSnapshot
from phoenix_os.events import Event
from phoenix_os.jobs import (
    JobRecord,
    JobSchedulerSnapshot,
    JobStatus,
    JobWorkerSnapshot,
)
from phoenix_os.plugins import (
    PluginManagerState,
    PluginManifest,
    PluginSnapshot,
    PluginStatus,
)
from phoenix_os.runtime import RuntimeSnapshot
from phoenix_os.workflows import (
    WorkflowRecord,
    WorkflowStatus,
    WorkflowStepStatus,
    WorkflowWorkerSnapshot,
)

DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 200
DEFAULT_EVENT_BATCH_SIZE = 50
MAX_EVENT_BATCH_SIZE = 200


class ControlPlaneHealth(StrEnum):
    """Coarse non-sensitive health exposed to dashboard clients."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    STOPPED = "stopped"


@dataclass(frozen=True, slots=True)
class PageRequest:
    """Validated offset pagination accepted by local control-plane queries."""

    offset: int = 0
    limit: int = DEFAULT_PAGE_SIZE

    def __post_init__(self) -> None:
        if self.offset < 0:
            raise ValueError("page offset cannot be negative")
        if self.limit <= 0 or self.limit > MAX_PAGE_SIZE:
            raise ValueError(f"page limit must be between 1 and {MAX_PAGE_SIZE}")


DEFAULT_PAGE_REQUEST = PageRequest()


@dataclass(frozen=True, slots=True)
class PageInfo:
    """Stable pagination metadata shared by every detail collection."""

    offset: int
    limit: int
    returned: int
    total: int
    next_offset: int | None

    def __post_init__(self) -> None:
        if self.offset < 0 or self.returned < 0 or self.total < 0:
            raise ValueError("page counters cannot be negative")
        if self.limit <= 0 or self.limit > MAX_PAGE_SIZE:
            raise ValueError(f"page limit must be between 1 and {MAX_PAGE_SIZE}")
        if self.returned > self.limit:
            raise ValueError("page returned count cannot exceed limit")
        if self.returned > self.total:
            raise ValueError("page returned count cannot exceed total")
        expected = self.offset + self.returned
        if self.next_offset is None:
            if expected < self.total:
                raise ValueError("page requires next_offset while more items remain")
        elif self.next_offset != expected or self.next_offset >= self.total:
            raise ValueError("page next_offset is inconsistent")

    @classmethod
    def from_slice(cls, request: PageRequest, *, returned: int, total: int) -> PageInfo:
        next_offset = request.offset + returned
        return cls(
            offset=request.offset,
            limit=request.limit,
            returned=returned,
            total=total,
            next_offset=next_offset if next_offset < total else None,
        )


@dataclass(frozen=True, slots=True)
class EventStreamRequest:
    """Validated cursor and long-poll bounds for dashboard event reads."""

    after: int = 0
    limit: int = DEFAULT_EVENT_BATCH_SIZE
    wait: float = 0.0

    def __post_init__(self) -> None:
        if self.after < 0:
            raise ValueError("event cursor cannot be negative")
        if self.limit <= 0 or self.limit > MAX_EVENT_BATCH_SIZE:
            raise ValueError(f"event limit must be between 1 and {MAX_EVENT_BATCH_SIZE}")
        if self.wait < 0:
            raise ValueError("event wait cannot be negative")


DEFAULT_EVENT_STREAM_REQUEST = EventStreamRequest()


@dataclass(frozen=True, slots=True)
class EventView:
    """Safe Event Bus header with payload and metadata intentionally omitted."""

    sequence: int
    id: UUID
    name: str
    source: str
    occurred_at: datetime
    correlation_id: str | None
    causation_id: UUID | None

    def __post_init__(self) -> None:
        if self.sequence <= 0:
            raise ValueError("event sequence must be positive")
        if not self.name.strip() or not self.source.strip():
            raise ValueError("event name and source must not be blank")
        _require_aware(self.occurred_at, "occurred_at")
        correlation_id = (
            None if self.correlation_id is None else self.correlation_id.strip() or None
        )
        object.__setattr__(self, "name", self.name.strip())
        object.__setattr__(self, "source", self.source.strip())
        object.__setattr__(self, "correlation_id", correlation_id)

    @classmethod
    def from_event(cls, sequence: int, event: Event) -> EventView:
        return cls(
            sequence=sequence,
            id=event.id,
            name=event.name,
            source=event.source,
            occurred_at=event.occurred_at,
            correlation_id=event.correlation_id,
            causation_id=event.causation_id,
        )


@dataclass(frozen=True, slots=True)
class EventBatch:
    """Bounded event-stream response with cursor-gap diagnostics."""

    items: tuple[EventView, ...]
    cursor: int
    oldest_cursor: int | None
    latest_cursor: int | None
    gap: bool
    dropped: int
    timed_out: bool
    schema_version: int = 1

    def __post_init__(self) -> None:
        if self.schema_version != 1:
            raise ValueError("unsupported event batch schema version")
        if self.cursor < 0 or self.dropped < 0:
            raise ValueError("event cursors and counters cannot be negative")
        sequences = tuple(item.sequence for item in self.items)
        if sequences != tuple(sorted(sequences)) or len(set(sequences)) != len(sequences):
            raise ValueError("event batch sequences must be strictly increasing")
        if self.items and self.cursor != self.items[-1].sequence:
            raise ValueError("event batch cursor must match the final item")
        if self.timed_out and self.items:
            raise ValueError("timed out event batch cannot contain items")
        if self.gap != (self.dropped > 0):
            raise ValueError("event batch gap must match dropped count")
        if self.oldest_cursor is None or self.latest_cursor is None:
            if self.oldest_cursor is not None or self.latest_cursor is not None or self.items:
                raise ValueError("empty retention requires empty cursors and items")
        elif self.oldest_cursor <= 0 or self.latest_cursor < self.oldest_cursor:
            raise ValueError("event retention cursors are inconsistent")
        elif any(
            sequence < self.oldest_cursor or sequence > self.latest_cursor for sequence in sequences
        ):
            raise ValueError("event items must fall within retained cursors")


class EventStreamReader(Protocol):
    def read(
        self, request: EventStreamRequest = DEFAULT_EVENT_STREAM_REQUEST
    ) -> Awaitable[EventBatch]: ...


@dataclass(frozen=True, slots=True)
class WorkflowSummary:
    """Aggregate workflow counts without definitions, arguments, or outputs."""

    total: int
    pending: int
    running: int
    succeeded: int
    failed: int
    cancelled: int

    def __post_init__(self) -> None:
        counts = (
            self.total,
            self.pending,
            self.running,
            self.succeeded,
            self.failed,
            self.cancelled,
        )
        if any(value < 0 for value in counts):
            raise ValueError("workflow summary counts cannot be negative")
        states = self.pending + self.running + self.succeeded + self.failed + self.cancelled
        if states != self.total:
            raise ValueError("workflow state counts must equal total")

    @classmethod
    def from_records(cls, records: Iterable[WorkflowRecord]) -> WorkflowSummary:
        """Build a deterministic aggregate from immutable workflow records."""

        materialized = tuple(records)
        counts = Counter(record.status for record in materialized)
        return cls(
            total=len(materialized),
            pending=counts[WorkflowStatus.PENDING],
            running=counts[WorkflowStatus.RUNNING],
            succeeded=counts[WorkflowStatus.SUCCEEDED],
            failed=counts[WorkflowStatus.FAILED],
            cancelled=counts[WorkflowStatus.CANCELLED],
        )


@dataclass(frozen=True, slots=True)
class JobView:
    """Allowlisted job fields safe for an authenticated local dashboard."""

    id: UUID
    capability: str
    status: JobStatus
    attempts: int
    max_attempts: int
    recurring: bool
    created_at: datetime
    updated_at: datetime
    next_run_at: datetime
    has_error: bool

    def __post_init__(self) -> None:
        if not self.capability.strip():
            raise ValueError("job capability must not be blank")
        if self.attempts < 0 or self.max_attempts <= 0 or self.attempts > self.max_attempts:
            raise ValueError("invalid job attempt counters")
        _require_aware(self.created_at, "created_at")
        _require_aware(self.updated_at, "updated_at")
        _require_aware(self.next_run_at, "next_run_at")
        object.__setattr__(self, "capability", self.capability.strip())
        object.__setattr__(self, "status", JobStatus(self.status))

    @classmethod
    def from_record(cls, record: JobRecord) -> JobView:
        return cls(
            id=record.id,
            capability=record.spec.capability,
            status=record.status,
            attempts=record.attempts,
            max_attempts=record.spec.retry.max_attempts,
            recurring=record.spec.schedule.recurring,
            created_at=record.created_at,
            updated_at=record.updated_at,
            next_run_at=record.next_run_at,
            has_error=record.error is not None,
        )


@dataclass(frozen=True, slots=True)
class JobPage:
    items: tuple[JobView, ...]
    page: PageInfo

    def __post_init__(self) -> None:
        _validate_page_items(self.items, self.page)


@dataclass(frozen=True, slots=True)
class WorkflowStepView:
    """Safe workflow step progress without arguments, outputs, or metadata."""

    id: str
    status: WorkflowStepStatus
    job_id: UUID | None
    started_at: datetime | None
    finished_at: datetime | None
    has_error: bool

    def __post_init__(self) -> None:
        if not self.id.strip():
            raise ValueError("workflow step id must not be blank")
        if self.started_at is not None:
            _require_aware(self.started_at, "started_at")
        if self.finished_at is not None:
            _require_aware(self.finished_at, "finished_at")
        object.__setattr__(self, "id", self.id.strip())
        object.__setattr__(self, "status", WorkflowStepStatus(self.status))


@dataclass(frozen=True, slots=True)
class WorkflowView:
    """Allowlisted workflow identity and progress for dashboard clients."""

    id: UUID
    name: str
    version: str
    status: WorkflowStatus
    revision: int
    created_at: datetime
    updated_at: datetime
    finished_at: datetime | None
    completed_steps: int
    total_steps: int
    steps: tuple[WorkflowStepView, ...]
    has_error: bool

    def __post_init__(self) -> None:
        if not self.name.strip() or not self.version.strip():
            raise ValueError("workflow name and version must not be blank")
        if self.revision < 0:
            raise ValueError("workflow revision cannot be negative")
        if self.completed_steps < 0 or self.total_steps <= 0:
            raise ValueError("invalid workflow step counters")
        if self.completed_steps > self.total_steps or len(self.steps) != self.total_steps:
            raise ValueError("workflow step counters must match items")
        _require_aware(self.created_at, "created_at")
        _require_aware(self.updated_at, "updated_at")
        if self.finished_at is not None:
            _require_aware(self.finished_at, "finished_at")
        object.__setattr__(self, "name", self.name.strip())
        object.__setattr__(self, "version", self.version.strip())
        object.__setattr__(self, "status", WorkflowStatus(self.status))

    @classmethod
    def from_record(cls, record: WorkflowRecord) -> WorkflowView:
        steps = tuple(
            WorkflowStepView(
                id=step.id,
                status=record.steps[step.id].status,
                job_id=record.steps[step.id].job_id,
                started_at=record.steps[step.id].started_at,
                finished_at=record.steps[step.id].finished_at,
                has_error=record.steps[step.id].error is not None,
            )
            for step in record.definition.steps
        )
        completed = sum(step.status.terminal for step in steps)
        return cls(
            id=record.id,
            name=record.definition.name,
            version=record.definition.version,
            status=record.status,
            revision=record.revision,
            created_at=record.created_at,
            updated_at=record.updated_at,
            finished_at=record.finished_at,
            completed_steps=completed,
            total_steps=len(steps),
            steps=steps,
            has_error=record.error is not None,
        )


@dataclass(frozen=True, slots=True)
class WorkflowPage:
    items: tuple[WorkflowView, ...]
    page: PageInfo

    def __post_init__(self) -> None:
        _validate_page_items(self.items, self.page)


@dataclass(frozen=True, slots=True)
class CapabilityView:
    """Static capability metadata safe for administrative discovery."""

    name: str
    description: str
    version: str
    risk: RiskLevel
    required_permissions: tuple[str, ...]
    confirmation_required: bool
    default_timeout: float | None
    tags: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.name.strip() or not self.version.strip():
            raise ValueError("capability name and version must not be blank")
        if self.default_timeout is not None and self.default_timeout <= 0:
            raise ValueError("capability timeout must be positive")
        object.__setattr__(self, "name", self.name.strip())
        object.__setattr__(self, "description", self.description.strip())
        object.__setattr__(self, "version", self.version.strip())
        object.__setattr__(self, "risk", RiskLevel(self.risk))

    @classmethod
    def from_descriptor(cls, descriptor: CapabilityDescriptor) -> CapabilityView:
        return cls(
            name=descriptor.name,
            description=descriptor.description,
            version=descriptor.version,
            risk=descriptor.risk,
            required_permissions=tuple(sorted(descriptor.required_permissions)),
            confirmation_required=descriptor.confirmation_required,
            default_timeout=descriptor.default_timeout,
            tags=tuple(sorted(descriptor.tags)),
        )


@dataclass(frozen=True, slots=True)
class CapabilityPage:
    items: tuple[CapabilityView, ...]
    page: PageInfo

    def __post_init__(self) -> None:
        _validate_page_items(self.items, self.page)


@dataclass(frozen=True, slots=True)
class PluginView:
    """Plugin manifest and lifecycle state without arbitrary metadata."""

    plugin_id: str
    name: str
    version: str
    api_version: int
    status: PluginStatus
    dependencies: tuple[str, ...]
    permissions: tuple[str, ...]
    capability_exports: int
    state_store_exports: int
    service_exports: int
    has_failure: bool

    def __post_init__(self) -> None:
        if not self.plugin_id.strip() or not self.name.strip() or not self.version.strip():
            raise ValueError("plugin identity fields must not be blank")
        counts = (
            self.api_version,
            self.capability_exports,
            self.state_store_exports,
            self.service_exports,
        )
        if self.api_version <= 0 or any(value < 0 for value in counts[1:]):
            raise ValueError("invalid plugin API version or export counts")
        object.__setattr__(self, "plugin_id", self.plugin_id.strip())
        object.__setattr__(self, "name", self.name.strip())
        object.__setattr__(self, "version", self.version.strip())
        object.__setattr__(self, "status", PluginStatus(self.status))

    @classmethod
    def from_manifest(
        cls,
        manifest: PluginManifest,
        snapshot: PluginSnapshot,
    ) -> PluginView:
        plugin_id = manifest.plugin_id
        failures = {failure.plugin_id for failure in snapshot.failures}
        if plugin_id in failures:
            status = PluginStatus.FAILED
        elif plugin_id in snapshot.active:
            status = PluginStatus.ACTIVE
        elif plugin_id in snapshot.prepared:
            status = PluginStatus.PREPARED
        elif snapshot.state is PluginManagerState.STOPPED:
            status = PluginStatus.STOPPED
        else:
            status = PluginStatus.REGISTERED
        return cls(
            plugin_id=plugin_id,
            name=manifest.name,
            version=str(manifest.version),
            api_version=manifest.api_version,
            status=status,
            dependencies=tuple(sorted(item.plugin_id for item in manifest.dependencies)),
            permissions=tuple(sorted(item.value for item in manifest.permissions)),
            capability_exports=len(manifest.exports.capabilities),
            state_store_exports=len(manifest.exports.state_stores),
            service_exports=len(manifest.exports.services),
            has_failure=plugin_id in failures,
        )


@dataclass(frozen=True, slots=True)
class PluginPage:
    items: tuple[PluginView, ...]
    page: PageInfo

    def __post_init__(self) -> None:
        _validate_page_items(self.items, self.page)


@dataclass(frozen=True, slots=True)
class AuditSummary:
    """Non-sensitive audit counters; record bodies and chain digests stay private."""

    closed: bool
    records: int
    head_sequence: int | None
    signed_records: int
    appended: int
    reads: int
    verifications: int
    verification_failures: int
    denied_operations: int

    def __post_init__(self) -> None:
        counters = (
            self.records,
            self.signed_records,
            self.appended,
            self.reads,
            self.verifications,
            self.verification_failures,
            self.denied_operations,
        )
        if any(value < 0 for value in counters):
            raise ValueError("audit summary counters cannot be negative")
        if self.signed_records > self.records:
            raise ValueError("signed audit records cannot exceed total records")
        if self.records == 0 and self.head_sequence is not None:
            raise ValueError("empty audit summary cannot have a head sequence")
        if self.records > 0 and self.head_sequence is None:
            raise ValueError("non-empty audit summary requires a head sequence")

    @classmethod
    def from_snapshot(cls, snapshot: AuditLedgerSnapshot) -> AuditSummary:
        return cls(
            closed=snapshot.closed,
            records=snapshot.records,
            head_sequence=snapshot.head_sequence,
            signed_records=snapshot.signed_records,
            appended=snapshot.appended,
            reads=snapshot.reads,
            verifications=snapshot.verifications,
            verification_failures=snapshot.verification_failures,
            denied_operations=snapshot.denied_operations,
        )


@dataclass(frozen=True, slots=True)
class ControlPlaneSnapshot:
    """Versioned read-only snapshot consumed by dashboard transports."""

    generated_at: datetime
    health: ControlPlaneHealth
    runtime: RuntimeSnapshot
    jobs: JobSchedulerSnapshot
    workflows: WorkflowSummary
    job_worker: JobWorkerSnapshot | None = None
    workflow_worker: WorkflowWorkerSnapshot | None = None
    command_journal: ControlPlaneCommandJournalSnapshot | None = None
    schema_version: int = 1

    def __post_init__(self) -> None:
        _require_aware(self.generated_at, "generated_at")
        if self.schema_version != 1:
            raise ValueError("unsupported control plane schema version")
        object.__setattr__(self, "health", ControlPlaneHealth(self.health))


class RuntimeSnapshotSource(Protocol):
    def snapshot(self) -> Awaitable[RuntimeSnapshot]: ...


class JobSnapshotSource(Protocol):
    def snapshot(self) -> Awaitable[JobSchedulerSnapshot]: ...


class JobRecordSource(Protocol):
    def list_all(self) -> Awaitable[tuple[JobRecord, ...]]: ...


class WorkflowSnapshotSource(Protocol):
    def list_all(self) -> Awaitable[tuple[WorkflowRecord, ...]]: ...


class CapabilitySnapshotSource(Protocol):
    def list_descriptors(self) -> Awaitable[tuple[CapabilityDescriptor, ...]]: ...


class PluginSnapshotSource(Protocol):
    def list_manifests(self) -> Awaitable[tuple[PluginManifest, ...]]: ...

    def snapshot(self) -> Awaitable[PluginSnapshot]: ...


class AuditSnapshotSource(Protocol):
    def snapshot(self) -> Awaitable[AuditLedgerSnapshot]: ...


class JobWorkerSnapshotSource(Protocol):
    def snapshot(self) -> Awaitable[JobWorkerSnapshot]: ...


class WorkflowWorkerSnapshotSource(Protocol):
    def snapshot(self) -> Awaitable[WorkflowWorkerSnapshot]: ...


class ControlPlaneReader(Protocol):
    """Read-only query API that transports may expose after authorization."""

    def snapshot(self) -> Awaitable[ControlPlaneSnapshot]: ...

    def list_jobs(self, page: PageRequest = DEFAULT_PAGE_REQUEST) -> Awaitable[JobPage]: ...

    def list_workflows(
        self, page: PageRequest = DEFAULT_PAGE_REQUEST
    ) -> Awaitable[WorkflowPage]: ...

    def list_capabilities(
        self, page: PageRequest = DEFAULT_PAGE_REQUEST
    ) -> Awaitable[CapabilityPage]: ...

    def list_plugins(self, page: PageRequest = DEFAULT_PAGE_REQUEST) -> Awaitable[PluginPage]: ...

    def audit_summary(self) -> Awaitable[AuditSummary | None]: ...


def _require_aware(value: datetime, label: str) -> None:
    if value.tzinfo is None:
        raise ValueError(f"{label} must be timezone-aware")


def _validate_page_items(items: tuple[object, ...], page: PageInfo) -> None:
    if len(items) != page.returned:
        raise ValueError("page returned count must match items")
