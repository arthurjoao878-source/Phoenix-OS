"""Safe snapshot and paginated query collection for the Phoenix dashboard."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from datetime import UTC, datetime

from phoenix_os.control_plane.contracts import (
    DEFAULT_PAGE_REQUEST,
    AuditSnapshotSource,
    AuditSummary,
    CapabilityPage,
    CapabilitySnapshotSource,
    CapabilityView,
    ControlPlaneHealth,
    ControlPlaneSnapshot,
    JobPage,
    JobRecordSource,
    JobSnapshotSource,
    JobView,
    JobWorkerSnapshotSource,
    PageInfo,
    PageRequest,
    PluginPage,
    PluginSnapshotSource,
    PluginView,
    RuntimeSnapshotSource,
    WorkflowPage,
    WorkflowSnapshotSource,
    WorkflowSummary,
    WorkflowView,
    WorkflowWorkerSnapshotSource,
)
from phoenix_os.jobs import JobSchedulerSnapshot, JobWorkerSnapshot
from phoenix_os.runtime import RuntimeSnapshot, RuntimeState
from phoenix_os.workflows import WorkflowWorkerSnapshot

type ControlPlaneClock = Callable[[], datetime]


def _utc_now() -> datetime:
    return datetime.now(UTC)


class ControlPlaneService:
    """Collect bounded, deterministic views without operational payloads."""

    def __init__(
        self,
        runtime: RuntimeSnapshotSource,
        jobs: JobSnapshotSource,
        workflows: WorkflowSnapshotSource,
        *,
        job_records: JobRecordSource | None = None,
        capabilities: CapabilitySnapshotSource | None = None,
        plugins: PluginSnapshotSource | None = None,
        audit: AuditSnapshotSource | None = None,
        job_worker: JobWorkerSnapshotSource | None = None,
        workflow_worker: WorkflowWorkerSnapshotSource | None = None,
        clock: ControlPlaneClock = _utc_now,
    ) -> None:
        if not callable(clock):
            raise TypeError("clock must be callable")
        self._runtime = runtime
        self._jobs = jobs
        self._job_records = job_records
        self._workflows = workflows
        self._capabilities = capabilities
        self._plugins = plugins
        self._audit = audit
        self._job_worker = job_worker
        self._workflow_worker = workflow_worker
        self._clock = clock

    async def snapshot(self) -> ControlPlaneSnapshot:
        """Return one consistent, non-sensitive dashboard snapshot."""

        generated_at = self._clock()
        if generated_at.tzinfo is None:
            raise ValueError("control plane clock must return a timezone-aware datetime")

        runtime = await self._runtime.snapshot()
        jobs = await self._jobs.snapshot()
        workflows = WorkflowSummary.from_records(await self._workflows.list_all())
        job_worker = None if self._job_worker is None else await self._job_worker.snapshot()
        workflow_worker = (
            None if self._workflow_worker is None else await self._workflow_worker.snapshot()
        )
        health = _derive_health(runtime, jobs, workflows, job_worker, workflow_worker)
        return ControlPlaneSnapshot(
            generated_at=generated_at,
            health=health,
            runtime=runtime,
            jobs=jobs,
            workflows=workflows,
            job_worker=job_worker,
            workflow_worker=workflow_worker,
        )

    async def list_jobs(self, page: PageRequest = DEFAULT_PAGE_REQUEST) -> JobPage:
        """Return recent jobs without arguments, contexts, outputs, or error messages."""

        if self._job_records is None:
            return JobPage((), PageInfo.from_slice(page, returned=0, total=0))
        records = sorted(
            await self._job_records.list_all(),
            key=lambda record: (record.updated_at, str(record.id)),
            reverse=True,
        )
        items = tuple(JobView.from_record(record) for record in _slice(records, page))
        return JobPage(items, PageInfo.from_slice(page, returned=len(items), total=len(records)))

    async def list_workflows(self, page: PageRequest = DEFAULT_PAGE_REQUEST) -> WorkflowPage:
        """Return recent workflow progress without definitions or execution payloads."""

        records = sorted(
            await self._workflows.list_all(),
            key=lambda record: (record.updated_at, str(record.id)),
            reverse=True,
        )
        items = tuple(WorkflowView.from_record(record) for record in _slice(records, page))
        return WorkflowPage(
            items,
            PageInfo.from_slice(page, returned=len(items), total=len(records)),
        )

    async def list_capabilities(self, page: PageRequest = DEFAULT_PAGE_REQUEST) -> CapabilityPage:
        """Return sorted static capability descriptors."""

        if self._capabilities is None:
            return CapabilityPage((), PageInfo.from_slice(page, returned=0, total=0))
        descriptors = sorted(
            await self._capabilities.list_descriptors(),
            key=lambda descriptor: descriptor.name,
        )
        items = tuple(
            CapabilityView.from_descriptor(descriptor) for descriptor in _slice(descriptors, page)
        )
        return CapabilityPage(
            items,
            PageInfo.from_slice(page, returned=len(items), total=len(descriptors)),
        )

    async def list_plugins(self, page: PageRequest = DEFAULT_PAGE_REQUEST) -> PluginPage:
        """Return sorted plugin identity, declarations, and coarse lifecycle state."""

        if self._plugins is None:
            return PluginPage((), PageInfo.from_slice(page, returned=0, total=0))
        manifests = sorted(
            await self._plugins.list_manifests(),
            key=lambda manifest: manifest.plugin_id,
        )
        snapshot = await self._plugins.snapshot()
        items = tuple(
            PluginView.from_manifest(manifest, snapshot) for manifest in _slice(manifests, page)
        )
        return PluginPage(
            items,
            PageInfo.from_slice(page, returned=len(items), total=len(manifests)),
        )

    async def audit_summary(self) -> AuditSummary | None:
        """Return audit counters while withholding records and cryptographic digests."""

        if self._audit is None:
            return None
        return AuditSummary.from_snapshot(await self._audit.snapshot())


def _slice[T](items: Sequence[T], page: PageRequest) -> Sequence[T]:
    return items[page.offset : page.offset + page.limit]


def _derive_health(
    runtime: RuntimeSnapshot,
    jobs: JobSchedulerSnapshot,
    workflows: WorkflowSummary,
    job_worker: JobWorkerSnapshot | None,
    workflow_worker: WorkflowWorkerSnapshot | None,
) -> ControlPlaneHealth:
    if runtime.state in {RuntimeState.CREATED, RuntimeState.STOPPED}:
        return ControlPlaneHealth.STOPPED
    if runtime.state is not RuntimeState.RUNNING:
        return ControlPlaneHealth.DEGRADED
    if jobs.dead_letter > 0 or workflows.failed > 0:
        return ControlPlaneHealth.DEGRADED
    if job_worker is not None and (job_worker.failures > 0 or job_worker.last_error is not None):
        return ControlPlaneHealth.DEGRADED
    if workflow_worker is not None and (
        workflow_worker.failures > 0 or workflow_worker.last_error is not None
    ):
        return ControlPlaneHealth.DEGRADED
    return ControlPlaneHealth.HEALTHY
