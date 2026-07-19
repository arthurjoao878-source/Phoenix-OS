"""Runtime assembly helpers for the local Phoenix control plane."""

from __future__ import annotations

from dataclasses import dataclass

from phoenix_os.capabilities import CapabilityRegistry
from phoenix_os.control_plane.auth import AdminTokenAuthenticator
from phoenix_os.control_plane.contracts import (
    AuditSnapshotSource,
    JobRecordSource,
    JobSnapshotSource,
    JobWorkerSnapshotSource,
    PluginSnapshotSource,
    RuntimeSnapshotSource,
    WorkflowSnapshotSource,
    WorkflowWorkerSnapshotSource,
)
from phoenix_os.control_plane.event_stream import (
    ControlPlaneEventStream,
    ControlPlaneEventStreamConfig,
)
from phoenix_os.control_plane.http import ControlPlaneHttpConfig, ControlPlaneHttpServer
from phoenix_os.control_plane.service import ControlPlaneService
from phoenix_os.events import EventBus
from phoenix_os.jobs import JobSchedulerSnapshot
from phoenix_os.runtime import PhoenixRuntime, RuntimeSnapshot
from phoenix_os.workflows import WorkflowRecord


class _RuntimeSnapshotProxy:
    def __init__(self) -> None:
        self._runtime: RuntimeSnapshotSource | None = None

    def bind(self, runtime: RuntimeSnapshotSource) -> None:
        if self._runtime is not None:
            raise RuntimeError("control plane runtime source is already bound")
        self._runtime = runtime

    async def snapshot(self) -> RuntimeSnapshot:
        if self._runtime is None:
            raise RuntimeError("control plane runtime source is not bound")
        return await self._runtime.snapshot()


class _EmptyJobSource:
    async def snapshot(self) -> JobSchedulerSnapshot:
        return JobSchedulerSnapshot(
            closed=False,
            jobs=0,
            scheduled=0,
            running=0,
            retrying=0,
            succeeded=0,
            cancelled=0,
            dead_letter=0,
            runs=0,
        )


class _EmptyWorkflowSource:
    async def list_all(self) -> tuple[WorkflowRecord, ...]:
        return ()


@dataclass(frozen=True, slots=True)
class ControlPlaneRuntimeStack:
    """Control-plane services constructed before the Runtime self-reference exists."""

    service: ControlPlaneService
    events: ControlPlaneEventStream
    http: ControlPlaneHttpServer
    _runtime: _RuntimeSnapshotProxy

    @classmethod
    def create(
        cls,
        *,
        event_bus: EventBus,
        capabilities: CapabilityRegistry,
        authenticator: AdminTokenAuthenticator,
        jobs: JobSnapshotSource | None = None,
        job_records: JobRecordSource | None = None,
        workflows: WorkflowSnapshotSource | None = None,
        plugins: PluginSnapshotSource | None = None,
        audit: AuditSnapshotSource | None = None,
        job_worker: JobWorkerSnapshotSource | None = None,
        workflow_worker: WorkflowWorkerSnapshotSource | None = None,
        http_config: ControlPlaneHttpConfig | None = None,
        event_config: ControlPlaneEventStreamConfig | None = None,
    ) -> ControlPlaneRuntimeStack:
        runtime = _RuntimeSnapshotProxy()
        service = ControlPlaneService(
            runtime,
            _EmptyJobSource() if jobs is None else jobs,
            _EmptyWorkflowSource() if workflows is None else workflows,
            job_records=job_records,
            capabilities=capabilities,
            plugins=plugins,
            audit=audit,
            job_worker=job_worker,
            workflow_worker=workflow_worker,
        )
        event_stream = ControlPlaneEventStream(event_bus, config=event_config)
        http = ControlPlaneHttpServer(
            service,
            authenticator,
            config=http_config,
            event_stream=event_stream,
        )
        return cls(service, event_stream, http, runtime)

    def bind_runtime(self, runtime: PhoenixRuntime) -> None:
        self._runtime.bind(runtime)
