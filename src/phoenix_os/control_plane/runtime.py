"""Runtime assembly helpers for the local Phoenix control plane."""

from __future__ import annotations

import secrets
from dataclasses import dataclass

from phoenix_os.capabilities import CapabilityRegistry
from phoenix_os.control_plane.auth import (
    AdminTokenAuthenticator,
    ControlPlaneCommandAuthorizer,
)
from phoenix_os.control_plane.command_api import ControlPlaneCommandApi
from phoenix_os.control_plane.confirmation import InMemoryControlPlaneConfirmationService
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
from phoenix_os.control_plane.csrf import ControlPlaneCsrfProtector
from phoenix_os.control_plane.event_stream import (
    ControlPlaneEventStream,
    ControlPlaneEventStreamConfig,
)
from phoenix_os.control_plane.http import ControlPlaneHttpConfig, ControlPlaneHttpServer
from phoenix_os.control_plane.idempotency import InMemoryControlPlaneIdempotencyStore
from phoenix_os.control_plane.job_commands import (
    ControlPlaneJobCommandHandler,
    ControlPlaneJobScheduler,
)
from phoenix_os.control_plane.protection import ControlPlaneCommandProtector
from phoenix_os.control_plane.service import ControlPlaneService
from phoenix_os.control_plane.workflow_commands import (
    ControlPlaneWorkflowCommandHandler,
    ControlPlaneWorkflowOrchestrator,
)
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
    commands: ControlPlaneCommandApi
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
        job_commands: ControlPlaneJobScheduler | None = None,
        workflow_commands: ControlPlaneWorkflowOrchestrator | None = None,
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
        authorizer = ControlPlaneCommandAuthorizer()
        csrf = ControlPlaneCsrfProtector(secrets.token_bytes(32))
        confirmations = InMemoryControlPlaneConfirmationService(secrets.token_bytes(32))
        idempotency = InMemoryControlPlaneIdempotencyStore()
        protector = ControlPlaneCommandProtector(csrf, confirmations)
        job_handler = (
            None
            if job_commands is None
            else ControlPlaneJobCommandHandler(
                job_commands,
                capabilities,
                authorizer,
                protector,
                idempotency,
            )
        )
        workflow_handler = (
            None
            if workflow_commands is None
            else ControlPlaneWorkflowCommandHandler(
                workflow_commands,
                authorizer,
                protector,
                idempotency,
            )
        )
        command_api = ControlPlaneCommandApi(
            csrf=csrf,
            confirmations=confirmations,
            idempotency=idempotency,
            authorizer=authorizer,
            events=event_bus,
            jobs=job_handler,
            workflows=workflow_handler,
        )
        http = ControlPlaneHttpServer(
            service,
            authenticator,
            config=http_config,
            event_stream=event_stream,
            command_api=command_api,
        )
        return cls(service, event_stream, command_api, http, runtime)

    def bind_runtime(self, runtime: PhoenixRuntime) -> None:
        self._runtime.bind(runtime)
