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
from phoenix_os.control_plane.job_commands import (
    ControlPlaneJobCommandHandler,
    ControlPlaneJobScheduler,
)
from phoenix_os.control_plane.journal_contracts import ControlPlaneCommandJournalRepository
from phoenix_os.control_plane.journal_history import ControlPlaneCommandHistoryService
from phoenix_os.control_plane.journal_idempotency import JournalControlPlaneIdempotencyStore
from phoenix_os.control_plane.journal_memory import InMemoryControlPlaneCommandJournalRepository
from phoenix_os.control_plane.journal_recovery import (
    ControlPlaneCommandRecoveryService,
    ControlPlaneCommandRecoveryWorker,
    ControlPlaneCommandSideEffectProbe,
)
from phoenix_os.control_plane.journal_retention import (
    ControlPlaneCommandRetentionPolicy,
    ControlPlaneCommandRetentionService,
    ControlPlaneCommandRetentionWorker,
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


class _CommandJournalOwner:
    """Close the journal after command workers and API components stop."""

    def __init__(self, repository: ControlPlaneCommandJournalRepository) -> None:
        self._repository = repository

    async def start(self, context: object) -> None:
        del context
        if self._repository.closed:
            raise RuntimeError("control plane command journal is closed")

    async def stop(self, context: object) -> None:
        del context
        await self._repository.close()


@dataclass(frozen=True, slots=True)
class ControlPlaneRuntimeStack:
    """Control-plane services constructed before the Runtime self-reference exists."""

    service: ControlPlaneService
    journal: ControlPlaneCommandJournalRepository
    journal_owner: _CommandJournalOwner
    history: ControlPlaneCommandHistoryService
    recovery: ControlPlaneCommandRecoveryWorker
    retention: ControlPlaneCommandRetentionWorker
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
        command_journal: ControlPlaneCommandJournalRepository | None = None,
        command_recovery_poll_interval: float = 1.0,
        command_recovery_batch_size: int = 100,
        command_retention_policy: ControlPlaneCommandRetentionPolicy | None = None,
        command_retention_poll_interval: float = 3600.0,
    ) -> ControlPlaneRuntimeStack:
        runtime = _RuntimeSnapshotProxy()
        journal = command_journal or InMemoryControlPlaneCommandJournalRepository()
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
            command_journal=journal,
        )
        event_stream = ControlPlaneEventStream(event_bus, config=event_config)
        authorizer = ControlPlaneCommandAuthorizer()
        csrf = ControlPlaneCsrfProtector(secrets.token_bytes(32))
        confirmations = InMemoryControlPlaneConfirmationService(secrets.token_bytes(32))
        idempotency = JournalControlPlaneIdempotencyStore(
            journal,
            principal=authenticator.principal.name,
        )
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
        history = ControlPlaneCommandHistoryService(journal, events=event_bus)
        recovery = ControlPlaneCommandRecoveryWorker(
            ControlPlaneCommandRecoveryService(
                journal,
                ControlPlaneCommandSideEffectProbe(
                    jobs=job_commands,
                    workflows=workflow_commands,
                ),
            ),
            poll_interval=command_recovery_poll_interval,
            batch_size=command_recovery_batch_size,
        )
        retention = ControlPlaneCommandRetentionWorker(
            ControlPlaneCommandRetentionService(journal, events=event_bus),
            command_retention_policy or ControlPlaneCommandRetentionPolicy(),
            poll_interval=command_retention_poll_interval,
        )
        http = ControlPlaneHttpServer(
            service,
            authenticator,
            config=http_config,
            event_stream=event_stream,
            command_api=command_api,
            command_history=history,
        )
        return cls(
            service,
            journal,
            _CommandJournalOwner(journal),
            history,
            recovery,
            retention,
            event_stream,
            command_api,
            http,
            runtime,
        )

    def bind_runtime(self, runtime: PhoenixRuntime) -> None:
        self._runtime.bind(runtime)
