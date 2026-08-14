from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

import phoenix_os.agent.workspace_observer as workspace_observer_module
from phoenix_os.agent import (
    AgentAuthorizationRejectedError,
    AgentId,
    AgentServiceUnavailableError,
    AgentWorkspaceCleanupRuntime,
    AgentWorkspaceCleanupRuntimeConfiguration,
    AgentWorkspaceOperation,
    AgentWorkspaceOperationObservation,
    AgentWorkspaceOperationOutcome,
    AgentWorkspaceService,
    AgentWorkspaceTransferRuntime,
    AgentWorkspaceTransferRuntimeConfiguration,
    ArtifactDeleteRequest,
    ArtifactId,
    ArtifactImportRequest,
    ArtifactListRequest,
    ArtifactLogicalPath,
    ArtifactOriginKind,
    ArtifactProvenance,
    ArtifactReadRequest,
    ArtifactTransferDirection,
    ArtifactWriteRequest,
    ContentFreeAgentWorkspaceObserver,
    InMemoryWorkspaceStore,
    WorkspaceExportPayload,
    WorkspaceExportResult,
    WorkspaceImportResult,
    WorkspaceNamespace,
    WorkspaceScope,
    WorkspaceTransferAdapterId,
    WorkspaceTransferReference,
    agent_workspace_scope,
    artifact_content_digest,
)
from phoenix_os.agent.workspace_observer import WORKSPACE_OBSERVER_QUEUE_CAPACITY
from phoenix_os.audit import AuditLedger, AuditQuery, InMemoryAuditStore
from phoenix_os.events import Event, EventBus
from phoenix_os.observability import InMemorySink, ObservabilityHub
from phoenix_os.policy import PrincipalType, SecurityContext
from phoenix_os.runtime import RuntimeContext

_NOW = datetime(2026, 8, 14, 6, tzinfo=UTC)
_ARTIFACT_ID = ArtifactId(UUID("e0000000-0000-0000-0000-000000000031"))
_SECRET_CONTENT = b"TOP-SECRET-WORKSPACE-CONTENT-4C"
_SECRET_PATH = "private/top-secret-workspace-name-4c.txt"
_SECRET_METADATA = "TOP-SECRET-WORKSPACE-METADATA-4C"
_SECRET_PROVIDER = "TOP-SECRET-PROVIDER-BODY C:/private/token https://provider.invalid/body"


def _scope() -> WorkspaceScope:
    return agent_workspace_scope(
        namespace=WorkspaceNamespace("observed-workspace"),
        agent_id=AgentId("observer-agent"),
    )


def _context() -> SecurityContext:
    return SecurityContext(
        principal="service:workspace-observer",
        principal_type=PrincipalType.SERVICE,
        authenticated=True,
        correlation_id="corr-workspace-4c",
    )


def _write_request() -> ArtifactWriteRequest:
    digest = artifact_content_digest(_SECRET_CONTENT)
    return ArtifactWriteRequest(
        scope=_scope(),
        artifact_id=_ARTIFACT_ID,
        logical_path=ArtifactLogicalPath(_SECRET_PATH),
        content=_SECRET_CONTENT,
        provenance=ArtifactProvenance(
            origin=ArtifactOriginKind.OPERATOR,
            content_digest=digest,
            created_at=_NOW,
        ),
        metadata={"private": _SECRET_METADATA},
        created_at=_NOW,
    )


class _AllowingAuthorizer:
    async def authorize_list(
        self,
        request: ArtifactListRequest,
        context: SecurityContext,
    ) -> None:
        del request, context

    async def authorize_read(
        self,
        request: ArtifactReadRequest,
        context: SecurityContext,
    ) -> None:
        del request, context

    async def authorize_write(
        self,
        request: ArtifactWriteRequest,
        context: SecurityContext,
    ) -> None:
        del request, context

    async def authorize_delete(
        self,
        request: ArtifactDeleteRequest,
        context: SecurityContext,
    ) -> None:
        del request, context

    async def authorize_import(
        self,
        scope: WorkspaceScope,
        artifact_id: ArtifactId,
        context: SecurityContext,
        *,
        created_at: datetime | None = None,
    ) -> None:
        del scope, artifact_id, context, created_at

    async def authorize_export(
        self,
        scope: WorkspaceScope,
        artifact_id: ArtifactId,
        context: SecurityContext,
        *,
        created_at: datetime | None = None,
    ) -> None:
        del scope, artifact_id, context, created_at

    async def authorize_admin(
        self,
        scope: WorkspaceScope,
        context: SecurityContext,
        *,
        created_at: datetime | None = None,
    ) -> None:
        del scope, context, created_at


class _DenyReadAuthorizer(_AllowingAuthorizer):
    async def authorize_read(
        self,
        request: ArtifactReadRequest,
        context: SecurityContext,
    ) -> None:
        del request, context
        raise AgentAuthorizationRejectedError()


class _FailingImportAdapter:
    @property
    def adapter_id(self) -> WorkspaceTransferAdapterId:
        return WorkspaceTransferAdapterId("observed-transfer")

    @property
    def closed(self) -> bool:
        return False

    async def import_artifact(
        self,
        source_reference: WorkspaceTransferReference,
        *,
        max_bytes: int,
    ) -> WorkspaceImportResult:
        del source_reference, max_bytes
        raise RuntimeError(_SECRET_PROVIDER)

    async def export_artifact(
        self,
        payload: WorkspaceExportPayload,
    ) -> WorkspaceExportResult:
        del payload
        raise AssertionError("export is not expected")


class _ExplodingObserver:
    def record(
        self,
        observation: AgentWorkspaceOperationObservation,
        context: SecurityContext | None = None,
    ) -> None:
        del observation, context
        raise RuntimeError(_SECRET_PROVIDER)


class _CleanupOwner:
    def __init__(self) -> None:
        self.closed = False
        self.running = True
        self.calls = 0
        self.succeeded = asyncio.Event()

    async def cleanup_once(self) -> int:
        self.calls += 1
        if self.calls == 1:
            raise RuntimeError(_SECRET_PROVIDER)
        self.succeeded.set()
        return 2


@pytest.mark.asyncio
async def test_workspace_service_observations_are_content_free() -> None:
    events = EventBus()
    captured: list[Event] = []

    async def capture(event: Event) -> None:
        if event.name.startswith("agent.workspace."):
            captured.append(event)

    await events.subscribe("*", capture)
    audit_store = InMemoryAuditStore()
    audit = AuditLedger(audit_store)
    sink = InMemorySink(capacity=200)
    observability = ObservabilityHub((sink,))
    observer = ContentFreeAgentWorkspaceObserver(
        events=events,
        audit=audit,
        observability=observability,
    )
    await observer.start(RuntimeContext(services={}))

    store = InMemoryWorkspaceStore(clock=lambda: _NOW)
    service = AgentWorkspaceService(
        store=store,
        authorizer=_AllowingAuthorizer(),
        observer=observer,
        clock=lambda: _NOW,
    )

    record = await service.write(_write_request(), _context())
    loaded = await service.read(
        ArtifactReadRequest(
            scope=_scope(),
            artifact_id=_ARTIFACT_ID,
            created_at=_NOW,
        ),
        _context(),
    )
    assert loaded is not None
    await service.list(
        ArtifactListRequest(scope=_scope(), created_at=_NOW),
        _context(),
    )
    await service.delete(
        ArtifactDeleteRequest(
            scope=_scope(),
            artifact_id=_ARTIFACT_ID,
            expected_version=record.version,
            created_at=_NOW,
        ),
        _context(),
    )

    await observer.close()
    records = await audit_store.read(AuditQuery(limit=1000))
    observations = (await sink.snapshot()).records

    names = {event.name for event in captured}
    assert {
        "agent.workspace.write.succeeded",
        "agent.workspace.read.succeeded",
        "agent.workspace.list.succeeded",
        "agent.workspace.delete.succeeded",
    } <= names
    assert all(event.payload == {} for event in captured)

    serialized = repr((captured, records, observations))
    for secret in (
        _SECRET_CONTENT.decode(),
        _SECRET_PATH,
        _SECRET_METADATA,
    ):
        assert secret not in serialized
    assert str(_ARTIFACT_ID) in serialized
    assert "scope_kind" in serialized
    assert "byte_count" in serialized

    await store.close()


@pytest.mark.asyncio
async def test_workspace_authorization_failure_uses_fixed_reason_code() -> None:
    events = EventBus()
    captured: list[Event] = []

    async def capture(event: Event) -> None:
        if event.name.startswith("agent.workspace.read."):
            captured.append(event)

    await events.subscribe("*", capture)
    observer = ContentFreeAgentWorkspaceObserver(events=events)
    await observer.start(RuntimeContext(services={}))
    store = InMemoryWorkspaceStore(clock=lambda: _NOW)
    service = AgentWorkspaceService(
        store=store,
        authorizer=_DenyReadAuthorizer(),
        observer=observer,
        clock=lambda: _NOW,
    )

    with pytest.raises(AgentAuthorizationRejectedError):
        await service.read(
            ArtifactReadRequest(
                scope=_scope(),
                artifact_id=_ARTIFACT_ID,
                created_at=_NOW,
            ),
            _context(),
        )

    await observer.close()
    assert [event.name for event in captured] == ["agent.workspace.read.rejected"]
    assert captured[0].metadata["reason_code"] == "authorization_rejected"
    await store.close()


@pytest.mark.asyncio
async def test_transfer_provider_failure_is_sanitized_in_public_error_and_telemetry() -> None:
    events = EventBus()
    captured: list[Event] = []

    async def capture(event: Event) -> None:
        if event.name.startswith("agent.workspace."):
            captured.append(event)

    await events.subscribe("*", capture)
    audit_store = InMemoryAuditStore()
    audit = AuditLedger(audit_store)
    sink = InMemorySink(capacity=200)
    observability = ObservabilityHub((sink,))
    observer = ContentFreeAgentWorkspaceObserver(
        events=events,
        audit=audit,
        observability=observability,
    )
    context = RuntimeContext(services={})
    await observer.start(context)

    store = InMemoryWorkspaceStore(clock=lambda: _NOW)
    core = AgentWorkspaceService(
        store=store,
        authorizer=_AllowingAuthorizer(),
        transfer_adapter=_FailingImportAdapter(),
        observer=observer,
        clock=lambda: _NOW,
    )
    transfer = AgentWorkspaceTransferRuntime(
        configuration=AgentWorkspaceTransferRuntimeConfiguration(
            operation_timeout=timedelta(seconds=1),
            settlement_timeout=timedelta(milliseconds=50),
            worker_count=1,
            queue_capacity=1,
        ),
        service=core,
        observer=observer,
    )
    await transfer.start(context)

    request = ArtifactImportRequest(
        scope=_scope(),
        artifact_id=_ARTIFACT_ID,
        source_reference=WorkspaceTransferReference("opaque-secret-reference-4c"),
        created_at=_NOW,
    )
    with pytest.raises(AgentServiceUnavailableError) as failure:
        await transfer.import_artifact(request, _context())
    assert str(failure.value) == "agent service is unavailable"
    assert _SECRET_PROVIDER not in repr(failure.value)

    await transfer.close()
    await observer.close()
    records = await audit_store.read(AuditQuery(limit=1000))
    observations = (await sink.snapshot()).records
    serialized = repr((captured, records, observations, failure.value))
    assert _SECRET_PROVIDER not in serialized
    assert request.source_reference.value not in serialized
    names = {event.name for event in captured}
    assert "agent.workspace.import.failed" in names
    assert "agent.workspace.transfer.import.failed" in names
    assert all(event.payload == {} for event in captured)
    assert all(
        event.metadata.get("reason_code") == "service_unavailable"
        for event in captured
        if event.name.endswith(".failed")
    )

    await store.close()


@pytest.mark.asyncio
async def test_cleanup_reports_failure_and_recovery_without_raw_exception() -> None:
    events = EventBus()
    captured: list[Event] = []

    async def capture(event: Event) -> None:
        if event.name.startswith("agent.workspace.cleanup."):
            captured.append(event)

    await events.subscribe("*", capture)
    observer = ContentFreeAgentWorkspaceObserver(events=events)
    context = RuntimeContext(services={})
    await observer.start(context)
    owner = _CleanupOwner()
    cleanup = AgentWorkspaceCleanupRuntime(
        configuration=AgentWorkspaceCleanupRuntimeConfiguration(
            interval=timedelta(milliseconds=10),
            shutdown_timeout=timedelta(seconds=1),
        ),
        owner=owner,
        namespace=_scope().namespace,
        observer=observer,
    )
    await cleanup.start(context)

    await asyncio.wait_for(owner.succeeded.wait(), timeout=1)
    await cleanup.close()
    await observer.close()

    names = [event.name for event in captured]
    assert "agent.workspace.cleanup.failed" in names
    assert "agent.workspace.cleanup.succeeded" in names
    serialized = repr(captured)
    assert _SECRET_PROVIDER not in serialized
    failed = next(event for event in captured if event.name.endswith(".failed"))
    assert failed.metadata["reason_code"] == "service_unavailable"


@pytest.mark.asyncio
async def test_observer_failure_cannot_change_committed_workspace_write() -> None:
    store = InMemoryWorkspaceStore(clock=lambda: _NOW)
    service = AgentWorkspaceService(
        store=store,
        authorizer=_AllowingAuthorizer(),
        observer=_ExplodingObserver(),
        clock=lambda: _NOW,
    )

    record = await service.write(_write_request(), _context())
    loaded = await store.read(
        ArtifactReadRequest(
            scope=_scope(),
            artifact_id=_ARTIFACT_ID,
            created_at=_NOW,
        )
    )
    assert loaded is not None
    assert loaded.record.version == record.version
    assert loaded.content == _SECRET_CONTENT
    await store.close()


@pytest.mark.asyncio
async def test_workspace_observer_queue_is_finite_and_drops_excess_signals() -> None:
    events = EventBus()
    delivery_started = asyncio.Event()
    release_delivery = asyncio.Event()

    async def block_delivery(event: Event) -> None:
        if event.name == "agent.workspace.read.succeeded":
            delivery_started.set()
            await release_delivery.wait()

    await events.subscribe("*", block_delivery)
    observer = ContentFreeAgentWorkspaceObserver(events=events)
    await observer.start(RuntimeContext(services={}))
    observation = AgentWorkspaceOperationObservation(
        operation=AgentWorkspaceOperation.READ,
        outcome=AgentWorkspaceOperationOutcome.SUCCEEDED,
        namespace=_scope().namespace,
        scope=_scope(),
        artifact_id=_ARTIFACT_ID,
        duration_ms=1,
    )

    observer.record(observation, _context())
    await asyncio.wait_for(delivery_started.wait(), timeout=1)
    for _ in range(WORKSPACE_OBSERVER_QUEUE_CAPACITY + 100):
        observer.record(observation, _context())

    assert observer.queued_observations == WORKSPACE_OBSERVER_QUEUE_CAPACITY
    release_delivery.set()
    await observer.close()


@pytest.mark.asyncio
async def test_observer_shutdown_releases_worker_after_suppressed_cancellation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events = EventBus()
    delivery_started = asyncio.Event()
    cancellation_seen = asyncio.Event()
    release_delivery = asyncio.Event()

    async def suppress_cancellation(event: Event) -> None:
        if event.name != "agent.workspace.read.succeeded":
            return
        delivery_started.set()
        try:
            await release_delivery.wait()
        except asyncio.CancelledError:
            cancellation_seen.set()
            await release_delivery.wait()

    await events.subscribe("*", suppress_cancellation)
    monkeypatch.setattr(
        workspace_observer_module,
        "WORKSPACE_OBSERVER_SHUTDOWN_TIMEOUT",
        timedelta(milliseconds=20),
    )
    observer = ContentFreeAgentWorkspaceObserver(events=events)
    await observer.start(RuntimeContext(services={}))

    worker = observer._worker
    assert worker is not None
    observer.record(
        AgentWorkspaceOperationObservation(
            operation=AgentWorkspaceOperation.READ,
            outcome=AgentWorkspaceOperationOutcome.SUCCEEDED,
            namespace=_scope().namespace,
            scope=_scope(),
            artifact_id=_ARTIFACT_ID,
            duration_ms=1,
        ),
        _context(),
    )
    await asyncio.wait_for(delivery_started.wait(), timeout=1)

    await asyncio.wait_for(observer.close(), timeout=0.5)
    await asyncio.wait_for(cancellation_seen.wait(), timeout=0.5)
    assert observer.closed is True
    assert worker.done() is False

    release_delivery.set()
    await asyncio.wait_for(worker, timeout=1)
    assert worker.done() is True


def test_workspace_observation_rejects_unbounded_reason_code() -> None:
    with pytest.raises(ValueError, match="reason_code"):
        AgentWorkspaceOperationObservation(
            operation=AgentWorkspaceOperation.READ,
            outcome=AgentWorkspaceOperationOutcome.FAILED,
            namespace=_scope().namespace,
            scope=_scope(),
            artifact_id=_ARTIFACT_ID,
            reason_code="../TOP-SECRET/" + "x" * 100,
        )

    observation = AgentWorkspaceOperationObservation(
        operation=AgentWorkspaceOperation.TRANSFER_IMPORT,
        outcome=AgentWorkspaceOperationOutcome.SUCCEEDED,
        namespace=_scope().namespace,
        scope=_scope(),
        artifact_id=_ARTIFACT_ID,
        transfer_direction=ArtifactTransferDirection.IMPORT,
        duration_ms=1,
    )
    assert "source_reference" not in observation.metadata()
    assert "logical_path" not in observation.metadata()
