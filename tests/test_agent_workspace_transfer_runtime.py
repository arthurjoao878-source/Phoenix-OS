from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from phoenix_os.agent import (
    AgentId,
    AgentServiceUnavailableError,
    AgentWorkspaceTransferRuntime,
    AgentWorkspaceTransferRuntimeConfiguration,
    ArtifactExportRequest,
    ArtifactId,
    ArtifactImportRequest,
    ArtifactTransferDirection,
    ArtifactTransferReceipt,
    ArtifactVersion,
    WorkspaceNamespace,
    WorkspaceScope,
    WorkspaceTransferAdapterId,
    WorkspaceTransferReference,
    agent_workspace_scope,
    artifact_content_digest,
)
from phoenix_os.policy import SecurityContext
from phoenix_os.runtime import RuntimeContext

_NOW = datetime(2026, 8, 14, tzinfo=UTC)
_NAMESPACE = WorkspaceNamespace("transfer-runtime")
_SCOPE: WorkspaceScope = agent_workspace_scope(
    namespace=_NAMESPACE,
    agent_id=AgentId("transfer-agent"),
)
_CONTEXT = SecurityContext()
_SOURCE = WorkspaceTransferReference("source-item")
_DESTINATION = WorkspaceTransferReference("destination-item")
_EXPORT_ID = ArtifactId(UUID("c0000000-0000-0000-0000-000000000001"))
_IMPORT_ID = ArtifactId(UUID("c0000000-0000-0000-0000-000000000002"))
_VERSION = ArtifactVersion()
_DIGEST = artifact_content_digest(b"transfer-receipt")


def _import_request(
    *,
    source: WorkspaceTransferReference = _SOURCE,
    artifact_id: ArtifactId = _IMPORT_ID,
) -> ArtifactImportRequest:
    return ArtifactImportRequest(
        scope=_SCOPE,
        artifact_id=artifact_id,
        source_reference=source,
        created_at=_NOW,
    )


def _export_request(
    *,
    destination: WorkspaceTransferReference = _DESTINATION,
    artifact_id: ArtifactId = _EXPORT_ID,
) -> ArtifactExportRequest:
    return ArtifactExportRequest(
        scope=_SCOPE,
        artifact_id=artifact_id,
        expected_version=_VERSION,
        destination_reference=destination,
        created_at=_NOW,
    )


def _receipt(
    direction: ArtifactTransferDirection,
    artifact_id: ArtifactId,
) -> ArtifactTransferReceipt:
    return ArtifactTransferReceipt(
        direction=direction,
        scope=_SCOPE,
        artifact_id=artifact_id,
        version=_VERSION,
        content_digest=_DIGEST,
        byte_length=len(b"transfer-receipt"),
        adapter_id=WorkspaceTransferAdapterId("runtime-test"),
        completed_at=_NOW,
        transfer_reference=(
            _SOURCE if direction is ArtifactTransferDirection.IMPORT else _DESTINATION
        ),
    )


class _ImmediateTransferService:
    def __init__(self) -> None:
        self._closed = False
        self.import_calls = 0
        self.export_calls = 0

    @property
    def closed(self) -> bool:
        return self._closed

    async def import_artifact(
        self,
        request: ArtifactImportRequest,
        context: SecurityContext,
    ) -> ArtifactTransferReceipt:
        assert context == _CONTEXT
        self.import_calls += 1
        return _receipt(ArtifactTransferDirection.IMPORT, request.artifact_id)

    async def export_artifact(
        self,
        request: ArtifactExportRequest,
        context: SecurityContext,
    ) -> ArtifactTransferReceipt:
        assert context == _CONTEXT
        self.export_calls += 1
        return _receipt(ArtifactTransferDirection.EXPORT, request.artifact_id)


class _BlockingImportService:
    def __init__(self) -> None:
        self._closed = False
        self.started = 0
        self.first_started = asyncio.Event()
        self.release = asyncio.Event()

    @property
    def closed(self) -> bool:
        return self._closed

    async def import_artifact(
        self,
        request: ArtifactImportRequest,
        context: SecurityContext,
    ) -> ArtifactTransferReceipt:
        del context
        self.started += 1
        self.first_started.set()
        await self.release.wait()
        return _receipt(ArtifactTransferDirection.IMPORT, request.artifact_id)

    async def export_artifact(
        self,
        request: ArtifactExportRequest,
        context: SecurityContext,
    ) -> ArtifactTransferReceipt:
        del request, context
        raise AssertionError("export not expected")


class _CancellationSuppressingImportService:
    def __init__(self) -> None:
        self._closed = False
        self.started = 0
        self.cancelled = asyncio.Event()
        self.release = asyncio.Event()

    @property
    def closed(self) -> bool:
        return self._closed

    async def import_artifact(
        self,
        request: ArtifactImportRequest,
        context: SecurityContext,
    ) -> ArtifactTransferReceipt:
        del context
        self.started += 1
        try:
            await asyncio.Future()
        except asyncio.CancelledError:
            self.cancelled.set()
            await self.release.wait()
            return _receipt(ArtifactTransferDirection.IMPORT, request.artifact_id)
        raise AssertionError("unreachable")

    async def export_artifact(
        self,
        request: ArtifactExportRequest,
        context: SecurityContext,
    ) -> ArtifactTransferReceipt:
        del request, context
        raise AssertionError("export not expected")


class _PostCommitExportService:
    def __init__(self) -> None:
        self._closed = False
        self.started = asyncio.Event()
        self.cancelled_after_commit = asyncio.Event()

    @property
    def closed(self) -> bool:
        return self._closed

    async def import_artifact(
        self,
        request: ArtifactImportRequest,
        context: SecurityContext,
    ) -> ArtifactTransferReceipt:
        del request, context
        raise AssertionError("import not expected")

    async def export_artifact(
        self,
        request: ArtifactExportRequest,
        context: SecurityContext,
    ) -> ArtifactTransferReceipt:
        del context
        self.started.set()
        try:
            await asyncio.Future()
        except asyncio.CancelledError:
            self.cancelled_after_commit.set()
            # This models the WorkspaceTransferAdapter contract: an external
            # side effect already committed, so cancellation becomes completion.
            return _receipt(ArtifactTransferDirection.EXPORT, request.artifact_id)
        raise AssertionError("unreachable")


class _CancellationSuppressingExportService:
    def __init__(self) -> None:
        self._closed = False
        self.started = 0
        self.cancelled = asyncio.Event()
        self.release = asyncio.Event()

    @property
    def closed(self) -> bool:
        return self._closed

    async def import_artifact(
        self,
        request: ArtifactImportRequest,
        context: SecurityContext,
    ) -> ArtifactTransferReceipt:
        del request, context
        raise AssertionError("import not expected")

    async def export_artifact(
        self,
        request: ArtifactExportRequest,
        context: SecurityContext,
    ) -> ArtifactTransferReceipt:
        del context
        self.started += 1
        try:
            await asyncio.Future()
        except asyncio.CancelledError:
            self.cancelled.set()
            await self.release.wait()
            return _receipt(ArtifactTransferDirection.EXPORT, request.artifact_id)
        raise AssertionError("unreachable")


class _LateFailingExportService:
    def __init__(self) -> None:
        self._closed = False
        self.cancelled = asyncio.Event()
        self.release = asyncio.Event()
        self.finished = asyncio.Event()

    @property
    def closed(self) -> bool:
        return self._closed

    async def import_artifact(
        self,
        request: ArtifactImportRequest,
        context: SecurityContext,
    ) -> ArtifactTransferReceipt:
        del request, context
        raise AssertionError("import not expected")

    async def export_artifact(
        self,
        request: ArtifactExportRequest,
        context: SecurityContext,
    ) -> ArtifactTransferReceipt:
        del request, context
        try:
            await asyncio.Future()
        except asyncio.CancelledError:
            self.cancelled.set()
            await self.release.wait()
            self.finished.set()
            raise AgentServiceUnavailableError() from None
        raise AssertionError("unreachable")


class _PreCommitExportService:
    def __init__(self) -> None:
        self._closed = False
        self.started = asyncio.Event()

    @property
    def closed(self) -> bool:
        return self._closed

    async def import_artifact(
        self,
        request: ArtifactImportRequest,
        context: SecurityContext,
    ) -> ArtifactTransferReceipt:
        del request, context
        raise AssertionError("import not expected")

    async def export_artifact(
        self,
        request: ArtifactExportRequest,
        context: SecurityContext,
    ) -> ArtifactTransferReceipt:
        del request, context
        self.started.set()
        await asyncio.Future()
        raise AssertionError("unreachable")


@pytest.mark.asyncio
async def test_transfer_runtime_executes_service_after_dequeue() -> None:
    service = _ImmediateTransferService()
    runtime = AgentWorkspaceTransferRuntime(
        configuration=AgentWorkspaceTransferRuntimeConfiguration(
            worker_count=2,
            queue_capacity=4,
        ),
        service=service,
    )
    await runtime.start(RuntimeContext(services={}))

    imported = await runtime.import_artifact(_import_request(), _CONTEXT)
    exported = await runtime.export_artifact(_export_request(), _CONTEXT)

    assert imported.direction is ArtifactTransferDirection.IMPORT
    assert exported.direction is ArtifactTransferDirection.EXPORT
    assert service.import_calls == 1
    assert service.export_calls == 1

    await runtime.close()
    assert runtime.closed is True
    assert runtime.running is False


@pytest.mark.asyncio
async def test_transfer_runtime_queue_capacity_fails_closed_without_blocking() -> None:
    service = _BlockingImportService()
    runtime = AgentWorkspaceTransferRuntime(
        configuration=AgentWorkspaceTransferRuntimeConfiguration(
            operation_timeout=timedelta(seconds=1),
            worker_count=1,
            queue_capacity=1,
        ),
        service=service,
    )
    await runtime.start(RuntimeContext(services={}))

    first = asyncio.create_task(runtime.import_artifact(_import_request(), _CONTEXT))
    await asyncio.wait_for(service.first_started.wait(), timeout=0.2)

    second_id = ArtifactId(UUID("c0000000-0000-0000-0000-000000000003"))
    second = asyncio.create_task(
        runtime.import_artifact(
            _import_request(
                source=WorkspaceTransferReference("source-queued"),
                artifact_id=second_id,
            ),
            _CONTEXT,
        )
    )
    await asyncio.sleep(0)
    assert runtime.queued_transfers == 1

    with pytest.raises(AgentServiceUnavailableError):
        await runtime.import_artifact(
            _import_request(
                source=WorkspaceTransferReference("source-overflow"),
                artifact_id=ArtifactId(UUID("c0000000-0000-0000-0000-000000000004")),
            ),
            _CONTEXT,
        )

    service.release.set()
    await first
    await second
    await runtime.close()


@pytest.mark.asyncio
async def test_transfer_runtime_timeout_keeps_import_concurrency_finite() -> None:
    service = _CancellationSuppressingImportService()
    runtime = AgentWorkspaceTransferRuntime(
        configuration=AgentWorkspaceTransferRuntimeConfiguration(
            operation_timeout=timedelta(milliseconds=1),
            worker_count=1,
            queue_capacity=1,
        ),
        service=service,
    )
    await runtime.start(RuntimeContext(services={}))

    with pytest.raises(AgentServiceUnavailableError):
        await runtime.import_artifact(_import_request(), _CONTEXT)
    await asyncio.wait_for(service.cancelled.wait(), timeout=0.2)

    with pytest.raises(AgentServiceUnavailableError):
        await runtime.import_artifact(
            _import_request(
                source=WorkspaceTransferReference("source-queued"),
                artifact_id=ArtifactId(UUID("c0000000-0000-0000-0000-000000000005")),
            ),
            _CONTEXT,
        )

    with pytest.raises(AgentServiceUnavailableError):
        await runtime.import_artifact(
            _import_request(
                source=WorkspaceTransferReference("source-overflow"),
                artifact_id=ArtifactId(UUID("c0000000-0000-0000-0000-000000000006")),
            ),
            _CONTEXT,
        )

    assert service.started == 1
    assert runtime.queued_transfers == 1

    service.release.set()
    await asyncio.sleep(0)
    await asyncio.sleep(0)
    await runtime.close()


@pytest.mark.asyncio
async def test_started_export_preserves_post_commit_completion_after_deadline() -> None:
    service = _PostCommitExportService()
    runtime = AgentWorkspaceTransferRuntime(
        configuration=AgentWorkspaceTransferRuntimeConfiguration(
            operation_timeout=timedelta(milliseconds=1),
            settlement_timeout=timedelta(milliseconds=50),
            worker_count=1,
            queue_capacity=1,
        ),
        service=service,
    )
    await runtime.start(RuntimeContext(services={}))

    receipt = await asyncio.wait_for(
        runtime.export_artifact(_export_request(), _CONTEXT),
        timeout=0.2,
    )

    assert receipt.direction is ArtifactTransferDirection.EXPORT
    assert receipt.artifact_id == _EXPORT_ID
    assert service.cancelled_after_commit.is_set()
    await runtime.close()


@pytest.mark.asyncio
async def test_nonsettling_export_cannot_bypass_runtime_response_bound() -> None:
    service = _CancellationSuppressingExportService()
    runtime = AgentWorkspaceTransferRuntime(
        configuration=AgentWorkspaceTransferRuntimeConfiguration(
            operation_timeout=timedelta(milliseconds=2),
            settlement_timeout=timedelta(milliseconds=20),
            worker_count=1,
            queue_capacity=1,
        ),
        service=service,
    )
    await runtime.start(RuntimeContext(services={}))

    with pytest.raises(AgentServiceUnavailableError):
        await asyncio.wait_for(
            runtime.export_artifact(_export_request(), _CONTEXT),
            timeout=0.2,
        )
    await asyncio.wait_for(service.cancelled.wait(), timeout=0.2)

    assert service.started == 1

    service.release.set()
    await asyncio.sleep(0)
    await asyncio.sleep(0)
    await runtime.close()


@pytest.mark.asyncio
async def test_settlement_timeout_abandons_late_failure_without_future_leak() -> None:
    loop = asyncio.get_running_loop()
    captured: list[dict[str, object]] = []
    previous_handler = loop.get_exception_handler()
    loop.set_exception_handler(lambda _loop, context: captured.append(dict(context)))
    try:
        service = _LateFailingExportService()
        runtime = AgentWorkspaceTransferRuntime(
            configuration=AgentWorkspaceTransferRuntimeConfiguration(
                operation_timeout=timedelta(milliseconds=2),
                settlement_timeout=timedelta(milliseconds=20),
                worker_count=1,
                queue_capacity=1,
            ),
            service=service,
        )
        await runtime.start(RuntimeContext(services={}))

        with pytest.raises(AgentServiceUnavailableError):
            await asyncio.wait_for(
                runtime.export_artifact(_export_request(), _CONTEXT),
                timeout=0.2,
            )
        await asyncio.wait_for(service.cancelled.wait(), timeout=0.2)

        service.release.set()
        await asyncio.wait_for(service.finished.wait(), timeout=0.2)
        await asyncio.sleep(0)
        await runtime.close()
        await asyncio.sleep(0)
    finally:
        loop.set_exception_handler(previous_handler)

    assert not any(
        context.get("message") == "Future exception was never retrieved" for context in captured
    )


@pytest.mark.asyncio
async def test_started_export_reports_pre_commit_cancellation_as_unavailable() -> None:
    service = _PreCommitExportService()
    runtime = AgentWorkspaceTransferRuntime(
        configuration=AgentWorkspaceTransferRuntimeConfiguration(
            operation_timeout=timedelta(milliseconds=1),
            worker_count=1,
            queue_capacity=1,
        ),
        service=service,
    )
    await runtime.start(RuntimeContext(services={}))

    with pytest.raises(AgentServiceUnavailableError):
        await runtime.export_artifact(_export_request(), _CONTEXT)

    await runtime.close()


@pytest.mark.asyncio
async def test_transfer_runtime_shutdown_is_bounded_when_service_suppresses_cancel() -> None:
    service = _CancellationSuppressingImportService()
    runtime = AgentWorkspaceTransferRuntime(
        configuration=AgentWorkspaceTransferRuntimeConfiguration(
            operation_timeout=timedelta(milliseconds=1),
            worker_count=1,
            queue_capacity=1,
        ),
        service=service,
    )
    await runtime.start(RuntimeContext(services={}))

    with pytest.raises(AgentServiceUnavailableError):
        await runtime.import_artifact(_import_request(), _CONTEXT)
    await asyncio.wait_for(service.cancelled.wait(), timeout=0.2)

    await asyncio.wait_for(runtime.close(), timeout=0.2)

    assert runtime.closed is True
    assert runtime.running is False
    assert service.started == 1

    service.release.set()
    await asyncio.sleep(0)
    await asyncio.sleep(0)


def test_transfer_runtime_configuration_is_strictly_bounded() -> None:
    with pytest.raises(ValueError, match="worker_count"):
        AgentWorkspaceTransferRuntimeConfiguration(worker_count=0)
    with pytest.raises(ValueError, match="worker_count"):
        AgentWorkspaceTransferRuntimeConfiguration(worker_count=65)
    with pytest.raises(ValueError, match="queue_capacity"):
        AgentWorkspaceTransferRuntimeConfiguration(queue_capacity=0)
    with pytest.raises(ValueError, match="queue_capacity"):
        AgentWorkspaceTransferRuntimeConfiguration(queue_capacity=4_097)
    with pytest.raises(ValueError, match="operation_timeout"):
        AgentWorkspaceTransferRuntimeConfiguration(
            operation_timeout=timedelta(minutes=6),
        )
    with pytest.raises(ValueError, match="settlement_timeout"):
        AgentWorkspaceTransferRuntimeConfiguration(
            settlement_timeout=timedelta(0),
        )
    with pytest.raises(ValueError, match="settlement_timeout"):
        AgentWorkspaceTransferRuntimeConfiguration(
            settlement_timeout=timedelta(seconds=31),
        )
