"""Runtime-owned finite transfer workers for secure Phoenix workspaces."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import timedelta
from typing import Protocol, cast, runtime_checkable

from phoenix_os.agent.errors import (
    AgentCodecError,
    AgentError,
    AgentServiceUnavailableError,
)
from phoenix_os.agent.workspace_contracts import (
    ArtifactExportRequest,
    ArtifactImportRequest,
    ArtifactTransferDirection,
    ArtifactTransferReceipt,
)
from phoenix_os.policy import SecurityContext
from phoenix_os.runtime import RuntimeContext

MAX_WORKSPACE_TRANSFER_RUNTIME_OPERATION_TIMEOUT = timedelta(minutes=5)
MAX_WORKSPACE_TRANSFER_RUNTIME_QUEUE_CAPACITY = 4_096
MAX_WORKSPACE_TRANSFER_RUNTIME_SETTLEMENT_TIMEOUT = timedelta(seconds=30)
MAX_WORKSPACE_TRANSFER_RUNTIME_WORKERS = 64


def _consume_worker_task_result(task: asyncio.Task[None]) -> None:
    try:
        task.result()
    except asyncio.CancelledError:
        pass
    except Exception:
        pass


def _consume_receipt_task_result(task: asyncio.Task[ArtifactTransferReceipt]) -> None:
    try:
        task.result()
    except asyncio.CancelledError:
        pass
    except Exception:
        pass


def _consume_cancel_wait_result(task: asyncio.Task[bool]) -> None:
    try:
        task.result()
    except asyncio.CancelledError:
        pass
    except Exception:
        pass


@runtime_checkable
class _WorkspaceTransferService(Protocol):
    """Server-owned transfer service executed only after queue dequeue."""

    @property
    def closed(self) -> bool: ...

    async def import_artifact(
        self,
        request: ArtifactImportRequest,
        context: SecurityContext,
    ) -> ArtifactTransferReceipt: ...

    async def export_artifact(
        self,
        request: ArtifactExportRequest,
        context: SecurityContext,
    ) -> ArtifactTransferReceipt: ...


@dataclass(frozen=True, slots=True)
class AgentWorkspaceTransferRuntimeConfiguration:
    """Finite queue, concurrency, and cancellation-deadline bounds."""

    operation_timeout: timedelta = timedelta(seconds=30)
    settlement_timeout: timedelta = timedelta(seconds=1)
    worker_count: int = 4
    queue_capacity: int = 64

    def __post_init__(self) -> None:
        if not isinstance(self.operation_timeout, timedelta):
            raise TypeError("operation_timeout must be timedelta")
        if (
            self.operation_timeout <= timedelta(0)
            or self.operation_timeout > MAX_WORKSPACE_TRANSFER_RUNTIME_OPERATION_TIMEOUT
        ):
            raise ValueError("operation_timeout is outside supported bounds")
        if not isinstance(self.settlement_timeout, timedelta):
            raise TypeError("settlement_timeout must be timedelta")
        if (
            self.settlement_timeout <= timedelta(0)
            or self.settlement_timeout > MAX_WORKSPACE_TRANSFER_RUNTIME_SETTLEMENT_TIMEOUT
        ):
            raise ValueError("settlement_timeout is outside supported bounds")
        if (
            isinstance(self.worker_count, bool)
            or not isinstance(self.worker_count, int)
            or not 1 <= self.worker_count <= MAX_WORKSPACE_TRANSFER_RUNTIME_WORKERS
        ):
            raise ValueError("worker_count is outside supported bounds")
        if (
            isinstance(self.queue_capacity, bool)
            or not isinstance(self.queue_capacity, int)
            or not 1 <= self.queue_capacity <= MAX_WORKSPACE_TRANSFER_RUNTIME_QUEUE_CAPACITY
        ):
            raise ValueError("queue_capacity is outside supported bounds")


@dataclass(slots=True)
class _ImportJob:
    request: ArtifactImportRequest
    context: SecurityContext
    future: asyncio.Future[ArtifactTransferReceipt]
    cancel_event: asyncio.Event


@dataclass(slots=True)
class _ExportJob:
    request: ArtifactExportRequest
    context: SecurityContext
    future: asyncio.Future[ArtifactTransferReceipt]
    cancel_event: asyncio.Event
    started_event: asyncio.Event


type _TransferJob = _ImportJob | _ExportJob


class AgentWorkspaceTransferRuntime:
    """Queue immutable requests, then run fresh authorization inside workers.

    Queue admission is finite and non-blocking. Import deadlines are hard response
    deadlines. Export deadlines trigger cancellation, then allow one additional
    bounded settlement window so a compliant adapter can return completion evidence
    for an already-committed side effect. A non-settling provider cannot hold the
    caller forever. Fixed workers bound provider concurrency when cancellation is
    suppressed.
    """

    def __init__(
        self,
        *,
        configuration: AgentWorkspaceTransferRuntimeConfiguration,
        service: _WorkspaceTransferService,
    ) -> None:
        if not isinstance(configuration, AgentWorkspaceTransferRuntimeConfiguration):
            raise TypeError("configuration must be AgentWorkspaceTransferRuntimeConfiguration")
        if not isinstance(service, _WorkspaceTransferService):
            raise TypeError("service must implement the workspace transfer service")
        try:
            service_closed = service.closed
        except Exception:
            raise AgentServiceUnavailableError() from None
        if not isinstance(service_closed, bool):
            raise TypeError("service closed state must be bool")
        if service_closed:
            raise AgentServiceUnavailableError()

        self._configuration = configuration
        self._service = service
        self._queue: asyncio.Queue[_TransferJob] = asyncio.Queue(
            maxsize=configuration.queue_capacity
        )
        self._workers: tuple[asyncio.Task[None], ...] = ()
        self._started = False
        self._closed = False

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def running(self) -> bool:
        return self._started and not self._closed

    @property
    def queued_transfers(self) -> int:
        return self._queue.qsize()

    async def start(self, context: RuntimeContext) -> None:
        if not isinstance(context, RuntimeContext):
            raise TypeError("context must be RuntimeContext")
        if self._closed:
            raise AgentServiceUnavailableError()
        self._require_service_open()
        if self._started:
            return

        self._workers = tuple(
            asyncio.create_task(
                self._worker_loop(),
                name=f"phoenix-agent-workspace-transfer-{index}",
            )
            for index in range(self._configuration.worker_count)
        )
        self._started = True

    async def stop(self, context: RuntimeContext) -> None:
        if not isinstance(context, RuntimeContext):
            raise TypeError("context must be RuntimeContext")
        await self.close()

    async def import_artifact(
        self,
        request: ArtifactImportRequest,
        context: SecurityContext,
    ) -> ArtifactTransferReceipt:
        self._require_request_context(request, ArtifactImportRequest, context)
        self._ensure_running()

        loop = asyncio.get_running_loop()
        future: asyncio.Future[ArtifactTransferReceipt] = loop.create_future()
        cancel_event = asyncio.Event()
        self._admit(
            _ImportJob(
                request=request,
                context=context,
                future=future,
                cancel_event=cancel_event,
            )
        )
        return await self._wait_for_import(future, cancel_event)

    async def export_artifact(
        self,
        request: ArtifactExportRequest,
        context: SecurityContext,
    ) -> ArtifactTransferReceipt:
        self._require_request_context(request, ArtifactExportRequest, context)
        self._ensure_running()

        loop = asyncio.get_running_loop()
        future: asyncio.Future[ArtifactTransferReceipt] = loop.create_future()
        cancel_event = asyncio.Event()
        started_event = asyncio.Event()
        self._admit(
            _ExportJob(
                request=request,
                context=context,
                future=future,
                cancel_event=cancel_event,
                started_event=started_event,
            )
        )
        return await self._wait_for_export(
            future,
            cancel_event=cancel_event,
            started_event=started_event,
        )

    async def close(self) -> None:
        if self._closed:
            return

        self._closed = True
        self._started = False

        while True:
            try:
                job = self._queue.get_nowait()
            except asyncio.QueueEmpty:
                break
            job.cancel_event.set()
            if not job.future.done():
                job.future.set_exception(AgentServiceUnavailableError())
            self._queue.task_done()

        workers = self._workers
        self._workers = ()
        for worker in workers:
            worker.cancel()

        if not workers:
            return

        try:
            done, pending = await asyncio.wait(
                set(workers),
                timeout=self._configuration.operation_timeout.total_seconds(),
            )
        except asyncio.CancelledError:
            for worker in workers:
                worker.add_done_callback(_consume_worker_task_result)
            raise

        for worker in done:
            _consume_worker_task_result(worker)
        for worker in pending:
            worker.add_done_callback(_consume_worker_task_result)

    def _admit(self, job: _TransferJob) -> None:
        try:
            self._queue.put_nowait(job)
        except asyncio.QueueFull:
            raise AgentServiceUnavailableError() from None

    async def _wait_for_import(
        self,
        future: asyncio.Future[ArtifactTransferReceipt],
        cancel_event: asyncio.Event,
    ) -> ArtifactTransferReceipt:
        try:
            done, pending = await asyncio.wait(
                {future},
                timeout=self._configuration.operation_timeout.total_seconds(),
            )
        except asyncio.CancelledError:
            cancel_event.set()
            if not future.done():
                future.cancel()
            raise

        if pending or future not in done:
            cancel_event.set()
            if not future.done():
                future.cancel()
            raise AgentServiceUnavailableError()

        return self._receipt_result(future)

    async def _wait_for_export(
        self,
        future: asyncio.Future[ArtifactTransferReceipt],
        *,
        cancel_event: asyncio.Event,
        started_event: asyncio.Event,
    ) -> ArtifactTransferReceipt:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + self._configuration.operation_timeout.total_seconds()
        started_wait = asyncio.create_task(
            started_event.wait(),
            name="phoenix-agent-workspace-transfer-export-start",
        )
        try:
            remaining = max(0.0, deadline - loop.time())
            waitables: set[asyncio.Future[object]] = {
                cast(asyncio.Future[object], future),
                cast(asyncio.Future[object], started_wait),
            }
            done, _pending = await asyncio.wait(
                waitables,
                timeout=remaining,
                return_when=asyncio.FIRST_COMPLETED,
            )
        except asyncio.CancelledError:
            started_wait.cancel()
            started_wait.add_done_callback(_consume_cancel_wait_result)
            if not started_event.is_set():
                cancel_event.set()
                if not future.done():
                    future.cancel()
                raise
            cancel_event.set()
            return await self._settle_started_export(
                future,
                cancellation_origin="caller",
            )

        if future in done:
            started_wait.cancel()
            started_wait.add_done_callback(_consume_cancel_wait_result)
            return self._receipt_result(future)

        if started_wait not in done and not started_event.is_set():
            started_wait.cancel()
            started_wait.add_done_callback(_consume_cancel_wait_result)
            cancel_event.set()
            if not future.done():
                future.cancel()
            raise AgentServiceUnavailableError()

        started_wait.cancel()
        started_wait.add_done_callback(_consume_cancel_wait_result)

        remaining = max(0.0, deadline - loop.time())
        try:
            result_done, _result_pending = await asyncio.wait(
                {future},
                timeout=remaining,
            )
        except asyncio.CancelledError:
            cancel_event.set()
            return await self._settle_started_export(
                future,
                cancellation_origin="caller",
            )

        if future in result_done:
            return self._receipt_result(future)

        # The deadline is now a cancellation trigger, not permission to discard
        # post-commit completion evidence. A compliant service/adapter either
        # acknowledges cancellation before commit or returns the committed receipt.
        cancel_event.set()
        return await self._settle_started_export(
            future,
            cancellation_origin="deadline",
        )

    async def _settle_started_export(
        self,
        future: asyncio.Future[ArtifactTransferReceipt],
        *,
        cancellation_origin: str,
    ) -> ArtifactTransferReceipt:
        loop = asyncio.get_running_loop()
        settlement_deadline = loop.time() + self._configuration.settlement_timeout.total_seconds()
        while True:
            remaining = max(0.0, settlement_deadline - loop.time())
            if remaining <= 0:
                if not future.done():
                    future.cancel()
                if cancellation_origin == "caller":
                    raise asyncio.CancelledError
                raise AgentServiceUnavailableError()

            try:
                done, _pending = await asyncio.wait(
                    {future},
                    timeout=remaining,
                )
            except asyncio.CancelledError:
                # Repeated caller cancellation cannot extend the finite settlement
                # window. Preserve a committed receipt if it arrives inside the
                # bound; otherwise cancellation wins when the window expires.
                continue

            if future in done:
                if future.cancelled():
                    if cancellation_origin == "caller":
                        raise asyncio.CancelledError
                    raise AgentServiceUnavailableError()
                return self._receipt_result(future)

            if not future.done():
                future.cancel()
            if cancellation_origin == "caller":
                raise asyncio.CancelledError
            raise AgentServiceUnavailableError()

    async def _worker_loop(self) -> None:
        while True:
            job = await self._queue.get()
            try:
                if job.future.done() or job.cancel_event.is_set():
                    if not job.future.done():
                        job.future.set_exception(AgentServiceUnavailableError())
                    continue
                if isinstance(job, _ImportJob):
                    await self._run_import_job(job)
                else:
                    await self._run_export_job(job)
            finally:
                self._queue.task_done()

    async def _run_import_job(self, job: _ImportJob) -> None:
        operation = asyncio.create_task(
            self._service.import_artifact(job.request, job.context),
            name="phoenix-agent-workspace-transfer-import",
        )
        cancel_wait = asyncio.create_task(
            job.cancel_event.wait(),
            name="phoenix-agent-workspace-transfer-import-cancel",
        )
        try:
            done, _pending = await asyncio.wait(
                {operation, cancel_wait},
                return_when=asyncio.FIRST_COMPLETED,
            )
        except asyncio.CancelledError:
            operation.cancel()
            operation.add_done_callback(_consume_receipt_task_result)
            cancel_wait.cancel()
            cancel_wait.add_done_callback(_consume_cancel_wait_result)
            if not job.future.done():
                job.future.set_exception(AgentServiceUnavailableError())
            raise

        if cancel_wait in done and operation not in done:
            operation.cancel()
            try:
                await asyncio.wait({operation})
            except asyncio.CancelledError:
                operation.add_done_callback(_consume_receipt_task_result)
                raise

        cancel_wait.cancel()
        cancel_wait.add_done_callback(_consume_cancel_wait_result)
        self._complete_job_from_operation(
            job.future,
            operation,
            expected_direction=ArtifactTransferDirection.IMPORT,
            request=job.request,
        )

    async def _run_export_job(self, job: _ExportJob) -> None:
        # Fresh authorization remains inside AgentWorkspaceService and therefore
        # happens only after dequeue, immediately before its provider boundary.
        job.started_event.set()
        operation = asyncio.create_task(
            self._service.export_artifact(job.request, job.context),
            name="phoenix-agent-workspace-transfer-export",
        )
        cancel_wait = asyncio.create_task(
            job.cancel_event.wait(),
            name="phoenix-agent-workspace-transfer-export-cancel",
        )
        try:
            done, _pending = await asyncio.wait(
                {operation, cancel_wait},
                return_when=asyncio.FIRST_COMPLETED,
            )
        except asyncio.CancelledError:
            operation.cancel()
            operation.add_done_callback(_consume_receipt_task_result)
            cancel_wait.cancel()
            cancel_wait.add_done_callback(_consume_cancel_wait_result)
            if not job.future.done():
                job.future.set_exception(AgentServiceUnavailableError())
            raise

        if cancel_wait in done and operation not in done:
            operation.cancel()
            try:
                await asyncio.wait({operation})
            except asyncio.CancelledError:
                operation.add_done_callback(_consume_receipt_task_result)
                raise

        cancel_wait.cancel()
        cancel_wait.add_done_callback(_consume_cancel_wait_result)
        self._complete_job_from_operation(
            job.future,
            operation,
            expected_direction=ArtifactTransferDirection.EXPORT,
            request=job.request,
        )

    def _complete_job_from_operation(
        self,
        future: asyncio.Future[ArtifactTransferReceipt],
        operation: asyncio.Task[ArtifactTransferReceipt],
        *,
        expected_direction: ArtifactTransferDirection,
        request: ArtifactImportRequest | ArtifactExportRequest,
    ) -> None:
        if future.done():
            _consume_receipt_task_result(operation)
            return
        try:
            receipt = operation.result()
        except asyncio.CancelledError:
            future.cancel()
            return
        except AgentError as exception:
            future.set_exception(exception)
            return
        except Exception:
            future.set_exception(AgentServiceUnavailableError())
            return

        try:
            validated = self._validate_receipt(
                receipt,
                expected_direction=expected_direction,
                request=request,
            )
        except AgentError as exception:
            future.set_exception(exception)
            return
        future.set_result(validated)

    @staticmethod
    def _validate_receipt(
        receipt: ArtifactTransferReceipt,
        *,
        expected_direction: ArtifactTransferDirection | None = None,
        request: ArtifactImportRequest | ArtifactExportRequest | None = None,
    ) -> ArtifactTransferReceipt:
        if not isinstance(receipt, ArtifactTransferReceipt):
            raise AgentCodecError("workspace transfer receipt is invalid")
        if expected_direction is not None and receipt.direction is not expected_direction:
            raise AgentCodecError("workspace transfer receipt is invalid")
        if request is not None:
            if receipt.scope != request.scope or receipt.artifact_id != request.artifact_id:
                raise AgentCodecError("workspace transfer receipt is invalid")
            if (
                isinstance(request, ArtifactExportRequest)
                and receipt.version != request.expected_version
            ):
                raise AgentCodecError("workspace transfer receipt is invalid")
        return receipt

    @classmethod
    def _receipt_result(
        cls,
        future: asyncio.Future[ArtifactTransferReceipt],
    ) -> ArtifactTransferReceipt:
        try:
            return cls._validate_receipt(future.result())
        except asyncio.CancelledError:
            raise AgentServiceUnavailableError() from None

    @staticmethod
    def _require_request_context(
        request: object,
        request_type: type[object],
        context: SecurityContext,
    ) -> None:
        if not isinstance(request, request_type):
            raise TypeError(f"request must be {request_type.__name__}")
        if not isinstance(context, SecurityContext):
            raise TypeError("context must be SecurityContext")

    def _ensure_running(self) -> None:
        if self._closed or not self._started:
            raise AgentServiceUnavailableError()
        self._require_service_open()

    def _require_service_open(self) -> None:
        try:
            closed = self._service.closed
        except Exception:
            raise AgentServiceUnavailableError() from None
        if not isinstance(closed, bool) or closed:
            raise AgentServiceUnavailableError()
