"""High-level command API used by the loopback HTTP transport."""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Mapping
from contextlib import AbstractContextManager, nullcontext
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol, cast
from uuid import UUID

from phoenix_os.control_plane.auth import (
    ControlPlaneCommandAuthorizer,
    ControlPlanePrincipal,
)
from phoenix_os.control_plane.commands import (
    ControlPlaneCommandAction,
    ControlPlaneCommandIntent,
    ControlPlaneCommandReceipt,
    ControlPlaneIdempotencyStore,
    IdempotencyKey,
)
from phoenix_os.control_plane.confirmation import (
    ControlPlaneConfirmationChallenge,
    ControlPlaneConfirmationProof,
    ControlPlaneConfirmationService,
)
from phoenix_os.control_plane.csrf import (
    ControlPlaneBrowserOrigin,
    ControlPlaneCsrfProtector,
    ControlPlaneCsrfToken,
)
from phoenix_os.control_plane.job_commands import (
    ControlPlaneCancelJobCommand,
    ControlPlaneCreateJobCommand,
    ControlPlaneJobCommandHandler,
    ControlPlaneJobCommandResult,
    ControlPlaneRetryDeadLetterJobCommand,
)
from phoenix_os.control_plane.workflow_commands import (
    ControlPlaneCancelWorkflowCommand,
    ControlPlaneWorkflowCommandHandler,
    ControlPlaneWorkflowCommandResult,
)
from phoenix_os.events import BusClosedError, EventBus

type ControlPlaneCommandApiClock = Callable[[], datetime]


class _PrincipalScopedIdempotencyStore(Protocol):
    def principal_scope(self, principal: str) -> AbstractContextManager[None]: ...


def _utc_now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class ControlPlaneCommandAvailability:
    """Non-sensitive action availability for one authenticated principal."""

    create_job: bool
    cancel_job: bool
    retry_dead_letter_job: bool
    cancel_workflow: bool
    schema_version: int = 1

    def __post_init__(self) -> None:
        if self.schema_version != 1:
            raise ValueError("unsupported command availability schema version")


class ControlPlaneCommandApi:
    """Issue browser protections and invoke exact safe command handlers."""

    def __init__(
        self,
        *,
        csrf: ControlPlaneCsrfProtector,
        confirmations: ControlPlaneConfirmationService,
        idempotency: ControlPlaneIdempotencyStore,
        authorizer: ControlPlaneCommandAuthorizer,
        events: EventBus,
        jobs: ControlPlaneJobCommandHandler | None = None,
        workflows: ControlPlaneWorkflowCommandHandler | None = None,
        clock: ControlPlaneCommandApiClock = _utc_now,
    ) -> None:
        if not callable(clock):
            raise TypeError("command API clock must be callable")
        self._csrf = csrf
        self._confirmations = confirmations
        self._idempotency = idempotency
        self._authorizer = authorizer
        self._events = events
        self._jobs = jobs
        self._workflows = workflows
        self._clock = clock
        self._closed = False
        self._lock = asyncio.Lock()

    @property
    def closed(self) -> bool:
        return self._closed

    async def start(self, context: object = None) -> None:
        del context
        async with self._lock:
            if self._closed:
                raise RuntimeError("control-plane command API is closed")

    async def stop(self, context: object = None) -> None:
        del context
        async with self._lock:
            if self._closed:
                return
            self._closed = True
        await self._confirmations.close()
        await self._idempotency.close()

    def availability(self, principal: ControlPlanePrincipal) -> ControlPlaneCommandAvailability:
        jobs = self._jobs is not None
        workflows = self._workflows is not None
        return ControlPlaneCommandAvailability(
            create_job=jobs
            and self._authorizer.decide(principal, ControlPlaneCommandAction.CREATE_JOB).allowed,
            cancel_job=jobs
            and self._authorizer.decide(principal, ControlPlaneCommandAction.CANCEL_JOB).allowed,
            retry_dead_letter_job=jobs
            and self._authorizer.decide(
                principal,
                ControlPlaneCommandAction.RETRY_DEAD_LETTER_JOB,
            ).allowed,
            cancel_workflow=workflows
            and self._authorizer.decide(
                principal,
                ControlPlaneCommandAction.CANCEL_WORKFLOW,
            ).allowed,
        )

    def issue_csrf(
        self,
        principal: ControlPlanePrincipal,
        origin: ControlPlaneBrowserOrigin,
    ) -> ControlPlaneCsrfToken:
        self._require_open()
        return self._csrf.issue(principal, origin)

    async def create_job(
        self,
        principal: ControlPlanePrincipal,
        command: ControlPlaneCreateJobCommand,
        key: IdempotencyKey,
        *,
        origin: ControlPlaneBrowserOrigin,
        csrf_token: ControlPlaneCsrfToken,
    ) -> ControlPlaneJobCommandResult:
        handler = self._require_jobs()
        intent = command.intent(key, requested_at=self._now())
        with self._principal_scope(principal):
            result = await handler.create_job(
                principal,
                intent,
                command,
                origin=origin,
                csrf_token=csrf_token,
            )
        await self._record_receipt(principal, result.receipt)
        return result

    async def retry_dead_letter_job(
        self,
        principal: ControlPlanePrincipal,
        command: ControlPlaneRetryDeadLetterJobCommand,
        key: IdempotencyKey,
        *,
        origin: ControlPlaneBrowserOrigin,
        csrf_token: ControlPlaneCsrfToken,
    ) -> ControlPlaneJobCommandResult:
        handler = self._require_jobs()
        intent = command.intent(key, requested_at=self._now())
        with self._principal_scope(principal):
            result = await handler.retry_dead_letter_job(
                principal,
                intent,
                command,
                origin=origin,
                csrf_token=csrf_token,
            )
        await self._record_receipt(principal, result.receipt)
        return result

    async def issue_job_cancel_confirmation(
        self,
        principal: ControlPlanePrincipal,
        command: ControlPlaneCancelJobCommand,
        key: IdempotencyKey,
        *,
        command_id: UUID,
        origin: ControlPlaneBrowserOrigin,
        csrf_token: ControlPlaneCsrfToken,
    ) -> ControlPlaneConfirmationChallenge:
        handler = self._require_jobs()
        intent = command.intent(key, requested_at=self._now(), command_id=command_id)
        challenge = await handler.issue_cancel_confirmation(
            principal,
            intent,
            command,
            origin=origin,
            csrf_token=csrf_token,
        )
        await self._record(
            principal,
            intent,
            status="confirmation-issued",
            result_code="confirmation.issued",
        )
        return challenge

    async def cancel_job(
        self,
        principal: ControlPlanePrincipal,
        command: ControlPlaneCancelJobCommand,
        key: IdempotencyKey,
        *,
        command_id: UUID,
        origin: ControlPlaneBrowserOrigin,
        csrf_token: ControlPlaneCsrfToken,
        confirmation: ControlPlaneConfirmationProof,
    ) -> ControlPlaneJobCommandResult:
        handler = self._require_jobs()
        intent = command.intent(key, requested_at=self._now(), command_id=command_id)
        with self._principal_scope(principal):
            result = await handler.cancel_job(
                principal,
                intent,
                command,
                origin=origin,
                csrf_token=csrf_token,
                confirmation=confirmation,
            )
        await self._record_receipt(principal, result.receipt)
        return result

    async def issue_workflow_cancel_confirmation(
        self,
        principal: ControlPlanePrincipal,
        command: ControlPlaneCancelWorkflowCommand,
        key: IdempotencyKey,
        *,
        command_id: UUID,
        origin: ControlPlaneBrowserOrigin,
        csrf_token: ControlPlaneCsrfToken,
    ) -> ControlPlaneConfirmationChallenge:
        handler = self._require_workflows()
        intent = command.intent(key, requested_at=self._now(), command_id=command_id)
        challenge = await handler.issue_cancel_confirmation(
            principal,
            intent,
            command,
            origin=origin,
            csrf_token=csrf_token,
        )
        await self._record(
            principal,
            intent,
            status="confirmation-issued",
            result_code="confirmation.issued",
        )
        return challenge

    async def cancel_workflow(
        self,
        principal: ControlPlanePrincipal,
        command: ControlPlaneCancelWorkflowCommand,
        key: IdempotencyKey,
        *,
        command_id: UUID,
        origin: ControlPlaneBrowserOrigin,
        csrf_token: ControlPlaneCsrfToken,
        confirmation: ControlPlaneConfirmationProof,
    ) -> ControlPlaneWorkflowCommandResult:
        handler = self._require_workflows()
        intent = command.intent(key, requested_at=self._now(), command_id=command_id)
        with self._principal_scope(principal):
            result = await handler.cancel_workflow(
                principal,
                intent,
                command,
                origin=origin,
                csrf_token=csrf_token,
                confirmation=confirmation,
            )
        await self._record_receipt(principal, result.receipt)
        return result

    async def record_rejection(
        self,
        principal: ControlPlanePrincipal,
        *,
        action: ControlPlaneCommandAction | None,
        target: str,
        result_code: str,
        command_id: UUID | None = None,
    ) -> None:
        payload: dict[str, object] = {
            "actor": principal.name,
            "outcome": "denied",
            "result_code": result_code,
            "resource": target,
            "status": "rejected",
        }
        if action is not None:
            payload["action"] = action.value
        if command_id is not None:
            payload["command_id"] = str(command_id)
        await self._safe_emit("control-plane.command.rejected", payload)

    async def _record_receipt(
        self,
        principal: ControlPlanePrincipal,
        receipt: ControlPlaneCommandReceipt,
    ) -> None:
        status = receipt.status.value
        await self._safe_emit(
            f"control-plane.command.{status}",
            {
                "action": receipt.action.value,
                "actor": principal.name,
                "command_id": str(receipt.command_id),
                "outcome": "succeeded" if status == "succeeded" else "failed",
                "resource": receipt.target,
                "result_code": receipt.result_code or "command.pending",
                "status": status,
            },
            correlation_id=f"control-plane:{receipt.command_id.hex}",
            causation_id=receipt.command_id,
        )

    async def _record(
        self,
        principal: ControlPlanePrincipal,
        intent: ControlPlaneCommandIntent,
        *,
        status: str,
        result_code: str,
    ) -> None:
        outcome = "succeeded" if status in {"succeeded", "confirmation-issued"} else "failed"
        await self._safe_emit(
            f"control-plane.command.{status}",
            {
                "action": intent.action.value,
                "actor": principal.name,
                "command_id": str(intent.id),
                "outcome": outcome,
                "resource": intent.target,
                "result_code": result_code,
                "status": status,
            },
            correlation_id=f"control-plane:{intent.id.hex}",
            causation_id=intent.id,
        )

    async def _safe_emit(
        self,
        name: str,
        payload: Mapping[str, object],
        *,
        correlation_id: str | None = None,
        causation_id: UUID | None = None,
    ) -> None:
        try:
            await self._events.emit(
                name,
                source="phoenix.control-plane",
                payload=payload,
                correlation_id=correlation_id,
                causation_id=causation_id,
            )
        except (BusClosedError, RuntimeError):
            pass

    def _require_jobs(self) -> ControlPlaneJobCommandHandler:
        self._require_open()
        if self._jobs is None:
            raise RuntimeError("job commands are unavailable")
        return self._jobs

    def _require_workflows(self) -> ControlPlaneWorkflowCommandHandler:
        self._require_open()
        if self._workflows is None:
            raise RuntimeError("workflow commands are unavailable")
        return self._workflows

    def _principal_scope(
        self,
        principal: ControlPlanePrincipal,
    ) -> AbstractContextManager[None]:
        scope = getattr(self._idempotency, "principal_scope", None)
        if scope is None:
            return nullcontext()
        scoped = cast(_PrincipalScopedIdempotencyStore, self._idempotency)
        return scoped.principal_scope(principal.name)

    def _require_open(self) -> None:
        if self._closed:
            raise RuntimeError("control-plane command API is closed")

    def _now(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None:
            raise ValueError("command API clock must return timezone-aware datetimes")
        return value
