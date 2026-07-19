"""Safe workflow command contracts and handlers for the local control plane."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Awaitable
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol
from uuid import UUID, uuid4

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
    command_payload_digest,
)
from phoenix_os.control_plane.confirmation import (
    ControlPlaneConfirmationChallenge,
    ControlPlaneConfirmationProof,
)
from phoenix_os.control_plane.csrf import (
    ControlPlaneBrowserOrigin,
    ControlPlaneCsrfToken,
)
from phoenix_os.control_plane.errors import (
    ControlPlaneCommandBindingError,
    ControlPlaneCommandStateError,
)
from phoenix_os.control_plane.protection import ControlPlaneCommandProtector
from phoenix_os.workflows import WorkflowRecord, WorkflowStatus


class ControlPlaneWorkflowOrchestrator(Protocol):
    """Minimal workflow surface required by command handlers."""

    def get(self, workflow_id: UUID) -> Awaitable[WorkflowRecord | None]: ...

    def cancel(
        self,
        workflow_id: UUID,
        *,
        now: datetime | None = None,
    ) -> Awaitable[WorkflowRecord]: ...


@dataclass(frozen=True, slots=True)
class ControlPlaneCancelWorkflowCommand:
    """Exact workflow cancellation target used by the destructive command path."""

    workflow_id: UUID
    schema_version: int = 1

    def __post_init__(self) -> None:
        if self.schema_version != 1:
            raise ValueError("unsupported cancel-workflow command schema version")

    @property
    def target(self) -> str:
        return f"workflow:{self.workflow_id}"

    @property
    def canonical_payload(self) -> bytes:
        return json.dumps(
            {
                "schema_version": self.schema_version,
                "workflow_id": str(self.workflow_id),
            },
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    @property
    def payload_digest(self) -> str:
        return command_payload_digest(self.canonical_payload)

    def intent(
        self,
        idempotency_key: IdempotencyKey,
        *,
        requested_at: datetime,
        command_id: UUID | None = None,
    ) -> ControlPlaneCommandIntent:
        return ControlPlaneCommandIntent(
            id=uuid4() if command_id is None else command_id,
            action=ControlPlaneCommandAction.CANCEL_WORKFLOW,
            target=self.target,
            idempotency_key=idempotency_key,
            payload_digest=self.payload_digest,
            requested_at=requested_at,
        )


@dataclass(frozen=True, slots=True)
class ControlPlaneWorkflowCommandResult:
    """Safe workflow handler result containing only the command receipt."""

    receipt: ControlPlaneCommandReceipt

    def __post_init__(self) -> None:
        if self.receipt.action is not ControlPlaneCommandAction.CANCEL_WORKFLOW:
            raise ValueError("workflow command result requires workflow.cancel receipt")


class ControlPlaneWorkflowCommandHandler:
    """Authorize, protect, deduplicate, and execute workflow cancellation."""

    def __init__(
        self,
        orchestrator: ControlPlaneWorkflowOrchestrator,
        authorizer: ControlPlaneCommandAuthorizer,
        protector: ControlPlaneCommandProtector,
        idempotency: ControlPlaneIdempotencyStore,
    ) -> None:
        self._orchestrator = orchestrator
        self._authorizer = authorizer
        self._protector = protector
        self._idempotency = idempotency

    async def issue_cancel_confirmation(
        self,
        principal: ControlPlanePrincipal,
        intent: ControlPlaneCommandIntent,
        command: ControlPlaneCancelWorkflowCommand,
        *,
        origin: ControlPlaneBrowserOrigin,
        csrf_token: ControlPlaneCsrfToken,
    ) -> ControlPlaneConfirmationChallenge:
        _require_binding(intent, command)
        self._authorizer.require(principal, intent.action)
        return await self._protector.issue_confirmation(
            principal,
            intent,
            origin=origin,
            csrf_token=csrf_token,
        )

    async def cancel_workflow(
        self,
        principal: ControlPlanePrincipal,
        intent: ControlPlaneCommandIntent,
        command: ControlPlaneCancelWorkflowCommand,
        *,
        origin: ControlPlaneBrowserOrigin,
        csrf_token: ControlPlaneCsrfToken,
        confirmation: ControlPlaneConfirmationProof,
    ) -> ControlPlaneWorkflowCommandResult:
        _require_binding(intent, command)
        self._authorizer.require(principal, intent.action)
        await self._protector.verify(
            principal,
            intent,
            origin=origin,
            csrf_token=csrf_token,
            confirmation=confirmation,
        )
        reservation = await self._idempotency.reserve(intent)
        receipt = reservation.receipt
        if receipt.status.terminal:
            return ControlPlaneWorkflowCommandResult(receipt)

        existing = await self._safe_get(command.workflow_id)
        if existing is None:
            return ControlPlaneWorkflowCommandResult(await self._fail(intent, "workflow.not-found"))
        if existing.status is WorkflowStatus.CANCELLED:
            return ControlPlaneWorkflowCommandResult(
                await self._complete(intent, "workflow.cancelled")
            )
        if existing.status.terminal:
            return ControlPlaneWorkflowCommandResult(
                await self._fail(intent, "workflow.not-cancellable")
            )

        try:
            cancelled = await self._orchestrator.cancel(
                command.workflow_id,
                now=receipt.created_at,
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            current = await self._safe_get(command.workflow_id)
            if current is None:
                return ControlPlaneWorkflowCommandResult(
                    await self._fail(intent, "workflow.not-found")
                )
            if current.status is WorkflowStatus.CANCELLED:
                return ControlPlaneWorkflowCommandResult(
                    await self._complete(intent, "workflow.cancelled")
                )
            return ControlPlaneWorkflowCommandResult(
                await self._fail(intent, "workflow.cancel-failed")
            )

        if cancelled.status is WorkflowStatus.CANCELLED:
            return ControlPlaneWorkflowCommandResult(
                await self._complete(intent, "workflow.cancelled")
            )
        if cancelled.status.terminal:
            return ControlPlaneWorkflowCommandResult(
                await self._fail(intent, "workflow.not-cancellable")
            )
        return ControlPlaneWorkflowCommandResult(await self._fail(intent, "workflow.cancel-failed"))

    async def _safe_get(self, workflow_id: UUID) -> WorkflowRecord | None:
        try:
            return await self._orchestrator.get(workflow_id)
        except asyncio.CancelledError:
            raise
        except Exception:
            return None

    async def _complete(
        self,
        intent: ControlPlaneCommandIntent,
        result_code: str,
    ) -> ControlPlaneCommandReceipt:
        try:
            return await self._idempotency.complete(intent, result_code=result_code)
        except ControlPlaneCommandStateError:
            current = await self._idempotency.get(intent.idempotency_key)
            if current is not None and current.status.terminal:
                return current
            raise

    async def _fail(
        self,
        intent: ControlPlaneCommandIntent,
        result_code: str,
    ) -> ControlPlaneCommandReceipt:
        try:
            return await self._idempotency.fail(intent, result_code=result_code)
        except ControlPlaneCommandStateError:
            current = await self._idempotency.get(intent.idempotency_key)
            if current is not None and current.status.terminal:
                return current
            raise


def _require_binding(
    intent: ControlPlaneCommandIntent,
    command: ControlPlaneCancelWorkflowCommand,
) -> None:
    if (
        intent.action is not ControlPlaneCommandAction.CANCEL_WORKFLOW
        or intent.target != command.target
        or intent.payload_digest != command.payload_digest
    ):
        raise ControlPlaneCommandBindingError("command intent does not match submitted command")
