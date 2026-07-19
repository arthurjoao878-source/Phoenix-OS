"""Allowlisted durable operator-session history for the local control plane."""

from __future__ import annotations

from collections.abc import Awaitable, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol
from uuid import UUID

from phoenix_os.control_plane.auth import ControlPlanePrincipal
from phoenix_os.control_plane.durable_session_contracts import (
    DEFAULT_DURABLE_SESSION_PAGE_REQUEST,
    ControlPlaneDurableSessionPageInfo,
    ControlPlaneDurableSessionPageRequest,
    ControlPlaneDurableSessionRecord,
    ControlPlaneDurableSessionRepository,
    ControlPlaneDurableSessionStatus,
    ControlPlaneDurableSessionTerminationReason,
)
from phoenix_os.control_plane.errors import ControlPlaneOperatorPermissionDeniedError
from phoenix_os.control_plane.operator_contracts import (
    CONTROL_PLANE_OPERATOR_SESSIONS_READ_PERMISSION,
)
from phoenix_os.events import BusClosedError, EventBus


@dataclass(frozen=True, slots=True)
class ControlPlaneDurableSessionView:
    """Safe session history without token or CSRF digests."""

    session_id: UUID
    operator_id: UUID
    username: str
    generation: int
    issued_at: datetime
    last_seen_at: datetime
    absolute_expires_at: datetime
    idle_expires_at: datetime
    rotate_after: datetime
    status: ControlPlaneDurableSessionStatus
    terminated_at: datetime | None
    termination_reason: ControlPlaneDurableSessionTerminationReason | None
    predecessor_session_id: UUID | None
    successor_session_id: UUID | None
    revision: int
    schema_version: int = 1

    def __post_init__(self) -> None:
        username = self.username.strip().lower()
        if not username:
            raise ValueError("durable session history username must not be blank")
        if self.generation <= 0 or self.revision <= 0:
            raise ValueError("durable session history versions must be positive")
        for label, value in (
            ("issued_at", self.issued_at),
            ("last_seen_at", self.last_seen_at),
            ("absolute_expires_at", self.absolute_expires_at),
            ("idle_expires_at", self.idle_expires_at),
            ("rotate_after", self.rotate_after),
        ):
            if value.tzinfo is None:
                raise ValueError(f"durable session history {label} must be timezone-aware")
        if self.terminated_at is not None and self.terminated_at.tzinfo is None:
            raise ValueError("durable session history terminated_at must be timezone-aware")
        if self.schema_version != 1:
            raise ValueError("unsupported durable session history schema version")
        object.__setattr__(self, "username", username)
        object.__setattr__(self, "status", ControlPlaneDurableSessionStatus(self.status))
        if self.termination_reason is not None:
            object.__setattr__(
                self,
                "termination_reason",
                ControlPlaneDurableSessionTerminationReason(self.termination_reason),
            )

    @classmethod
    def from_record(
        cls, record: ControlPlaneDurableSessionRecord
    ) -> ControlPlaneDurableSessionView:
        return cls(
            session_id=record.id,
            operator_id=record.operator_id,
            username=record.username,
            generation=record.generation,
            issued_at=record.issued_at,
            last_seen_at=record.last_seen_at,
            absolute_expires_at=record.absolute_expires_at,
            idle_expires_at=record.idle_expires_at,
            rotate_after=record.rotate_after,
            status=record.status,
            terminated_at=record.terminated_at,
            termination_reason=record.termination_reason,
            predecessor_session_id=record.predecessor_session_id,
            successor_session_id=record.successor_session_id,
            revision=record.revision,
        )


@dataclass(frozen=True, slots=True)
class ControlPlaneDurableSessionHistoryPage:
    """Bounded newest-first session history page."""

    items: tuple[ControlPlaneDurableSessionView, ...]
    page: ControlPlaneDurableSessionPageInfo
    schema_version: int = 1

    def __post_init__(self) -> None:
        if len(self.items) != self.page.returned:
            raise ValueError("durable session history page count must match items")
        if len({item.session_id for item in self.items}) != len(self.items):
            raise ValueError("durable session history items must be unique")
        if self.schema_version != 1:
            raise ValueError("unsupported durable session history page schema version")


class ControlPlaneDurableSessionHistoryReader(Protocol):
    def list_history(
        self,
        principal: ControlPlanePrincipal,
        request: ControlPlaneDurableSessionPageRequest = DEFAULT_DURABLE_SESSION_PAGE_REQUEST,
    ) -> Awaitable[ControlPlaneDurableSessionHistoryPage]: ...


class ControlPlaneDurableSessionHistoryService:
    """Read safe session history under an exact RBAC permission."""

    def __init__(
        self,
        repository: ControlPlaneDurableSessionRepository,
        *,
        events: EventBus | None = None,
    ) -> None:
        self._repository = repository
        self._events = events

    async def list_history(
        self,
        principal: ControlPlanePrincipal,
        request: ControlPlaneDurableSessionPageRequest = DEFAULT_DURABLE_SESSION_PAGE_REQUEST,
    ) -> ControlPlaneDurableSessionHistoryPage:
        if CONTROL_PLANE_OPERATOR_SESSIONS_READ_PERMISSION not in principal.permissions:
            raise ControlPlaneOperatorPermissionDeniedError(
                "durable session history permission denied"
            )
        page = await self._repository.list_page(request)
        history = ControlPlaneDurableSessionHistoryPage(
            items=tuple(ControlPlaneDurableSessionView.from_record(item) for item in page.items),
            page=page.page,
        )
        await self._safe_emit(
            "control-plane.operator.session.history-read",
            {
                "action": "operator-session.history-read",
                "actor": principal.name,
                "outcome": "succeeded",
                "resource": "control-plane:operator-sessions",
                "returned": history.page.returned,
                "status": "succeeded",
                "total": history.page.total,
                **(
                    {} if request.operator_id is None else {"operator_id": str(request.operator_id)}
                ),
            },
        )
        return history

    async def _safe_emit(self, name: str, payload: Mapping[str, object]) -> None:
        if self._events is None:
            return
        try:
            await self._events.emit(name, source="phoenix.control-plane", payload=payload)
        except (BusClosedError, RuntimeError):
            pass
