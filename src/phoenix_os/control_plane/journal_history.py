"""Safe paginated history views for durable control-plane commands."""

from __future__ import annotations

from collections.abc import Awaitable, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol
from uuid import UUID

from phoenix_os.control_plane.auth import ControlPlanePrincipal
from phoenix_os.control_plane.commands import ControlPlaneCommandAction
from phoenix_os.control_plane.journal_contracts import (
    DEFAULT_COMMAND_JOURNAL_PAGE_REQUEST,
    ControlPlaneCommandJournalPageInfo,
    ControlPlaneCommandJournalPageRequest,
    ControlPlaneCommandJournalRecord,
    ControlPlaneCommandJournalRepository,
    ControlPlaneCommandJournalStatus,
)
from phoenix_os.events import BusClosedError, EventBus


@dataclass(frozen=True, slots=True)
class ControlPlaneCommandHistoryView:
    """Allowlisted command history item without digests, payloads, or exception text."""

    command_id: UUID
    action: ControlPlaneCommandAction
    target: str
    principal: str
    status: ControlPlaneCommandJournalStatus
    requested_at: datetime
    updated_at: datetime
    completed_at: datetime | None
    result_code: str | None
    revision: int
    schema_version: int = 1

    def __post_init__(self) -> None:
        if self.schema_version != 1:
            raise ValueError("unsupported command history schema version")
        if self.revision <= 0:
            raise ValueError("command history revision must be positive")
        if not self.target.strip() or not self.principal.strip():
            raise ValueError("command history identity fields must not be blank")
        for label, value in (
            ("requested_at", self.requested_at),
            ("updated_at", self.updated_at),
        ):
            if value.tzinfo is None:
                raise ValueError(f"{label} must be timezone-aware")
        if self.completed_at is not None and self.completed_at.tzinfo is None:
            raise ValueError("completed_at must be timezone-aware")
        object.__setattr__(self, "action", ControlPlaneCommandAction(self.action))
        object.__setattr__(self, "status", ControlPlaneCommandJournalStatus(self.status))
        object.__setattr__(self, "target", self.target.strip())
        object.__setattr__(self, "principal", self.principal.strip())

    @classmethod
    def from_record(
        cls,
        record: ControlPlaneCommandJournalRecord,
    ) -> ControlPlaneCommandHistoryView:
        return cls(
            command_id=record.command_id,
            action=record.action,
            target=record.target,
            principal=record.principal,
            status=record.status,
            requested_at=record.requested_at,
            updated_at=record.updated_at,
            completed_at=record.completed_at,
            result_code=record.result_code,
            revision=record.revision,
        )


@dataclass(frozen=True, slots=True)
class ControlPlaneCommandHistoryPage:
    """Bounded newest-first operation history page."""

    items: tuple[ControlPlaneCommandHistoryView, ...]
    page: ControlPlaneCommandJournalPageInfo
    schema_version: int = 1

    def __post_init__(self) -> None:
        if self.schema_version != 1:
            raise ValueError("unsupported command history page schema version")
        if len(self.items) != self.page.returned:
            raise ValueError("command history page count must match items")
        identities = tuple(item.command_id for item in self.items)
        if len(identities) != len(set(identities)):
            raise ValueError("command history page items must be unique")


class ControlPlaneCommandHistoryReader(Protocol):
    def list_history(
        self,
        principal: ControlPlanePrincipal,
        request: ControlPlaneCommandJournalPageRequest = DEFAULT_COMMAND_JOURNAL_PAGE_REQUEST,
    ) -> Awaitable[ControlPlaneCommandHistoryPage]: ...


class ControlPlaneCommandHistoryService:
    """Read safe command history and emit payload-free audit facts."""

    def __init__(
        self,
        repository: ControlPlaneCommandJournalRepository,
        *,
        events: EventBus | None = None,
    ) -> None:
        self._repository = repository
        self._events = events

    async def list_history(
        self,
        principal: ControlPlanePrincipal,
        request: ControlPlaneCommandJournalPageRequest = DEFAULT_COMMAND_JOURNAL_PAGE_REQUEST,
    ) -> ControlPlaneCommandHistoryPage:
        page = await self._repository.list_page(request)
        history = ControlPlaneCommandHistoryPage(
            items=tuple(ControlPlaneCommandHistoryView.from_record(item) for item in page.items),
            page=page.page,
        )
        await self._safe_emit(
            "control-plane.command.journal.history-read",
            {
                "action": "command-history.read",
                "actor": principal.name,
                "outcome": "succeeded",
                "resource": "control-plane:command-journal",
                "returned": history.page.returned,
                "status": "succeeded",
                "total": history.page.total,
            },
        )
        return history

    async def _safe_emit(self, name: str, payload: Mapping[str, object]) -> None:
        if self._events is None:
            return
        try:
            await self._events.emit(
                name,
                source="phoenix.control-plane",
                payload=payload,
            )
        except (BusClosedError, RuntimeError):
            pass
