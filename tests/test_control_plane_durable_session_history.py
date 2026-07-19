from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest

from phoenix_os.control_plane.auth import CONTROL_PLANE_READ_PERMISSION, ControlPlanePrincipal
from phoenix_os.control_plane.durable_session_contracts import (
    ControlPlaneDurableCsrfSecret,
    ControlPlaneDurableSessionPageRequest,
    ControlPlaneDurableSessionPolicy,
    ControlPlaneDurableSessionRecord,
    ControlPlaneDurableSessionStatus,
    ControlPlaneDurableSessionTerminationReason,
    ControlPlaneDurableSessionToken,
)
from phoenix_os.control_plane.durable_session_history import (
    ControlPlaneDurableSessionHistoryService,
    ControlPlaneDurableSessionView,
)
from phoenix_os.control_plane.durable_session_memory import (
    InMemoryControlPlaneDurableSessionRepository,
)
from phoenix_os.control_plane.errors import ControlPlaneOperatorPermissionDeniedError
from phoenix_os.control_plane.operator_contracts import (
    CONTROL_PLANE_OPERATOR_SESSIONS_READ_PERMISSION,
)
from phoenix_os.control_plane.serialization import durable_session_history_page_to_dict
from phoenix_os.events import Event, EventBus

_BASE = datetime(2026, 7, 19, 18, tzinfo=UTC)
_POLICY = ControlPlaneDurableSessionPolicy(
    absolute_ttl=timedelta(hours=2),
    idle_ttl=timedelta(hours=1),
    rotation_interval=timedelta(minutes=30),
)


def _principal(*permissions: str) -> ControlPlanePrincipal:
    return ControlPlanePrincipal(
        "maintainer",
        frozenset({CONTROL_PLANE_READ_PERMISSION, *permissions}),
    )


def _record(index: int, *, operator_id: UUID | None = None) -> ControlPlaneDurableSessionRecord:
    return ControlPlaneDurableSessionRecord.issue(
        operator_id=operator_id or uuid4(),
        username=f"operator-{index}",
        token=ControlPlaneDurableSessionToken(f"token-{index:026d}"),
        csrf_secret=ControlPlaneDurableCsrfSecret(f"csrf-{index:027d}"),
        operator_revision=1,
        operator_token_version=1,
        issued_at=_BASE + timedelta(minutes=index),
        policy=_POLICY,
    )


@pytest.mark.asyncio
async def test_history_requires_exact_read_permission() -> None:
    repository = InMemoryControlPlaneDurableSessionRepository()
    service = ControlPlaneDurableSessionHistoryService(repository)

    with pytest.raises(ControlPlaneOperatorPermissionDeniedError):
        await service.list_history(_principal())


@pytest.mark.asyncio
async def test_history_returns_allowlisted_view_without_digests() -> None:
    repository = InMemoryControlPlaneDurableSessionRepository()
    record = _record(1)
    await repository.add(record)
    service = ControlPlaneDurableSessionHistoryService(repository)

    page = await service.list_history(_principal(CONTROL_PLANE_OPERATOR_SESSIONS_READ_PERMISSION))
    document = durable_session_history_page_to_dict(page)

    assert page.items == (ControlPlaneDurableSessionView.from_record(record),)
    assert document["items"][0]["session_id"] == str(record.id)  # type: ignore[index]
    assert "token_digest" not in repr(document)
    assert "csrf_digest" not in repr(document)


@pytest.mark.asyncio
async def test_history_is_newest_first_and_paginated() -> None:
    repository = InMemoryControlPlaneDurableSessionRepository()
    records = [_record(index) for index in range(1, 5)]
    for record in records:
        await repository.add(record)
    service = ControlPlaneDurableSessionHistoryService(repository)
    principal = _principal(CONTROL_PLANE_OPERATOR_SESSIONS_READ_PERMISSION)

    first = await service.list_history(
        principal,
        ControlPlaneDurableSessionPageRequest(limit=2),
    )
    second = await service.list_history(
        principal,
        ControlPlaneDurableSessionPageRequest(offset=2, limit=2),
    )

    assert [item.session_id for item in first.items] == [records[3].id, records[2].id]
    assert [item.session_id for item in second.items] == [records[1].id, records[0].id]
    assert first.page.next_offset == 2
    assert second.page.next_offset is None


@pytest.mark.asyncio
async def test_history_filters_exact_operator_and_status() -> None:
    repository = InMemoryControlPlaneDurableSessionRepository()
    operator_id = uuid4()
    active = _record(1, operator_id=operator_id)
    terminal = _record(2, operator_id=operator_id)
    other = _record(3)
    for record in (active, terminal, other):
        await repository.add(record)
    terminal = await repository.terminate(
        terminal.id,
        expected_revision=terminal.revision,
        status=ControlPlaneDurableSessionStatus.REVOKED,
        reason=ControlPlaneDurableSessionTerminationReason.ADMINISTRATIVE,
        terminated_at=_BASE + timedelta(minutes=10),
    )
    service = ControlPlaneDurableSessionHistoryService(repository)

    page = await service.list_history(
        _principal(CONTROL_PLANE_OPERATOR_SESSIONS_READ_PERMISSION),
        ControlPlaneDurableSessionPageRequest(
            operator_id=operator_id,
            status=ControlPlaneDurableSessionStatus.REVOKED,
        ),
    )

    assert [item.session_id for item in page.items] == [terminal.id]
    assert page.items[0].termination_reason is (
        ControlPlaneDurableSessionTerminationReason.ADMINISTRATIVE
    )


@pytest.mark.asyncio
async def test_history_emits_safe_read_event() -> None:
    repository = InMemoryControlPlaneDurableSessionRepository()
    await repository.add(_record(1))
    events = EventBus()
    captured: list[Event] = []
    await events.subscribe("*", captured.append)
    service = ControlPlaneDurableSessionHistoryService(repository, events=events)

    await service.list_history(_principal(CONTROL_PLANE_OPERATOR_SESSIONS_READ_PERMISSION))

    event = captured[-1]
    assert event.name == "control-plane.operator.session.history-read"
    assert event.payload["actor"] == "maintainer"
    assert "token" not in repr(event.payload).lower()
    assert "digest" not in repr(event.payload).lower()


def test_history_view_rejects_blank_username() -> None:
    record = _record(1)
    with pytest.raises(ValueError, match="username"):
        ControlPlaneDurableSessionView(
            session_id=record.id,
            operator_id=record.operator_id,
            username=" ",
            generation=record.generation,
            issued_at=record.issued_at,
            last_seen_at=record.last_seen_at,
            absolute_expires_at=record.absolute_expires_at,
            idle_expires_at=record.idle_expires_at,
            rotate_after=record.rotate_after,
            status=record.status,
            terminated_at=None,
            termination_reason=None,
            predecessor_session_id=None,
            successor_session_id=None,
            revision=record.revision,
        )
