from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import pytest

from phoenix_os.control_plane import (
    AdminTokenAuthenticator,
    AuditSummary,
    CapabilityPage,
    ControlPlaneCommandAction,
    ControlPlaneCommandHistoryPage,
    ControlPlaneCommandHistoryService,
    ControlPlaneCommandHistoryView,
    ControlPlaneCommandJournalPageInfo,
    ControlPlaneCommandJournalPageRequest,
    ControlPlaneCommandJournalRecord,
    ControlPlaneCommandJournalSnapshot,
    ControlPlaneCommandJournalStatus,
    ControlPlaneHealth,
    ControlPlaneHttpServer,
    ControlPlanePrincipal,
    ControlPlaneService,
    ControlPlaneSnapshot,
    InMemoryControlPlaneCommandJournalRepository,
    JobPage,
    PageInfo,
    PageRequest,
    PluginPage,
    WorkflowPage,
    WorkflowSummary,
    command_history_page_to_dict,
    snapshot_to_dict,
)
from phoenix_os.events import Event, EventBus
from phoenix_os.jobs import JobSchedulerSnapshot
from phoenix_os.runtime import RuntimeSnapshot, RuntimeState

_NOW = datetime(2026, 7, 19, 6, 0, tzinfo=UTC)
_TOKEN = "command-history-token-000000000001"
_DEFAULT_PAGE = PageRequest()


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def _record(
    index: int = 1,
    *,
    status: ControlPlaneCommandJournalStatus = ControlPlaneCommandJournalStatus.PENDING,
    principal: str = "dashboard.operator",
) -> ControlPlaneCommandJournalRecord:
    requested_at = _NOW + timedelta(minutes=index)
    terminal = status.terminal
    return ControlPlaneCommandJournalRecord(
        command_id=UUID(int=index),
        action=ControlPlaneCommandAction.CREATE_JOB,
        target=f"job:history-{index}",
        principal=principal,
        idempotency_digest=_digest(f"key-{index}"),
        fingerprint=_digest(f"fingerprint-{index}"),
        status=status,
        requested_at=requested_at,
        updated_at=requested_at + (timedelta(seconds=1) if terminal else timedelta()),
        completed_at=requested_at + timedelta(seconds=1) if terminal else None,
        result_code="job.created" if terminal else None,
        revision=2 if terminal else 1,
    )


class _Reader:
    async def snapshot(self) -> ControlPlaneSnapshot:
        return _snapshot()

    async def list_jobs(self, page: PageRequest = _DEFAULT_PAGE) -> JobPage:
        return JobPage((), PageInfo.from_slice(page, returned=0, total=0))

    async def list_workflows(self, page: PageRequest = _DEFAULT_PAGE) -> WorkflowPage:
        return WorkflowPage((), PageInfo.from_slice(page, returned=0, total=0))

    async def list_capabilities(self, page: PageRequest = _DEFAULT_PAGE) -> CapabilityPage:
        return CapabilityPage((), PageInfo.from_slice(page, returned=0, total=0))

    async def list_plugins(self, page: PageRequest = _DEFAULT_PAGE) -> PluginPage:
        return PluginPage((), PageInfo.from_slice(page, returned=0, total=0))

    async def audit_summary(self) -> AuditSummary | None:
        return None


class _RuntimeSource:
    async def snapshot(self) -> RuntimeSnapshot:
        return _snapshot().runtime


class _JobSource:
    async def snapshot(self) -> JobSchedulerSnapshot:
        return _snapshot().jobs


class _WorkflowSource:
    async def list_all(self) -> tuple[object, ...]:
        return ()


def _snapshot() -> ControlPlaneSnapshot:
    return ControlPlaneSnapshot(
        generated_at=_NOW,
        health=ControlPlaneHealth.HEALTHY,
        runtime=RuntimeSnapshot(
            runtime_id=UUID(int=900),
            state=RuntimeState.RUNNING,
            components=(),
            active_components=(),
            in_flight_requests=0,
            created_at=_NOW,
            started_at=_NOW,
            stopped_at=None,
        ),
        jobs=JobSchedulerSnapshot(False, 0, 0, 0, 0, 0, 0, 0, 0),
        workflows=WorkflowSummary(0, 0, 0, 0, 0, 0),
    )


async def _request(
    server: ControlPlaneHttpServer,
    path: str,
    *,
    token: str | None = _TOKEN,
    method: str = "GET",
) -> tuple[int, dict[str, Any]]:
    assert server.port is not None
    reader, writer = await asyncio.open_connection(server.host, server.port)
    lines = [f"{method} {path} HTTP/1.1", f"Host: {server.host}"]
    if token is not None:
        lines.append(f"Authorization: Bearer {token}")
    writer.write(("\r\n".join(lines) + "\r\n\r\n").encode("ascii"))
    await writer.drain()
    response = await reader.read()
    writer.close()
    await writer.wait_closed()
    head, body = response.split(b"\r\n\r\n", 1)
    status = int(head.split(b" ", 2)[1])
    return status, json.loads(body)


def test_history_view_from_record_omits_protected_fields() -> None:
    record = _record(1, status=ControlPlaneCommandJournalStatus.SUCCEEDED)

    view = ControlPlaneCommandHistoryView.from_record(record)

    assert view.command_id == record.command_id
    assert view.status is ControlPlaneCommandJournalStatus.SUCCEEDED
    assert not hasattr(view, "idempotency_digest")
    assert not hasattr(view, "fingerprint")
    assert "idempotency" not in repr(view)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("schema_version", 2, "schema"),
        ("revision", 0, "revision"),
        ("target", " ", "identity"),
        ("principal", " ", "identity"),
        ("requested_at", datetime(2026, 1, 1), "requested_at"),
        ("updated_at", datetime(2026, 1, 1), "updated_at"),
        ("completed_at", datetime(2026, 1, 1), "completed_at"),
    ],
)
def test_history_view_rejects_invalid_values(field: str, value: object, message: str) -> None:
    view = ControlPlaneCommandHistoryView.from_record(
        _record(1, status=ControlPlaneCommandJournalStatus.SUCCEEDED)
    )

    with pytest.raises(ValueError, match=message):
        replace(view, **{field: value})  # type: ignore[arg-type]


def test_history_page_rejects_count_mismatch() -> None:
    with pytest.raises(ValueError, match="count"):
        ControlPlaneCommandHistoryPage(
            (),
            ControlPlaneCommandJournalPageInfo(0, 10, 1, 1, None),
        )


def test_history_page_rejects_duplicate_items() -> None:
    item = ControlPlaneCommandHistoryView.from_record(_record())

    with pytest.raises(ValueError, match="unique"):
        ControlPlaneCommandHistoryPage(
            (item, item),
            ControlPlaneCommandJournalPageInfo(0, 2, 2, 2, None),
        )


def test_history_page_rejects_unknown_schema() -> None:
    with pytest.raises(ValueError, match="schema"):
        ControlPlaneCommandHistoryPage(
            (),
            ControlPlaneCommandJournalPageInfo(0, 10, 0, 0, None),
            schema_version=2,
        )


@pytest.mark.asyncio
async def test_history_service_returns_newest_first_page_and_safe_audit_fact() -> None:
    repository = InMemoryControlPlaneCommandJournalRepository()
    for index in range(1, 4):
        await repository.add(_record(index))
    events = EventBus()
    captured: list[Event] = []
    await events.subscribe("*", captured.append)
    service = ControlPlaneCommandHistoryService(repository, events=events)

    page = await service.list_history(
        ControlPlanePrincipal("dashboard.operator"),
        ControlPlaneCommandJournalPageRequest(offset=1, limit=1),
    )

    assert tuple(item.command_id for item in page.items) == (UUID(int=2),)
    assert page.page.total == 3
    assert page.page.next_offset == 2
    event = captured[-1]
    assert event.name == "control-plane.command.journal.history-read"
    assert event.payload["actor"] == "dashboard.operator"
    assert event.payload["returned"] == 1
    assert "digest" not in repr(event.payload)
    assert "fingerprint" not in repr(event.payload)


@pytest.mark.asyncio
async def test_history_service_ignores_closed_event_bus() -> None:
    repository = InMemoryControlPlaneCommandJournalRepository()
    await repository.add(_record())
    events = EventBus()
    await events.close()
    service = ControlPlaneCommandHistoryService(repository, events=events)

    page = await service.list_history(ControlPlanePrincipal("operator"))

    assert page.page.total == 1


@pytest.mark.asyncio
async def test_history_service_filters_exact_operator_before_paginating() -> None:
    repository = InMemoryControlPlaneCommandJournalRepository()
    principals = ("alice", "bob", "alice", "carol", "alice")
    for index, principal in enumerate(principals, start=1):
        await repository.add(_record(index, principal=principal))
    service = ControlPlaneCommandHistoryService(repository)

    page = await service.list_history(
        ControlPlanePrincipal("maintainer"),
        ControlPlaneCommandJournalPageRequest(offset=1, limit=2),
        operator=" Alice ",
    )

    assert tuple(item.command_id for item in page.items) == (UUID(int=3), UUID(int=1))
    assert all(item.principal == "alice" for item in page.items)
    assert page.page.total == 3
    assert page.page.next_offset is None


@pytest.mark.asyncio
async def test_history_service_operator_filter_is_included_as_safe_audit_fact() -> None:
    repository = InMemoryControlPlaneCommandJournalRepository()
    await repository.add(_record(1, principal="alice"))
    events = EventBus()
    captured: list[Event] = []
    await events.subscribe("*", captured.append)
    service = ControlPlaneCommandHistoryService(repository, events=events)

    await service.list_history(ControlPlanePrincipal("maintainer"), operator="alice")

    assert captured[-1].payload["operator"] == "alice"
    assert "digest" not in repr(captured[-1].payload)


@pytest.mark.asyncio
async def test_http_history_endpoint_filters_by_operator() -> None:
    repository = InMemoryControlPlaneCommandJournalRepository()
    await repository.add(_record(1, principal="alice"))
    await repository.add(_record(2, principal="bob"))
    await repository.add(_record(3, principal="alice"))
    server = ControlPlaneHttpServer(
        _Reader(),
        AdminTokenAuthenticator(_TOKEN),
        command_history=ControlPlaneCommandHistoryService(repository),
    )
    await server.start()
    try:
        status, payload = await _request(
            server,
            "/v1/control-plane/commands/history?operator=alice&limit=20",
        )
    finally:
        await server.stop()

    assert status == 200
    assert payload["page"]["total"] == 2
    assert [item["principal"] for item in payload["items"]] == ["alice", "alice"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "path",
    [
        "/v1/control-plane/commands/history?operator=",
        "/v1/control-plane/commands/history?operator=alice&operator=bob",
    ],
)
async def test_http_history_endpoint_rejects_invalid_operator_filter(path: str) -> None:
    server = ControlPlaneHttpServer(
        _Reader(),
        AdminTokenAuthenticator(_TOKEN),
        command_history=ControlPlaneCommandHistoryService(
            InMemoryControlPlaneCommandJournalRepository()
        ),
    )
    await server.start()
    try:
        status, payload = await _request(server, path)
    finally:
        await server.stop()

    assert status == 400
    assert payload == {"error": "invalid_pagination"}


def test_command_history_serializer_is_allowlisted() -> None:
    record = _record(1, status=ControlPlaneCommandJournalStatus.SUCCEEDED)
    page = ControlPlaneCommandHistoryPage(
        (ControlPlaneCommandHistoryView.from_record(record),),
        ControlPlaneCommandJournalPageInfo(0, 10, 1, 1, None),
    )

    payload = command_history_page_to_dict(page)
    serialized = json.dumps(payload, sort_keys=True)

    assert payload["schema_version"] == 1
    assert payload["items"][0]["command_id"] == str(record.command_id)  # type: ignore[index]
    assert "idempotency_digest" not in serialized
    assert "fingerprint" not in serialized
    assert "arguments" not in serialized
    assert "output" not in serialized
    assert "secret" not in serialized


def test_snapshot_serializer_includes_safe_command_journal_counters() -> None:
    journal = ControlPlaneCommandJournalSnapshot(False, 3, 1, 1, 1, 0, 0, 10)
    payload = snapshot_to_dict(replace(_snapshot(), command_journal=journal))

    assert payload["command_journal"] == {
        "closed": False,
        "entries": 3,
        "pending": 1,
        "executing": 1,
        "succeeded": 1,
        "rejected": 0,
        "failed": 0,
        "capacity": 10,
    }


@pytest.mark.asyncio
async def test_control_plane_service_collects_command_journal_snapshot() -> None:
    repository = InMemoryControlPlaneCommandJournalRepository(capacity=10)
    await repository.add(_record())
    service = ControlPlaneService(
        _RuntimeSource(),
        _JobSource(),
        _WorkflowSource(),  # type: ignore[arg-type]
        command_journal=repository,
        clock=lambda: _NOW,
    )

    snapshot = await service.snapshot()

    assert snapshot.command_journal is not None
    assert snapshot.command_journal.entries == 1
    assert snapshot.health is ControlPlaneHealth.HEALTHY


@pytest.mark.asyncio
async def test_closed_command_journal_degrades_control_plane_health() -> None:
    repository = InMemoryControlPlaneCommandJournalRepository(capacity=10)
    await repository.close()
    service = ControlPlaneService(
        _RuntimeSource(),
        _JobSource(),
        _WorkflowSource(),  # type: ignore[arg-type]
        command_journal=repository,
        clock=lambda: _NOW,
    )

    snapshot = await service.snapshot()

    assert snapshot.command_journal is not None
    assert snapshot.command_journal.closed is True
    assert snapshot.health is ControlPlaneHealth.DEGRADED


@pytest.mark.asyncio
async def test_http_history_endpoint_requires_authentication_and_supports_pagination() -> None:
    repository = InMemoryControlPlaneCommandJournalRepository()
    await repository.add(_record(1))
    await repository.add(_record(2))
    history = ControlPlaneCommandHistoryService(repository)
    server = ControlPlaneHttpServer(
        _Reader(),
        AdminTokenAuthenticator(_TOKEN),
        command_history=history,
    )
    await server.start()
    try:
        unauthorized, _ = await _request(server, "/v1/control-plane/commands/history", token=None)
        status, payload = await _request(
            server,
            "/v1/control-plane/commands/history?offset=1&limit=1",
        )
    finally:
        await server.stop()

    assert unauthorized == 401
    assert status == 200
    assert payload["page"]["total"] == 2
    assert payload["items"][0]["command_id"] == str(UUID(int=1))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("/v1/control-plane/commands/history?offset=-1", 400),
        ("/v1/control-plane/commands/history?limit=0", 400),
        ("/v1/control-plane/commands/history?limit=201", 400),
        ("/v1/control-plane/commands/history?unknown=1", 400),
    ],
)
async def test_http_history_endpoint_rejects_invalid_pagination(path: str, expected: int) -> None:
    repository = InMemoryControlPlaneCommandJournalRepository()
    server = ControlPlaneHttpServer(
        _Reader(),
        AdminTokenAuthenticator(_TOKEN),
        command_history=ControlPlaneCommandHistoryService(repository),
    )
    await server.start()
    try:
        status, payload = await _request(server, path)
    finally:
        await server.stop()

    assert status == expected
    assert payload == {"error": "invalid_pagination"}


@pytest.mark.asyncio
async def test_http_history_endpoint_reports_unavailable_and_rejects_post() -> None:
    server = ControlPlaneHttpServer(_Reader(), AdminTokenAuthenticator(_TOKEN))
    await server.start()
    try:
        unavailable, payload = await _request(server, "/v1/control-plane/commands/history")
        method, method_payload = await _request(
            server,
            "/v1/control-plane/commands/history",
            method="POST",
        )
    finally:
        await server.stop()

    assert unavailable == 503
    assert payload == {"error": "history_unavailable"}
    assert method == 405
    assert method_payload == {"error": "method_not_allowed"}
