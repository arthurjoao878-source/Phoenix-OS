from __future__ import annotations

import asyncio
import json

import pytest

from phoenix_os import (
    AllowAllAuthorizer,
    CapabilityRegistry,
    ConfigLoader,
    ConfigSchema,
    EventBus,
    Kernel,
    MappingConfigSource,
    MemoryStateStore,
    PhoenixRuntime,
    Router,
    RuntimeAssembler,
)
from phoenix_os.control_plane import (
    AdminTokenAuthenticator,
    ControlPlaneCommandHistoryService,
    ControlPlaneCommandJournalRepository,
    ControlPlaneCommandRecoveryWorker,
    ControlPlaneCommandRecoveryWorkerState,
    ControlPlaneCommandRetentionWorker,
    ControlPlaneCommandRetentionWorkerState,
    ControlPlaneHttpServer,
    ControlPlaneService,
    InMemoryControlPlaneCommandJournalRepository,
    StateControlPlaneCommandJournalRepository,
)

_TOKEN = "durable-command-journal-token-000001"


async def _runtime(
    *,
    state: MemoryStateStore | None = None,
    journal: ControlPlaneCommandJournalRepository | None = None,
) -> PhoenixRuntime:
    events = EventBus()
    configuration = await ConfigLoader(ConfigSchema(()), (MappingConfigSource({}),)).load()
    return await RuntimeAssembler(
        kernel=Kernel(router=Router(), authorizer=AllowAllAuthorizer(), events=events),
        events=events,
        capabilities=CapabilityRegistry(events=events),
        configuration=configuration,
        state=state,
        control_plane_authenticator=AdminTokenAuthenticator(_TOKEN),
        control_plane_command_journal=journal,
        control_plane_command_recovery_poll_interval=3600,
        control_plane_command_retention_poll_interval=3600,
    ).assemble()


async def _get(server: ControlPlaneHttpServer, path: str) -> tuple[int, dict[str, object]]:
    assert server.port is not None
    reader, writer = await asyncio.open_connection(server.host, server.port)
    request = f"GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {_TOKEN}\r\n\r\n"
    writer.write(request.encode("ascii"))
    await writer.drain()
    response = await reader.read()
    writer.close()
    await writer.wait_closed()
    head, body = response.split(b"\r\n\r\n", 1)
    status = int(head.split(b" ", 2)[1])
    return status, json.loads(body)


@pytest.mark.asyncio
async def test_runtime_assembler_uses_memory_journal_without_state_store() -> None:
    runtime = await _runtime()

    assert isinstance(
        runtime.service("control_plane.command-journal"),
        InMemoryControlPlaneCommandJournalRepository,
    )
    assert isinstance(
        runtime.service("control_plane.command-history"),
        ControlPlaneCommandHistoryService,
    )


@pytest.mark.asyncio
async def test_runtime_assembler_uses_state_journal_with_default_state_store() -> None:
    runtime = await _runtime(state=MemoryStateStore())

    assert isinstance(
        runtime.service("control_plane.command-journal"),
        StateControlPlaneCommandJournalRepository,
    )


@pytest.mark.asyncio
async def test_runtime_assembler_honors_explicit_command_journal() -> None:
    journal = InMemoryControlPlaneCommandJournalRepository(capacity=17)
    runtime = await _runtime(journal=journal)

    assert runtime.service("control_plane.command-journal") is journal
    assert (await journal.snapshot()).capacity == 17


@pytest.mark.asyncio
async def test_runtime_owns_recovery_retention_and_journal_lifecycle() -> None:
    runtime = await _runtime()
    journal = runtime.service("control_plane.command-journal")
    assert isinstance(journal, InMemoryControlPlaneCommandJournalRepository)
    recovery = runtime.service("control_plane.command-recovery")
    retention = runtime.service("control_plane.command-retention")
    assert isinstance(recovery, ControlPlaneCommandRecoveryWorker)
    assert isinstance(retention, ControlPlaneCommandRetentionWorker)

    await runtime.start()

    assert recovery.state is ControlPlaneCommandRecoveryWorkerState.RUNNING
    assert retention.state is ControlPlaneCommandRetentionWorkerState.RUNNING
    snapshot = await runtime.snapshot()
    assert "control_plane.command-journal" in snapshot.active_components
    assert "control_plane.command-recovery" in snapshot.active_components
    assert "control_plane.command-retention" in snapshot.active_components

    await runtime.stop()

    assert (await recovery.snapshot()).state is ControlPlaneCommandRecoveryWorkerState.STOPPED
    assert (await retention.snapshot()).state is ControlPlaneCommandRetentionWorkerState.STOPPED
    assert journal.closed


@pytest.mark.asyncio
async def test_runtime_exposes_empty_authenticated_command_history() -> None:
    runtime = await _runtime()
    server = runtime.service("control_plane.http")
    assert isinstance(server, ControlPlaneHttpServer)
    await runtime.start()

    status, payload = await _get(server, "/v1/control-plane/commands/history?limit=20")

    assert status == 200
    assert payload["items"] == []
    page = payload["page"]
    assert isinstance(page, dict)
    assert page["total"] == 0
    await runtime.stop()


@pytest.mark.asyncio
async def test_runtime_snapshot_includes_durable_command_journal_counters() -> None:
    runtime = await _runtime()
    service = runtime.service("control_plane")
    assert isinstance(service, ControlPlaneService)
    await runtime.start()

    snapshot = await service.snapshot()

    assert snapshot.command_journal is not None
    assert snapshot.command_journal.entries == 0
    assert not snapshot.command_journal.closed
    await runtime.stop()


@pytest.mark.asyncio
async def test_runtime_assembler_rejects_journal_without_authenticator() -> None:
    events = EventBus()
    configuration = await ConfigLoader(ConfigSchema(()), (MappingConfigSource({}),)).load()

    with pytest.raises(ValueError, match="require an authenticator"):
        RuntimeAssembler(
            kernel=Kernel(router=Router(), authorizer=AllowAllAuthorizer(), events=events),
            events=events,
            capabilities=CapabilityRegistry(events=events),
            configuration=configuration,
            control_plane_command_journal=InMemoryControlPlaneCommandJournalRepository(),
        )
