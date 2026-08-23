from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from phoenix_os.agent import (
    AgentAuthorizationRejectedError,
    AgentCodecError,
    AgentId,
    AgentServiceUnavailableError,
    AgentTimeoutError,
    AgentWorkspaceAdministration,
    AgentWorkspaceAdministrationSnapshot,
    ArtifactId,
    ArtifactLogicalPath,
    ArtifactOriginKind,
    ArtifactProvenance,
    ArtifactWriteRequest,
    ContentFreeAgentWorkspaceObserver,
    InMemoryWorkspaceBackingAdapter,
    StateStoreWorkspaceStore,
    WorkspaceAdministrationScan,
    WorkspaceLimits,
    WorkspaceNamespace,
    WorkspaceScope,
    agent_workspace_scope,
    artifact_content_digest,
)
from phoenix_os.events import Event, EventBus
from phoenix_os.policy import PrincipalType, SecurityContext
from phoenix_os.runtime import RuntimeContext
from phoenix_os.state import MemoryStateStore

_NOW = datetime(2026, 8, 14, 6, tzinfo=UTC)
_SECRET_CONTENT = b"TOP-SECRET-WORKSPACE-ADMIN-CONTENT"
_SECRET_PATH = "private/top-secret-workspace-admin-name.txt"
_SECRET_METADATA = "TOP-SECRET-WORKSPACE-ADMIN-METADATA"


def _scope() -> WorkspaceScope:
    return agent_workspace_scope(
        namespace=WorkspaceNamespace("admin-workspace"),
        agent_id=AgentId("administration-agent"),
    )


def _context() -> SecurityContext:
    return SecurityContext(
        principal="service:workspace-administration",
        principal_type=PrincipalType.SERVICE,
        authenticated=True,
        correlation_id="corr-workspace-admin",
    )


def _write_request(index: int) -> ArtifactWriteRequest:
    content = _SECRET_CONTENT + str(index).encode()
    return ArtifactWriteRequest(
        scope=_scope(),
        artifact_id=ArtifactId(UUID(f"e0000000-0000-0000-0000-{index:012x}")),
        logical_path=ArtifactLogicalPath(f"{_SECRET_PATH[:-4]}-{index}.txt"),
        content=content,
        provenance=ArtifactProvenance(
            origin=ArtifactOriginKind.OPERATOR,
            content_digest=artifact_content_digest(content),
            created_at=_NOW,
        ),
        metadata={"private": f"{_SECRET_METADATA}-{index}"},
        created_at=_NOW,
    )


class _RuntimeGate:
    def __init__(self, *, limits: WorkspaceLimits, running: bool = True) -> None:
        self._limits = limits
        self._running = running

    @property
    def running(self) -> bool:
        return self._running

    @property
    def limits(self) -> WorkspaceLimits:
        return self._limits


class _Authorizer:
    def __init__(self, *, deny_admin: bool = False) -> None:
        self.admin_calls = 0
        self.deny_admin = deny_admin

    async def authorize_list(self, request: object, context: SecurityContext) -> None:
        del request, context

    async def authorize_read(self, request: object, context: SecurityContext) -> None:
        del request, context

    async def authorize_write(self, request: object, context: SecurityContext) -> None:
        del request, context

    async def authorize_delete(self, request: object, context: SecurityContext) -> None:
        del request, context

    async def authorize_import(
        self,
        request: object,
        context: SecurityContext,
    ) -> None:
        del request, context

    async def authorize_export(
        self,
        request: object,
        context: SecurityContext,
    ) -> None:
        del request, context

    async def authorize_admin(
        self,
        scope: WorkspaceScope,
        context: SecurityContext,
        *,
        created_at: datetime | None = None,
    ) -> None:
        del scope, context, created_at
        self.admin_calls += 1
        if self.deny_admin:
            raise AgentAuthorizationRejectedError()


class _ScanStore:
    def __init__(self, scan: WorkspaceAdministrationScan) -> None:
        self.closed = False
        self.scan = scan
        self.calls = 0

    async def administration_scan(
        self,
        *,
        scope: WorkspaceScope,
        max_records: int,
    ) -> WorkspaceAdministrationScan:
        self.calls += 1
        del max_records
        if self.scan.scope != scope:
            raise AssertionError("unexpected scope")
        return self.scan


@pytest.mark.asyncio
async def test_workspace_administration_snapshot_is_bounded_content_free_and_observed() -> None:
    limits = WorkspaceLimits(
        max_artifact_bytes=1_024,
        max_artifacts_per_scope=10,
        max_artifact_id_history_per_scope=10,
        max_total_bytes_per_scope=10_240,
        max_list_results=5,
    )
    store = StateStoreWorkspaceStore(
        MemoryStateStore(clock=lambda: _NOW),
        InMemoryWorkspaceBackingAdapter(),
        limits=limits,
        clock=lambda: _NOW,
        owns_state_store=True,
        owns_backing=True,
    )
    for index in range(1, 4):
        await store.write(_write_request(index))

    events = EventBus()
    captured: list[Event] = []

    async def capture(event: Event) -> None:
        if event.name.startswith("agent.workspace.admin."):
            captured.append(event)

    await events.subscribe("*", capture)
    observer = ContentFreeAgentWorkspaceObserver(events=events)
    await observer.start(RuntimeContext(services={}))
    authorizer = _Authorizer()
    administration = AgentWorkspaceAdministration(
        runtime=_RuntimeGate(limits=limits),
        store=store,
        authorizer=authorizer,
        observer=observer,
        max_records_per_snapshot=2,
    )

    snapshot = await administration.snapshot(_scope(), _context())
    await observer.close()

    assert isinstance(snapshot, AgentWorkspaceAdministrationSnapshot)
    assert snapshot.scanned_records == 2
    assert snapshot.active_artifacts == 2
    assert snapshot.expired_artifacts == 0
    assert snapshot.tombstones == 0
    assert snapshot.truncated is True
    assert snapshot.active_bytes == sum(len(_SECRET_CONTENT + str(i).encode()) for i in (1, 2))
    assert authorizer.admin_calls == 1
    serialized = repr((snapshot, captured))
    assert _SECRET_CONTENT.decode() not in serialized
    assert _SECRET_PATH not in serialized
    assert _SECRET_METADATA not in serialized
    assert "logical_path" not in serialized
    assert "'private'" not in serialized
    assert [event.name for event in captured] == ["agent.workspace.admin.succeeded"]
    assert captured[0].payload == {}
    await store.close()


@pytest.mark.asyncio
async def test_workspace_administration_requires_fresh_admin_before_store_access() -> None:
    scan = WorkspaceAdministrationScan(
        scope=_scope(),
        scanned_records=0,
        active_artifacts=0,
        active_bytes=0,
        expired_artifacts=0,
        tombstones=0,
        truncated=False,
        created_at=_NOW,
    )
    store = _ScanStore(scan)
    authorizer = _Authorizer(deny_admin=True)
    administration = AgentWorkspaceAdministration(
        runtime=_RuntimeGate(limits=WorkspaceLimits()),
        store=store,
        authorizer=authorizer,
    )

    with pytest.raises(AgentAuthorizationRejectedError):
        await administration.snapshot(_scope(), _context())

    assert authorizer.admin_calls == 1
    assert store.calls == 0


@pytest.mark.asyncio
async def test_workspace_administration_enforces_configured_scan_bound_before_authority() -> None:
    scan = WorkspaceAdministrationScan(
        scope=_scope(),
        scanned_records=0,
        active_artifacts=0,
        active_bytes=0,
        expired_artifacts=0,
        tombstones=0,
        truncated=False,
        created_at=_NOW,
    )
    store = _ScanStore(scan)
    authorizer = _Authorizer()
    administration = AgentWorkspaceAdministration(
        runtime=_RuntimeGate(limits=WorkspaceLimits()),
        store=store,
        authorizer=authorizer,
        max_records_per_snapshot=2,
    )

    with pytest.raises(ValueError, match="max_records"):
        await administration.snapshot(_scope(), _context(), max_records=3)

    assert authorizer.admin_calls == 0
    assert store.calls == 0


@pytest.mark.asyncio
async def test_workspace_administration_fails_closed_when_runtime_is_not_running() -> None:
    scan = WorkspaceAdministrationScan(
        scope=_scope(),
        scanned_records=0,
        active_artifacts=0,
        active_bytes=0,
        expired_artifacts=0,
        tombstones=0,
        truncated=False,
        created_at=_NOW,
    )
    store = _ScanStore(scan)
    authorizer = _Authorizer()
    administration = AgentWorkspaceAdministration(
        runtime=_RuntimeGate(limits=WorkspaceLimits(), running=False),
        store=store,
        authorizer=authorizer,
    )

    with pytest.raises(AgentServiceUnavailableError):
        await administration.snapshot(_scope(), _context())

    assert authorizer.admin_calls == 0
    assert store.calls == 0


@pytest.mark.asyncio
async def test_workspace_administration_rejects_record_missing_from_identity_ledger() -> None:
    class _MissingLedgerStateStore(MemoryStateStore):
        def bounded_read_transaction(self) -> object:  # type: ignore[override]
            inner = super().bounded_read_transaction()

            class _Transaction:
                @property
                def state(self) -> object:
                    return inner.state

                async def __aenter__(self) -> object:
                    await inner.__aenter__()
                    return self

                async def list_bounded(
                    self,
                    *,
                    namespace: str | None = None,
                    prefix: str | None = None,
                    limit: int,
                ) -> object:
                    if (
                        namespace == "agent-workspace"
                        and prefix is not None
                        and prefix.startswith("ledger.")
                    ):
                        return ()
                    return await inner.list_bounded(
                        namespace=namespace,
                        prefix=prefix,
                        limit=limit,
                    )

                async def list_bounded_page(
                    self,
                    *,
                    namespace: str | None = None,
                    prefix: str | None = None,
                    after: str | None = None,
                    limit: int,
                ) -> object:
                    return await inner.list_bounded_page(
                        namespace=namespace,
                        prefix=prefix,
                        after=after,
                        limit=limit,
                    )

                async def commit(self) -> None:
                    await inner.commit()

                async def rollback(self) -> None:
                    await inner.rollback()

            return _Transaction()

    limits = WorkspaceLimits(
        max_artifact_bytes=1_024,
        max_artifacts_per_scope=10,
        max_artifact_id_history_per_scope=10,
        max_total_bytes_per_scope=10_240,
        max_list_results=5,
    )
    state = _MissingLedgerStateStore(clock=lambda: _NOW)
    store = StateStoreWorkspaceStore(
        state,
        InMemoryWorkspaceBackingAdapter(),
        limits=limits,
        clock=lambda: _NOW,
        owns_state_store=True,
        owns_backing=True,
    )
    await store.write(_write_request(1))

    administration = AgentWorkspaceAdministration(
        runtime=_RuntimeGate(limits=limits),
        store=store,
        authorizer=_Authorizer(),
    )

    with pytest.raises(AgentCodecError, match="identity ledger"):
        await administration.snapshot(_scope(), _context())

    await store.close()


@pytest.mark.asyncio
async def test_workspace_administration_sanitizes_unexpected_provider_failure() -> None:
    class _FailingStore(_ScanStore):
        async def administration_scan(
            self,
            *,
            scope: WorkspaceScope,
            max_records: int,
        ) -> WorkspaceAdministrationScan:
            del scope, max_records
            raise RuntimeError("TOP-SECRET-PROVIDER-BODY")

    scan = WorkspaceAdministrationScan(
        scope=_scope(),
        scanned_records=0,
        active_artifacts=0,
        active_bytes=0,
        expired_artifacts=0,
        tombstones=0,
        truncated=False,
        created_at=_NOW,
    )
    administration = AgentWorkspaceAdministration(
        runtime=_RuntimeGate(limits=WorkspaceLimits()),
        store=_FailingStore(scan),
        authorizer=_Authorizer(),
    )

    with pytest.raises(AgentServiceUnavailableError) as failure:
        await administration.snapshot(_scope(), _context())

    assert str(failure.value) == "agent service is unavailable"
    assert "TOP-SECRET-PROVIDER-BODY" not in repr(failure.value)


def test_workspace_administration_snapshot_rejects_active_count_above_configured_limit() -> None:
    with pytest.raises(ValueError, match="active_artifacts"):
        AgentWorkspaceAdministrationSnapshot(
            scope=_scope(),
            scanned_records=2,
            active_artifacts=2,
            active_bytes=2,
            expired_artifacts=0,
            tombstones=0,
            truncated=False,
            record_limit=2,
            max_artifact_bytes=1_024,
            max_artifacts_per_scope=1,
            max_total_bytes_per_scope=1_024,
            created_at=_NOW,
        )


def test_workspace_administration_scan_rejects_bytes_without_active_artifacts() -> None:
    with pytest.raises(ValueError, match="byte counters"):
        WorkspaceAdministrationScan(
            scope=_scope(),
            scanned_records=0,
            active_artifacts=0,
            active_bytes=1,
            expired_artifacts=0,
            tombstones=0,
            truncated=False,
            created_at=_NOW,
        )


def test_workspace_administration_snapshot_rejects_bytes_above_artifact_bound() -> None:
    with pytest.raises(ValueError, match="active artifact bounds"):
        AgentWorkspaceAdministrationSnapshot(
            scope=_scope(),
            scanned_records=1,
            active_artifacts=1,
            active_bytes=2,
            expired_artifacts=0,
            tombstones=0,
            truncated=False,
            record_limit=1,
            max_artifact_bytes=1,
            max_artifacts_per_scope=1,
            max_total_bytes_per_scope=10,
            created_at=_NOW,
        )


def test_workspace_administration_snapshot_rejects_impossible_truncation() -> None:
    with pytest.raises(ValueError, match="truncated"):
        AgentWorkspaceAdministrationSnapshot(
            scope=_scope(),
            scanned_records=1,
            active_artifacts=1,
            active_bytes=1,
            expired_artifacts=0,
            tombstones=0,
            truncated=True,
            record_limit=2,
            max_artifact_bytes=1_024,
            max_artifacts_per_scope=2,
            max_total_bytes_per_scope=2_048,
            created_at=_NOW,
        )


@pytest.mark.asyncio
async def test_workspace_administration_timeout_includes_authorization() -> None:
    scan = WorkspaceAdministrationScan(
        scope=_scope(),
        scanned_records=0,
        active_artifacts=0,
        active_bytes=0,
        expired_artifacts=0,
        tombstones=0,
        truncated=False,
        created_at=_NOW,
    )

    class _SlowAuthorizer(_Authorizer):
        def __init__(self) -> None:
            super().__init__()
            self.cancelled = asyncio.Event()
            self.release = asyncio.Event()

        async def authorize_admin(
            self,
            scope: WorkspaceScope,
            context: SecurityContext,
            *,
            created_at: datetime | None = None,
        ) -> None:
            del scope, context, created_at
            self.admin_calls += 1
            try:
                await asyncio.Future()
            except asyncio.CancelledError:
                self.cancelled.set()
                await self.release.wait()
                return
            raise AssertionError("unreachable")

    store = _ScanStore(scan)
    authorizer = _SlowAuthorizer()
    administration = AgentWorkspaceAdministration(
        runtime=_RuntimeGate(limits=WorkspaceLimits()),
        store=store,
        authorizer=authorizer,
        operation_timeout=timedelta(milliseconds=1),
    )

    with pytest.raises(AgentTimeoutError):
        await asyncio.wait_for(
            administration.snapshot(_scope(), _context()),
            timeout=0.2,
        )

    await asyncio.wait_for(authorizer.cancelled.wait(), timeout=0.2)
    assert authorizer.admin_calls == 1
    assert store.calls == 0

    authorizer.release.set()
    await asyncio.sleep(0)


@pytest.mark.asyncio
async def test_workspace_administration_timeout_is_finite_with_suppressed_cancellation() -> None:
    scan = WorkspaceAdministrationScan(
        scope=_scope(),
        scanned_records=0,
        active_artifacts=0,
        active_bytes=0,
        expired_artifacts=0,
        tombstones=0,
        truncated=False,
        created_at=_NOW,
    )

    class _SlowStore(_ScanStore):
        def __init__(self, value: WorkspaceAdministrationScan) -> None:
            super().__init__(value)
            self.cancelled = asyncio.Event()
            self.release = asyncio.Event()

        async def administration_scan(
            self,
            *,
            scope: WorkspaceScope,
            max_records: int,
        ) -> WorkspaceAdministrationScan:
            del scope, max_records
            self.calls += 1
            try:
                await asyncio.Future()
            except asyncio.CancelledError:
                self.cancelled.set()
                await self.release.wait()
                return self.scan
            raise AssertionError("unreachable")

    store = _SlowStore(scan)
    authorizer = _Authorizer()
    administration = AgentWorkspaceAdministration(
        runtime=_RuntimeGate(limits=WorkspaceLimits()),
        store=store,
        authorizer=authorizer,
        operation_timeout=timedelta(milliseconds=1),
    )

    with pytest.raises(AgentTimeoutError):
        await asyncio.wait_for(
            administration.snapshot(_scope(), _context()),
            timeout=0.2,
        )

    await asyncio.wait_for(store.cancelled.wait(), timeout=0.2)
    assert authorizer.admin_calls == 1
    assert store.calls == 1

    store.release.set()
    await asyncio.sleep(0)
