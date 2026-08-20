from __future__ import annotations

import asyncio
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from phoenix_os.agent import (
    MAX_WORKSPACE_ARTIFACT_BYTES,
    WORKSPACE_LIST_ACTION,
    AgentAuthorizationRejectedError,
    AgentCodecError,
    AgentId,
    AgentLimitExceededError,
    AgentServiceUnavailableError,
    AgentStateConflictError,
    AgentWorkspaceService,
    ArtifactDeleteRequest,
    ArtifactExportRequest,
    ArtifactId,
    ArtifactImportRequest,
    ArtifactListRequest,
    ArtifactListResult,
    ArtifactLogicalPath,
    ArtifactOriginKind,
    ArtifactProvenance,
    ArtifactReadRequest,
    ArtifactReadResult,
    ArtifactRecord,
    ArtifactTransferDirection,
    ArtifactVersion,
    ArtifactWriteRequest,
    InMemoryWorkspaceStore,
    PolicyEngineWorkspaceAuthorizer,
    WorkspaceExportPayload,
    WorkspaceExportResult,
    WorkspaceImportResult,
    WorkspaceLimits,
    WorkspaceNamespace,
    WorkspaceScope,
    WorkspaceTransferAdapterId,
    WorkspaceTransferReference,
    agent_workspace_scope,
    artifact_content_digest,
    principal_workspace_scope,
    workspace_scope_resource,
)
from phoenix_os.policy import (
    PolicyEffect,
    PolicyEngine,
    PolicyRule,
    PrincipalType,
    SecurityContext,
)

_NOW = datetime(2026, 8, 12, 16, tzinfo=UTC)
_ARTIFACT_ID = ArtifactId(UUID("a0000000-0000-0000-0000-000000000031"))


class FakeClock:
    def __init__(self) -> None:
        self.now = _NOW

    def __call__(self) -> datetime:
        return self.now

    def advance(self, delta: timedelta) -> None:
        self.now += delta


def _context() -> SecurityContext:
    return SecurityContext(
        principal="service:workspace-owner",
        principal_type=PrincipalType.SERVICE,
        authenticated=True,
    )


def _scope(agent_id: str = "researcher") -> WorkspaceScope:
    return agent_workspace_scope(
        namespace=WorkspaceNamespace("default"),
        agent_id=AgentId(agent_id),
    )


def _import_request(
    *,
    scope: WorkspaceScope | None = None,
    artifact_id: ArtifactId = _ARTIFACT_ID,
) -> ArtifactImportRequest:
    return ArtifactImportRequest(
        scope=_scope() if scope is None else scope,
        artifact_id=artifact_id,
        source_reference=WorkspaceTransferReference("source-object"),
        created_at=_NOW,
    )


def _export_request(
    version: ArtifactVersion,
    *,
    scope: WorkspaceScope | None = None,
    artifact_id: ArtifactId = _ARTIFACT_ID,
) -> ArtifactExportRequest:
    return ArtifactExportRequest(
        scope=_scope() if scope is None else scope,
        artifact_id=artifact_id,
        expected_version=version,
        destination_reference=WorkspaceTransferReference("reviewed-destination"),
        created_at=_NOW,
    )


def _direct_write(
    content: bytes = b"authoritative export bytes",
    *,
    scope: WorkspaceScope | None = None,
    artifact_id: ArtifactId = _ARTIFACT_ID,
    expected_version: ArtifactVersion | None = None,
    created_at: datetime = _NOW,
    metadata: Mapping[str, str] | None = None,
) -> ArtifactWriteRequest:
    digest = artifact_content_digest(content)
    return ArtifactWriteRequest(
        scope=_scope() if scope is None else scope,
        artifact_id=artifact_id,
        logical_path=ArtifactLogicalPath("reports/export.txt"),
        content=content,
        provenance=ArtifactProvenance(
            origin=ArtifactOriginKind.OPERATOR,
            content_digest=digest,
            created_at=created_at,
        ),
        metadata={} if metadata is None else metadata,
        expected_version=expected_version,
        created_at=created_at,
    )


class _Authorizer:
    def __init__(
        self,
        *,
        allowed: set[str] | None = None,
        revoke_import_after_first: bool = False,
        revoke_export_after_first: bool = False,
    ) -> None:
        self.allowed = set() if allowed is None else allowed
        self.calls: list[str] = []
        self.read_requests: list[ArtifactReadRequest] = []
        self.revoke_import_after_first = revoke_import_after_first
        self.revoke_export_after_first = revoke_export_after_first

    async def _authorize(self, action: str) -> None:
        self.calls.append(action)
        count = self.calls.count(action)
        revoked = (action == "import" and self.revoke_import_after_first and count > 1) or (
            action == "export" and self.revoke_export_after_first and count > 1
        )
        if action not in self.allowed or revoked:
            raise AgentAuthorizationRejectedError()

    async def authorize_list(
        self,
        request: ArtifactListRequest,
        context: SecurityContext,
    ) -> None:
        await self._authorize("list")

    async def authorize_read(
        self,
        request: ArtifactReadRequest,
        context: SecurityContext,
    ) -> None:
        self.read_requests.append(request)
        await self._authorize("read")

    async def authorize_write(
        self,
        request: ArtifactWriteRequest,
        context: SecurityContext,
    ) -> None:
        await self._authorize("write")

    async def authorize_delete(
        self,
        request: ArtifactDeleteRequest,
        context: SecurityContext,
    ) -> None:
        await self._authorize("delete")

    async def authorize_import(
        self,
        scope: WorkspaceScope,
        artifact_id: ArtifactId,
        context: SecurityContext,
        *,
        created_at: datetime | None = None,
    ) -> None:
        await self._authorize("import")

    async def authorize_export(
        self,
        scope: WorkspaceScope,
        artifact_id: ArtifactId,
        context: SecurityContext,
        *,
        created_at: datetime | None = None,
    ) -> None:
        await self._authorize("export")

    async def authorize_admin(
        self,
        scope: WorkspaceScope,
        context: SecurityContext,
        *,
        created_at: datetime | None = None,
    ) -> None:
        await self._authorize("admin")


class _BlockingReadReauthorization(_Authorizer):
    def __init__(self) -> None:
        super().__init__(allowed={"read"})
        self.reauthorization_started = asyncio.Event()
        self.release_reauthorization = asyncio.Event()

    async def authorize_read(
        self,
        request: ArtifactReadRequest,
        context: SecurityContext,
    ) -> None:
        self.read_requests.append(request)
        if self.calls.count("read") == 1:
            self.reauthorization_started.set()
            await self.release_reauthorization.wait()
        await self._authorize("read")


class _BlockingExportReauthorization(_Authorizer):
    def __init__(self) -> None:
        super().__init__(allowed={"export"})
        self.reauthorization_started = asyncio.Event()
        self.release_reauthorization = asyncio.Event()

    async def authorize_export(
        self,
        scope: WorkspaceScope,
        artifact_id: ArtifactId,
        context: SecurityContext,
        *,
        created_at: datetime | None = None,
    ) -> None:
        if self.calls.count("export") == 1:
            self.reauthorization_started.set()
            await self.release_reauthorization.wait()
        await self._authorize("export")


class _Adapter:
    def __init__(self, imported: WorkspaceImportResult | object | None = None) -> None:
        self.adapter_id = WorkspaceTransferAdapterId("server-owned-transfer")
        self.closed = False
        self.imported = (
            WorkspaceImportResult(
                content=b"imported bytes",
                logical_path="reports/import.txt",
                media_type="text/plain",
                metadata={"kind": "import"},
                source_version="source-v3",
                transfer_reference=WorkspaceTransferReference("import-receipt"),
            )
            if imported is None
            else imported
        )
        self.import_calls: list[WorkspaceTransferReference] = []
        self.import_max_bytes: list[int] = []
        self.export_calls: list[WorkspaceExportPayload] = []
        self.import_failure: BaseException | None = None
        self.export_failure: BaseException | None = None
        self.exported: WorkspaceExportResult | object = WorkspaceExportResult(
            transfer_reference=WorkspaceTransferReference("export-receipt")
        )
        self.import_started = asyncio.Event()
        self.import_release: asyncio.Event | None = None

    async def import_artifact(
        self,
        source_reference: WorkspaceTransferReference,
        *,
        max_bytes: int,
    ) -> WorkspaceImportResult:
        self.import_calls.append(source_reference)
        self.import_max_bytes.append(max_bytes)
        self.import_started.set()
        if self.import_release is not None:
            await self.import_release.wait()
        if self.import_failure is not None:
            raise self.import_failure
        return self.imported  # type: ignore[return-value]

    async def export_artifact(
        self,
        payload: WorkspaceExportPayload,
    ) -> WorkspaceExportResult:
        self.export_calls.append(payload)
        if self.export_failure is not None:
            raise self.export_failure
        return self.exported  # type: ignore[return-value]


class _ClosedPropertyFailureAdapter:
    @property
    def adapter_id(self) -> WorkspaceTransferAdapterId:
        return WorkspaceTransferAdapterId("server-owned-transfer")

    @property
    def closed(self) -> bool:
        raise RuntimeError("secret token C:/native/path https://provider.invalid/body")

    async def import_artifact(
        self,
        source_reference: WorkspaceTransferReference,
        *,
        max_bytes: int,
    ) -> WorkspaceImportResult:
        raise AssertionError("unreachable")

    async def export_artifact(
        self,
        payload: WorkspaceExportPayload,
    ) -> WorkspaceExportResult:
        raise AssertionError("unreachable")


class _AdapterIdPropertyFailureAdapter:
    @property
    def adapter_id(self) -> WorkspaceTransferAdapterId:
        raise RuntimeError("secret token C:/native/path https://provider.invalid/body")

    @property
    def closed(self) -> bool:
        return False

    async def import_artifact(
        self,
        source_reference: WorkspaceTransferReference,
        *,
        max_bytes: int,
    ) -> WorkspaceImportResult:
        raise AssertionError("unreachable")

    async def export_artifact(
        self,
        payload: WorkspaceExportPayload,
    ) -> WorkspaceExportResult:
        raise AssertionError("unreachable")


class _MaliciousImportResult(WorkspaceImportResult):
    @property
    def content(self) -> bytes:
        raise RuntimeError("secret token C:/native/path https://provider.invalid/body")


class _MaliciousCodecImportResult(WorkspaceImportResult):
    @property
    def content(self) -> bytes:
        raise AgentCodecError("secret-token C:/private/path https://provider.invalid/body")


class _MaliciousExportResult(WorkspaceExportResult):
    @property
    def transfer_reference(
        self,
    ) -> WorkspaceTransferReference | None:
        raise RuntimeError("secret token C:/native/path https://provider.invalid/body")


class _CountingStore(InMemoryWorkspaceStore):
    def __init__(self, *, clock: FakeClock, limits: WorkspaceLimits | None = None) -> None:
        super().__init__(clock=clock, limits=limits)
        self.read_calls = 0
        self.write_calls = 0
        self.list_calls = 0
        self.delete_calls = 0

    async def read(
        self,
        request: ArtifactReadRequest,
    ) -> ArtifactReadResult | None:
        self.read_calls += 1
        return await super().read(request)

    async def write(self, request: ArtifactWriteRequest) -> ArtifactRecord:
        self.write_calls += 1
        return await super().write(request)

    async def list(self, request: ArtifactListRequest) -> ArtifactListResult:
        self.list_calls += 1
        return await super().list(request)

    async def delete(self, request: ArtifactDeleteRequest) -> None:
        self.delete_calls += 1
        await super().delete(request)


def _service(
    *,
    allowed: set[str],
    clock: FakeClock | None = None,
    adapter: _Adapter | None = None,
    authorizer: _Authorizer | None = None,
    limits: WorkspaceLimits | None = None,
) -> tuple[AgentWorkspaceService, _CountingStore, _Adapter, _Authorizer]:
    trusted_clock = FakeClock() if clock is None else clock
    store = _CountingStore(clock=trusted_clock, limits=limits)
    transfer = _Adapter() if adapter is None else adapter
    workspace_authorizer = _Authorizer(allowed=allowed) if authorizer is None else authorizer
    service = AgentWorkspaceService(
        store=store,
        authorizer=workspace_authorizer,
        transfer_adapter=transfer,
        clock=trusted_clock,
    )
    return service, store, transfer, workspace_authorizer


@pytest.mark.asyncio
async def test_authorized_import_creates_exact_artifact_with_phoenix_digest() -> None:
    service, store, adapter, authorizer = _service(allowed={"import"})

    receipt = await service.import_artifact(_import_request(), _context())

    loaded = await store.read(
        ArtifactReadRequest(scope=_scope(), artifact_id=_ARTIFACT_ID, created_at=_NOW)
    )
    assert loaded is not None
    assert loaded.content == b"imported bytes"
    assert loaded.record.provenance is not None
    assert loaded.record.provenance.origin is ArtifactOriginKind.IMPORT
    assert loaded.record.content_digest == artifact_content_digest(b"imported bytes")
    assert loaded.record.scope == _scope()
    assert loaded.record.artifact_id == _ARTIFACT_ID
    assert authorizer.calls == ["import", "import"]
    assert len(adapter.import_calls) == 1
    assert adapter.import_max_bytes == [store.limits.max_artifact_bytes]
    assert receipt.direction is ArtifactTransferDirection.IMPORT
    assert receipt.content_digest == loaded.record.content_digest
    assert not hasattr(receipt, "content")


@pytest.mark.asyncio
async def test_import_rejects_forged_digest_oversize_and_malformed_adapter_data() -> None:
    cases = (
        (
            WorkspaceImportResult(
                content=b"real",
                logical_path="reports/real.txt",
                external_digest=str(artifact_content_digest(b"forged")),
            ),
            AgentCodecError,
        ),
        (
            WorkspaceImportResult(
                content=b"12345",
                logical_path="reports/large.txt",
            ),
            AgentLimitExceededError,
        ),
    )
    for imported, expected_error in cases:
        adapter = _Adapter(imported)
        service, store, _, _ = _service(
            allowed={"import"},
            adapter=adapter,
            limits=WorkspaceLimits(max_artifact_bytes=4, max_total_bytes_per_scope=4),
        )
        with pytest.raises(expected_error) as failure:
            await service.import_artifact(_import_request(), _context())
        if expected_error is AgentCodecError:
            assert str(failure.value) == "workspace import digest is invalid"
        assert store.write_calls == 0

    for field, value in (
        ("logical_path", "../escape.txt"),
        ("media_type", "text/plain; charset=utf-8"),
        ("metadata", {"x" * 129: "bad"}),
    ):
        malformed = object.__new__(WorkspaceImportResult)
        object.__setattr__(malformed, "content", b"bytes")
        object.__setattr__(malformed, "logical_path", "reports/good.txt")
        object.__setattr__(malformed, "media_type", "text/plain")
        object.__setattr__(malformed, "metadata", {})
        object.__setattr__(malformed, "external_digest", None)
        object.__setattr__(malformed, "source_version", None)
        object.__setattr__(malformed, "transfer_reference", None)
        object.__setattr__(malformed, field, value)
        service, store, _, _ = _service(allowed={"import"}, adapter=_Adapter(malformed))
        with pytest.raises(AgentCodecError, match="import result"):
            await service.import_artifact(_import_request(), _context())
        assert store.write_calls == 0


@pytest.mark.asyncio
async def test_import_adapter_receives_exact_configured_byte_bound() -> None:
    configured_max = 7
    adapter = _Adapter(
        WorkspaceImportResult(
            content=b"12345678",
            logical_path="reports/too-large.txt",
        )
    )
    service, store, _, _ = _service(
        allowed={"import"},
        adapter=adapter,
        limits=WorkspaceLimits(
            max_artifact_bytes=configured_max,
            max_total_bytes_per_scope=configured_max,
        ),
    )

    with pytest.raises(AgentLimitExceededError):
        await service.import_artifact(_import_request(), _context())

    assert adapter.import_max_bytes == [configured_max]
    assert store.write_calls == 0
    with pytest.raises(ValueError, match="global maximum"):
        WorkspaceLimits(
            max_artifact_bytes=MAX_WORKSPACE_ARTIFACT_BYTES + 1,
            max_total_bytes_per_scope=MAX_WORKSPACE_ARTIFACT_BYTES + 1,
        )


@pytest.mark.asyncio
async def test_provider_exception_is_sanitized_and_fatal_base_exception_propagates() -> None:
    adapter = _Adapter()
    adapter.import_failure = RuntimeError(
        "secret bytes C:/native/provider/path https://private.invalid/body"
    )
    service, store, _, _ = _service(allowed={"import"}, adapter=adapter)

    with pytest.raises(AgentServiceUnavailableError) as captured:
        await service.import_artifact(_import_request(), _context())
    assert "secret" not in str(captured.value)
    assert "C:/native" not in str(captured.value)
    assert "https://" not in str(captured.value)
    assert store.write_calls == 0

    for fatal_error in (
        KeyboardInterrupt("must propagate keyboard interrupt"),
        SystemExit("must propagate system exit"),
    ):
        fatal = _Adapter()
        fatal.import_failure = fatal_error
        service, store, _, _ = _service(allowed={"import"}, adapter=fatal)
        with pytest.raises(type(fatal_error), match="must propagate"):
            await service.import_artifact(_import_request(), _context())
        assert store.write_calls == 0


@pytest.mark.asyncio
async def test_adapter_properties_and_malicious_results_are_sanitized() -> None:
    sensitive = ("secret", "C:/native", "https://", "provider")
    for property_adapter in (
        _ClosedPropertyFailureAdapter(),
        _AdapterIdPropertyFailureAdapter(),
    ):
        clock = FakeClock()
        store = _CountingStore(clock=clock)
        service = AgentWorkspaceService(
            store=store,
            authorizer=_Authorizer(allowed={"import"}),
            transfer_adapter=property_adapter,
            clock=clock,
        )
        with pytest.raises(AgentServiceUnavailableError) as property_failure:
            await service.import_artifact(_import_request(), _context())
        assert all(item not in str(property_failure.value) for item in sensitive)
        assert store.write_calls == 0

    for malicious_type in (
        _MaliciousImportResult,
        _MaliciousCodecImportResult,
    ):
        malicious_import = object.__new__(malicious_type)
        import_adapter = _Adapter(malicious_import)
        service, store, _, _ = _service(allowed={"import"}, adapter=import_adapter)
        with pytest.raises(AgentCodecError) as import_failure:
            await service.import_artifact(_import_request(), _context())
        assert str(import_failure.value) == "workspace import result is invalid"
        assert all(item not in str(import_failure.value) for item in sensitive)
        assert store.write_calls == 0

    malicious_export = object.__new__(_MaliciousExportResult)
    export_adapter = _Adapter()
    export_adapter.exported = malicious_export
    service, store, _, _ = _service(allowed={"export"}, adapter=export_adapter)
    created = await store.write(_direct_write())
    with pytest.raises(AgentCodecError) as export_failure:
        await service.export_artifact(_export_request(created.version), _context())
    assert all(item not in str(export_failure.value) for item in sensitive)


@pytest.mark.asyncio
async def test_import_denial_and_policy_revocation_prevent_authoritative_write() -> None:
    service, store, adapter, _ = _service(allowed={"write"})
    with pytest.raises(AgentAuthorizationRejectedError):
        await service.import_artifact(_import_request(), _context())
    assert adapter.import_calls == []
    assert store.write_calls == 0

    authorizer = _Authorizer(allowed={"import"}, revoke_import_after_first=True)
    service, store, adapter, _ = _service(allowed={"import"}, authorizer=authorizer)
    with pytest.raises(AgentAuthorizationRejectedError):
        await service.import_artifact(_import_request(), _context())
    assert len(adapter.import_calls) == 1
    assert store.write_calls == 0


@pytest.mark.asyncio
async def test_import_authority_is_independent_from_write_and_export() -> None:
    service, store, _, authorizer = _service(allowed={"import"})
    await service.import_artifact(_import_request(), _context())
    assert "write" not in authorizer.calls

    direct = _direct_write(artifact_id=ArtifactId(UUID(int=2)))
    with pytest.raises(AgentAuthorizationRejectedError):
        await service.write(direct, _context())

    with pytest.raises(AgentAuthorizationRejectedError):
        await service.export_artifact(
            _export_request(ArtifactVersion(), artifact_id=_ARTIFACT_ID),
            _context(),
        )
    assert store.read_calls == 0


@pytest.mark.asyncio
async def test_authorized_export_sends_exact_expected_version_and_server_destination() -> None:
    service, store, adapter, authorizer = _service(allowed={"export"})
    created = await store.write(_direct_write())
    store.read_calls = 0

    receipt = await service.export_artifact(
        _export_request(created.version),
        _context(),
    )

    assert authorizer.calls == ["export", "export"]
    assert len(adapter.export_calls) == 1
    payload = adapter.export_calls[0]
    assert payload.scope == created.scope
    assert payload.artifact_id == created.artifact_id
    assert payload.version == created.version
    assert payload.content == b"authoritative export bytes"
    assert payload.destination_reference == WorkspaceTransferReference("reviewed-destination")
    assert receipt.direction is ArtifactTransferDirection.EXPORT
    assert receipt.version == created.version
    assert receipt.transfer_reference == WorkspaceTransferReference("export-receipt")
    assert not hasattr(receipt, "content")


@pytest.mark.asyncio
async def test_export_update_during_reauthorization_is_not_disclosed() -> None:
    clock = FakeClock()
    authorizer = _BlockingExportReauthorization()
    service, store, adapter, _ = _service(
        allowed={"export"},
        clock=clock,
        authorizer=authorizer,
    )
    created = await store.write(_direct_write())
    task = asyncio.create_task(
        service.export_artifact(_export_request(created.version), _context())
    )
    await authorizer.reauthorization_started.wait()

    clock.advance(timedelta(seconds=1))
    updated = await store.write(
        _direct_write(
            b"updated while reauthorizing",
            expected_version=created.version,
            created_at=clock(),
        )
    )
    authorizer.release_reauthorization.set()

    with pytest.raises(AgentStateConflictError):
        await task
    assert updated.version == created.version.next()
    assert adapter.export_calls == []


@pytest.mark.asyncio
async def test_export_delete_during_reauthorization_is_not_disclosed() -> None:
    clock = FakeClock()
    authorizer = _BlockingExportReauthorization()
    service, store, adapter, _ = _service(
        allowed={"export"},
        clock=clock,
        authorizer=authorizer,
    )
    created = await store.write(_direct_write())
    task = asyncio.create_task(
        service.export_artifact(_export_request(created.version), _context())
    )
    await authorizer.reauthorization_started.wait()

    clock.advance(timedelta(seconds=1))
    await store.delete(
        ArtifactDeleteRequest(
            scope=created.scope,
            artifact_id=created.artifact_id,
            expected_version=created.version,
            created_at=clock(),
        )
    )
    authorizer.release_reauthorization.set()

    with pytest.raises(AgentStateConflictError):
        await task
    assert adapter.export_calls == []


@pytest.mark.asyncio
async def test_export_expiry_during_reauthorization_is_not_disclosed() -> None:
    clock = FakeClock()
    authorizer = _BlockingExportReauthorization()
    service, store, adapter, _ = _service(
        allowed={"export"},
        clock=clock,
        authorizer=authorizer,
    )
    created = await store.write(_direct_write())
    task = asyncio.create_task(
        service.export_artifact(_export_request(created.version), _context())
    )
    await authorizer.reauthorization_started.wait()

    clock.advance(store.limits.retention.artifact_ttl + timedelta(seconds=1))
    authorizer.release_reauthorization.set()

    with pytest.raises(AgentStateConflictError):
        await task
    assert adapter.export_calls == []


@pytest.mark.asyncio
async def test_stale_deleted_expired_and_cross_scope_artifacts_are_not_exported() -> None:
    service, store, adapter, _ = _service(allowed={"export"})
    created = await store.write(_direct_write())

    with pytest.raises(AgentStateConflictError):
        await service.export_artifact(
            _export_request(ArtifactVersion(created.version.value + 1)),
            _context(),
        )
    assert adapter.export_calls == []

    await store.delete(
        ArtifactDeleteRequest(
            scope=created.scope,
            artifact_id=created.artifact_id,
            expected_version=created.version,
            created_at=_NOW,
        )
    )
    with pytest.raises(AgentStateConflictError):
        await service.export_artifact(_export_request(created.version), _context())
    assert adapter.export_calls == []

    other_scope = _scope("other-agent")
    with pytest.raises(AgentStateConflictError):
        await service.export_artifact(
            _export_request(created.version, scope=other_scope),
            _context(),
        )
    assert adapter.export_calls == []

    clock = FakeClock()
    limits = WorkspaceLimits(
        retention=store.limits.retention,
    )
    expiring_service, expiring_store, expiring_adapter, _ = _service(
        allowed={"export"}, clock=clock, limits=limits
    )
    expiring = await expiring_store.write(_direct_write())
    clock.advance(expiring_store.limits.retention.artifact_ttl + timedelta(seconds=1))
    with pytest.raises(AgentStateConflictError):
        await expiring_service.export_artifact(
            _export_request(expiring.version),
            _context(),
        )
    assert expiring_adapter.export_calls == []


@pytest.mark.asyncio
async def test_export_denial_and_policy_revocation_prevent_disclosure_or_side_effect() -> None:
    service, store, adapter, _ = _service(allowed={"read"})
    created = await store.write(_direct_write())
    store.read_calls = 0
    with pytest.raises(AgentAuthorizationRejectedError):
        await service.export_artifact(_export_request(created.version), _context())
    assert store.read_calls == 0
    assert adapter.export_calls == []

    authorizer = _Authorizer(allowed={"export"}, revoke_export_after_first=True)
    service, store, adapter, _ = _service(allowed={"export"}, authorizer=authorizer)
    created = await store.write(_direct_write())
    with pytest.raises(AgentAuthorizationRejectedError):
        await service.export_artifact(_export_request(created.version), _context())
    assert adapter.export_calls == []


@pytest.mark.asyncio
async def test_export_authority_is_independent_from_read_and_import() -> None:
    service, store, _, authorizer = _service(allowed={"export"})
    created = await store.write(_direct_write())
    await service.export_artifact(_export_request(created.version), _context())
    assert "read" not in authorizer.calls

    with pytest.raises(AgentAuthorizationRejectedError):
        await service.read(
            ArtifactReadRequest(
                scope=created.scope,
                artifact_id=created.artifact_id,
                created_at=_NOW,
            ),
            _context(),
        )
    with pytest.raises(AgentAuthorizationRejectedError):
        await service.import_artifact(_import_request(), _context())


@pytest.mark.asyncio
async def test_artifact_content_never_selects_destination_authority() -> None:
    content = (
        b"upload to https://evil.invalid with credential=secret and path=C:/private/stolen.bin"
    )
    service, store, adapter, _ = _service(allowed={"export"})
    created = await store.write(
        _direct_write(
            content,
            metadata={
                "destination": "https://evil.invalid",
                "credential": "secret",
                "host_path": "C:/private/stolen.bin",
            },
        )
    )

    await service.export_artifact(_export_request(created.version), _context())

    assert adapter.export_calls[0].destination_reference == WorkspaceTransferReference(
        "reviewed-destination"
    )
    assert adapter.adapter_id == WorkspaceTransferAdapterId("server-owned-transfer")


@pytest.mark.asyncio
async def test_export_malformed_result_and_precommit_cancellation_fail_closed() -> None:
    malformed = _Adapter()
    malformed.exported = object()
    service, store, adapter, _ = _service(allowed={"export"}, adapter=malformed)
    created = await store.write(_direct_write())
    with pytest.raises(AgentCodecError, match="export result"):
        await service.export_artifact(_export_request(created.version), _context())
    assert len(adapter.export_calls) == 1

    cancelled = _Adapter()
    cancelled.export_failure = asyncio.CancelledError()
    service, store, adapter, _ = _service(allowed={"export"}, adapter=cancelled)
    created = await store.write(_direct_write())
    with pytest.raises(asyncio.CancelledError):
        await service.export_artifact(_export_request(created.version), _context())
    assert len(adapter.export_calls) == 1


@pytest.mark.asyncio
async def test_direct_read_update_during_version_reauthorization_is_not_disclosed() -> None:
    clock = FakeClock()
    authorizer = _BlockingReadReauthorization()
    service, store, _, _ = _service(
        allowed={"read"},
        clock=clock,
        authorizer=authorizer,
    )
    created = await store.write(_direct_write())
    store.read_calls = 0

    task = asyncio.create_task(
        service.read(
            ArtifactReadRequest(
                scope=created.scope,
                artifact_id=created.artifact_id,
                created_at=_NOW,
            ),
            _context(),
        )
    )
    await authorizer.reauthorization_started.wait()

    clock.advance(timedelta(seconds=1))
    updated = await store.write(
        _direct_write(
            b"updated during direct read",
            expected_version=created.version,
            created_at=clock(),
        )
    )
    authorizer.release_reauthorization.set()

    with pytest.raises(AgentStateConflictError):
        await task

    assert updated.version == created.version.next()
    assert authorizer.calls == ["read", "read"]
    assert authorizer.read_requests[0].expected_version is None
    assert authorizer.read_requests[1].expected_version == created.version
    assert store.read_calls == 2


@pytest.mark.asyncio
async def test_authorized_list_read_write_delete_delegate_only_after_policy() -> None:
    service, store, _, authorizer = _service(allowed={"list", "read", "write", "delete"})
    write = _direct_write()
    created = await service.write(write, _context())
    loaded = await service.read(
        ArtifactReadRequest(
            scope=created.scope,
            artifact_id=created.artifact_id,
            created_at=_NOW,
        ),
        _context(),
    )
    listing = await service.list(
        ArtifactListRequest(scope=created.scope, created_at=_NOW), _context()
    )
    await service.delete(
        ArtifactDeleteRequest(
            scope=created.scope,
            artifact_id=created.artifact_id,
            expected_version=created.version,
            created_at=_NOW,
        ),
        _context(),
    )

    assert loaded is not None
    assert listing.artifacts == (created,)
    assert authorizer.calls == ["write", "read", "read", "list", "delete"]
    assert authorizer.read_requests[0].expected_version is None
    assert authorizer.read_requests[1].expected_version == created.version
    assert store.write_calls == 1
    assert store.read_calls == 2
    assert store.list_calls == 1
    assert store.delete_calls == 1


@pytest.mark.asyncio
async def test_list_read_write_delete_denial_never_touches_store() -> None:
    service, store, _, _ = _service(allowed=set())
    operations = (
        service.list(ArtifactListRequest(scope=_scope(), created_at=_NOW), _context()),
        service.read(
            ArtifactReadRequest(scope=_scope(), artifact_id=_ARTIFACT_ID, created_at=_NOW),
            _context(),
        ),
        service.write(_direct_write(), _context()),
        service.delete(
            ArtifactDeleteRequest(
                scope=_scope(),
                artifact_id=_ARTIFACT_ID,
                expected_version=ArtifactVersion(),
                created_at=_NOW,
            ),
            _context(),
        ),
    )

    for operation in operations:
        with pytest.raises(AgentAuthorizationRejectedError):
            await operation

    assert store.list_calls == 0
    assert store.read_calls == 0
    assert store.write_calls == 0
    assert store.delete_calls == 0


@pytest.mark.asyncio
async def test_real_authorizer_preserves_principal_scope_binding_through_service() -> None:
    owner = _context()
    attacker = SecurityContext(
        principal="service:attacker",
        principal_type=PrincipalType.SERVICE,
        authenticated=True,
    )
    scope = principal_workspace_scope(
        namespace=WorkspaceNamespace("default"),
        context=owner,
    )
    policy = PolicyEngine(
        (
            PolicyRule(
                rule_id="allow.owner.workspace.list",
                effect=PolicyEffect.ALLOW,
                actions=frozenset({WORKSPACE_LIST_ACTION}),
                resources=frozenset({workspace_scope_resource(scope)}),
                principals=frozenset({"*"}),
                authenticated=True,
            ),
        )
    )
    clock = FakeClock()
    store = _CountingStore(clock=clock)
    service = AgentWorkspaceService(
        store=store,
        authorizer=PolicyEngineWorkspaceAuthorizer(policy),
        clock=clock,
    )
    request = ArtifactListRequest(scope=scope, created_at=_NOW)

    assert (await service.list(request, owner)).artifacts == ()
    with pytest.raises(AgentAuthorizationRejectedError):
        await service.list(request, attacker)
    assert store.list_calls == 1


@pytest.mark.asyncio
async def test_cancelled_import_before_authoritative_write_creates_nothing() -> None:
    adapter = _Adapter()
    adapter.import_release = asyncio.Event()
    service, store, _, _ = _service(allowed={"import"}, adapter=adapter)

    task = asyncio.create_task(service.import_artifact(_import_request(), _context()))
    await adapter.import_started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert store.write_calls == 0
    assert (
        await store.read(
            ArtifactReadRequest(scope=_scope(), artifact_id=_ARTIFACT_ID, created_at=_NOW)
        )
        is None
    )


@pytest.mark.asyncio
async def test_unavailable_adapter_and_closed_service_fail_closed() -> None:
    service, store, adapter, _ = _service(allowed={"import", "export"})
    adapter.closed = True
    with pytest.raises(AgentServiceUnavailableError):
        await service.import_artifact(_import_request(), _context())
    assert store.write_calls == 0

    await service.close()
    with pytest.raises(AgentServiceUnavailableError):
        await service.list(ArtifactListRequest(scope=_scope(), created_at=_NOW), _context())

    no_adapter = AgentWorkspaceService(
        store=store,
        authorizer=_Authorizer(allowed={"import"}),
        clock=FakeClock(),
    )
    with pytest.raises(AgentServiceUnavailableError):
        await no_adapter.import_artifact(_import_request(), _context())
