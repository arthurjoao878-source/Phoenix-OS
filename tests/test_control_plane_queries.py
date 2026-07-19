from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from phoenix_os.audit import AuditLedgerSnapshot
from phoenix_os.capabilities import CapabilityContext, CapabilityDescriptor, RiskLevel
from phoenix_os.control_plane import (
    AuditSummary,
    CapabilityPage,
    CapabilityView,
    ControlPlaneService,
    JobPage,
    JobView,
    PageInfo,
    PageRequest,
    PluginPage,
    PluginView,
    WorkflowPage,
    WorkflowView,
    audit_summary_to_dict,
    capability_page_to_dict,
    job_page_to_dict,
    plugin_page_to_dict,
    workflow_page_to_dict,
)
from phoenix_os.jobs import (
    JobRecord,
    JobSchedule,
    JobSchedulerSnapshot,
    JobSpec,
    JobStatus,
    RetryPolicy,
)
from phoenix_os.plugins import (
    PluginExports,
    PluginFailure,
    PluginFailurePhase,
    PluginManagerState,
    PluginManifest,
    PluginPermission,
    PluginSnapshot,
    PluginStatus,
)
from phoenix_os.runtime import RuntimeSnapshot, RuntimeState
from phoenix_os.workflows import (
    WorkflowDefinition,
    WorkflowRecord,
    WorkflowStatus,
    WorkflowStep,
    WorkflowStepRecord,
    WorkflowStepStatus,
)

_NOW = datetime(2026, 7, 18, 21, 0, tzinfo=UTC)
_RUNTIME_ID = UUID("10000000-0000-0000-0000-000000000001")


class _RuntimeSource:
    async def snapshot(self) -> RuntimeSnapshot:
        return RuntimeSnapshot(
            runtime_id=_RUNTIME_ID,
            state=RuntimeState.RUNNING,
            components=(),
            active_components=(),
            in_flight_requests=0,
            created_at=_NOW,
            started_at=_NOW,
            stopped_at=None,
        )


class _SchedulerSource:
    async def snapshot(self) -> JobSchedulerSnapshot:
        return JobSchedulerSnapshot(False, 0, 0, 0, 0, 0, 0, 0, 0)


class _JobRecords:
    def __init__(self, records: tuple[JobRecord, ...]) -> None:
        self.records = records

    async def list_all(self) -> tuple[JobRecord, ...]:
        return self.records


class _WorkflowRecords:
    def __init__(self, records: tuple[WorkflowRecord, ...]) -> None:
        self.records = records

    async def list_all(self) -> tuple[WorkflowRecord, ...]:
        return self.records


class _Capabilities:
    def __init__(self, descriptors: tuple[CapabilityDescriptor, ...]) -> None:
        self.descriptors = descriptors

    async def list_descriptors(self) -> tuple[CapabilityDescriptor, ...]:
        return self.descriptors


class _Plugins:
    def __init__(
        self,
        manifests: tuple[PluginManifest, ...],
        snapshot: PluginSnapshot,
    ) -> None:
        self.manifests = manifests
        self.current = snapshot

    async def list_manifests(self) -> tuple[PluginManifest, ...]:
        return self.manifests

    async def snapshot(self) -> PluginSnapshot:
        return self.current


class _Audit:
    def __init__(self, snapshot: AuditLedgerSnapshot) -> None:
        self.current = snapshot

    async def snapshot(self) -> AuditLedgerSnapshot:
        return self.current


def _job(index: int, *, status: JobStatus = JobStatus.SCHEDULED) -> JobRecord:
    created = _NOW + timedelta(minutes=index)
    error = "SecretProviderError: token=hidden" if status is JobStatus.DEAD_LETTER else None
    output = {"password": "hidden"} if status is JobStatus.SUCCEEDED else {}
    return JobRecord(
        id=UUID(f"20000000-0000-0000-0000-{index:012d}"),
        spec=JobSpec(
            capability=f"jobs.task.{index}",
            schedule=JobSchedule(created, timedelta(hours=1) if index % 2 else None),
            arguments={"token": "secret-value"},
            context=CapabilityContext(metadata={"secret": "context-value"}),
            retry=RetryPolicy(max_attempts=3),
            metadata={"password": "metadata-secret"},
        ),
        status=status,
        created_at=created,
        updated_at=created,
        next_run_at=created,
        attempts=3 if status is JobStatus.DEAD_LETTER else 0,
        output=output,
        error=error,
    )


def _workflow(index: int, *, failed: bool = False) -> WorkflowRecord:
    created = _NOW + timedelta(minutes=index)
    definition = WorkflowDefinition(
        name=f"workflow-{index}",
        version="2",
        metadata={"token": "definition-secret"},
        steps=(
            WorkflowStep(
                id="publish",
                capability="release.publish",
                arguments={"secret": "argument-value"},
                metadata={"password": "metadata-secret"},
            ),
        ),
    )
    if failed:
        step = WorkflowStepRecord(
            "publish",
            WorkflowStepStatus.FAILED,
            job_id=UUID(f"30000000-0000-0000-0000-{index:012d}"),
            started_at=created,
            finished_at=created,
            error="SecretFailure: password=hidden",
        )
        return WorkflowRecord(
            id=UUID(f"40000000-0000-0000-0000-{index:012d}"),
            definition=definition,
            status=WorkflowStatus.FAILED,
            created_at=created,
            updated_at=created,
            steps={"publish": step},
            revision=index,
            finished_at=created,
            error="SecretFailure: password=hidden",
        )
    step = WorkflowStepRecord("publish", WorkflowStepStatus.READY)
    return WorkflowRecord(
        id=UUID(f"40000000-0000-0000-0000-{index:012d}"),
        definition=definition,
        status=WorkflowStatus.PENDING,
        created_at=created,
        updated_at=created,
        steps={"publish": step},
        revision=index,
    )


def _service(
    *,
    jobs: tuple[JobRecord, ...] = (),
    workflows: tuple[WorkflowRecord, ...] = (),
    capabilities: tuple[CapabilityDescriptor, ...] = (),
    plugins: _Plugins | None = None,
    audit: AuditLedgerSnapshot | None = None,
) -> ControlPlaneService:
    return ControlPlaneService(
        _RuntimeSource(),
        _SchedulerSource(),
        _WorkflowRecords(workflows),
        job_records=_JobRecords(jobs),
        capabilities=_Capabilities(capabilities),
        plugins=plugins,
        audit=None if audit is None else _Audit(audit),
        clock=lambda: _NOW,
    )


@pytest.mark.parametrize(
    "kwargs",
    [
        {"offset": -1},
        {"limit": 0},
        {"limit": -1},
        {"limit": 201},
    ],
)
def test_page_request_rejects_invalid_bounds(kwargs: dict[str, int]) -> None:
    with pytest.raises(ValueError):
        PageRequest(**kwargs)


def test_page_info_computes_next_offset() -> None:
    request = PageRequest(offset=2, limit=3)

    page = PageInfo.from_slice(request, returned=3, total=10)

    assert page.next_offset == 5


def test_page_info_omits_next_offset_at_end() -> None:
    request = PageRequest(offset=8, limit=5)

    page = PageInfo.from_slice(request, returned=2, total=10)

    assert page.next_offset is None


def test_page_info_rejects_inconsistent_next_offset() -> None:
    with pytest.raises(ValueError, match="next_offset"):
        PageInfo(offset=0, limit=2, returned=2, total=4, next_offset=3)


def test_job_view_exposes_only_allowlisted_state() -> None:
    record = _job(1, status=JobStatus.DEAD_LETTER)

    payload = job_page_to_dict(
        JobPage(
            (JobView.from_record(record),),
            PageInfo.from_slice(PageRequest(), returned=1, total=1),
        )
    )
    rendered = repr(payload)

    assert payload["items"][0]["has_error"] is True  # type: ignore[index]
    assert "secret-value" not in rendered
    assert "context-value" not in rendered
    assert "metadata-secret" not in rendered
    assert "token=hidden" not in rendered


def test_workflow_view_exposes_progress_but_not_execution_payloads() -> None:
    record = _workflow(1, failed=True)

    view = WorkflowView.from_record(record)
    payload = workflow_page_to_dict(
        WorkflowPage(
            (view,),
            PageInfo.from_slice(PageRequest(), returned=1, total=1),
        )
    )
    rendered = repr(payload)

    assert view.completed_steps == 1
    assert view.has_error is True
    assert payload["items"][0]["steps"][0]["status"] == "failed"  # type: ignore[index]
    assert "argument-value" not in rendered
    assert "definition-secret" not in rendered
    assert "password=hidden" not in rendered
    assert "release.publish" not in rendered


@pytest.mark.asyncio
async def test_service_paginates_jobs_recent_first() -> None:
    service = _service(jobs=tuple(_job(index) for index in range(5)))

    page = await service.list_jobs(PageRequest(offset=1, limit=2))

    assert [item.capability for item in page.items] == ["jobs.task.3", "jobs.task.2"]
    assert page.page == PageInfo(1, 2, 2, 5, 3)


@pytest.mark.asyncio
async def test_service_returns_empty_job_page_when_record_source_is_absent() -> None:
    service = ControlPlaneService(
        _RuntimeSource(),
        _SchedulerSource(),
        _WorkflowRecords(()),
        clock=lambda: _NOW,
    )

    page = await service.list_jobs(PageRequest(offset=10, limit=5))

    assert page.items == ()
    assert page.page.total == 0
    assert page.page.next_offset is None


@pytest.mark.asyncio
async def test_service_paginates_workflows_recent_first() -> None:
    service = _service(workflows=tuple(_workflow(index) for index in range(4)))

    page = await service.list_workflows(PageRequest(limit=2))

    assert [item.name for item in page.items] == ["workflow-3", "workflow-2"]
    assert page.page.next_offset == 2


def test_capability_view_sorts_set_fields() -> None:
    descriptor = CapabilityDescriptor(
        name="system.inspect",
        description=" Inspect system ",
        version="3",
        risk=RiskLevel.SENSITIVE,
        required_permissions=frozenset({"z.read", "a.read"}),
        confirmation_required=True,
        default_timeout=5,
        tags=frozenset({"system", "admin"}),
    )

    view = CapabilityView.from_descriptor(descriptor)

    assert view.required_permissions == ("a.read", "z.read")
    assert view.tags == ("admin", "system")
    assert view.description == "Inspect system"


@pytest.mark.asyncio
async def test_service_sorts_and_paginates_capabilities() -> None:
    service = _service(
        capabilities=(
            CapabilityDescriptor("z.last"),
            CapabilityDescriptor("a.first"),
            CapabilityDescriptor("m.middle"),
        )
    )

    page = await service.list_capabilities(PageRequest(offset=1, limit=1))

    assert [item.name for item in page.items] == ["m.middle"]
    assert page.page.next_offset == 2


def _plugin_snapshot(*, failed: bool = False) -> PluginSnapshot:
    failures = (
        (PluginFailure("com.example.alpha", PluginFailurePhase.START, RuntimeError("secret")),)
        if failed
        else ()
    )
    return PluginSnapshot(
        state=PluginManagerState.RUNNING,
        registered=("com.example.alpha",),
        resolved_order=("com.example.alpha",),
        prepared=("com.example.alpha",),
        active=() if failed else ("com.example.alpha",),
        services=("secret.service",),
        failures=failures,
    )


def _plugin_manifest(plugin_id: str = "com.example.alpha") -> PluginManifest:
    return PluginManifest(
        plugin_id=plugin_id,
        name="Alpha",
        version="1.2.3",
        permissions=frozenset({PluginPermission.REGISTER_CAPABILITIES}),
        exports=PluginExports(
            capabilities=frozenset({"secret.capability"}),
            services=frozenset({"secret.service"}),
        ),
        metadata={"token": "plugin-secret"},
    )


def test_plugin_view_derives_active_status_and_export_counts() -> None:
    view = PluginView.from_manifest(_plugin_manifest(), _plugin_snapshot())

    assert view.status is PluginStatus.ACTIVE
    assert view.capability_exports == 1
    assert view.service_exports == 1
    assert view.permissions == ("capabilities.register",)


def test_plugin_view_derives_failed_status_without_exception_text() -> None:
    view = PluginView.from_manifest(_plugin_manifest(), _plugin_snapshot(failed=True))
    payload = plugin_page_to_dict(
        PluginPage(
            (view,),
            PageInfo.from_slice(PageRequest(), returned=1, total=1),
        )
    )

    assert view.status is PluginStatus.FAILED
    assert view.has_failure is True
    assert "secret" not in repr(payload)
    assert "plugin-secret" not in repr(payload)
    assert "secret.service" not in repr(payload)
    assert "secret.capability" not in repr(payload)


@pytest.mark.asyncio
async def test_service_sorts_plugin_pages_by_id() -> None:
    manifests = (_plugin_manifest("z.plugin"), _plugin_manifest("a.plugin"))
    snapshot = PluginSnapshot(
        state=PluginManagerState.CREATED,
        registered=("z.plugin", "a.plugin"),
        resolved_order=(),
        prepared=(),
        active=(),
        services=(),
        failures=(),
    )
    service = _service(plugins=_Plugins(manifests, snapshot))

    page = await service.list_plugins(PageRequest(limit=1))

    assert [item.plugin_id for item in page.items] == ["a.plugin"]
    assert page.page.next_offset == 1


def test_audit_summary_omits_digest_and_record_bodies() -> None:
    snapshot = AuditLedgerSnapshot(
        closed=False,
        records=2,
        head_sequence=2,
        head_digest="a" * 64,
        signed_records=1,
        appended=2,
        reads=3,
        verifications=1,
        verification_failures=0,
        denied_operations=4,
    )

    payload = audit_summary_to_dict(AuditSummary.from_snapshot(snapshot))

    assert payload["available"] is True
    assert payload["records"] == 2
    assert "digest" not in repr(payload)
    assert "a" * 64 not in repr(payload)


@pytest.mark.asyncio
async def test_service_returns_audit_summary() -> None:
    snapshot = AuditLedgerSnapshot(False, 1, 1, "b" * 64, 0, 1, 0, 0, 0, 0)
    service = _service(audit=snapshot)

    summary = await service.audit_summary()

    assert summary is not None
    assert summary.records == 1
    assert summary.head_sequence == 1


@pytest.mark.asyncio
async def test_service_reports_unavailable_optional_catalogs() -> None:
    service = ControlPlaneService(
        _RuntimeSource(),
        _SchedulerSource(),
        _WorkflowRecords(()),
        clock=lambda: _NOW,
    )

    assert (await service.list_capabilities()).items == ()
    assert (await service.list_plugins()).items == ()
    assert await service.audit_summary() is None
    assert audit_summary_to_dict(None) == {"available": False}


def test_capability_serializer_is_deterministic() -> None:
    view = CapabilityView.from_descriptor(
        CapabilityDescriptor(
            "system.inspect",
            required_permissions=frozenset({"b", "a"}),
            tags=frozenset({"z", "x"}),
        )
    )
    payload = capability_page_to_dict(
        CapabilityPage(
            (view,),
            PageInfo.from_slice(PageRequest(), returned=1, total=1),
        )
    )

    assert payload["items"][0]["required_permissions"] == ["a", "b"]  # type: ignore[index]
    assert payload["items"][0]["tags"] == ["x", "z"]  # type: ignore[index]
