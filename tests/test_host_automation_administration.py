from datetime import timedelta

import pytest

from phoenix_os.host_automation import (
    HOST_HEALTH_READ_PERMISSION,
    DeterministicHostAutomationAdapter,
    HostApplicationId,
    HostAutomationAdministration,
    HostAutomationAdministrationAccessDeniedError,
    HostAutomationLimits,
    HostAutomationService,
    HostEpoch,
    HostId,
    InMemoryHostAutomationApprovalGate,
    PolicyEngineHostAutomationAuthorizer,
    host_health_resource,
)
from phoenix_os.policy import PolicyEngine, PrincipalType, SecurityContext

_HOST_ID = HostId("desktop")
_EPOCH = HostEpoch()
_APP_ID = HostApplicationId("notes")
_LIMITS = HostAutomationLimits(
    max_process_results=8,
    max_window_results=12,
    max_process_label_chars=64,
    max_window_title_chars=128,
    max_clipboard_text_chars=256,
    max_clipboard_text_bytes=512,
    operation_timeout=timedelta(seconds=7),
)


def _service(*, close_approval_required: bool = False) -> HostAutomationService:
    gate = InMemoryHostAutomationApprovalGate() if close_approval_required else None
    return HostAutomationService(
        adapter=DeterministicHostAutomationAdapter(
            host_id=_HOST_ID,
            host_epoch=_EPOCH,
            limits=_LIMITS,
            applications=(_APP_ID,),
        ),
        authorizer=PolicyEngineHostAutomationAuthorizer(PolicyEngine()),
        approval_gate=gate,
        require_application_close_approval=close_approval_required,
    )


def _admin_context(
    *,
    resource: str | None = None,
    authenticated: bool = True,
    permissions: frozenset[str] = frozenset({HOST_HEALTH_READ_PERMISSION}),
) -> SecurityContext:
    return SecurityContext(
        principal="service:operator",
        principal_type=PrincipalType.SERVICE,
        authenticated=authenticated,
        permissions=permissions,
        attributes={"resource": (host_health_resource(_HOST_ID) if resource is None else resource)},
        correlation_id="corr-host-admin",
    )


@pytest.mark.asyncio
async def test_host_administration_snapshot_is_bounded_and_content_free() -> None:
    service = _service()
    administration = HostAutomationAdministration(service)

    snapshot = await administration.snapshot(_admin_context())

    assert snapshot.schema_version == 1
    assert snapshot.runtime.host_id == _HOST_ID
    assert snapshot.runtime.host_epoch == _EPOCH
    assert snapshot.runtime.limits == _LIMITS
    assert snapshot.runtime.closed is False
    assert snapshot.runtime.available is True
    assert snapshot.runtime.close_approval_required is False

    assert not hasattr(snapshot.runtime, "applications")
    assert not hasattr(snapshot.runtime, "processes")
    assert not hasattr(snapshot.runtime, "windows")
    assert not hasattr(snapshot.runtime, "clipboard_text")
    assert not hasattr(snapshot.runtime, "native_error")
    assert str(_APP_ID) not in repr(snapshot)


@pytest.mark.asyncio
async def test_host_administration_requires_exact_health_permission_and_resource() -> None:
    administration = HostAutomationAdministration(_service())

    with pytest.raises(HostAutomationAdministrationAccessDeniedError):
        await administration.snapshot(_admin_context(permissions=frozenset()))

    with pytest.raises(HostAutomationAdministrationAccessDeniedError):
        await administration.snapshot(_admin_context(resource="host-automation:host:other/health"))

    with pytest.raises(HostAutomationAdministrationAccessDeniedError):
        await administration.snapshot(_admin_context(authenticated=False))


@pytest.mark.asyncio
async def test_host_administration_wildcard_permission_still_requires_service_resource_scope() -> (
    None
):
    administration = HostAutomationAdministration(_service())

    snapshot = await administration.snapshot(_admin_context(permissions=frozenset({"*"})))
    assert snapshot.runtime.host_id == _HOST_ID

    with pytest.raises(HostAutomationAdministrationAccessDeniedError):
        await administration.snapshot(
            _admin_context(
                resource="host-automation:host:other/health",
                permissions=frozenset({"*"}),
            )
        )


@pytest.mark.asyncio
async def test_host_health_snapshot_reports_closed_service_without_desktop_probe() -> None:
    service = _service()
    administration = HostAutomationAdministration(service)

    before = await administration.snapshot(_admin_context())
    await service.close()
    after = await administration.snapshot(_admin_context())

    assert before.runtime.available is True
    assert before.runtime.closed is False
    assert after.runtime.available is False
    assert after.runtime.closed is True
    assert after.runtime.host_id == before.runtime.host_id
    assert after.runtime.host_epoch == before.runtime.host_epoch
    assert after.runtime.limits == before.runtime.limits


@pytest.mark.asyncio
async def test_host_service_snapshot_reports_close_approval_configuration_without_effect() -> None:
    default_service = _service()
    approval_service = _service(close_approval_required=True)

    default_snapshot = await default_service.snapshot()
    approval_snapshot = await approval_service.snapshot()

    assert default_snapshot.close_approval_required is False
    assert default_snapshot.available is True
    assert approval_snapshot.close_approval_required is True
    assert approval_snapshot.available is True

    await approval_service.close()
