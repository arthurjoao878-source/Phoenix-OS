from datetime import UTC, datetime, timedelta

import pytest

from phoenix_os.audit import AuditLedger, AuditQuery, InMemoryAuditStore
from phoenix_os.events import Event, EventBus
from phoenix_os.host_automation import (
    HOST_APPLICATION_CLOSE_ACTION,
    HOST_APPLICATION_LAUNCH_ACTION,
    HOST_CLIPBOARD_READ_ACTION,
    HOST_CLIPBOARD_WRITE_ACTION,
    HOST_PROCESS_LIST_ACTION,
    HOST_WINDOW_FOCUS_ACTION,
    HOST_WINDOW_LIST_ACTION,
    ContentFreeHostAutomationObserver,
    DeterministicHostAutomationAdapter,
    HostApplicationCloseRequest,
    HostApplicationCloseResult,
    HostApplicationId,
    HostApplicationLaunchRequest,
    HostApplicationLaunchResult,
    HostAutomationAdapterError,
    HostAutomationAuthorizationRejectedError,
    HostAutomationIndeterminateEffectError,
    HostAutomationLimits,
    HostAutomationObservabilityConfiguration,
    HostAutomationOperationObservation,
    HostAutomationService,
    HostClipboardReadRequest,
    HostClipboardReadResult,
    HostClipboardWriteRequest,
    HostClipboardWriteResult,
    HostEpoch,
    HostId,
    HostProcessDescriptor,
    HostProcessId,
    HostProcessListRequest,
    HostProcessListResult,
    HostWindowDescriptor,
    HostWindowFocusRequest,
    HostWindowFocusResult,
    HostWindowId,
    HostWindowListRequest,
    HostWindowListResult,
    PolicyEngineHostAutomationAuthorizer,
    host_application_resource,
    host_clipboard_resource,
    host_process_collection_resource,
    host_process_resource,
    host_window_collection_resource,
    host_window_resource,
)
from phoenix_os.observability import InMemorySink, ObservabilityHub
from phoenix_os.policy import (
    PolicyEffect,
    PolicyEngine,
    PolicyRule,
    PrincipalType,
    SecurityContext,
)

_NOW = datetime(2026, 8, 16, 20, tzinfo=UTC)
_HOST_ID = HostId("desktop")
_EPOCH = HostEpoch()
_APP_ID = HostApplicationId("secret-app-id")
_PROCESS_ID = HostProcessId()
_WINDOW_ID = HostWindowId()
_SECRET_PROCESS_LABEL = "TOP-SECRET-PROCESS-LABEL-6B1"
_SECRET_WINDOW_TITLE = "TOP-SECRET-WINDOW-TITLE-6B1"
_SECRET_CLIPBOARD_READ = "TOP-SECRET-CLIPBOARD-READ-6B1"
_SECRET_CLIPBOARD_WRITE = "TOP-SECRET-CLIPBOARD-WRITE-6B1"
_NATIVE_SECRET = "TOP-SECRET-NATIVE-ERROR-6B1"
_OBSERVER_SECRET = "TOP-SECRET-OBSERVER-ERROR-6B1"


def _context() -> SecurityContext:
    return SecurityContext(
        principal="service:assistant",
        principal_type=PrincipalType.SERVICE,
        authenticated=True,
        correlation_id="corr-host-observer",
    )


def _limits() -> HostAutomationLimits:
    return HostAutomationLimits(
        max_process_results=8,
        max_window_results=8,
        max_process_label_chars=256,
        max_window_title_chars=512,
        max_clipboard_text_chars=256,
        max_clipboard_text_bytes=512,
        operation_timeout=timedelta(seconds=30),
    )


def _native() -> DeterministicHostAutomationAdapter:
    return DeterministicHostAutomationAdapter(
        host_id=_HOST_ID,
        host_epoch=_EPOCH,
        limits=_limits(),
        applications=(_APP_ID,),
        processes=(
            HostProcessDescriptor(
                host_id=_HOST_ID,
                host_epoch=_EPOCH,
                process_id=_PROCESS_ID,
                application_id=_APP_ID,
                label=_SECRET_PROCESS_LABEL,
            ),
        ),
        windows=(
            HostWindowDescriptor(
                host_id=_HOST_ID,
                host_epoch=_EPOCH,
                window_id=_WINDOW_ID,
                process_id=_PROCESS_ID,
                application_id=_APP_ID,
                title=_SECRET_WINDOW_TITLE,
            ),
        ),
        clipboard_text=_SECRET_CLIPBOARD_READ,
    )


def _allow(action: str, resource: str) -> PolicyRule:
    return PolicyRule(
        rule_id=f"allow.{action}",
        effect=PolicyEffect.ALLOW,
        actions=frozenset({action}),
        resources=frozenset({resource}),
        principals=frozenset({"service:assistant"}),
        authenticated=True,
    )


def _policy() -> PolicyEngine:
    return PolicyEngine(
        (
            _allow(HOST_PROCESS_LIST_ACTION, host_process_collection_resource(_HOST_ID)),
            _allow(HOST_WINDOW_LIST_ACTION, host_window_collection_resource(_HOST_ID)),
            _allow(HOST_APPLICATION_LAUNCH_ACTION, host_application_resource(_HOST_ID, _APP_ID)),
            _allow(HOST_WINDOW_FOCUS_ACTION, host_window_resource(_HOST_ID, _WINDOW_ID)),
            _allow(HOST_APPLICATION_CLOSE_ACTION, host_process_resource(_HOST_ID, _PROCESS_ID)),
            _allow(HOST_CLIPBOARD_READ_ACTION, host_clipboard_resource(_HOST_ID)),
            _allow(HOST_CLIPBOARD_WRITE_ACTION, host_clipboard_resource(_HOST_ID)),
        )
    )


class _ExplodingObserver:
    async def record(
        self,
        observation: HostAutomationOperationObservation,
        context: SecurityContext,
    ) -> None:
        del observation, context
        raise RuntimeError(_OBSERVER_SECRET)


class _LeakyAdapter(DeterministicHostAutomationAdapter):
    async def list_processes(
        self,
        request: HostProcessListRequest,
    ) -> HostProcessListResult:
        del request
        raise RuntimeError(_NATIVE_SECRET)

    async def list_windows(
        self,
        request: HostWindowListRequest,
    ) -> HostWindowListResult:
        del request
        raise RuntimeError(_NATIVE_SECRET)

    async def launch_application(
        self,
        request: HostApplicationLaunchRequest,
    ) -> HostApplicationLaunchResult:
        del request
        raise RuntimeError(_NATIVE_SECRET)

    async def focus_window(
        self,
        request: HostWindowFocusRequest,
    ) -> HostWindowFocusResult:
        del request
        raise RuntimeError(_NATIVE_SECRET)

    async def close_application(
        self,
        request: HostApplicationCloseRequest,
    ) -> HostApplicationCloseResult:
        del request
        raise RuntimeError(_NATIVE_SECRET)

    async def read_clipboard(
        self,
        request: HostClipboardReadRequest,
    ) -> HostClipboardReadResult:
        del request
        raise RuntimeError(_NATIVE_SECRET)

    async def write_clipboard(
        self,
        request: HostClipboardWriteRequest,
    ) -> HostClipboardWriteResult:
        del request
        raise RuntimeError(_NATIVE_SECRET)


def _leaky_native() -> _LeakyAdapter:
    return _LeakyAdapter(
        host_id=_HOST_ID,
        host_epoch=_EPOCH,
        limits=_limits(),
        applications=(_APP_ID,),
        processes=(
            HostProcessDescriptor(
                host_id=_HOST_ID,
                host_epoch=_EPOCH,
                process_id=_PROCESS_ID,
                application_id=_APP_ID,
                label=_SECRET_PROCESS_LABEL,
            ),
        ),
        windows=(
            HostWindowDescriptor(
                host_id=_HOST_ID,
                host_epoch=_EPOCH,
                window_id=_WINDOW_ID,
                process_id=_PROCESS_ID,
                application_id=_APP_ID,
                title=_SECRET_WINDOW_TITLE,
            ),
        ),
        clipboard_text=_SECRET_CLIPBOARD_READ,
    )


@pytest.mark.asyncio
async def test_host_operations_emit_only_content_free_fixed_signals() -> None:
    events = EventBus()
    captured: list[Event] = []

    async def capture(event: Event) -> None:
        if event.name.startswith("host."):
            captured.append(event)

    await events.subscribe("*", capture)
    store = InMemoryAuditStore()
    audit = AuditLedger(store)
    sink = InMemorySink(capacity=500)
    observability = ObservabilityHub((sink,))
    observer = ContentFreeHostAutomationObserver(
        _HOST_ID,
        HostAutomationObservabilityConfiguration(),
        events=events,
        audit=audit,
        observability=observability,
    )
    service = HostAutomationService(
        adapter=_native(),
        authorizer=PolicyEngineHostAutomationAuthorizer(_policy()),
        observer=observer,
    )
    context = _context()

    process_result = await service.list_processes(
        HostProcessListRequest(host_id=_HOST_ID, limit=8, created_at=_NOW),
        context,
    )
    window_result = await service.list_windows(
        HostWindowListRequest(host_id=_HOST_ID, limit=8, created_at=_NOW),
        context,
    )
    clipboard_result = await service.read_clipboard(
        HostClipboardReadRequest(host_id=_HOST_ID, created_at=_NOW),
        context,
    )
    await service.write_clipboard(
        HostClipboardWriteRequest(
            host_id=_HOST_ID,
            text=_SECRET_CLIPBOARD_WRITE,
            created_at=_NOW,
        ),
        context,
    )
    await service.focus_window(
        HostWindowFocusRequest(
            host_id=_HOST_ID,
            host_epoch=_EPOCH,
            window_id=_WINDOW_ID,
            process_id=_PROCESS_ID,
            application_id=_APP_ID,
            created_at=_NOW,
        ),
        context,
    )
    await service.launch_application(
        HostApplicationLaunchRequest(
            host_id=_HOST_ID,
            application_id=_APP_ID,
            created_at=_NOW,
        ),
        context,
    )
    await service.close_application(
        HostApplicationCloseRequest(
            host_id=_HOST_ID,
            host_epoch=_EPOCH,
            application_id=_APP_ID,
            process_id=_PROCESS_ID,
            created_at=_NOW,
        ),
        context,
    )

    assert process_result.processes[0].label == _SECRET_PROCESS_LABEL
    assert window_result.windows[0].title == _SECRET_WINDOW_TITLE
    assert clipboard_result.text == _SECRET_CLIPBOARD_READ

    names = {event.name for event in captured}
    expected_actions = {
        HOST_PROCESS_LIST_ACTION,
        HOST_WINDOW_LIST_ACTION,
        HOST_APPLICATION_LAUNCH_ACTION,
        HOST_WINDOW_FOCUS_ACTION,
        HOST_APPLICATION_CLOSE_ACTION,
        HOST_CLIPBOARD_READ_ACTION,
        HOST_CLIPBOARD_WRITE_ACTION,
    }
    assert {f"{action}.started" for action in expected_actions} <= names
    assert {f"{action}.succeeded" for action in expected_actions} <= names
    assert all(event.payload == {} for event in captured)

    allowed_metadata = {
        "host_id",
        "request_id",
        "action",
        "outcome",
        "duration_ms",
        "result_count",
        "truncated",
        "error_code",
    }
    assert all(set(event.metadata) <= allowed_metadata for event in captured)

    records = await store.read(AuditQuery(limit=1000))
    observations = (await sink.snapshot()).records
    serialized = repr((captured, records, observations))
    for secret in (
        str(_APP_ID),
        _SECRET_PROCESS_LABEL,
        _SECRET_WINDOW_TITLE,
        _SECRET_CLIPBOARD_READ,
        _SECRET_CLIPBOARD_WRITE,
    ):
        assert secret not in serialized

    assert "result_count" in serialized
    assert HOST_PROCESS_LIST_ACTION in serialized
    assert HOST_CLIPBOARD_READ_ACTION in serialized


@pytest.mark.asyncio
async def test_observer_failure_never_changes_host_operation_result() -> None:
    service = HostAutomationService(
        adapter=_native(),
        authorizer=PolicyEngineHostAutomationAuthorizer(_policy()),
        observer=_ExplodingObserver(),
    )

    result = await service.list_processes(
        HostProcessListRequest(host_id=_HOST_ID, limit=8, created_at=_NOW),
        _context(),
    )

    assert [item.process_id for item in result.processes] == [_PROCESS_ID]


@pytest.mark.asyncio
async def test_observer_failure_never_masks_host_authorization_rejection() -> None:
    service = HostAutomationService(
        adapter=_native(),
        authorizer=PolicyEngineHostAutomationAuthorizer(PolicyEngine()),
        observer=_ExplodingObserver(),
    )

    with pytest.raises(HostAutomationAuthorizationRejectedError):
        await service.list_processes(
            HostProcessListRequest(host_id=_HOST_ID, limit=8, created_at=_NOW),
            _context(),
        )


@pytest.mark.asyncio
async def test_unknown_read_only_adapter_failures_are_safe_and_content_free() -> None:
    events = EventBus()
    captured: list[Event] = []

    async def capture(event: Event) -> None:
        if event.name.startswith("host."):
            captured.append(event)

    await events.subscribe("*", capture)
    observer = ContentFreeHostAutomationObserver(
        _HOST_ID,
        HostAutomationObservabilityConfiguration(
            audit_enabled=False,
            metrics_enabled=False,
            logs_enabled=False,
        ),
        events=events,
    )
    service = HostAutomationService(
        adapter=_leaky_native(),
        authorizer=PolicyEngineHostAutomationAuthorizer(_policy()),
        observer=observer,
    )
    context = _context()

    with pytest.raises(HostAutomationAdapterError) as process_error:
        await service.list_processes(
            HostProcessListRequest(host_id=_HOST_ID, limit=8, created_at=_NOW),
            context,
        )
    with pytest.raises(HostAutomationAdapterError) as window_error:
        await service.list_windows(
            HostWindowListRequest(host_id=_HOST_ID, limit=8, created_at=_NOW),
            context,
        )
    with pytest.raises(HostAutomationAdapterError) as clipboard_error:
        await service.read_clipboard(
            HostClipboardReadRequest(host_id=_HOST_ID, created_at=_NOW),
            context,
        )

    for error in (process_error.value, window_error.value, clipboard_error.value):
        assert _NATIVE_SECRET not in str(error)
        assert str(error) == "host automation adapter failed"

    failed_events = [event for event in captured if event.name.endswith(".failed")]
    assert len(failed_events) == 3
    assert all(event.metadata["error_code"] == "adapter_failed" for event in failed_events)
    assert _NATIVE_SECRET not in repr(captured)


@pytest.mark.asyncio
async def test_unknown_effectful_adapter_failures_become_indeterminate_without_retry() -> None:
    events = EventBus()
    captured: list[Event] = []

    async def capture(event: Event) -> None:
        if event.name.startswith("host."):
            captured.append(event)

    await events.subscribe("*", capture)
    observer = ContentFreeHostAutomationObserver(
        _HOST_ID,
        HostAutomationObservabilityConfiguration(
            audit_enabled=False,
            metrics_enabled=False,
            logs_enabled=False,
        ),
        events=events,
    )
    service = HostAutomationService(
        adapter=_leaky_native(),
        authorizer=PolicyEngineHostAutomationAuthorizer(_policy()),
        observer=observer,
    )
    context = _context()

    with pytest.raises(HostAutomationIndeterminateEffectError) as launch_error:
        await service.launch_application(
            HostApplicationLaunchRequest(
                host_id=_HOST_ID,
                application_id=_APP_ID,
                created_at=_NOW,
            ),
            context,
        )
    with pytest.raises(HostAutomationIndeterminateEffectError) as focus_error:
        await service.focus_window(
            HostWindowFocusRequest(
                host_id=_HOST_ID,
                host_epoch=_EPOCH,
                window_id=_WINDOW_ID,
                process_id=_PROCESS_ID,
                application_id=_APP_ID,
                created_at=_NOW,
            ),
            context,
        )
    with pytest.raises(HostAutomationIndeterminateEffectError) as close_error:
        await service.close_application(
            HostApplicationCloseRequest(
                host_id=_HOST_ID,
                host_epoch=_EPOCH,
                application_id=_APP_ID,
                process_id=_PROCESS_ID,
                created_at=_NOW,
            ),
            context,
        )
    with pytest.raises(HostAutomationIndeterminateEffectError) as write_error:
        await service.write_clipboard(
            HostClipboardWriteRequest(
                host_id=_HOST_ID,
                text=_SECRET_CLIPBOARD_WRITE,
                created_at=_NOW,
            ),
            context,
        )

    for error in (
        launch_error.value,
        focus_error.value,
        close_error.value,
        write_error.value,
    ):
        assert _NATIVE_SECRET not in str(error)
        assert str(error) == "host automation effect outcome is indeterminate"

    indeterminate_events = [event for event in captured if event.name.endswith(".indeterminate")]
    assert len(indeterminate_events) == 4
    assert all(
        event.metadata["error_code"] == "indeterminate_effect" for event in indeterminate_events
    )
    serialized = repr(captured)
    assert _NATIVE_SECRET not in serialized
    assert _SECRET_CLIPBOARD_WRITE not in serialized
    assert str(_APP_ID) not in serialized
