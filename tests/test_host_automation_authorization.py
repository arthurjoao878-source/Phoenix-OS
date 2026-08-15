from datetime import UTC, datetime
from uuid import UUID

import pytest

from phoenix_os.host_automation import (
    HOST_APPLICATION_CLOSE_ACTION,
    HOST_APPLICATION_LAUNCH_ACTION,
    HOST_CLIPBOARD_READ_ACTION,
    HOST_CLIPBOARD_WRITE_ACTION,
    HOST_PROCESS_LIST_ACTION,
    HOST_WINDOW_FOCUS_ACTION,
    HOST_WINDOW_LIST_ACTION,
    HostApplicationCloseRequest,
    HostApplicationId,
    HostApplicationLaunchRequest,
    HostAutomationAuthorizationRejectedError,
    HostAutomationAuthorizer,
    HostClipboardReadRequest,
    HostClipboardWriteRequest,
    HostEpoch,
    HostId,
    HostProcessId,
    HostProcessListRequest,
    HostWindowFocusRequest,
    HostWindowId,
    HostWindowListRequest,
    PolicyEngineHostAutomationAuthorizer,
    host_application_resource,
    host_clipboard_resource,
    host_process_collection_resource,
    host_process_resource,
    host_resource,
    host_window_collection_resource,
    host_window_resource,
)
from phoenix_os.policy import (
    PolicyDecision,
    PolicyEffect,
    PolicyEngine,
    PolicyRequest,
    PolicyRule,
    PrincipalType,
    SecurityContext,
)

_NOW = datetime(2026, 8, 15, 1, tzinfo=UTC)
_HOST = HostId("local")
_APP = HostApplicationId("editor")
_EPOCH = HostEpoch(UUID("32000000-0000-4000-8000-000000000032"))
_PROCESS = HostProcessId(UUID("32000000-0000-4000-8000-000000000033"))
_WINDOW = HostWindowId(UUID("32000000-0000-4000-8000-000000000034"))


def _context(*, authenticated: bool = True) -> SecurityContext:
    return SecurityContext(
        principal="service:assistant" if authenticated else "anonymous",
        principal_type=PrincipalType.SERVICE if authenticated else PrincipalType.ANONYMOUS,
        authenticated=authenticated,
    )


def _allow(action: str, resource: str) -> PolicyRule:
    return PolicyRule(
        rule_id=f"allow.{action.replace('.', '-')}",
        effect=PolicyEffect.ALLOW,
        actions=frozenset({action}),
        resources=frozenset({resource}),
        principals=frozenset({"service:assistant"}),
        authenticated=True,
    )


class _RecordingPolicyEngine(PolicyEngine):
    def __init__(self, rules: tuple[PolicyRule, ...]) -> None:
        super().__init__(rules)
        self.requests: list[PolicyRequest] = []

    async def enforce(self, request: PolicyRequest) -> PolicyDecision:
        self.requests.append(request)
        return await super().enforce(request)


def test_host_actions_and_resource_shapes_are_exact() -> None:
    assert (
        HOST_PROCESS_LIST_ACTION,
        HOST_WINDOW_LIST_ACTION,
        HOST_APPLICATION_LAUNCH_ACTION,
        HOST_WINDOW_FOCUS_ACTION,
        HOST_APPLICATION_CLOSE_ACTION,
        HOST_CLIPBOARD_WRITE_ACTION,
        HOST_CLIPBOARD_READ_ACTION,
    ) == (
        "host.process.list",
        "host.window.list",
        "host.app.launch",
        "host.window.focus",
        "host.app.close",
        "host.clipboard.write",
        "host.clipboard.read",
    )

    assert host_resource(_HOST) == "host-automation:host:local"
    assert host_process_collection_resource(_HOST) == "host-automation:host:local/processes"
    assert host_window_collection_resource(_HOST) == "host-automation:host:local/windows"
    assert host_clipboard_resource(_HOST) == "host-automation:host:local/clipboard:text"
    assert host_application_resource(_HOST, _APP) == "host-automation:host:local/application:editor"
    assert host_process_resource(_HOST, _PROCESS) == (
        "host-automation:host:local/process:32000000-0000-4000-8000-000000000033"
    )
    assert host_window_resource(_HOST, _WINDOW) == (
        "host-automation:host:local/window:32000000-0000-4000-8000-000000000034"
    )


def test_resource_builders_reject_untyped_model_strings() -> None:
    with pytest.raises(TypeError):
        host_resource("local")  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        host_application_resource(_HOST, "editor")  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        host_process_resource(_HOST, "1234")  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        host_window_resource(_HOST, "5678")  # type: ignore[arg-type]


def test_host_automation_authorizer_is_runtime_checkable_protocol() -> None:
    assert getattr(HostAutomationAuthorizer, "_is_runtime_protocol", False) is True


@pytest.mark.asyncio
async def test_process_list_authorization_uses_exact_collection_resource() -> None:
    request = HostProcessListRequest(
        host_id=_HOST,
        limit=25,
        request_id=UUID(int=1),
        created_at=_NOW,
    )
    policy = _RecordingPolicyEngine(
        (_allow(HOST_PROCESS_LIST_ACTION, host_process_collection_resource(_HOST)),)
    )
    authorizer = PolicyEngineHostAutomationAuthorizer(policy)

    await authorizer.authorize_process_list(request, _context())

    assert len(policy.requests) == 1
    policy_request = policy.requests[0]
    assert policy_request.action == HOST_PROCESS_LIST_ACTION
    assert policy_request.resource == host_process_collection_resource(_HOST)
    assert policy_request.attributes == {
        "host_id": "local",
        "request_id": str(request.request_id),
        "max_results": "25",
    }


@pytest.mark.asyncio
async def test_window_list_does_not_inherit_process_list_authority() -> None:
    policy = PolicyEngine(
        (_allow(HOST_PROCESS_LIST_ACTION, host_process_collection_resource(_HOST)),)
    )
    authorizer = PolicyEngineHostAutomationAuthorizer(policy)

    await authorizer.authorize_process_list(
        HostProcessListRequest(host_id=_HOST, created_at=_NOW),
        _context(),
    )
    with pytest.raises(HostAutomationAuthorizationRejectedError):
        await authorizer.authorize_window_list(
            HostWindowListRequest(host_id=_HOST, created_at=_NOW),
            _context(),
        )


@pytest.mark.asyncio
async def test_launch_authorization_targets_configured_application_not_executable_data() -> None:
    request = HostApplicationLaunchRequest(
        host_id=_HOST,
        application_id=_APP,
        request_id=UUID(int=2),
        created_at=_NOW,
    )
    policy = _RecordingPolicyEngine(
        (_allow(HOST_APPLICATION_LAUNCH_ACTION, host_application_resource(_HOST, _APP)),)
    )
    authorizer = PolicyEngineHostAutomationAuthorizer(policy)

    await authorizer.authorize_application_launch(request, _context())

    captured = policy.requests[0]
    assert captured.resource == host_application_resource(_HOST, _APP)
    assert captured.attributes["application_id"] == "editor"
    for forbidden in ("executable", "path", "command", "working_directory", "environment"):
        assert forbidden not in captured.attributes


@pytest.mark.asyncio
async def test_focus_authorization_is_bound_to_exact_opaque_window() -> None:
    request = HostWindowFocusRequest(
        host_id=_HOST,
        host_epoch=_EPOCH,
        window_id=_WINDOW,
        process_id=_PROCESS,
        application_id=_APP,
        request_id=UUID(int=3),
        created_at=_NOW,
    )
    policy = _RecordingPolicyEngine(
        (_allow(HOST_WINDOW_FOCUS_ACTION, host_window_resource(_HOST, _WINDOW)),)
    )
    authorizer = PolicyEngineHostAutomationAuthorizer(policy)

    await authorizer.authorize_window_focus(request, _context())

    captured = policy.requests[0]
    assert captured.resource == host_window_resource(_HOST, _WINDOW)
    assert captured.attributes["host_epoch"] == str(_EPOCH)
    assert captured.attributes["process_id"] == str(_PROCESS)
    assert captured.attributes["application_id"] == "editor"


@pytest.mark.asyncio
async def test_close_authorization_is_bound_to_exact_opaque_process() -> None:
    request = HostApplicationCloseRequest(
        host_id=_HOST,
        host_epoch=_EPOCH,
        application_id=_APP,
        process_id=_PROCESS,
        request_id=UUID(int=4),
        created_at=_NOW,
    )
    policy = _RecordingPolicyEngine(
        (_allow(HOST_APPLICATION_CLOSE_ACTION, host_process_resource(_HOST, _PROCESS)),)
    )
    authorizer = PolicyEngineHostAutomationAuthorizer(policy)

    await authorizer.authorize_application_close(request, _context())

    captured = policy.requests[0]
    assert captured.resource == host_process_resource(_HOST, _PROCESS)
    assert captured.attributes["application_id"] == "editor"
    assert captured.attributes["host_epoch"] == str(_EPOCH)


@pytest.mark.asyncio
async def test_clipboard_read_and_write_authority_are_independent() -> None:
    policy = PolicyEngine((_allow(HOST_CLIPBOARD_WRITE_ACTION, host_clipboard_resource(_HOST)),))
    authorizer = PolicyEngineHostAutomationAuthorizer(policy)

    await authorizer.authorize_clipboard_write(
        HostClipboardWriteRequest(host_id=_HOST, text="hello", created_at=_NOW),
        _context(),
    )
    with pytest.raises(HostAutomationAuthorizationRejectedError):
        await authorizer.authorize_clipboard_read(
            HostClipboardReadRequest(host_id=_HOST, created_at=_NOW),
            _context(),
        )


@pytest.mark.asyncio
async def test_clipboard_write_policy_attributes_never_include_clipboard_text() -> None:
    secret = "super-secret-token"
    request = HostClipboardWriteRequest(
        host_id=_HOST,
        text=secret,
        request_id=UUID(int=5),
        created_at=_NOW,
    )
    policy = _RecordingPolicyEngine(
        (_allow(HOST_CLIPBOARD_WRITE_ACTION, host_clipboard_resource(_HOST)),)
    )
    authorizer = PolicyEngineHostAutomationAuthorizer(policy)

    await authorizer.authorize_clipboard_write(request, _context())

    captured = policy.requests[0]
    assert captured.attributes["text_characters"] == str(len(secret))
    assert captured.attributes["text_bytes"] == str(len(secret.encode("utf-8")))
    assert secret not in captured.resource
    assert secret not in captured.attributes
    assert secret not in captured.attributes.values()


@pytest.mark.asyncio
async def test_default_deny_uses_safe_host_authorization_error() -> None:
    authorizer = PolicyEngineHostAutomationAuthorizer(PolicyEngine())

    with pytest.raises(
        HostAutomationAuthorizationRejectedError,
        match="host automation request authorization failed",
    ):
        await authorizer.authorize_process_list(
            HostProcessListRequest(host_id=_HOST, created_at=_NOW),
            _context(),
        )


@pytest.mark.asyncio
async def test_unauthenticated_context_is_rejected_before_policy_evaluation() -> None:
    policy = PolicyEngine()
    authorizer = PolicyEngineHostAutomationAuthorizer(policy)

    with pytest.raises(HostAutomationAuthorizationRejectedError):
        await authorizer.authorize_clipboard_read(
            HostClipboardReadRequest(host_id=_HOST, created_at=_NOW),
            _context(authenticated=False),
        )

    assert (await policy.snapshot()).evaluations == 0


@pytest.mark.asyncio
async def test_policy_confirmation_is_not_implicitly_accepted() -> None:
    policy = PolicyEngine(
        (
            PolicyRule(
                rule_id="confirm.clipboard-read",
                effect=PolicyEffect.REQUIRE_CONFIRMATION,
                actions=frozenset({HOST_CLIPBOARD_READ_ACTION}),
                resources=frozenset({host_clipboard_resource(_HOST)}),
                principals=frozenset({"service:assistant"}),
                authenticated=True,
            ),
        )
    )
    authorizer = PolicyEngineHostAutomationAuthorizer(policy)

    with pytest.raises(HostAutomationAuthorizationRejectedError):
        await authorizer.authorize_clipboard_read(
            HostClipboardReadRequest(host_id=_HOST, created_at=_NOW),
            _context(),
        )


@pytest.mark.asyncio
async def test_authorization_rechecks_current_policy_on_every_operation() -> None:
    policy = PolicyEngine()
    registration = await policy.register(
        _allow(HOST_PROCESS_LIST_ACTION, host_process_collection_resource(_HOST))
    )
    authorizer = PolicyEngineHostAutomationAuthorizer(policy)
    request = HostProcessListRequest(host_id=_HOST, created_at=_NOW)

    await authorizer.authorize_process_list(request, _context())
    assert await policy.unregister(registration) is True

    with pytest.raises(HostAutomationAuthorizationRejectedError):
        await authorizer.authorize_process_list(request, _context())


@pytest.mark.asyncio
async def test_wrong_request_type_fails_before_policy_evaluation() -> None:
    policy = PolicyEngine()
    authorizer = PolicyEngineHostAutomationAuthorizer(policy)

    with pytest.raises(TypeError, match="HostProcessListRequest"):
        await authorizer.authorize_process_list(
            HostWindowListRequest(host_id=_HOST, created_at=_NOW),  # type: ignore[arg-type]
            _context(),
        )

    assert (await policy.snapshot()).evaluations == 0
