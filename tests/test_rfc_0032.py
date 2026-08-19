from __future__ import annotations

from pathlib import Path

_RFC = (
    Path(__file__).resolve().parents[1]
    / "docs"
    / "rfcs"
    / "RFC-0032-secure-host-automation-and-desktop-control.md"
)


def _text() -> str:
    return " ".join(_RFC.read_text(encoding="utf-8").split())


def _security_invariant_numbers() -> list[int]:
    document = _RFC.read_text(encoding="utf-8")
    section = document.split("## Security invariants", 1)[1].split("## Initial action surface", 1)[
        0
    ]
    numbers: list[int] = []
    for line in section.splitlines():
        prefix, separator, _ = line.partition(". ")
        if separator and prefix.isdigit():
            numbers.append(int(prefix))
    return numbers


def test_rfc_0032_is_accepted_for_v0320() -> None:
    text = _text()
    assert "# RFC-0032: Secure Host Automation and Desktop Control" in text
    assert "- Status: Accepted" in text
    assert "- Target release: Phoenix OS v0.32.0" in text
    assert "Desktop state is data; host effects require fresh authority." in text


def test_rfc_0032_keeps_public_contracts_os_neutral_and_windows_first() -> None:
    text = _text()
    for phrase in (
        "The public contracts are operating-system-neutral.",
        "Phoenix OS v0.32.0 implements only a Windows adapter.",
        "Linux and macOS adapters are not required by this release",
        "WindowsHostAutomationAdapter",
        "Windows is the only required concrete adapter for Phoenix OS v0.32.0.",
    ):
        assert phrase in text

    for native_type in (
        "Win32 handle",
        "PID contract",
        "HWND contract",
        "COM object",
        "native structure",
        "clipboard handle",
    ):
        assert native_type in text


def test_rfc_0032_defines_exact_initial_host_actions() -> None:
    text = _text()
    for action in (
        "host.process.list",
        "host.window.list",
        "host.app.launch",
        "host.window.focus",
        "host.app.close",
        "host.clipboard.write",
        "host.clipboard.read",
    ):
        assert action in text


def test_rfc_0032_explicitly_excludes_broad_host_authority() -> None:
    text = _text()
    for deferred in (
        "shell.*",
        "powershell.*",
        "keyboard.*",
        "mouse.*",
        "process.kill",
        "admin.*",
    ):
        assert deferred in text

    for phrase in (
        "Arbitrary shell execution",
        "Arbitrary PowerShell execution",
        "Generic command-line execution",
        "Model-selected executable paths",
        "Privilege elevation, UAC bypass, administrator automation",
        "Raw keyboard injection",
        "Raw mouse injection",
        "Arbitrary process termination or `process.kill`",
    ):
        assert phrase in text


def test_rfc_0032_defines_server_owned_policy_resource_shapes() -> None:
    text = _text()
    for resource in (
        "host-automation:host:<host-id>",
        "host-automation:host:<host-id>/processes",
        "host-automation:host:<host-id>/windows",
        "host-automation:host:<host-id>/clipboard:text",
        "host-automation:host:<host-id>/application:<application-id>",
        "host-automation:host:<host-id>/process:<process-id>",
        "host-automation:host:<host-id>/window:<window-id>",
    ):
        assert resource in text

    assert (
        "Native PIDs, HWND values, executable paths, window titles, command lines, "
        "clipboard contents, and model-provided strings are never policy resource names." in text
    )


def test_rfc_0032_keeps_tool_and_host_authority_independent() -> None:
    text = _text()
    assert (
        "A model-originated host effect therefore requires the normal RFC-0027 "
        "`tool.invoke` decision and the exact RFC-0032 `host.*` decision." in text
    )
    assert "Neither authorization implies the other." in text
    assert (
        "Authorization for `agent.run`, `model.infer`, `tool.invoke`, `workspace.*`, "
        "`memory.*`, or any other Phoenix action does not imply any `host.*` action." in text
    )
    assert "Authorization for one `host.*` action never implies another `host.*` action." in text


def test_rfc_0032_launch_is_profile_based_not_command_based() -> None:
    text = _text()
    for phrase in (
        "Phoenix application launch is profile-based, not path-based.",
        "trusted server-owned `HostApplicationId`",
        "The model cannot replace the executable, working directory, shell verb, "
        "environment, elevation behavior, or adapter.",
        "The initial release does not require arbitrary launch arguments.",
        "cannot expose a generic command-line escape hatch",
    ):
        assert phrase in text


def test_rfc_0032_defines_stale_safe_window_focus() -> None:
    text = _text()
    for phrase in (
        "The adapter revalidates the target immediately before attempting focus.",
        "stale or reused native handle",
        "changed owning process",
        "changed host epoch",
        "Focus does not authorize keyboard or mouse injection.",
        "UI-target TOCTOU",
    ):
        assert phrase in text


def test_rfc_0032_defines_no_transparent_retry_for_host_side_effects() -> None:
    text = _text()
    assert "Launch is an external side effect and is never transparently retried." in text
    assert (
        "Host side effects are not transparently retried by the host service or Windows adapter."
        in text
    )
    assert (
        "Durable agent recovery never transparently replays an indeterminate host side effect."
        in text
    )
    assert (
        "cancellation after an operating-system effect has started never fabricates "
        "a guaranteed rollback" in text
    )


def test_rfc_0032_close_is_graceful_and_approval_bound() -> None:
    text = _text()
    for phrase in (
        "`host.app.close` is graceful-close semantics only in v0.32.0",
        "force kill is not included",
        "Close may cause unsaved user data loss.",
        "action-bound approval",
        "non-agent callers cannot bypass configured close confirmation",
    ):
        assert phrase in text


def test_rfc_0032_clipboard_read_and_write_are_separate_sensitive_boundaries() -> None:
    text = _text()
    for phrase in (
        "`host.clipboard.write` and `host.clipboard.read` are distinct permissions.",
        "Deployments may enable write while leaving read disabled.",
        "Clipboard support is text-only in the initial release.",
        "Clipboard read results are sensitive untrusted data",
        "clipboard text commonly contains passwords, tokens, private messages, source code",
        "The adapter never logs clipboard text",
    ):
        assert phrase in text


def test_rfc_0032_observability_runtime_and_compatibility_are_bounded() -> None:
    text = _text()
    for phrase in (
        "Host automation events and administration are content-free.",
        "Runtime owns adapter startup",
        "reverse-order shutdown",
        "Unsupported platforms fail explicitly when host automation is configured",
        "Omitting host automation remains compatible and does not probe the desktop.",
        "Existing Phoenix OS v0.31.0 inference, agent, durable-agent, multi-agent, memory, "
        "and workspace behavior remains unchanged.",
    ):
        assert phrase in text


def test_rfc_0032_has_fifty_six_security_invariants() -> None:
    assert _security_invariant_numbers() == list(range(1, 57))


def test_rfc_0032_proposes_provider_neutral_host_contracts() -> None:
    text = _text()
    for contract in (
        "HostId",
        "HostEpoch",
        "HostApplicationId",
        "HostProcessId",
        "HostWindowId",
        "HostProcessDescriptor",
        "HostWindowDescriptor",
        "HostProcessListRequest",
        "HostProcessListResult",
        "HostWindowListRequest",
        "HostWindowListResult",
        "HostApplicationLaunchRequest",
        "HostApplicationLaunchResult",
        "HostWindowFocusRequest",
        "HostWindowFocusResult",
        "HostApplicationCloseRequest",
        "HostApplicationCloseResult",
        "HostClipboardReadRequest",
        "HostClipboardReadResult",
        "HostClipboardWriteRequest",
        "HostClipboardWriteResult",
        "HostAutomationLimits",
        "HostAutomationAdapter",
        "HostAutomationAuthorizer",
        "HostAutomationApprovalGate",
        "HostAutomationService",
        "HostAutomationObserver",
        "HostAutomationAdministration",
        "HostAutomationError",
        "WindowsHostAutomationAdapter",
    ):
        assert f"`{contract}`" in text


def test_rfc_0032_slice_plan_is_fully_complete() -> None:
    text = _text()
    assert "### Slice 0 - RFC foundation and executable specification" in text
    assert "### Slice 7 - Security review, migration, and release hardening" in text

    for item in (
        "Draft RFC-0032 with OS-neutral contracts and Windows-only v0.32.0 target",
        "Define initial `host.*` action and resource naming",
        "Define no-shell/no-keyboard/no-mouse/no-force-kill authority boundary",
        "Define independent tool and host authorization",
        "Define compatibility-by-omission contract",
        "Add RFC structure and regression tests",
    ):
        assert f"- [x] {item}" in text

    for item in (
        "Immutable bounded host/application/process/window contracts",
        "Host epoch and stale-identity rules",
        "Exact `host.*` constants/resources and current-policy authorization",
        "Host automation limits and safe errors",
        "Deterministic fake adapter for network/OS-effect-free tests",
        "Contract, policy, stale-ID, and compatibility regressions",
    ):
        assert f"- [x] {item}" in text

    for item in (
        "`WindowsHostAutomationAdapter` process enumeration",
        "Bounded content-minimized `host.process.list`",
        "Bounded reviewed `host.window.list`",
        "Native identity translation without public handles",
        "Session/desktop and stale-enumeration failure handling",
        "Windows discovery integration tests",
    ):
        assert f"- [x] {item}" in text
    for item in (
        "Reviewed RFC-0027 host tool descriptors and schemas",
        "Independent `tool.invoke` plus `host.*` enforcement",
        "Content-free host observer events and safe public failures",
        "Bounded host administration/health surface",
        "Runtime assembler ownership and disabled-by-default tests",
        "Threat-model/security-invariant review",
        "ADRs for host authority, application profiles, native identity opacity, and UI TOCTOU",
        "v0.31.0 to v0.32.0 migration guidance",
    ):
        assert f"- [x] {item}" in text

    assert "- [x] Named host-automation release gate" in text
    assert "- [x] Windows dogfood with real process/window/app/clipboard effects" in text
    assert "- [x] Offline wheel/sdist validation" in text
    assert "- [x] Release notes and package version 0.32.0" in text
    assert "- [x] Tag, artifacts, and checksums" in text
    assert "- [ ]" not in text
    assert "- Status: Accepted" in text
    assert "docs/releases/v0.32.0.md" in text
    assert "RFC-0032 is accepted for Phoenix OS 0.32.0." in text


def test_rfc_0032_acceptance_preserves_security_boundary() -> None:
    text = _text()
    for phrase in (
        "host automation is opt-in and bounded",
        "public contracts are OS-neutral",
        "Windows is the reviewed v0.32.0 implementation",
        "arbitrary executable and shell authority cannot enter through model arguments",
        "every operation has fresh exact `host.*` authorization",
        "process/window identities fail closed when stale",
        "focus does not imply keyboard/mouse authority",
        "clipboard read and write are independently authorized and text-only",
        "host side effects are never transparently replayed after indeterminate failure",
        "omitting host automation preserves Phoenix OS v0.31.0 behavior",
    ):
        assert phrase in text
