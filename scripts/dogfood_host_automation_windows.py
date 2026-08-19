from __future__ import annotations

import argparse
import asyncio
import os
import sys
from pathlib import Path
from time import monotonic

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
    HostAutomationIndeterminateEffectError,
    HostAutomationLimits,
    HostAutomationService,
    HostClipboardReadRequest,
    HostClipboardWriteRequest,
    HostId,
    HostProcessId,
    HostProcessListRequest,
    HostProcessListResult,
    HostWindowDescriptor,
    HostWindowFocusRequest,
    HostWindowListRequest,
    PolicyEngineHostAutomationAuthorizer,
    WindowsHostAutomationAdapter,
    host_application_resource,
    host_clipboard_resource,
    host_process_collection_resource,
    host_process_resource,
    host_window_collection_resource,
    host_window_resource,
)
from phoenix_os.host_automation.windows_effects import WindowsApplicationProfile
from phoenix_os.policy import PolicyEffect, PolicyEngine, PolicyRule, PrincipalType, SecurityContext

_CONFIRMATION_FLAG = "--confirm-real-effects"
_HOST = HostId("windows-dogfood")
_APPLICATION = HostApplicationId("phoenix-dogfood-notepad")
_PRINCIPAL = "service:windows-dogfood"
_CLIPBOARD_BASELINE = "PHOENIX-RFC0032-DOGFOOD-BASELINE"
_CLIPBOARD_PROBE = "PHOENIX-RFC0032-DOGFOOD-WRITE-READ"
_LIST_LIMIT = 4096
_WAIT_SECONDS = 20.0
_POLL_SECONDS = 0.25


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run the RFC-0032 real-Windows host-automation dogfood. "
            "This launches, focuses, and gracefully closes Notepad and writes the clipboard."
        )
    )
    parser.add_argument(
        _CONFIRMATION_FLAG,
        action="store_true",
        help="confirm that this run may perform the documented real Windows effects",
    )
    return parser


def _allow(rule_id: str, action: str, resource: str) -> PolicyRule:
    return PolicyRule(
        rule_id=rule_id,
        effect=PolicyEffect.ALLOW,
        actions=frozenset({action}),
        resources=frozenset({resource}),
        principals=frozenset({_PRINCIPAL}),
        authenticated=True,
    )


def _security_context() -> SecurityContext:
    return SecurityContext(
        principal=_PRINCIPAL,
        principal_type=PrincipalType.SERVICE,
        authenticated=True,
    )


def _notepad_executable() -> str:
    system_root = os.environ.get("SystemRoot")
    if not system_root:
        raise RuntimeError("SystemRoot is unavailable")
    executable = Path(system_root) / "System32" / "notepad.exe"
    if not executable.is_file():
        raise RuntimeError("configured Windows dogfood Notepad executable is unavailable")
    return str(executable)


def _static_policy_rules() -> tuple[PolicyRule, ...]:
    return (
        _allow(
            "allow.windows-dogfood.process-list",
            HOST_PROCESS_LIST_ACTION,
            host_process_collection_resource(_HOST),
        ),
        _allow(
            "allow.windows-dogfood.window-list",
            HOST_WINDOW_LIST_ACTION,
            host_window_collection_resource(_HOST),
        ),
        _allow(
            "allow.windows-dogfood.app-launch",
            HOST_APPLICATION_LAUNCH_ACTION,
            host_application_resource(_HOST, _APPLICATION),
        ),
        _allow(
            "allow.windows-dogfood.clipboard-write",
            HOST_CLIPBOARD_WRITE_ACTION,
            host_clipboard_resource(_HOST),
        ),
        _allow(
            "allow.windows-dogfood.clipboard-read",
            HOST_CLIPBOARD_READ_ACTION,
            host_clipboard_resource(_HOST),
        ),
    )


async def _list_processes(
    service: HostAutomationService,
    context: SecurityContext,
) -> HostProcessListResult:
    return await service.list_processes(
        HostProcessListRequest(host_id=_HOST, limit=_LIST_LIMIT),
        context,
    )


async def _wait_for_process(
    service: HostAutomationService,
    context: SecurityContext,
    process_id: HostProcessId,
    *,
    present: bool,
) -> None:
    deadline = monotonic() + _WAIT_SECONDS
    while True:
        result = await _list_processes(service, context)
        if not present and result.truncated:
            raise RuntimeError(
                "process discovery truncated while verifying exact dogfood process exit"
            )
        found = any(item.process_id == process_id for item in result.processes)
        if found is present:
            return
        if monotonic() >= deadline:
            state = "appear" if present else "exit after graceful close"
            raise RuntimeError(f"dogfood Notepad process did not {state} within timeout")
        await asyncio.sleep(_POLL_SECONDS)


async def _wait_for_window(
    service: HostAutomationService,
    context: SecurityContext,
    process_id: HostProcessId,
) -> HostWindowDescriptor:
    deadline = monotonic() + _WAIT_SECONDS
    while True:
        result = await service.list_windows(
            HostWindowListRequest(host_id=_HOST, limit=_LIST_LIMIT),
            context,
        )
        for window in result.windows:
            if window.process_id == process_id and window.application_id == _APPLICATION:
                return window
        if result.truncated:
            raise RuntimeError("window discovery truncated before exact dogfood target was found")
        if monotonic() >= deadline:
            raise RuntimeError("dogfood Notepad window did not appear within timeout")
        await asyncio.sleep(_POLL_SECONDS)


async def _run_dogfood() -> None:
    context = _security_context()
    policy = PolicyEngine(_static_policy_rules())
    adapter = WindowsHostAutomationAdapter(
        host_id=_HOST,
        limits=HostAutomationLimits(
            max_process_results=_LIST_LIMIT,
            max_window_results=_LIST_LIMIT,
        ),
        application_profiles=(
            WindowsApplicationProfile(
                application_id=_APPLICATION,
                executable=_notepad_executable(),
            ),
        ),
        clipboard_read_enabled=True,
    )
    service = HostAutomationService(
        adapter=adapter,
        authorizer=PolicyEngineHostAutomationAuthorizer(policy),
    )

    close_request: HostApplicationCloseRequest | None = None
    close_attempted = False
    close_succeeded = False
    clipboard_probe_succeeded = False
    clipboard_restore_attempted = False

    try:
        print("[1/7] process.list: checking real Windows process discovery", flush=True)
        initial_processes = await _list_processes(service, context)
        if initial_processes.truncated:
            raise RuntimeError("process discovery truncated; refusing unsafe Notepad preflight")
        if any(item.label.casefold() == "notepad.exe" for item in initial_processes.processes):
            raise RuntimeError("close every existing Notepad window before running the dogfood")

        print("[2/7] clipboard.read: validating the operator-provided safe baseline", flush=True)
        baseline = await service.read_clipboard(
            HostClipboardReadRequest(host_id=_HOST),
            context,
        )
        if baseline.text != _CLIPBOARD_BASELINE:
            raise RuntimeError(
                "clipboard baseline mismatch; run "
                f'Set-Clipboard -Value "{_CLIPBOARD_BASELINE}" before dogfood'
            )

        print("[3/7] app.launch: launching configured Notepad profile", flush=True)
        launched = await service.launch_application(
            HostApplicationLaunchRequest(
                host_id=_HOST,
                application_id=_APPLICATION,
            ),
            context,
        )
        await policy.register(
            _allow(
                "allow.windows-dogfood.app-close",
                HOST_APPLICATION_CLOSE_ACTION,
                host_process_resource(_HOST, launched.process_id),
            )
        )
        close_request = HostApplicationCloseRequest(
            host_id=_HOST,
            host_epoch=launched.host_epoch,
            application_id=_APPLICATION,
            process_id=launched.process_id,
        )
        await _wait_for_process(service, context, launched.process_id, present=True)

        print("[4/7] window.list + window.focus: targeting the exact launched window", flush=True)
        window = await _wait_for_window(service, context, launched.process_id)
        await policy.register(
            _allow(
                "allow.windows-dogfood.window-focus",
                HOST_WINDOW_FOCUS_ACTION,
                host_window_resource(_HOST, window.window_id),
            )
        )
        focused = await service.focus_window(
            HostWindowFocusRequest(
                host_id=_HOST,
                host_epoch=window.host_epoch,
                window_id=window.window_id,
                process_id=window.process_id,
                application_id=_APPLICATION,
            ),
            context,
        )
        if focused.window_id != window.window_id or focused.process_id != launched.process_id:
            raise RuntimeError("focused window identity did not match the exact dogfood target")

        print("[5/7] clipboard.write/read: writing and verifying the fixed probe", flush=True)
        try:
            written = await service.write_clipboard(
                HostClipboardWriteRequest(host_id=_HOST, text=_CLIPBOARD_PROBE),
                context,
            )
        except HostAutomationIndeterminateEffectError:
            print(
                "WARNING: clipboard write outcome is indeterminate; "
                "the script will not retry or claim restoration.",
                flush=True,
            )
            raise
        clipboard_probe_succeeded = True
        if written.written_characters != len(_CLIPBOARD_PROBE):
            raise RuntimeError("clipboard write character count did not match the fixed probe")
        probe = await service.read_clipboard(
            HostClipboardReadRequest(host_id=_HOST),
            context,
        )
        if probe.text != _CLIPBOARD_PROBE:
            raise RuntimeError("clipboard read did not return the fixed dogfood probe")

        print("[6/7] clipboard.write/read: restoring and verifying the safe baseline", flush=True)
        clipboard_restore_attempted = True
        try:
            await service.write_clipboard(
                HostClipboardWriteRequest(host_id=_HOST, text=_CLIPBOARD_BASELINE),
                context,
            )
        except HostAutomationIndeterminateEffectError:
            print(
                "WARNING: clipboard restoration outcome is indeterminate; "
                "the script will not retry it.",
                flush=True,
            )
            raise
        restored = await service.read_clipboard(
            HostClipboardReadRequest(host_id=_HOST),
            context,
        )
        if restored.text != _CLIPBOARD_BASELINE:
            raise RuntimeError("clipboard baseline restoration could not be verified")

        print("[7/7] app.close: issuing one exact graceful close and observing exit", flush=True)
        close_attempted = True
        try:
            await service.close_application(close_request, context)
        except HostAutomationIndeterminateEffectError:
            print(
                "WARNING: graceful close outcome is indeterminate; "
                "the script will not retry the close.",
                flush=True,
            )
            raise
        close_succeeded = True
        await _wait_for_process(service, context, launched.process_id, present=False)

        print(
            "RFC-0032 Windows dogfood passed: real process/window/app/clipboard effects "
            "completed through fresh host authorization.",
            flush=True,
        )
    finally:
        if clipboard_probe_succeeded and not clipboard_restore_attempted:
            clipboard_restore_attempted = True
            try:
                await service.write_clipboard(
                    HostClipboardWriteRequest(host_id=_HOST, text=_CLIPBOARD_BASELINE),
                    context,
                )
                print(
                    "Cleanup: restored the known dogfood clipboard baseline once.",
                    flush=True,
                )
            except Exception as exception:
                print(
                    "WARNING: clipboard cleanup could not be confirmed "
                    f"({type(exception).__name__}); no retry was attempted.",
                    flush=True,
                )

        if close_request is not None and not close_attempted:
            close_attempted = True
            try:
                await service.close_application(close_request, context)
                close_succeeded = True
                print("Cleanup: issued one graceful close to dogfood Notepad.", flush=True)
            except Exception as exception:
                print(
                    "WARNING: dogfood Notepad cleanup could not be confirmed "
                    f"({type(exception).__name__}); no retry was attempted.",
                    flush=True,
                )
        elif close_request is not None and close_attempted and not close_succeeded:
            print(
                "WARNING: close was already attempted with an unconfirmed outcome; "
                "it was not retried.",
                flush=True,
            )

        await service.close()


def main() -> int:
    args = _parser().parse_args()
    if not args.confirm_real_effects:
        print(
            f"Refusing real host effects without {_CONFIRMATION_FLAG}. "
            f'First run: Set-Clipboard -Value "{_CLIPBOARD_BASELINE}"',
            file=sys.stderr,
        )
        return 2
    if sys.platform != "win32":
        print("RFC-0032 Windows dogfood requires an interactive win32 session.", file=sys.stderr)
        return 2

    try:
        asyncio.run(_run_dogfood())
    except Exception as exception:
        print(
            f"RFC-0032 Windows dogfood FAILED ({type(exception).__name__}): {exception}",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
