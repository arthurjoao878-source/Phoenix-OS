from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_DOGFOOD = _ROOT / "scripts" / "dogfood_host_automation_windows.py"
_CI = _ROOT / ".github" / "workflows" / "ci.yml"
_CHECK_PS1 = _ROOT / "scripts" / "check.ps1"
_CHECK_SH = _ROOT / "scripts" / "check.sh"
_README = _ROOT / "README.md"
_RFC = _ROOT / "docs" / "rfcs" / "RFC-0032-secure-host-automation-and-desktop-control.md"


def test_windows_dogfood_requires_explicit_manual_real_effect_confirmation() -> None:
    text = _DOGFOOD.read_text(encoding="utf-8")
    assert '"--confirm-real-effects"' in text
    assert 'sys.platform != "win32"' in text
    assert '"System32" / "notepad.exe"' in text
    assert 'HostApplicationId("phoenix-dogfood-notepad")' in text
    assert "clipboard_read_enabled=True" in text
    assert "PHOENIX-RFC0032-DOGFOOD-BASELINE" in text
    assert "PHOENIX-RFC0032-DOGFOOD-WRITE-READ" in text
    assert "if not present and result.truncated:" in text
    assert "process discovery truncated while verifying exact dogfood process exit" in text


def test_windows_dogfood_exercises_real_service_policy_and_effect_boundaries() -> None:
    text = _DOGFOOD.read_text(encoding="utf-8")
    for phrase in (
        "WindowsHostAutomationAdapter(",
        "WindowsApplicationProfile(",
        "PolicyEngineHostAutomationAuthorizer(policy)",
        "HostAutomationService(",
        "service.list_processes(",
        "service.launch_application(",
        "service.list_windows(",
        "service.focus_window(",
        "service.write_clipboard(",
        "service.read_clipboard(",
        "service.close_application(",
        "host_process_resource(_HOST, launched.process_id)",
        "host_window_resource(_HOST, window.window_id)",
    ):
        assert phrase in text


def test_windows_dogfood_has_no_arbitrary_launch_or_force_kill_escape_hatch() -> None:
    text = _DOGFOOD.read_text(encoding="utf-8")
    for forbidden in (
        "--executable",
        "--command",
        "--working-directory",
        "--clipboard-text",
        "shell=True",
        "os.system",
        "subprocess.",
        "TerminateProcess",
        "taskkill",
    ):
        assert forbidden not in text


def test_windows_dogfood_is_not_part_of_automatic_ci_or_local_check_aggregators() -> None:
    command = "python scripts/dogfood_host_automation_windows.py"
    for path in (_CI, _CHECK_PS1, _CHECK_SH):
        assert command not in path.read_text(encoding="utf-8")

    readme = _README.read_text(encoding="utf-8")
    rfc = _RFC.read_text(encoding="utf-8")
    assert f"{command} --confirm-real-effects" in readme
    assert f"{command} --confirm-real-effects" in rfc
    assert "manual and Windows-only" in readme
    assert "manual and Windows-only" in rfc


def test_windows_dogfood_completion_is_recorded_without_closing_later_gates() -> None:
    rfc = _RFC.read_text(encoding="utf-8")
    readme = _README.read_text(encoding="utf-8")
    assert "- [x] Windows dogfood host integration" in rfc
    assert "- [x] Windows dogfood with real process/window/app/clipboard effects" in rfc
    assert "- [x] Offline wheel/sdist validation" in rfc
    assert "- [ ] Release notes and package version 0.32.0" in rfc
    assert "- [ ] Tag, artifacts, and checksums" in rfc
    assert "completed all seven" in readme
    assert "steps with exit code 0" in readme
