from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_REVIEW = _ROOT / "docs" / "security" / "RFC-0032-host-automation-threat-model-review.md"


def test_host_automation_security_review_covers_all_invariants() -> None:
    text = _REVIEW.read_text(encoding="utf-8")
    assert "all fifty-six security invariants" in text
    for heading in (
        "## Review method",
        "## Trust boundaries",
        "## Threat review",
        "## Security-invariant review",
        "## Residual risks",
        "## Release conclusion",
    ):
        assert heading in text
    for marker in (
        "Invariants 1-10",
        "Invariants 11-24",
        "Invariants 25-36",
        "Invariants 37-43",
        "Invariants 44-50",
        "Invariants 51-56",
    ):
        assert marker in text


def test_host_automation_security_review_records_core_security_boundaries() -> None:
    text = " ".join(_REVIEW.read_text(encoding="utf-8").split())
    for phrase in (
        "Desktop state is data; host effects require fresh authority.",
        "Fresh independent `host.*` action/resource authorization",
        "Server-owned `HostApplicationId` profiles, never model-selected executable authority",
        "Opaque Phoenix process/window identities are separated from native PID/HWND state.",
        "Immediate pre-effect identity and desktop revalidation",
        "Action-bound, expiring, single-use close approval",
        "Clipboard text remains sensitive untrusted data, never authority.",
        "content-free bounded projections",
        "No transparent retry",
        "Runtime owns availability and reverse shutdown",
        (
            "RFC-0032 grants no shell, PowerShell, keyboard, mouse, force-kill, "
            "privilege-elevation, or generic administrator authority."
        ),
    ):
        assert phrase in text


def test_host_automation_security_review_names_executable_evidence() -> None:
    text = _REVIEW.read_text(encoding="utf-8")
    for evidence in (
        "test_host_automation_contracts.py",
        "test_host_automation_authorization.py",
        "test_host_automation_agent_control_tools.py",
        "test_host_automation_approval.py",
        "test_host_automation_service.py",
        "test_host_automation_windows.py",
        "test_host_automation_windows_discovery.py",
        "test_host_automation_windows_focus.py",
        "test_host_automation_windows_launch.py",
        "test_host_automation_windows_close.py",
        "test_host_automation_clipboard_hardening.py",
        "test_host_automation_windows_clipboard_read.py",
        "test_host_automation_durable_recovery.py",
        "test_host_automation_observer.py",
        "test_host_automation_administration.py",
        "test_runtime_assembler.py",
        "test_rfc_0032.py",
    ):
        assert evidence in text
