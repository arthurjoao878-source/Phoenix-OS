from __future__ import annotations

import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]

_COMPANION_TESTS = ("tests/test_rfc_0032.py",)

_REQUIRED_HOST_AUTOMATION_TESTS = frozenset(
    {
        "tests/test_host_automation_administration.py",
        "tests/test_host_automation_adrs.py",
        "tests/test_host_automation_agent_control_tools.py",
        "tests/test_host_automation_agent_tools.py",
        "tests/test_host_automation_approval.py",
        "tests/test_host_automation_authorization.py",
        "tests/test_host_automation_clipboard_hardening.py",
        "tests/test_host_automation_contracts.py",
        "tests/test_host_automation_durable_recovery.py",
        "tests/test_host_automation_errors.py",
        "tests/test_host_automation_fake.py",
        "tests/test_host_automation_migration_guidance.py",
        "tests/test_host_automation_observer.py",
        "tests/test_host_automation_release_gate.py",
        "tests/test_host_automation_security_review.py",
        "tests/test_host_automation_service.py",
        "tests/test_host_automation_windows.py",
        "tests/test_host_automation_windows_clipboard_read.py",
        "tests/test_host_automation_windows_clipboard_write.py",
        "tests/test_host_automation_windows_close.py",
        "tests/test_host_automation_windows_discovery.py",
        "tests/test_host_automation_windows_dogfood.py",
        "tests/test_host_automation_windows_focus.py",
        "tests/test_host_automation_windows_launch.py",
    }
)

_REQUIRED_HOST_AUTOMATION_MODULES = frozenset(
    {
        "phoenix_os/host_automation/__init__.py",
        "phoenix_os/host_automation/administration.py",
        "phoenix_os/host_automation/agent_control_tools.py",
        "phoenix_os/host_automation/agent_tools.py",
        "phoenix_os/host_automation/approval.py",
        "phoenix_os/host_automation/authorization.py",
        "phoenix_os/host_automation/contracts.py",
        "phoenix_os/host_automation/errors.py",
        "phoenix_os/host_automation/fake.py",
        "phoenix_os/host_automation/observer.py",
        "phoenix_os/host_automation/service.py",
        "phoenix_os/host_automation/windows.py",
        "phoenix_os/host_automation/windows_clipboard.py",
        "phoenix_os/host_automation/windows_effects.py",
    }
)

_REQUIRED_RELEASE_HARDENING_FILES = (
    "README.md",
    "docs/rfcs/RFC-0032-secure-host-automation-and-desktop-control.md",
    "docs/migrations/v0.31.0-to-v0.32.0-secure-host-automation.md",
    "docs/adrs/ADR-0060-host-state-is-data-effects-require-fresh-authority.md",
    "docs/adrs/ADR-0061-server-owned-configured-application-profiles.md",
    "docs/adrs/ADR-0062-opaque-phoenix-host-identities.md",
    "docs/adrs/ADR-0063-immediate-ui-toctou-revalidation.md",
    "scripts/dogfood_host_automation_windows.py",
    "src/phoenix_os/configuration/dependencies.py",
)


def _run(command: Sequence[str]) -> None:
    print("+ " + " ".join(command), flush=True)
    subprocess.run(tuple(command), cwd=_ROOT, check=True)


def _host_automation_test_files() -> tuple[str, ...]:
    discovered = tuple(
        path.relative_to(_ROOT).as_posix()
        for path in sorted((_ROOT / "tests").glob("test_host_automation*.py"))
    )
    missing = sorted(_REQUIRED_HOST_AUTOMATION_TESTS - frozenset(discovered))
    if missing:
        raise RuntimeError(
            "host-automation regression suite is missing required tests: " + ", ".join(missing)
        )

    for relative in _COMPANION_TESTS:
        if not (_ROOT / relative).is_file():
            raise RuntimeError(f"required host-automation companion test is missing: {relative}")
    return (*discovered, *_COMPANION_TESTS)


def _host_automation_source_files() -> tuple[str, ...]:
    source = _ROOT / "src" / "phoenix_os" / "host_automation"
    discovered = tuple(
        f"phoenix_os/host_automation/{path.name}" for path in sorted(source.glob("*.py"))
    )
    missing = sorted(_REQUIRED_HOST_AUTOMATION_MODULES - frozenset(discovered))
    if missing:
        raise RuntimeError(
            "host-automation package is missing required modules: " + ", ".join(missing)
        )
    return discovered


def _validate_release_hardening_files() -> None:
    for relative in _REQUIRED_RELEASE_HARDENING_FILES:
        if not (_ROOT / relative).is_file():
            raise RuntimeError(f"required host-automation release file is missing: {relative}")

    security_reviews = tuple(sorted((_ROOT / "docs" / "security").glob("RFC-0032-*.md")))
    if not security_reviews:
        raise RuntimeError("required RFC-0032 security review is missing")


def main() -> int:
    source_files = _host_automation_source_files()
    _validate_release_hardening_files()

    print(
        "Running RFC-0032 host-automation contracts, authorization, Windows adapter, "
        "agent-tool, lifecycle, migration, ADR, security-review, and named release suites.",
        flush=True,
    )
    print(f"Validated {len(source_files)} required host-automation source modules.", flush=True)
    _run((sys.executable, "-m", "pytest", "-q", *_host_automation_test_files()))

    print("RFC-0032 host-automation named release gate passed.", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
