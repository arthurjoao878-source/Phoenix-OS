import runpy
from pathlib import Path
from typing import Any

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_GATE = _ROOT / "scripts" / "check_browser_automation_release.py"
_CI = _ROOT / ".github" / "workflows" / "ci.yml"
_CHECK_PS1 = _ROOT / "scripts" / "check.ps1"
_CHECK_SH = _ROOT / "scripts" / "check.sh"
_RFC = (
    _ROOT / "docs" / "rfcs" / "RFC-0035-secure-browser-automation-and-controlled-web-interaction.md"
)


def test_browser_release_gate_covers_normative_suite_and_exact_package_surface() -> None:
    text = _GATE.read_text(encoding="utf-8")
    for phrase in (
        'glob("test_browser_automation*.py")',
        '"tests/test_browser_automation_administration.py"',
        '"tests/test_browser_automation_observability_adversarial.py"',
        '"tests/test_browser_automation_release_gate.py"',
        '"tests/test_browser_automation_security_review.py"',
        '"tests/test_browser_automation_s6.py"',
        '"tests/test_rfc_0035.py"',
        '"tests/test_v035_release.py"',
        '"docs/releases/v0.35.0.md"',
        '"phoenix_os/browser_automation/administration.py"',
        '"phoenix_os/browser_automation/agent_tools.py"',
        '"phoenix_os/browser_automation/network.py"',
        '"phoenix_os/browser_automation/runtime.py"',
        '"phoenix_os/browser_automation/service.py"',
        '"phoenix_os/authority/catalog.py"',
        '"phoenix_os/runtime/__init__.py"',
        "unexpected browser-automation package files",
    ):
        assert phrase in text

    assert '"phoenix_os/runtime.py"' not in text


def test_browser_release_gate_builds_validates_and_rebuilds_packages() -> None:
    text = _GATE.read_text(encoding="utf-8")
    for phrase in (
        "import tarfile",
        "import zipfile",
        "_REQUIRED_SDIST_DOCUMENTS",
        "_validate_archive_names(",
        "_validate_exact_browser_package_files(",
        "_validate_wheel(",
        'tarfile.open(sdist, mode="r:gz")',
        '"--no-isolation"',
        "Rebuilding a wheel from the validated sdist.",
    ):
        assert phrase in text


def test_browser_release_gate_uses_offline_non_networking_contract_smoke() -> None:
    text = _GATE.read_text(encoding="utf-8")
    for phrase in (
        "import venv",
        '"--no-deps"',
        '"--no-index"',
        "PYTHONNOUSERSITE",
        'env.pop("PYTHONPATH", None)',
        "BrowserProfile",
        "BUILTIN_AUTHORITY_CATALOG",
        '"-I"',
    ):
        assert phrase in text
    for forbidden in (
        "socket.create_connection",
        "asyncio.open_connection",
        "urllib.request",
        "requests.",
        "httpx.",
        "playwright",
        "selenium",
    ):
        assert forbidden not in text


def test_browser_release_gate_is_after_network_gate_in_ci_local_checks_and_rfc() -> None:
    network = "python scripts/check_network_egress_release.py"
    browser = "python scripts/check_browser_automation_release.py"
    for path in (_CI, _CHECK_PS1, _CHECK_SH, _RFC):
        text = path.read_text(encoding="utf-8")
        assert browser in text
        if path is not _RFC:
            assert text.index(network) < text.index(browser)


def _gate_namespace() -> dict[str, Any]:
    return runpy.run_path(str(_GATE))


def test_browser_release_gate_rejects_unreviewed_browser_package_entries() -> None:
    namespace = _gate_namespace()
    validate = namespace["_validate_exact_browser_package_files"]
    required = namespace["_REQUIRED_BROWSER_MODULES"]
    names = tuple(
        sorted(
            {
                *required,
                "phoenix_os/browser_automation/unreviewed-native-extension.pyd",
            }
        )
    )
    with pytest.raises(RuntimeError, match="unexpected browser-automation package files"):
        validate(names, prefix="", label="test wheel")


def test_browser_release_gate_artifact_names_are_exact_and_s8_compatible(tmp_path: Path) -> None:
    namespace = _gate_namespace()
    release_artifact_names = namespace["_release_artifact_names"]
    exact_artifacts = namespace["_exact_artifacts"]

    for version in ("0.34.0", "0.35.0"):
        expected = (
            f"phoenix_os-{version}-py3-none-any.whl",
            f"phoenix_os-{version}.tar.gz",
        )
        assert release_artifact_names(version) == expected

    with pytest.raises(RuntimeError, match="unsupported browser release version"):
        release_artifact_names("0.35.0.dev1")

    expected = release_artifact_names("0.34.0")
    for name in expected:
        (tmp_path / name).write_bytes(b"release-test")
    artifacts = exact_artifacts(tmp_path, expected, label="test release build")
    assert tuple(path.name for path in artifacts) == expected
    (tmp_path / "unexpected-extra.whl").write_bytes(b"unexpected")
    with pytest.raises(RuntimeError, match="artifact set mismatch"):
        exact_artifacts(tmp_path, expected, label="test release build")


def test_browser_release_gate_main_uses_exact_artifact_names_without_wildcards() -> None:
    text = _GATE.read_text(encoding="utf-8")
    assert "wheel_name, sdist_name = _release_artifact_names(version)" in text
    assert 'label="release build"' in text
    assert 'label="rebuilt wheel"' in text
    assert '"*.whl"' not in text
    assert '"*.tar.gz"' not in text
    assert 'f"phoenix_os-{version}-py3-none-any.whl"' in text
