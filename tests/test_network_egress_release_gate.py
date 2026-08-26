import re
import runpy
from pathlib import Path
from typing import Any

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_GATE = _ROOT / "scripts" / "check_network_egress_release.py"
_CI = _ROOT / ".github" / "workflows" / "ci.yml"
_CHECK_PS1 = _ROOT / "scripts" / "check.ps1"
_CHECK_SH = _ROOT / "scripts" / "check.sh"
_README = _ROOT / "README.md"
_RFC = _ROOT / "docs" / "rfcs" / "RFC-0034-secure-network-egress-and-controlled-http-operations.md"


def test_network_release_gate_covers_normative_suite_and_exact_package_surface() -> None:
    text = _GATE.read_text(encoding="utf-8")
    for phrase in (
        'glob("test_network_egress*.py")',
        '"tests/test_network_egress_admission.py"',
        '"tests/test_network_egress_authorization.py"',
        '"tests/test_network_egress_freshness.py"',
        '"tests/test_network_egress_ssrf_adversarial.py"',
        '"tests/test_network_egress_observability_adversarial.py"',
        '"tests/test_network_egress_release_gate.py"',
        '"tests/test_network_egress_security_review.py"',
        '"tests/test_rfc_0034.py"',
        '"tests/test_v034_release.py"',
        '"phoenix_os/network_egress/_admission.py"',
        '"phoenix_os/network_egress/_transport.py"',
        '"phoenix_os/network_egress/authorization.py"',
        '"phoenix_os/network_egress/service.py"',
        '"phoenix_os/agent/tools.py"',
        '"phoenix_os/authority/catalog.py"',
        "unexpected network-egress package files",
    ):
        assert phrase in text


def test_network_release_gate_builds_validates_and_rebuilds_packages() -> None:
    text = _GATE.read_text(encoding="utf-8")
    for phrase in (
        "import tarfile",
        "import zipfile",
        "_REQUIRED_SDIST_DOCUMENTS",
        "_validate_archive_names(",
        "_validate_exact_network_package_files(",
        "_validate_wheel(",
        'tarfile.open(sdist, mode="r:gz")',
        '"build"',
        '"--no-isolation"',
        "Rebuilding a wheel from the validated sdist.",
    ):
        assert phrase in text


def test_network_release_gate_uses_offline_isolated_non_networking_smoke() -> None:
    text = _GATE.read_text(encoding="utf-8")
    for phrase in (
        "import venv",
        '"--no-deps"',
        '"--no-index"',
        "PYTHONNOUSERSITE",
        'env.pop("PYTHONPATH", None)',
        "NetworkHttpRequest",
        "BUILTIN_AUTHORITY_CATALOG",
        '"-I"',
    ):
        assert phrase in text
    assert re.search(
        r'\(\s*"tool\.invoke"\s*,\s*NETWORK_HTTP_REQUEST_ACTION\s*,?\s*\)'
        r"\s+in\s+BUILTIN_AUTHORITY_CATALOG\.mediated_transitions",
        text,
    )
    for forbidden in (
        "socket.create_connection",
        "asyncio.open_connection",
        "urllib.request",
        "requests.",
        "httpx.",
    ):
        assert forbidden not in text


def test_network_release_gate_is_after_authority_gate_in_ci_local_checks_and_docs() -> None:
    authority = "python scripts/check_authority_release.py"
    command = "python scripts/check_network_egress_release.py"
    for path in (_CI, _CHECK_PS1, _CHECK_SH, _README, _RFC):
        assert command in path.read_text(encoding="utf-8")
    for path in (_CI, _CHECK_PS1, _CHECK_SH):
        text = path.read_text(encoding="utf-8")
        assert text.index(authority) < text.index(command)


def _gate_namespace() -> dict[str, Any]:
    return runpy.run_path(str(_GATE))


def test_network_release_gate_rejects_non_python_network_package_entries() -> None:
    namespace = _gate_namespace()
    validate = namespace["_validate_exact_network_package_files"]
    required = namespace["_REQUIRED_NETWORK_MODULES"]
    names = tuple(
        sorted(
            {
                *required,
                "phoenix_os/network_egress/unreviewed-native-extension.pyd",
            }
        )
    )

    with pytest.raises(RuntimeError, match="unexpected network-egress package files"):
        validate(names, prefix="", label="test wheel")


def test_network_release_gate_artifact_names_are_exact_and_s8_compatible(tmp_path: Path) -> None:
    namespace = _gate_namespace()
    release_artifact_names = namespace["_release_artifact_names"]
    exact_artifacts = namespace["_exact_artifacts"]

    for version in ("0.34.0", "0.35.0"):
        expected = (
            f"phoenix_os-{version}-py3-none-any.whl",
            f"phoenix_os-{version}.tar.gz",
        )
        assert release_artifact_names(version) == expected

    for unsupported in ("0.35.0.dev1", "0.35.1", "0.36.0", "1.0.0"):
        with pytest.raises(RuntimeError, match="unsupported network-egress release version"):
            release_artifact_names(unsupported)

    expected = release_artifact_names("0.35.0")
    for name in expected:
        (tmp_path / name).write_bytes(b"release-test")

    artifacts = exact_artifacts(tmp_path, expected, label="test release build")
    assert tuple(path.name for path in artifacts) == expected

    (tmp_path / "unexpected-extra.whl").write_bytes(b"unexpected")
    with pytest.raises(RuntimeError, match="artifact set mismatch"):
        exact_artifacts(tmp_path, expected, label="test release build")


def test_network_release_gate_main_uses_exact_artifact_names_without_wildcards() -> None:
    text = _GATE.read_text(encoding="utf-8")
    for phrase in (
        '_SUPPORTED_RELEASE_VERSIONS = frozenset({"0.34.0", "0.35.0"})',
        'f"phoenix_os-{version}-py3-none-any.whl"',
        'f"phoenix_os-{version}.tar.gz"',
        "wheel_name, sdist_name = _release_artifact_names(version)",
        'label="release build"',
        'label="rebuilt wheel"',
    ):
        assert phrase in text

    assert '"*.whl"' not in text
    assert '"*.tar.gz"' not in text
