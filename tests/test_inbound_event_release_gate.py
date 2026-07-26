from __future__ import annotations

import ast
import tomllib
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_GATE = _ROOT / "scripts" / "check_inbound_release.py"
_RFC = (
    _ROOT / "docs" / "rfcs" / "RFC-0025-secure-inbound-event-gateway-and-external-event-sources.md"
)
_README = _ROOT / "README.md"
_CI = _ROOT / ".github" / "workflows" / "ci.yml"
_CHECK_PS1 = _ROOT / "scripts" / "check.ps1"
_CHECK_SH = _ROOT / "scripts" / "check.sh"
_PYPROJECT = _ROOT / "pyproject.toml"

_REQUIRED_SECURITY_SUITES = (
    "tests/test_inbound_event_contracts.py",
    "tests/test_inbound_event_codec.py",
    "tests/test_inbound_event_memory.py",
    "tests/test_inbound_event_state.py",
    "tests/test_inbound_event_authentication.py",
    "tests/test_inbound_event_replay_idempotency.py",
    "tests/test_inbound_event_gateway.py",
    "tests/test_inbound_event_limits.py",
    "tests/test_inbound_event_http.py",
    "tests/test_inbound_event_secure_transport.py",
    "tests/test_inbound_event_publisher.py",
    "tests/test_inbound_event_recovery.py",
    "tests/test_inbound_event_manager.py",
    "tests/test_control_plane_inbound_management_http.py",
    "tests/test_control_plane_service_account_inbound_http.py",
    "tests/test_inbound_event_runtime_integration.py",
)

_REQUIRED_DOCUMENTS = (
    "docs/rfcs/RFC-0025-secure-inbound-event-gateway-and-external-event-sources.md",
    "docs/migrations/v0.24.0-to-v0.25.0-inbound-events.md",
    "docs/adrs/ADR-0006-reviewed-inbound-schemas-and-normalization.md",
    "docs/adrs/ADR-0007-per-source-authentication-replay-and-idempotency.md",
    "docs/adrs/ADR-0008-shared-control-plane-listener-and-exact-inbound-routes.md",
    "docs/adrs/ADR-0009-durable-acceptance-and-at-least-once-publication.md",
    "docs/adrs/ADR-0010-opt-in-inbound-runtime-and-separated-administration.md",
)


def _gate() -> str:
    return _GATE.read_text(encoding="utf-8")


def test_inbound_release_gate_script_is_valid_python() -> None:
    ast.parse(_gate())


def test_inbound_release_gate_covers_required_security_suites() -> None:
    gate = _gate()
    for relative in _REQUIRED_SECURITY_SUITES:
        assert (_ROOT / relative).is_file()
        assert relative in gate


def test_inbound_release_gate_requires_package_contract_documents() -> None:
    gate = _gate()
    for relative in _REQUIRED_DOCUMENTS:
        assert (_ROOT / relative).is_file()
        assert relative in gate


def test_inbound_release_gate_validates_all_inbound_modules_and_integrations() -> None:
    gate = _gate()
    required = (
        '"phoenix_os/inbound_events/{path.name}"',
        "phoenix_os/configuration/dependencies.py",
        "phoenix_os/control_plane/inbound_machine_http.py",
        "phoenix_os/control_plane/inbound_management_http.py",
        "phoenix_os/control_plane/runtime.py",
        "phoenix_os/control_plane/secure_http.py",
        "phoenix_os/control_plane/dashboard/app.js",
    )
    for phrase in required:
        assert phrase in gate


def test_inbound_release_gate_builds_and_validates_wheel_and_sdist() -> None:
    gate = _gate()
    required = (
        '"build"',
        '"--no-isolation"',
        '"*.whl"',
        '"*.tar.gz"',
        "zipfile.ZipFile",
        'tarfile.open(sdist, mode="r:gz")',
        "Rebuilding a wheel from the validated sdist",
        "_validate_filename_version",
    )
    for phrase in required:
        assert phrase in gate


def test_inbound_release_gate_uses_offline_isolated_smoke_installs() -> None:
    gate = _gate()
    required = (
        "venv.EnvBuilder(with_pip=True, clear=True)",
        '"--no-deps"',
        '"--no-index"',
        '"-I"',
        'env["PYTHONNOUSERSITE"] = "1"',
        'env.pop("PYTHONPATH", None)',
        "Path(sys.prefix).resolve()",
    )
    for phrase in required:
        assert phrase in gate


def test_inbound_release_gate_smokes_public_and_control_plane_surfaces() -> None:
    gate = _gate()
    required = (
        "InboundEventSchema",
        "InboundServiceAccountPolicy",
        "InboundPublicationRetryPolicy",
        "InboundAdmissionLimitPolicy",
        "canonical_inbound_json_bytes",
        "ControlPlaneInboundManagementHttpAdapter",
        "CONTROL_PLANE_INBOUND_MACHINE_RESOURCE",
        "inbound_event.submit",
    )
    for phrase in required:
        assert phrase in gate


def test_inbound_release_gate_rejects_unsafe_archive_content() -> None:
    gate = _gate()
    required = (
        '".env"',
        '".git"',
        '"__pycache__"',
        '".key"',
        '".pem"',
        '".pfx"',
        'path.is_absolute() or ".." in path.parts',
        "member.issym() or member.islnk()",
    )
    for phrase in required:
        assert phrase in gate


def test_inbound_release_gate_is_wired_into_every_quality_entrypoint() -> None:
    command = "python scripts/check_inbound_release.py"
    assert _CI.read_text(encoding="utf-8").count(command) == 1
    assert _CHECK_PS1.read_text(encoding="utf-8").count(command) == 1
    assert _CHECK_SH.read_text(encoding="utf-8").count(command) == 1


def test_inbound_release_build_dependencies_are_declared() -> None:
    document = tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))
    dependencies = document["project"]["optional-dependencies"]["dev"]

    assert any(item.startswith("build>=") for item in dependencies)
    assert any(item.startswith("hatchling>=") for item in dependencies)


def test_readme_documents_the_named_inbound_release_gate() -> None:
    readme = _README.read_text(encoding="utf-8")
    assert "## Inbound event release gate" in readme
    assert "python scripts/check_inbound_release.py" in readme
    assert "isolated offline environments" in readme


def test_rfc_marks_inbound_security_and_packaging_gate_complete() -> None:
    rfc = _RFC.read_text(encoding="utf-8")
    assert "- [x] Regression, authentication, replay, admission, and packaging gate" in rfc
    assert "`scripts/check_inbound_release.py`" in rfc
    assert "wheel and sdist" in rfc
    assert "isolated offline environments" in rfc
    assert "source-tree imports" in rfc
