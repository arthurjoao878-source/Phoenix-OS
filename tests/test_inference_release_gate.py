from __future__ import annotations

import ast
import tomllib
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_GATE = _ROOT / "scripts" / "check_inference_release.py"
_RFC = _ROOT / "docs" / "rfcs" / "RFC-0026-secure-model-providers-and-inference-runtime.md"
_README = _ROOT / "README.md"
_CI = _ROOT / ".github" / "workflows" / "ci.yml"
_CHECK_PS1 = _ROOT / "scripts" / "check.ps1"
_CHECK_SH = _ROOT / "scripts" / "check.sh"
_PYPROJECT = _ROOT / "pyproject.toml"

_REQUIRED_SECURITY_SUITES = (
    "tests/test_inference_contracts.py",
    "tests/test_inference_codec.py",
    "tests/test_inference_fake_provider.py",
    "tests/test_inference_registry.py",
    "tests/test_inference_authorization.py",
    "tests/test_inference_credentials.py",
    "tests/test_inference_endpoints.py",
    "tests/test_inference_admission.py",
    "tests/test_inference_execution.py",
    "tests/test_inference_streaming.py",
    "tests/test_inference_configuration.py",
    "tests/test_inference_service.py",
    "tests/test_inference_runtime_integration.py",
    "tests/test_inference_administration.py",
    "tests/test_control_plane_inference_http.py",
    "tests/test_control_plane_inference_dashboard.py",
    "tests/test_control_plane_inference_machine_http.py",
    "tests/test_inference_migration_guidance.py",
    "tests/test_inference_adrs.py",
    "tests/test_rfc_0026.py",
    "tests/test_v026_release.py",
)

_REQUIRED_DOCUMENTS = (
    "docs/releases/v0.26.0.md",
    "docs/rfcs/RFC-0026-secure-model-providers-and-inference-runtime.md",
    "docs/migrations/v0.25.0-to-v0.26.0-inference.md",
    "docs/adrs/ADR-0011-provider-neutral-contracts-and-reviewed-inference-registry.md",
    "docs/adrs/ADR-0012-exact-inference-authorization-and-untrusted-model-output.md",
    "docs/adrs/ADR-0013-exact-credential-leases-and-fail-closed-provider-endpoints.md",
    "docs/adrs/ADR-0014-bounded-streaming-cancellation-and-no-transparent-retry.md",
    "docs/adrs/ADR-0015-opt-in-inference-runtime-and-separated-administration.md",
)


def _gate() -> str:
    return _GATE.read_text(encoding="utf-8")


def test_inference_release_gate_script_is_valid_python() -> None:
    ast.parse(_gate())


def test_inference_release_gate_covers_required_security_suites() -> None:
    gate = _gate()
    for relative in _REQUIRED_SECURITY_SUITES:
        assert (_ROOT / relative).is_file()
        assert relative in gate


def test_inference_release_gate_requires_package_contract_documents() -> None:
    gate = _gate()
    for relative in _REQUIRED_DOCUMENTS:
        assert (_ROOT / relative).is_file()
        assert relative in gate


def test_inference_release_gate_validates_all_modules_and_integrations() -> None:
    gate = _gate()
    required = (
        '"phoenix_os/inference/{path.name}"',
        "phoenix_os/configuration/dependencies.py",
        "phoenix_os/control_plane/inference_http.py",
        "phoenix_os/control_plane/inference_machine_http.py",
        "phoenix_os/control_plane/runtime.py",
        "phoenix_os/control_plane/secure_http.py",
        "phoenix_os/control_plane/dashboard/app.js",
    )
    for phrase in required:
        assert phrase in gate


def test_inference_release_gate_builds_and_validates_wheel_and_sdist() -> None:
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


def test_inference_release_gate_uses_offline_isolated_smoke_installs() -> None:
    gate = _gate()
    required = (
        "venv.EnvBuilder",
        "with_pip=True",
        '"--no-deps"',
        '"--no-index"',
        '"-I"',
        'env["PYTHONNOUSERSITE"] = "1"',
        'env.pop("PYTHONPATH", None)',
        "Path(sys.prefix).resolve()",
    )
    for phrase in required:
        assert phrase in gate


def test_inference_release_gate_smokes_public_execution_surfaces() -> None:
    gate = _gate()
    required = (
        "DeterministicModelProvider",
        "InferenceRequest",
        "InferenceServiceConfiguration",
        "InferenceExecutionLimits",
        "InferenceAdmissionLimits",
        "model.infer",
        "model-provider:release-fake/model:chat",
        "await provider.infer(request)",
        "async for chunk in provider.stream(request)",
        "sum(chunk.terminal for chunk in chunks) == 1",
    )
    for phrase in required:
        assert phrase in gate


def test_inference_release_gate_smokes_security_and_admin_surfaces() -> None:
    gate = _gate()
    required = (
        "ModelEndpointPolicy",
        "ModelCredentialPolicy",
        "SecretRef",
        "secured_provider = InferenceProviderConfiguration(",
        "not in repr(secured_provider)",
        "INFERENCE_CONTROL_PLANE_BASE_PATH",
        "ControlPlaneInferenceHttpAdapter",
        "CONTROL_PLANE_INFERENCE_MACHINE_BASE_PATH",
        "CONTROL_PLANE_INFERENCE_MACHINE_RESOURCE",
        "inference-machine",
    )
    for phrase in required:
        assert phrase in gate


def test_inference_release_gate_rejects_unsafe_archive_content() -> None:
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


def test_inference_release_gate_is_wired_into_every_quality_entrypoint() -> None:
    command = "python scripts/check_inference_release.py"
    assert _CI.read_text(encoding="utf-8").count(command) == 1
    assert _CHECK_PS1.read_text(encoding="utf-8").count(command) == 1
    assert _CHECK_SH.read_text(encoding="utf-8").count(command) == 1


def test_inference_release_build_dependencies_are_declared() -> None:
    document = tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))
    dependencies = document["project"]["optional-dependencies"]["dev"]

    assert any(item.startswith("build>=") for item in dependencies)
    assert any(item.startswith("hatchling>=") for item in dependencies)


def test_readme_documents_the_named_inference_release_gate() -> None:
    readme = _README.read_text(encoding="utf-8")
    assert "## Inference release gate" in readme
    assert "python scripts/check_inference_release.py" in readme
    assert "isolated offline environments" in readme
    assert "complete and streaming" in readme


def test_rfc_marks_inference_security_and_packaging_gate_complete() -> None:
    rfc = _RFC.read_text(encoding="utf-8")
    assert "- [x] Security, limits, streaming, and packaging release gate" in rfc
    assert "`scripts/check_inference_release.py`" in rfc
    assert "wheel and sdist" in rfc
    assert "isolated offline environments" in rfc
    assert "source-tree imports" in rfc


def test_inference_release_gate_includes_v026_release_metadata() -> None:
    gate = _gate()
    for phrase in (
        '"tests/test_v026_release.py"',
        '"CHANGELOG.md"',
        '"docs/releases/v0.26.0.md"',
    ):
        assert phrase in gate
