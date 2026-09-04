from __future__ import annotations

import io
import json
import os
from pathlib import Path

import pytest

from phoenix_os.control_plane import authority_cli as cli
from phoenix_os.control_plane import operator_cli, operator_configuration
from phoenix_os.control_plane.operator_configuration import (
    OperatorConfigurationError,
    load_operator_configuration,
)
from phoenix_os.inference.contracts import ModelId
from phoenix_os.inference.ollama import (
    OLLAMA_PROVIDER_ID,
    OllamaModelAvailability,
    OllamaModelDiagnostic,
    OllamaModelProvider,
)


def _configured_document(root: Path) -> str:
    return f"""\
schema_version = 1

[providers.ollama-local]
kind = "ollama-local"

[models.dev]
provider = "ollama-local"
provider_model_name = "qwen3:4b-instruct"

[workspaces.project]
kind = "development-checkout"
root = {json.dumps(root.as_posix())}
read_prefixes = ["src", "tests"]
patch_prefixes = ["src"]

[profiles.development]
model = "dev"
workspace = "project"
context_paths = ["src/example.py"]
allow_workspace_patch = true
"""


def test_config_init_is_explicit_non_overwriting_and_valid(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config = tmp_path / "phoenix.toml"

    assert cli.main(["config", "init", "--config", str(config)]) == 0
    assert config.exists()
    assert cli.main(["config", "validate", "--config", str(config)]) == 0

    second = cli.main(["config", "init", "--config", str(config)])
    captured = capsys.readouterr()
    assert second == 3
    assert "already exists" in captured.err


def test_operator_configuration_read_is_bounded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = tmp_path / "phoenix.toml"
    config.write_text("schema_version = 1\n", encoding="utf-8")
    selected = config.resolve(strict=True)
    payload = b"schema_version = 1\n"
    observed_sizes: list[int | None] = []

    class _TrackingReader(io.BytesIO):
        def read(self, size: int | None = -1) -> bytes:
            observed_sizes.append(size)
            return super().read(size)

    def tracked_open(
        self: Path,
        *args: object,
        **kwargs: object,
    ) -> _TrackingReader:
        del args, kwargs
        assert self == selected
        return _TrackingReader(payload)

    monkeypatch.setattr(Path, "open", tracked_open)

    compiled = load_operator_configuration(config)

    assert compiled.source == selected
    assert observed_sizes == [operator_configuration.MAX_OPERATOR_CONFIG_BYTES + 1]


def test_operator_configuration_rejects_oversized_document(tmp_path: Path) -> None:
    config = tmp_path / "phoenix.toml"
    config.write_bytes(b"#" * (operator_configuration.MAX_OPERATOR_CONFIG_BYTES + 1))

    with pytest.raises(OperatorConfigurationError):
        load_operator_configuration(config)


def test_operator_configuration_compiles_into_existing_inference_contracts(
    tmp_path: Path,
) -> None:
    root = tmp_path / "checkout"
    root.mkdir()
    config = tmp_path / "phoenix.toml"
    config.write_text(_configured_document(root), encoding="utf-8")

    compiled = load_operator_configuration(config)

    assert compiled.inference is not None
    assert compiled.inference.provider_ids == (OLLAMA_PROVIDER_ID,)
    assert compiled.models[0].descriptor.provider_model_name == "qwen3:4b-instruct"
    assert compiled.profiles[0].allow_workspace_patch is True
    assert compiled.profiles[0].context_paths == ("src/example.py",)


@pytest.mark.parametrize(
    "addition",
    [
        '\ncredential = "secret"\n',
        '\nendpoint = "http://127.0.0.1:9999/"\n',
    ],
)
def test_model_controlled_or_credential_like_provider_fields_are_rejected(
    tmp_path: Path,
    addition: str,
) -> None:
    config = tmp_path / "phoenix.toml"
    config.write_text(
        'schema_version = 1\n\n[providers.ollama-local]\nkind = "ollama-local"\n' + addition,
        encoding="utf-8",
    )

    with pytest.raises(OperatorConfigurationError):
        load_operator_configuration(config)


def test_duplicate_normalized_identifiers_fail_closed(tmp_path: Path) -> None:
    config = tmp_path / "phoenix.toml"
    config.write_text(
        """\
schema_version = 1

[providers.ollama-local]
kind = "ollama-local"

[models.Dev]
provider = "ollama-local"
provider_model_name = "qwen3:4b-instruct"

[models.dev]
provider = "ollama-local"
provider_model_name = "qwen3:4b-instruct"
""",
        encoding="utf-8",
    )

    with pytest.raises(OperatorConfigurationError):
        load_operator_configuration(config)


def test_profile_context_must_be_inside_workspace_read_prefixes(tmp_path: Path) -> None:
    root = tmp_path / "checkout"
    root.mkdir()
    config = tmp_path / "phoenix.toml"
    config.write_text(
        _configured_document(root).replace(
            'context_paths = ["src/example.py"]',
            'context_paths = ["private/example.py"]',
        ),
        encoding="utf-8",
    )

    with pytest.raises(OperatorConfigurationError):
        load_operator_configuration(config)


def test_config_show_is_normalized_and_does_not_gain_secret_fields(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    root = tmp_path / "checkout"
    root.mkdir()
    config = tmp_path / "phoenix.toml"
    config.write_text(_configured_document(root), encoding="utf-8")

    assert cli.main(["config", "show", "--config", str(config)]) == 0

    document = json.loads(capsys.readouterr().out)
    assert document["schema_version"] == 1
    assert document["providers"] == {"ollama-local": {"kind": "ollama-local"}}
    assert "credential" not in json.dumps(document).lower()


def test_doctor_reuses_reviewed_ollama_diagnostic_boundary(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "checkout"
    root.mkdir()
    config = tmp_path / "phoenix.toml"
    config.write_text(_configured_document(root), encoding="utf-8")

    calls: list[str] = []

    async def diagnose(self: object, model_id: ModelId) -> OllamaModelDiagnostic:
        del self
        calls.append(str(model_id))
        return OllamaModelDiagnostic(
            provider_id=OLLAMA_PROVIDER_ID,
            model_id=model_id,
            status=OllamaModelAvailability.AVAILABLE,
        )

    monkeypatch.setattr(OllamaModelProvider, "diagnose_model", diagnose)

    assert cli.main(["doctor", "--config", str(config)]) == 0

    document = json.loads(capsys.readouterr().out)
    assert calls == ["dev"]
    assert {
        "category": "provider",
        "id": "ollama-local",
        "status": "reachable",
    } in document["checks"]
    assert {"category": "model", "id": "dev", "status": "available"} in document["checks"]
    assert {
        "category": "workspace",
        "id": "project",
        "status": "ready",
    } in document["checks"]
    assert {
        "category": "profile",
        "id": "development",
        "status": "ready",
    } in document["checks"]


def test_doctor_absent_config_is_content_free_and_does_not_probe_provider(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    called = False

    async def diagnose(self: object, model_id: ModelId) -> OllamaModelDiagnostic:
        nonlocal called
        del self, model_id
        called = True
        raise AssertionError("provider diagnostic must not run")

    monkeypatch.setattr(OllamaModelProvider, "diagnose_model", diagnose)

    assert cli.main(["doctor", "--config", str(tmp_path / "missing.toml")]) == 5

    document = json.loads(capsys.readouterr().out)
    assert called is False
    assert document["checks"][1]["category"] == "configuration"
    assert document["checks"][1]["status"] == "absent"


def test_patch_prefixes_must_be_within_read_prefixes(tmp_path: Path) -> None:
    root = tmp_path / "checkout"
    root.mkdir()
    config = tmp_path / "phoenix.toml"
    config.write_text(
        _configured_document(root).replace(
            'patch_prefixes = ["src"]',
            'patch_prefixes = ["private"]',
        ),
        encoding="utf-8",
    )

    with pytest.raises(OperatorConfigurationError):
        load_operator_configuration(config)


def test_config_show_reports_effective_explicit_source(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config = tmp_path / "phoenix.toml"
    config.write_text("schema_version = 1\n", encoding="utf-8")

    assert cli.main(["config", "show", "--config", str(config)]) == 0

    document = json.loads(capsys.readouterr().out)
    assert document["source"] == {
        "kind": "explicit",
        "path": str(config.resolve(strict=True)),
    }


def test_doctor_marks_filesystem_root_unsafe(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config = tmp_path / "phoenix.toml"
    filesystem_root = Path(tmp_path.anchor)
    config.write_text(
        "schema_version = 1\n\n"
        "[workspaces.root]\n"
        'kind = "development-checkout"\n'
        f"root = {json.dumps(filesystem_root.as_posix())}\n"
        "read_prefixes = []\n"
        "patch_prefixes = []\n",
        encoding="utf-8",
    )

    assert cli.main(["doctor", "--config", str(config)]) == 5

    document = json.loads(capsys.readouterr().out)
    workspace = next(check for check in document["checks"] if check["category"] == "workspace")
    assert workspace["status"] == "unsafe"
    assert workspace["operator_action"] == "select_non_root_checkout_directory"


def test_doctor_reparse_detection_fails_closed(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "checkout"
    root.mkdir()
    config = tmp_path / "phoenix.toml"
    config.write_text(
        "schema_version = 1\n\n"
        "[workspaces.project]\n"
        'kind = "development-checkout"\n'
        f"root = {json.dumps(root.as_posix())}\n"
        "read_prefixes = []\n"
        "patch_prefixes = []\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(operator_cli, "_is_reparse_point", lambda information: True)

    assert cli.main(["doctor", "--config", str(config)]) == 5

    document = json.loads(capsys.readouterr().out)
    workspace = next(check for check in document["checks"] if check["category"] == "workspace")
    assert workspace["status"] == "unsafe"


def test_doctor_malformed_provider_diagnostic_is_content_free(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from phoenix_os.inference.errors import InferenceMalformedOutputError

    root = tmp_path / "checkout"
    root.mkdir()
    config = tmp_path / "phoenix.toml"
    config.write_text(_configured_document(root), encoding="utf-8")

    async def diagnose(self: object, model_id: ModelId) -> OllamaModelDiagnostic:
        del self, model_id
        raise InferenceMalformedOutputError()

    monkeypatch.setattr(OllamaModelProvider, "diagnose_model", diagnose)

    assert cli.main(["doctor", "--config", str(config)]) == 5

    captured = capsys.readouterr()
    assert captured.err == ""
    document = json.loads(captured.out)
    provider = next(check for check in document["checks"] if check["category"] == "provider")
    model = next(check for check in document["checks"] if check["category"] == "model")
    assert provider["status"] == "invalid"
    assert model["status"] == "unknown"
    assert "traceback" not in captured.out.lower()
    assert "model provider output is invalid" not in captured.out.lower()


def test_foreign_platform_root_is_rejected(tmp_path: Path) -> None:
    foreign_root = "C:/foreign/project" if os.name != "nt" else "/foreign/project"
    config = tmp_path / "phoenix.toml"
    config.write_text(
        "schema_version = 1\n\n"
        "[workspaces.project]\n"
        'kind = "development-checkout"\n'
        f"root = {json.dumps(foreign_root)}\n"
        "read_prefixes = []\n"
        "patch_prefixes = []\n",
        encoding="utf-8",
    )

    with pytest.raises(OperatorConfigurationError):
        load_operator_configuration(config)


def test_workspace_root_is_normalized_before_registration(tmp_path: Path) -> None:
    root = tmp_path / "checkout"
    root.mkdir()
    raw_root = str(root.parent / "checkout" / ".." / "checkout")
    config = tmp_path / "phoenix.toml"
    config.write_text(
        "schema_version = 1\n\n"
        "[workspaces.project]\n"
        'kind = "development-checkout"\n'
        f"root = {json.dumps(raw_root)}\n"
        "read_prefixes = []\n"
        "patch_prefixes = []\n",
        encoding="utf-8",
    )

    compiled = load_operator_configuration(config)

    assert compiled.workspaces[0].root == os.path.abspath(raw_root)


def test_config_source_resolution_failure_is_content_free(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = tmp_path / "phoenix.toml"
    config.write_text("schema_version = 1\n", encoding="utf-8")
    original_resolve = Path.resolve

    def fail_selected(self: Path, strict: bool = False) -> Path:
        if self == config:
            raise RuntimeError("secret path-resolution detail")
        return original_resolve(self, strict=strict)

    monkeypatch.setattr(Path, "resolve", fail_selected)

    assert cli.main(["config", "validate", "--config", str(config)]) == 3

    captured = capsys.readouterr()
    assert captured.out == ""
    assert "configuration invalid" in captured.err
    assert "secret path-resolution detail" not in captured.err


def test_doctor_unexpected_provider_failure_is_content_free(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "checkout"
    root.mkdir()
    config = tmp_path / "phoenix.toml"
    config.write_text(_configured_document(root), encoding="utf-8")

    async def diagnose(self: object, model_id: ModelId) -> OllamaModelDiagnostic:
        del self, model_id
        raise RuntimeError("secret provider diagnostic detail")

    monkeypatch.setattr(OllamaModelProvider, "diagnose_model", diagnose)

    assert cli.main(["doctor", "--config", str(config)]) == 5

    captured = capsys.readouterr()
    assert captured.err == ""
    document = json.loads(captured.out)
    provider = next(check for check in document["checks"] if check["category"] == "provider")
    model = next(check for check in document["checks"] if check["category"] == "model")
    assert provider["status"] == "invalid"
    assert model["status"] == "unknown"
    assert "secret provider diagnostic detail" not in captured.out


def test_doctor_rejects_noncanonical_resolved_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "checkout"
    resolved_other = tmp_path / "resolved-other"
    root.mkdir()
    resolved_other.mkdir()
    original_resolve = Path.resolve

    def resolve_selected(self: Path, strict: bool = False) -> Path:
        if self == root:
            return resolved_other
        return original_resolve(self, strict=strict)

    monkeypatch.setattr(Path, "resolve", resolve_selected)

    assert operator_cli._diagnose_checkout_root(root) == (
        "unsafe",
        "select_canonical_checkout_root",
    )


def test_existing_authority_parser_path_remains_available() -> None:
    parser = cli._parser()

    authority = parser.parse_args(
        [
            "authority",
            "--server",
            "http://127.0.0.1:8080",
            "inspect",
            "agent-42",
        ]
    )
    config = parser.parse_args(["config", "validate", "--config", "phoenix.toml"])
    doctor = parser.parse_args(["doctor", "--config", "phoenix.toml"])

    assert authority.command == "authority"
    assert authority.authority_command == "inspect"
    assert config.command == "config"
    assert doctor.command == "doctor"
