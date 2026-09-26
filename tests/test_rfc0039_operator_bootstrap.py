from __future__ import annotations

import asyncio
import getpass
import json
from pathlib import Path

import pytest

from phoenix_os.agent.authorization import AGENT_RUN_ACTION, TOOL_INVOKE_ACTION
from phoenix_os.agent.durable_authorization import AGENT_CANCEL_ACTION
from phoenix_os.agent.workspace_authorization import (
    WORKSPACE_LIST_ACTION,
    WORKSPACE_PATCH_ACTION,
    WORKSPACE_READ_ACTION,
)
from phoenix_os.control_plane import authority_cli as cli
from phoenix_os.control_plane import operator_bootstrap
from phoenix_os.control_plane.operator_contracts import (
    ControlPlaneOperatorRole,
    ControlPlaneOperatorToken,
)
from phoenix_os.control_plane.operator_state import StateControlPlaneOperatorRegistry
from phoenix_os.inference.authorization import INFERENCE_MODEL_ACTION
from phoenix_os.state.sqlite import SQLiteStateStore

_TOKEN = "dogfood-local-maintainer-credential-0123456789abcdef"


def _configured_document(root: Path, state: Path, *, patch: bool = True) -> str:
    allow_patch = "true" if patch else "false"
    patch_prefixes = '["src"]' if patch else "[]"
    return f"""schema_version = 1

[runtime]
durable_state_path = {json.dumps(state.as_posix())}

[providers.ollama-local]
kind = "ollama-local"

[models.dev]
provider = "ollama-local"
provider_model_name = "qwen3:4b-instruct"

[workspaces.project]
kind = "development-checkout"
root = {json.dumps(root.as_posix())}
read_prefixes = ["src", "tests"]
patch_prefixes = {patch_prefixes}

[profiles.development]
model = "dev"
workspace = "project"
context_paths = ["src/example.py"]
allow_workspace_patch = {allow_patch}
"""


def _write_config(tmp_path: Path, *, patch: bool = True) -> tuple[Path, Path]:
    root = tmp_path / "checkout"
    (root / "src").mkdir(parents=True)
    (root / "tests").mkdir()
    (root / "src" / "example.py").write_text("value = 1\n", encoding="utf-8")

    state = tmp_path / "state" / "agent-durable.sqlite3"
    state.parent.mkdir()
    config = tmp_path / "phoenix.toml"
    config.write_text(
        _configured_document(root, state, patch=patch),
        encoding="utf-8",
    )
    return config, state


def test_parser_exposes_explicit_operator_bootstrap_surface() -> None:
    parser = cli._parser()
    arguments = parser.parse_args(["operator", "bootstrap", "--config", "C:/Phoenix/phoenix.toml"])

    assert arguments.command == "operator"
    assert arguments.operator_command == "bootstrap"
    assert arguments.config == "C:/Phoenix/phoenix.toml"


def test_bootstrap_creates_one_maintainer_with_exact_task_permissions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config, state = _write_config(tmp_path)
    prompts = iter((_TOKEN, _TOKEN))
    monkeypatch.setattr(
        getpass,
        "getpass",
        lambda _prompt: next(prompts),
    )

    assert operator_bootstrap.run_operator_bootstrap(config) == 0

    captured = capsys.readouterr()
    assert _TOKEN not in captured.out
    assert _TOKEN not in captured.err
    document = json.loads(captured.out)

    expected = frozenset(
        {
            AGENT_RUN_ACTION,
            AGENT_CANCEL_ACTION,
            INFERENCE_MODEL_ACTION,
            TOOL_INVOKE_ACTION,
            WORKSPACE_LIST_ACTION,
            WORKSPACE_READ_ACTION,
            WORKSPACE_PATCH_ACTION,
        }
    )

    assert document["operator"] == "created"
    assert document["username"] == "local-maintainer"
    assert document["role"] == "maintainer"
    assert frozenset(document["task_permissions"]) == expected

    async def inspect() -> None:
        store = SQLiteStateStore(state)
        registry = StateControlPlaneOperatorRegistry(store)
        try:
            record = await registry.get_by_username("local-maintainer")
            assert record is not None
            assert record.role is ControlPlaneOperatorRole.MAINTAINER
            assert record.token_digest == ControlPlaneOperatorToken(_TOKEN).digest
            assert record.additional_permissions == expected
            assert (await registry.snapshot()).operators == 1
        finally:
            await store.close()

    asyncio.run(inspect())
    assert _TOKEN.encode("ascii") not in state.read_bytes()


def test_bootstrap_without_patch_profile_omits_patch_permission(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config, _state = _write_config(tmp_path, patch=False)
    prompts = iter((_TOKEN, _TOKEN))
    monkeypatch.setattr(
        getpass,
        "getpass",
        lambda _prompt: next(prompts),
    )

    assert operator_bootstrap.run_operator_bootstrap(config) == 0

    document = json.loads(capsys.readouterr().out)
    assert WORKSPACE_PATCH_ACTION not in document["task_permissions"]


def test_bootstrap_rejects_mismatched_secret_without_echo(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config, state = _write_config(tmp_path)
    values = iter(
        (
            _TOKEN,
            "different-local-maintainer-token-0123456789abcdef",
        )
    )
    monkeypatch.setattr(
        getpass,
        "getpass",
        lambda _prompt: next(values),
    )

    assert operator_bootstrap.run_operator_bootstrap(config) == 3

    captured = capsys.readouterr()
    assert "operator credential invalid" in captured.err
    assert _TOKEN not in captured.out + captured.err

    async def count() -> int:
        store = SQLiteStateStore(state)
        registry = StateControlPlaneOperatorRegistry(store)
        try:
            return (await registry.snapshot()).operators
        finally:
            await store.close()

    assert asyncio.run(count()) == 0


def test_bootstrap_is_one_shot_and_second_call_does_not_prompt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config, _state = _write_config(tmp_path)
    prompts = iter((_TOKEN, _TOKEN))
    monkeypatch.setattr(
        getpass,
        "getpass",
        lambda _prompt: next(prompts),
    )
    assert operator_bootstrap.run_operator_bootstrap(config) == 0
    capsys.readouterr()

    def unexpected_prompt(_prompt: str) -> str:
        raise AssertionError("initialized registry must fail before prompting")

    monkeypatch.setattr(
        getpass,
        "getpass",
        unexpected_prompt,
    )
    assert operator_bootstrap.run_operator_bootstrap(config) == 4
    assert "operator registry already initialized" in capsys.readouterr().err


def test_bootstrap_requires_explicit_durable_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config = tmp_path / "phoenix.toml"
    config.write_text("schema_version = 1\n", encoding="utf-8")

    def unexpected_prompt(_prompt: str) -> str:
        raise AssertionError("invalid config must fail before prompting")

    monkeypatch.setattr(
        getpass,
        "getpass",
        unexpected_prompt,
    )

    assert operator_bootstrap.run_operator_bootstrap(config) == 3
    assert "durable state configuration required" in capsys.readouterr().err
