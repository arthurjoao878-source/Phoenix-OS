from __future__ import annotations

import io
import json
import sys
from pathlib import Path
from typing import Any

import pytest

from phoenix_os.control_plane import authority_cli as cli
from phoenix_os.control_plane import task_cli
from phoenix_os.control_plane.task_cli import TaskRunSummary
from phoenix_os.control_plane.task_runtime_bridge import TaskStatusSummary

_RUN_ID = "00000000-0000-4000-8000-000000000001"


def _configured_document(root: Path) -> str:
    return f"""
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
patch_prefixes = []

[profiles.development]
model = "dev"
workspace = "project"
context_paths = ["src/example.py"]
allow_workspace_patch = false
"""


class _FakeBridge:
    def __init__(self) -> None:
        self.task_text: str | None = None
        self.run_id: str | None = None

    def run(
        self,
        *,
        configuration: Any,
        profile: Any,
        workspace: Any,
        task_text: str,
    ) -> TaskRunSummary:
        assert configuration.source.is_absolute()
        assert profile.profile_name == "development"
        assert workspace.workspace_name == "project"
        self.task_text = task_text
        return TaskRunSummary(1, "task-1", _RUN_ID, "completed")

    def status(
        self,
        *,
        configuration: Any,
        run_id: str,
    ) -> TaskStatusSummary:
        assert configuration.source.is_absolute()
        self.run_id = run_id
        return TaskStatusSummary(
            schema_version=1,
            task_id="task-1",
            run_id=run_id,
            profile_name="development",
            provider_id="ollama-local",
            model_id="dev",
            run_state="completed",
            current_step_category=None,
            model_turns_used=1,
            model_turns_max=4,
            tool_calls_used=0,
            tool_calls_max=2,
            accepted_tool_proposals=0,
            rejected_tool_proposals=0,
            deadline_state="remaining",
            cancellation_state="not_cancelled",
            provider_failure_category=None,
            durable_recovery_disposition=None,
            terminal_category="completed",
        )

    def cancel(
        self,
        *,
        configuration: Any,
        run_id: str,
    ) -> TaskRunSummary:
        assert configuration.source.is_absolute()
        self.run_id = run_id
        return TaskRunSummary(1, "task-1", run_id, "cancelled")

    def resume(
        self,
        *,
        configuration: Any,
        run_id: str,
    ) -> TaskRunSummary:
        assert configuration.source.is_absolute()
        self.run_id = run_id
        return TaskRunSummary(1, "task-1", run_id, "completed")


def _write_config(tmp_path: Path) -> Path:
    root = tmp_path / "checkout"
    root.mkdir()
    (root / "src").mkdir()
    config = tmp_path / "phoenix.toml"
    config.write_text(_configured_document(root), encoding="utf-8")
    return config


def _stdin(payload: bytes) -> io.TextIOWrapper:
    return io.TextIOWrapper(io.BytesIO(payload), encoding="utf-8")


def test_task_run_accepts_only_hidden_or_piped_stdin_not_prompt_argv(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _write_config(tmp_path)
    bridge = _FakeBridge()
    monkeypatch.setattr(task_cli, "_task_runtime_bridge", lambda: bridge)
    monkeypatch.setattr(sys, "stdin", _stdin(b"inspect the configured project\n"))

    assert (
        cli.main(
            [
                "task",
                "run",
                "--config",
                str(config),
                "--profile",
                "development",
                "--workspace",
                "project",
            ]
        )
        == 0
    )

    captured = capsys.readouterr()
    document = json.loads(captured.out)
    assert bridge.task_text == "inspect the configured project\n"
    assert document == {
        "run_id": _RUN_ID,
        "schema_version": 1,
        "status": "completed",
        "task_id": "task-1",
    }
    assert "inspect the configured project" not in captured.out
    assert "inspect the configured project" not in captured.err


def test_task_run_rejects_raw_task_text_in_argv_without_echo(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config = _write_config(tmp_path)
    secret_prompt = "do-not-echo-this-task-text"

    with pytest.raises(SystemExit) as exit_info:
        cli.main(
            [
                "task",
                "run",
                "--config",
                str(config),
                "--profile",
                "development",
                "--workspace",
                "project",
                secret_prompt,
            ]
        )

    assert exit_info.value.code == 2

    captured = capsys.readouterr()
    assert secret_prompt not in captured.out
    assert secret_prompt not in captured.err


def test_task_run_bounds_stdin_before_runtime_bridge(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _write_config(tmp_path)
    bridge = _FakeBridge()
    monkeypatch.setattr(task_cli, "_task_runtime_bridge", lambda: bridge)
    monkeypatch.setattr(
        sys,
        "stdin",
        _stdin(b"x" * (task_cli.MAX_TASK_INPUT_BYTES + 1)),
    )

    assert (
        cli.main(
            [
                "task",
                "run",
                "--config",
                str(config),
                "--profile",
                "development",
                "--workspace",
                "project",
            ]
        )
        == 3
    )

    captured = capsys.readouterr()
    assert bridge.task_text is None
    assert captured.err == "phoenix: task request invalid\n"


def test_task_run_requires_profile_workspace_binding(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _write_config(tmp_path)
    document = config.read_text(encoding="utf-8")
    document += f"""
[workspaces.other]
kind = "development-checkout"
root = {json.dumps((tmp_path / "checkout").as_posix())}
read_prefixes = []
patch_prefixes = []
"""
    config.write_text(document, encoding="utf-8")
    bridge = _FakeBridge()
    monkeypatch.setattr(task_cli, "_task_runtime_bridge", lambda: bridge)
    monkeypatch.setattr(sys, "stdin", _stdin(b"task\n"))

    assert (
        cli.main(
            [
                "task",
                "run",
                "--config",
                str(config),
                "--profile",
                "development",
                "--workspace",
                "other",
            ]
        )
        == 3
    )
    assert bridge.task_text is None
    assert capsys.readouterr().err == "phoenix: task request invalid\n"


def test_task_status_is_content_free_projection(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _write_config(tmp_path)
    bridge = _FakeBridge()
    monkeypatch.setattr(task_cli, "_task_runtime_bridge", lambda: bridge)

    assert cli.main(["task", "status", _RUN_ID, "--config", str(config)]) == 0

    captured = capsys.readouterr()
    document = json.loads(captured.out)
    assert bridge.run_id == _RUN_ID
    assert document["run_id"] == _RUN_ID
    assert document["model_turns_used"] == 1
    assert document["model_turns_max"] == 4
    assert document["tool_calls_used"] == 0
    assert document["tool_calls_max"] == 2
    forbidden = ("prompt", "response", "tool_arguments", "tool_results", "workspace_bytes")
    assert all(name not in captured.out.lower() for name in forbidden)


def test_task_cancel_uses_bridge_and_preserves_run_identity(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _write_config(tmp_path)
    bridge = _FakeBridge()
    monkeypatch.setattr(task_cli, "_task_runtime_bridge", lambda: bridge)

    assert cli.main(["task", "cancel", _RUN_ID, "--config", str(config)]) == 0

    document = json.loads(capsys.readouterr().out)
    assert bridge.run_id == _RUN_ID
    assert document["run_id"] == _RUN_ID
    assert document["status"] == "cancelled"


def test_task_control_rejects_noncanonical_durable_run_id_before_bridge(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _write_config(tmp_path)
    bridge = _FakeBridge()
    monkeypatch.setattr(task_cli, "_task_runtime_bridge", lambda: bridge)

    assert cli.main(["task", "status", "run-1", "--config", str(config)]) == 3

    assert bridge.run_id is None
    assert capsys.readouterr().err == "phoenix: task request invalid\n"


def test_task_resume_uses_bridge_and_preserves_run_identity(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _write_config(tmp_path)
    bridge = _FakeBridge()
    monkeypatch.setattr(task_cli, "_task_runtime_bridge", lambda: bridge)

    assert cli.main(["task", "resume", _RUN_ID, "--config", str(config)]) == 0

    document = json.loads(capsys.readouterr().out)
    assert bridge.run_id == _RUN_ID
    assert document["run_id"] == _RUN_ID


def test_unbound_task_runtime_fails_closed_without_task_content(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _write_config(tmp_path)
    monkeypatch.setattr(
        task_cli,
        "_task_runtime_bridge",
        lambda: task_cli._UnavailableTaskRuntimeBridge(),
    )
    monkeypatch.setattr(sys, "stdin", _stdin(b"sensitive task text\n"))

    assert (
        cli.main(
            [
                "task",
                "run",
                "--config",
                str(config),
                "--profile",
                "development",
                "--workspace",
                "project",
            ]
        )
        == 6
    )

    captured = capsys.readouterr()
    assert captured.err == "phoenix: task runtime unavailable\n"
    assert "sensitive task text" not in captured.out
    assert "sensitive task text" not in captured.err
