"""RFC-0039 operator-facing task command surface.

This module owns only CLI admission and content-free projection. It deliberately
does not implement a second task runtime or durable state machine. Production
runtime composition is supplied through the reviewed bridge seam and must reuse
the existing integrated/durable services.
"""

from __future__ import annotations

import argparse
import getpass
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, BinaryIO, Protocol, TextIO, cast, runtime_checkable
from uuid import UUID

from phoenix_os.control_plane.operator_configuration import (
    OperatorConfiguration,
    OperatorConfigurationAbsentError,
    OperatorConfigurationError,
    OperatorProfileConfiguration,
    OperatorWorkspaceConfiguration,
    load_operator_configuration,
)
from phoenix_os.control_plane.task_resume_context_resupply import (
    MAX_TASK_RESUME_CONTEXT_DOCUMENT_BYTES,
    TaskResumeContextCodecError,
    TaskResumeContextResupply,
    decode_task_resume_context_resupply,
)
from phoenix_os.control_plane.task_runtime_bridge import TaskStatusSummary

MAX_TASK_INPUT_BYTES = 65_536
MAX_TASK_RUN_ID_LENGTH = 128

_REFERENCE_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,127})$")


class TaskCliError(ValueError):
    """Content-free RFC-0039 task CLI boundary error."""


class TaskRuntimeUnavailableError(TaskCliError):
    """The reviewed production task-runtime bridge is not composed yet."""


@dataclass(frozen=True, slots=True)
class TaskRunSummary:
    schema_version: int
    task_id: str
    run_id: str
    status: str


@runtime_checkable
class TaskRuntimeBridge(Protocol):
    """Reviewed bridge to the existing integrated/durable runtime services."""

    def run(
        self,
        *,
        configuration: OperatorConfiguration,
        profile: OperatorProfileConfiguration,
        workspace: OperatorWorkspaceConfiguration,
        task_text: str,
    ) -> TaskRunSummary: ...

    def status(
        self,
        *,
        configuration: OperatorConfiguration,
        run_id: str,
    ) -> TaskStatusSummary: ...

    def cancel(
        self,
        *,
        configuration: OperatorConfiguration,
        run_id: str,
    ) -> TaskRunSummary: ...

    def resume(
        self,
        *,
        configuration: OperatorConfiguration,
        run_id: str,
        context_resupply: TaskResumeContextResupply | None = None,
    ) -> TaskRunSummary: ...


class _UnavailableTaskRuntimeBridge:
    """Fail closed until the reviewed integrated-runtime composition is bound."""

    def run(
        self,
        *,
        configuration: OperatorConfiguration,
        profile: OperatorProfileConfiguration,
        workspace: OperatorWorkspaceConfiguration,
        task_text: str,
    ) -> TaskRunSummary:
        del configuration, profile, workspace, task_text
        raise TaskRuntimeUnavailableError()

    def status(
        self,
        *,
        configuration: OperatorConfiguration,
        run_id: str,
    ) -> TaskStatusSummary:
        del configuration, run_id
        raise TaskRuntimeUnavailableError()

    def cancel(
        self,
        *,
        configuration: OperatorConfiguration,
        run_id: str,
    ) -> TaskRunSummary:
        del configuration, run_id
        raise TaskRuntimeUnavailableError()

    def resume(
        self,
        *,
        configuration: OperatorConfiguration,
        run_id: str,
        context_resupply: TaskResumeContextResupply | None = None,
    ) -> TaskRunSummary:
        del configuration, run_id, context_resupply
        raise TaskRuntimeUnavailableError()


_TASK_RUNTIME_BRIDGE: TaskRuntimeBridge | None = None


def _task_runtime_bridge() -> TaskRuntimeBridge:
    global _TASK_RUNTIME_BRIDGE
    if _TASK_RUNTIME_BRIDGE is None:
        from phoenix_os.control_plane.task_runtime_bootstrap import (
            StandaloneTaskRuntimeBridge,
        )

        _TASK_RUNTIME_BRIDGE = cast(TaskRuntimeBridge, StandaloneTaskRuntimeBridge())
    return _TASK_RUNTIME_BRIDGE


def add_task_commands(commands: Any) -> None:
    task = commands.add_parser("task", help="run and inspect durable integrated tasks")
    task_commands = task.add_subparsers(dest="task_command", required=True)

    run = task_commands.add_parser("run", help="run one task from hidden/piped stdin")
    run.add_argument("--config", required=True, help="explicit TOML configuration path")
    run.add_argument("--profile", required=True, help="configured execution profile")
    run.add_argument("--workspace", required=True, help="configured workspace")

    status = task_commands.add_parser("status", help="show bounded content-free task status")
    status.add_argument("run_id")
    status.add_argument("--config", required=True, help="explicit TOML configuration path")

    cancel = task_commands.add_parser("cancel", help="cancel through durable control")
    cancel.add_argument("run_id")
    cancel.add_argument("--config", required=True, help="explicit TOML configuration path")

    resume = task_commands.add_parser("resume", help="resume through durable recovery")
    resume.add_argument("run_id")
    resume.add_argument("--config", required=True, help="explicit TOML configuration path")


def run_task_command(arguments: argparse.Namespace) -> int:
    try:
        configuration = load_operator_configuration(Path(arguments.config))

        if arguments.task_command == "run":
            profile_name = _trusted_reference(arguments.profile)
            workspace_name = _trusted_reference(arguments.workspace)
            profile = _profile(configuration, profile_name)
            workspace = configuration.workspace(workspace_name)
            if profile.workspace_name != workspace.workspace_name:
                raise TaskCliError()
            configuration.model(profile.model_name)
            task_text = _read_task_input()
            summary = _task_runtime_bridge().run(
                configuration=configuration,
                profile=profile,
                workspace=workspace,
                task_text=task_text,
            )
            _print_summary(summary)
            return 0

        run_id = _trusted_run_id(arguments.run_id)
        if arguments.task_command == "status":
            _print_summary(
                _task_runtime_bridge().status(
                    configuration=configuration,
                    run_id=run_id,
                )
            )
            return 0
        if arguments.task_command == "cancel":
            _print_summary(
                _task_runtime_bridge().cancel(
                    configuration=configuration,
                    run_id=run_id,
                )
            )
            return 0
        if arguments.task_command == "resume":
            bridge = _task_runtime_bridge()
            if getattr(bridge, "requires_resume_context_resupply", False):
                context_resupply = _read_resume_context_resupply()
                summary = bridge.resume(
                    configuration=configuration,
                    run_id=run_id,
                    context_resupply=context_resupply,
                )
            else:
                summary = bridge.resume(
                    configuration=configuration,
                    run_id=run_id,
                )
            _print_summary(summary)
            return 0

    except TaskRuntimeUnavailableError:
        print("phoenix: task runtime unavailable", file=sys.stderr)
        return 6
    except OperatorConfigurationAbsentError:
        print("phoenix: configuration absent", file=sys.stderr)
        return 3
    except OperatorConfigurationError:
        print("phoenix: configuration invalid", file=sys.stderr)
        return 3
    except (KeyError, TaskCliError, TaskResumeContextCodecError, UnicodeError):
        print("phoenix: task request invalid", file=sys.stderr)
        return 3
    except (EOFError, KeyboardInterrupt):
        print("phoenix: task input cancelled", file=sys.stderr)
        return 3

    raise RuntimeError("unreachable task command")


def _profile(
    configuration: OperatorConfiguration,
    profile_name: str,
) -> OperatorProfileConfiguration:
    for profile in configuration.profiles:
        if profile.profile_name == profile_name:
            return profile
    raise KeyError(profile_name)


def _trusted_reference(value: object) -> str:
    if not isinstance(value, str):
        raise TaskCliError()
    if value != value.strip() or _REFERENCE_PATTERN.fullmatch(value) is None:
        raise TaskCliError()
    return value


def _trusted_run_id(value: object) -> str:
    if not isinstance(value, str):
        raise TaskCliError()
    if value != value.strip() or not value or len(value) > MAX_TASK_RUN_ID_LENGTH:
        raise TaskCliError()
    try:
        canonical = str(UUID(value))
    except (ValueError, AttributeError):
        raise TaskCliError() from None
    if value != canonical:
        raise TaskCliError()
    return canonical


def _read_task_input() -> str:
    stream = sys.stdin
    if stream.isatty():
        text = getpass.getpass("Task: ")
        encoded = text.encode("utf-8")
        if len(encoded) > MAX_TASK_INPUT_BYTES:
            raise TaskCliError()
    else:
        text = _read_bounded_text(stream)

    if "\x00" in text or text.startswith("\ufeff") or not text.strip():
        raise TaskCliError()
    return text


def _read_bounded_text(stream: TextIO) -> str:
    binary = getattr(stream, "buffer", None)
    if binary is not None:
        payload = cast(BinaryIO, binary).read(MAX_TASK_INPUT_BYTES + 1)
        if len(payload) > MAX_TASK_INPUT_BYTES:
            raise TaskCliError()
        return payload.decode("utf-8", errors="strict")

    text = stream.read(MAX_TASK_INPUT_BYTES + 1)
    if len(text.encode("utf-8")) > MAX_TASK_INPUT_BYTES:
        raise TaskCliError()
    return text


def _read_resume_context_resupply() -> TaskResumeContextResupply:
    stream = sys.stdin
    if stream.isatty():
        raise TaskCliError()
    binary = getattr(stream, "buffer", None)
    if binary is not None:
        payload = cast(BinaryIO, binary).read(MAX_TASK_RESUME_CONTEXT_DOCUMENT_BYTES + 1)
    else:
        text = stream.read(MAX_TASK_RESUME_CONTEXT_DOCUMENT_BYTES + 1)
        payload = text.encode("utf-8")
    if len(payload) > MAX_TASK_RESUME_CONTEXT_DOCUMENT_BYTES:
        raise TaskCliError()
    return decode_task_resume_context_resupply(payload)


def _print_summary(summary: TaskRunSummary | TaskStatusSummary) -> None:
    print(
        json.dumps(
            asdict(summary),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
    )
