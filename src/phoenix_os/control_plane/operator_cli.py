"""RFC-0039 operator-facing config and doctor commands."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any, TypedDict

from phoenix_os.control_plane.operator_configuration import (
    OperatorConfiguration,
    OperatorConfigurationAbsentError,
    OperatorConfigurationError,
    initialize_operator_configuration,
    load_operator_configuration,
    project_operator_configuration,
)
from phoenix_os.inference.ollama import (
    OllamaModelAvailability,
    OllamaModelDiagnostic,
    OllamaModelDiagnosticCause,
    OllamaModelProvider,
)

_DOCTOR_FAILURE_STATUSES = frozenset(
    {
        "absent",
        "invalid",
        "unavailable",
        "unsafe",
        "unreachable",
        "timeout",
        "revision_mismatch",
        "unknown",
    }
)


class _DoctorDocument(TypedDict):
    schema_version: int
    checks: list[dict[str, str]]


def add_operator_commands(commands: Any) -> None:
    config = commands.add_parser("config", help="manage explicit operator configuration")
    config_commands = config.add_subparsers(dest="config_command", required=True)
    for name, help_text in (
        ("init", "create a minimal configuration scaffold"),
        ("validate", "validate and compile operator configuration"),
        ("show", "show the normalized redacted configuration"),
    ):
        command = config_commands.add_parser(name, help=help_text)
        command.add_argument("--config", required=True, help="explicit TOML configuration path")

    doctor = commands.add_parser("doctor", help="run bounded read-only diagnostics")
    doctor.add_argument("--config", required=True, help="explicit TOML configuration path")


def run_operator_command(arguments: argparse.Namespace) -> int:
    if arguments.command == "config":
        return _run_config(arguments)
    if arguments.command == "doctor":
        return _run_doctor(Path(arguments.config))
    raise RuntimeError("unreachable operator CLI command")


def _run_config(arguments: argparse.Namespace) -> int:
    path = Path(arguments.config)
    try:
        if arguments.config_command == "init":
            initialize_operator_configuration(path)
            print(json.dumps({"configuration": "created"}, sort_keys=True))
            return 0
        configuration = load_operator_configuration(path)
        if arguments.config_command == "validate":
            print(json.dumps({"configuration": "ready"}, sort_keys=True))
            return 0
        if arguments.config_command == "show":
            print(
                json.dumps(
                    project_operator_configuration(configuration),
                    ensure_ascii=False,
                    indent=2,
                    sort_keys=True,
                )
            )
            return 0
    except FileExistsError:
        print("phoenix: configuration destination already exists", file=sys.stderr)
        return 3
    except OperatorConfigurationAbsentError:
        print("phoenix: configuration absent", file=sys.stderr)
        return 3
    except OperatorConfigurationError:
        print("phoenix: configuration invalid", file=sys.stderr)
        return 3
    raise RuntimeError("unreachable config command")


def _run_doctor(path: Path) -> int:
    document = doctor_document(path)
    print(json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True))
    return (
        5 if any(check["status"] in _DOCTOR_FAILURE_STATUSES for check in document["checks"]) else 0
    )


def doctor_document(path: Path) -> _DoctorDocument:
    """Build a bounded, content-free, read-only diagnostic projection."""

    checks: list[dict[str, str]] = [{"category": "package", "status": "ready"}]
    try:
        configuration = load_operator_configuration(path)
    except OperatorConfigurationAbsentError:
        checks.append(
            {
                "category": "configuration",
                "status": "absent",
                "operator_action": "create_or_select_config",
            }
        )
        checks.extend(_inactive_boundary_checks())
        return {"schema_version": 1, "checks": checks}
    except OperatorConfigurationError:
        checks.append(
            {
                "category": "configuration",
                "status": "invalid",
                "operator_action": "correct_selected_config",
            }
        )
        checks.extend(_inactive_boundary_checks())
        return {"schema_version": 1, "checks": checks}

    checks.append({"category": "configuration", "status": "ready"})
    checks.extend(_workspace_checks(configuration))
    checks.extend(
        {"category": "profile", "id": profile.profile_name, "status": "ready"}
        for profile in configuration.profiles
    )
    if configuration.inference is not None:
        checks.extend(asyncio.run(_ollama_checks(configuration)))
    checks.extend(_inactive_boundary_checks())
    return {"schema_version": 1, "checks": checks}


async def _ollama_checks(configuration: OperatorConfiguration) -> list[dict[str, str]]:
    inference = configuration.inference
    if inference is None:
        return []

    provider_configuration = inference.providers[0]
    try:
        provider = OllamaModelProvider(
            provider_configuration,
            tuple(model.binding for model in configuration.models),
        )
    except Exception:
        return _invalid_provider_checks(configuration)

    diagnostics: list[OllamaModelDiagnostic | None] = []
    diagnostic_failed = False
    for model in configuration.models:
        try:
            diagnostics.append(await provider.diagnose_model(model.descriptor.model_id))
        except Exception:
            diagnostics.append(None)
            diagnostic_failed = True

    provider_status = "invalid" if diagnostic_failed else "reachable"
    provider_action: str | None = (
        "inspect_configured_provider_and_retry" if diagnostic_failed else None
    )
    for diagnostic in diagnostics:
        if diagnostic is not None and (
            diagnostic.status is OllamaModelAvailability.PROVIDER_UNREACHABLE
        ):
            if diagnostic.cause is OllamaModelDiagnosticCause.PROVIDER_TIMEOUT:
                provider_status = "timeout"
            else:
                provider_status = "unreachable"
            provider_action = "make_configured_provider_reachable"
            break

    checks: list[dict[str, str]] = [
        {
            "category": "provider",
            "id": str(provider.provider_id),
            "status": provider_status,
            **({"operator_action": provider_action} if provider_action is not None else {}),
        }
    ]
    for model, diagnostic in zip(configuration.models, diagnostics, strict=True):
        if diagnostic is None:
            status = "unknown"
            action = "inspect_configured_provider_and_retry"
        elif diagnostic.status is OllamaModelAvailability.AVAILABLE:
            status = "available"
            action = None
        elif diagnostic.status is OllamaModelAvailability.UNAVAILABLE:
            status = "unavailable"
            action = "install_or_select_configured_model"
        elif diagnostic.status is OllamaModelAvailability.REVISION_MISMATCH:
            status = "revision_mismatch"
            action = "select_expected_model_revision"
        else:
            status = "unknown"
            action = "restore_configured_provider_then_retry"
        checks.append(
            {
                "category": "model",
                "id": model.model_name,
                "status": status,
                **({"operator_action": action} if action is not None else {}),
            }
        )
    return checks


def _invalid_provider_checks(
    configuration: OperatorConfiguration,
) -> list[dict[str, str]]:
    return [
        {
            "category": "provider",
            "id": "ollama-local",
            "status": "invalid",
            "operator_action": "inspect_configured_provider_and_retry",
        },
        *(
            {
                "category": "model",
                "id": model.model_name,
                "status": "unknown",
                "operator_action": "inspect_configured_provider_and_retry",
            }
            for model in configuration.models
        ),
    ]


def _workspace_checks(configuration: OperatorConfiguration) -> list[dict[str, str]]:
    checks: list[dict[str, str]] = []
    for workspace in configuration.workspaces:
        status, action = _diagnose_checkout_root(Path(workspace.root))
        checks.append(
            {
                "category": "workspace",
                "id": workspace.workspace_name,
                "status": status,
                **({"operator_action": action} if action is not None else {}),
            }
        )
    return checks


def _diagnose_checkout_root(path: Path) -> tuple[str, str | None]:
    try:
        information = path.lstat()
    except FileNotFoundError:
        return "unavailable", "make_configured_checkout_available"
    except OSError:
        return "unavailable", "make_configured_checkout_available"

    if path.is_symlink() or _is_reparse_point(information):
        return "unsafe", "select_non_reparse_checkout_root"
    if not stat.S_ISDIR(information.st_mode):
        return "invalid", "select_directory_checkout_root"

    try:
        resolved = path.resolve(strict=True)
        resolved_information = resolved.lstat()
    except (FileNotFoundError, OSError, RuntimeError):
        return "unavailable", "make_configured_checkout_available"

    if resolved.is_symlink() or _is_reparse_point(resolved_information):
        return "unsafe", "select_non_reparse_checkout_root"
    if not stat.S_ISDIR(resolved_information.st_mode):
        return "invalid", "select_directory_checkout_root"
    if resolved.parent == resolved:
        return "unsafe", "select_non_root_checkout_directory"

    configured_key = os.path.normcase(os.path.normpath(str(path)))
    resolved_key = os.path.normcase(os.path.normpath(str(resolved)))
    if configured_key != resolved_key:
        return "unsafe", "select_canonical_checkout_root"

    return "ready", None


def _is_reparse_point(information: object) -> bool:
    attributes = getattr(information, "st_file_attributes", 0)
    flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(flag and attributes & flag)


def _inactive_boundary_checks() -> list[dict[str, str]]:
    return [
        {"category": "memory", "status": "disabled"},
        {"category": "network", "status": "disabled"},
        {"category": "browser", "status": "unconfigured"},
        {"category": "host", "status": "unconfigured"},
    ]
