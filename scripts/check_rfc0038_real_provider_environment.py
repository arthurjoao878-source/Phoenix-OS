"""Explicit non-CI environment readiness probe for RFC-0038 real-provider dogfood."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
from collections.abc import Sequence

_OLLAMA_HOST = "127.0.0.1"
_OLLAMA_PORT = 11_434


def _environment_truthy(name: str) -> bool:
    value = os.environ.get(name)
    if value is None:
        return False
    return value.strip().lower() not in {"", "0", "false", "no", "off"}


def _loopback_reachable(timeout_seconds: float) -> bool:
    try:
        with socket.create_connection(
            (_OLLAMA_HOST, _OLLAMA_PORT),
            timeout=timeout_seconds,
        ):
            return True
    except OSError:
        return False


def _emit(payload: dict[str, object]) -> None:
    print(json.dumps(payload, sort_keys=True, separators=(",", ":")))


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Check whether the explicit RFC-0038 Ollama loopback environment is "
            "ready for a separately invoked real-provider canary."
        )
    )
    parser.add_argument(
        "--timeout-seconds",
        type=float,
        default=1.0,
        help="bounded TCP connect timeout for 127.0.0.1:11434",
    )
    arguments = parser.parse_args(argv)

    if arguments.timeout_seconds <= 0 or arguments.timeout_seconds > 5:
        parser.error("--timeout-seconds must be > 0 and <= 5")

    if _environment_truthy("CI"):
        _emit(
            {
                "schema_version": 1,
                "kind": "rfc0038_real_provider_environment",
                "provider_id": "ollama-local",
                "status": "refused_ci",
            }
        )
        return 3

    command_present = shutil.which("ollama") is not None
    provider_reachable = _loopback_reachable(arguments.timeout_seconds)
    status = "ready_for_provider_diagnostic" if provider_reachable else "provider_unreachable"

    _emit(
        {
            "schema_version": 1,
            "kind": "rfc0038_real_provider_environment",
            "provider_id": "ollama-local",
            "endpoint_mode": "loopback_http",
            "endpoint_host": _OLLAMA_HOST,
            "endpoint_port": _OLLAMA_PORT,
            "ollama_command_present": command_present,
            "provider_reachable": provider_reachable,
            "status": status,
        }
    )
    return 0 if provider_reachable else 2


if __name__ == "__main__":
    raise SystemExit(main())
