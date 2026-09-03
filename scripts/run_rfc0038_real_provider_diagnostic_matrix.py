"""RFC-0038 S5c3d real Ollama model disappearance and revision-drift canary.

Operational, explicit, content-free, and non-CI. This script performs only
GET /api/tags diagnostics against the already-running reviewed loopback Ollama
provider. It never calls /api/chat, removes models, pulls weights, or changes
the Ollama process.
"""

from __future__ import annotations

import asyncio
import hashlib
import importlib.util
import json
import os
import subprocess
from dataclasses import replace
from pathlib import Path
from types import ModuleType

from phoenix_os.inference import InferenceRequest, InferenceResponse, ModelId
from phoenix_os.inference.ollama import (
    OllamaModelAvailability,
    OllamaModelBinding,
    OllamaModelProvider,
)

ROOT = Path(__file__).resolve().parents[1]
BASE_CANARY = ROOT / "scripts" / "run_rfc0038_real_provider_canary.py"
EXPECTED_BASE_CANARY_SHA256 = "75047f6bae0c5feec3ab471d993d1700a5906fa03d56d4fc2c79e7d3ed25b8f6"
EXPECTED_BRANCH = "feat/rfc-0038-slice-5-durable-real-provider-dogfood"
EXPECTED_HEAD = "5beab1d70b4d0154cf3ead307c6e79a07e366d62"

MISSING_MODEL_ID = ModelId("rfc0038-missing-model")
MISSING_PROVIDER_MODEL_NAME = "phoenix-rfc0038-missing-model:latest"
IMPOSSIBLE_EXPECTED_DIGEST = "0" * 64


class _DiagnosticOnlyOllamaProvider(OllamaModelProvider):
    """Count accidental inference; diagnostics remain the real provider path."""

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]
        self.infer_calls = 0
        self.stream_calls = 0

    async def infer(self, request: InferenceRequest) -> InferenceResponse:
        self.infer_calls += 1
        return await super().infer(request)

    def stream(self, request: InferenceRequest):  # type: ignore[no-untyped-def]
        self.stream_calls += 1
        return super().stream(request)


def _environment_truthy(name: str) -> bool:
    value = os.environ.get(name)
    if value is None:
        return False
    return value.strip().lower() not in {"", "0", "false", "no", "off"}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _safe_git(*args: str) -> str | None:
    result = subprocess.run(
        ["git", *args],
        cwd=ROOT,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if result.returncode != 0:
        return None
    return result.stdout.strip()


def _json_evidence(values: dict[str, object]) -> None:
    print(json.dumps(values, sort_keys=True, separators=(",", ":")))


def _require_repository_identity() -> tuple[str, str]:
    branch = _safe_git("branch", "--show-current")
    commit = _safe_git("rev-parse", "HEAD")
    if branch != EXPECTED_BRANCH or commit != EXPECTED_HEAD:
        raise RuntimeError("repository_identity_changed")
    return branch, commit


def _load_base_canary() -> ModuleType:
    if not BASE_CANARY.is_file():
        raise RuntimeError("base_canary_missing")
    if _sha256(BASE_CANARY) != EXPECTED_BASE_CANARY_SHA256:
        raise RuntimeError("base_canary_changed")
    spec = importlib.util.spec_from_file_location(
        "_rfc0038_s5c3b_real_provider_canary",
        BASE_CANARY,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("base_canary_import_unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


async def _run() -> int:
    if _environment_truthy("CI"):
        _json_evidence(
            {
                "schema_version": 1,
                "kind": "rfc0038_real_provider_diagnostic_matrix",
                "status": "refused_ci",
            }
        )
        return 3

    branch, commit = _require_repository_identity()
    module = _load_base_canary()
    provider_configuration = module._provider_configuration()
    real_descriptor = module._model_descriptor()

    available_provider = _DiagnosticOnlyOllamaProvider(
        provider_configuration,
        (OllamaModelBinding(real_descriptor),),
    )
    available = await available_provider.diagnose_model(real_descriptor.model_id)

    missing_descriptor = replace(
        real_descriptor,
        model_id=MISSING_MODEL_ID,
        provider_model_name=MISSING_PROVIDER_MODEL_NAME,
    )
    missing_provider = _DiagnosticOnlyOllamaProvider(
        provider_configuration,
        (OllamaModelBinding(missing_descriptor),),
    )
    missing = await missing_provider.diagnose_model(MISSING_MODEL_ID)

    drift_provider = _DiagnosticOnlyOllamaProvider(
        provider_configuration,
        (
            OllamaModelBinding(
                real_descriptor,
                expected_digest=IMPOSSIBLE_EXPECTED_DIGEST,
            ),
        ),
    )
    drift = await drift_provider.diagnose_model(real_descriptor.model_id)

    infer_calls = (
        available_provider.infer_calls + missing_provider.infer_calls + drift_provider.infer_calls
    )
    stream_calls = (
        available_provider.stream_calls
        + missing_provider.stream_calls
        + drift_provider.stream_calls
    )

    passed = (
        available.status is OllamaModelAvailability.AVAILABLE
        and missing.status is OllamaModelAvailability.UNAVAILABLE
        and drift.status is OllamaModelAvailability.REVISION_MISMATCH
        and infer_calls == 0
        and stream_calls == 0
    )

    _json_evidence(
        {
            "schema_version": 1,
            "kind": "rfc0038_real_provider_diagnostic_matrix",
            "branch": branch,
            "commit": commit,
            "provider_id": str(available.provider_id),
            "available_model_id": str(available.model_id),
            "available_status": available.status.value,
            "missing_model_id": str(missing.model_id),
            "missing_status": missing.status.value,
            "revision_model_id": str(drift.model_id),
            "revision_status": drift.status.value,
            "infer_calls": infer_calls,
            "stream_calls": stream_calls,
            "provider_process_mutated": False,
            "model_inventory_mutated": False,
            "content_free_evidence": True,
            "status": "passed" if passed else "contract_failed",
        }
    )
    return 0 if passed else 6


def main() -> int:
    try:
        return asyncio.run(_run())
    except KeyboardInterrupt:
        return 130
    except BaseException as exception:
        _json_evidence(
            {
                "schema_version": 1,
                "kind": "rfc0038_real_provider_diagnostic_matrix",
                "exception_category": type(exception).__name__,
                "status": "execution_exception",
            }
        )
        return 7


if __name__ == "__main__":
    raise SystemExit(main())
