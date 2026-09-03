"""Explicit RFC-0038 S5c3c real cancellation + process-restart dogfood.

This is an operational, non-CI canary. It deliberately uses the real reviewed
Ollama path in ``prepare-cancel`` and a separate process with no provider in
``recover``. Evidence is content-free. The script never installs, starts,
stops, pulls, retries, or deletes Ollama or model weights.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import importlib.util
import json
import os
import re
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType
from uuid import UUID, uuid4

from phoenix_os.agent.contracts import AgentRunStatus
from phoenix_os.agent.durable_compatibility import (
    DurableCompatibilityPolicy,
    StaticDurableCompatibilityValidator,
)
from phoenix_os.agent.durable_contracts import (
    CheckpointNextOperation,
    DurableAgentRunId,
    DurableRunStatus,
    ExecutionAttemptStatus,
    RecoveryDisposition,
    RecoveryPoint,
)
from phoenix_os.agent.durable_runtime import create_durable_agent_runtime_stack
from phoenix_os.agent.durable_sqlite import SQLiteDurableRunStore
from phoenix_os.agent.state import AgentCancellationToken
from phoenix_os.inference import InferenceRequest, InferenceResponse
from phoenix_os.inference.ollama import OllamaModelAvailability, OllamaModelProvider
from phoenix_os.runtime import RuntimeContext

ROOT = Path(__file__).resolve().parents[1]
CANARY_PATH = ROOT / "scripts" / "run_rfc0038_real_provider_canary.py"
EXPECTED_CANARY_SHA256 = "15db737fdce329238ed66b35681ee6cb805f0eb72f51b3a4be0d57fd0f9d7537"
EXPECTED_BRANCH = "feat/rfc-0038-slice-5-durable-real-provider-dogfood"
EXPECTED_HEAD = "5beab1d70b4d0154cf3ead307c6e79a07e366d62"

EVIDENCE_DIR = ROOT.parent / ".rfc0038-dogfood"
_SESSION_PATTERN = re.compile(r"^[0-9a-f]{32}$")
CANCEL_TASK = (
    "Return a final result whose content is exactly 512 lowercase letter a "
    "characters. Do not request a tool."
)
CANCEL_AFTER_PROVIDER_ENTRY_SECONDS = 0.20
START_OBSERVATION_TIMEOUT_SECONDS = 15.0


class _ObservedOllamaModelProvider(OllamaModelProvider):
    """Real Ollama provider with content-free call-entry observation only."""

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]
        self.infer_calls = 0
        self.infer_entered = asyncio.Event()

    async def infer(self, request: InferenceRequest) -> InferenceResponse:
        self.infer_calls += 1
        self.infer_entered.set()
        return await super().infer(request)


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


def _load_canary_module() -> ModuleType:
    if not CANARY_PATH.is_file():
        raise RuntimeError("base_canary_missing")
    if _sha256(CANARY_PATH) != EXPECTED_CANARY_SHA256:
        raise RuntimeError("base_canary_changed")
    spec = importlib.util.spec_from_file_location(
        "_rfc0038_s5c3b_real_provider_canary",
        CANARY_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("base_canary_import_unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _session_paths(session: str) -> tuple[Path, Path]:
    if _SESSION_PATTERN.fullmatch(session) is None:
        raise ValueError("session must be 32 lowercase hexadecimal characters")
    return (
        EVIDENCE_DIR / f"s5c3c-{session}.sqlite3",
        EVIDENCE_DIR / f"s5c3c-{session}.json",
    )


def _state_document(
    *,
    session: str,
    durable_run_id: DurableAgentRunId,
    checkpoint_digest: str,
    checkpoint_sequence: int,
    budget_deadline: datetime,
    state_capture_pid: int,
    state_origin: str,
    branch: str,
    commit: str,
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "kind": "rfc0038_real_provider_cancel_restart_state",
        "session": session,
        "durable_run_id": str(durable_run_id),
        "checkpoint_digest": checkpoint_digest,
        "checkpoint_sequence": checkpoint_sequence,
        "budget_deadline": budget_deadline.isoformat(),
        "state_capture_pid": state_capture_pid,
        "state_origin": state_origin,
        "branch": branch,
        "commit": commit,
    }


def _read_state(session: str) -> dict[str, object]:
    database_path, state_path = _session_paths(session)
    if not database_path.is_file() or not state_path.is_file():
        raise RuntimeError("session_artifacts_missing")
    try:
        decoded = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exception:
        raise RuntimeError("session_state_invalid") from exception
    if not isinstance(decoded, dict):
        raise RuntimeError("session_state_invalid")
    expected_fields = {
        "schema_version",
        "kind",
        "session",
        "durable_run_id",
        "checkpoint_digest",
        "checkpoint_sequence",
        "budget_deadline",
        "state_capture_pid",
        "state_origin",
        "branch",
        "commit",
    }
    if set(decoded) != expected_fields:
        raise RuntimeError("session_state_invalid")
    if (
        decoded.get("schema_version") != 1
        or decoded.get("kind") != "rfc0038_real_provider_cancel_restart_state"
        or decoded.get("session") != session
        or decoded.get("state_origin") not in {"prepare_cancel", "salvaged_prior_prepare_cancel"}
        or decoded.get("branch") != EXPECTED_BRANCH
        or decoded.get("commit") != EXPECTED_HEAD
    ):
        raise RuntimeError("session_state_invalid")
    return decoded


async def _wait_for_started_attempt(
    store: SQLiteDurableRunStore,
    run_id: DurableAgentRunId,
    run_task: asyncio.Task[object],
    provider: _ObservedOllamaModelProvider,
) -> bool:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + START_OBSERVATION_TIMEOUT_SECONDS
    while loop.time() < deadline:
        if run_task.done():
            return False
        current = await store.get_current(run_id)
        attempt = None if current is None else current.metadata.active_attempt
        if (
            attempt is not None
            and attempt.status is ExecutionAttemptStatus.STARTED
            and provider.infer_entered.is_set()
        ):
            return True
        await asyncio.sleep(0.01)
    return False


async def _prepare_cancel() -> int:
    if _environment_truthy("CI"):
        _json_evidence(
            {
                "schema_version": 1,
                "kind": "rfc0038_real_provider_cancel_restart_prepare",
                "status": "refused_ci",
            }
        )
        return 3

    branch, commit = _require_repository_identity()
    module = _load_canary_module()
    module.CANARY_USER_TEXT = CANCEL_TASK
    module.OllamaModelProvider = _ObservedOllamaModelProvider

    now = datetime.now(UTC)
    agent_run_id = module.AgentRunId(uuid4())
    durable_run_id = DurableAgentRunId(uuid4())
    configuration = module._configuration()
    request = module._request(configuration, now=now, agent_run_id=agent_run_id)

    inference_service, provider, _ = module._inference_service()
    if not isinstance(provider, _ObservedOllamaModelProvider):
        raise RuntimeError("provider_observer_not_installed")
    diagnostic = await provider.diagnose_model(module.MODEL_ID)
    if diagnostic.status is not OllamaModelAvailability.AVAILABLE:
        _json_evidence(
            {
                "schema_version": 1,
                "kind": "rfc0038_real_provider_cancel_restart_prepare",
                "diagnostic_status": diagnostic.status.value,
                "status": "provider_not_ready",
            }
        )
        return 2

    session = uuid4().hex
    database_path, state_path = _session_paths(session)
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    if database_path.exists() or state_path.exists():
        raise RuntimeError("session_collision")

    agent_service, _ = module._agent_service(
        configuration,
        inference_service,
        now=now,
    )
    store = SQLiteDurableRunStore(database_path)
    await store.create(module._checkpoint(request, durable_run_id=durable_run_id))
    stack = create_durable_agent_runtime_stack(
        store=store,
        lease_manager=store.lease_manager,
        compatibility_validator=StaticDurableCompatibilityValidator(()),
    )
    lease = await store.lease_manager.acquire(
        durable_run_id,
        owner_id="s5c3c-real-cancel-prepare",
        now=now,
    )
    driver = stack.create_model_turn_execution_driver(lease=lease)
    token = AgentCancellationToken()

    inference_context = RuntimeContext(services={"inference": inference_service})
    agent_context = RuntimeContext(services={})
    run_task: asyncio.Task[object] | None = None
    result: object | None = None
    early_exit_code: int | None = None

    await inference_service.start(inference_context)
    await agent_service.start(agent_context)
    try:
        run_task = asyncio.create_task(
            agent_service.run(
                request,
                module._context(),
                cancellation=token,
                _model_turn_execution_driver=driver,
            )
        )
        observed = await _wait_for_started_attempt(
            store,
            durable_run_id,
            run_task,
            provider,
        )
        if not observed:
            if not run_task.done():
                token.cancel()
            result = await run_task
            current = await store.get_current(durable_run_id)
            _json_evidence(
                {
                    "schema_version": 1,
                    "kind": "rfc0038_real_provider_cancel_restart_prepare",
                    "diagnostic_status": diagnostic.status.value,
                    "provider_infer_calls": provider.infer_calls,
                    "durable_status": None if current is None else current.status.value,
                    "status": "did_not_observe_started_real_inference",
                }
            )
            early_exit_code = 4
        else:
            await asyncio.sleep(CANCEL_AFTER_PROVIDER_ENTRY_SECONDS)
            if run_task.done():
                result = await run_task
                current = await store.get_current(durable_run_id)
                _json_evidence(
                    {
                        "schema_version": 1,
                        "kind": "rfc0038_real_provider_cancel_restart_prepare",
                        "diagnostic_status": diagnostic.status.value,
                        "provider_infer_calls": provider.infer_calls,
                        "durable_status": (None if current is None else current.status.value),
                        "status": "provider_completed_before_cancel",
                    }
                )
                early_exit_code = 5
            else:
                token.cancel()
                result = await run_task
    finally:
        await agent_service.stop(agent_context)
        await inference_service.stop(inference_context)

    if early_exit_code is not None:
        await store.lease_manager.release(lease, now=datetime.now(UTC))
        await stack.close()
        return early_exit_code

    current = await store.get_current(durable_run_id)
    history = await store.list_history(durable_run_id, limit=32)
    durable_repr = repr(history)

    try:
        if current is None:
            raise RuntimeError("missing_durable_state")
        attempt = current.metadata.active_attempt
        run_status = getattr(result, "status", None)
        run_error_code = getattr(result, "error_code", None)
        final_output = getattr(result, "final_output", None)
        content_free_history = CANCEL_TASK not in durable_repr and (
            final_output is None or final_output not in durable_repr
        )
        passed = (
            run_status is AgentRunStatus.CANCELLED
            and run_error_code == "cancelled"
            and final_output is None
            and provider.infer_calls == 1
            and provider.infer_entered.is_set()
            and current.status is DurableRunStatus.INDETERMINATE_MODEL
            and current.metadata.next_operation is CheckpointNextOperation.OPERATOR_REVIEW
            and attempt is not None
            and attempt.status is ExecutionAttemptStatus.INDETERMINATE
            and content_free_history
        )

        if not passed:
            _json_evidence(
                {
                    "schema_version": 1,
                    "kind": "rfc0038_real_provider_cancel_restart_prepare",
                    "branch": branch,
                    "commit": commit,
                    "diagnostic_status": diagnostic.status.value,
                    "provider_infer_calls": provider.infer_calls,
                    "provider_infer_entered": provider.infer_entered.is_set(),
                    "run_status": (
                        None
                        if run_status is None
                        else getattr(run_status, "value", str(run_status))
                    ),
                    "run_error_code": run_error_code,
                    "durable_status": current.status.value,
                    "durable_next_operation": current.metadata.next_operation.value,
                    "attempt_status": None if attempt is None else attempt.status.value,
                    "attempt_error_code": None if attempt is None else attempt.error_code,
                    "content_free_history": content_free_history,
                    "driver_last_checkpoint_matches_current": (driver.last_checkpoint == current),
                    "status": "contract_failed",
                }
            )
            return 6

        state_path.write_text(
            json.dumps(
                _state_document(
                    session=session,
                    durable_run_id=durable_run_id,
                    checkpoint_digest=current.digest.value,
                    checkpoint_sequence=current.sequence.value,
                    budget_deadline=current.metadata.budget.deadline,
                    state_capture_pid=os.getpid(),
                    state_origin="prepare_cancel",
                    branch=branch,
                    commit=commit,
                ),
                sort_keys=True,
                separators=(",", ":"),
            ),
            encoding="utf-8",
            newline="\n",
        )
        _json_evidence(
            {
                "schema_version": 1,
                "kind": "rfc0038_real_provider_cancel_restart_prepare",
                "session": session,
                "branch": branch,
                "commit": commit,
                "diagnostic_status": diagnostic.status.value,
                "provider_infer_calls": provider.infer_calls,
                "provider_infer_entered": True,
                "cancelled_after_durable_started": True,
                "run_status": run_status.value,
                "run_error_code": run_error_code,
                "durable_status": current.status.value,
                "durable_next_operation": current.metadata.next_operation.value,
                "attempt_status": attempt.status.value,
                "attempt_error_code": attempt.error_code,
                "indeterminate_reason": (
                    None
                    if attempt.indeterminate_reason is None
                    else attempt.indeterminate_reason.value
                ),
                "history_entries": len(history),
                "content_free_history": True,
                "state_capture_pid": os.getpid(),
                "state_origin": "prepare_cancel",
                "status": "passed",
            }
        )
        return 0
    finally:
        await store.lease_manager.release(lease, now=datetime.now(UTC))
        await stack.close()


async def _salvage_cancel() -> int:
    """Capture one prior contract-failed cancellation DB without model replay."""

    if _environment_truthy("CI"):
        _json_evidence(
            {
                "schema_version": 1,
                "kind": "rfc0038_real_provider_cancel_restart_salvage",
                "status": "refused_ci",
            }
        )
        return 3

    branch, commit = _require_repository_identity()
    if not EVIDENCE_DIR.is_dir():
        raise RuntimeError("dogfood_evidence_directory_missing")

    matches: list[tuple[str, Path, DurableAgentRunId, object, tuple[object, ...]]] = []

    for database_path in sorted(EVIDENCE_DIR.glob("s5c3c-*.sqlite3")):
        session = database_path.stem.removeprefix("s5c3c-")
        if _SESSION_PATTERN.fullmatch(session) is None:
            continue
        _db_path, state_path = _session_paths(session)
        if state_path.exists():
            continue

        store = SQLiteDurableRunStore(database_path)
        try:
            candidates = await store.list_recovery_candidates(limit=8)
            if len(candidates) != 1:
                continue
            run_id = candidates[0]
            current = await store.get_current(run_id)
            if current is None:
                continue
            attempt = current.metadata.active_attempt
            if (
                current.status is not DurableRunStatus.INDETERMINATE_MODEL
                or current.metadata.next_operation is not CheckpointNextOperation.OPERATOR_REVIEW
                or attempt is None
                or attempt.status is not ExecutionAttemptStatus.INDETERMINATE
            ):
                continue
            history = await store.list_history(
                run_id,
                limit=current.sequence.value,
            )
            if CANCEL_TASK in repr(history):
                raise RuntimeError("salvage_history_not_content_free")
            matches.append(
                (
                    session,
                    database_path,
                    run_id,
                    current,
                    tuple(history),
                )
            )
        finally:
            await store.close()

    if len(matches) != 1:
        _json_evidence(
            {
                "schema_version": 1,
                "kind": "rfc0038_real_provider_cancel_restart_salvage",
                "eligible_orphan_count": len(matches),
                "status": "ambiguous_or_missing_orphan",
            }
        )
        return 8

    session, _database_path, durable_run_id, current_object, history = matches[0]
    current = current_object
    if not hasattr(current, "digest"):
        raise RuntimeError("salvage_checkpoint_invalid")

    _db_path, state_path = _session_paths(session)
    state_path.write_text(
        json.dumps(
            _state_document(
                session=session,
                durable_run_id=durable_run_id,
                checkpoint_digest=current.digest.value,
                checkpoint_sequence=current.sequence.value,
                budget_deadline=current.metadata.budget.deadline,
                state_capture_pid=os.getpid(),
                state_origin="salvaged_prior_prepare_cancel",
                branch=branch,
                commit=commit,
            ),
            sort_keys=True,
            separators=(",", ":"),
        ),
        encoding="utf-8",
        newline="\n",
    )

    attempt = current.metadata.active_attempt
    _json_evidence(
        {
            "schema_version": 1,
            "kind": "rfc0038_real_provider_cancel_restart_salvage",
            "session": session,
            "branch": branch,
            "commit": commit,
            "provider_constructed": False,
            "provider_infer_calls": 0,
            "durable_status": current.status.value,
            "durable_next_operation": current.metadata.next_operation.value,
            "attempt_status": None if attempt is None else attempt.status.value,
            "history_entries": len(history),
            "content_free_history": True,
            "state_capture_pid": os.getpid(),
            "state_origin": "salvaged_prior_prepare_cancel",
            "status": "passed",
        }
    )
    return 0


async def _recover(session: str) -> int:
    if _environment_truthy("CI"):
        _json_evidence(
            {
                "schema_version": 1,
                "kind": "rfc0038_real_provider_cancel_restart_recover",
                "status": "refused_ci",
            }
        )
        return 3

    branch, commit = _require_repository_identity()
    state = _read_state(session)
    database_path, _ = _session_paths(session)

    state_capture_pid = state["state_capture_pid"]
    state_origin = state["state_origin"]
    if isinstance(state_capture_pid, bool) or not isinstance(state_capture_pid, int):
        raise RuntimeError("session_state_invalid")
    if not isinstance(state_origin, str):
        raise RuntimeError("session_state_invalid")
    process_changed = state_capture_pid != os.getpid()
    if not process_changed:
        raise RuntimeError("recover_requires_new_process")

    try:
        durable_run_id = DurableAgentRunId(UUID(str(state["durable_run_id"])))
    except (TypeError, ValueError) as exception:
        raise RuntimeError("session_state_invalid") from exception

    store = SQLiteDurableRunStore(database_path)
    before = await store.get_current(durable_run_id)
    if before is None:
        await store.close()
        raise RuntimeError("persisted_checkpoint_missing")
    if (
        before.digest.value != state["checkpoint_digest"]
        or before.sequence.value != state["checkpoint_sequence"]
        or before.metadata.budget.deadline.isoformat() != state["budget_deadline"]
    ):
        await store.close()
        raise RuntimeError("persisted_checkpoint_changed_before_recovery")

    before_history = await store.list_history(
        durable_run_id,
        limit=before.sequence.value,
    )
    before_budget = before.metadata.budget

    policy = DurableCompatibilityPolicy(
        agent_id=before.metadata.agent_id,
        current=before.metadata.compatibility,
        payload_profile=before.metadata.payload_profile,
    )
    stack = create_durable_agent_runtime_stack(
        store=store,
        lease_manager=store.lease_manager,
        compatibility_validator=StaticDurableCompatibilityValidator((policy,)),
    )

    try:
        assessment = await stack.recovery_coordinator.assess_candidate(
            durable_run_id,
            owner_id="s5c3c-real-cancel-recover",
            now=datetime.now(UTC),
        )
        after = await store.get_current(durable_run_id)
        if after is None:
            raise RuntimeError("persisted_checkpoint_missing_after_recovery")
        after_history = await store.list_history(
            durable_run_id,
            limit=after.sequence.value,
        )
        attempt = after.metadata.active_attempt
        checkpoint_unchanged = after == before
        history_unchanged = after_history == before_history
        budget_continuity = after.metadata.budget == before_budget
        deadline_continuity = after.metadata.budget.deadline == before_budget.deadline
        passed = (
            process_changed
            and before.status is DurableRunStatus.INDETERMINATE_MODEL
            and attempt is not None
            and attempt.status is ExecutionAttemptStatus.INDETERMINATE
            and assessment.point is RecoveryPoint.ACTIVE_MODEL_ATTEMPT
            and assessment.disposition is RecoveryDisposition.PAUSE_OPERATOR
            and assessment.compatibility.compatible
            and checkpoint_unchanged
            and history_unchanged
            and budget_continuity
            and deadline_continuity
        )

        _json_evidence(
            {
                "schema_version": 1,
                "kind": "rfc0038_real_provider_cancel_restart_recover",
                "session": session,
                "branch": branch,
                "commit": commit,
                "state_capture_pid": state_capture_pid,
                "state_origin": state_origin,
                "recover_pid": os.getpid(),
                "process_changed": process_changed,
                "provider_constructed": False,
                "provider_infer_calls": 0,
                "durable_status": after.status.value,
                "durable_next_operation": after.metadata.next_operation.value,
                "attempt_status": None if attempt is None else attempt.status.value,
                "recovery_point": assessment.point.value,
                "recovery_disposition": assessment.disposition.value,
                "compatibility_category": assessment.compatibility.category.value,
                "compatibility_mode": (
                    "structural_exact_from_persisted_checkpoint_not_live_revalidation"
                ),
                "checkpoint_unchanged": checkpoint_unchanged,
                "history_unchanged": history_unchanged,
                "budget_continuity": budget_continuity,
                "deadline_continuity": deadline_continuity,
                "status": "passed" if passed else "contract_failed",
            }
        )
        return 0 if passed else 6
    finally:
        await stack.close()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="RFC-0038 real cancellation + process restart dogfood",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser(
        "prepare-cancel",
        help="run real Ollama inference, cancel after STARTED, persist SQLite",
    )
    subparsers.add_parser(
        "salvage-cancel",
        help="capture one prior orphan cancellation SQLite without provider replay",
    )
    recover = subparsers.add_parser(
        "recover",
        help="open persisted SQLite in a new process and assess without provider",
    )
    recover.add_argument("--session", required=True)
    return parser


async def _run(arguments: argparse.Namespace) -> int:
    if arguments.command == "prepare-cancel":
        return await _prepare_cancel()
    if arguments.command == "salvage-cancel":
        return await _salvage_cancel()
    if arguments.command == "recover":
        return await _recover(arguments.session)
    raise RuntimeError("unsupported_command")


def main() -> int:
    arguments = _parser().parse_args()
    try:
        return asyncio.run(_run(arguments))
    except KeyboardInterrupt:
        return 130
    except BaseException as exception:
        _json_evidence(
            {
                "schema_version": 1,
                "kind": "rfc0038_real_provider_cancel_restart_canary",
                "exception_category": type(exception).__name__,
                "status": "execution_exception",
            }
        )
        return 7


if __name__ == "__main__":
    raise SystemExit(main())
