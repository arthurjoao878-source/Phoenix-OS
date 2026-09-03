"""RFC-0038 S5c3e real-model rejected tool-proposal dogfood.

Explicit non-CI canary. A real local model is constrained to propose one
reviewed read-only sentinel tool. Phoenix validates the proposal, then a
server-owned ToolAuthorizer rejects it before any adapter invocation.
Evidence is content-free.
"""

from __future__ import annotations

import asyncio
import hashlib
import importlib.util
import json
import os
import subprocess
import time
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import ModuleType
from uuid import uuid4

from phoenix_os.agent.admission import AgentAdmissionController
from phoenix_os.agent.configuration import AgentToolConfiguration
from phoenix_os.agent.contracts import (
    AgentRunStatus,
    ToolEffect,
    ToolId,
    ToolInvocationRequest,
    ToolInvocationResult,
)
from phoenix_os.agent.durable_compatibility import StaticDurableCompatibilityValidator
from phoenix_os.agent.durable_contracts import (
    DurableAgentRunId,
    ExecutionAttemptStatus,
)
from phoenix_os.agent.durable_memory import InMemoryDurableRunStore
from phoenix_os.agent.durable_runtime import create_durable_agent_runtime_stack
from phoenix_os.agent.errors import AgentAuthorizationRejectedError
from phoenix_os.agent.execution import BoundedAgentExecutor
from phoenix_os.agent.loop import AgentLoop
from phoenix_os.agent.model_turn import InferenceBackedAgentModelTurnAdapter
from phoenix_os.agent.registry import ToolRegistry
from phoenix_os.agent.schemas import (
    ToolInputSchema,
    ToolOutputSchema,
    ToolSchema,
    ToolSchemaType,
)
from phoenix_os.agent.service import AgentService
from phoenix_os.agent.tools import StaticToolResourceResolver, ToolDescriptor
from phoenix_os.events import EventBus
from phoenix_os.inference.ollama import OllamaModelAvailability
from phoenix_os.policy import SecurityContext
from phoenix_os.runtime import RuntimeContext

ROOT = Path(__file__).resolve().parents[1]
BASE_CANARY = ROOT / "scripts" / "run_rfc0038_real_provider_canary.py"
EXPECTED_BASE_CANARY_SHA256 = "15db737fdce329238ed66b35681ee6cb805f0eb72f51b3a4be0d57fd0f9d7537"
EXPECTED_BRANCH = "feat/rfc-0038-slice-5-durable-real-provider-dogfood"
EXPECTED_HEAD = "5beab1d70b4d0154cf3ead307c6e79a07e366d62"

TOOL_ID = ToolId("dogfood.reject")
TOOL_PROMPT = "Use the available dogfood.reject tool exactly once with an empty arguments object."
TOOL_OUTPUT_SCHEMA = json.dumps(
    {
        "type": "object",
        "properties": {
            "version": {"type": "integer", "enum": [1]},
            "kind": {"type": "string", "enum": ["tool"]},
            "tool": {"type": "string", "enum": [str(TOOL_ID)]},
            "arguments": {
                "type": "object",
                "properties": {},
                "required": [],
                "additionalProperties": False,
            },
        },
        "required": ["version", "kind", "tool", "arguments"],
        "additionalProperties": False,
    },
    separators=(",", ":"),
    sort_keys=True,
)


@dataclass(slots=True)
class _SentinelToolAdapter:
    tool_id: ToolId = TOOL_ID
    adapter_id: str = "adapter.dogfood.reject"
    invocations: int = 0

    async def invoke(self, request: ToolInvocationRequest) -> ToolInvocationResult:
        del request
        self.invocations += 1
        raise AssertionError("rejected sentinel tool adapter must never be invoked")


class _RejectingToolAuthorizer:
    def __init__(self) -> None:
        self.calls = 0

    async def authorize(
        self,
        request: ToolInvocationRequest,
        descriptor: ToolDescriptor,
        context: SecurityContext,
    ) -> None:
        if request.tool_id != TOOL_ID or descriptor.tool_id != TOOL_ID:
            raise AssertionError("unexpected tool reached rejecting authorizer")
        if not context.authenticated:
            raise AssertionError("tool authorization context must be authenticated")
        self.calls += 1
        raise AgentAuthorizationRejectedError()


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


def _tool_descriptor() -> ToolDescriptor:
    empty = ToolSchema(kind=ToolSchemaType.OBJECT)
    return ToolDescriptor(
        tool_id=TOOL_ID,
        name="Rejected dogfood sentinel",
        description=(
            "Read-only sentinel used only to prove server authorization rejection "
            "before tool execution."
        ),
        input_schema=ToolInputSchema(empty),
        output_schema=ToolOutputSchema(empty),
        effect=ToolEffect.READ_ONLY,
        approval_may_be_required=False,
        max_input_bytes=256,
        max_output_bytes=256,
        timeout=timedelta(seconds=1),
        resolver_id="resolver.dogfood.reject",
        adapter_id="adapter.dogfood.reject",
    )


def _agent_service(
    module: ModuleType,
    configuration: object,
    inference_service: object,
    *,
    now: datetime,
    descriptor: ToolDescriptor,
    sentinel: _SentinelToolAdapter,
    tool_authorizer: _RejectingToolAuthorizer,
) -> tuple[AgentService, object]:
    registry = ToolRegistry()
    registry.register_tool(
        descriptor,
        resolver=StaticToolResourceResolver(
            "resolver.dogfood.reject",
            "dogfood:tool/reject",
        ),
        adapter=sentinel,
    )
    admission = AgentAdmissionController()
    model_authorizer = module._ModelAuthorizer()
    adapter = InferenceBackedAgentModelTurnAdapter(inference_service)

    loop = AgentLoop(
        run_authorizer=module._RunAuthorizer(),
        model_authorizer=model_authorizer,
        tool_authorizer=tool_authorizer,
        model_adapter=adapter,
        registry=registry,
        executor=BoundedAgentExecutor(clock=lambda: now),
        admission=admission,
        clock=lambda: now,
    )
    service = AgentService(
        loop,
        registry,
        admission,
        configuration,
        events=EventBus(),
        model_adapter=adapter,
    )
    return service, model_authorizer


async def _run() -> int:
    if _environment_truthy("CI"):
        _json_evidence(
            {
                "schema_version": 1,
                "kind": "rfc0038_real_provider_rejected_tool_canary",
                "status": "refused_ci",
            }
        )
        return 3

    branch, commit = _require_repository_identity()
    module = _load_base_canary()

    # Server-owned provider schema and user task are process-local only.
    module.AGENT_FINAL_OUTPUT_SCHEMA = TOOL_OUTPUT_SCHEMA
    module.CANARY_USER_TEXT = TOOL_PROMPT

    descriptor = _tool_descriptor()
    configuration = replace(
        module._configuration(),
        tools=(AgentToolConfiguration(descriptor),),
    )
    now = datetime.now(UTC)
    agent_run_id = module.AgentRunId(uuid4())
    durable_run_id = DurableAgentRunId(uuid4())
    request = module._request(
        configuration,
        now=now,
        agent_run_id=agent_run_id,
    )

    inference_service, provider, inference_authorizer = module._inference_service()
    diagnostic = await provider.diagnose_model(module.MODEL_ID)
    if diagnostic.status is not OllamaModelAvailability.AVAILABLE:
        _json_evidence(
            {
                "schema_version": 1,
                "kind": "rfc0038_real_provider_rejected_tool_canary",
                "diagnostic_status": diagnostic.status.value,
                "status": "provider_not_ready",
            }
        )
        return 2

    sentinel = _SentinelToolAdapter()
    tool_authorizer = _RejectingToolAuthorizer()
    agent_service, model_authorizer = _agent_service(
        module,
        configuration,
        inference_service,
        now=now,
        descriptor=descriptor,
        sentinel=sentinel,
        tool_authorizer=tool_authorizer,
    )

    store = InMemoryDurableRunStore()
    await store.create(
        module._checkpoint(
            request,
            durable_run_id=durable_run_id,
        )
    )
    stack = create_durable_agent_runtime_stack(
        store=store,
        lease_manager=store.lease_manager,
        compatibility_validator=StaticDurableCompatibilityValidator(()),
    )
    lease = await store.lease_manager.acquire(
        durable_run_id,
        owner_id="s5c3e-real-rejected-tool",
        now=now,
    )
    driver = stack.create_model_turn_execution_driver(lease=lease)

    inference_context = RuntimeContext(services={"inference": inference_service})
    agent_context = RuntimeContext(services={})
    result = None
    terminal_exception: BaseException | None = None
    started_clock = time.perf_counter()

    await inference_service.start(inference_context)
    await agent_service.start(agent_context)
    try:
        try:
            result = await agent_service.run(
                request,
                module._context(),
                _model_turn_execution_driver=driver,
            )
        except BaseException as exception:
            terminal_exception = exception
    finally:
        await agent_service.stop(agent_context)
        await inference_service.stop(inference_context)

    try:
        elapsed_ms = max(
            0,
            round((time.perf_counter() - started_clock) * 1_000),
        )
        current = await store.get_current(durable_run_id)
        history = await store.list_history(durable_run_id, limit=32)
        durable_repr = repr(history)

        if terminal_exception is not None:
            _json_evidence(
                {
                    "schema_version": 1,
                    "kind": "rfc0038_real_provider_rejected_tool_canary",
                    "exception_category": type(terminal_exception).__name__,
                    "elapsed_ms": elapsed_ms,
                    "status": "execution_exception",
                }
            )
            return 4
        if result is None or current is None:
            _json_evidence(
                {
                    "schema_version": 1,
                    "kind": "rfc0038_real_provider_rejected_tool_canary",
                    "status": "missing_terminal_state",
                }
            )
            return 5

        attempt = current.metadata.active_attempt
        exact_request_identity = (
            len(inference_authorizer.requests) == 1
            and len(model_authorizer.requests) >= 1
            and any(
                inference_authorizer.requests[0] is authorized
                for authorized in model_authorizer.requests
            )
        )
        content_free_history = TOOL_PROMPT not in durable_repr
        rejected_before_execution = (
            result.status is AgentRunStatus.FAILED
            and result.error_code == "authorization_rejected"
            and result.model_turns == 1
            and result.tool_calls == 0
            and result.final_output is None
            and tool_authorizer.calls == 1
            and sentinel.invocations == 0
            and attempt is not None
            and attempt.status is ExecutionAttemptStatus.SUCCEEDED
            and attempt.error_code is None
            and exact_request_identity
            and content_free_history
        )

        _json_evidence(
            {
                "schema_version": 1,
                "kind": "rfc0038_real_provider_rejected_tool_canary",
                "branch": branch,
                "commit": commit,
                "diagnostic_status": diagnostic.status.value,
                "elapsed_ms": elapsed_ms,
                "run_status": result.status.value,
                "run_error_code": result.error_code,
                "model_turns": result.model_turns,
                "tool_calls": result.tool_calls,
                "tool_authorizer_calls": tool_authorizer.calls,
                "tool_adapter_invocations": sentinel.invocations,
                "durable_status": current.status.value,
                "durable_next_operation": current.metadata.next_operation.value,
                "attempt_status": None if attempt is None else attempt.status.value,
                "attempt_error_code": None if attempt is None else attempt.error_code,
                "exact_request_identity": exact_request_identity,
                "content_free_history": content_free_history,
                "status": "passed" if rejected_before_execution else "contract_failed",
            }
        )
        return 0 if rejected_before_execution else 6
    finally:
        await stack.close()


def main() -> int:
    try:
        return asyncio.run(_run())
    except KeyboardInterrupt:
        return 130
    except BaseException as exception:
        _json_evidence(
            {
                "schema_version": 1,
                "kind": "rfc0038_real_provider_rejected_tool_canary",
                "exception_category": type(exception).__name__,
                "status": "execution_exception",
            }
        )
        return 7


if __name__ == "__main__":
    raise SystemExit(main())
