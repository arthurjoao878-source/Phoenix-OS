"""Explicit non-CI RFC-0038 durable real-provider canary.

This script deliberately executes one real local Ollama model turn through the
Phoenix durable AgentService -> AgentLoop -> RFC-0026 inference composition.
It emits only bounded content-free operational evidence.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import math
import os
import subprocess
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import phoenix_os.agent.model_turn as agent_model_turn_module
from phoenix_os.agent.admission import AgentAdmissionController
from phoenix_os.agent.configuration import AgentServiceConfiguration
from phoenix_os.agent.contracts import (
    AgentId,
    AgentLimits,
    AgentMessage,
    AgentMessageRole,
    AgentRunId,
    AgentRunRequest,
    AgentRunStatus,
    ToolInvocationRequest,
)
from phoenix_os.agent.durable_codec import seal_checkpoint_envelope
from phoenix_os.agent.durable_compatibility import StaticDurableCompatibilityValidator
from phoenix_os.agent.durable_contracts import (
    CheckpointDigest,
    CheckpointEnvelope,
    CheckpointId,
    CheckpointMetadata,
    CheckpointNextOperation,
    CheckpointPayloadProfile,
    CheckpointSchemaVersion,
    CheckpointSequence,
    CompatibilityDigests,
    DurableAgentRunId,
    DurableRunStatus,
    DurableRunVersion,
    ExecutionAttemptStatus,
)
from phoenix_os.agent.durable_memory import InMemoryDurableRunStore
from phoenix_os.agent.durable_runtime import create_durable_agent_runtime_stack
from phoenix_os.agent.execution import BoundedAgentExecutor
from phoenix_os.agent.fake import AgentModelTurnRequest, AgentModelTurnResult
from phoenix_os.agent.loop import AgentLoop
from phoenix_os.agent.model_turn import InferenceBackedAgentModelTurnAdapter
from phoenix_os.agent.registry import ToolRegistry
from phoenix_os.agent.service import AgentService
from phoenix_os.agent.state import AgentBudgetSnapshot
from phoenix_os.agent.tools import ToolDescriptor
from phoenix_os.events import EventBus
from phoenix_os.inference import (
    InferenceLimits,
    InferenceRequest,
    ModelCapabilities,
    ModelDescriptor,
    ModelEndpointMode,
    ModelEndpointPolicy,
    ModelId,
)
from phoenix_os.inference.configuration import (
    InferenceProviderConfiguration,
    InferenceServiceConfiguration,
)
from phoenix_os.inference.execution import InferenceRuntime
from phoenix_os.inference.ollama import (
    OLLAMA_PROVIDER_ID,
    OllamaModelAvailability,
    OllamaModelBinding,
    OllamaModelProvider,
)
from phoenix_os.inference.registry import ModelProviderRegistry
from phoenix_os.inference.service import InferenceService
from phoenix_os.policy import PrincipalType, SecurityContext
from phoenix_os.runtime import RuntimeContext

MODEL_ID = ModelId("qwen3-4b-instruct")
PROVIDER_MODEL_NAME = "qwen3:4b-instruct"
AGENT_FINAL_OUTPUT_SCHEMA = json.dumps(
    {
        "type": "object",
        "properties": {
            "version": {"type": "integer", "enum": [1]},
            "kind": {"type": "string", "enum": ["final"]},
            "content": {"type": "string"},
        },
        "required": ["version", "kind", "content"],
        "additionalProperties": False,
    },
    separators=(",", ":"),
    sort_keys=True,
)
_MODEL_OUTPUT_CLASSIFICATION: dict[str, object] | None = None
_ORIGINAL_MODEL_TURN_DECODER = agent_model_turn_module.decode_agent_model_turn_envelope

CANARY_USER_TEXT = (
    'Return a final result whose content is exactly "canary-ok". Do not request a tool.'
)
ROOT = Path(__file__).resolve().parents[1]


def _environment_truthy(name: str) -> bool:
    value = os.environ.get(name)
    if value is None:
        return False
    return value.strip().lower() not in {"", "0", "false", "no", "off"}


def _bounded_elapsed_observation(
    started_clock: float,
    finished_clock: float,
    *,
    maximum_ms: int,
) -> tuple[int, bool]:
    for label, value in (
        ("started_clock", started_clock),
        ("finished_clock", finished_clock),
    ):
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise TypeError(f"{label} must be a number")
        if not math.isfinite(value):
            raise ValueError(f"{label} must be finite")
    if isinstance(maximum_ms, bool) or not isinstance(maximum_ms, int):
        raise TypeError("maximum_ms must be an integer")
    if maximum_ms <= 0:
        raise ValueError("maximum_ms must be positive")

    raw_ms = max(0, round((finished_clock - started_clock) * 1_000))
    return min(raw_ms, maximum_ms), raw_ms > maximum_ms


def _usage_within_limits(
    input_tokens: int,
    output_tokens: int,
    limits: AgentLimits,
) -> bool:
    for label, value in (
        ("input_tokens", input_tokens),
        ("output_tokens", output_tokens),
    ):
        if isinstance(value, bool) or not isinstance(value, int):
            raise TypeError(f"{label} must be an integer")
        if value < 0:
            raise ValueError(f"{label} must not be negative")
    if not isinstance(limits, AgentLimits):
        raise TypeError("limits must be AgentLimits")
    return input_tokens <= limits.max_input_tokens and output_tokens <= limits.max_output_tokens


def _json_evidence(values: dict[str, object]) -> None:
    evidence = dict(values)
    classification = _MODEL_OUTPUT_CLASSIFICATION
    if classification is not None:
        evidence.update({f"model_output_{key}": value for key, value in classification.items()})
    print(json.dumps(evidence, sort_keys=True, separators=(",", ":")))


def _classify_model_output(text: str) -> dict[str, object]:
    classification: dict[str, object] = {
        "bytes": len(text.encode()),
        "strict_json_valid": False,
        "top_level_object": False,
        "top_level_array": False,
        "duplicate_key_seen": False,
        "has_version": False,
        "has_kind": False,
        "has_content": False,
        "has_tool": False,
        "has_arguments": False,
        "version_is_one": False,
        "kind_is_final": False,
        "kind_is_tool": False,
        "kind_is_other": False,
        "content_is_string": False,
        "final_keyset_exact": False,
        "tool_keyset_exact": False,
    }
    duplicate_key_seen = False

    def strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        nonlocal duplicate_key_seen
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                duplicate_key_seen = True
            result[key] = value
        return result

    def reject_constant(value: str) -> object:
        raise ValueError(f"unsupported JSON constant: {value}")

    try:
        decoded = json.loads(
            text,
            object_pairs_hook=strict_object,
            parse_constant=reject_constant,
        )
    except (TypeError, ValueError, OverflowError, RecursionError):
        classification["duplicate_key_seen"] = duplicate_key_seen
        return classification

    classification["strict_json_valid"] = not duplicate_key_seen
    classification["duplicate_key_seen"] = duplicate_key_seen
    classification["top_level_array"] = isinstance(decoded, list)

    if not isinstance(decoded, dict):
        return classification

    classification["top_level_object"] = True
    keys = set(decoded)
    classification["has_version"] = "version" in keys
    classification["has_kind"] = "kind" in keys
    classification["has_content"] = "content" in keys
    classification["has_tool"] = "tool" in keys
    classification["has_arguments"] = "arguments" in keys

    version = decoded.get("version")
    kind = decoded.get("kind")
    classification["version_is_one"] = (
        isinstance(version, int) and not isinstance(version, bool) and version == 1
    )
    classification["kind_is_final"] = kind == "final"
    classification["kind_is_tool"] = kind == "tool"
    classification["kind_is_other"] = isinstance(kind, str) and kind not in {"final", "tool"}
    classification["content_is_string"] = isinstance(decoded.get("content"), str)
    classification["final_keyset_exact"] = keys == {"version", "kind", "content"}
    classification["tool_keyset_exact"] = keys == {
        "version",
        "kind",
        "tool",
        "arguments",
    }
    return classification


def _classifying_model_turn_decoder(
    text: str,
    request: AgentModelTurnRequest,
) -> AgentModelTurnResult:
    global _MODEL_OUTPUT_CLASSIFICATION
    _MODEL_OUTPUT_CLASSIFICATION = _classify_model_output(text)
    return _ORIGINAL_MODEL_TURN_DECODER(text, request)


agent_model_turn_module.decode_agent_model_turn_envelope = _classifying_model_turn_decoder


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
    value = result.stdout.strip()
    return value or None


def _compatibility_digest(label: str) -> CheckpointDigest:
    material = (
        f"rfc0038-s5c3b|{label}|ollama-local|qwen3-4b-instruct|loopback-http|11434|metadata-only"
    ).encode()
    return CheckpointDigest(hashlib.sha256(material).hexdigest())


def _model_provider_compatibility_digest(
    structured_json_schema: str,
) -> CheckpointDigest:
    binding = OllamaModelBinding(
        _model_descriptor(),
        structured_json_schema=structured_json_schema,
    )
    canonical_schema = binding.structured_json_schema
    if canonical_schema is None:
        raise AssertionError("real-provider dogfood requires a structured JSON schema")
    schema_digest = hashlib.sha256(canonical_schema.encode()).hexdigest()
    material = (
        f"{_compatibility_digest('model-provider')}|structured-json-schema-sha256:{schema_digest}"
    ).encode()
    return CheckpointDigest(hashlib.sha256(material).hexdigest())


def _compatibility(
    *,
    structured_json_schema: str = AGENT_FINAL_OUTPUT_SCHEMA,
) -> CompatibilityDigests:
    return CompatibilityDigests(
        configuration=_compatibility_digest("configuration"),
        tool_registry=_compatibility_digest("tool-registry"),
        model_provider=_model_provider_compatibility_digest(structured_json_schema),
        checkpoint_codec=_compatibility_digest("checkpoint-codec"),
    )


def _provider_configuration() -> InferenceProviderConfiguration:
    return InferenceProviderConfiguration(
        OLLAMA_PROVIDER_ID,
        endpoint_policy=ModelEndpointPolicy(
            "http://127.0.0.1:11434/",
            mode=ModelEndpointMode.LOOPBACK_HTTP,
            allowed_ports=frozenset({11_434}),
        ),
    )


def _model_descriptor() -> ModelDescriptor:
    return ModelDescriptor(
        provider_id=OLLAMA_PROVIDER_ID,
        model_id=MODEL_ID,
        provider_model_name=PROVIDER_MODEL_NAME,
        capabilities=ModelCapabilities(complete=True, streaming=True),
        limits=InferenceLimits(
            max_output_tokens=128,
            max_response_chars=16_384,
        ),
    )


def _configuration() -> AgentServiceConfiguration:
    return AgentServiceConfiguration(
        agent_id=AgentId("assistant"),
        provider_id=OLLAMA_PROVIDER_ID,
        model_id=MODEL_ID,
        limits=AgentLimits(max_output_tokens=128),
    )


def _request(
    configuration: AgentServiceConfiguration,
    *,
    now: datetime,
    agent_run_id: AgentRunId,
) -> AgentRunRequest:
    return AgentRunRequest(
        agent_id=configuration.agent_id,
        provider_id=configuration.provider_id,
        model_id=configuration.model_id,
        messages=(
            AgentMessage(
                AgentMessageRole.USER,
                CANARY_USER_TEXT,
            ),
        ),
        limits=configuration.limits,
        run_id=agent_run_id,
        created_at=now,
        deadline=now + timedelta(minutes=2),
    )


def _checkpoint(
    request: AgentRunRequest,
    *,
    durable_run_id: DurableAgentRunId,
) -> CheckpointEnvelope:
    return seal_checkpoint_envelope(
        CheckpointEnvelope(
            schema_version=CheckpointSchemaVersion(),
            durable_run_id=durable_run_id,
            checkpoint_id=CheckpointId(uuid4()),
            sequence=CheckpointSequence(1),
            previous_digest=None,
            run_version=DurableRunVersion(1),
            status=DurableRunStatus.ACTIVE,
            agent_run_id=request.run_id,
            step_id=None,
            metadata=CheckpointMetadata(
                agent_id=request.agent_id,
                actor_id="s5c3b-real-provider-canary",
                next_operation=CheckpointNextOperation.MODEL_TURN,
                budget=AgentBudgetSnapshot(
                    steps=0,
                    model_turns=0,
                    tool_calls=0,
                    model_output_bytes=0,
                    tool_result_bytes=0,
                    input_tokens=0,
                    output_tokens=0,
                    started_at=request.created_at,
                    deadline=request.deadline,
                ),
                compatibility=_compatibility(),
                payload_profile=CheckpointPayloadProfile.METADATA_ONLY,
                retention_deadline=request.deadline + timedelta(days=1),
            ),
            created_at=request.created_at,
            digest=CheckpointDigest("0" * 64),
        )
    )


def _context() -> SecurityContext:
    return SecurityContext(
        principal="service:assistant",
        principal_type=PrincipalType.SERVICE,
        authenticated=True,
    )


class _RunAuthorizer:
    async def authorize(
        self,
        request: AgentRunRequest,
        context: SecurityContext,
    ) -> None:
        if not context.authenticated or request.model_id != MODEL_ID:
            raise RuntimeError("canary run authorization invariant failed")


class _ModelAuthorizer:
    def __init__(self) -> None:
        self.requests: list[InferenceRequest] = []

    async def authorize(
        self,
        request: InferenceRequest,
        context: SecurityContext,
    ) -> None:
        if (
            not context.authenticated
            or request.provider_id != OLLAMA_PROVIDER_ID
            or request.model_id != MODEL_ID
        ):
            raise RuntimeError("canary model authorization invariant failed")
        self.requests.append(request)


class _ToolAuthorizer:
    async def authorize(
        self,
        request: ToolInvocationRequest,
        descriptor: ToolDescriptor,
        context: SecurityContext,
    ) -> None:
        del request, descriptor, context
        raise RuntimeError("final-output canary must not reach tools")


class _InferenceAuthorizer:
    def __init__(self) -> None:
        self.requests: list[InferenceRequest] = []

    async def authorize(
        self,
        request: InferenceRequest,
        context: SecurityContext,
    ) -> None:
        if (
            not context.authenticated
            or request.provider_id != OLLAMA_PROVIDER_ID
            or request.model_id != MODEL_ID
        ):
            raise RuntimeError("canary inference authorization invariant failed")
        self.requests.append(request)


def _inference_service() -> tuple[
    InferenceService,
    OllamaModelProvider,
    _InferenceAuthorizer,
]:
    provider_configuration = _provider_configuration()
    descriptor = _model_descriptor()
    provider = OllamaModelProvider(
        provider_configuration,
        (
            OllamaModelBinding(
                descriptor,
                structured_json_schema=AGENT_FINAL_OUTPUT_SCHEMA,
            ),
        ),
    )

    registry = ModelProviderRegistry()
    registry.register_provider(provider)
    registry.register_model(descriptor)

    authorizer = _InferenceAuthorizer()
    runtime = InferenceRuntime(registry, authorizer)
    service = InferenceService(
        runtime,
        registry,
        InferenceServiceConfiguration(
            providers=(provider_configuration,),
            models=(descriptor,),
        ),
        events=EventBus(),
    )
    return service, provider, authorizer


def _agent_service(
    configuration: AgentServiceConfiguration,
    inference_service: InferenceService,
    *,
    now: datetime,
) -> tuple[AgentService, _ModelAuthorizer]:
    registry = ToolRegistry()
    admission = AgentAdmissionController()
    model_authorizer = _ModelAuthorizer()
    adapter = InferenceBackedAgentModelTurnAdapter(inference_service)

    loop = AgentLoop(
        run_authorizer=_RunAuthorizer(),
        model_authorizer=model_authorizer,
        tool_authorizer=_ToolAuthorizer(),
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
                "kind": "rfc0038_real_provider_canary",
                "provider_id": str(OLLAMA_PROVIDER_ID),
                "phoenix_model_id": str(MODEL_ID),
                "status": "refused_ci",
            }
        )
        return 3

    now = datetime.now(UTC)
    agent_run_id = AgentRunId(uuid4())
    durable_run_id = DurableAgentRunId(uuid4())
    configuration = _configuration()
    request = _request(
        configuration,
        now=now,
        agent_run_id=agent_run_id,
    )

    inference_service, provider, inference_authorizer = _inference_service()
    diagnostic = await provider.diagnose_model(MODEL_ID)
    if diagnostic.status is not OllamaModelAvailability.AVAILABLE:
        _json_evidence(
            {
                "schema_version": 1,
                "kind": "rfc0038_real_provider_canary",
                "provider_id": str(OLLAMA_PROVIDER_ID),
                "phoenix_model_id": str(MODEL_ID),
                "diagnostic_status": diagnostic.status.value,
                "status": "provider_not_ready",
            }
        )
        return 2

    agent_service, model_authorizer = _agent_service(
        configuration,
        inference_service,
        now=now,
    )

    store = InMemoryDurableRunStore()
    await store.create(
        _checkpoint(
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
        owner_id="s5c3b-real-provider-canary",
        now=now,
    )
    driver = stack.create_model_turn_execution_driver(lease=lease)

    inference_context = RuntimeContext(services={"inference": inference_service})
    agent_context = RuntimeContext(services={})

    started_clock = time.perf_counter()
    result = None
    terminal_exception: BaseException | None = None

    await inference_service.start(inference_context)
    await agent_service.start(agent_context)
    try:
        try:
            result = await agent_service.run(
                request,
                _context(),
                _model_turn_execution_driver=driver,
            )
        except BaseException as exception:
            terminal_exception = exception
    finally:
        await agent_service.stop(agent_context)
        await inference_service.stop(inference_context)

    try:
        maximum_elapsed_ms = round((request.deadline - request.created_at).total_seconds() * 1_000)
        elapsed_ms, elapsed_ms_capped = _bounded_elapsed_observation(
            started_clock,
            time.perf_counter(),
            maximum_ms=maximum_elapsed_ms,
        )

        current = await store.get_current(durable_run_id)
        history = await store.list_history(durable_run_id, limit=32)
        durable_repr = repr(history)

        if terminal_exception is not None:
            _json_evidence(
                {
                    "schema_version": 1,
                    "kind": "rfc0038_real_provider_canary",
                    "provider_id": str(OLLAMA_PROVIDER_ID),
                    "phoenix_model_id": str(MODEL_ID),
                    "diagnostic_status": diagnostic.status.value,
                    "elapsed_ms": elapsed_ms,
                    "elapsed_ms_capped": elapsed_ms_capped,
                    "exception_category": type(terminal_exception).__name__,
                    "branch": _safe_git("branch", "--show-current"),
                    "commit": _safe_git("rev-parse", "HEAD"),
                    "status": "execution_exception",
                }
            )
            return 4

        if result is None or current is None:
            _json_evidence(
                {
                    "schema_version": 1,
                    "kind": "rfc0038_real_provider_canary",
                    "provider_id": str(OLLAMA_PROVIDER_ID),
                    "phoenix_model_id": str(MODEL_ID),
                    "diagnostic_status": diagnostic.status.value,
                    "elapsed_ms": elapsed_ms,
                    "elapsed_ms_capped": elapsed_ms_capped,
                    "status": "missing_terminal_state",
                }
            )
            return 5

        attempt = current.metadata.active_attempt
        final_output = result.final_output
        content_free_history = CANARY_USER_TEXT not in durable_repr and (
            final_output is None or final_output not in durable_repr
        )
        exact_request_identity = len(inference_authorizer.requests) == 1 and any(
            inference_authorizer.requests[0] is authorized
            for authorized in model_authorizer.requests
        )
        usage_within_limits = _usage_within_limits(
            current.metadata.budget.input_tokens,
            current.metadata.budget.output_tokens,
            request.limits,
        )
        succeeded = (
            result.status is AgentRunStatus.COMPLETED
            and result.model_turns == 1
            and result.tool_calls == 0
            and final_output is not None
            and current.status is DurableRunStatus.ACTIVE
            and current.metadata.next_operation is CheckpointNextOperation.COMPLETE
            and attempt is not None
            and attempt.status is ExecutionAttemptStatus.SUCCEEDED
            and attempt.error_code is None
            and driver.last_checkpoint == current
            and exact_request_identity
            and content_free_history
            and usage_within_limits
        )

        _json_evidence(
            {
                "schema_version": 1,
                "kind": "rfc0038_real_provider_canary",
                "provider_id": str(OLLAMA_PROVIDER_ID),
                "phoenix_model_id": str(MODEL_ID),
                "diagnostic_status": diagnostic.status.value,
                "branch": _safe_git("branch", "--show-current"),
                "commit": _safe_git("rev-parse", "HEAD"),
                "elapsed_ms": elapsed_ms,
                "elapsed_ms_capped": elapsed_ms_capped,
                "run_status": result.status.value,
                "model_turns": result.model_turns,
                "tool_calls": result.tool_calls,
                "durable_status": current.status.value,
                "durable_next_operation": current.metadata.next_operation.value,
                "attempt_status": None if attempt is None else attempt.status.value,
                "attempt_error_code": None if attempt is None else attempt.error_code,
                "run_error_code": result.error_code,
                "input_tokens": current.metadata.budget.input_tokens,
                "output_tokens": current.metadata.budget.output_tokens,
                "usage_within_limits": usage_within_limits,
                "exact_request_identity": exact_request_identity,
                "content_free_history": content_free_history,
                "final_output_present": final_output is not None,
                "status": "passed" if succeeded else "contract_failed",
            }
        )
        return 0 if succeeded else 6
    finally:
        await stack.close()


def main() -> int:
    try:
        return asyncio.run(_run())
    except KeyboardInterrupt:
        _json_evidence(
            {
                "schema_version": 1,
                "kind": "rfc0038_real_provider_canary",
                "provider_id": str(OLLAMA_PROVIDER_ID),
                "phoenix_model_id": str(MODEL_ID),
                "status": "operator_interrupted",
            }
        )
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
