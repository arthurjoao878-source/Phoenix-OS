from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

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
    OllamaModelBinding,
    OllamaModelProvider,
)
from phoenix_os.inference.registry import ModelProviderRegistry
from phoenix_os.inference.service import InferenceService
from phoenix_os.policy import PrincipalType, SecurityContext
from phoenix_os.runtime import RuntimeContext

DURABLE_RUN_ID = DurableAgentRunId(UUID("13000000-0000-0000-0000-000000000038"))
AGENT_RUN_ID = AgentRunId(UUID("23000000-0000-0000-0000-000000000038"))
USER_TEXT = "bounded real-provider durable dogfood"
FINAL_TEXT = "durable ollama complete"


def _digest(character: str) -> CheckpointDigest:
    return CheckpointDigest(character * 64)


def _compatibility() -> CompatibilityDigests:
    return CompatibilityDigests(
        configuration=_digest("a"),
        tool_registry=_digest("b"),
        model_provider=_digest("c"),
        checkpoint_codec=_digest("d"),
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
        model_id=ModelId("qwen3-coder-30b"),
        provider_model_name="qwen3-coder:30b",
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
        model_id=ModelId("qwen3-coder-30b"),
        limits=AgentLimits(max_output_tokens=64),
    )


def _request(
    configuration: AgentServiceConfiguration,
    *,
    now: datetime,
) -> AgentRunRequest:
    return AgentRunRequest(
        agent_id=configuration.agent_id,
        provider_id=configuration.provider_id,
        model_id=configuration.model_id,
        messages=(AgentMessage(AgentMessageRole.USER, USER_TEXT),),
        limits=configuration.limits,
        run_id=AGENT_RUN_ID,
        created_at=now,
        deadline=now + timedelta(minutes=2),
    )


def _checkpoint(request: AgentRunRequest) -> CheckpointEnvelope:
    return seal_checkpoint_envelope(
        CheckpointEnvelope(
            schema_version=CheckpointSchemaVersion(),
            durable_run_id=DURABLE_RUN_ID,
            checkpoint_id=CheckpointId(UUID("53000000-0000-0000-0000-000000000038")),
            sequence=CheckpointSequence(1),
            previous_digest=None,
            run_version=DurableRunVersion(1),
            status=DurableRunStatus.ACTIVE,
            agent_run_id=request.run_id,
            step_id=None,
            metadata=CheckpointMetadata(
                agent_id=request.agent_id,
                actor_id="s5c2-real-provider-worker",
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
            digest=_digest("0"),
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
        assert request.run_id == AGENT_RUN_ID
        assert context.authenticated


class _ModelAuthorizer:
    def __init__(self) -> None:
        self.requests: list[InferenceRequest] = []

    async def authorize(
        self,
        request: InferenceRequest,
        context: SecurityContext,
    ) -> None:
        assert request.correlation_id == str(AGENT_RUN_ID)
        assert context.authenticated
        self.requests.append(request)


class _ToolAuthorizer:
    async def authorize(
        self,
        request: ToolInvocationRequest,
        descriptor: ToolDescriptor,
        context: SecurityContext,
    ) -> None:
        del request, descriptor, context
        raise AssertionError("real-provider final-output dogfood must not reach tools")


class _InferenceAuthorizer:
    def __init__(self) -> None:
        self.requests: list[InferenceRequest] = []

    async def authorize(
        self,
        request: InferenceRequest,
        context: SecurityContext,
    ) -> None:
        assert request.provider_id == OLLAMA_PROVIDER_ID
        assert request.model_id == ModelId("qwen3-coder-30b")
        assert context.authenticated
        self.requests.append(request)


class _FakeConnection:
    def __init__(self, response: bytes, *, read_limit: int) -> None:
        self._reader = asyncio.StreamReader(limit=read_limit)
        self._reader.feed_data(response)
        self._reader.feed_eof()
        self.written = bytearray()
        self.closed = False

    @property
    def reader(self) -> asyncio.StreamReader:
        return self._reader

    def write(self, data: bytes) -> None:
        self.written.extend(data)

    async def drain(self) -> None:
        await asyncio.sleep(0)

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        await asyncio.sleep(0)


class _FakeConnector:
    def __init__(self, response: bytes) -> None:
        self._response: bytes | None = response
        self.calls: list[tuple[str, int, float, int]] = []
        self.connections: list[_FakeConnection] = []

    async def connect(
        self,
        address: str,
        port: int,
        *,
        connect_timeout: float,
        read_limit: int,
    ) -> _FakeConnection:
        self.calls.append((address, port, connect_timeout, read_limit))
        if self._response is None:
            raise AssertionError("unexpected second Ollama transport submission")
        response = self._response
        self._response = None
        connection = _FakeConnection(response, read_limit=read_limit)
        self.connections.append(connection)
        return connection


def _ollama_response() -> bytes:
    body = json.dumps(
        {
            "model": "qwen3-coder:30b",
            "created_at": "2026-09-01T00:00:00Z",
            "message": {
                "role": "assistant",
                "content": json.dumps(
                    {
                        "version": 1,
                        "kind": "final",
                        "content": FINAL_TEXT,
                    },
                    separators=(",", ":"),
                ),
            },
            "done": True,
            "done_reason": "stop",
            "total_duration": 100,
            "load_duration": 10,
            "prompt_eval_count": 7,
            "prompt_eval_duration": 20,
            "eval_count": 4,
            "eval_duration": 30,
        },
        separators=(",", ":"),
    ).encode("utf-8")
    return (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: application/json\r\n"
        + f"Content-Length: {len(body)}\r\n".encode("ascii")
        + b"\r\n"
        + body
    )


def _inference_service(
    connector: _FakeConnector,
) -> tuple[
    InferenceService,
    ModelProviderRegistry,
    _InferenceAuthorizer,
]:
    provider_configuration = _provider_configuration()
    descriptor = _model_descriptor()
    provider = OllamaModelProvider(
        provider_configuration,
        (OllamaModelBinding(descriptor),),
        _connector=connector,
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
    return service, registry, authorizer


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


@pytest.mark.asyncio
async def test_durable_agent_executes_reviewed_ollama_provider_once_without_network() -> None:
    now = datetime.now(UTC)
    configuration = _configuration()
    request = _request(configuration, now=now)
    connector = _FakeConnector(_ollama_response())
    inference_service, _inference_registry, inference_authorizer = _inference_service(connector)
    agent_service, model_authorizer = _agent_service(
        configuration,
        inference_service,
        now=now,
    )

    store = InMemoryDurableRunStore()
    await store.create(_checkpoint(request))
    stack = create_durable_agent_runtime_stack(
        store=store,
        lease_manager=store.lease_manager,
        compatibility_validator=StaticDurableCompatibilityValidator(()),
    )
    lease = await store.lease_manager.acquire(
        DURABLE_RUN_ID,
        owner_id="s5c2-real-provider-worker",
        now=now,
    )
    driver = stack.create_model_turn_execution_driver(lease=lease)

    inference_context = RuntimeContext(services={"inference": inference_service})
    agent_context = RuntimeContext(services={})

    await inference_service.start(inference_context)
    await agent_service.start(agent_context)
    try:
        result = await agent_service.run(
            request,
            _context(),
            _model_turn_execution_driver=driver,
        )
    finally:
        await agent_service.stop(agent_context)
        await inference_service.stop(inference_context)

    try:
        assert result.status is AgentRunStatus.COMPLETED
        assert result.final_output == FINAL_TEXT

        assert len(model_authorizer.requests) >= 1
        assert len(inference_authorizer.requests) == 1
        runtime_request = inference_authorizer.requests[0]
        assert any(runtime_request is authorized for authorized in model_authorizer.requests)

        assert len(connector.calls) == 1
        assert connector.calls[0][0:2] == ("127.0.0.1", 11_434)
        assert len(connector.connections) == 1

        written = bytes(connector.connections[0].written)
        assert written.startswith(b"POST /api/chat HTTP/1.1\r\n")
        assert b'"model":"qwen3-coder:30b"' in written
        assert b'"stream":false' in written
        assert connector.connections[0].closed is True

        current = await store.get_current(DURABLE_RUN_ID)
        assert current is not None
        assert current.status is DurableRunStatus.ACTIVE
        assert current.metadata.next_operation is CheckpointNextOperation.COMPLETE
        attempt = current.metadata.active_attempt
        assert attempt is not None
        assert attempt.status is ExecutionAttemptStatus.SUCCEEDED
        assert attempt.error_code is None
        assert driver.last_checkpoint == current

        history = await store.list_history(DURABLE_RUN_ID, limit=16)
        durable_evidence = repr(history)
        assert USER_TEXT not in durable_evidence
        assert FINAL_TEXT not in durable_evidence
    finally:
        await stack.close()
