import asyncio
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta

import pytest

from phoenix_os.audit import AuditLedger, AuditQuery, InMemoryAuditStore
from phoenix_os.events import Event, EventBus
from phoenix_os.inference import (
    DeterministicModelProvider,
    InferenceChunk,
    InferenceExecutionLimits,
    InferenceFinishReason,
    InferenceMessage,
    InferenceProviderConfiguration,
    InferenceRequest,
    InferenceResponse,
    InferenceRole,
    InferenceService,
    InferenceServiceConfiguration,
    InferenceServiceState,
    InferenceServiceUnavailableError,
    InferenceUsage,
    ModelCapabilities,
    ModelDescriptor,
    ModelId,
    ModelProviderId,
    create_inference_runtime_stack,
    inference_model_resource,
)
from phoenix_os.observability import InMemorySink, ObservabilityHub
from phoenix_os.policy import (
    PolicyEffect,
    PolicyEngine,
    PolicyRule,
    PrincipalType,
    SecurityContext,
)
from phoenix_os.runtime import RuntimeContext


class BlockingProvider:
    def __init__(self) -> None:
        self._provider_id = ModelProviderId("blocking")
        self.started = asyncio.Event()
        self.cancelled = asyncio.Event()
        self.calls = 0

    @property
    def provider_id(self) -> ModelProviderId:
        return self._provider_id

    @property
    def capabilities(self) -> ModelCapabilities:
        return ModelCapabilities(complete=True, streaming=True)

    async def infer(self, request: InferenceRequest) -> InferenceResponse:
        del request
        self.calls += 1
        self.started.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            self.cancelled.set()
            raise
        raise AssertionError("unreachable")

    async def stream(
        self,
        request: InferenceRequest,
    ) -> AsyncIterator[InferenceChunk]:
        await self.infer(request)
        if False:  # pragma: no cover
            yield InferenceChunk(
                request_id=request.request_id,
                provider_id=request.provider_id,
                model_id=request.model_id,
                index=0,
                terminal=True,
                finish_reason=InferenceFinishReason.ERROR,
                usage=InferenceUsage(input_tokens=0, output_tokens=0),
            )


def _context() -> SecurityContext:
    return SecurityContext(
        principal="service:assistant",
        principal_type=PrincipalType.SERVICE,
        authenticated=True,
        correlation_id="corr-inference",
    )


def _runtime_context() -> RuntimeContext:
    return RuntimeContext(services={})


def _request(
    provider: str = "deterministic",
    *,
    prompt: str = "hello",
) -> InferenceRequest:
    now = datetime.now(UTC)
    return InferenceRequest(
        provider_id=ModelProviderId(provider),
        model_id=ModelId("chat"),
        messages=(InferenceMessage(InferenceRole.USER, prompt),),
        max_output_tokens=16,
        created_at=now,
        deadline=now + timedelta(minutes=1),
        correlation_id="corr-inference",
    )


def _policy(provider: str = "deterministic") -> PolicyEngine:
    return PolicyEngine(
        (
            PolicyRule(
                rule_id=f"allow.{provider}.chat",
                effect=PolicyEffect.ALLOW,
                actions=frozenset({"model.infer"}),
                resources=frozenset(
                    {
                        inference_model_resource(
                            ModelProviderId(provider),
                            ModelId("chat"),
                        )
                    }
                ),
                principals=frozenset({"service:assistant"}),
                authenticated=True,
            ),
        )
    )


def _configuration(
    provider: str = "deterministic",
    *,
    drain_timeout: timedelta = timedelta(seconds=1),
    execution_limits: InferenceExecutionLimits | None = None,
) -> InferenceServiceConfiguration:
    return InferenceServiceConfiguration(
        providers=(InferenceProviderConfiguration(ModelProviderId(provider)),),
        models=(
            ModelDescriptor(
                provider_id=ModelProviderId(provider),
                model_id=ModelId("chat"),
                provider_model_name="chat",
                capabilities=ModelCapabilities(complete=True, streaming=True),
            ),
        ),
        drain_timeout=drain_timeout,
        execution_limits=(
            InferenceExecutionLimits() if execution_limits is None else execution_limits
        ),
    )


def _service(
    provider: DeterministicModelProvider,
    *,
    events: EventBus | None = None,
    audit: AuditLedger | None = None,
    observability: ObservabilityHub | None = None,
) -> InferenceService:
    stack = create_inference_runtime_stack(
        configuration=_configuration(str(provider.provider_id)),
        providers=(provider,),
        policy=_policy(str(provider.provider_id)),
        events=EventBus() if events is None else events,
        audit=audit,
        observability=observability,
    )
    return stack.service


@pytest.mark.asyncio
async def test_service_lifecycle_and_health_snapshot() -> None:
    service = _service(
        DeterministicModelProvider(
            {"chat": "hello phoenix"},
            provider_id="deterministic",
        )
    )

    created = await service.snapshot()
    assert created.state is InferenceServiceState.CREATED
    assert created.accepting is False
    assert created.providers == 1
    assert created.models == 1

    await service.start(_runtime_context())
    response = await service.infer(_request(), _context())
    running = await service.snapshot()

    assert response.text == "hello phoenix"
    assert running.state is InferenceServiceState.RUNNING
    assert running.accepting is True
    assert running.active == 0
    assert running.started == 1
    assert running.completed == 1
    assert running.failed == 0

    await service.stop(_runtime_context())
    stopped = await service.snapshot()
    assert stopped.state is InferenceServiceState.STOPPED
    assert stopped.accepting is False


@pytest.mark.asyncio
async def test_service_rejects_invocations_outside_running_lifecycle() -> None:
    service = _service(
        DeterministicModelProvider(
            {"chat": "ok"},
            provider_id="deterministic",
        )
    )

    with pytest.raises(InferenceServiceUnavailableError):
        await service.infer(_request(), _context())

    await service.start(_runtime_context())
    await service.stop(_runtime_context())

    with pytest.raises(InferenceServiceUnavailableError):
        await service.infer(_request(), _context())


@pytest.mark.asyncio
async def test_complete_and_streaming_signals_never_include_content() -> None:
    prompt = "TOP-SECRET-PROMPT-4782"
    response_text = "TOP-SECRET-RESPONSE-9231"
    events = EventBus()
    observed_events: list[Event] = []

    async def record_event(event: Event) -> None:
        if event.name.startswith("inference."):
            observed_events.append(event)

    await events.subscribe("*", record_event)
    audit_store = InMemoryAuditStore()
    audit = AuditLedger(audit_store)
    sink = InMemorySink(capacity=200)
    observability = ObservabilityHub((sink,))
    service = _service(
        DeterministicModelProvider(
            {"chat": response_text},
            provider_id="deterministic",
            chunk_characters=4,
        ),
        events=events,
        audit=audit,
        observability=observability,
    )
    await service.start(_runtime_context())

    response = await service.infer(
        _request(prompt=prompt),
        _context(),
    )
    chunks = [
        chunk
        async for chunk in service.stream(
            _request(prompt=prompt),
            _context(),
        )
    ]

    assert response.text == response_text
    assert "".join(chunk.text for chunk in chunks) == response_text
    assert all(event.payload == {} for event in observed_events)

    audit_records = await audit_store.read(AuditQuery(limit=1000))
    observations = (await sink.snapshot()).records
    serialized = repr((observed_events, audit_records, observations))

    assert prompt not in serialized
    assert response_text not in serialized
    assert "request_id" in serialized
    assert "provider_id" in serialized
    assert "model_id" in serialized

    snapshot = await service.snapshot()
    assert snapshot.started == 2
    assert snapshot.completed == 2
    await service.stop(_runtime_context())


@pytest.mark.asyncio
async def test_shutdown_drains_then_cancels_active_provider_work() -> None:
    provider = BlockingProvider()
    configuration = _configuration(
        "blocking",
        drain_timeout=timedelta(milliseconds=20),
        execution_limits=InferenceExecutionLimits(
            first_byte_timeout=timedelta(seconds=5),
            total_timeout=timedelta(seconds=5),
            cancellation_grace=timedelta(milliseconds=100),
        ),
    )
    stack = create_inference_runtime_stack(
        configuration=configuration,
        providers=(provider,),
        policy=_policy("blocking"),
        events=EventBus(),
    )
    service = stack.service
    await service.start(_runtime_context())
    invocation = asyncio.create_task(
        service.infer(
            _request("blocking"),
            _context(),
        )
    )

    await asyncio.wait_for(provider.started.wait(), timeout=1)
    await service.stop(_runtime_context())

    with pytest.raises(asyncio.CancelledError):
        await invocation
    await asyncio.wait_for(provider.cancelled.wait(), timeout=1)

    snapshot = await service.snapshot()
    assert snapshot.state is InferenceServiceState.STOPPED
    assert snapshot.active == 0
    assert snapshot.cancelled == 1
    assert snapshot.forced_cancellations == 1
    assert provider.calls == 1


@pytest.mark.asyncio
async def test_stream_consumer_close_is_recorded_as_cancellation() -> None:
    service = _service(
        DeterministicModelProvider(
            {"chat": "abcdefgh"},
            provider_id="deterministic",
            chunk_characters=2,
        )
    )
    await service.start(_runtime_context())
    stream = service.stream(_request(), _context())

    assert (await anext(stream)).text == "ab"
    await stream.aclose()

    snapshot = await service.snapshot()
    assert snapshot.started == 1
    assert snapshot.cancelled == 1
    assert snapshot.completed == 0
    await service.stop(_runtime_context())
