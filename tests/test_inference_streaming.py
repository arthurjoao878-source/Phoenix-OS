import asyncio
from collections.abc import AsyncIterator, Callable
from datetime import UTC, datetime, timedelta

import pytest

from phoenix_os.inference import (
    DeterministicModelProvider,
    InferenceChunk,
    InferenceExecutionLimits,
    InferenceFinishReason,
    InferenceLimitExceededError,
    InferenceLimits,
    InferenceMalformedOutputError,
    InferenceMessage,
    InferenceRequest,
    InferenceResponse,
    InferenceRole,
    InferenceRuntime,
    InferenceTimeoutError,
    InferenceUsage,
    ModelCapabilities,
    ModelDescriptor,
    ModelId,
    ModelProvider,
    ModelProviderExecutionError,
    ModelProviderId,
    ModelProviderRegistry,
)
from phoenix_os.policy import PrincipalType, SecurityContext


class AllowAuthorizer:
    async def authorize(
        self,
        request: InferenceRequest,
        context: SecurityContext,
    ) -> None:
        del request, context


type ChunkScript = Callable[[InferenceRequest], tuple[InferenceChunk, ...]]


class ScriptedStreamProvider:
    def __init__(
        self,
        script: ChunkScript,
        *,
        provider_id: str = "scripted",
        first_delay: float = 0,
        between_delay: float = 0,
    ) -> None:
        self._script = script
        self._provider_id = ModelProviderId(provider_id)
        self._first_delay = first_delay
        self._between_delay = between_delay
        self.calls = 0
        self.started = asyncio.Event()
        self.closed = asyncio.Event()

    @property
    def provider_id(self) -> ModelProviderId:
        return self._provider_id

    @property
    def capabilities(self) -> ModelCapabilities:
        return ModelCapabilities(complete=True, streaming=True)

    async def infer(self, request: InferenceRequest) -> InferenceResponse:
        del request
        raise AssertionError("complete inference is not used")

    async def stream(
        self,
        request: InferenceRequest,
    ) -> AsyncIterator[InferenceChunk]:
        self.calls += 1
        self.started.set()
        try:
            if self._first_delay:
                await asyncio.sleep(self._first_delay)
            for index, chunk in enumerate(self._script(request)):
                if index and self._between_delay:
                    await asyncio.sleep(self._between_delay)
                yield chunk
        finally:
            self.closed.set()


class FailingStreamProvider:
    def __init__(self) -> None:
        self._provider_id = ModelProviderId("failing-stream")
        self.calls = 0

    @property
    def provider_id(self) -> ModelProviderId:
        return self._provider_id

    @property
    def capabilities(self) -> ModelCapabilities:
        return ModelCapabilities(complete=True, streaming=True)

    async def infer(self, request: InferenceRequest) -> InferenceResponse:
        del request
        raise AssertionError("complete inference is not used")

    async def stream(
        self,
        request: InferenceRequest,
    ) -> AsyncIterator[InferenceChunk]:
        self.calls += 1
        raise RuntimeError("private streaming frame")
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
        principal="service:test",
        principal_type=PrincipalType.SERVICE,
        authenticated=True,
    )


def _request(provider_id: str = "scripted") -> InferenceRequest:
    now = datetime.now(UTC)
    return InferenceRequest(
        provider_id=ModelProviderId(provider_id),
        model_id=ModelId("chat"),
        messages=(InferenceMessage(InferenceRole.USER, "hello"),),
        max_output_tokens=8,
        created_at=now,
        deadline=now + timedelta(minutes=1),
    )


def _register(
    provider: ModelProvider,
    *,
    limits: InferenceLimits | None = None,
) -> ModelProviderRegistry:
    registry = ModelProviderRegistry()
    registry.register_provider(provider)
    registry.register_model(
        ModelDescriptor(
            provider_id=provider.provider_id,
            model_id=ModelId("chat"),
            provider_model_name="chat",
            capabilities=ModelCapabilities(complete=True, streaming=True),
            limits=InferenceLimits() if limits is None else limits,
        )
    )
    return registry


def _chunk(
    request: InferenceRequest,
    index: int,
    *,
    text: str = "",
    terminal: bool = False,
) -> InferenceChunk:
    return InferenceChunk(
        request_id=request.request_id,
        provider_id=request.provider_id,
        model_id=request.model_id,
        index=index,
        text=text,
        terminal=terminal,
        finish_reason=InferenceFinishReason.STOP if terminal else None,
        usage=(InferenceUsage(input_tokens=1, output_tokens=1) if terminal else None),
    )


@pytest.mark.asyncio
async def test_stream_yields_ordered_chunks_and_exactly_one_terminal() -> None:
    provider = DeterministicModelProvider(
        {"chat": "hello phoenix"},
        provider_id="deterministic",
        chunk_characters=5,
    )
    registry = _register(provider)
    runtime = InferenceRuntime(registry, AllowAuthorizer())
    request = _request("deterministic")

    chunks = [chunk async for chunk in runtime.stream(request, _context())]

    assert [chunk.index for chunk in chunks] == list(range(len(chunks)))
    assert sum(chunk.terminal for chunk in chunks) == 1
    assert chunks[-1].terminal is True
    assert "".join(chunk.text for chunk in chunks) == "hello phoenix"


@pytest.mark.asyncio
async def test_stream_rejects_out_of_order_chunks() -> None:
    provider = ScriptedStreamProvider(
        lambda request: (
            _chunk(request, 1, text="bad"),
            _chunk(request, 2, terminal=True),
        )
    )
    runtime = InferenceRuntime(_register(provider), AllowAuthorizer())

    with pytest.raises(InferenceMalformedOutputError):
        async for _chunk_value in runtime.stream(_request(), _context()):
            pass


@pytest.mark.asyncio
async def test_stream_rejects_missing_terminal_record() -> None:
    provider = ScriptedStreamProvider(lambda request: (_chunk(request, 0, text="partial"),))
    runtime = InferenceRuntime(_register(provider), AllowAuthorizer())

    with pytest.raises(InferenceMalformedOutputError):
        async for _chunk_value in runtime.stream(_request(), _context()):
            pass


@pytest.mark.asyncio
async def test_stream_rejects_records_after_terminal() -> None:
    provider = ScriptedStreamProvider(
        lambda request: (
            _chunk(request, 0, terminal=True),
            _chunk(request, 1, text="extra"),
        )
    )
    runtime = InferenceRuntime(_register(provider), AllowAuthorizer())

    with pytest.raises(InferenceMalformedOutputError):
        async for _chunk_value in runtime.stream(_request(), _context()):
            pass


@pytest.mark.asyncio
async def test_stream_enforces_first_byte_timeout_and_closes_adapter() -> None:
    provider = ScriptedStreamProvider(
        lambda request: (_chunk(request, 0, terminal=True),),
        first_delay=0.2,
    )
    runtime = InferenceRuntime(
        _register(provider),
        AllowAuthorizer(),
        execution_limits=InferenceExecutionLimits(
            first_byte_timeout=timedelta(milliseconds=20),
            total_timeout=timedelta(seconds=1),
            cancellation_grace=timedelta(milliseconds=100),
        ),
    )

    with pytest.raises(InferenceTimeoutError):
        async for _chunk_value in runtime.stream(_request(), _context()):
            pass

    await asyncio.wait_for(provider.closed.wait(), timeout=1)
    assert provider.calls == 1


@pytest.mark.asyncio
async def test_stream_enforces_total_duration_between_chunks() -> None:
    provider = ScriptedStreamProvider(
        lambda request: (
            _chunk(request, 0, text="a"),
            _chunk(request, 1, terminal=True),
        ),
        between_delay=0.2,
    )
    runtime = InferenceRuntime(
        _register(provider),
        AllowAuthorizer(),
        execution_limits=InferenceExecutionLimits(
            first_byte_timeout=timedelta(milliseconds=50),
            total_timeout=timedelta(milliseconds=50),
            cancellation_grace=timedelta(milliseconds=100),
        ),
    )
    stream = runtime.stream(_request(), _context())

    assert (await anext(stream)).text == "a"
    with pytest.raises(InferenceTimeoutError):
        await anext(stream)


@pytest.mark.asyncio
async def test_stream_enforces_chunk_count_and_utf8_byte_limits() -> None:
    count_provider = ScriptedStreamProvider(
        lambda request: (
            _chunk(request, 0, text="a"),
            _chunk(request, 1, text="b"),
            _chunk(request, 2, terminal=True),
        )
    )
    count_runtime = InferenceRuntime(
        _register(
            count_provider,
            limits=InferenceLimits(max_chunks=2),
        ),
        AllowAuthorizer(),
    )
    with pytest.raises(InferenceLimitExceededError):
        async for _chunk_value in count_runtime.stream(_request(), _context()):
            pass

    byte_provider = ScriptedStreamProvider(
        lambda request: (
            _chunk(request, 0, text="éé"),
            _chunk(request, 1, terminal=True),
        ),
        provider_id="byte-stream",
    )
    byte_runtime = InferenceRuntime(
        _register(byte_provider),
        AllowAuthorizer(),
        execution_limits=InferenceExecutionLimits(
            max_response_bytes=3,
            max_chunk_bytes=3,
        ),
    )
    with pytest.raises(InferenceLimitExceededError):
        async for _chunk_value in byte_runtime.stream(
            _request("byte-stream"),
            _context(),
        ):
            pass


@pytest.mark.asyncio
async def test_consumer_close_cooperatively_closes_provider_stream() -> None:
    provider = ScriptedStreamProvider(
        lambda request: (
            _chunk(request, 0, text="first"),
            _chunk(request, 1, text="second"),
            _chunk(request, 2, terminal=True),
        )
    )
    runtime = InferenceRuntime(_register(provider), AllowAuthorizer())
    stream = runtime.stream(_request(), _context())

    assert (await anext(stream)).text == "first"
    await stream.aclose()

    await asyncio.wait_for(provider.closed.wait(), timeout=1)


@pytest.mark.asyncio
async def test_caller_cancellation_closes_pending_provider_stream() -> None:
    provider = ScriptedStreamProvider(
        lambda request: (_chunk(request, 0, terminal=True),),
        first_delay=10,
    )
    runtime = InferenceRuntime(
        _register(provider),
        AllowAuthorizer(),
        execution_limits=InferenceExecutionLimits(
            first_byte_timeout=timedelta(seconds=5),
            total_timeout=timedelta(seconds=5),
            cancellation_grace=timedelta(milliseconds=100),
        ),
    )
    stream = runtime.stream(_request(), _context())
    pending = asyncio.create_task(anext(stream))

    await asyncio.wait_for(provider.started.wait(), timeout=1)
    pending.cancel()
    with pytest.raises(asyncio.CancelledError):
        await pending

    await asyncio.wait_for(provider.closed.wait(), timeout=1)
    await stream.aclose()


@pytest.mark.asyncio
async def test_stream_provider_failure_is_generic_and_not_retried() -> None:
    provider = FailingStreamProvider()
    runtime = InferenceRuntime(_register(provider), AllowAuthorizer())

    with pytest.raises(
        ModelProviderExecutionError,
        match="model provider execution failed",
    ) as captured:
        async for _chunk_value in runtime.stream(
            _request("failing-stream"),
            _context(),
        ):
            pass

    assert "private" not in str(captured.value)
    assert provider.calls == 1
