import asyncio
from collections.abc import AsyncIterator, Callable
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from phoenix_os.inference import (
    DeterministicModelProvider,
    InferenceAuthorizationRejectedError,
    InferenceCancelledError,
    InferenceChunk,
    InferenceEndpointRejectedError,
    InferenceEndpointRejectionCode,
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
    def __init__(self) -> None:
        self.requests: list[InferenceRequest] = []

    async def authorize(
        self,
        request: InferenceRequest,
        context: SecurityContext,
    ) -> None:
        del context
        self.requests.append(request)


class DenyAuthorizer:
    async def authorize(
        self,
        request: InferenceRequest,
        context: SecurityContext,
    ) -> None:
        del request, context
        raise InferenceAuthorizationRejectedError()


class FixedResponseProvider:
    def __init__(
        self,
        response_factory: Callable[[InferenceRequest], InferenceResponse],
        *,
        provider_id: str = "fixed",
    ) -> None:
        self._factory = response_factory
        self._provider_id = ModelProviderId(provider_id)
        self.calls = 0

    @property
    def provider_id(self) -> ModelProviderId:
        return self._provider_id

    @property
    def capabilities(self) -> ModelCapabilities:
        return ModelCapabilities(complete=True, streaming=True)

    async def infer(self, request: InferenceRequest) -> InferenceResponse:
        self.calls += 1
        response = self._factory(request)
        if not isinstance(response, InferenceResponse):
            raise TypeError("factory must return InferenceResponse")
        return response

    async def stream(
        self,
        request: InferenceRequest,
    ) -> AsyncIterator[InferenceChunk]:
        response = await self.infer(request)
        yield InferenceChunk(
            request_id=request.request_id,
            provider_id=request.provider_id,
            model_id=request.model_id,
            index=0,
            terminal=True,
            finish_reason=response.finish_reason,
            usage=response.usage,
        )


class BlockingProvider:
    def __init__(self) -> None:
        self._provider_id = ModelProviderId("blocking")
        self.calls = 0
        self.cancelled = asyncio.Event()

    @property
    def provider_id(self) -> ModelProviderId:
        return self._provider_id

    @property
    def capabilities(self) -> ModelCapabilities:
        return ModelCapabilities(complete=True, streaming=True)

    async def infer(self, request: InferenceRequest) -> InferenceResponse:
        del request
        self.calls += 1
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
        response = await self.infer(request)
        yield InferenceChunk(
            request_id=response.request_id,
            provider_id=response.provider_id,
            model_id=response.model_id,
            index=0,
            terminal=True,
            finish_reason=response.finish_reason,
            usage=response.usage,
        )


class FailingProvider:
    def __init__(self) -> None:
        self._provider_id = ModelProviderId("failing")
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
        raise RuntimeError("private provider body and secret")

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


class SafeRejectingProvider:
    def __init__(
        self,
        exception_factory: Callable[[], Exception],
        *,
        provider_id: str,
    ) -> None:
        self._exception_factory = exception_factory
        self._provider_id = ModelProviderId(provider_id)
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
        raise self._exception_factory()

    async def stream(
        self,
        request: InferenceRequest,
    ) -> AsyncIterator[InferenceChunk]:
        del request
        self.calls += 1
        raise self._exception_factory()
        if False:  # pragma: no cover
            yield InferenceChunk(
                request_id=uuid4(),
                provider_id=self.provider_id,
                model_id=ModelId("chat"),
                index=0,
            )


def _context() -> SecurityContext:
    return SecurityContext(
        principal="service:test",
        principal_type=PrincipalType.SERVICE,
        authenticated=True,
    )


def _request(
    provider_id: str,
    *,
    model_id: str = "chat",
    max_output_tokens: int = 8,
    created_at: datetime | None = None,
    deadline: datetime | None = None,
) -> InferenceRequest:
    now = datetime.now(UTC)
    created = now if created_at is None else created_at
    due = created + timedelta(minutes=1) if deadline is None else deadline
    return InferenceRequest(
        provider_id=ModelProviderId(provider_id),
        model_id=ModelId(model_id),
        messages=(InferenceMessage(InferenceRole.USER, "hello"),),
        max_output_tokens=max_output_tokens,
        created_at=created,
        deadline=due,
    )


def _register(
    provider: ModelProvider,
    *,
    limits: InferenceLimits | None = None,
) -> ModelProviderRegistry:
    registry = ModelProviderRegistry()
    registry.register_provider(provider)
    provider_id = provider.provider_id
    registry.register_model(
        ModelDescriptor(
            provider_id=provider_id,
            model_id=ModelId("chat"),
            provider_model_name="chat",
            capabilities=ModelCapabilities(complete=True, streaming=True),
            limits=InferenceLimits() if limits is None else limits,
        )
    )
    return registry


def _response(
    request: InferenceRequest,
    *,
    text: str = "ok",
    output_tokens: int = 1,
    finish_reason: InferenceFinishReason = InferenceFinishReason.STOP,
    wrong_request_id: bool = False,
) -> InferenceResponse:
    return InferenceResponse(
        request_id=uuid4() if wrong_request_id else request.request_id,
        provider_id=request.provider_id,
        model_id=request.model_id,
        text=text,
        finish_reason=finish_reason,
        usage=InferenceUsage(input_tokens=1, output_tokens=output_tokens),
    )


@pytest.mark.asyncio
async def test_complete_inference_authorizes_and_executes_once() -> None:
    provider = DeterministicModelProvider(
        {"chat": "hello from phoenix"},
        provider_id="deterministic",
    )
    authorizer = AllowAuthorizer()
    runtime = InferenceRuntime(_register(provider), authorizer)
    request = _request("deterministic")

    response = await runtime.infer(request, _context())

    assert response.text == "hello from phoenix"
    assert response.request_id == request.request_id
    assert authorizer.requests == [request]
    assert provider.requests == (request,)


@pytest.mark.asyncio
async def test_authorization_precedes_registry_resolution() -> None:
    request = _request("missing")
    runtime = InferenceRuntime(ModelProviderRegistry(), DenyAuthorizer())

    with pytest.raises(InferenceAuthorizationRejectedError):
        await runtime.infer(request, _context())


@pytest.mark.asyncio
async def test_authorized_missing_model_fails_without_enumeration() -> None:
    runtime = InferenceRuntime(ModelProviderRegistry(), AllowAuthorizer())

    with pytest.raises(
        ModelProviderExecutionError,
        match="model provider execution failed",
    ) as captured:
        await runtime.infer(_request("missing"), _context())

    assert "missing" not in str(captured.value)


@pytest.mark.asyncio
async def test_request_limits_fail_before_provider_execution() -> None:
    provider = DeterministicModelProvider(
        {"chat": "one two"},
        provider_id="deterministic",
    )
    limits = InferenceLimits(max_output_tokens=1)
    runtime = InferenceRuntime(_register(provider, limits=limits), AllowAuthorizer())

    with pytest.raises(InferenceLimitExceededError):
        await runtime.infer(
            _request("deterministic", max_output_tokens=2),
            _context(),
        )

    assert provider.requests == ()


@pytest.mark.asyncio
async def test_complete_response_identity_is_validated() -> None:
    provider = FixedResponseProvider(lambda request: _response(request, wrong_request_id=True))
    runtime = InferenceRuntime(_register(provider), AllowAuthorizer())

    with pytest.raises(InferenceMalformedOutputError):
        await runtime.infer(_request("fixed"), _context())

    assert provider.calls == 1


@pytest.mark.asyncio
async def test_complete_response_enforces_utf8_byte_limit() -> None:
    provider = FixedResponseProvider(lambda request: _response(request, text="éé"))
    runtime = InferenceRuntime(
        _register(provider),
        AllowAuthorizer(),
        execution_limits=InferenceExecutionLimits(
            max_response_bytes=3,
            max_chunk_bytes=3,
        ),
    )

    with pytest.raises(InferenceLimitExceededError):
        await runtime.infer(_request("fixed"), _context())


@pytest.mark.asyncio
async def test_complete_response_enforces_requested_token_limit() -> None:
    provider = FixedResponseProvider(lambda request: _response(request, output_tokens=3))
    runtime = InferenceRuntime(_register(provider), AllowAuthorizer())

    with pytest.raises(InferenceLimitExceededError):
        await runtime.infer(
            _request("fixed", max_output_tokens=2),
            _context(),
        )


@pytest.mark.asyncio
async def test_complete_timeout_cancels_provider_without_retry() -> None:
    provider = BlockingProvider()
    runtime = InferenceRuntime(
        _register(provider),
        AllowAuthorizer(),
        execution_limits=InferenceExecutionLimits(
            first_byte_timeout=timedelta(milliseconds=20),
            total_timeout=timedelta(milliseconds=20),
            cancellation_grace=timedelta(milliseconds=100),
        ),
    )

    with pytest.raises(InferenceTimeoutError):
        await runtime.infer(_request("blocking"), _context())

    await asyncio.wait_for(provider.cancelled.wait(), timeout=1)
    assert provider.calls == 1


@pytest.mark.asyncio
async def test_expired_deadline_rejects_before_provider_call() -> None:
    provider = DeterministicModelProvider(
        {"chat": "ok"},
        provider_id="deterministic",
    )
    runtime = InferenceRuntime(_register(provider), AllowAuthorizer())
    now = datetime.now(UTC)

    with pytest.raises(InferenceTimeoutError):
        await runtime.infer(
            _request(
                "deterministic",
                created_at=now - timedelta(seconds=2),
                deadline=now - timedelta(seconds=1),
            ),
            _context(),
        )

    assert provider.requests == ()


@pytest.mark.asyncio
async def test_provider_failure_is_generic_and_not_retried() -> None:
    provider = FailingProvider()
    runtime = InferenceRuntime(_register(provider), AllowAuthorizer())

    with pytest.raises(
        ModelProviderExecutionError,
        match="model provider execution failed",
    ) as captured:
        await runtime.infer(_request("failing"), _context())

    assert "private" not in str(captured.value)
    assert "secret" not in str(captured.value)
    assert provider.calls == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("exception_factory", "expected_type", "provider_id"),
    [
        (InferenceCancelledError, InferenceCancelledError, "safe-cancelled"),
        (
            lambda: InferenceEndpointRejectedError(
                InferenceEndpointRejectionCode.LOOPBACK_RESOLUTION_MISMATCH
            ),
            InferenceEndpointRejectedError,
            "safe-endpoint",
        ),
        (InferenceLimitExceededError, InferenceLimitExceededError, "safe-limit"),
        (InferenceMalformedOutputError, InferenceMalformedOutputError, "safe-malformed"),
    ],
)
async def test_provider_safe_complete_failures_preserve_public_category(
    exception_factory: Callable[[], Exception],
    expected_type: type[Exception],
    provider_id: str,
) -> None:
    provider = SafeRejectingProvider(exception_factory, provider_id=provider_id)
    runtime = InferenceRuntime(_register(provider), AllowAuthorizer())

    with pytest.raises(expected_type):
        await runtime.infer(_request(provider_id), _context())

    assert provider.calls == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("exception_factory", "expected_type", "provider_id"),
    [
        (InferenceCancelledError, InferenceCancelledError, "stream-cancelled"),
        (
            lambda: InferenceEndpointRejectedError(
                InferenceEndpointRejectionCode.LOOPBACK_RESOLUTION_MISMATCH
            ),
            InferenceEndpointRejectedError,
            "stream-endpoint",
        ),
        (InferenceLimitExceededError, InferenceLimitExceededError, "stream-limit"),
        (InferenceMalformedOutputError, InferenceMalformedOutputError, "stream-malformed"),
    ],
)
async def test_provider_safe_stream_failures_preserve_public_category(
    exception_factory: Callable[[], Exception],
    expected_type: type[Exception],
    provider_id: str,
) -> None:
    provider = SafeRejectingProvider(exception_factory, provider_id=provider_id)
    runtime = InferenceRuntime(_register(provider), AllowAuthorizer())

    with pytest.raises(expected_type):
        async for _chunk in runtime.stream(_request(provider_id), _context()):
            pass

    assert provider.calls == 1


@pytest.mark.asyncio
async def test_provider_cannot_impersonate_complete_authorization_rejection() -> None:
    provider = SafeRejectingProvider(
        InferenceAuthorizationRejectedError,
        provider_id="provider-auth-complete",
    )
    runtime = InferenceRuntime(_register(provider), AllowAuthorizer())

    with pytest.raises(ModelProviderExecutionError):
        await runtime.infer(_request("provider-auth-complete"), _context())

    assert provider.calls == 1


@pytest.mark.asyncio
async def test_provider_cannot_impersonate_stream_authorization_rejection() -> None:
    provider = SafeRejectingProvider(
        InferenceAuthorizationRejectedError,
        provider_id="provider-auth-stream",
    )
    runtime = InferenceRuntime(_register(provider), AllowAuthorizer())

    with pytest.raises(ModelProviderExecutionError):
        async for _chunk in runtime.stream(_request("provider-auth-stream"), _context()):
            pass

    assert provider.calls == 1


@pytest.mark.asyncio
async def test_provider_finish_categories_are_not_reported_as_success() -> None:
    cancelled = FixedResponseProvider(
        lambda request: _response(
            request,
            finish_reason=InferenceFinishReason.CANCELLED,
        )
    )
    errored = FixedResponseProvider(
        lambda request: _response(
            request,
            finish_reason=InferenceFinishReason.ERROR,
        ),
        provider_id="errored",
    )

    with pytest.raises(InferenceCancelledError):
        await InferenceRuntime(
            _register(cancelled),
            AllowAuthorizer(),
        ).infer(_request("fixed"), _context())

    with pytest.raises(ModelProviderExecutionError):
        await InferenceRuntime(
            _register(errored),
            AllowAuthorizer(),
        ).infer(_request("errored"), _context())


def _register_secondary_no_fallback_provider(
    registry: ModelProviderRegistry,
    provider: ModelProvider,
) -> None:
    registry.register_provider(provider)
    registry.register_model(
        ModelDescriptor(
            provider_id=provider.provider_id,
            model_id=ModelId("chat"),
            provider_model_name="chat",
            capabilities=ModelCapabilities(complete=True, streaming=True),
            limits=InferenceLimits(),
        )
    )


@pytest.mark.asyncio
async def test_complete_failure_never_falls_back_to_other_registered_provider() -> None:
    local_provider = FailingProvider()
    cloud_provider = FixedResponseProvider(
        lambda request: _response(request),
        provider_id="cloud-fallback-sentinel",
    )
    registry = _register(local_provider)
    _register_secondary_no_fallback_provider(registry, cloud_provider)
    runtime = InferenceRuntime(registry, AllowAuthorizer())

    with pytest.raises(ModelProviderExecutionError):
        await runtime.infer(_request("failing"), _context())

    assert local_provider.calls == 1
    assert cloud_provider.calls == 0


@pytest.mark.asyncio
async def test_stream_failure_never_falls_back_to_other_registered_provider() -> None:
    local_provider = FailingProvider()
    cloud_provider = FixedResponseProvider(
        lambda request: _response(request),
        provider_id="cloud-stream-fallback-sentinel",
    )
    registry = _register(local_provider)
    _register_secondary_no_fallback_provider(registry, cloud_provider)
    runtime = InferenceRuntime(registry, AllowAuthorizer())

    with pytest.raises(ModelProviderExecutionError):
        async for _chunk in runtime.stream(_request("failing"), _context()):
            pass

    assert local_provider.calls == 1
    assert cloud_provider.calls == 0
