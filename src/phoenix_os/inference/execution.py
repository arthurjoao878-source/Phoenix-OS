"""Bounded complete and streaming inference execution."""

from __future__ import annotations

import asyncio
import inspect
from collections.abc import AsyncGenerator, AsyncIterator, Awaitable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import cast

from phoenix_os.inference.admission import InferenceAdmissionController
from phoenix_os.inference.authorization import InferenceAuthorizer
from phoenix_os.inference.contracts import (
    InferenceChunk,
    InferenceFinishReason,
    InferenceRequest,
    InferenceResponse,
    ModelDescriptor,
    ModelProvider,
    ensure_request_within_limits,
)
from phoenix_os.inference.errors import (
    InferenceCancelledError,
    InferenceEndpointRejectedError,
    InferenceLimitExceededError,
    InferenceMalformedOutputError,
    InferenceTimeoutError,
    ModelCapabilityMismatchError,
    ModelNotFoundError,
    ModelProviderExecutionError,
    ModelProviderNotFoundError,
)
from phoenix_os.inference.registry import ModelProviderRegistry
from phoenix_os.policy import SecurityContext

MAX_INFERENCE_EXECUTION_INPUT_BYTES = 4_194_304
MAX_INFERENCE_EXECUTION_RESPONSE_BYTES = 4_194_304
MAX_INFERENCE_EXECUTION_CHUNK_BYTES = 262_144
MAX_INFERENCE_FIRST_BYTE_TIMEOUT = timedelta(minutes=5)
MAX_INFERENCE_TOTAL_TIMEOUT = timedelta(hours=1)
MAX_INFERENCE_CANCELLATION_GRACE = timedelta(seconds=30)


def _require_duration(
    value: timedelta,
    *,
    label: str,
    maximum: timedelta,
) -> None:
    if not isinstance(value, timedelta):
        raise TypeError(f"{label} must be timedelta")
    if value <= timedelta(0):
        raise ValueError(f"{label} must be positive")
    if value > maximum:
        raise ValueError(f"{label} exceeds the supported maximum")


def _require_byte_limit(value: int, *, label: str, maximum: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{label} must be an integer")
    if value <= 0:
        raise ValueError(f"{label} must be greater than zero")
    if value > maximum:
        raise ValueError(f"{label} exceeds the supported maximum")


@dataclass(frozen=True, slots=True)
class InferenceExecutionLimits:
    """Finite execution, byte, deadline, and cleanup limits."""

    first_byte_timeout: timedelta = timedelta(seconds=10)
    total_timeout: timedelta = timedelta(seconds=60)
    cancellation_grace: timedelta = timedelta(seconds=1)
    max_input_bytes: int = 1_048_576
    max_response_bytes: int = 1_048_576
    max_chunk_bytes: int = 65_536

    def __post_init__(self) -> None:
        _require_duration(
            self.first_byte_timeout,
            label="first_byte_timeout",
            maximum=MAX_INFERENCE_FIRST_BYTE_TIMEOUT,
        )
        _require_duration(
            self.total_timeout,
            label="total_timeout",
            maximum=MAX_INFERENCE_TOTAL_TIMEOUT,
        )
        _require_duration(
            self.cancellation_grace,
            label="cancellation_grace",
            maximum=MAX_INFERENCE_CANCELLATION_GRACE,
        )
        if self.first_byte_timeout > self.total_timeout:
            raise ValueError("first_byte_timeout cannot exceed total_timeout")
        _require_byte_limit(
            self.max_input_bytes,
            label="max_input_bytes",
            maximum=MAX_INFERENCE_EXECUTION_INPUT_BYTES,
        )
        _require_byte_limit(
            self.max_response_bytes,
            label="max_response_bytes",
            maximum=MAX_INFERENCE_EXECUTION_RESPONSE_BYTES,
        )
        _require_byte_limit(
            self.max_chunk_bytes,
            label="max_chunk_bytes",
            maximum=MAX_INFERENCE_EXECUTION_CHUNK_BYTES,
        )
        if self.max_chunk_bytes > self.max_response_bytes:
            raise ValueError("max_chunk_bytes cannot exceed max_response_bytes")


class InferenceRuntime:
    """Authorize, admit, execute, validate, and never transparently retry."""

    def __init__(
        self,
        registry: ModelProviderRegistry,
        authorizer: InferenceAuthorizer,
        *,
        execution_limits: InferenceExecutionLimits | None = None,
        admission: InferenceAdmissionController | None = None,
    ) -> None:
        if not isinstance(registry, ModelProviderRegistry):
            raise TypeError("registry must be ModelProviderRegistry")
        if not callable(getattr(authorizer, "authorize", None)):
            raise TypeError("authorizer must provide an authorize method")
        self._registry = registry
        self._authorizer = authorizer
        self._execution_limits = (
            InferenceExecutionLimits() if execution_limits is None else execution_limits
        )
        if not isinstance(self._execution_limits, InferenceExecutionLimits):
            raise TypeError("execution_limits must be InferenceExecutionLimits")
        self._admission = InferenceAdmissionController() if admission is None else admission
        if not isinstance(self._admission, InferenceAdmissionController):
            raise TypeError("admission must be InferenceAdmissionController")

    @property
    def execution_limits(self) -> InferenceExecutionLimits:
        return self._execution_limits

    @property
    def admission(self) -> InferenceAdmissionController:
        return self._admission

    async def infer(
        self,
        request: InferenceRequest,
        context: SecurityContext,
    ) -> InferenceResponse:
        self._validate_inputs(request, context)
        await self._authorizer.authorize(request, context)
        provider, descriptor = self._resolve(request, streaming=False)
        self._validate_request(request, descriptor)

        async with self._admission.admit(request.provider_id, request.model_id):
            timeout = self._execution_timeout(request)
            try:
                response = await _await_with_timeout(
                    provider.infer(request),
                    timeout_seconds=timeout,
                    cancellation_grace=self._execution_limits.cancellation_grace.total_seconds(),
                )
            except (
                InferenceCancelledError,
                InferenceEndpointRejectedError,
                InferenceLimitExceededError,
                InferenceMalformedOutputError,
                InferenceTimeoutError,
            ):
                raise
            except asyncio.CancelledError:
                raise
            except Exception as exception:
                raise ModelProviderExecutionError() from exception

        return self._validate_response(response, request, descriptor)

    def stream(
        self,
        request: InferenceRequest,
        context: SecurityContext,
    ) -> AsyncGenerator[InferenceChunk, None]:
        self._validate_inputs(request, context)
        return self._stream(request, context)

    async def _stream(
        self,
        request: InferenceRequest,
        context: SecurityContext,
    ) -> AsyncGenerator[InferenceChunk, None]:
        await self._authorizer.authorize(request, context)
        provider, descriptor = self._resolve(request, streaming=True)
        self._validate_request(request, descriptor)

        async with self._admission.admit(request.provider_id, request.model_id):
            total_timeout = self._execution_timeout(request)
            total_deadline = asyncio.get_running_loop().time() + total_timeout
            try:
                iterator = provider.stream(request)
            except (
                InferenceCancelledError,
                InferenceEndpointRejectedError,
                InferenceLimitExceededError,
                InferenceMalformedOutputError,
                InferenceTimeoutError,
            ):
                raise
            except Exception as exception:
                raise ModelProviderExecutionError() from exception
            if not hasattr(iterator, "__anext__"):
                raise InferenceMalformedOutputError()

            expected_index = 0
            chunk_count = 0
            response_chars = 0
            response_bytes = 0
            first = True
            try:
                while True:
                    timeout = _remaining_seconds(total_deadline)
                    if first:
                        timeout = min(
                            timeout,
                            self._execution_limits.first_byte_timeout.total_seconds(),
                        )
                    try:
                        chunk = await _next_with_timeout(
                            iterator,
                            timeout_seconds=timeout,
                            cancellation_grace=(
                                self._execution_limits.cancellation_grace.total_seconds()
                            ),
                        )
                    except StopAsyncIteration as exception:
                        raise InferenceMalformedOutputError() from exception
                    except (
                        InferenceCancelledError,
                        InferenceEndpointRejectedError,
                        InferenceLimitExceededError,
                        InferenceMalformedOutputError,
                        InferenceTimeoutError,
                    ):
                        raise
                    except asyncio.CancelledError:
                        raise
                    except Exception as exception:
                        raise ModelProviderExecutionError() from exception
                    first = False

                    if not isinstance(chunk, InferenceChunk):
                        raise InferenceMalformedOutputError()
                    if (
                        chunk.request_id != request.request_id
                        or chunk.provider_id != request.provider_id
                        or chunk.model_id != request.model_id
                        or chunk.index != expected_index
                    ):
                        raise InferenceMalformedOutputError()

                    expected_index += 1
                    chunk_count += 1
                    response_chars += len(chunk.text)
                    encoded_bytes = len(chunk.text.encode("utf-8"))
                    response_bytes += encoded_bytes
                    if (
                        chunk_count > descriptor.limits.max_chunks
                        or len(chunk.text) > descriptor.limits.max_chunk_chars
                        or response_chars > descriptor.limits.max_response_chars
                        or encoded_bytes > self._execution_limits.max_chunk_bytes
                        or response_bytes > self._execution_limits.max_response_bytes
                    ):
                        raise InferenceLimitExceededError()

                    if not chunk.terminal:
                        yield chunk
                        continue

                    self._validate_terminal_chunk(chunk, request, descriptor)
                    try:
                        await _next_with_timeout(
                            iterator,
                            timeout_seconds=_remaining_seconds(total_deadline),
                            cancellation_grace=(
                                self._execution_limits.cancellation_grace.total_seconds()
                            ),
                        )
                    except StopAsyncIteration:
                        pass
                    except (
                        InferenceCancelledError,
                        InferenceEndpointRejectedError,
                        InferenceLimitExceededError,
                        InferenceMalformedOutputError,
                        InferenceTimeoutError,
                    ):
                        raise
                    except asyncio.CancelledError:
                        raise
                    except Exception as exception:
                        raise ModelProviderExecutionError() from exception
                    else:
                        raise InferenceMalformedOutputError()

                    _raise_for_finish_reason(chunk.finish_reason)
                    yield chunk
                    return
            finally:
                await _close_iterator(
                    iterator,
                    grace=self._execution_limits.cancellation_grace.total_seconds(),
                )

    def _validate_inputs(
        self,
        request: InferenceRequest,
        context: SecurityContext,
    ) -> None:
        if not isinstance(request, InferenceRequest):
            raise TypeError("request must be InferenceRequest")
        if not isinstance(context, SecurityContext):
            raise TypeError("context must be SecurityContext")

    def _resolve(
        self,
        request: InferenceRequest,
        *,
        streaming: bool,
    ) -> tuple[ModelProvider, ModelDescriptor]:
        try:
            descriptor = self._registry.resolve_model(
                request.provider_id,
                request.model_id,
            )
            provider = self._registry.resolve_provider(request.provider_id)
        except (ModelProviderNotFoundError, ModelNotFoundError) as exception:
            raise ModelProviderExecutionError() from exception

        supported = (
            descriptor.capabilities.streaming if streaming else descriptor.capabilities.complete
        )
        if not supported:
            raise ModelCapabilityMismatchError("requested inference mode is not supported")
        return provider, descriptor

    def _validate_request(
        self,
        request: InferenceRequest,
        descriptor: ModelDescriptor,
    ) -> None:
        try:
            ensure_request_within_limits(request, descriptor.limits)
        except (TypeError, ValueError) as exception:
            raise InferenceLimitExceededError() from exception
        input_bytes = sum(len(message.content.encode("utf-8")) for message in request.messages)
        if input_bytes > self._execution_limits.max_input_bytes:
            raise InferenceLimitExceededError()

    def _validate_response(
        self,
        response: object,
        request: InferenceRequest,
        descriptor: ModelDescriptor,
    ) -> InferenceResponse:
        if not isinstance(response, InferenceResponse):
            raise InferenceMalformedOutputError()
        if (
            response.request_id != request.request_id
            or response.provider_id != request.provider_id
            or response.model_id != request.model_id
        ):
            raise InferenceMalformedOutputError()
        if (
            len(response.text) > descriptor.limits.max_response_chars
            or len(response.text.encode("utf-8")) > self._execution_limits.max_response_bytes
        ):
            raise InferenceLimitExceededError()
        self._validate_usage(response.usage.output_tokens, request, descriptor)
        _raise_for_finish_reason(response.finish_reason)
        return response

    def _validate_terminal_chunk(
        self,
        chunk: InferenceChunk,
        request: InferenceRequest,
        descriptor: ModelDescriptor,
    ) -> None:
        if chunk.usage is None or chunk.finish_reason is None:
            raise InferenceMalformedOutputError()
        self._validate_usage(chunk.usage.output_tokens, request, descriptor)

    @staticmethod
    def _validate_usage(
        output_tokens: int,
        request: InferenceRequest,
        descriptor: ModelDescriptor,
    ) -> None:
        if (
            output_tokens > request.max_output_tokens
            or output_tokens > descriptor.limits.max_output_tokens
        ):
            raise InferenceLimitExceededError()

    def _execution_timeout(self, request: InferenceRequest) -> float:
        deadline_remaining = (request.deadline - datetime.now(UTC)).total_seconds()
        if deadline_remaining <= 0:
            raise InferenceTimeoutError()
        return min(
            deadline_remaining,
            self._execution_limits.total_timeout.total_seconds(),
        )


def _raise_for_finish_reason(
    finish_reason: InferenceFinishReason | None,
) -> None:
    if finish_reason is InferenceFinishReason.ERROR:
        raise ModelProviderExecutionError()
    if finish_reason is InferenceFinishReason.CANCELLED:
        raise InferenceCancelledError()


def _remaining_seconds(deadline: float) -> float:
    remaining = deadline - asyncio.get_running_loop().time()
    if remaining <= 0:
        raise InferenceTimeoutError()
    return remaining


async def _await_with_timeout[T](
    awaitable: Awaitable[T],
    *,
    timeout_seconds: float,
    cancellation_grace: float,
) -> T:
    future = asyncio.ensure_future(awaitable)
    try:
        return await asyncio.wait_for(
            asyncio.shield(future),
            timeout=timeout_seconds,
        )
    except TimeoutError as exception:
        await _cancel_future(future, grace=cancellation_grace)
        raise InferenceTimeoutError() from exception
    except asyncio.CancelledError:
        await _cancel_future(future, grace=cancellation_grace)
        raise


async def _next_with_timeout(
    iterator: AsyncIterator[InferenceChunk],
    *,
    timeout_seconds: float,
    cancellation_grace: float,
) -> InferenceChunk:
    return await _await_with_timeout(
        anext(iterator),
        timeout_seconds=timeout_seconds,
        cancellation_grace=cancellation_grace,
    )


async def _cancel_future[T](
    future: asyncio.Future[T],
    *,
    grace: float,
) -> None:
    if not future.done():
        future.cancel()
    done, _pending = await asyncio.wait({future}, timeout=grace)
    if future in done:
        _consume_future(future)
    else:
        future.add_done_callback(_consume_future)


def _consume_future[T](future: asyncio.Future[T]) -> None:
    if future.cancelled():
        return
    try:
        future.exception()
    except Exception:
        pass


async def _close_iterator(
    iterator: object,
    *,
    grace: float,
) -> None:
    close = getattr(iterator, "aclose", None)
    if not callable(close):
        return
    try:
        result = close()
    except Exception:
        return
    if not inspect.isawaitable(result):
        return
    future = asyncio.ensure_future(cast(Awaitable[object], result))
    done, _pending = await asyncio.wait({future}, timeout=grace)
    if future not in done:
        future.cancel()
        future.add_done_callback(_consume_future)
        return
    _consume_future(future)
