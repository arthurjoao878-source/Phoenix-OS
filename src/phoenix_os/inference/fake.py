"""Deterministic network-free model provider for tests and examples."""

from __future__ import annotations

from collections.abc import AsyncIterator, Mapping

from phoenix_os.inference.contracts import (
    InferenceChunk,
    InferenceFinishReason,
    InferenceRequest,
    InferenceResponse,
    InferenceUsage,
    ModelCapabilities,
    ModelId,
    ModelProviderId,
    normalize_model_id,
    normalize_provider_id,
)
from phoenix_os.inference.errors import ModelNotFoundError, ModelProviderNotFoundError


class DeterministicModelProvider:
    """Return reviewed fixed text without network, credentials, or hidden state."""

    def __init__(
        self,
        responses: Mapping[ModelId | str, str],
        *,
        provider_id: ModelProviderId | str = "deterministic",
        chunk_characters: int = 8,
    ) -> None:
        self._provider_id = normalize_provider_id(provider_id)
        if isinstance(chunk_characters, bool) or not isinstance(chunk_characters, int):
            raise TypeError("chunk_characters must be an integer")
        if chunk_characters <= 0:
            raise ValueError("chunk_characters must be greater than zero")
        normalized: dict[ModelId, str] = {}
        for model, response in responses.items():
            model_id = normalize_model_id(model)
            if model_id in normalized:
                raise ValueError("responses contain a duplicate normalized model id")
            if not isinstance(response, str):
                raise TypeError("fake provider responses must be strings")
            normalized[model_id] = response
        if not normalized:
            raise ValueError("fake provider requires at least one model response")
        self._responses = normalized
        self._chunk_characters = chunk_characters
        self._requests: list[InferenceRequest] = []

    @property
    def provider_id(self) -> ModelProviderId:
        return self._provider_id

    @property
    def capabilities(self) -> ModelCapabilities:
        return ModelCapabilities(complete=True, streaming=True)

    @property
    def requests(self) -> tuple[InferenceRequest, ...]:
        return tuple(self._requests)

    async def infer(self, request: InferenceRequest) -> InferenceResponse:
        self._requests.append(request)
        return self._response_for(request)

    async def stream(self, request: InferenceRequest) -> AsyncIterator[InferenceChunk]:
        self._requests.append(request)
        response = self._response_for(request)
        index = 0
        for offset in range(0, len(response.text), self._chunk_characters):
            yield InferenceChunk(
                request_id=request.request_id,
                provider_id=request.provider_id,
                model_id=request.model_id,
                index=index,
                text=response.text[offset : offset + self._chunk_characters],
            )
            index += 1
        yield InferenceChunk(
            request_id=request.request_id,
            provider_id=request.provider_id,
            model_id=request.model_id,
            index=index,
            terminal=True,
            finish_reason=response.finish_reason,
            usage=response.usage,
        )

    def _response_for(self, request: InferenceRequest) -> InferenceResponse:
        if request.provider_id != self._provider_id:
            raise ModelProviderNotFoundError("request provider does not match adapter")
        try:
            configured = self._responses[request.model_id]
        except KeyError as exception:
            raise ModelNotFoundError("requested fake model is not configured") from exception

        words = configured.split()
        limited = words[: request.max_output_tokens]
        finish_reason = (
            InferenceFinishReason.LENGTH
            if len(words) > request.max_output_tokens
            else InferenceFinishReason.STOP
        )
        text = " ".join(limited)
        input_tokens = sum(max(1, len(message.content.split())) for message in request.messages)
        usage = InferenceUsage(
            input_tokens=input_tokens,
            output_tokens=len(limited),
        )
        return InferenceResponse(
            request_id=request.request_id,
            provider_id=request.provider_id,
            model_id=request.model_id,
            text=text,
            finish_reason=finish_reason,
            usage=usage,
            created_at=request.created_at,
            metadata={"provider": "deterministic"},
        )
