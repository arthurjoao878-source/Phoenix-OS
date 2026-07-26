from datetime import UTC, datetime

import pytest

from phoenix_os.inference import (
    DeterministicModelProvider,
    InferenceFinishReason,
    InferenceMessage,
    InferenceRequest,
    InferenceRole,
    ModelId,
    ModelNotFoundError,
    ModelProviderId,
    ModelProviderNotFoundError,
)


def _request(
    *,
    provider: str = "fake",
    model: str = "chat",
    max_output_tokens: int = 32,
) -> InferenceRequest:
    return InferenceRequest(
        provider_id=ModelProviderId(provider),
        model_id=ModelId(model),
        messages=(
            InferenceMessage(InferenceRole.SYSTEM, "be concise"),
            InferenceMessage(InferenceRole.USER, "hello world"),
        ),
        max_output_tokens=max_output_tokens,
        created_at=datetime(2026, 7, 26, 12, tzinfo=UTC),
        deadline=datetime(2026, 7, 26, 12, 1, tzinfo=UTC),
    )


@pytest.mark.asyncio
async def test_fake_complete_inference_is_deterministic_and_network_free() -> None:
    provider = DeterministicModelProvider(
        {"chat": "deterministic response"},
        provider_id="fake",
    )
    request = _request()

    first = await provider.infer(request)
    second = await provider.infer(request)

    assert first == second
    assert first.text == "deterministic response"
    assert first.finish_reason is InferenceFinishReason.STOP
    assert first.usage.input_tokens == 4
    assert first.usage.output_tokens == 2
    assert first.created_at == request.created_at
    assert provider.requests == (request, request)


@pytest.mark.asyncio
async def test_fake_provider_applies_output_budget_deterministically() -> None:
    provider = DeterministicModelProvider(
        {"chat": "one two three four"},
        provider_id="fake",
    )

    response = await provider.infer(_request(max_output_tokens=2))

    assert response.text == "one two"
    assert response.finish_reason is InferenceFinishReason.LENGTH
    assert response.usage.output_tokens == 2


@pytest.mark.asyncio
async def test_fake_stream_is_ordered_and_has_one_terminal_record() -> None:
    provider = DeterministicModelProvider(
        {"chat": "abcdefghij"},
        provider_id="fake",
        chunk_characters=4,
    )
    request = _request()
    chunks = [chunk async for chunk in provider.stream(request)]

    assert [chunk.index for chunk in chunks] == [0, 1, 2, 3]
    assert "".join(chunk.text for chunk in chunks[:-1]) == "abcdefghij"
    assert all(not chunk.terminal for chunk in chunks[:-1])
    assert chunks[-1].terminal is True
    assert chunks[-1].finish_reason is InferenceFinishReason.STOP
    assert chunks[-1].usage is not None
    assert provider.requests == (request,)


@pytest.mark.asyncio
async def test_fake_provider_rejects_wrong_provider_or_model() -> None:
    provider = DeterministicModelProvider({"chat": "hello"}, provider_id="fake")

    with pytest.raises(ModelProviderNotFoundError):
        await provider.infer(_request(provider="other"))
    with pytest.raises(ModelNotFoundError):
        await provider.infer(_request(model="missing"))


def test_fake_provider_rejects_empty_or_duplicate_configuration() -> None:
    with pytest.raises(ValueError, match="at least one"):
        DeterministicModelProvider({})
    with pytest.raises(ValueError, match="duplicate"):
        DeterministicModelProvider(
            {
                ModelId("chat"): "one",
                "chat": "two",
            }
        )
