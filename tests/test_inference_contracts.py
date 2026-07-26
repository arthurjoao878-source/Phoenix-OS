from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from phoenix_os.inference import (
    MAX_INFERENCE_OUTPUT_TOKENS,
    InferenceChunk,
    InferenceFinishReason,
    InferenceLimits,
    InferenceMessage,
    InferenceRequest,
    InferenceResponse,
    InferenceRole,
    InferenceUsage,
    ModelCapabilities,
    ModelDescriptor,
    ModelId,
    ModelProviderId,
    ensure_request_within_limits,
)


def _request(**overrides: object) -> InferenceRequest:
    values: dict[str, object] = {
        "provider_id": ModelProviderId("local"),
        "model_id": ModelId("echo"),
        "messages": (InferenceMessage(InferenceRole.USER, "hello"),),
        "created_at": datetime(2026, 7, 26, 12, tzinfo=UTC),
        "deadline": datetime(2026, 7, 26, 12, 1, tzinfo=UTC),
    }
    values.update(overrides)
    return InferenceRequest(**values)  # type: ignore[arg-type]


def test_identifiers_normalize_and_reject_unsafe_values() -> None:
    assert str(ModelProviderId(" provider.one ")) == "provider.one"
    assert str(ModelId("model_1")) == "model_1"

    for value in ("", "UPPER", "has space", "/remote"):
        with pytest.raises(ValueError):
            ModelProviderId(value)


def test_message_and_request_freeze_caller_owned_collections() -> None:
    message_metadata = {"channel": "test"}
    parameters: dict[str, str | int | float | bool | None] = {"temperature": 0.0}
    request_metadata = {"tenant": "demo"}
    message = InferenceMessage(
        InferenceRole.USER,
        "hello",
        metadata=message_metadata,
    )
    request = _request(
        messages=[message],
        parameters=parameters,
        metadata=request_metadata,
    )

    message_metadata["channel"] = "changed"
    parameters["temperature"] = 1.0
    request_metadata["tenant"] = "changed"

    assert request.messages == (message,)
    assert request.messages[0].metadata == {"channel": "test"}
    assert request.parameters == {"temperature": 0.0}
    assert request.metadata == {"tenant": "demo"}
    with pytest.raises(TypeError):
        request.metadata["new"] = "value"  # type: ignore[index]


def test_request_validates_messages_deadline_and_output_budget() -> None:
    with pytest.raises(ValueError, match="messages"):
        _request(messages=())
    with pytest.raises(ValueError, match="deadline"):
        _request(deadline=datetime(2026, 7, 26, 11, 59, tzinfo=UTC))
    with pytest.raises(ValueError, match="timezone-aware"):
        _request(deadline=datetime(2026, 7, 26, 12, 1))
    with pytest.raises(ValueError, match="max_output_tokens"):
        _request(max_output_tokens=MAX_INFERENCE_OUTPUT_TOKENS + 1)


def test_limits_are_finite_and_composable() -> None:
    provider = InferenceLimits(max_output_tokens=1024)
    model = InferenceLimits(max_output_tokens=512)

    assert provider.contains(model)
    assert not model.contains(provider)
    with pytest.raises(ValueError, match="max_messages"):
        InferenceLimits(max_messages=0)
    with pytest.raises(ValueError, match="max_message_chars"):
        InferenceLimits(max_message_chars=100, max_total_input_chars=50)


def test_model_descriptor_is_immutable_and_validates_capabilities() -> None:
    descriptor = ModelDescriptor(
        provider_id=ModelProviderId("fake"),
        model_id=ModelId("chat"),
        provider_model_name=" provider/chat ",
        capabilities=ModelCapabilities(complete=True, streaming=True),
        metadata={"tier": "test"},
    )

    assert descriptor.provider_model_name == "provider/chat"
    assert descriptor.metadata == {"tier": "test"}
    with pytest.raises(FrozenInstanceError):
        descriptor.provider_model_name = "changed"  # type: ignore[misc]
    with pytest.raises(ValueError, match="at least one"):
        ModelCapabilities(complete=False, streaming=False)


def test_response_and_terminal_chunk_contracts() -> None:
    request = _request()
    usage = InferenceUsage(input_tokens=1, output_tokens=2)
    response = InferenceResponse(
        request_id=request.request_id,
        provider_id=request.provider_id,
        model_id=request.model_id,
        text="hello back",
        finish_reason=InferenceFinishReason.STOP,
        usage=usage,
        created_at=request.created_at,
    )
    terminal = InferenceChunk(
        request_id=request.request_id,
        provider_id=request.provider_id,
        model_id=request.model_id,
        index=1,
        terminal=True,
        finish_reason=InferenceFinishReason.STOP,
        usage=usage,
    )

    assert response.usage.total_tokens == 3
    assert terminal.terminal is True
    with pytest.raises(ValueError, match="finish_reason"):
        InferenceChunk(
            request_id=request.request_id,
            provider_id=request.provider_id,
            model_id=request.model_id,
            index=0,
            terminal=True,
            usage=usage,
        )
    with pytest.raises(ValueError, match="non-terminal"):
        InferenceChunk(
            request_id=request.request_id,
            provider_id=request.provider_id,
            model_id=request.model_id,
            index=0,
            finish_reason=InferenceFinishReason.STOP,
        )


def test_usage_rejects_negative_or_inconsistent_counts() -> None:
    with pytest.raises(ValueError, match="negative"):
        InferenceUsage(input_tokens=-1, output_tokens=0)
    with pytest.raises(ValueError, match="cached"):
        InferenceUsage(input_tokens=1, output_tokens=0, cached_input_tokens=2)


def test_request_model_limit_validation() -> None:
    request = _request(max_output_tokens=20)
    ensure_request_within_limits(request, InferenceLimits(max_output_tokens=20))

    with pytest.raises(ValueError, match="output token"):
        ensure_request_within_limits(
            request,
            InferenceLimits(max_output_tokens=10),
        )


def test_request_uses_stable_uuid_and_timezone_aware_timestamps() -> None:
    request = _request()

    assert isinstance(request.request_id, UUID)
    assert request.created_at.utcoffset() == timedelta(0)
