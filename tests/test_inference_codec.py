import json
from datetime import UTC, datetime

import pytest

from phoenix_os.inference import (
    MAX_INFERENCE_REQUEST_DOCUMENT_BYTES,
    InferenceChunk,
    InferenceCodecError,
    InferenceFinishReason,
    InferenceMessage,
    InferenceRequest,
    InferenceResponse,
    InferenceRole,
    InferenceUsage,
    ModelId,
    ModelProviderId,
    decode_inference_chunk,
    decode_inference_request,
    decode_inference_response,
    encode_inference_chunk,
    encode_inference_request,
    encode_inference_response,
)


def _request() -> InferenceRequest:
    return InferenceRequest(
        provider_id=ModelProviderId("fake"),
        model_id=ModelId("chat"),
        messages=(
            InferenceMessage(
                InferenceRole.USER,
                "hello",
                metadata={"channel": "test"},
            ),
        ),
        max_output_tokens=12,
        parameters={"temperature": 0.0, "seed": 7},
        metadata={"tenant": "demo"},
        correlation_id="correlation-1",
        created_at=datetime(2026, 7, 26, 12, tzinfo=UTC),
        deadline=datetime(2026, 7, 26, 12, 1, tzinfo=UTC),
    )


def _response(request: InferenceRequest) -> InferenceResponse:
    return InferenceResponse(
        request_id=request.request_id,
        provider_id=request.provider_id,
        model_id=request.model_id,
        text="hello back",
        finish_reason=InferenceFinishReason.STOP,
        usage=InferenceUsage(input_tokens=1, output_tokens=2),
        created_at=request.created_at,
        metadata={"provider": "fake"},
    )


def test_request_codec_is_canonical_and_round_trips() -> None:
    request = _request()
    encoded = encode_inference_request(request)

    assert encoded == encode_inference_request(request)
    assert decode_inference_request(encoded) == request
    assert encoded.startswith(b'{"kind":"phoenix.inference.request"')


def test_response_and_chunk_codecs_round_trip() -> None:
    request = _request()
    response = _response(request)
    chunk = InferenceChunk(
        request_id=request.request_id,
        provider_id=request.provider_id,
        model_id=request.model_id,
        index=0,
        terminal=True,
        finish_reason=InferenceFinishReason.STOP,
        usage=response.usage,
        metadata={"provider": "fake"},
    )

    assert decode_inference_response(encode_inference_response(response)) == response
    assert decode_inference_chunk(encode_inference_chunk(chunk)) == chunk


def test_decoder_rejects_noncanonical_json() -> None:
    canonical = encode_inference_request(_request())
    document = json.loads(canonical)
    noncanonical = json.dumps(document, indent=2).encode()

    with pytest.raises(InferenceCodecError, match="canonical"):
        decode_inference_request(noncanonical)


def test_decoder_rejects_unknown_or_missing_fields() -> None:
    document = json.loads(encode_inference_request(_request()))
    document["record"]["unexpected"] = True
    encoded = json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()

    with pytest.raises(InferenceCodecError, match="fields"):
        decode_inference_request(encoded)


def test_decoder_rejects_wrong_kind_and_malformed_input() -> None:
    request = _request()

    with pytest.raises(InferenceCodecError, match="kind"):
        decode_inference_response(encode_inference_request(request))
    with pytest.raises(InferenceCodecError):
        decode_inference_request(b"not-json")
    with pytest.raises(InferenceCodecError):
        decode_inference_request(b"")


def test_decoder_rejects_oversized_document_before_parsing() -> None:
    encoded = b"{" + b"x" * MAX_INFERENCE_REQUEST_DOCUMENT_BYTES

    with pytest.raises(InferenceCodecError):
        decode_inference_request(encoded)


def test_decoder_rejects_non_scalar_parameters() -> None:
    document = json.loads(encode_inference_request(_request()))
    document["record"]["parameters"]["nested"] = {"unsafe": True}
    encoded = json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()

    with pytest.raises(InferenceCodecError, match="scalar"):
        decode_inference_request(encoded)
