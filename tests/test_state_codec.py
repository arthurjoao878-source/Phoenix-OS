import pytest

from phoenix_os import JsonStateCodec, SecretValue, StateSerializationError


def test_json_codec_is_deterministic_and_returns_fresh_values() -> None:
    codec = JsonStateCodec()
    first = codec.encode({"b": [2, 3], "a": 1})
    second = codec.encode({"a": 1, "b": (2, 3)})

    assert first == second == b'{"a":1,"b":[2,3]}'
    decoded = codec.decode(first)
    assert decoded == {"a": 1, "b": [2, 3]}
    assert isinstance(decoded, dict)


@pytest.mark.parametrize("value", [object(), b"bytes", {1: "non-string"}, float("inf")])
def test_json_codec_rejects_unsafe_or_unsupported_values(value: object) -> None:
    with pytest.raises(StateSerializationError):
        JsonStateCodec().encode(value)


def test_json_codec_rejects_secret_value_without_explicit_reveal() -> None:
    codec = JsonStateCodec()
    secret = SecretValue("token")

    with pytest.raises(StateSerializationError, match="revealed explicitly"):
        codec.encode(secret)
    assert codec.decode(codec.encode(secret.reveal(str))) == "token"


def test_json_codec_rejects_invalid_payload() -> None:
    with pytest.raises(StateSerializationError, match="UTF-8 JSON"):
        JsonStateCodec().decode(b"not-json")
