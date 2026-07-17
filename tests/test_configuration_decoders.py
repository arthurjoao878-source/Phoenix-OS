from pathlib import Path

import pytest

from phoenix_os.configuration import (
    as_boolean,
    as_csv,
    as_float,
    as_integer,
    as_non_empty_string,
    as_path,
    as_string,
    non_negative,
    one_of,
    positive,
)


def test_string_decoders_are_strict() -> None:
    assert as_string(" value ") == " value "
    assert as_non_empty_string(" value ") == "value"
    with pytest.raises(TypeError):
        as_string(1)
    with pytest.raises(ValueError):
        as_non_empty_string("   ")


@pytest.mark.parametrize(("raw", "expected"), [(7, 7), (" 42 ", 42), (-3, -3)])
def test_integer_decoder(raw: object, expected: int) -> None:
    assert as_integer(raw) == expected


@pytest.mark.parametrize("raw", [True, 1.5, object()])
def test_integer_decoder_rejects_unsafe_coercions(raw: object) -> None:
    with pytest.raises((TypeError, ValueError)):
        as_integer(raw)


@pytest.mark.parametrize(("raw", "expected"), [(1, 1.0), ("1.25", 1.25), (2.5, 2.5)])
def test_float_decoder(raw: object, expected: float) -> None:
    assert as_float(raw) == expected


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (True, True),
        (False, False),
        (1, True),
        (0, False),
        ("YES", True),
        ("off", False),
    ],
)
def test_boolean_decoder(raw: object, expected: bool) -> None:
    assert as_boolean(raw) is expected


def test_boolean_decoder_rejects_ambiguous_values() -> None:
    with pytest.raises(ValueError):
        as_boolean("maybe")
    with pytest.raises(ValueError):
        as_boolean(2)


def test_csv_decoder_supports_text_and_sequences() -> None:
    assert as_csv("a, b,,c") == ("a", "b", "c")
    assert as_csv([" a ", "b"]) == ("a", "b")
    with pytest.raises(TypeError):
        as_csv(["a", 2])


def test_path_and_validators() -> None:
    assert as_path(" ./config.json ") == Path("config.json")
    assert positive(0.1) is True
    assert positive(0) is False
    assert non_negative(0) is True
    assert non_negative(-1) is False
    assert one_of("dev", "prod")("dev") is True
    assert one_of("dev", "prod")("test") is False
    with pytest.raises(ValueError):
        one_of()
