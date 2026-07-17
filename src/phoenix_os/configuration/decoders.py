"""Strict, dependency-free decoders for common configuration types."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path


def as_string(value: object) -> str:
    """Decode a string without silently coercing unrelated values."""

    if not isinstance(value, str):
        raise TypeError("expected a string")
    return value


def as_non_empty_string(value: object) -> str:
    """Decode and trim a non-empty string."""

    decoded = as_string(value).strip()
    if not decoded:
        raise ValueError("expected a non-empty string")
    return decoded


def as_integer(value: object) -> int:
    """Decode an integer while rejecting booleans and fractional values."""

    if isinstance(value, bool):
        raise TypeError("booleans are not integers")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value.strip())
    raise TypeError("expected an integer or integer string")


def as_float(value: object) -> float:
    """Decode a floating-point value while rejecting booleans."""

    if isinstance(value, bool):
        raise TypeError("booleans are not numbers")
    if isinstance(value, (int, float, str)):
        return float(value)
    raise TypeError("expected a number or numeric string")


def as_boolean(value: object) -> bool:
    """Decode conventional boolean representations deterministically."""

    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in {0, 1}:
        return bool(value)
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "on"}:
            return True
        if normalized in {"0", "false", "no", "off"}:
            return False
    raise ValueError("expected a boolean value")


def as_path(value: object) -> Path:
    """Decode a path without touching the filesystem."""

    return Path(as_non_empty_string(value))


def as_csv(value: object) -> tuple[str, ...]:
    """Decode a comma-separated string or a sequence of strings."""

    if isinstance(value, str):
        items = value.split(",")
    elif isinstance(value, (list, tuple)):
        items = list(value)
    else:
        raise TypeError("expected CSV text or a string sequence")

    result: list[str] = []
    for item in items:
        if not isinstance(item, str):
            raise TypeError("CSV items must be strings")
        normalized = item.strip()
        if normalized:
            result.append(normalized)
    return tuple(result)


def one_of(*allowed: str) -> Callable[[object], bool]:
    """Create a validator that accepts one of the supplied string values."""

    accepted = frozenset(allowed)
    if not accepted:
        raise ValueError("at least one allowed value is required")
    return lambda value: isinstance(value, str) and value in accepted


def positive(value: object) -> bool:
    """Validate a positive integer or float."""

    return isinstance(value, (int, float)) and not isinstance(value, bool) and value > 0


def non_negative(value: object) -> bool:
    """Validate a non-negative integer or float."""

    return isinstance(value, (int, float)) and not isinstance(value, bool) and value >= 0
