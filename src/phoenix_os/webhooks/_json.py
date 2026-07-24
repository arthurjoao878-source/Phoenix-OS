"""Shared canonical JSON helpers for the webhook subsystem."""

from __future__ import annotations

import json
from collections.abc import Mapping


def canonical_json_bytes(value: object) -> bytes:
    """Return deterministic UTF-8 JSON bytes."""

    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def thaw_json_value(value: object) -> object:
    """Convert immutable webhook JSON values into plain JSON containers."""

    if isinstance(value, Mapping):
        return {key: thaw_json_value(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [thaw_json_value(item) for item in value]
    return value
