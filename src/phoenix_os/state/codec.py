"""Safe JSON serialization for Phoenix state values."""

from __future__ import annotations

import json
import math
from collections.abc import Mapping, Sequence

from phoenix_os.state.errors import StateSerializationError

_JSON_SCALARS = (str, int, float, bool, type(None))


def _to_json_value(value: object, *, path: str = "$") -> object:
    value_type = type(value)
    if (
        value_type.__name__ == "SecretValue"
        and value_type.__module__ == "phoenix_os.configuration.contracts"
    ):
        raise StateSerializationError(
            f"secret values must be revealed explicitly before persistence at {path}"
        )
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise StateSerializationError(f"non-finite number is not supported at {path}")
        return value
    if isinstance(value, Mapping):
        result: dict[str, object] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise StateSerializationError(f"mapping keys must be strings at {path}")
            result[key] = _to_json_value(item, path=f"{path}.{key}")
        return result
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_to_json_value(item, path=f"{path}[{index}]") for index, item in enumerate(value)]
    raise StateSerializationError(f"unsupported state value type {type(value).__name__} at {path}")


class JsonStateCodec:
    """Deterministic JSON codec that never executes arbitrary code."""

    def encode(self, value: object) -> bytes:
        normalized = _to_json_value(value)
        try:
            document = json.dumps(
                normalized,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            )
        except (TypeError, ValueError) as exception:
            raise StateSerializationError("state value could not be encoded as JSON") from exception
        return document.encode("utf-8")

    def decode(self, payload: bytes) -> object:
        try:
            decoded = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exception:
            raise StateSerializationError("state payload is not valid UTF-8 JSON") from exception
        return decoded
