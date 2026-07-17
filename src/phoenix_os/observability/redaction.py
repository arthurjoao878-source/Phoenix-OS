"""Deterministic redaction of structured observability attributes."""

from __future__ import annotations

import math
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path
from types import MappingProxyType
from typing import cast
from uuid import UUID

_DEFAULT_SENSITIVE_KEYS = frozenset(
    {
        "access_token",
        "api_key",
        "authorization",
        "cookie",
        "credential",
        "credentials",
        "password",
        "passphrase",
        "private_key",
        "refresh_token",
        "secret",
        "token",
    }
)


def _normalized_key(value: str) -> str:
    return value.strip().lower().replace("-", "_").replace(" ", "_")


@dataclass(frozen=True, slots=True)
class RedactionPolicy:
    """Convert attributes to safe deterministic values and redact sensitive keys."""

    sensitive_keys: frozenset[str] = field(default_factory=lambda: _DEFAULT_SENSITIVE_KEYS)
    replacement: str = "***"
    max_depth: int = 8

    def __post_init__(self) -> None:
        normalized = frozenset(_normalized_key(key) for key in self.sensitive_keys)
        if any(not key for key in normalized):
            raise ValueError("sensitive keys must not be blank")
        if not self.replacement:
            raise ValueError("replacement must not be empty")
        if self.max_depth < 1:
            raise ValueError("max_depth must be at least one")
        object.__setattr__(self, "sensitive_keys", normalized)

    def redact(self, attributes: Mapping[str, object]) -> Mapping[str, object]:
        """Return an immutable recursively redacted attribute mapping."""

        result = self._redact_mapping(cast(Mapping[object, object], attributes), depth=0)
        return MappingProxyType(result)

    def _redact_mapping(
        self,
        value: Mapping[object, object],
        *,
        depth: int,
    ) -> dict[str, object]:
        if depth >= self.max_depth:
            return {"value": "<max-depth>"}

        result: dict[str, object] = {}
        for raw_key, item in value.items():
            key = str(raw_key).strip()
            if not key:
                raise ValueError("attribute keys must not be blank")
            if key in result:
                raise ValueError(f"duplicate attribute key: {key}")
            if self._is_sensitive(key):
                result[key] = self.replacement
            else:
                result[key] = self._redact_value(item, depth=depth + 1)
        return result

    def _redact_value(self, value: object, *, depth: int) -> object:
        if depth >= self.max_depth:
            return "<max-depth>"
        if value is None or isinstance(value, (str, int, bool)):
            return value
        if isinstance(value, float):
            return value if math.isfinite(value) else str(value)
        if isinstance(value, Mapping):
            return MappingProxyType(self._redact_mapping(value, depth=depth))
        if isinstance(value, (list, tuple)):
            return tuple(self._redact_value(item, depth=depth + 1) for item in value)
        if isinstance(value, (datetime, date, UUID, Path)):
            return str(value)
        if type(value).__name__ == "SecretValue":
            return self.replacement
        return f"<{type(value).__name__}>"

    def _is_sensitive(self, key: str) -> bool:
        normalized = _normalized_key(key)
        segments = tuple(part for part in normalized.replace(".", "_").split("_") if part)
        return normalized in self.sensitive_keys or any(
            sensitive in normalized or sensitive in segments for sensitive in self.sensitive_keys
        )
