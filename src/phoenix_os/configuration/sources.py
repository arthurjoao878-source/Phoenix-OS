"""Safe built-in configuration sources."""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Protocol

from phoenix_os.configuration.contracts import normalize_key
from phoenix_os.configuration.errors import ConfigSourceError


@dataclass(frozen=True, slots=True)
class ConfigSourceData:
    """Immutable raw values emitted by one named source."""

    source: str
    values: Mapping[str, object]
    _raw_keys: Mapping[str, str] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        source = self.source.strip()
        if not source:
            raise ValueError("source name must not be blank")

        normalized_values: dict[str, object] = {}
        raw_keys: dict[str, str] = {}
        for raw_key, value in self.values.items():
            normalized = normalize_key(raw_key)
            if normalized in normalized_values:
                raise ConfigSourceError(
                    f"source {source!r} contains duplicate normalized key {normalized!r}"
                )
            normalized_values[normalized] = value
            raw_keys[normalized] = raw_key

        object.__setattr__(self, "source", source)
        object.__setattr__(self, "values", MappingProxyType(normalized_values))
        object.__setattr__(self, "_raw_keys", MappingProxyType(raw_keys))

    def raw_key(self, normalized_key: str) -> str:
        return self._raw_keys[normalized_key]


class ConfigSource(Protocol):
    """Asynchronous source contract used by the deterministic loader."""

    async def load(self) -> ConfigSourceData: ...


@dataclass(frozen=True, slots=True)
class MappingConfigSource:
    """Load configuration from an in-memory mapping."""

    values: Mapping[str, object]
    name: str = "mapping"

    async def load(self) -> ConfigSourceData:
        return ConfigSourceData(self.name, self.values)


@dataclass(frozen=True, slots=True)
class EnvironmentConfigSource:
    """Load prefixed environment variables into dotted lowercase keys."""

    prefix: str = "PHOENIX_"
    separator: str = "__"
    environ: Mapping[str, str] | None = field(default=None, repr=False)
    name: str = "environment"

    def __post_init__(self) -> None:
        if not self.prefix:
            raise ValueError("environment prefix must not be empty")
        if not self.separator:
            raise ValueError("environment separator must not be empty")

    async def load(self) -> ConfigSourceData:
        environment = os.environ if self.environ is None else self.environ
        values: dict[str, object] = {}
        for raw_key, value in environment.items():
            if not raw_key.startswith(self.prefix):
                continue
            suffix = raw_key[len(self.prefix) :]
            key = suffix.lower().replace(self.separator.lower(), ".")
            values[key] = value
        return ConfigSourceData(self.name, values)


@dataclass(frozen=True, slots=True)
class JsonFileConfigSource:
    """Load a JSON object and flatten nested objects into dotted keys."""

    path: Path
    optional: bool = False
    encoding: str = "utf-8"
    name: str | None = None

    async def load(self) -> ConfigSourceData:
        source_name = self.name or f"json:{self.path}"
        try:
            content = self.path.read_text(encoding=self.encoding)
        except FileNotFoundError as exception:
            if self.optional:
                return ConfigSourceData(source_name, {})
            raise ConfigSourceError(f"configuration file not found: {self.path}") from exception
        except OSError as exception:
            raise ConfigSourceError(f"cannot read configuration file: {self.path}") from exception

        try:
            payload = json.loads(content)
        except json.JSONDecodeError as exception:
            raise ConfigSourceError(f"invalid JSON configuration: {self.path}") from exception

        if not isinstance(payload, dict):
            raise ConfigSourceError("JSON configuration root must be an object")

        flattened: dict[str, object] = {}
        self._flatten(payload, prefix="", output=flattened)
        return ConfigSourceData(source_name, flattened)

    def _flatten(
        self,
        payload: Mapping[str, object],
        *,
        prefix: str,
        output: dict[str, object],
    ) -> None:
        for key, value in payload.items():
            if not isinstance(key, str):
                raise ConfigSourceError("JSON configuration object keys must be strings")
            full_key = f"{prefix}.{key}" if prefix else key
            if isinstance(value, dict):
                self._flatten(value, prefix=full_key, output=output)
            else:
                normalized = normalize_key(full_key)
                if normalized in output:
                    raise ConfigSourceError(f"duplicate flattened JSON key: {normalized}")
                output[normalized] = value
