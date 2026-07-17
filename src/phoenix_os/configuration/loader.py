"""Deterministic schema-driven configuration loading."""

from __future__ import annotations

from collections.abc import Iterable

from phoenix_os.configuration.contracts import (
    ConfigOrigin,
    ConfigSchema,
    Configuration,
    SecretValue,
    UnknownKeyPolicy,
)
from phoenix_os.configuration.errors import (
    ConfigDecodeError,
    ConfigMissingError,
    ConfigUnknownKeyError,
    ConfigValidationError,
)
from phoenix_os.configuration.sources import ConfigSource


class ConfigLoader:
    """Resolve ordered sources against one immutable schema.

    Sources are loaded in registration order and later sources override earlier
    sources. Decoding and validation happen only after precedence is resolved.
    """

    def __init__(self, schema: ConfigSchema, sources: Iterable[ConfigSource] = ()) -> None:
        self._schema = schema
        self._sources = tuple(sources)

    @property
    def schema(self) -> ConfigSchema:
        return self._schema

    @property
    def sources(self) -> tuple[ConfigSource, ...]:
        return self._sources

    async def load(self) -> Configuration:
        raw_values: dict[str, object] = {}
        origins: dict[str, ConfigOrigin] = {}

        for source in self._sources:
            data = await source.load()
            for key, value in data.values.items():
                raw_values[key] = value
                origins[key] = ConfigOrigin(data.source, data.raw_key(key))

        unknown = raw_values.keys() - self._schema.by_key.keys()
        if unknown and self._schema.unknown_keys is UnknownKeyPolicy.REJECT:
            raise ConfigUnknownKeyError(unknown)

        resolved: dict[str, object] = {}
        resolved_origins: dict[str, ConfigOrigin] = {}
        sensitive: set[str] = set()

        for key, config_field in self._schema.by_key.items():
            if key in raw_values:
                origin = origins[key]
                try:
                    decoded = config_field.decoder(raw_values[key])
                except (TypeError, ValueError) as exception:
                    raise ConfigDecodeError(key, origin.source, exception) from exception
            elif config_field.required:
                raise ConfigMissingError(key)
            else:
                decoded = config_field.default
                origin = ConfigOrigin("default", key)

            if config_field.validator is not None and not config_field.validator(decoded):
                raise ConfigValidationError(key)

            if config_field.secret:
                resolved[key] = SecretValue(decoded)
                sensitive.add(key)
            else:
                resolved[key] = decoded
            resolved_origins[key] = origin

        return Configuration(
            values=resolved,
            origins=resolved_origins,
            _sensitive=frozenset(sensitive),
        )
