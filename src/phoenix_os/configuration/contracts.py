"""Immutable public contracts for Phoenix configuration."""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import Final, TypeVar, cast, overload

from phoenix_os.configuration.errors import (
    ConfigKeyError,
    ConfigSecretError,
    ConfigTypeError,
)

_KEY_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)*$")
_MISSING: Final[object] = object()
T = TypeVar("T")


type ConfigDecoder = Callable[[object], object]
type ConfigValidator = Callable[[object], bool]


def normalize_key(key: str) -> str:
    """Normalize and validate a dotted configuration key."""

    normalized = key.strip().lower()
    if not normalized or _KEY_PATTERN.fullmatch(normalized) is None:
        raise ConfigKeyError(f"invalid configuration key: {key!r}")
    return normalized


class UnknownKeyPolicy(StrEnum):
    """Policy applied to raw keys not declared by the schema."""

    IGNORE = "ignore"
    REJECT = "reject"


@dataclass(frozen=True, slots=True)
class SecretValue:
    """A value that is redacted by default and revealed only explicitly."""

    _value: object = field(repr=False)

    @overload
    def reveal(self, expected_type: type[T]) -> T: ...

    @overload
    def reveal(self, expected_type: None = None) -> object: ...

    def reveal(self, expected_type: type[T] | None = None) -> T | object:
        """Return the wrapped value, optionally enforcing an expected type."""

        if expected_type is not None and not isinstance(self._value, expected_type):
            message = (
                f"secret value has type {type(self._value).__name__}, "
                f"expected {expected_type.__name__}"
            )
            raise ConfigTypeError(message)
        if expected_type is None:
            return self._value
        return cast(T, self._value)

    def __repr__(self) -> str:
        return "SecretValue(***)"

    def __str__(self) -> str:
        return "***"


@dataclass(frozen=True, slots=True)
class ConfigField:
    """Schema declaration for one typed configuration value."""

    key: str
    decoder: ConfigDecoder
    default: object = field(default=_MISSING, repr=False)
    secret: bool = False
    validator: ConfigValidator | None = field(default=None, repr=False)
    description: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "key", normalize_key(self.key))
        if not callable(self.decoder):
            raise TypeError("decoder must be callable")
        if self.validator is not None and not callable(self.validator):
            raise TypeError("validator must be callable")

    @property
    def required(self) -> bool:
        """Whether the field has no default and must be supplied by a source."""

        return self.default is _MISSING


@dataclass(frozen=True, slots=True)
class ConfigOrigin:
    """Provenance of a resolved configuration value."""

    source: str
    raw_key: str

    def __post_init__(self) -> None:
        normalized_source = self.source.strip()
        if not normalized_source:
            raise ValueError("origin source must not be blank")
        object.__setattr__(self, "source", normalized_source)
        object.__setattr__(self, "raw_key", self.raw_key.strip())


@dataclass(frozen=True, slots=True)
class ConfigSchema:
    """Immutable set of uniquely named configuration fields."""

    fields: tuple[ConfigField, ...]
    unknown_keys: UnknownKeyPolicy = UnknownKeyPolicy.REJECT
    _by_key: Mapping[str, ConfigField] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        by_key: dict[str, ConfigField] = {}
        for config_field in self.fields:
            if config_field.key in by_key:
                raise ValueError(f"duplicate configuration field: {config_field.key}")
            by_key[config_field.key] = config_field
        object.__setattr__(self, "_by_key", MappingProxyType(by_key))

    @property
    def by_key(self) -> Mapping[str, ConfigField]:
        return self._by_key


@dataclass(frozen=True, slots=True)
class Configuration:
    """Resolved, immutable and provenance-aware application configuration."""

    values: Mapping[str, object]
    origins: Mapping[str, ConfigOrigin]
    _sensitive: frozenset[str] = field(default_factory=frozenset, repr=False)

    def __post_init__(self) -> None:
        normalized_values: dict[str, object] = {}
        for key, value in self.values.items():
            normalized = normalize_key(key)
            if normalized in normalized_values:
                raise ValueError(f"duplicate configuration value: {normalized}")
            normalized_values[normalized] = value

        normalized_origins: dict[str, ConfigOrigin] = {}
        for key, origin in self.origins.items():
            normalized_origins[normalize_key(key)] = origin

        if normalized_values.keys() != normalized_origins.keys():
            raise ValueError("configuration values and origins must have identical keys")

        sensitive = frozenset(normalize_key(key) for key in self._sensitive)
        if not sensitive.issubset(normalized_values):
            raise ValueError("sensitive keys must exist in configuration values")

        object.__setattr__(self, "values", MappingProxyType(normalized_values))
        object.__setattr__(self, "origins", MappingProxyType(normalized_origins))
        object.__setattr__(self, "_sensitive", sensitive)

    def __contains__(self, key: object) -> bool:
        return isinstance(key, str) and normalize_key(key) in self.values

    @overload
    def value(self, key: str, expected_type: type[T]) -> T: ...

    @overload
    def value(self, key: str, expected_type: None = None) -> object: ...

    def value(self, key: str, expected_type: type[T] | None = None) -> T | object:
        """Read a non-secret value and optionally enforce its concrete type."""

        normalized = normalize_key(key)
        value = self.values[normalized]
        if isinstance(value, SecretValue):
            raise ConfigSecretError(f"configuration value is secret: {normalized}")
        if expected_type is not None and not isinstance(value, expected_type):
            message = (
                f"configuration value {normalized!r} has type {type(value).__name__}, "
                f"expected {expected_type.__name__}"
            )
            raise ConfigTypeError(message)
        if expected_type is None:
            return value
        return cast(T, value)

    def secret(self, key: str) -> SecretValue:
        """Return the redacted wrapper for a declared secret value."""

        normalized = normalize_key(key)
        value = self.values[normalized]
        if not isinstance(value, SecretValue):
            raise ConfigSecretError(f"configuration value is not secret: {normalized}")
        return value

    def origin(self, key: str) -> ConfigOrigin:
        """Return the winning source for a resolved key."""

        return self.origins[normalize_key(key)]

    def as_dict(self, *, reveal_secrets: bool = False) -> Mapping[str, object]:
        """Return an immutable snapshot, redacting secrets unless explicitly requested."""

        result: dict[str, object] = {}
        for key, value in self.values.items():
            if isinstance(value, SecretValue):
                result[key] = value.reveal() if reveal_secrets else "***"
            else:
                result[key] = value
        return MappingProxyType(result)

    @property
    def sensitive_keys(self) -> frozenset[str]:
        return self._sensitive
