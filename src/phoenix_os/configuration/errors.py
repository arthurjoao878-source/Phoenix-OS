"""Configuration and dependency-composition exceptions."""

from __future__ import annotations

from collections.abc import Iterable


class PhoenixConfigurationError(RuntimeError):
    """Base class for Phoenix configuration failures."""


class ConfigKeyError(PhoenixConfigurationError, ValueError):
    """Raised when a configuration key is malformed."""


class ConfigSourceError(PhoenixConfigurationError):
    """Raised when a configuration source cannot be loaded safely."""


class ConfigMissingError(PhoenixConfigurationError):
    """Raised when a required configuration field is absent."""

    def __init__(self, key: str) -> None:
        self.key = key
        super().__init__(f"required configuration value is missing: {key}")


class ConfigUnknownKeyError(PhoenixConfigurationError):
    """Raised when strict loading encounters keys outside the schema."""

    def __init__(self, keys: Iterable[str]) -> None:
        self.keys = tuple(sorted(keys))
        joined = ", ".join(self.keys)
        super().__init__(f"unknown configuration key(s): {joined}")


class ConfigDecodeError(PhoenixConfigurationError):
    """Raised when a raw value cannot be decoded to its declared type."""

    def __init__(self, key: str, source: str, exception: Exception) -> None:
        self.key = key
        self.source = source
        self.exception = exception
        super().__init__(f"failed to decode configuration key {key!r} from {source!r}")


class ConfigValidationError(PhoenixConfigurationError):
    """Raised when a decoded value violates a field validator."""

    def __init__(self, key: str) -> None:
        self.key = key
        super().__init__(f"configuration validation failed for key: {key}")


class ConfigTypeError(PhoenixConfigurationError, TypeError):
    """Raised when a caller requests a value using the wrong expected type."""


class ConfigSecretError(PhoenixConfigurationError):
    """Raised when a non-secret value is requested through the secret API."""


class DependencyError(PhoenixConfigurationError):
    """Base class for deterministic dependency-composition failures."""


class DuplicateServiceError(DependencyError):
    """Raised when a service name is registered more than once."""


class ServiceNotFoundError(DependencyError):
    """Raised when a requested dependency or built service is unknown."""

    def __init__(self, name: str) -> None:
        self.name = name
        super().__init__(f"service not found: {name}")


class DependencyCycleError(DependencyError):
    """Raised when service definitions contain a dependency cycle."""

    def __init__(self, cycle: tuple[str, ...]) -> None:
        self.cycle = cycle
        super().__init__(f"dependency cycle detected: {' -> '.join(cycle)}")


class ServiceFactoryError(DependencyError):
    """Raised when a service factory fails."""

    def __init__(self, name: str, exception: Exception) -> None:
        self.name = name
        self.exception = exception
        super().__init__(f"service factory failed: {name}")


class InvalidLifecycleServiceError(DependencyError, TypeError):
    """Raised when a lifecycle service does not expose start and stop hooks."""
