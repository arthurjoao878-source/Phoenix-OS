"""Immutable public contracts for the Phoenix plugin system."""

from __future__ import annotations

import re
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import Protocol
from uuid import UUID, uuid4

from phoenix_os.capabilities import CapabilityDescriptor, CapabilityProvider
from phoenix_os.state import StateStore

_PLUGIN_ID_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?$")
_VERSION_PATTERN = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")

PLUGIN_API_VERSION = 1
PHOENIX_VERSION = "0.14.0"


def normalize_plugin_id(value: str) -> str:
    """Normalize and validate a stable plugin identifier."""

    normalized = value.strip().lower()
    if not normalized:
        raise ValueError("plugin id must not be blank")
    if not _PLUGIN_ID_PATTERN.fullmatch(normalized):
        raise ValueError(
            "plugin id must contain only lowercase letters, digits, dots, underscores, or hyphens"
        )
    return normalized


def _normalize_name(value: str, label: str) -> str:
    normalized = value.strip()
    if not normalized:
        raise ValueError(f"{label} must not be blank")
    return normalized


def _freeze_strings(values: frozenset[str] | set[str]) -> frozenset[str]:
    result = frozenset(item.strip() for item in values if item.strip())
    if len(result) != len(values):
        raise ValueError("string sets must not contain blank values")
    return result


@dataclass(frozen=True, slots=True, order=True)
class SemanticVersion:
    """Strict three-part semantic version used for compatibility checks."""

    major: int
    minor: int
    patch: int

    def __post_init__(self) -> None:
        if self.major < 0 or self.minor < 0 or self.patch < 0:
            raise ValueError("semantic version parts must not be negative")

    @classmethod
    def parse(cls, value: str | SemanticVersion) -> SemanticVersion:
        if isinstance(value, SemanticVersion):
            return value
        normalized = value.strip()
        match = _VERSION_PATTERN.fullmatch(normalized)
        if match is None:
            raise ValueError(f"invalid semantic version: {value!r}")
        return cls(*(int(part) for part in match.groups()))

    def __str__(self) -> str:
        return f"{self.major}.{self.minor}.{self.patch}"


@dataclass(frozen=True, slots=True)
class VersionRange:
    """Inclusive/exclusive semantic version bounds."""

    minimum: SemanticVersion | str | None = None
    maximum: SemanticVersion | str | None = None
    include_minimum: bool = True
    include_maximum: bool = False

    def __post_init__(self) -> None:
        minimum = None if self.minimum is None else SemanticVersion.parse(self.minimum)
        maximum = None if self.maximum is None else SemanticVersion.parse(self.maximum)
        if minimum is not None and maximum is not None:
            if maximum < minimum:
                raise ValueError("maximum version must not be lower than minimum version")
            if maximum == minimum and not (self.include_minimum and self.include_maximum):
                raise ValueError("empty version range")
        object.__setattr__(self, "minimum", minimum)
        object.__setattr__(self, "maximum", maximum)

    def accepts(self, version: SemanticVersion | str) -> bool:
        candidate = SemanticVersion.parse(version)
        minimum = self.minimum
        maximum = self.maximum
        if isinstance(minimum, SemanticVersion):
            if candidate < minimum or (candidate == minimum and not self.include_minimum):
                return False
        if isinstance(maximum, SemanticVersion):
            if candidate > maximum or (candidate == maximum and not self.include_maximum):
                return False
        return True

    def __str__(self) -> str:
        clauses: list[str] = []
        if isinstance(self.minimum, SemanticVersion):
            clauses.append((">=" if self.include_minimum else ">") + str(self.minimum))
        if isinstance(self.maximum, SemanticVersion):
            clauses.append(("<=" if self.include_maximum else "<") + str(self.maximum))
        return ",".join(clauses) if clauses else "*"


class PluginPermission(StrEnum):
    """Privileged contribution types that a host may explicitly allow."""

    REGISTER_CAPABILITIES = "capabilities.register"
    REGISTER_STATE_STORES = "state_stores.register"
    PUBLISH_SERVICES = "services.publish"


@dataclass(frozen=True, slots=True)
class PluginExports:
    """Names a plugin is allowed to contribute during setup."""

    capabilities: frozenset[str] = field(default_factory=frozenset)
    state_stores: frozenset[str] = field(default_factory=frozenset)
    services: frozenset[str] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        object.__setattr__(self, "capabilities", _freeze_strings(self.capabilities))
        object.__setattr__(self, "state_stores", _freeze_strings(self.state_stores))
        object.__setattr__(self, "services", _freeze_strings(self.services))


@dataclass(frozen=True, slots=True)
class PluginDependency:
    """One required or optional dependency on another plugin."""

    plugin_id: str
    versions: VersionRange = field(default_factory=VersionRange)
    optional: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "plugin_id", normalize_plugin_id(self.plugin_id))


@dataclass(frozen=True, slots=True)
class PluginManifest:
    """Static, side-effect-free metadata for one plugin."""

    plugin_id: str
    name: str
    version: SemanticVersion | str
    api_version: int = PLUGIN_API_VERSION
    phoenix_versions: VersionRange = field(default_factory=VersionRange)
    permissions: frozenset[PluginPermission] = field(default_factory=frozenset)
    dependencies: tuple[PluginDependency, ...] = ()
    exports: PluginExports = field(default_factory=PluginExports)
    description: str = ""
    metadata: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        plugin_id = normalize_plugin_id(self.plugin_id)
        name = _normalize_name(self.name, "plugin name")
        version = SemanticVersion.parse(self.version)
        if self.api_version <= 0:
            raise ValueError("api_version must be greater than zero")
        permissions = frozenset(PluginPermission(item) for item in self.permissions)
        dependencies = tuple(self.dependencies)
        dependency_ids = [dependency.plugin_id for dependency in dependencies]
        if len(dependency_ids) != len(set(dependency_ids)):
            raise ValueError("plugin dependencies must be unique")
        if plugin_id in dependency_ids:
            raise ValueError("plugin cannot depend on itself")
        metadata = MappingProxyType(dict(self.metadata))
        for key, value in metadata.items():
            _normalize_name(key, "metadata key")
            _normalize_name(value, "metadata value")
        object.__setattr__(self, "plugin_id", plugin_id)
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "version", version)
        object.__setattr__(self, "permissions", permissions)
        object.__setattr__(self, "dependencies", dependencies)
        object.__setattr__(self, "metadata", metadata)
        object.__setattr__(self, "description", self.description.strip())


class PluginManagerState(StrEnum):
    CREATED = "created"
    PREPARING = "preparing"
    PREPARED = "prepared"
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    STOPPED = "stopped"
    FAILED = "failed"


class PluginStatus(StrEnum):
    REGISTERED = "registered"
    PREPARED = "prepared"
    ACTIVE = "active"
    STOPPED = "stopped"
    FAILED = "failed"


class PluginFailurePhase(StrEnum):
    SETUP = "setup"
    START = "start"
    STOP = "stop"
    CLEANUP = "cleanup"


@dataclass(frozen=True, slots=True)
class PluginRegistration:
    id: UUID
    plugin_id: str


@dataclass(frozen=True, slots=True)
class PluginFailure:
    plugin_id: str
    phase: PluginFailurePhase
    exception: Exception


@dataclass(frozen=True, slots=True)
class PluginSnapshot:
    state: PluginManagerState
    registered: tuple[str, ...]
    resolved_order: tuple[str, ...]
    prepared: tuple[str, ...]
    active: tuple[str, ...]
    services: tuple[str, ...]
    failures: tuple[PluginFailure, ...]


class PluginRegistrar(Protocol):
    """Restricted contribution surface exposed to one plugin."""

    async def register_capability(
        self,
        descriptor: CapabilityDescriptor,
        provider: CapabilityProvider,
    ) -> None: ...

    async def register_state_store(
        self,
        name: str,
        store: StateStore,
        *,
        make_default: bool = False,
    ) -> None: ...

    async def publish_service(self, name: str, service: object) -> None: ...

    def service(self, name: str) -> object: ...


@dataclass(frozen=True, slots=True)
class PluginContext:
    """Host-owned context supplied to plugin hooks."""

    manifest: PluginManifest
    registrar: PluginRegistrar
    host_services: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "host_services", MappingProxyType(dict(self.host_services)))

    def service(self, name: str) -> object:
        return self.registrar.service(name)


class Plugin(Protocol):
    """Plugin lifecycle contract. Start and stop hooks may be omitted at runtime."""

    manifest: PluginManifest

    def setup(self, context: PluginContext) -> Awaitable[None] | None: ...


@dataclass(frozen=True, slots=True)
class PluginReference:
    """Side-effect-free package entry-point metadata."""

    name: str
    value: str
    group: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", _normalize_name(self.name, "entry point name"))
        object.__setattr__(self, "value", _normalize_name(self.value, "entry point value"))
        object.__setattr__(self, "group", _normalize_name(self.group, "entry point group"))


type PluginHook = Callable[[PluginContext], Awaitable[None] | None]


def new_plugin_registration(plugin_id: str) -> PluginRegistration:
    """Create an opaque registration handle."""

    return PluginRegistration(uuid4(), normalize_plugin_id(plugin_id))
