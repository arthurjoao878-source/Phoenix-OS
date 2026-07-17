"""Immutable public contracts for Phoenix capabilities."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from types import MappingProxyType
from typing import Protocol
from uuid import UUID, uuid4

type CapabilityArguments = Mapping[str, object]
type CapabilityOutput = Mapping[str, object]
type CapabilityMetadata = Mapping[str, str]
type CapabilityProvider = Callable[
    [CapabilityInvocation], Awaitable[CapabilityOutput] | CapabilityOutput
]


def _freeze_object_mapping(value: Mapping[str, object]) -> Mapping[str, object]:
    return MappingProxyType(dict(value))


def _freeze_string_mapping(value: Mapping[str, str]) -> Mapping[str, str]:
    return MappingProxyType(dict(value))


def _normalize_strings(values: frozenset[str]) -> frozenset[str]:
    normalized = frozenset(value.strip() for value in values)
    if "" in normalized:
        raise ValueError("string collections must not contain blank values")
    return normalized


class RiskLevel(StrEnum):
    """Declared operational risk of a capability."""

    SAFE = "safe"
    SENSITIVE = "sensitive"
    DESTRUCTIVE = "destructive"


@dataclass(frozen=True, slots=True)
class CapabilityDescriptor:
    """Static metadata and policy requirements for one capability."""

    name: str
    description: str = ""
    version: str = "1.0"
    risk: RiskLevel = RiskLevel.SAFE
    required_permissions: frozenset[str] = field(default_factory=frozenset)
    confirmation_required: bool = False
    default_timeout: float | None = None
    tags: frozenset[str] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        normalized_name = self.name.strip()
        if not normalized_name:
            raise ValueError("capability name must not be blank")
        if not self.version.strip():
            raise ValueError("capability version must not be blank")
        if self.default_timeout is not None and self.default_timeout <= 0:
            raise ValueError("default_timeout must be greater than zero")
        object.__setattr__(self, "name", normalized_name)
        object.__setattr__(
            self,
            "required_permissions",
            _normalize_strings(self.required_permissions),
        )
        object.__setattr__(self, "tags", _normalize_strings(self.tags))


@dataclass(frozen=True, slots=True)
class CapabilityContext:
    """Security and tracing context supplied by a trusted adapter."""

    principal: str = "anonymous"
    request_id: UUID | None = None
    correlation_id: str | None = None
    confirmed: bool = False
    permissions: frozenset[str] = field(default_factory=frozenset)
    metadata: CapabilityMetadata = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.principal.strip():
            raise ValueError("principal must not be blank")
        object.__setattr__(self, "permissions", _normalize_strings(self.permissions))
        object.__setattr__(self, "metadata", _freeze_string_mapping(self.metadata))


@dataclass(frozen=True, slots=True)
class CapabilityInvocation:
    """Immutable request delivered to a capability provider."""

    capability: str
    arguments: CapabilityArguments = field(default_factory=dict)
    context: CapabilityContext = field(default_factory=CapabilityContext)
    id: UUID = field(default_factory=uuid4)
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        normalized = self.capability.strip()
        if not normalized:
            raise ValueError("capability must not be blank")
        if self.created_at.tzinfo is None:
            raise ValueError("created_at must be timezone-aware")
        object.__setattr__(self, "capability", normalized)
        object.__setattr__(self, "arguments", _freeze_object_mapping(self.arguments))


@dataclass(frozen=True, slots=True)
class CapabilityResult:
    """Normalized immutable result returned by the registry."""

    invocation_id: UUID
    output: CapabilityOutput = field(default_factory=dict)
    metadata: CapabilityMetadata = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "output", _freeze_object_mapping(self.output))
        object.__setattr__(self, "metadata", _freeze_string_mapping(self.metadata))


@dataclass(frozen=True, slots=True)
class CapabilityRegistration:
    """Opaque handle returned by registry registration."""

    id: UUID
    name: str


class PermissionStatus(StrEnum):
    ALLOW = "allow"
    DENY = "deny"


@dataclass(frozen=True, slots=True)
class PermissionDecision:
    status: PermissionStatus
    reason: str = ""


class ConfirmationStatus(StrEnum):
    NOT_REQUIRED = "not_required"
    REQUIRED = "required"


@dataclass(frozen=True, slots=True)
class ConfirmationDecision:
    status: ConfirmationStatus
    reason: str = ""


class PermissionPolicy(Protocol):
    def decide(
        self,
        invocation: CapabilityInvocation,
        descriptor: CapabilityDescriptor,
    ) -> Awaitable[PermissionDecision]: ...


class ConfirmationPolicy(Protocol):
    def decide(
        self,
        invocation: CapabilityInvocation,
        descriptor: CapabilityDescriptor,
    ) -> Awaitable[ConfirmationDecision]: ...
