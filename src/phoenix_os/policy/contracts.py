"""Immutable contracts for Phoenix authorization policy evaluation."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from types import MappingProxyType
from uuid import UUID, uuid4

_NAME_PATTERN = re.compile(r"^[a-z][a-z0-9_.:*?/-]*$")


def _normalize(value: str, label: str) -> str:
    normalized = value.strip().lower()
    if not normalized or _NAME_PATTERN.fullmatch(normalized) is None:
        raise ValueError(f"invalid {label}: {value!r}")
    return normalized


def _freeze_strings(values: frozenset[str]) -> frozenset[str]:
    normalized = frozenset(item.strip().lower() for item in values)
    if "" in normalized:
        raise ValueError("string sets must not contain blank values")
    return normalized


def _freeze_text_mapping(values: Mapping[str, str]) -> Mapping[str, str]:
    frozen: dict[str, str] = {}
    for key, value in values.items():
        normalized_key = key.strip().lower()
        normalized_value = value.strip()
        if not normalized_key or not normalized_value:
            raise ValueError("attribute keys and values must not be blank")
        frozen[normalized_key] = normalized_value
    return MappingProxyType(frozen)


class PrincipalType(StrEnum):
    """Portable identity categories used by policy rules."""

    ANONYMOUS = "anonymous"
    USER = "user"
    SERVICE = "service"
    PLUGIN = "plugin"
    SYSTEM = "system"


class PolicyEffect(StrEnum):
    """Terminal policy outcomes."""

    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_CONFIRMATION = "require_confirmation"


@dataclass(frozen=True, slots=True)
class SecurityContext:
    """Trusted immutable identity and authorization context."""

    principal: str = "anonymous"
    principal_type: PrincipalType = PrincipalType.ANONYMOUS
    authenticated: bool = False
    roles: frozenset[str] = field(default_factory=frozenset)
    permissions: frozenset[str] = field(default_factory=frozenset)
    scopes: frozenset[str] = field(default_factory=frozenset)
    attributes: Mapping[str, str] = field(default_factory=dict)
    correlation_id: str | None = None
    causation_id: UUID | None = None
    confirmed: bool = False

    def __post_init__(self) -> None:
        principal = self.principal.strip()
        if not principal:
            raise ValueError("principal must not be blank")
        if self.principal_type is PrincipalType.ANONYMOUS and self.authenticated:
            raise ValueError("anonymous principals cannot be authenticated")
        if self.correlation_id is not None and not self.correlation_id.strip():
            raise ValueError("correlation_id must not be blank")
        object.__setattr__(self, "principal", principal)
        object.__setattr__(self, "roles", _freeze_strings(self.roles))
        object.__setattr__(self, "permissions", _freeze_strings(self.permissions))
        object.__setattr__(self, "scopes", _freeze_strings(self.scopes))
        object.__setattr__(self, "attributes", _freeze_text_mapping(self.attributes))
        if self.correlation_id is not None:
            object.__setattr__(self, "correlation_id", self.correlation_id.strip())


@dataclass(frozen=True, slots=True)
class PolicyRequest:
    """One immutable authorization question."""

    action: str
    resource: str
    context: SecurityContext = field(default_factory=SecurityContext)
    attributes: Mapping[str, str] = field(default_factory=dict)
    id: UUID = field(default_factory=uuid4)
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        if self.created_at.tzinfo is None:
            raise ValueError("created_at must be timezone-aware")
        object.__setattr__(self, "action", _normalize(self.action, "policy action"))
        object.__setattr__(self, "resource", _normalize(self.resource, "policy resource"))
        object.__setattr__(self, "attributes", _freeze_text_mapping(self.attributes))


@dataclass(frozen=True, slots=True)
class PolicyRule:
    """Declarative deterministic policy rule."""

    rule_id: str
    effect: PolicyEffect
    actions: frozenset[str] = field(default_factory=lambda: frozenset({"*"}))
    resources: frozenset[str] = field(default_factory=lambda: frozenset({"*"}))
    principals: frozenset[str] = field(default_factory=lambda: frozenset({"*"}))
    principal_types: frozenset[PrincipalType] = field(default_factory=frozenset)
    required_roles: frozenset[str] = field(default_factory=frozenset)
    required_permissions: frozenset[str] = field(default_factory=frozenset)
    required_scopes: frozenset[str] = field(default_factory=frozenset)
    authenticated: bool | None = None
    attribute_equals: Mapping[str, str] = field(default_factory=dict)
    priority: int = 0
    reason: str = ""
    metadata: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "rule_id", _normalize(self.rule_id, "policy rule id"))
        actions = _freeze_strings(self.actions)
        resources = _freeze_strings(self.resources)
        principals = _freeze_strings(self.principals)
        if not actions or not resources or not principals:
            raise ValueError("actions, resources, and principals must not be empty")
        object.__setattr__(self, "actions", actions)
        object.__setattr__(self, "resources", resources)
        object.__setattr__(self, "principals", principals)
        object.__setattr__(
            self,
            "principal_types",
            frozenset(PrincipalType(item) for item in self.principal_types),
        )
        object.__setattr__(self, "required_roles", _freeze_strings(self.required_roles))
        object.__setattr__(self, "required_permissions", _freeze_strings(self.required_permissions))
        object.__setattr__(self, "required_scopes", _freeze_strings(self.required_scopes))
        object.__setattr__(self, "attribute_equals", _freeze_text_mapping(self.attribute_equals))
        object.__setattr__(self, "metadata", _freeze_text_mapping(self.metadata))
        object.__setattr__(self, "reason", self.reason.strip())


@dataclass(frozen=True, slots=True)
class PolicyRegistration:
    """Opaque rule registration handle."""

    id: UUID
    rule_id: str


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    """Explainable result of one policy evaluation."""

    request_id: UUID
    effect: PolicyEffect
    reason: str
    rule_id: str | None = None
    matched_rules: tuple[str, ...] = ()
    confirmation_satisfied: bool = False
    metadata: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.reason.strip():
            raise ValueError("policy decision reason must not be blank")
        object.__setattr__(self, "reason", self.reason.strip())
        object.__setattr__(self, "metadata", _freeze_text_mapping(self.metadata))


@dataclass(frozen=True, slots=True)
class PolicySnapshot:
    """Point-in-time engine state without sensitive request data."""

    closed: bool
    rules: tuple[str, ...]
    evaluations: int
    allowed: int
    denied: int
    confirmations: int
