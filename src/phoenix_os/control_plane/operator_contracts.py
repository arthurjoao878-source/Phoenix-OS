"""Immutable contracts for local Phoenix control-plane operators and RBAC."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Awaitable
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Protocol
from uuid import UUID

from phoenix_os.control_plane.auth import (
    CONTROL_PLANE_READ_PERMISSION,
    ControlPlanePrincipal,
)
from phoenix_os.control_plane.commands import ControlPlaneCommandAction
from phoenix_os.webhooks.manager import (
    WEBHOOK_DELIVERIES_READ_PERMISSION,
    WEBHOOK_HEALTH_READ_PERMISSION,
    WEBHOOK_REDRIVE_PERMISSION,
    WEBHOOK_SUBSCRIPTIONS_CREATE_PERMISSION,
    WEBHOOK_SUBSCRIPTIONS_DISABLE_PERMISSION,
    WEBHOOK_SUBSCRIPTIONS_ENABLE_PERMISSION,
    WEBHOOK_SUBSCRIPTIONS_READ_PERMISSION,
    WEBHOOK_SUBSCRIPTIONS_REVOKE_PERMISSION,
    WEBHOOK_SUBSCRIPTIONS_ROTATE_PERMISSION,
    WEBHOOK_SUBSCRIPTIONS_UPDATE_PERMISSION,
)

DEFAULT_CONTROL_PLANE_OPERATOR_PAGE_SIZE = 50
MAX_CONTROL_PLANE_OPERATOR_PAGE_SIZE = 200
MAX_CONTROL_PLANE_OPERATOR_CAPACITY = 10_000

CONTROL_PLANE_OPERATORS_READ_PERMISSION = "control-plane.operators.read"
CONTROL_PLANE_OPERATORS_CREATE_PERMISSION = "control-plane.operators.create"
CONTROL_PLANE_OPERATORS_UPDATE_PERMISSION = "control-plane.operators.update"
CONTROL_PLANE_OPERATORS_DISABLE_PERMISSION = "control-plane.operators.disable"
CONTROL_PLANE_OPERATORS_ROTATE_PERMISSION = "control-plane.operators.rotate"
CONTROL_PLANE_OPERATORS_REVOKE_PERMISSION = "control-plane.operators.revoke"
CONTROL_PLANE_OPERATOR_SESSIONS_READ_PERMISSION = "control-plane.operator-sessions.read"
CONTROL_PLANE_OPERATOR_SESSIONS_REVOKE_PERMISSION = "control-plane.operator-sessions.revoke"
CONTROL_PLANE_SERVICE_ACCOUNTS_READ_PERMISSION = "control-plane.service-accounts.read"
CONTROL_PLANE_SERVICE_ACCOUNTS_CREATE_PERMISSION = "control-plane.service-accounts.create"
CONTROL_PLANE_SERVICE_ACCOUNTS_UPDATE_PERMISSION = "control-plane.service-accounts.update"
CONTROL_PLANE_SERVICE_ACCOUNTS_DISABLE_PERMISSION = "control-plane.service-accounts.disable"
CONTROL_PLANE_SERVICE_ACCOUNTS_REVOKE_PERMISSION = "control-plane.service-accounts.revoke"
CONTROL_PLANE_API_TOKENS_ISSUE_PERMISSION = "control-plane.api-tokens.issue"
CONTROL_PLANE_API_TOKENS_ROTATE_PERMISSION = "control-plane.api-tokens.rotate"
CONTROL_PLANE_API_TOKENS_REVOKE_PERMISSION = "control-plane.api-tokens.revoke"

_USERNAME_PATTERN = re.compile(r"[a-z][a-z0-9_.-]{2,63}\Z")
_PERMISSION_PATTERN = re.compile(r"[a-z][a-z0-9._-]{2,127}\Z")
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
_TOKEN_PATTERN = re.compile(r"[A-Za-z0-9._:-]{32,128}\Z")


class ControlPlaneOperatorRole(StrEnum):
    """Built-in least-privilege roles for local administrative operators."""

    VIEWER = "viewer"
    OPERATOR = "operator"
    MAINTAINER = "maintainer"

    @property
    def permissions(self) -> frozenset[str]:
        viewer = frozenset({CONTROL_PLANE_READ_PERMISSION})
        operator = viewer | frozenset(action.permission for action in ControlPlaneCommandAction)
        if self is self.VIEWER:
            return viewer
        if self is self.OPERATOR:
            return operator
        return operator | frozenset(
            {
                CONTROL_PLANE_OPERATORS_READ_PERMISSION,
                CONTROL_PLANE_OPERATORS_CREATE_PERMISSION,
                CONTROL_PLANE_OPERATORS_UPDATE_PERMISSION,
                CONTROL_PLANE_OPERATORS_DISABLE_PERMISSION,
                CONTROL_PLANE_OPERATORS_ROTATE_PERMISSION,
                CONTROL_PLANE_OPERATORS_REVOKE_PERMISSION,
                CONTROL_PLANE_OPERATOR_SESSIONS_READ_PERMISSION,
                CONTROL_PLANE_OPERATOR_SESSIONS_REVOKE_PERMISSION,
                CONTROL_PLANE_SERVICE_ACCOUNTS_READ_PERMISSION,
                CONTROL_PLANE_SERVICE_ACCOUNTS_CREATE_PERMISSION,
                CONTROL_PLANE_SERVICE_ACCOUNTS_UPDATE_PERMISSION,
                CONTROL_PLANE_SERVICE_ACCOUNTS_DISABLE_PERMISSION,
                CONTROL_PLANE_SERVICE_ACCOUNTS_REVOKE_PERMISSION,
                CONTROL_PLANE_API_TOKENS_ISSUE_PERMISSION,
                CONTROL_PLANE_API_TOKENS_ROTATE_PERMISSION,
                CONTROL_PLANE_API_TOKENS_REVOKE_PERMISSION,
                WEBHOOK_DELIVERIES_READ_PERMISSION,
                WEBHOOK_HEALTH_READ_PERMISSION,
                WEBHOOK_REDRIVE_PERMISSION,
                WEBHOOK_SUBSCRIPTIONS_CREATE_PERMISSION,
                WEBHOOK_SUBSCRIPTIONS_DISABLE_PERMISSION,
                WEBHOOK_SUBSCRIPTIONS_ENABLE_PERMISSION,
                WEBHOOK_SUBSCRIPTIONS_READ_PERMISSION,
                WEBHOOK_SUBSCRIPTIONS_REVOKE_PERMISSION,
                WEBHOOK_SUBSCRIPTIONS_ROTATE_PERMISSION,
                WEBHOOK_SUBSCRIPTIONS_UPDATE_PERMISSION,
            }
        )


class ControlPlaneOperatorStatus(StrEnum):
    """Administrative availability state for one local operator."""

    ACTIVE = "active"
    DISABLED = "disabled"
    REVOKED = "revoked"

    @property
    def authenticatable(self) -> bool:
        return self is self.ACTIVE


@dataclass(frozen=True, slots=True, repr=False)
class ControlPlaneOperatorToken:
    """One-time operator bearer whose plaintext is never persisted or displayed."""

    value: str = field(repr=False)

    def __post_init__(self) -> None:
        if self.value != self.value.strip():
            raise ValueError("operator token must not contain surrounding whitespace")
        try:
            self.value.encode("ascii")
        except UnicodeEncodeError as exception:
            raise ValueError("operator token must contain ASCII characters only") from exception
        if _TOKEN_PATTERN.fullmatch(self.value) is None:
            raise ValueError("operator token must contain 32 to 128 URL-safe identifier characters")

    @property
    def digest(self) -> str:
        """Return the stable SHA-256 storage representation."""

        return hashlib.sha256(self.value.encode("ascii")).hexdigest()

    def __repr__(self) -> str:
        return "ControlPlaneOperatorToken(<redacted>)"

    def __str__(self) -> str:
        return "<redacted>"


@dataclass(frozen=True, slots=True)
class ControlPlaneOperatorRecord:
    """Versioned operator record containing only a protected credential digest."""

    id: UUID
    username: str
    display_name: str
    role: ControlPlaneOperatorRole
    token_digest: str = field(repr=False)
    created_at: datetime
    updated_at: datetime
    additional_permissions: frozenset[str] = field(default_factory=frozenset)
    status: ControlPlaneOperatorStatus = ControlPlaneOperatorStatus.ACTIVE
    disabled_at: datetime | None = None
    revoked_at: datetime | None = None
    token_version: int = 1
    revision: int = 1
    schema_version: int = 1

    def __post_init__(self) -> None:
        username = _normalize_username(self.username)
        display_name = self.display_name.strip()
        role = ControlPlaneOperatorRole(self.role)
        status = ControlPlaneOperatorStatus(self.status)
        token_digest = _normalize_digest(self.token_digest)
        permissions = _normalize_permissions(self.additional_permissions)

        if not display_name or len(display_name) > 128:
            raise ValueError("operator display name must contain between 1 and 128 characters")
        if any(ord(character) < 32 or ord(character) == 127 for character in display_name):
            raise ValueError("operator display name must not contain control characters")
        if self.schema_version != 1:
            raise ValueError("unsupported control-plane operator schema version")
        if self.token_version <= 0:
            raise ValueError("operator token version must be positive")
        if self.revision <= 0:
            raise ValueError("operator revision must be positive")
        _require_aware(self.created_at, "created_at")
        _require_aware(self.updated_at, "updated_at")
        if self.updated_at < self.created_at:
            raise ValueError("operator updated_at cannot precede created_at")
        if self.disabled_at is not None:
            _require_aware(self.disabled_at, "disabled_at")
            if self.disabled_at < self.created_at:
                raise ValueError("operator disabled_at cannot precede created_at")
        if self.revoked_at is not None:
            _require_aware(self.revoked_at, "revoked_at")
            if self.revoked_at < self.created_at:
                raise ValueError("operator revoked_at cannot precede created_at")

        if status is ControlPlaneOperatorStatus.ACTIVE:
            if self.disabled_at is not None or self.revoked_at is not None:
                raise ValueError("active operator cannot contain disabled or revoked timestamps")
        elif status is ControlPlaneOperatorStatus.DISABLED:
            if self.disabled_at is None or self.revoked_at is not None:
                raise ValueError("disabled operator requires only disabled_at")
        elif self.revoked_at is None:
            raise ValueError("revoked operator requires revoked_at")

        object.__setattr__(self, "username", username)
        object.__setattr__(self, "display_name", display_name)
        object.__setattr__(self, "role", role)
        object.__setattr__(self, "status", status)
        object.__setattr__(self, "token_digest", token_digest)
        object.__setattr__(self, "additional_permissions", permissions)

    @property
    def effective_permissions(self) -> frozenset[str]:
        """Return role permissions plus explicit operator grants."""

        return self.role.permissions | self.additional_permissions

    def principal(self) -> ControlPlanePrincipal:
        """Translate an active operator into the existing transport principal."""

        if not self.status.authenticatable:
            raise ValueError("inactive operator cannot become a control-plane principal")
        return ControlPlanePrincipal(self.username, self.effective_permissions)


@dataclass(frozen=True, slots=True)
class ControlPlaneOperatorPageRequest:
    """Validated offset pagination for the local operator registry."""

    offset: int = 0
    limit: int = DEFAULT_CONTROL_PLANE_OPERATOR_PAGE_SIZE

    def __post_init__(self) -> None:
        if self.offset < 0:
            raise ValueError("operator page offset cannot be negative")
        if self.limit <= 0 or self.limit > MAX_CONTROL_PLANE_OPERATOR_PAGE_SIZE:
            raise ValueError(
                f"operator page limit must be between 1 and {MAX_CONTROL_PLANE_OPERATOR_PAGE_SIZE}"
            )


DEFAULT_CONTROL_PLANE_OPERATOR_PAGE_REQUEST = ControlPlaneOperatorPageRequest()


@dataclass(frozen=True, slots=True)
class ControlPlaneOperatorPageInfo:
    """Stable pagination metadata for operator registry reads."""

    offset: int
    limit: int
    returned: int
    total: int
    next_offset: int | None

    def __post_init__(self) -> None:
        if self.offset < 0 or self.returned < 0 or self.total < 0:
            raise ValueError("operator page counters cannot be negative")
        if self.limit <= 0 or self.limit > MAX_CONTROL_PLANE_OPERATOR_PAGE_SIZE:
            raise ValueError(
                f"operator page limit must be between 1 and {MAX_CONTROL_PLANE_OPERATOR_PAGE_SIZE}"
            )
        if self.returned > self.limit or self.returned > self.total:
            raise ValueError("operator page returned count is inconsistent")
        expected = self.offset + self.returned
        if self.next_offset is None:
            if expected < self.total:
                raise ValueError("operator page requires next_offset while items remain")
        elif self.next_offset != expected or self.next_offset >= self.total:
            raise ValueError("operator page next_offset is inconsistent")

    @classmethod
    def from_slice(
        cls,
        request: ControlPlaneOperatorPageRequest,
        *,
        returned: int,
        total: int,
    ) -> ControlPlaneOperatorPageInfo:
        next_offset = request.offset + returned
        return cls(
            offset=request.offset,
            limit=request.limit,
            returned=returned,
            total=total,
            next_offset=next_offset if next_offset < total else None,
        )


@dataclass(frozen=True, slots=True)
class ControlPlaneOperatorPage:
    """Deterministically ordered page of local operator records."""

    items: tuple[ControlPlaneOperatorRecord, ...]
    page: ControlPlaneOperatorPageInfo

    def __post_init__(self) -> None:
        if len(self.items) != self.page.returned:
            raise ValueError("operator page returned count must match items")
        ids = tuple(item.id for item in self.items)
        usernames = tuple(item.username for item in self.items)
        if len(ids) != len(set(ids)) or len(usernames) != len(set(usernames)):
            raise ValueError("operator page items must be unique")


@dataclass(frozen=True, slots=True)
class ControlPlaneOperatorRegistrySnapshot:
    """Non-sensitive counters for the bounded local operator registry."""

    closed: bool
    operators: int
    active: int
    disabled: int
    revoked: int
    viewers: int
    operators_role: int
    maintainers: int
    capacity: int

    def __post_init__(self) -> None:
        counters = (
            self.operators,
            self.active,
            self.disabled,
            self.revoked,
            self.viewers,
            self.operators_role,
            self.maintainers,
        )
        if any(value < 0 for value in counters):
            raise ValueError("operator registry counters cannot be negative")
        if self.capacity <= 0 or self.capacity > MAX_CONTROL_PLANE_OPERATOR_CAPACITY:
            raise ValueError("operator registry capacity is outside supported bounds")
        if self.operators > self.capacity:
            raise ValueError("operator registry entries cannot exceed capacity")
        if self.active + self.disabled + self.revoked != self.operators:
            raise ValueError("operator status counts must equal entries")
        if self.viewers + self.operators_role + self.maintainers != self.operators:
            raise ValueError("operator role counts must equal entries")


class ControlPlaneOperatorRegistry(Protocol):
    """Asynchronous persistence boundary for local operator identities."""

    @property
    def closed(self) -> bool: ...

    def add(self, record: ControlPlaneOperatorRecord) -> Awaitable[None]: ...

    def get(self, operator_id: UUID) -> Awaitable[ControlPlaneOperatorRecord | None]: ...

    def get_by_username(self, username: str) -> Awaitable[ControlPlaneOperatorRecord | None]: ...

    def get_by_token_digest(
        self,
        token_digest: str,
    ) -> Awaitable[ControlPlaneOperatorRecord | None]: ...

    def list_page(
        self,
        request: ControlPlaneOperatorPageRequest = DEFAULT_CONTROL_PLANE_OPERATOR_PAGE_REQUEST,
    ) -> Awaitable[ControlPlaneOperatorPage]: ...

    def replace(
        self,
        record: ControlPlaneOperatorRecord,
        *,
        expected_revision: int,
    ) -> Awaitable[ControlPlaneOperatorRecord]: ...

    def snapshot(self) -> Awaitable[ControlPlaneOperatorRegistrySnapshot]: ...

    def close(self) -> Awaitable[None]: ...


def _normalize_username(value: str) -> str:
    normalized = value.strip().lower()
    if _USERNAME_PATTERN.fullmatch(normalized) is None:
        raise ValueError("operator username must match [a-z][a-z0-9_.-]{2,63}")
    return normalized


def _normalize_digest(value: str) -> str:
    normalized = value.strip().lower()
    if _SHA256_PATTERN.fullmatch(normalized) is None:
        raise ValueError("operator token digest must be a SHA-256 hexadecimal digest")
    return normalized


def _normalize_permissions(values: frozenset[str]) -> frozenset[str]:
    permissions = frozenset(value.strip().lower() for value in values)
    if any(_PERMISSION_PATTERN.fullmatch(value) is None for value in permissions):
        raise ValueError("operator permissions contain unsupported characters")
    return permissions


def _require_aware(value: datetime, label: str) -> None:
    if value.tzinfo is None:
        raise ValueError(f"{label} must be timezone-aware")
