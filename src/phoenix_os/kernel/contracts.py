"""Immutable public contracts for the Phoenix Kernel."""

from __future__ import annotations

from collections.abc import Awaitable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import Protocol
from uuid import UUID, uuid4


def _freeze(value: Mapping[str, object]) -> Mapping[str, object]:
    return MappingProxyType(dict(value))


@dataclass(frozen=True, slots=True)
class Request:
    action: str
    payload: Mapping[str, object] = field(default_factory=dict)
    principal: str = "anonymous"
    correlation_id: str | None = None
    confirmed: bool = False
    id: UUID = field(default_factory=uuid4)

    def __post_init__(self) -> None:
        if not self.action or self.action.isspace():
            raise ValueError("request action must not be blank")
        object.__setattr__(self, "payload", _freeze(self.payload))


@dataclass(frozen=True, slots=True)
class Response:
    status: int
    body: Mapping[str, object] = field(default_factory=dict)
    request_id: UUID | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "body", _freeze(self.body))


class AuthorizationStatus(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    CONFIRM = "confirm"


@dataclass(frozen=True, slots=True)
class AuthorizationDecision:
    status: AuthorizationStatus
    reason: str = ""


class Handler(Protocol):
    def __call__(self, request: Request) -> Awaitable[Response]: ...


class Authorizer(Protocol):
    def authorize(self, request: Request, route: Route) -> Awaitable[AuthorizationDecision]: ...


@dataclass(frozen=True, slots=True)
class Route:
    action: str
    handler: Handler
    sensitive: bool = False
