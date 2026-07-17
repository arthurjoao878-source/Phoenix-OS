"""Immutable contracts exposed by the Phoenix Event Bus."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from types import MappingProxyType
from uuid import UUID, uuid4

type EventPayload = Mapping[str, object]
type EventMetadata = Mapping[str, str]
type EventHandler = Callable[[Event], Awaitable[None] | None]


def _freeze_object_mapping(value: Mapping[str, object]) -> Mapping[str, object]:
    return MappingProxyType(dict(value))


def _freeze_string_mapping(value: Mapping[str, str]) -> Mapping[str, str]:
    return MappingProxyType(dict(value))


@dataclass(frozen=True, slots=True)
class Event:
    """An immutable fact that occurred inside Phoenix OS."""

    name: str
    source: str
    payload: EventPayload = field(default_factory=dict)
    metadata: EventMetadata = field(default_factory=dict)
    id: UUID = field(default_factory=uuid4)
    occurred_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    correlation_id: str | None = None
    causation_id: UUID | None = None

    def __post_init__(self) -> None:
        if not self.name or self.name.isspace():
            raise ValueError("event name must not be blank")
        if not self.source or self.source.isspace():
            raise ValueError("event source must not be blank")
        if self.occurred_at.tzinfo is None:
            raise ValueError("occurred_at must be timezone-aware")
        object.__setattr__(self, "payload", _freeze_object_mapping(self.payload))
        object.__setattr__(self, "metadata", _freeze_string_mapping(self.metadata))


@dataclass(frozen=True, slots=True)
class Subscription:
    """Opaque handle returned when a handler is registered."""

    id: UUID
    event_name: str


@dataclass(frozen=True, slots=True)
class DispatchFailure:
    """A handler failure captured during delivery."""

    subscription: Subscription
    exception: Exception


@dataclass(frozen=True, slots=True)
class DispatchReport:
    """Deterministic result returned after all matching handlers finish."""

    event: Event
    matched: int
    delivered: int
    failures: tuple[DispatchFailure, ...]

    @property
    def succeeded(self) -> bool:
        return not self.failures


class ErrorPolicy(StrEnum):
    """How publish reacts after collecting handler failures."""

    COLLECT = "collect"
    RAISE = "raise"
