"""Immutable public contracts for the Phoenix Runtime."""

from __future__ import annotations

from collections.abc import Awaitable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from types import MappingProxyType
from typing import Protocol
from uuid import UUID, uuid4


def _freeze_services(value: Mapping[str, object]) -> Mapping[str, object]:
    normalized: dict[str, object] = {}
    for name, service in value.items():
        normalized_name = name.strip()
        if not normalized_name:
            raise ValueError("service names must not be blank")
        if normalized_name in normalized:
            raise ValueError(f"duplicate service name: {normalized_name}")
        normalized[normalized_name] = service
    return MappingProxyType(normalized)


def _freeze_metadata(value: Mapping[str, str]) -> Mapping[str, str]:
    return MappingProxyType(dict(value))


class RuntimeState(StrEnum):
    """Observable lifecycle state of a one-shot runtime."""

    CREATED = "created"
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    STOPPED = "stopped"
    FAILED = "failed"


class RuntimePhase(StrEnum):
    """Lifecycle phase associated with a component failure."""

    START = "start"
    ROLLBACK = "rollback"
    STOP = "stop"
    DRAIN = "drain"


@dataclass(frozen=True, slots=True)
class RuntimeContext:
    """Shared immutable composition context passed to lifecycle components."""

    services: Mapping[str, object]
    metadata: Mapping[str, str] = field(default_factory=dict)
    id: UUID = field(default_factory=uuid4)
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        if self.created_at.tzinfo is None:
            raise ValueError("created_at must be timezone-aware")
        object.__setattr__(self, "services", _freeze_services(self.services))
        object.__setattr__(self, "metadata", _freeze_metadata(self.metadata))


class LifecycleComponent(Protocol):
    """A component with explicit asynchronous startup and shutdown hooks."""

    def start(self, context: RuntimeContext) -> Awaitable[None]: ...

    def stop(self, context: RuntimeContext) -> Awaitable[None]: ...


@dataclass(frozen=True, slots=True)
class ComponentSpec:
    """Named component registered in deterministic lifecycle order."""

    name: str
    component: LifecycleComponent

    def __post_init__(self) -> None:
        normalized = self.name.strip()
        if not normalized:
            raise ValueError("component name must not be blank")
        object.__setattr__(self, "name", normalized)


@dataclass(frozen=True, slots=True)
class ComponentFailure:
    """Captured internal failure associated with one lifecycle phase."""

    component: str
    phase: RuntimePhase
    exception: Exception


@dataclass(frozen=True, slots=True)
class RuntimeSnapshot:
    """Immutable point-in-time runtime status."""

    runtime_id: UUID
    state: RuntimeState
    components: tuple[str, ...]
    active_components: tuple[str, ...]
    in_flight_requests: int
    created_at: datetime
    started_at: datetime | None
    stopped_at: datetime | None
