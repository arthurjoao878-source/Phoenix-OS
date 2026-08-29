"""Deterministic RFC-0037 reliability test utilities."""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from phoenix_os.agent.durable_reliability import ReliabilityFaultPoint

_MAX_FAULT_PLAN_SIZE = 512
_MAX_TOTAL_FAULT_HITS = 4096
_MAX_INTERLEAVING_STEPS = 1024
_ACTOR_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


@dataclass(frozen=True, slots=True)
class ReliabilityFaultTrigger:
    """One deterministic fault trigger at a per-point occurrence."""

    point: ReliabilityFaultPoint
    occurrence: int = 1

    def __post_init__(self) -> None:
        if not isinstance(self.point, ReliabilityFaultPoint):
            raise TypeError("point must be ReliabilityFaultPoint")
        if not isinstance(self.occurrence, int) or isinstance(self.occurrence, bool):
            raise TypeError("occurrence must be int")
        if self.occurrence < 1:
            raise ValueError("occurrence must be positive")
        if self.occurrence > _MAX_TOTAL_FAULT_HITS:
            raise ValueError("occurrence exceeds the bounded reliability test limit")


@dataclass(frozen=True, slots=True)
class ReliabilityFaultObservation:
    """Content-free observation of one reached reliability fault point."""

    point: ReliabilityFaultPoint
    occurrence: int
    injected: bool


class InjectedReliabilityFault(RuntimeError):
    """Deterministic test-only crash signal."""

    def __init__(self, point: ReliabilityFaultPoint, occurrence: int) -> None:
        self.point = point
        self.occurrence = occurrence
        super().__init__(f"injected reliability fault at {point.value} occurrence {occurrence}")


class ReliabilityFaultPlanExhausted(RuntimeError):
    """Raised when a test exceeds its finite configured fault-hit bound."""


class DeterministicReliabilityFaultInjector:
    """Finite deterministic injector driven only by fixed Phoenix-owned points."""

    __slots__ = (
        "_counts",
        "_fired",
        "_max_total_hits",
        "_observations",
        "_total_hits",
        "_triggers",
    )

    def __init__(
        self,
        triggers: Iterable[ReliabilityFaultTrigger] = (),
        *,
        max_total_hits: int = 1024,
    ) -> None:
        trigger_values = tuple(triggers)
        if len(trigger_values) > _MAX_FAULT_PLAN_SIZE:
            raise ValueError("reliability fault plan exceeds the bounded plan limit")
        if not all(isinstance(trigger, ReliabilityFaultTrigger) for trigger in trigger_values):
            raise TypeError("triggers must contain ReliabilityFaultTrigger values")
        if not isinstance(max_total_hits, int) or isinstance(max_total_hits, bool):
            raise TypeError("max_total_hits must be int")
        if not 1 <= max_total_hits <= _MAX_TOTAL_FAULT_HITS:
            raise ValueError("max_total_hits is outside the bounded reliability test range")

        trigger_keys = tuple((trigger.point, trigger.occurrence) for trigger in trigger_values)
        if len(set(trigger_keys)) != len(trigger_keys):
            raise ValueError("reliability fault plan contains duplicate triggers")
        if any(trigger.occurrence > max_total_hits for trigger in trigger_values):
            raise ValueError("fault trigger occurrence exceeds max_total_hits")

        self._triggers = frozenset(trigger_keys)
        self._max_total_hits = max_total_hits
        self._counts: dict[ReliabilityFaultPoint, int] = {}
        self._fired: set[tuple[ReliabilityFaultPoint, int]] = set()
        self._observations: list[ReliabilityFaultObservation] = []
        self._total_hits = 0

    @property
    def observations(self) -> tuple[ReliabilityFaultObservation, ...]:
        return tuple(self._observations)

    @property
    def total_hits(self) -> int:
        return self._total_hits

    @property
    def pending_trigger_count(self) -> int:
        return len(self._triggers - self._fired)

    def inject(self, point: ReliabilityFaultPoint, /) -> None:
        if not isinstance(point, ReliabilityFaultPoint):
            raise TypeError("point must be ReliabilityFaultPoint")
        if self._total_hits >= self._max_total_hits:
            raise ReliabilityFaultPlanExhausted(
                "deterministic reliability fault-hit bound exhausted"
            )

        occurrence = self._counts.get(point, 0) + 1
        self._counts[point] = occurrence
        self._total_hits += 1

        key = (point, occurrence)
        injected = key in self._triggers and key not in self._fired
        self._observations.append(
            ReliabilityFaultObservation(
                point=point,
                occurrence=occurrence,
                injected=injected,
            )
        )
        if injected:
            self._fired.add(key)
            raise InjectedReliabilityFault(point, occurrence)


class DeterministicUtcClock:
    """Manually advanced UTC clock for bounded reliability tests."""

    __slots__ = ("_current",)

    def __init__(self, current: datetime) -> None:
        self._current = self._validate(current)

    @staticmethod
    def _validate(value: datetime) -> datetime:
        if not isinstance(value, datetime):
            raise TypeError("current must be datetime")
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("current must be timezone-aware")
        return value.astimezone(UTC)

    @property
    def current(self) -> datetime:
        return self._current

    def __call__(self) -> datetime:
        return self._current

    def advance(self, delta: timedelta) -> datetime:
        if not isinstance(delta, timedelta):
            raise TypeError("delta must be timedelta")
        if delta < timedelta(0):
            raise ValueError("deterministic clock cannot move backward")
        self._current += delta
        return self._current


@dataclass(frozen=True, slots=True)
class ReliabilityInterleavingStep:
    """One expected actor arrival at one fixed reliability boundary."""

    actor: str
    point: ReliabilityFaultPoint

    def __post_init__(self) -> None:
        if not isinstance(self.actor, str):
            raise TypeError("actor must be str")
        if _ACTOR_PATTERN.fullmatch(self.actor) is None:
            raise ValueError("actor must be a bounded test identifier")
        if not isinstance(self.point, ReliabilityFaultPoint):
            raise TypeError("point must be ReliabilityFaultPoint")


class UnexpectedReliabilityInterleaving(RuntimeError):
    """Raised when a deterministic interleaving deviates from its finite plan."""


class DeterministicReliabilityInterleaving:
    """Finite deterministic sequence checker for concurrency/restart tests."""

    __slots__ = ("_index", "_steps")

    def __init__(self, steps: Iterable[ReliabilityInterleavingStep]) -> None:
        step_values = tuple(steps)
        if len(step_values) > _MAX_INTERLEAVING_STEPS:
            raise ValueError("reliability interleaving exceeds the bounded plan limit")
        if not all(isinstance(step, ReliabilityInterleavingStep) for step in step_values):
            raise TypeError("steps must contain ReliabilityInterleavingStep values")
        self._steps = step_values
        self._index = 0

    @property
    def complete(self) -> bool:
        return self._index == len(self._steps)

    @property
    def remaining(self) -> tuple[ReliabilityInterleavingStep, ...]:
        return self._steps[self._index :]

    def arrive(self, actor: str, point: ReliabilityFaultPoint, /) -> None:
        candidate = ReliabilityInterleavingStep(actor=actor, point=point)
        if self._index >= len(self._steps):
            raise UnexpectedReliabilityInterleaving(
                "deterministic reliability interleaving received an extra step"
            )
        if candidate != self._steps[self._index]:
            raise UnexpectedReliabilityInterleaving(
                "deterministic reliability interleaving diverged from its plan"
            )
        self._index += 1
