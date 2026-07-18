"""Event Bus bridge that records redacted Phoenix security journal facts."""

from __future__ import annotations

import asyncio
import inspect
import re
from collections.abc import Awaitable, Callable, Mapping

from phoenix_os.audit.contracts import (
    AuditCategory,
    AuditEvent,
    AuditOutcome,
    AuditSeverity,
    SecurityJournalSnapshot,
)
from phoenix_os.audit.errors import SecurityJournalStateError
from phoenix_os.audit.ledger import AuditLedger
from phoenix_os.events import BusClosedError, Event, EventBus, Subscription

type JournalEventMapper = Callable[[Event], AuditEvent | None | Awaitable[AuditEvent | None]]

_IDENTIFIER_SANITIZER = re.compile(r"[^a-z0-9_.-]+")
_ACTION_SANITIZER = re.compile(r"[^a-z0-9_.:*?/-]+")

_CATEGORY_PREFIXES: tuple[tuple[str, AuditCategory], ...] = (
    ("identity.authentication.", AuditCategory.AUTHENTICATION),
    ("identity.session.", AuditCategory.AUTHENTICATION),
    ("identity.", AuditCategory.IDENTITY),
    ("job.", AuditCategory.JOB),
    ("jobs.", AuditCategory.JOB),
    ("workflow.", AuditCategory.WORKFLOW),
    ("workflows.", AuditCategory.WORKFLOW),
    ("authentication.", AuditCategory.AUTHENTICATION),
    ("session.", AuditCategory.AUTHENTICATION),
    ("policy.", AuditCategory.AUTHORIZATION),
    ("secrets.", AuditCategory.SECRETS),
    ("plugin.", AuditCategory.PLUGIN),
    ("plugins.", AuditCategory.PLUGIN),
    ("capability.", AuditCategory.CAPABILITY),
    ("capabilities.", AuditCategory.CAPABILITY),
    ("state.", AuditCategory.STATE),
    ("runtime.", AuditCategory.RUNTIME),
    ("kernel.", AuditCategory.RUNTIME),
    ("configuration.", AuditCategory.CONFIGURATION),
)


class SecurityJournal:
    """Convert Event Bus facts into append-only audit records."""

    def __init__(
        self,
        *,
        events: EventBus,
        ledger: AuditLedger,
        mapper: JournalEventMapper | None = None,
        priority: int = -100,
    ) -> None:
        self._events = events
        self._ledger = ledger
        self._mapper = default_journal_event if mapper is None else mapper
        if not callable(self._mapper):
            raise TypeError("journal mapper must be callable")
        self._priority = priority
        self._subscription: Subscription | None = None
        self._captured = 0
        self._ignored = 0
        self._failures = 0
        self._lock = asyncio.Lock()

    async def start(self, context: object) -> None:
        del context
        async with self._lock:
            if self._subscription is not None:
                raise SecurityJournalStateError("security journal is already started")
            self._subscription = await self._events.subscribe(
                "*",
                self._handle,
                priority=self._priority,
            )

    async def stop(self, context: object) -> None:
        del context
        async with self._lock:
            subscription = self._subscription
            self._subscription = None
        if subscription is not None:
            try:
                await self._events.unsubscribe(subscription)
            except BusClosedError:
                pass

    async def snapshot(self) -> SecurityJournalSnapshot:
        async with self._lock:
            return SecurityJournalSnapshot(
                started=self._subscription is not None,
                captured=self._captured,
                ignored=self._ignored,
                failures=self._failures,
            )

    async def _handle(self, event: Event) -> None:
        if event.name.strip().lower().startswith("audit."):
            async with self._lock:
                self._ignored += 1
            return
        try:
            mapped = self._mapper(event)
            if inspect.isawaitable(mapped):
                mapped = await mapped
            if mapped is None:
                async with self._lock:
                    self._ignored += 1
                return
            await self._ledger.record(mapped)
            async with self._lock:
                self._captured += 1
        except asyncio.CancelledError:
            raise
        except Exception:
            async with self._lock:
                self._failures += 1
            raise


def default_journal_event(event: Event) -> AuditEvent | None:
    """Map one non-audit Event Bus fact into a conservative security record."""

    raw_name = event.name.strip().lower()
    if raw_name.startswith("audit."):
        return None
    normalized_name = _safe_identifier(raw_name, fallback="event")
    payload = event.payload
    actor = _first_text(payload, "principal", "actor", "identity", "plugin") or event.source
    action = _safe_action(_first_text(payload, "action") or normalized_name)
    resource = _first_text(payload, "resource") or f"event:{normalized_name}"
    outcome = _derive_outcome(normalized_name, payload)
    details: dict[str, object] = {
        "event_id": str(event.id),
        "payload": payload,
        "metadata": event.metadata,
    }
    if event.causation_id is not None:
        details["original_causation_id"] = str(event.causation_id)
    return AuditEvent(
        name=normalized_name,
        source=_safe_identifier(event.source, fallback="source"),
        category=_derive_category(normalized_name),
        action=action,
        resource=resource,
        actor=actor,
        outcome=outcome,
        severity=_derive_severity(normalized_name, outcome),
        details=details,
        occurred_at=event.occurred_at,
        correlation_id=event.correlation_id,
        causation_id=event.id,
    )


def _derive_category(name: str) -> AuditCategory:
    for prefix, category in _CATEGORY_PREFIXES:
        if name.startswith(prefix):
            return category
    if name.startswith("system."):
        return AuditCategory.SYSTEM
    return AuditCategory.OTHER


def _derive_outcome(name: str, payload: Mapping[str, object]) -> AuditOutcome:
    effect = _first_text(payload, "effect", "outcome", "result", "status")
    normalized = "" if effect is None else effect.strip().lower()
    if normalized in {"deny", "denied", "rejected", "unauthorized", "forbidden"}:
        return AuditOutcome.DENIED
    if normalized in {"require_confirmation", "restricted", "challenge", "challenged"}:
        return AuditOutcome.RESTRICTED
    if normalized in {
        "failed",
        "failure",
        "error",
        "cancelled",
        "retrying",
        "dead_letter",
        "dead_lettered",
    }:
        return AuditOutcome.FAILED
    if normalized in {"allow", "allowed", "success", "succeeded", "active", "ok"}:
        return AuditOutcome.SUCCEEDED
    if any(token in name for token in (".denied", ".rejected", ".unauthorized")):
        return AuditOutcome.DENIED
    if any(
        token in name for token in (".failed", ".failure", ".error", ".retrying", ".dead_lettered")
    ):
        return AuditOutcome.FAILED
    return AuditOutcome.SUCCEEDED


def _derive_severity(name: str, outcome: AuditOutcome) -> AuditSeverity:
    if outcome is AuditOutcome.FAILED:
        return AuditSeverity.ERROR
    if outcome in {AuditOutcome.DENIED, AuditOutcome.RESTRICTED}:
        return AuditSeverity.WARNING
    if any(token in name for token in ("revoked", "expired", "conflict")):
        return AuditSeverity.WARNING
    return AuditSeverity.INFO


def _first_text(payload: Mapping[str, object], *keys: str) -> str | None:
    for key in keys:
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _safe_identifier(value: str, *, fallback: str) -> str:
    normalized = _IDENTIFIER_SANITIZER.sub(".", value.strip().lower()).strip(".-_")
    if not normalized:
        normalized = fallback
    if not normalized[0].isalpha():
        normalized = f"{fallback}.{normalized}"
    return normalized


def _safe_action(value: str) -> str:
    normalized = _ACTION_SANITIZER.sub(".", value.strip().lower()).strip(".")
    if not normalized:
        return "event.unknown"
    if not normalized[0].isalpha():
        normalized = f"event.{normalized}"
    return normalized
