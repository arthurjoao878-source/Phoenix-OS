"""Policy-protected Phoenix audit ledger manager."""

from __future__ import annotations

import asyncio
import inspect
from collections.abc import Callable, Mapping
from datetime import UTC, datetime

from phoenix_os.audit.contracts import (
    AuditCategory,
    AuditEvent,
    AuditLedgerSnapshot,
    AuditOutcome,
    AuditQuery,
    AuditRecord,
    AuditSeverity,
    AuditStore,
    AuditVerification,
)
from phoenix_os.audit.errors import AuditAccessDeniedError, AuditLedgerClosedError
from phoenix_os.audit.memory import InMemoryAuditStore
from phoenix_os.events import EventBus
from phoenix_os.observability import MetricKind, ObservabilityHub, Severity
from phoenix_os.policy import PolicyEngine, PolicyRequest, SecurityContext
from phoenix_os.policy.errors import PolicyConfirmationRequiredError, PolicyDeniedError

type Clock = Callable[[], datetime]


def _utc_now() -> datetime:
    return datetime.now(UTC)


class AuditLedger:
    """Append security facts and protect historical inspection by policy."""

    def __init__(
        self,
        store: AuditStore | None = None,
        *,
        policy: PolicyEngine | None = None,
        events: EventBus | None = None,
        observability: ObservabilityHub | None = None,
        clock: Clock = _utc_now,
        source: str = "phoenix.audit",
    ) -> None:
        normalized_source = source.strip().lower()
        if not normalized_source:
            raise ValueError("source must not be blank")
        if not callable(clock):
            raise TypeError("clock must be callable")
        self._store = InMemoryAuditStore() if store is None else store
        self._policy = policy
        self._events = events
        self._observability = observability
        self._clock = clock
        self._source = normalized_source
        self._closed = False
        self._appended = 0
        self._reads = 0
        self._verifications = 0
        self._verification_failures = 0
        self._denied_operations = 0
        self._lock = asyncio.Lock()

    @property
    def closed(self) -> bool:
        return self._closed

    async def record(self, event: AuditEvent) -> AuditRecord:
        """Append one already-structured trusted in-process security fact."""

        self._ensure_open()
        recorded_at = self._clock()
        if recorded_at.tzinfo is None:
            raise ValueError("audit clock must return timezone-aware datetimes")
        record = await self._store.append(event, recorded_at=recorded_at)
        async with self._lock:
            self._appended += 1
        await self._signal_record(record)
        return record

    async def record_security(
        self,
        name: str,
        *,
        category: AuditCategory,
        action: str,
        resource: str,
        outcome: AuditOutcome = AuditOutcome.SUCCEEDED,
        severity: AuditSeverity = AuditSeverity.INFO,
        details: Mapping[str, object] | None = None,
        context: SecurityContext | None = None,
        actor: str | None = None,
        source: str | None = None,
    ) -> AuditRecord:
        """Build and append a redacted event from an optional trusted security context."""

        principal = actor
        if principal is None:
            principal = "phoenix" if context is None else context.principal
        event = AuditEvent(
            name=name,
            source=self._source if source is None else source,
            category=category,
            action=action,
            resource=resource,
            actor=principal,
            outcome=outcome,
            severity=severity,
            details={} if details is None else details,
            correlation_id=None if context is None else context.correlation_id,
            causation_id=None if context is None else context.causation_id,
        )
        return await self.record(event)

    async def read(
        self,
        query: AuditQuery,
        context: SecurityContext,
    ) -> tuple[AuditRecord, ...]:
        self._ensure_open()
        await self._authorize("audit.read", context)
        records = await self._store.read(query)
        async with self._lock:
            self._reads += 1
        if self._observability is not None:
            await self._observability.metric(
                "audit.reads",
                1,
                source=self._source,
                kind=MetricKind.COUNTER,
                attributes={"records": len(records)},
                correlation_id=context.correlation_id,
                causation_id=context.causation_id,
            )
        return records

    async def verify(self, context: SecurityContext) -> AuditVerification:
        self._ensure_open()
        await self._authorize("audit.verify", context)
        result = await self._store.verify()
        async with self._lock:
            self._verifications += 1
            if not result.valid:
                self._verification_failures += 1
        await self._signal_verification(result, context)
        return result

    async def snapshot(self) -> AuditLedgerSnapshot:
        store = await self._store.snapshot()
        async with self._lock:
            return AuditLedgerSnapshot(
                closed=self._closed,
                records=store.records,
                head_sequence=store.head_sequence,
                head_digest=store.head_digest,
                signed_records=store.signed_records,
                appended=self._appended,
                reads=self._reads,
                verifications=self._verifications,
                verification_failures=self._verification_failures,
                denied_operations=self._denied_operations,
            )

    async def close(self) -> None:
        async with self._lock:
            if self._closed:
                return
            self._closed = True
        await self._store.close()

    async def start(self, context: object) -> None:
        self._ensure_open()
        start = getattr(self._store, "start", None)
        if callable(start):
            result = start(context)
            if inspect.isawaitable(result):
                await result

    async def stop(self, context: object) -> None:
        del context
        await self.close()

    async def _authorize(self, action: str, context: SecurityContext) -> None:
        if not context.authenticated:
            await self._deny("authenticated identity required")
        if self._policy is not None:
            try:
                await self._policy.enforce(
                    PolicyRequest(
                        action=action,
                        resource="audit:ledger",
                        context=context,
                    )
                )
                return
            except (PolicyDeniedError, PolicyConfirmationRequiredError) as exception:
                await self._deny(str(exception))
        permissions = context.permissions
        if action not in permissions and "audit.*" not in permissions and "*" not in permissions:
            await self._deny(f"permission required: {action}")

    async def _deny(self, reason: str) -> None:
        async with self._lock:
            self._denied_operations += 1
        raise AuditAccessDeniedError(reason)

    async def _signal_record(self, record: AuditRecord) -> None:
        payload: dict[str, object] = {
            "sequence": record.sequence,
            "digest": record.digest,
            "category": record.event.category.value,
            "outcome": record.event.outcome.value,
            "source": record.event.source,
            "actor": record.event.actor,
            "action": record.event.action,
            "resource": record.event.resource,
            "signed": record.seal is not None,
        }
        if self._events is not None:
            await self._events.emit(
                "audit.recorded",
                source=self._source,
                payload=payload,
                correlation_id=record.event.correlation_id,
                causation_id=record.event.id,
            )
        if self._observability is not None:
            await self._observability.metric(
                "audit.records",
                1,
                source=self._source,
                kind=MetricKind.COUNTER,
                attributes={
                    "category": record.event.category.value,
                    "outcome": record.event.outcome.value,
                    "signed": record.seal is not None,
                },
                correlation_id=record.event.correlation_id,
                causation_id=record.event.id,
            )
            await self._observability.log(
                "audit.recorded",
                source=self._source,
                message="audit record appended",
                severity=_observation_severity(record.event.severity),
                attributes=payload,
                correlation_id=record.event.correlation_id,
                causation_id=record.event.id,
            )

    async def _signal_verification(
        self,
        result: AuditVerification,
        context: SecurityContext,
    ) -> None:
        name = "audit.verified" if result.valid else "audit.verification.failed"
        payload: dict[str, object] = {
            "valid": result.valid,
            "checked_records": result.checked_records,
            "signatures_checked": result.signatures_checked,
            "head_digest": result.head_digest,
            "failure_sequence": result.failure_sequence,
            "reason": result.reason,
            "principal": context.principal,
        }
        if self._events is not None:
            await self._events.emit(
                name,
                source=self._source,
                payload=payload,
                correlation_id=context.correlation_id,
                causation_id=context.causation_id,
            )
        if self._observability is not None:
            await self._observability.log(
                name,
                source=self._source,
                message="audit chain valid" if result.valid else "audit chain invalid",
                severity=Severity.INFO if result.valid else Severity.CRITICAL,
                attributes=payload,
                correlation_id=context.correlation_id,
                causation_id=context.causation_id,
            )

    def _ensure_open(self) -> None:
        if self._closed:
            raise AuditLedgerClosedError("audit ledger is closed")


def _observation_severity(severity: AuditSeverity) -> Severity:
    return {
        AuditSeverity.INFO: Severity.INFO,
        AuditSeverity.WARNING: Severity.WARNING,
        AuditSeverity.ERROR: Severity.ERROR,
        AuditSeverity.CRITICAL: Severity.CRITICAL,
    }[severity]
