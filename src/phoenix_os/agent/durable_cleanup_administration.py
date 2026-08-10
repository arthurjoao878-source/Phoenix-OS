"""Authorized audited execution boundary for durable retention cleanup."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Protocol, runtime_checkable

from phoenix_os.agent.durable_administration import (
    AGENT_DURABLE_CLEANUP_ACTION,
    DURABLE_ADMINISTRATION_CLEANUP_RESOURCE,
)
from phoenix_os.agent.durable_contracts import (
    MAX_METADATA_RETENTION,
    MAX_PAYLOAD_RETENTION,
    MAX_TOMBSTONE_RETENTION,
    RetentionPolicy,
)
from phoenix_os.agent.durable_retention_worker import (
    MAX_RETENTION_WORKER_CANDIDATES,
    MAX_RETENTION_WORKER_PAGE_SIZE,
    MAX_RETENTION_WORKER_PASS_DURATION,
    DurableRetentionWorkerConfiguration,
    DurableRetentionWorkerReport,
)
from phoenix_os.agent.errors import (
    AgentAdministrationAccessDeniedError,
    AgentServiceUnavailableError,
    AgentStateConflictError,
)
from phoenix_os.audit import AuditCategory, AuditLedger, AuditOutcome, AuditSeverity
from phoenix_os.policy import PrincipalType, SecurityContext


def _timedelta_microseconds(value: timedelta) -> int:
    return value.days * 86_400_000_000 + value.seconds * 1_000_000 + value.microseconds


_MAX_RETENTION_WORKER_PASS_MICROSECONDS = _timedelta_microseconds(
    MAX_RETENTION_WORKER_PASS_DURATION
)
_MAX_PAYLOAD_RETENTION_MICROSECONDS = _timedelta_microseconds(MAX_PAYLOAD_RETENTION)
_MAX_METADATA_RETENTION_MICROSECONDS = _timedelta_microseconds(MAX_METADATA_RETENTION)
_MAX_TOMBSTONE_RETENTION_MICROSECONDS = _timedelta_microseconds(MAX_TOMBSTONE_RETENTION)


def _require_positive_integer(
    value: int,
    *,
    label: str,
    maximum: int,
) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{label} must be an integer")
    if value <= 0:
        raise ValueError(f"{label} must be positive")
    if value > maximum:
        raise ValueError(f"{label} exceeds the global maximum")


def _require_aware(value: datetime, *, label: str) -> None:
    if not isinstance(value, datetime):
        raise TypeError(f"{label} must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")


@dataclass(frozen=True, slots=True)
class DurableCleanupAdministrationBounds:
    """Content-free server-owned cleanup bounds safe to bind into confirmation."""

    page_size: int
    max_candidates: int
    pass_timeout_microseconds: int
    payload_retention_microseconds: int
    metadata_retention_microseconds: int
    tombstone_retention_microseconds: int
    schema_version: int = 1

    def __post_init__(self) -> None:
        for label, value, maximum in (
            ("page_size", self.page_size, MAX_RETENTION_WORKER_PAGE_SIZE),
            ("max_candidates", self.max_candidates, MAX_RETENTION_WORKER_CANDIDATES),
            (
                "pass_timeout_microseconds",
                self.pass_timeout_microseconds,
                _MAX_RETENTION_WORKER_PASS_MICROSECONDS,
            ),
            (
                "payload_retention_microseconds",
                self.payload_retention_microseconds,
                _MAX_PAYLOAD_RETENTION_MICROSECONDS,
            ),
            (
                "metadata_retention_microseconds",
                self.metadata_retention_microseconds,
                _MAX_METADATA_RETENTION_MICROSECONDS,
            ),
            (
                "tombstone_retention_microseconds",
                self.tombstone_retention_microseconds,
                _MAX_TOMBSTONE_RETENTION_MICROSECONDS,
            ),
        ):
            _require_positive_integer(value, label=label, maximum=maximum)

        if self.payload_retention_microseconds > self.metadata_retention_microseconds:
            raise ValueError("payload retention cannot exceed metadata retention")
        if self.metadata_retention_microseconds > self.tombstone_retention_microseconds:
            raise ValueError("metadata retention cannot exceed tombstone retention")
        if self.schema_version != 1:
            raise ValueError("unsupported durable cleanup administration bounds version")


@runtime_checkable
class DurableCleanupAdministrationWorker(Protocol):
    """Retention worker capabilities required by the cleanup administration boundary."""

    @property
    def policy(self) -> RetentionPolicy: ...

    @property
    def configuration(self) -> DurableRetentionWorkerConfiguration: ...

    def run_once(self) -> Awaitable[DurableRetentionWorkerReport]: ...


class DurableCleanupAdministration:
    """Authorize and audit one server-configured bounded destructive cleanup pass."""

    def __init__(
        self,
        *,
        worker: DurableCleanupAdministrationWorker,
        audit: AuditLedger,
    ) -> None:
        if not isinstance(worker, DurableCleanupAdministrationWorker):
            raise TypeError("worker must implement DurableCleanupAdministrationWorker")
        if not isinstance(audit, AuditLedger):
            raise TypeError("audit must be AuditLedger")

        self._worker = worker
        self._audit = audit
        self._closed = False
        self._operation_lock = asyncio.Lock()
        self._close_lock = asyncio.Lock()

    @property
    def closed(self) -> bool:
        return self._closed

    def bounds(
        self,
        context: SecurityContext,
    ) -> DurableCleanupAdministrationBounds:
        """Return only the exact server-owned bounds after cleanup authorization."""

        self._authorize(context)
        self._ensure_open()
        return _worker_bounds(self._worker)

    async def run(
        self,
        context: SecurityContext,
        *,
        expected_bounds: DurableCleanupAdministrationBounds,
        requested_at: datetime,
    ) -> DurableRetentionWorkerReport:
        """Run one bounded cleanup pass after exact auth, bound check, and audit."""

        self._authorize(context)

        if not isinstance(expected_bounds, DurableCleanupAdministrationBounds):
            raise TypeError("expected_bounds must be DurableCleanupAdministrationBounds")
        _require_aware(requested_at, label="requested_at")

        async with self._operation_lock:
            self._ensure_open()

            current_bounds = _worker_bounds(self._worker)
            if expected_bounds != current_bounds:
                raise AgentStateConflictError()

            await self._audit_request(
                context,
                bounds=current_bounds,
                requested_at=requested_at,
            )

            try:
                report = await self._worker.run_once()
            except asyncio.CancelledError:
                raise
            except AgentStateConflictError:
                raise
            except Exception:
                raise AgentServiceUnavailableError() from None

            await self._audit_outcome_best_effort(
                context,
                report=report,
            )
            return report

    async def close(self) -> None:
        """Stop cleanup admission and drain an already admitted pass."""

        self._closed = True
        await _await_drain(self._drain_close())

    async def _drain_close(self) -> None:
        async with self._close_lock:
            self._closed = True
            async with self._operation_lock:
                return

    def _ensure_open(self) -> None:
        if self._closed:
            raise AgentServiceUnavailableError()

    @staticmethod
    def _authorize(context: SecurityContext) -> None:
        if not isinstance(context, SecurityContext):
            raise TypeError("context must be SecurityContext")
        if (
            not context.authenticated
            or context.principal_type is not PrincipalType.USER
            or AGENT_DURABLE_CLEANUP_ACTION not in context.permissions
        ):
            raise AgentAdministrationAccessDeniedError()

    async def _audit_request(
        self,
        context: SecurityContext,
        *,
        bounds: DurableCleanupAdministrationBounds,
        requested_at: datetime,
    ) -> None:
        details: dict[str, object] = {
            "bounds_schema_version": bounds.schema_version,
            "max_candidates": bounds.max_candidates,
            "metadata_retention_microseconds": bounds.metadata_retention_microseconds,
            "page_size": bounds.page_size,
            "pass_timeout_microseconds": bounds.pass_timeout_microseconds,
            "payload_retention_microseconds": bounds.payload_retention_microseconds,
            "requested_at": requested_at.isoformat(),
            "tombstone_retention_microseconds": bounds.tombstone_retention_microseconds,
        }
        try:
            await self._audit.record_security(
                "agent.durable.cleanup.requested",
                category=AuditCategory.STATE,
                action=AGENT_DURABLE_CLEANUP_ACTION,
                resource=DURABLE_ADMINISTRATION_CLEANUP_RESOURCE,
                context=context,
                outcome=AuditOutcome.UNKNOWN,
                severity=AuditSeverity.WARNING,
                details=details,
                source="phoenix.agent.durable",
            )
        except Exception:
            raise AgentServiceUnavailableError() from None

    async def _audit_outcome_best_effort(
        self,
        context: SecurityContext,
        *,
        report: DurableRetentionWorkerReport,
    ) -> None:
        try:
            failed = report.failed > 0 or report.timed_out or report.stopped
            details: dict[str, object] = {
                "admitted": report.admitted,
                "conflicts": report.conflicts,
                "exhausted": report.exhausted,
                "failed": report.failed,
                "pages": report.pages,
                "payloads_deleted": report.payloads_deleted,
                "purged": report.purged,
                "stopped": report.stopped,
                "timed_out": report.timed_out,
                "tombstoned": report.tombstoned,
            }
            await self._audit.record_security(
                "agent.durable.cleanup.outcome",
                category=AuditCategory.STATE,
                action=AGENT_DURABLE_CLEANUP_ACTION,
                resource=DURABLE_ADMINISTRATION_CLEANUP_RESOURCE,
                context=context,
                outcome=AuditOutcome.FAILED if failed else AuditOutcome.SUCCEEDED,
                severity=AuditSeverity.WARNING if failed else AuditSeverity.INFO,
                details=details,
                source="phoenix.agent.durable",
            )
        except (Exception, asyncio.CancelledError):
            # Mutation may already have committed. Post-commit reporting must
            # never manufacture a retry signal, including caller cancellation.
            return


def _worker_bounds(
    worker: DurableCleanupAdministrationWorker,
) -> DurableCleanupAdministrationBounds:
    try:
        policy = worker.policy
        configuration = worker.configuration

        if not isinstance(policy, RetentionPolicy):
            raise AgentServiceUnavailableError()
        if not isinstance(configuration, DurableRetentionWorkerConfiguration):
            raise AgentServiceUnavailableError()

        return DurableCleanupAdministrationBounds(
            page_size=configuration.page_size,
            max_candidates=configuration.max_candidates,
            pass_timeout_microseconds=_timedelta_microseconds(configuration.pass_timeout),
            payload_retention_microseconds=_timedelta_microseconds(policy.payload_retention),
            metadata_retention_microseconds=_timedelta_microseconds(policy.metadata_retention),
            tombstone_retention_microseconds=_timedelta_microseconds(policy.tombstone_retention),
        )
    except AgentServiceUnavailableError:
        raise
    except Exception:
        raise AgentServiceUnavailableError() from None


async def _await_drain(operation: Awaitable[None]) -> None:
    task = asyncio.ensure_future(operation)
    cancelled = False
    while True:
        try:
            await asyncio.shield(task)
            break
        except asyncio.CancelledError:
            cancelled = True
            if task.done():
                break
    task.result()
    if cancelled:
        raise asyncio.CancelledError()
