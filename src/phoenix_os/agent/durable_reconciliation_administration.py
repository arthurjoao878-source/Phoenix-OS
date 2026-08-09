"""Fenced, audited administration for reviewed durable reconciliation."""

from __future__ import annotations

import asyncio
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from typing import Protocol, runtime_checkable
from uuid import UUID, uuid4

from phoenix_os.agent.durable_authorization import (
    AGENT_RECONCILE_ACTION,
    durable_reconciliation_resource,
)
from phoenix_os.agent.durable_contracts import (
    CheckpointDigest,
    CheckpointEnvelope,
    CheckpointId,
    CheckpointNextOperation,
    CheckpointSequence,
    DurableAgentRunId,
    DurableLease,
    DurableRunStatus,
    DurableRunStore,
    DurableRunVersion,
    ExecutionAttemptId,
    ExecutionAttemptStatus,
    FencingGeneration,
    ReconciliationDecision,
    ReconciliationEvidence,
    ReconciliationRequest,
)
from phoenix_os.agent.durable_lease import DurableLeaseManager
from phoenix_os.agent.durable_observer import (
    DurableRunObservation,
    DurableRunObservationOutcome,
    DurableRunObserver,
    DurableRunOperation,
    NullDurableRunObserver,
)
from phoenix_os.agent.durable_reconciliation import (
    DurableReconciliationDispositionApplier,
    reconciliation_disposition_record,
)
from phoenix_os.agent.durable_status_lookup import (
    DurableAttemptExternalStatus,
    DurableAttemptStatusLookupOutcome,
    DurableAttemptStatusLookupResult,
)
from phoenix_os.agent.errors import (
    AgentAdministrationAccessDeniedError,
    AgentError,
    AgentLimitExceededError,
    AgentServiceUnavailableError,
    AgentStateConflictError,
)
from phoenix_os.audit import AuditCategory, AuditLedger, AuditOutcome, AuditSeverity
from phoenix_os.policy import PrincipalType, SecurityContext

DEFAULT_DURABLE_RECONCILIATION_PREPARATION_CAPACITY = 1024
MAX_DURABLE_RECONCILIATION_PREPARATION_CAPACITY = 100_000
DEFAULT_DURABLE_RECONCILIATION_PREPARATION_TTL = timedelta(minutes=2)
MAX_DURABLE_RECONCILIATION_PREPARATION_TTL = timedelta(minutes=10)

_DEFAULT_OWNER_ID = "reconciliation-admin"
_IDENTIFIER_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,127})$")

_CONFIRM_DECISIONS = frozenset(
    {
        ReconciliationDecision.CONFIRM_SUCCEEDED,
        ReconciliationDecision.CONFIRM_FAILED,
        ReconciliationDecision.CONFIRM_NOT_STARTED,
    }
)
_FAILED_EXTERNAL_STATUSES = frozenset(
    {
        DurableAttemptExternalStatus.FAILED,
        DurableAttemptExternalStatus.CANCELLED,
        DurableAttemptExternalStatus.TIMED_OUT,
    }
)

type DurableReconciliationAdministrationClock = Callable[[], datetime]
type DurableReconciliationPreparationIdFactory = Callable[[], UUID]


@runtime_checkable
class DurableReconciliationStatusLookup(Protocol):
    """Trusted reviewed status lookup used only during reconciliation preparation."""

    async def lookup(
        self,
        checkpoint: CheckpointEnvelope,
        *,
        requested_at: datetime,
    ) -> DurableAttemptStatusLookupResult: ...


@dataclass(frozen=True, slots=True)
class DurableReconciliationAdministrationPreparation:
    """Exact server-prepared reconciliation handle with a safe evidence projection."""

    run_id: DurableAgentRunId
    attempt_id: ExecutionAttemptId
    expected_version: DurableRunVersion
    checkpoint_id: CheckpointId
    checkpoint_digest: CheckpointDigest
    decision: ReconciliationDecision
    requested_at: datetime
    prepared_at: datetime
    expires_at: datetime
    evidence_type: str | None = None
    evidence_digest: CheckpointDigest | None = None
    evidence_observed_at: datetime | None = None
    id: UUID = field(default_factory=uuid4)
    schema_version: int = 1

    def __post_init__(self) -> None:
        if not isinstance(self.run_id, DurableAgentRunId):
            raise TypeError("run_id must be DurableAgentRunId")
        if not isinstance(self.attempt_id, ExecutionAttemptId):
            raise TypeError("attempt_id must be ExecutionAttemptId")
        if not isinstance(self.expected_version, DurableRunVersion):
            raise TypeError("expected_version must be DurableRunVersion")
        if not isinstance(self.checkpoint_id, CheckpointId):
            raise TypeError("checkpoint_id must be CheckpointId")
        if not isinstance(self.checkpoint_digest, CheckpointDigest):
            raise TypeError("checkpoint_digest must be CheckpointDigest")
        if not isinstance(self.decision, ReconciliationDecision):
            raise TypeError("decision must be ReconciliationDecision")
        _require_aware(self.requested_at, "requested_at")
        _require_aware(self.prepared_at, "prepared_at")
        _require_aware(self.expires_at, "expires_at")
        if self.prepared_at < self.requested_at:
            raise ValueError("reconciliation preparation cannot precede request")
        if self.expires_at <= self.prepared_at:
            raise ValueError("reconciliation preparation expiry must follow preparation")
        if self.expires_at - self.prepared_at > MAX_DURABLE_RECONCILIATION_PREPARATION_TTL:
            raise ValueError("reconciliation preparation expiry exceeds the global maximum")
        evidence_values = (
            self.evidence_type,
            self.evidence_digest,
            self.evidence_observed_at,
        )
        evidence_present = any(value is not None for value in evidence_values)
        evidence_complete = all(value is not None for value in evidence_values)
        if evidence_present != evidence_complete:
            raise ValueError("reconciliation evidence projection must be complete")
        if self.decision in _CONFIRM_DECISIONS and not evidence_complete:
            raise ValueError("confirmed reconciliation requires safe evidence projection")
        if self.decision not in _CONFIRM_DECISIONS and evidence_present:
            raise ValueError("selected reconciliation decision cannot expose evidence projection")
        if evidence_complete:
            if (
                not isinstance(self.evidence_type, str)
                or _IDENTIFIER_PATTERN.fullmatch(self.evidence_type) is None
                or not isinstance(self.evidence_digest, CheckpointDigest)
                or not isinstance(self.evidence_observed_at, datetime)
            ):
                raise ValueError("reconciliation evidence projection is invalid")
            _require_aware(self.evidence_observed_at, "evidence_observed_at")
            if self.evidence_observed_at > self.requested_at:
                raise ValueError("reconciliation evidence cannot follow request")
        if not isinstance(self.id, UUID):
            raise TypeError("reconciliation preparation id must be UUID")
        if self.schema_version != 1:
            raise ValueError("unsupported reconciliation preparation version")


@dataclass(frozen=True, slots=True)
class _DurableReconciliationPreparedState:
    """Server-only trusted reconciliation state never exposed by administration."""

    preparation: DurableReconciliationAdministrationPreparation
    actor_id: str
    lease: DurableLease = field(repr=False)
    evidence: ReconciliationEvidence | None = field(default=None, repr=False)
    lookup_result: DurableAttemptStatusLookupResult | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if not isinstance(
            self.preparation,
            DurableReconciliationAdministrationPreparation,
        ):
            raise TypeError("preparation must be DurableReconciliationAdministrationPreparation")
        if (
            not isinstance(self.actor_id, str)
            or _IDENTIFIER_PATTERN.fullmatch(self.actor_id) is None
        ):
            raise ValueError("prepared reconciliation actor_id is invalid")
        if not isinstance(self.lease, DurableLease):
            raise TypeError("prepared reconciliation lease must be DurableLease")
        if (
            self.lease.run_id != self.preparation.run_id
            or self.lease.acquired_at != self.preparation.requested_at
            or not self.lease.active_at(self.preparation.requested_at)
            or self.preparation.expires_at > self.lease.expires_at
        ):
            raise ValueError("prepared reconciliation lease does not bind to preparation")

        decision = self.preparation.decision
        if decision in _CONFIRM_DECISIONS:
            lookup = self.lookup_result
            evidence = self.evidence
            if not isinstance(lookup, DurableAttemptStatusLookupResult):
                raise ValueError("confirmed reconciliation requires trusted lookup evidence")
            if not isinstance(evidence, ReconciliationEvidence):
                raise ValueError("confirmed reconciliation requires trusted evidence")
            if evidence.metadata:
                raise ValueError("administrative reconciliation evidence metadata must be empty")
            if lookup.evidence != evidence:
                raise ValueError("trusted lookup evidence does not match preparation evidence")
            if (
                self.preparation.evidence_type != evidence.evidence_type
                or self.preparation.evidence_digest != evidence.evidence_digest
                or self.preparation.evidence_observed_at != evidence.observed_at
            ):
                raise ValueError("safe evidence projection does not match trusted evidence")
            query = lookup.query
            if (
                query.durable_run_id != self.preparation.run_id
                or query.checkpoint_id != self.preparation.checkpoint_id
                or query.checkpoint_digest != self.preparation.checkpoint_digest
                or query.run_version != self.preparation.expected_version
                or query.attempt_id != self.preparation.attempt_id
                or query.requested_at > self.preparation.requested_at
                or evidence.observed_at > self.preparation.requested_at
                or not _lookup_supports_decision(lookup, decision)
            ):
                raise ValueError("trusted lookup does not bind to reconciliation preparation")
        elif self.evidence is not None or self.lookup_result is not None:
            raise ValueError("selected reconciliation decision must not carry lookup evidence")


@dataclass(frozen=True, slots=True)
class DurableReconciliationAdministrationResult:
    """Content-free result for one successfully checkpointed reconciliation."""

    run_id: DurableAgentRunId
    attempt_id: ExecutionAttemptId
    status: DurableRunStatus
    run_version: DurableRunVersion
    checkpoint_id: CheckpointId
    checkpoint_sequence: CheckpointSequence
    fencing_generation: FencingGeneration
    decision: ReconciliationDecision
    applied_at: datetime
    checkpoint_digest: CheckpointDigest
    schema_version: int = 1

    def __post_init__(self) -> None:
        if not isinstance(self.run_id, DurableAgentRunId):
            raise TypeError("run_id must be DurableAgentRunId")
        if not isinstance(self.attempt_id, ExecutionAttemptId):
            raise TypeError("attempt_id must be ExecutionAttemptId")
        if not isinstance(self.status, DurableRunStatus):
            raise TypeError("status must be DurableRunStatus")
        if not isinstance(self.run_version, DurableRunVersion):
            raise TypeError("run_version must be DurableRunVersion")
        if not isinstance(self.checkpoint_id, CheckpointId):
            raise TypeError("checkpoint_id must be CheckpointId")
        if not isinstance(self.checkpoint_sequence, CheckpointSequence):
            raise TypeError("checkpoint_sequence must be CheckpointSequence")
        if not isinstance(self.fencing_generation, FencingGeneration):
            raise TypeError("fencing_generation must be FencingGeneration")
        if not isinstance(self.decision, ReconciliationDecision):
            raise TypeError("decision must be ReconciliationDecision")
        _require_aware(self.applied_at, "applied_at")
        if not isinstance(self.checkpoint_digest, CheckpointDigest):
            raise TypeError("checkpoint_digest must be CheckpointDigest")
        if self.schema_version != 1:
            raise ValueError("unsupported reconciliation administration result version")


class DurableReconciliationAdministration:
    """Prepare trusted evidence and apply one audited fenced reconciliation."""

    def __init__(
        self,
        *,
        store: DurableRunStore,
        lease_manager: DurableLeaseManager,
        applier: DurableReconciliationDispositionApplier,
        audit: AuditLedger,
        status_lookup: DurableReconciliationStatusLookup | None = None,
        observer: DurableRunObserver | None = None,
        owner_id: str = _DEFAULT_OWNER_ID,
        preparation_capacity: int = DEFAULT_DURABLE_RECONCILIATION_PREPARATION_CAPACITY,
        preparation_ttl: timedelta = DEFAULT_DURABLE_RECONCILIATION_PREPARATION_TTL,
        clock: DurableReconciliationAdministrationClock | None = None,
        preparation_id_factory: DurableReconciliationPreparationIdFactory = uuid4,
    ) -> None:
        if not isinstance(store, DurableRunStore):
            raise TypeError("store must implement DurableRunStore")
        if not isinstance(lease_manager, DurableLeaseManager):
            raise TypeError("lease_manager must implement DurableLeaseManager")
        if not isinstance(applier, DurableReconciliationDispositionApplier):
            raise TypeError("applier must implement DurableReconciliationDispositionApplier")
        if not isinstance(audit, AuditLedger):
            raise TypeError("audit must be AuditLedger")
        if status_lookup is not None and not isinstance(
            status_lookup,
            DurableReconciliationStatusLookup,
        ):
            raise TypeError("status_lookup must implement DurableReconciliationStatusLookup")
        selected_observer = NullDurableRunObserver() if observer is None else observer
        if not isinstance(selected_observer, DurableRunObserver):
            raise TypeError("observer must implement DurableRunObserver")

        normalized_owner = owner_id.strip().lower()
        if _IDENTIFIER_PATTERN.fullmatch(normalized_owner) is None:
            raise ValueError("reconciliation administration owner_id is invalid")
        if isinstance(preparation_capacity, bool) or not isinstance(preparation_capacity, int):
            raise TypeError("reconciliation preparation capacity must be an integer")
        if (
            preparation_capacity <= 0
            or preparation_capacity > MAX_DURABLE_RECONCILIATION_PREPARATION_CAPACITY
        ):
            raise ValueError("reconciliation preparation capacity is outside supported bounds")
        if not isinstance(preparation_ttl, timedelta):
            raise TypeError("reconciliation preparation TTL must be timedelta")
        if (
            preparation_ttl <= timedelta(0)
            or preparation_ttl > MAX_DURABLE_RECONCILIATION_PREPARATION_TTL
        ):
            raise ValueError("reconciliation preparation TTL is outside supported bounds")
        if not callable(preparation_id_factory):
            raise TypeError("preparation_id_factory must be callable")
        selected_clock = (lambda: datetime.now(UTC)) if clock is None else clock
        if not callable(selected_clock):
            raise TypeError("reconciliation administration clock must be callable")

        bound_lease_manager = getattr(store, "lease_manager", None)
        if bound_lease_manager is not None and bound_lease_manager is not lease_manager:
            raise ValueError("lease_manager must match the durable store lease manager")

        self._store = store
        self._lease_manager = lease_manager
        self._applier = applier
        self._audit = audit
        self._status_lookup = status_lookup
        self._observer = selected_observer
        self._owner_id = normalized_owner
        self._preparation_capacity = preparation_capacity
        self._preparation_ttl = preparation_ttl
        self._clock: DurableReconciliationAdministrationClock = selected_clock
        self._preparation_id_factory = preparation_id_factory
        self._preparations: dict[UUID, _DurableReconciliationPreparedState] = {}
        self._closed = False
        self._lock = asyncio.Lock()
        self._operation_lock = asyncio.Lock()
        self._close_lock = asyncio.Lock()

    @property
    def closed(self) -> bool:
        return self._closed

    async def prepare(
        self,
        run_id: DurableAgentRunId,
        attempt_id: ExecutionAttemptId,
        expected_version: DurableRunVersion,
        decision: ReconciliationDecision,
        context: SecurityContext,
    ) -> DurableReconciliationAdministrationPreparation:
        """Reserve fencing and prepare only current trusted reconciliation evidence."""

        _require_human_reconciliation_permission(context)
        actor_id = _durable_actor_id(context)
        if not isinstance(run_id, DurableAgentRunId):
            raise TypeError("run_id must be DurableAgentRunId")
        if not isinstance(attempt_id, ExecutionAttemptId):
            raise TypeError("attempt_id must be ExecutionAttemptId")
        if not isinstance(expected_version, DurableRunVersion):
            raise TypeError("expected_version must be DurableRunVersion")
        if not isinstance(decision, ReconciliationDecision):
            raise TypeError("decision must be ReconciliationDecision")

        async with self._operation_lock:
            self._ensure_open()
            return await self._prepare_once(
                run_id,
                attempt_id,
                expected_version,
                decision,
                actor_id=actor_id,
            )

    async def _prepare_once(
        self,
        run_id: DurableAgentRunId,
        attempt_id: ExecutionAttemptId,
        expected_version: DurableRunVersion,
        decision: ReconciliationDecision,
        *,
        actor_id: str,
    ) -> DurableReconciliationAdministrationPreparation:
        lookup_started_at = self._now()
        try:
            checkpoint = await self._store.get_current(run_id)
        except Exception:
            raise AgentServiceUnavailableError() from None
        _require_preparable_checkpoint(
            checkpoint,
            run_id=run_id,
            attempt_id=attempt_id,
            expected_version=expected_version,
            now=lookup_started_at,
        )
        assert checkpoint is not None

        lookup_result: DurableAttemptStatusLookupResult | None = None
        evidence: ReconciliationEvidence | None = None
        if decision in _CONFIRM_DECISIONS:
            lookup = self._status_lookup
            if lookup is None:
                raise AgentServiceUnavailableError()
            try:
                lookup_result = await lookup.lookup(
                    checkpoint,
                    requested_at=lookup_started_at,
                )
            except (TypeError, ValueError):
                raise AgentStateConflictError() from None
            except Exception:
                raise AgentServiceUnavailableError() from None
            if not _lookup_supports_decision(lookup_result, decision):
                raise AgentStateConflictError()
            evidence = lookup_result.evidence
            if evidence is None or evidence.metadata:
                raise AgentStateConflictError()

        lease_requested_at = self._now()
        if lease_requested_at < lookup_started_at:
            raise AgentStateConflictError()
        if evidence is not None and evidence.observed_at > lease_requested_at:
            raise AgentStateConflictError()

        await self._prune_expired(lease_requested_at)

        try:
            lease = await self._lease_manager.acquire(
                run_id,
                owner_id=self._owner_id,
                now=lease_requested_at,
            )
        except AgentError:
            raise
        except asyncio.CancelledError:
            raise
        except Exception:
            raise AgentServiceUnavailableError() from None

        transferred = False
        try:
            prepared_at = self._now()
            if (
                prepared_at < lease.acquired_at
                or prepared_at >= lease.expires_at
                or lease.acquired_at != lease_requested_at
            ):
                raise AgentStateConflictError()

            try:
                current = await self._store.get_current(run_id)
            except Exception:
                raise AgentServiceUnavailableError() from None
            _require_matching_source_checkpoint(
                current,
                source=checkpoint,
                run_id=run_id,
                attempt_id=attempt_id,
                expected_version=expected_version,
                now=prepared_at,
            )
            assert current is not None

            expires_at = min(
                prepared_at + self._preparation_ttl,
                lease.expires_at,
            )
            if expires_at <= prepared_at:
                raise AgentStateConflictError()

            preparation_id = self._preparation_id_factory()
            if not isinstance(preparation_id, UUID):
                raise TypeError("preparation_id_factory must return UUID")

            try:
                preparation = DurableReconciliationAdministrationPreparation(
                    run_id=run_id,
                    attempt_id=attempt_id,
                    expected_version=expected_version,
                    checkpoint_id=current.checkpoint_id,
                    checkpoint_digest=current.digest,
                    decision=decision,
                    requested_at=lease.acquired_at,
                    prepared_at=prepared_at,
                    expires_at=expires_at,
                    evidence_type=None if evidence is None else evidence.evidence_type,
                    evidence_digest=None if evidence is None else evidence.evidence_digest,
                    evidence_observed_at=(None if evidence is None else evidence.observed_at),
                    id=preparation_id,
                )
                prepared_state = _DurableReconciliationPreparedState(
                    preparation=preparation,
                    actor_id=actor_id,
                    lease=lease,
                    evidence=evidence,
                    lookup_result=lookup_result,
                )
            except (TypeError, ValueError) as exception:
                raise AgentStateConflictError() from exception

            async with self._lock:
                if self._closed:
                    raise AgentServiceUnavailableError()
                if len(self._preparations) >= self._preparation_capacity:
                    raise AgentLimitExceededError()
                if preparation.id in self._preparations:
                    raise AgentStateConflictError()
                self._preparations[preparation.id] = prepared_state
                transferred = True
            return preparation
        finally:
            if not transferred:
                await self._release_reserved_lease(
                    lease,
                    release_at=lease.acquired_at,
                )

    async def apply(
        self,
        preparation: DurableReconciliationAdministrationPreparation,
        context: SecurityContext,
    ) -> DurableReconciliationAdministrationResult:
        """Consume one fenced server preparation, audit, and apply reconciliation."""

        if not isinstance(preparation, DurableReconciliationAdministrationPreparation):
            raise TypeError("preparation must be DurableReconciliationAdministrationPreparation")
        _require_human_reconciliation_permission(context)

        async with self._operation_lock:
            self._ensure_open()
            return await self._apply_once(preparation, context)

    async def _apply_once(
        self,
        preparation: DurableReconciliationAdministrationPreparation,
        context: SecurityContext,
    ) -> DurableReconciliationAdministrationResult:
        now = self._now()
        if now < preparation.prepared_at:
            raise AgentStateConflictError()

        actor_id = _durable_actor_id(context)
        prepared_state = await self._consume_preparation(
            preparation,
            actor_id=actor_id,
            now=now,
        )
        lease = prepared_state.lease

        committed = False
        failure: BaseException | None = None
        try:
            if not lease.active_at(now):
                raise AgentStateConflictError()
            try:
                current = await self._store.get_current(preparation.run_id)
            except Exception:
                raise AgentServiceUnavailableError() from None
            _require_matching_preparation(current, preparation=preparation, now=now)
            assert current is not None

            request = ReconciliationRequest(
                run_id=preparation.run_id,
                attempt_id=preparation.attempt_id,
                actor_id=actor_id,
                expected_version=preparation.expected_version,
                generation=lease.generation,
                decision=preparation.decision,
                evidence=prepared_state.evidence,
                requested_at=preparation.requested_at,
            )
            audit_context = replace(
                context,
                correlation_id=str(preparation.run_id),
                causation_id=preparation.id,
            )
            await self._record_required_audit(
                preparation,
                evidence=prepared_state.evidence,
                request=request,
                checkpoint=current,
                context=audit_context,
            )

            try:
                applied = await self._applier.apply(
                    request,
                    lease=lease,
                    context=audit_context,
                    now=now,
                    lookup_result=prepared_state.lookup_result,
                )
                committed = True
            except AgentError:
                raise
            except asyncio.CancelledError:
                raise
            except Exception:
                raise AgentServiceUnavailableError() from None

            try:
                record = reconciliation_disposition_record(applied)
            except (TypeError, ValueError, OverflowError):
                raise AgentStateConflictError() from None
            if (
                record.run_id != preparation.run_id
                or record.attempt_id != preparation.attempt_id
                or record.actor_id != actor_id
                or record.generation != lease.generation
                or record.decision is not preparation.decision
                or record.source_checkpoint_id != preparation.checkpoint_id
                or record.source_checkpoint_digest != preparation.checkpoint_digest
                or record.source_version != preparation.expected_version
                or record.requested_at != preparation.requested_at
                or record.result_status is not applied.status
                or record.applied_at != now
            ):
                raise AgentStateConflictError()

            result = DurableReconciliationAdministrationResult(
                run_id=applied.durable_run_id,
                attempt_id=preparation.attempt_id,
                status=applied.status,
                run_version=applied.run_version,
                checkpoint_id=applied.checkpoint_id,
                checkpoint_sequence=applied.sequence,
                fencing_generation=lease.generation,
                decision=preparation.decision,
                applied_at=applied.created_at,
                checkpoint_digest=applied.digest,
            )
        except (Exception, asyncio.CancelledError) as exception:
            failure = exception
            raise
        finally:
            try:
                await _await_drain(self._lease_manager.release(lease, now=now))
            except asyncio.CancelledError:
                if not committed and failure is None:
                    raise
            except Exception:
                if not committed and failure is None:
                    raise AgentServiceUnavailableError() from None

        await self._observe_success(result, applied, context=audit_context)
        return result

    async def discard(self, preparation_id: UUID) -> None:
        """Discard one unused preparation and release its reserved lease."""

        if not isinstance(preparation_id, UUID):
            raise TypeError("preparation_id must be UUID")

        async with self._operation_lock:
            self._ensure_open()
            async with self._lock:
                state = self._preparations.get(preparation_id)
            if state is None:
                return
            await self._release_reserved_state(state)
            async with self._lock:
                if self._preparations.get(preparation_id) is state:
                    del self._preparations[preparation_id]

    async def close(self) -> None:
        await _await_drain(self._drain_close())

    async def _drain_close(self) -> None:
        async with self._close_lock:
            async with self._lock:
                self._closed = True

            async with self._operation_lock:
                async with self._lock:
                    reservations = tuple(self._preparations.items())

                failure: BaseException | None = None
                for preparation_id, state in reservations:
                    try:
                        await self._release_reserved_state(state)
                    except (Exception, asyncio.CancelledError) as exception:
                        if failure is None:
                            failure = exception
                    finally:
                        async with self._lock:
                            if self._preparations.get(preparation_id) is state:
                                del self._preparations[preparation_id]

                if failure is not None:
                    raise failure

    async def _consume_preparation(
        self,
        preparation: DurableReconciliationAdministrationPreparation,
        *,
        actor_id: str,
        now: datetime,
    ) -> _DurableReconciliationPreparedState:
        await self._prune_expired(now)
        async with self._lock:
            stored = self._preparations.get(preparation.id)
            if (
                stored is None
                or stored.preparation != preparation
                or stored.actor_id != actor_id
                or now >= stored.preparation.expires_at
            ):
                raise AgentStateConflictError()
            del self._preparations[preparation.id]
            return stored

    async def _record_required_audit(
        self,
        preparation: DurableReconciliationAdministrationPreparation,
        *,
        evidence: ReconciliationEvidence | None,
        request: ReconciliationRequest,
        checkpoint: CheckpointEnvelope,
        context: SecurityContext,
    ) -> None:
        details: dict[str, object] = {
            "run_id": str(preparation.run_id),
            "attempt_id": str(preparation.attempt_id),
            "checkpoint_id": str(checkpoint.checkpoint_id),
            "checkpoint_digest": str(checkpoint.digest),
            "expected_version": preparation.expected_version.value,
            "fencing_generation": request.generation.value,
            "decision": preparation.decision.value,
            "prepared_at": preparation.prepared_at.isoformat(),
            "requested_at": request.requested_at.isoformat(),
        }
        if evidence is not None:
            details.update(
                {
                    "evidence_type": evidence.evidence_type,
                    "evidence_digest": str(evidence.evidence_digest),
                    "evidence_observed_at": evidence.observed_at.isoformat(),
                }
            )
        try:
            await self._audit.record_security(
                "agent.durable.reconciliation.requested",
                category=AuditCategory.STATE,
                action=AGENT_RECONCILE_ACTION,
                resource=durable_reconciliation_resource(
                    preparation.run_id,
                    preparation.attempt_id,
                ),
                context=context,
                outcome=AuditOutcome.UNKNOWN,
                severity=AuditSeverity.WARNING,
                details=details,
                source="phoenix.agent.durable",
            )
        except Exception:
            raise AgentServiceUnavailableError() from None

    async def _observe_success(
        self,
        result: DurableReconciliationAdministrationResult,
        checkpoint: CheckpointEnvelope,
        *,
        context: SecurityContext,
    ) -> None:
        try:
            await self._observer.record(
                DurableRunObservation(
                    operation=DurableRunOperation.RECONCILIATION,
                    outcome=DurableRunObservationOutcome.SUCCEEDED,
                    run_id=result.run_id,
                    status=result.status,
                    checkpoint_id=result.checkpoint_id,
                    sequence=result.checkpoint_sequence,
                    fencing_generation=result.fencing_generation,
                    payload_profile=checkpoint.metadata.payload_profile,
                    checkpoint_digest=result.checkpoint_digest,
                    category=result.decision.value,
                ),
                context,
            )
        except (Exception, asyncio.CancelledError):
            pass

    async def _prune_expired(self, now: datetime) -> None:
        async with self._lock:
            expired = tuple(
                (preparation_id, state)
                for preparation_id, state in self._preparations.items()
                if now >= state.preparation.expires_at
            )

        for preparation_id, state in expired:
            await self._release_reserved_state(state)
            async with self._lock:
                if self._preparations.get(preparation_id) is state:
                    del self._preparations[preparation_id]

    async def _release_reserved_state(
        self,
        state: _DurableReconciliationPreparedState,
    ) -> None:
        await self._release_reserved_lease(
            state.lease,
            release_at=state.preparation.requested_at,
        )

    async def _release_reserved_lease(
        self,
        lease: DurableLease,
        *,
        release_at: datetime,
    ) -> None:
        try:
            await _await_drain(self._lease_manager.release(lease, now=release_at))
        except AgentStateConflictError:
            return
        except asyncio.CancelledError:
            raise
        except Exception:
            raise AgentServiceUnavailableError() from None

    def _now(self) -> datetime:
        try:
            value = self._clock()
        except Exception:
            raise AgentServiceUnavailableError() from None
        if not isinstance(value, datetime):
            raise AgentServiceUnavailableError()
        if value.tzinfo is None or value.utcoffset() is None:
            raise AgentServiceUnavailableError()
        return value

    def _ensure_open(self) -> None:
        if self._closed:
            raise AgentServiceUnavailableError()


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


def _require_human_reconciliation_permission(context: SecurityContext) -> None:
    if not isinstance(context, SecurityContext):
        raise TypeError("context must be SecurityContext")
    if (
        not context.authenticated
        or context.principal_type is not PrincipalType.USER
        or AGENT_RECONCILE_ACTION not in context.permissions
    ):
        raise AgentAdministrationAccessDeniedError()


def _durable_actor_id(context: SecurityContext) -> str:
    value = context.attributes.get("durable_actor_id", context.principal)
    if not isinstance(value, str):
        raise AgentAdministrationAccessDeniedError()
    normalized = value.strip().lower()
    if _IDENTIFIER_PATTERN.fullmatch(normalized) is None:
        raise AgentAdministrationAccessDeniedError()
    return normalized


def _require_preparable_checkpoint(
    checkpoint: CheckpointEnvelope | None,
    *,
    run_id: DurableAgentRunId,
    attempt_id: ExecutionAttemptId,
    expected_version: DurableRunVersion,
    now: datetime,
) -> None:
    if checkpoint is None:
        raise AgentStateConflictError()
    attempt = checkpoint.metadata.active_attempt
    if (
        checkpoint.durable_run_id != run_id
        or checkpoint.run_version != expected_version
        or checkpoint.status
        not in {
            DurableRunStatus.INDETERMINATE_MODEL,
            DurableRunStatus.INDETERMINATE_TOOL,
        }
        or checkpoint.metadata.next_operation is not CheckpointNextOperation.OPERATOR_REVIEW
        or attempt is None
        or attempt.attempt_id != attempt_id
        or attempt.status is not ExecutionAttemptStatus.INDETERMINATE
        or now < checkpoint.created_at
        or now >= checkpoint.metadata.retention_deadline
    ):
        raise AgentStateConflictError()


def _require_matching_source_checkpoint(
    checkpoint: CheckpointEnvelope | None,
    *,
    source: CheckpointEnvelope,
    run_id: DurableAgentRunId,
    attempt_id: ExecutionAttemptId,
    expected_version: DurableRunVersion,
    now: datetime,
) -> None:
    _require_preparable_checkpoint(
        checkpoint,
        run_id=run_id,
        attempt_id=attempt_id,
        expected_version=expected_version,
        now=now,
    )
    assert checkpoint is not None
    if (
        checkpoint.checkpoint_id != source.checkpoint_id
        or checkpoint.digest != source.digest
        or checkpoint.run_version != source.run_version
    ):
        raise AgentStateConflictError()


def _require_matching_preparation(
    checkpoint: CheckpointEnvelope | None,
    *,
    preparation: DurableReconciliationAdministrationPreparation,
    now: datetime,
) -> None:
    _require_preparable_checkpoint(
        checkpoint,
        run_id=preparation.run_id,
        attempt_id=preparation.attempt_id,
        expected_version=preparation.expected_version,
        now=now,
    )
    assert checkpoint is not None
    if (
        checkpoint.checkpoint_id != preparation.checkpoint_id
        or checkpoint.digest != preparation.checkpoint_digest
    ):
        raise AgentStateConflictError()


def _lookup_supports_decision(
    result: DurableAttemptStatusLookupResult,
    decision: ReconciliationDecision,
) -> bool:
    if result.outcome is not DurableAttemptStatusLookupOutcome.OBSERVED or result.evidence is None:
        return False
    if decision is ReconciliationDecision.CONFIRM_SUCCEEDED:
        return result.status is DurableAttemptExternalStatus.SUCCEEDED
    if decision is ReconciliationDecision.CONFIRM_FAILED:
        return result.status in _FAILED_EXTERNAL_STATUSES
    if decision is ReconciliationDecision.CONFIRM_NOT_STARTED:
        return result.status is DurableAttemptExternalStatus.NOT_STARTED
    return False


def _require_aware(value: datetime, label: str) -> None:
    if not isinstance(value, datetime):
        raise TypeError(f"{label} must be datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")
