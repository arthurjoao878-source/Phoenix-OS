"""Durable delegation coordinator and fail-closed startup recovery."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta

from phoenix_os.agent.contracts import AgentRunId
from phoenix_os.agent.coordination import (
    AgentDelegationCoordinator,
    DelegatedChildRun,
)
from phoenix_os.agent.coordination_authorization import DelegationAuthorizer
from phoenix_os.agent.coordination_contracts import (
    DelegationBudget,
    DelegationId,
    DelegationLimits,
    DelegationRequest,
    DelegationStatus,
)
from phoenix_os.agent.coordination_durable_contracts import (
    DurableDelegationReconciliationDecision,
    DurableDelegationReconciliationRequest,
    DurableDelegationRecord,
    DurableDelegationRecoveryState,
    DurableDelegationStore,
    DurableDelegationVersion,
    durable_delegation_request_digest,
    require_recovery_page_limit,
)
from phoenix_os.agent.coordination_registry import AgentDelegationRegistry
from phoenix_os.agent.errors import (
    AgentCancelledError,
    AgentStateConflictError,
    AgentTimeoutError,
    DelegationNotFoundError,
)
from phoenix_os.agent.state import AgentCancellationToken
from phoenix_os.authority import AuthorityFreshnessValidator
from phoenix_os.policy import SecurityContext


def _utc_now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class DurableDelegationRecoveryReport:
    """Content-free bounded startup recovery result."""

    scanned: int
    recoverable: int
    indeterminate: int
    expired: int

    def __post_init__(self) -> None:
        values = (self.scanned, self.recoverable, self.indeterminate, self.expired)
        if any(isinstance(value, bool) or not isinstance(value, int) for value in values):
            raise TypeError("recovery report counters must be integers")
        if min(values) < 0:
            raise ValueError("recovery report counters must not be negative")
        if self.recoverable + self.indeterminate + self.expired > self.scanned:
            raise ValueError("recovery report counters are inconsistent")


class DurableAgentDelegationCoordinator(AgentDelegationCoordinator):
    """Persist child identity before admission and never replay unknown running work."""

    def __init__(
        self,
        registry: AgentDelegationRegistry,
        authorizer: DelegationAuthorizer,
        *,
        store: DurableDelegationStore,
        limits: DelegationLimits,
        root_budget_limit: DelegationBudget,
        authority_freshness: AuthorityFreshnessValidator | None = None,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        if not isinstance(store, DurableDelegationStore):
            raise TypeError("store must implement DurableDelegationStore")
        if not callable(clock):
            raise TypeError("clock must be callable")
        super().__init__(
            registry,
            authorizer,
            limits=limits,
            root_budget_limit=root_budget_limit,
            authority_freshness=authority_freshness,
            clock=clock,
        )
        self._durable_registry = registry
        self._store = store
        self._durable_root_budget_limit = root_budget_limit
        self._durable_clock = clock

    @property
    def store(self) -> DurableDelegationStore:
        return self._store

    async def delegate(
        self,
        request: DelegationRequest,
        context: SecurityContext,
        *,
        cancellation: AgentCancellationToken | None = None,
        _trusted_child_run_id: AgentRunId | None = None,
    ) -> DelegatedChildRun:
        if _trusted_child_run_id is not None:
            raise TypeError("durable coordinator owns the trusted child run id")
        if not isinstance(request, DelegationRequest):
            raise TypeError("request must be DelegationRequest")
        descriptor = self._durable_registry.resolve_request(request)
        request_digest = durable_delegation_request_digest(request)
        record = await self._store.get(request.delegation_id)
        root_records = await self._store.list_root_records(request.lineage.root_run_id)
        _require_root_constraints(
            root_records,
            request=request,
            root_budget_limit=self._durable_root_budget_limit,
            creating=record is None,
        )
        created = False
        claimed_recovery = False

        if record is None:
            child_run_id = AgentRunId()
            record = DurableDelegationRecord(
                delegation_id=request.delegation_id,
                namespace=request.namespace,
                parent_agent_id=request.parent_agent_id,
                parent_run_id=request.parent_run_id,
                root_run_id=request.lineage.root_run_id,
                child_agent_id=request.child_agent_id,
                child_run_id=child_run_id,
                depth=request.child_depth,
                budget=request.budget,
                status=DelegationStatus.REQUESTED,
                request_digest=request_digest,
                compatibility_digest=descriptor.compatibility_digest,
                version=DurableDelegationVersion(),
                recovery_state=DurableDelegationRecoveryState.CLEAN,
                created_at=request.created_at,
                updated_at=request.created_at,
                deadline=request.deadline,
            )
            await self._store.create(
                record,
                limits=request.limits,
                root_budget_limit=self._durable_root_budget_limit,
            )
            created = True
        else:
            _require_matching_replay(
                record,
                request=request,
                request_digest=request_digest,
                compatibility_digest=descriptor.compatibility_digest,
            )
            if record.terminal:
                raise AgentStateConflictError()
            if (
                record.status is DelegationStatus.RUNNING
                or record.recovery_state is DurableDelegationRecoveryState.INDETERMINATE
            ):
                raise AgentStateConflictError()
            if record.recovery_state is not DurableDelegationRecoveryState.RECOVERABLE:
                raise AgentStateConflictError()
            claim_time = self._durable_clock()
            record = await self._store.compare_and_swap(
                replace(
                    record,
                    recovery_state=DurableDelegationRecoveryState.CLEAN,
                    version=record.version.next(),
                    updated_at=claim_time,
                ),
                expected_version=record.version,
            )
            claimed_recovery = True

        try:
            child = await super().delegate(
                request,
                context,
                cancellation=cancellation,
                _trusted_child_run_id=record.child_run_id,
            )
        except AgentCancelledError:
            if created or claimed_recovery:
                await self._persist_terminal(
                    record.delegation_id,
                    DelegationStatus.CANCELLED,
                    error_code="cancelled",
                )
            raise
        except AgentTimeoutError:
            if created or claimed_recovery:
                await self._persist_terminal(
                    record.delegation_id,
                    DelegationStatus.EXPIRED,
                    error_code="timeout",
                )
            raise
        except Exception:
            if created or claimed_recovery:
                await self._persist_terminal(
                    record.delegation_id,
                    DelegationStatus.FAILED,
                    error_code="delegation_rejected",
                )
            raise

        await self._persist_state(
            request.delegation_id,
            status=child.status,
            recovery_state=DurableDelegationRecoveryState.CLEAN,
        )
        return child

    async def start(
        self,
        delegation_id: DelegationId,
        *,
        now: datetime | None = None,
    ) -> DelegatedChildRun:
        current = await self._require_record(delegation_id)
        if current.status is not DelegationStatus.ADMITTED:
            raise AgentStateConflictError()
        resolved = self._resolve_durable_now(now)

        running = await self._store.compare_and_swap(
            replace(
                current,
                status=DelegationStatus.RUNNING,
                version=current.version.next(),
                recovery_state=DurableDelegationRecoveryState.CLEAN,
                updated_at=resolved,
                error_code=None,
            ),
            expected_version=current.version,
        )
        try:
            return await super().start(delegation_id, now=resolved)
        except Exception:
            await self._store.compare_and_swap(
                replace(
                    running,
                    status=DelegationStatus.ADMITTED,
                    version=running.version.next(),
                    recovery_state=DurableDelegationRecoveryState.CLEAN,
                    updated_at=resolved,
                    error_code=None,
                ),
                expected_version=running.version,
            )
            raise

    async def complete(
        self,
        delegation_id: DelegationId,
        *,
        now: datetime | None = None,
    ) -> DelegatedChildRun:
        resolved = self._resolve_durable_now(now)
        child = await super().complete(delegation_id, now=resolved)
        await self._persist_terminal(
            delegation_id,
            DelegationStatus.COMPLETED,
            now=resolved,
        )
        return child

    async def fail(
        self,
        delegation_id: DelegationId,
        *,
        now: datetime | None = None,
    ) -> DelegatedChildRun:
        resolved = self._resolve_durable_now(now)
        child = await super().fail(delegation_id, now=resolved)
        await self._persist_terminal(
            delegation_id,
            DelegationStatus.FAILED,
            now=resolved,
            error_code="child_failed",
        )
        return child

    async def cancel(
        self,
        delegation_id: DelegationId,
        *,
        now: datetime | None = None,
    ) -> DelegatedChildRun:
        resolved = self._resolve_durable_now(now)
        child = await super().cancel(delegation_id, now=resolved)
        await self._persist_terminal(
            delegation_id,
            DelegationStatus.CANCELLED,
            now=resolved,
            error_code="cancelled",
        )
        return child

    async def get(self, delegation_id: DelegationId) -> DelegatedChildRun:
        try:
            return await super().get(delegation_id)
        except DelegationNotFoundError:
            record = await self._require_record(delegation_id)
            return _record_child_view(record)

    async def durable_record(
        self,
        delegation_id: DelegationId,
    ) -> DurableDelegationRecord:
        return await self._require_record(delegation_id)

    async def _persist_state(
        self,
        delegation_id: DelegationId,
        *,
        status: DelegationStatus,
        recovery_state: DurableDelegationRecoveryState,
        now: datetime | None = None,
        error_code: str | None = None,
    ) -> DurableDelegationRecord:
        current = await self._require_record(delegation_id)
        resolved = self._resolve_durable_now(now)
        return await self._store.compare_and_swap(
            replace(
                current,
                status=status,
                recovery_state=recovery_state,
                version=current.version.next(),
                updated_at=resolved,
                error_code=error_code,
            ),
            expected_version=current.version,
        )

    async def _persist_terminal(
        self,
        delegation_id: DelegationId,
        status: DelegationStatus,
        *,
        now: datetime | None = None,
        error_code: str | None = None,
    ) -> DurableDelegationRecord:
        if status not in {
            DelegationStatus.COMPLETED,
            DelegationStatus.FAILED,
            DelegationStatus.CANCELLED,
            DelegationStatus.EXPIRED,
        }:
            raise ValueError("status must be terminal")
        return await self._persist_state(
            delegation_id,
            status=status,
            recovery_state=DurableDelegationRecoveryState.CLEAN,
            now=now,
            error_code=error_code,
        )

    async def _require_record(
        self,
        delegation_id: DelegationId,
    ) -> DurableDelegationRecord:
        if not isinstance(delegation_id, DelegationId):
            raise TypeError("delegation_id must be DelegationId")
        record = await self._store.get(delegation_id)
        if record is None:
            raise DelegationNotFoundError()
        return record

    def _resolve_durable_now(self, now: datetime | None) -> datetime:
        resolved = self._durable_clock() if now is None else now
        if not isinstance(resolved, datetime):
            raise TypeError("now must be a datetime")
        if resolved.tzinfo is None or resolved.utcoffset() is None:
            raise ValueError("now must be timezone-aware")
        return resolved


class DurableDelegationRecoveryCoordinator:
    """Classify persisted non-terminal work without silently replaying a child."""

    def __init__(
        self,
        store: DurableDelegationStore,
        *,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        if not isinstance(store, DurableDelegationStore):
            raise TypeError("store must implement DurableDelegationStore")
        if not callable(clock):
            raise TypeError("clock must be callable")
        self._store = store
        self._clock = clock

    async def recover(
        self,
        *,
        limit: int = 256,
    ) -> DurableDelegationRecoveryReport:
        require_recovery_page_limit(limit)
        scanned = 0
        recoverable = 0
        indeterminate = 0
        expired = 0
        after: DelegationId | None = None

        while scanned < limit:
            page_limit = min(256, limit - scanned)
            page = await self._store.list_recovery_candidates(
                limit=page_limit,
                after=after,
            )
            if not page:
                break
            for delegation_id in page:
                record = await self._require_record(delegation_id)
                now = self._clock()
                if record.deadline <= now:
                    await self._store.compare_and_swap(
                        replace(
                            record,
                            status=DelegationStatus.EXPIRED,
                            recovery_state=DurableDelegationRecoveryState.CLEAN,
                            version=record.version.next(),
                            updated_at=now,
                            error_code="timeout",
                        ),
                        expected_version=record.version,
                    )
                    expired += 1
                elif record.status is DelegationStatus.RUNNING:
                    await self._mark_recovery(
                        record,
                        DurableDelegationRecoveryState.INDETERMINATE,
                    )
                    indeterminate += 1
                elif record.status in {
                    DelegationStatus.REQUESTED,
                    DelegationStatus.AUTHORIZED,
                    DelegationStatus.ADMITTED,
                }:
                    await self._mark_recovery(
                        record,
                        DurableDelegationRecoveryState.RECOVERABLE,
                    )
                    recoverable += 1
                scanned += 1
                after = delegation_id
                if scanned == limit:
                    break
            if len(page) < page_limit:
                break

        return DurableDelegationRecoveryReport(
            scanned=scanned,
            recoverable=recoverable,
            indeterminate=indeterminate,
            expired=expired,
        )

    async def reconcile(
        self,
        request: DurableDelegationReconciliationRequest,
    ) -> DurableDelegationRecord:
        if not isinstance(request, DurableDelegationReconciliationRequest):
            raise TypeError("request must be DurableDelegationReconciliationRequest")
        current = await self._require_record(request.delegation_id)
        if current.version != request.expected_version:
            raise AgentStateConflictError()
        if (
            current.status is not DelegationStatus.RUNNING
            or current.recovery_state is not DurableDelegationRecoveryState.INDETERMINATE
        ):
            raise AgentStateConflictError()

        decision = request.decision
        if decision is DurableDelegationReconciliationDecision.REMAIN_INDETERMINATE:
            return current
        if decision is DurableDelegationReconciliationDecision.CONFIRM_NOT_STARTED:
            status = DelegationStatus.ADMITTED
            recovery = DurableDelegationRecoveryState.RECOVERABLE
            error_code = None
        elif decision is DurableDelegationReconciliationDecision.CONFIRM_COMPLETED:
            status = DelegationStatus.COMPLETED
            recovery = DurableDelegationRecoveryState.CLEAN
            error_code = None
        elif decision is DurableDelegationReconciliationDecision.CONFIRM_CANCELLED:
            status = DelegationStatus.CANCELLED
            recovery = DurableDelegationRecoveryState.CLEAN
            error_code = "cancelled"
        else:
            status = DelegationStatus.FAILED
            recovery = DurableDelegationRecoveryState.CLEAN
            error_code = "child_failed"

        return await self._store.compare_and_swap(
            replace(
                current,
                status=status,
                recovery_state=recovery,
                version=current.version.next(),
                updated_at=request.requested_at,
                error_code=error_code,
            ),
            expected_version=current.version,
        )

    async def _mark_recovery(
        self,
        current: DurableDelegationRecord,
        recovery_state: DurableDelegationRecoveryState,
    ) -> DurableDelegationRecord:
        if current.recovery_state is recovery_state:
            return current
        now = self._clock()
        return await self._store.compare_and_swap(
            replace(
                current,
                recovery_state=recovery_state,
                version=current.version.next(),
                updated_at=now,
            ),
            expected_version=current.version,
        )

    async def _require_record(
        self,
        delegation_id: DelegationId,
    ) -> DurableDelegationRecord:
        record = await self._store.get(delegation_id)
        if record is None:
            raise DelegationNotFoundError()
        return record


def _require_root_constraints(
    records: tuple[DurableDelegationRecord, ...],
    *,
    request: DelegationRequest,
    root_budget_limit: DelegationBudget,
    creating: bool,
) -> None:
    if any(
        record.recovery_state is DurableDelegationRecoveryState.INDETERMINATE for record in records
    ):
        raise AgentStateConflictError()

    projected_count = len(records) + int(creating)
    if projected_count > request.limits.max_total_children:
        raise AgentStateConflictError()
    parent_count = sum(record.parent_run_id == request.parent_run_id for record in records) + int(
        creating
    )
    if parent_count > request.limits.max_fan_out:
        raise AgentStateConflictError()

    budgets = [record.budget for record in records]
    if creating:
        budgets.append(request.budget)
    if sum(item.max_model_turns for item in budgets) > root_budget_limit.max_model_turns:
        raise AgentStateConflictError()
    if sum(item.max_tool_calls for item in budgets) > root_budget_limit.max_tool_calls:
        raise AgentStateConflictError()
    if sum(item.max_input_tokens for item in budgets) > root_budget_limit.max_input_tokens:
        raise AgentStateConflictError()
    if sum(item.max_output_tokens for item in budgets) > root_budget_limit.max_output_tokens:
        raise AgentStateConflictError()
    if sum(item.max_prompt_bytes for item in budgets) > root_budget_limit.max_prompt_bytes:
        raise AgentStateConflictError()
    if sum(item.max_result_bytes for item in budgets) > root_budget_limit.max_result_bytes:
        raise AgentStateConflictError()
    duration = sum((item.duration for item in budgets), start=timedelta())
    if duration > root_budget_limit.duration:
        raise AgentStateConflictError()


def _require_matching_replay(
    record: DurableDelegationRecord,
    *,
    request: DelegationRequest,
    request_digest: str,
    compatibility_digest: str,
) -> None:
    if record.request_digest != request_digest:
        raise AgentStateConflictError()
    if record.compatibility_digest != compatibility_digest:
        raise AgentStateConflictError()
    if (
        record.namespace != request.namespace
        or record.parent_agent_id != request.parent_agent_id
        or record.parent_run_id != request.parent_run_id
        or record.root_run_id != request.lineage.root_run_id
        or record.child_agent_id != request.child_agent_id
        or record.depth != request.child_depth
        or record.budget != request.budget
        or record.deadline != request.deadline
    ):
        raise AgentStateConflictError()


def _record_child_view(record: DurableDelegationRecord) -> DelegatedChildRun:
    return DelegatedChildRun(
        delegation_id=record.delegation_id,
        parent_agent_id=record.parent_agent_id,
        parent_run_id=record.parent_run_id,
        root_run_id=record.root_run_id,
        child_agent_id=record.child_agent_id,
        child_run_id=record.child_run_id,
        depth=record.depth,
        status=record.status,
        budget=record.budget,
        created_at=record.created_at,
        updated_at=record.updated_at,
        deadline=record.deadline,
    )
