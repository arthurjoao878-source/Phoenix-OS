"""Runtime-owned composition for optional durable agent recovery services."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

from phoenix_os.agent.durable_administration import (
    DurableAdministrationConfiguration,
    DurableMachineAdministrationGuard,
    DurableRunAdministration,
)
from phoenix_os.agent.durable_approval import DurableApprovalRevalidator
from phoenix_os.agent.durable_authorization import DurableReconciliationAuthorizer
from phoenix_os.agent.durable_compatibility import DurableCompatibilityValidator
from phoenix_os.agent.durable_contracts import (
    CheckpointProtector,
    DurableRunStore,
    RetentionPolicy,
)
from phoenix_os.agent.durable_lease import DurableLeaseManager
from phoenix_os.agent.durable_observer import (
    DurableRunObserver,
    NullDurableRunObserver,
)
from phoenix_os.agent.durable_payload import DurableProtectedPayloadStore
from phoenix_os.agent.durable_reconciliation import (
    StoreBackedDurableReconciliationDispositionApplier,
)
from phoenix_os.agent.durable_reconciliation_administration import (
    DurableReconciliationAdministration,
    DurableReconciliationStatusLookup,
)
from phoenix_os.agent.durable_recovery import (
    DurableRecoveryCoordinator,
    StartupDurableRecoveryCoordinator,
)
from phoenix_os.agent.durable_retention import DurableRetentionStore
from phoenix_os.agent.durable_retention_worker import (
    BoundedDurableRetentionWorker,
    DurableRetentionWorker,
    DurableRetentionWorkerConfiguration,
)
from phoenix_os.agent.durable_worker import (
    BoundedDurableRecoveryWorker,
    DurableRecoveryWorker,
    DurableRecoveryWorkerConfiguration,
)
from phoenix_os.audit import AuditLedger
from phoenix_os.runtime import RuntimeContext


class DurableStorageLifecycle:
    """Own durable storage and lease shutdown as one Runtime lifecycle boundary."""

    def __init__(
        self,
        *,
        store: DurableRunStore,
        lease_manager: DurableLeaseManager,
    ) -> None:
        if not isinstance(store, DurableRunStore):
            raise TypeError("store must implement DurableRunStore")
        if not isinstance(lease_manager, DurableLeaseManager):
            raise TypeError("lease_manager must implement DurableLeaseManager")
        self._store = store
        self._lease_manager = lease_manager

    async def start(self, context: RuntimeContext) -> None:
        if not isinstance(context, RuntimeContext):
            raise TypeError("context must be RuntimeContext")
        if self._store.closed:
            raise RuntimeError("durable store is closed")
        if self._lease_manager.closed:
            raise RuntimeError("durable lease manager is closed")

    async def stop(self, context: RuntimeContext) -> None:
        if not isinstance(context, RuntimeContext):
            raise TypeError("context must be RuntimeContext")
        await self.close()

    async def close(self) -> None:
        """Close storage and leases even when Runtime construction never completed."""

        failure: BaseException | None = None
        try:
            await self._store.close()
        except (Exception, asyncio.CancelledError) as exception:
            failure = exception

        if not self._lease_manager.closed:
            try:
                await self._lease_manager.close()
            except (Exception, asyncio.CancelledError) as exception:
                if failure is None:
                    failure = exception

        if failure is not None:
            raise failure


class DurableRecoveryLifecycle:
    """Adapt the bounded durable recovery worker to Phoenix Runtime lifecycle hooks."""

    def __init__(self, worker: DurableRecoveryWorker) -> None:
        if not isinstance(worker, DurableRecoveryWorker):
            raise TypeError("worker must implement DurableRecoveryWorker")
        self._worker = worker

    async def start(self, context: RuntimeContext) -> None:
        if not isinstance(context, RuntimeContext):
            raise TypeError("context must be RuntimeContext")
        await self._worker.start()

    async def stop(self, context: RuntimeContext) -> None:
        if not isinstance(context, RuntimeContext):
            raise TypeError("context must be RuntimeContext")
        await self.close()

    async def close(self) -> None:
        """Close recovery admission without requiring a RuntimeContext."""

        await self._worker.close()


class DurableRetentionLifecycle:
    """Adapt manual durable retention to Phoenix Runtime lifecycle hooks."""

    def __init__(self, worker: DurableRetentionWorker) -> None:
        if not isinstance(worker, DurableRetentionWorker):
            raise TypeError("worker must implement DurableRetentionWorker")
        self._worker = worker

    async def start(self, context: RuntimeContext) -> None:
        if not isinstance(context, RuntimeContext):
            raise TypeError("context must be RuntimeContext")
        await self._worker.start()

    async def stop(self, context: RuntimeContext) -> None:
        if not isinstance(context, RuntimeContext):
            raise TypeError("context must be RuntimeContext")
        await self.close()

    async def close(self) -> None:
        """Close retention admission without requiring a RuntimeContext."""

        await self._worker.close()


@dataclass(frozen=True, slots=True)
class DurableAgentRuntimeStack:
    """Reviewed Runtime-owned durable services for one enabled agent."""

    store: DurableRunStore
    lease_manager: DurableLeaseManager
    compatibility_validator: DurableCompatibilityValidator
    recovery_coordinator: DurableRecoveryCoordinator
    recovery_worker: DurableRecoveryWorker
    storage_lifecycle: DurableStorageLifecycle
    recovery_lifecycle: DurableRecoveryLifecycle
    observer: DurableRunObserver
    administration: DurableRunAdministration
    reconciliation_administration: DurableReconciliationAdministration | None = None
    protector: CheckpointProtector | None = None
    retention_policy: RetentionPolicy | None = None
    retention_worker: DurableRetentionWorker | None = None
    retention_lifecycle: DurableRetentionLifecycle | None = None

    async def close(self) -> None:
        """Rollback composed durable resources in reverse lifecycle order."""

        failure: BaseException | None = None

        if self.reconciliation_administration is not None:
            try:
                await self.reconciliation_administration.close()
            except (Exception, asyncio.CancelledError) as exception:
                failure = exception

        if self.retention_lifecycle is not None:
            try:
                await self.retention_lifecycle.close()
            except (Exception, asyncio.CancelledError) as exception:
                failure = exception

        try:
            await self.recovery_lifecycle.close()
        except (Exception, asyncio.CancelledError) as exception:
            if failure is None:
                failure = exception

        try:
            await self.storage_lifecycle.close()
        except (Exception, asyncio.CancelledError) as exception:
            if failure is None:
                failure = exception

        if failure is not None:
            raise failure


def create_durable_agent_runtime_stack(
    *,
    store: DurableRunStore,
    lease_manager: DurableLeaseManager,
    compatibility_validator: DurableCompatibilityValidator,
    recovery_configuration: DurableRecoveryWorkerConfiguration | None = None,
    approval_revalidator: DurableApprovalRevalidator | None = None,
    observer: DurableRunObserver | None = None,
    administration_configuration: DurableAdministrationConfiguration | None = None,
    machine_guard: DurableMachineAdministrationGuard | None = None,
    reconciliation_authorizer: DurableReconciliationAuthorizer | None = None,
    reconciliation_audit: AuditLedger | None = None,
    reconciliation_status_lookup: DurableReconciliationStatusLookup | None = None,
    protector: CheckpointProtector | None = None,
    retention_policy: RetentionPolicy | None = None,
    retention_configuration: DurableRetentionWorkerConfiguration | None = None,
) -> DurableAgentRuntimeStack:
    """Compose bounded durable recovery without creating or scheduling agent work."""

    if not isinstance(store, DurableRunStore):
        raise TypeError("store must implement DurableRunStore")
    if not isinstance(lease_manager, DurableLeaseManager):
        raise TypeError("lease_manager must implement DurableLeaseManager")
    if not isinstance(compatibility_validator, DurableCompatibilityValidator):
        raise TypeError("compatibility_validator must implement DurableCompatibilityValidator")
    if approval_revalidator is not None and not isinstance(
        approval_revalidator,
        DurableApprovalRevalidator,
    ):
        raise TypeError("approval_revalidator must implement DurableApprovalRevalidator")
    if observer is not None and not isinstance(observer, DurableRunObserver):
        raise TypeError("observer must implement DurableRunObserver")
    if administration_configuration is not None and not isinstance(
        administration_configuration,
        DurableAdministrationConfiguration,
    ):
        raise TypeError("administration_configuration must be DurableAdministrationConfiguration")
    if machine_guard is not None and not isinstance(
        machine_guard,
        DurableMachineAdministrationGuard,
    ):
        raise TypeError("machine_guard must implement DurableMachineAdministrationGuard")
    if reconciliation_authorizer is not None and not isinstance(
        reconciliation_authorizer,
        DurableReconciliationAuthorizer,
    ):
        raise TypeError("reconciliation_authorizer must implement DurableReconciliationAuthorizer")
    if reconciliation_audit is not None and not isinstance(reconciliation_audit, AuditLedger):
        raise TypeError("reconciliation_audit must be AuditLedger")
    if reconciliation_status_lookup is not None and not isinstance(
        reconciliation_status_lookup,
        DurableReconciliationStatusLookup,
    ):
        raise TypeError(
            "reconciliation_status_lookup must implement DurableReconciliationStatusLookup"
        )
    if (reconciliation_authorizer is None) != (reconciliation_audit is None):
        raise ValueError("reconciliation administration requires authorizer and audit")
    if reconciliation_status_lookup is not None and reconciliation_authorizer is None:
        raise ValueError("reconciliation status lookup requires reconciliation administration")
    if protector is not None:
        if not isinstance(protector, CheckpointProtector):
            raise TypeError("protector must implement CheckpointProtector")
        if not isinstance(store, DurableProtectedPayloadStore):
            raise ValueError("checkpoint protector requires protected-payload store support")
    if recovery_configuration is not None and not isinstance(
        recovery_configuration,
        DurableRecoveryWorkerConfiguration,
    ):
        raise TypeError("recovery_configuration must be DurableRecoveryWorkerConfiguration")
    if retention_policy is not None and not isinstance(
        retention_policy,
        RetentionPolicy,
    ):
        raise TypeError("retention_policy must be RetentionPolicy")
    if retention_configuration is not None and not isinstance(
        retention_configuration,
        DurableRetentionWorkerConfiguration,
    ):
        raise TypeError("retention_configuration must be DurableRetentionWorkerConfiguration")
    if retention_configuration is not None and retention_policy is None:
        raise ValueError("retention_configuration requires retention_policy")
    if retention_policy is not None and not isinstance(
        store,
        DurableRetentionStore,
    ):
        raise TypeError("store must implement DurableRetentionStore when retention is enabled")

    bound_lease_manager = getattr(store, "lease_manager", None)
    if bound_lease_manager is not None and bound_lease_manager is not lease_manager:
        raise ValueError("lease_manager must match the durable store lease manager")
    if store.closed:
        raise ValueError("durable store must be open")
    if lease_manager.closed:
        raise ValueError("durable lease manager must be open")

    coordinator = StartupDurableRecoveryCoordinator(
        store=store,
        lease_manager=lease_manager,
        compatibility_validator=compatibility_validator,
        approval_revalidator=approval_revalidator,
    )
    worker = BoundedDurableRecoveryWorker(
        store=store,
        coordinator=coordinator,
        configuration=recovery_configuration,
    )

    retention_worker: DurableRetentionWorker | None = None
    retention_lifecycle: DurableRetentionLifecycle | None = None

    if retention_policy is not None:
        retention_store = store
        assert isinstance(retention_store, DurableRetentionStore)
        retention_worker = BoundedDurableRetentionWorker(
            store=retention_store,
            lease_manager=lease_manager,
            policy=retention_policy,
            configuration=retention_configuration,
        )
        retention_lifecycle = DurableRetentionLifecycle(retention_worker)

    selected_observer = NullDurableRunObserver() if observer is None else observer
    administration = DurableRunAdministration(
        store=store,
        lease_manager=lease_manager,
        compatibility_validator=compatibility_validator,
        configuration=administration_configuration,
        recovery_worker=worker,
        retention_worker=retention_worker,
        observer=selected_observer,
        machine_guard=machine_guard,
    )

    reconciliation_administration: DurableReconciliationAdministration | None = None
    if reconciliation_authorizer is not None and reconciliation_audit is not None:
        reconciliation_applier = StoreBackedDurableReconciliationDispositionApplier(
            store=store,
            authorizer=reconciliation_authorizer,
        )
        reconciliation_administration = DurableReconciliationAdministration(
            store=store,
            lease_manager=lease_manager,
            applier=reconciliation_applier,
            audit=reconciliation_audit,
            status_lookup=reconciliation_status_lookup,
            observer=selected_observer,
        )

    return DurableAgentRuntimeStack(
        store=store,
        lease_manager=lease_manager,
        compatibility_validator=compatibility_validator,
        recovery_coordinator=coordinator,
        recovery_worker=worker,
        storage_lifecycle=DurableStorageLifecycle(
            store=store,
            lease_manager=lease_manager,
        ),
        recovery_lifecycle=DurableRecoveryLifecycle(worker),
        observer=selected_observer,
        administration=administration,
        reconciliation_administration=reconciliation_administration,
        protector=protector,
        retention_policy=retention_policy,
        retention_worker=retention_worker,
        retention_lifecycle=retention_lifecycle,
    )
