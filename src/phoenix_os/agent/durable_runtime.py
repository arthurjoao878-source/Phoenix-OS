"""Runtime-owned composition for optional durable agent recovery services."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

from phoenix_os.agent.durable_approval import DurableApprovalRevalidator
from phoenix_os.agent.durable_compatibility import DurableCompatibilityValidator
from phoenix_os.agent.durable_contracts import CheckpointProtector, DurableRunStore
from phoenix_os.agent.durable_lease import DurableLeaseManager
from phoenix_os.agent.durable_payload import DurableProtectedPayloadStore
from phoenix_os.agent.durable_recovery import (
    DurableRecoveryCoordinator,
    StartupDurableRecoveryCoordinator,
)
from phoenix_os.agent.durable_worker import (
    BoundedDurableRecoveryWorker,
    DurableRecoveryWorker,
    DurableRecoveryWorkerConfiguration,
)
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
    protector: CheckpointProtector | None = None

    async def close(self) -> None:
        """Rollback composed durable resources in reverse lifecycle order."""

        failure: BaseException | None = None
        try:
            await self.recovery_lifecycle.close()
        except (Exception, asyncio.CancelledError) as exception:
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
    protector: CheckpointProtector | None = None,
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
        protector=protector,
    )
