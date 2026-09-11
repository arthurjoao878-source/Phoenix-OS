from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import pytest

from phoenix_os.agent.contracts import AgentStepId
from phoenix_os.agent.durable_compatibility import StaticDurableCompatibilityValidator
from phoenix_os.agent.durable_contracts import (
    CheckpointEnvelope,
    CheckpointId,
    CheckpointNextOperation,
    DurableRunStatus,
    ExecutionAttempt,
)
from phoenix_os.agent.durable_memory import InMemoryDurableRunStore
from phoenix_os.agent.durable_metadata import (
    ChainedDurableCheckpointMetadataProjector,
    DurableCheckpointMetadataProjector,
)
from phoenix_os.agent.durable_runtime import create_durable_agent_runtime_stack
from phoenix_os.integrated_agent.checkout_durable_history import (
    create_integrated_checkout_durable_history_validator,
)
from phoenix_os.integrated_agent.durable_run import IntegratedDurableRunCoordinator
from phoenix_os.integrated_agent.durable_transitions import (
    IntegratedDurableCheckpointMetadataProjector,
)


class _PassThroughProjector:
    def project_metadata(
        self,
        current: CheckpointEnvelope,
        *,
        checkpoint_id: CheckpointId,
        status: DurableRunStatus,
        step_id: AgentStepId | None,
        next_operation: CheckpointNextOperation,
        active_attempt: ExecutionAttempt | None,
        metadata: Mapping[str, str],
    ) -> Mapping[str, str]:
        del current, checkpoint_id, status, step_id, next_operation, active_attempt
        return dict(metadata)


class _Service:
    @property
    def configuration(self) -> Any:
        raise AssertionError("configuration must not be read during coordinator construction")

    @property
    def state(self) -> Any:
        raise AssertionError("state must not be read during coordinator construction")

    async def start(self, context: Any) -> None:
        del context

    async def stop(self, context: Any) -> None:
        del context

    async def run(self, *args: Any, **kwargs: Any) -> Any:
        del args, kwargs
        raise AssertionError("service.run must not execute in constructor tests")


class _RootProvider:
    def build_root(self, request: Any, binding: Any, provenance: Any) -> Any:
        del request, binding, provenance
        raise AssertionError("root provider must not execute during coordinator construction")


def _chain(
    *projectors: DurableCheckpointMetadataProjector,
) -> ChainedDurableCheckpointMetadataProjector:
    return ChainedDurableCheckpointMetadataProjector(tuple(projectors))


def _stack(projector: DurableCheckpointMetadataProjector) -> Any:
    store = InMemoryDurableRunStore()
    return create_durable_agent_runtime_stack(
        store=store,
        lease_manager=store.lease_manager,
        compatibility_validator=StaticDurableCompatibilityValidator(()),
        metadata_projector=projector,
        history_validator=create_integrated_checkout_durable_history_validator(),
    )


@pytest.mark.asyncio
async def test_coordinator_accepts_chain_with_exactly_one_integrated_projector() -> None:
    projector = _chain(_PassThroughProjector(), IntegratedDurableCheckpointMetadataProjector())
    stack = _stack(projector)
    service = _Service()
    try:
        coordinator = IntegratedDurableRunCoordinator(
            service=service,
            durable_stack=stack,
            root_provider=_RootProvider(),
            owner_id="rfc0039-composition-test",
        )
        assert coordinator.service is service
        assert stack.metadata_projector is projector
    finally:
        await stack.close()


@pytest.mark.asyncio
async def test_coordinator_accepts_nested_chain_with_one_integrated_projector() -> None:
    projector = _chain(
        _PassThroughProjector(),
        _chain(IntegratedDurableCheckpointMetadataProjector(), _PassThroughProjector()),
    )
    stack = _stack(projector)
    try:
        IntegratedDurableRunCoordinator(
            service=_Service(),
            durable_stack=stack,
            root_provider=_RootProvider(),
            owner_id="rfc0039-nested-composition-test",
        )
    finally:
        await stack.close()


@pytest.mark.asyncio
async def test_coordinator_rejects_chain_without_integrated_projector() -> None:
    stack = _stack(_chain(_PassThroughProjector()))
    try:
        with pytest.raises(ValueError, match="IntegratedDurableCheckpointMetadataProjector"):
            IntegratedDurableRunCoordinator(
                service=_Service(),
                durable_stack=stack,
                root_provider=_RootProvider(),
                owner_id="rfc0039-missing-projector-test",
            )
    finally:
        await stack.close()


@pytest.mark.asyncio
async def test_coordinator_rejects_duplicate_integrated_projectors() -> None:
    projector = _chain(
        IntegratedDurableCheckpointMetadataProjector(),
        _chain(_PassThroughProjector(), IntegratedDurableCheckpointMetadataProjector()),
    )
    stack = _stack(projector)
    try:
        with pytest.raises(ValueError, match="IntegratedDurableCheckpointMetadataProjector"):
            IntegratedDurableRunCoordinator(
                service=_Service(),
                durable_stack=stack,
                root_provider=_RootProvider(),
                owner_id="rfc0039-duplicate-projector-test",
            )
    finally:
        await stack.close()
