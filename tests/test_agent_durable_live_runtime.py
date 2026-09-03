from __future__ import annotations

from datetime import UTC, datetime

import pytest

from phoenix_os.agent.durable_attempts import (
    StoreBackedDurableExecutionAttemptRecorder,
)
from phoenix_os.agent.durable_compatibility import (
    StaticDurableCompatibilityValidator,
)
from phoenix_os.agent.durable_contracts import DurableAgentRunId
from phoenix_os.agent.durable_live_model_turn import (
    DurableAgentModelTurnExecutionDriver,
)
from phoenix_os.agent.durable_memory import InMemoryDurableRunStore
from phoenix_os.agent.durable_runtime import (
    create_durable_agent_runtime_stack,
)
from phoenix_os.integrated_agent.durable_transitions import (
    IntegratedDurableCheckpointMetadataProjector,
)

NOW = datetime(2026, 8, 1, 12, tzinfo=UTC)


@pytest.mark.asyncio
async def test_runtime_stack_composes_live_driver_without_taking_lease_ownership() -> None:
    store = InMemoryDurableRunStore()
    lease_manager = store.lease_manager
    projector = IntegratedDurableCheckpointMetadataProjector()
    compatibility_validator = StaticDurableCompatibilityValidator(())

    stack = create_durable_agent_runtime_stack(
        store=store,
        lease_manager=lease_manager,
        compatibility_validator=compatibility_validator,
        metadata_projector=projector,
    )

    try:
        assert stack.store is store
        assert stack.lease_manager is lease_manager
        assert stack.metadata_projector is projector
        assert isinstance(
            stack.attempt_recorder,
            StoreBackedDurableExecutionAttemptRecorder,
        )

        lease = await lease_manager.acquire(
            DurableAgentRunId(),
            owner_id="live-worker",
            now=NOW,
        )
        current_before = await lease_manager.get_current(
            lease.run_id,
            now=NOW,
        )

        driver = stack.create_model_turn_execution_driver(
            lease=lease,
        )

        current_after = await lease_manager.get_current(
            lease.run_id,
            now=NOW,
        )

        assert isinstance(
            driver,
            DurableAgentModelTurnExecutionDriver,
        )
        assert current_before == lease
        assert current_after == lease

    finally:
        await stack.close()
