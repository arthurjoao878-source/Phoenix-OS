from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, cast

import pytest

from phoenix_os.agent.checkout_durable_evidence import (
    CheckoutReadCumulativeByteBudget,
    CheckoutReadDurableResultMetadataProjectorFactory,
)
from phoenix_os.agent.contracts import AgentRunId
from phoenix_os.agent.durable_compatibility import StaticDurableCompatibilityValidator
from phoenix_os.agent.durable_contracts import DurableAgentRunId
from phoenix_os.agent.durable_live_tool import DurableAgentToolExecutionDriver
from phoenix_os.agent.durable_memory import InMemoryDurableRunStore
from phoenix_os.agent.durable_runtime import create_durable_agent_runtime_stack
from phoenix_os.integrated_agent.durable_run import (
    _create_checkout_read_durable_tool_execution_driver,
)

NOW = datetime(2026, 9, 7, 3, tzinfo=UTC)


@pytest.mark.asyncio
async def test_integrated_durable_tool_driver_binds_checkout_read_evidence_factory() -> None:
    store = InMemoryDurableRunStore()
    stack = create_durable_agent_runtime_stack(
        store=store,
        lease_manager=store.lease_manager,
        compatibility_validator=StaticDurableCompatibilityValidator(()),
    )
    try:
        lease = await store.lease_manager.acquire(
            DurableAgentRunId(),
            owner_id="rfc0039-checkout-result-binding-test",
            now=NOW,
        )
        before = await store.lease_manager.get_current(lease.run_id, now=NOW)

        read_budget = CheckoutReadCumulativeByteBudget(AgentRunId(), max_bytes=1)
        driver = _create_checkout_read_durable_tool_execution_driver(
            stack,
            lease=lease,
            lease_renewal_interval=timedelta(seconds=10),
            read_budget=read_budget,
            clock=lambda: NOW,
        )

        after = await store.lease_manager.get_current(lease.run_id, now=NOW)
        bound_driver = cast(Any, driver)
        assert bound_driver._read_budget is read_budget
        durable_driver = bound_driver._driver
        assert isinstance(durable_driver, DurableAgentToolExecutionDriver)
        assert isinstance(
            durable_driver._result_metadata_projector_factory,
            CheckoutReadDurableResultMetadataProjectorFactory,
        )
        assert before == lease
        assert after == lease
    finally:
        await stack.close()
