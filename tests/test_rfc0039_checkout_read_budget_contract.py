from __future__ import annotations

import pytest

from phoenix_os.integrated_agent.configuration import _decode_budget, _encode_budget
from phoenix_os.integrated_agent.contracts import (
    MAX_INTEGRATED_WORKSPACE_READ_BYTES,
    IntegratedBudgetExtension,
    IntegratedBudgetUsage,
)


def test_checkout_read_budget_has_bounded_integrated_policy_defaults() -> None:
    budget = IntegratedBudgetExtension()

    assert budget.max_workspace_read_bytes == 16_777_216
    assert MAX_INTEGRATED_WORKSPACE_READ_BYTES == 1_073_741_824


def test_checkout_read_budget_rejects_non_positive_and_unsupported_values() -> None:
    with pytest.raises(ValueError):
        IntegratedBudgetExtension(max_workspace_read_bytes=0)
    with pytest.raises(ValueError):
        IntegratedBudgetExtension(max_workspace_read_bytes=MAX_INTEGRATED_WORKSPACE_READ_BYTES + 1)


def test_checkout_read_budget_configuration_round_trips_without_usage_state() -> None:
    budget = _decode_budget({"max_workspace_read_bytes": 12_345_678})

    assert budget.max_workspace_read_bytes == 12_345_678
    encoded = _encode_budget(budget)
    assert encoded["max_workspace_read_bytes"] == 12_345_678
    assert _decode_budget(encoded) == budget


def test_checkout_read_bytes_are_not_duplicated_in_integrated_budget_usage() -> None:
    usage = IntegratedBudgetUsage()

    assert not hasattr(usage, "workspace_read_bytes")
