from __future__ import annotations

from phoenix_os.agent.checkout_durable_evidence import (
    CheckoutReadDurableEvidenceHistoryValidator,
)
from phoenix_os.agent.durable_metadata import (
    ChainedDurableCheckpointHistoryValidator,
    DurableCheckpointHistoryValidator,
)
from phoenix_os.integrated_agent.checkout_durable_history import (
    create_integrated_checkout_durable_history_validator,
)
from phoenix_os.integrated_agent.durable_recovery import (
    IntegratedDurableRecoveryHistoryValidator,
)


def test_integrated_checkout_history_composition_has_exact_order_and_protocol() -> None:
    validator = create_integrated_checkout_durable_history_validator()

    assert isinstance(validator, ChainedDurableCheckpointHistoryValidator)
    assert isinstance(validator, DurableCheckpointHistoryValidator)
    assert len(validator.validators) == 2
    assert isinstance(validator.validators[0], IntegratedDurableRecoveryHistoryValidator)
    assert isinstance(validator.validators[1], CheckoutReadDurableEvidenceHistoryValidator)


def test_integrated_checkout_history_composition_returns_fresh_validator_chain() -> None:
    first = create_integrated_checkout_durable_history_validator()
    second = create_integrated_checkout_durable_history_validator()

    assert first is not second
    assert first.validators[0] is not second.validators[0]
    assert first.validators[1] is not second.validators[1]
