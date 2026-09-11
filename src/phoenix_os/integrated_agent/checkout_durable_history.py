"""Integrated durable history composition for RFC-0039 checkout-read evidence."""

from phoenix_os.agent.checkout_durable_evidence import (
    CheckoutReadDurableEvidenceHistoryValidator,
)
from phoenix_os.agent.durable_metadata import (
    ChainedDurableCheckpointHistoryValidator,
    DurableCheckpointHistoryValidator,
)
from phoenix_os.integrated_agent.durable_recovery import (
    IntegratedDurableRecoveryHistoryValidator,
)


def create_integrated_checkout_durable_history_validator() -> (
    ChainedDurableCheckpointHistoryValidator
):
    """Compose integrated durable invariants before RFC-0039 checkout evidence."""

    return ChainedDurableCheckpointHistoryValidator(
        (
            IntegratedDurableRecoveryHistoryValidator(),
            CheckoutReadDurableEvidenceHistoryValidator(),
        )
    )


assert isinstance(
    create_integrated_checkout_durable_history_validator(),
    DurableCheckpointHistoryValidator,
)
