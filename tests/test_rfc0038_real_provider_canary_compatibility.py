from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import cast
from uuid import uuid4

from scripts import run_rfc0038_real_provider_canary as canary

from phoenix_os.agent.contracts import AgentRunId
from phoenix_os.agent.durable_compatibility import (
    DurableCompatibilityCategory,
    DurableCompatibilityPolicy,
    StaticDurableCompatibilityValidator,
)
from phoenix_os.agent.durable_contracts import (
    CheckpointPayloadProfile,
    DurableAgentRunId,
)


def test_real_provider_canary_revalidates_structured_schema_as_model_provider() -> None:
    baseline = canary._compatibility()

    equivalent_document = cast(
        dict[str, object],
        json.loads(canary.AGENT_FINAL_OUTPUT_SCHEMA),
    )
    whitespace_equivalent_schema = json.dumps(
        equivalent_document,
        indent=2,
        ensure_ascii=False,
        allow_nan=False,
    )
    equivalent = canary._compatibility(
        structured_json_schema=whitespace_equivalent_schema,
    )

    drifted_document = dict(equivalent_document)
    drifted_document["title"] = "rfc0038-drifted-final-contract"
    drifted_schema = json.dumps(
        drifted_document,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    drifted = canary._compatibility(
        structured_json_schema=drifted_schema,
    )

    assert equivalent == baseline
    assert drifted.configuration == baseline.configuration
    assert drifted.tool_registry == baseline.tool_registry
    assert drifted.checkpoint_codec == baseline.checkpoint_codec
    assert drifted.payload_codec == baseline.payload_codec
    assert drifted.model_provider != baseline.model_provider

    now = datetime.now(UTC)
    configuration = canary._configuration()
    request = canary._request(
        configuration,
        now=now,
        agent_run_id=AgentRunId(uuid4()),
    )
    checkpoint = canary._checkpoint(
        request,
        durable_run_id=DurableAgentRunId(uuid4()),
    )

    assert checkpoint.metadata.compatibility == baseline

    validator = StaticDurableCompatibilityValidator(
        (
            DurableCompatibilityPolicy(
                agent_id=configuration.agent_id,
                current=drifted,
                payload_profile=CheckpointPayloadProfile.METADATA_ONLY,
            ),
        )
    )
    assessment = validator.validate(checkpoint)

    assert assessment.category is DurableCompatibilityCategory.MODEL_PROVIDER_CHANGED
    assert assessment.compatible is False
