from __future__ import annotations

import inspect
from dataclasses import fields
from uuid import UUID

import pytest

from phoenix_os.agent import AgentRunId
from phoenix_os.integrated_agent import (
    ContentFreeIntegratedAgentObserver,
    IntegratedAgentObservation,
    IntegratedExecutionProfileGeneration,
    IntegratedExecutionProfileId,
    IntegratedOrchestrationPhase,
    IntegratedTaskId,
)


def _observation(
    *,
    capability_id: str | None = None,
    action_category: str | None = None,
) -> IntegratedAgentObservation:
    return IntegratedAgentObservation(
        task_id=IntegratedTaskId(UUID("22222222-2222-2222-2222-222222222222")),
        run_id=AgentRunId(UUID("11111111-1111-1111-1111-111111111111")),
        phase=IntegratedOrchestrationPhase.EXECUTING,
        profile_id=IntegratedExecutionProfileId("integrated-research"),
        profile_generation=IntegratedExecutionProfileGeneration(7),
        capability_id=capability_id,
        action_category=action_category,
    )


@pytest.mark.parametrize(
    "value",
    (
        "https://attacker.invalid/private",
        "../workspace/private",
        "memory\nsecret",
    ),
)
def test_observation_rejects_content_or_locator_shaped_capability_id(
    value: str,
) -> None:
    with pytest.raises(ValueError):
        _observation(capability_id=value)


@pytest.mark.parametrize(
    "value",
    (
        "workspace.write?body=secret",
        "/tmp/private",
        "browser.navigate\r\ncookie: secret",
    ),
)
def test_observation_rejects_content_or_locator_shaped_action_category(
    value: str,
) -> None:
    with pytest.raises(ValueError):
        _observation(action_category=value)


def test_observation_contract_has_no_generic_metadata_or_content_escape_hatch() -> None:
    field_names = {item.name for item in fields(IntegratedAgentObservation)}
    assert "metadata" not in field_names
    assert "attributes" not in field_names
    assert "details" not in field_names
    assert "payload" not in field_names
    assert "content" not in field_names
    assert "message" not in field_names
    assert "exception" not in field_names
    assert "url" not in field_names
    assert "path" not in field_names


def test_observer_emitter_has_no_content_source_dependency() -> None:
    source = inspect.getsource(ContentFreeIntegratedAgentObserver)
    for forbidden in (
        "IntegratedTaskRequest",
        "AgentRunRequest",
        "AgentMessage",
        "ToolInvocationResult",
        "BrowserPageSnapshot",
        "NetworkResponse",
        "Memory",
        "Workspace",
        "Clipboard",
        "Secret",
        "ApprovalToken",
        "AuthorityIntent",
    ):
        assert forbidden not in source
