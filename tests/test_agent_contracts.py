from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from phoenix_os.agent import (
    AgentCancelledError,
    AgentErrorCode,
    AgentId,
    AgentLimits,
    AgentMessage,
    AgentMessageRole,
    AgentRunId,
    AgentRunRequest,
    AgentRunResult,
    AgentRunStatus,
    AgentSnapshot,
    AgentStepId,
    ToolCallId,
    ToolCallProposal,
    ToolEffect,
    ToolId,
    ToolInvocationRequest,
    ToolInvocationResult,
    ToolNotFoundError,
    ToolResultStatus,
    canonical_agent_json_bytes,
    freeze_agent_json_object,
)
from phoenix_os.inference import ModelId, ModelProviderId

NOW = datetime(2026, 7, 27, 12, tzinfo=UTC)


def _proposal(**overrides: object) -> ToolCallProposal:
    values: dict[str, object] = {
        "run_id": AgentRunId(),
        "step_id": AgentStepId(),
        "call_id": ToolCallId(),
        "tool_id": ToolId("files.read"),
        "arguments": {"path": "docs/readme.md", "line_numbers": [1, 2]},
        "created_at": NOW,
        "deadline": NOW + timedelta(minutes=1),
    }
    values.update(overrides)
    return ToolCallProposal(**values)  # type: ignore[arg-type]


def test_identifiers_normalize_and_reject_unsafe_values() -> None:
    assert str(AgentId(" assistant.one ")) == "assistant.one"
    assert str(ToolId("files_read")) == "files_read"

    for value in ("", "UPPER", "has space", "/shell"):
        with pytest.raises(ValueError):
            ToolId(value)


def test_uuid_identifiers_are_stable_and_typed() -> None:
    run_id = AgentRunId()
    step_id = AgentStepId()
    call_id = ToolCallId()

    assert isinstance(run_id.value, UUID)
    assert str(run_id) == str(run_id.value)
    assert run_id != AgentRunId()
    assert step_id != AgentStepId()
    assert call_id != ToolCallId()


def test_agent_message_enforces_tool_correlation_and_immutability() -> None:
    call_id = ToolCallId()
    metadata = {"channel": "test"}
    message = AgentMessage(
        AgentMessageRole.TOOL,
        "result available",
        tool_call_id=call_id,
        metadata=metadata,
    )
    metadata["channel"] = "changed"

    assert message.metadata == {"channel": "test"}
    with pytest.raises(TypeError):
        message.metadata["new"] = "value"  # type: ignore[index]
    with pytest.raises(FrozenInstanceError):
        message.content = "changed"  # type: ignore[misc]
    with pytest.raises(ValueError, match="tool_call_id"):
        AgentMessage(AgentMessageRole.TOOL, "missing correlation")
    with pytest.raises(ValueError, match="only tool"):
        AgentMessage(AgentMessageRole.USER, "hello", tool_call_id=call_id)


def test_structured_values_are_deeply_frozen_and_canonical() -> None:
    caller_owned: dict[str, object] = {
        "path": "docs/readme.md",
        "options": {"lines": [1, 2], "strict": True},
    }
    frozen = freeze_agent_json_object(caller_owned)  # type: ignore[arg-type]
    encoded = canonical_agent_json_bytes(frozen)

    caller_owned["path"] = "changed"
    nested = caller_owned["options"]
    assert isinstance(nested, dict)
    nested["lines"] = [99]

    assert frozen["path"] == "docs/readme.md"
    assert frozen["options"] == {"lines": (1, 2), "strict": True}
    assert encoded == (b'{"options":{"lines":[1,2],"strict":true},"path":"docs/readme.md"}')
    with pytest.raises(TypeError):
        frozen["path"] = "changed"  # type: ignore[index]
    with pytest.raises(ValueError, match="finite"):
        freeze_agent_json_object({"unsafe": float("nan")})


def test_limits_are_finite_and_composable() -> None:
    global_limits = AgentLimits(max_model_turns=8, max_tool_calls=8)
    local_limits = AgentLimits(max_model_turns=4, max_tool_calls=3)

    assert global_limits.contains(local_limits)
    assert not local_limits.contains(global_limits)
    with pytest.raises(ValueError, match="max_steps"):
        AgentLimits(max_steps=0)
    with pytest.raises(ValueError, match="max_tool_calls"):
        AgentLimits(max_model_turns=2, max_tool_calls=3)
    with pytest.raises(ValueError, match="total_duration"):
        AgentLimits(
            model_turn_timeout=timedelta(minutes=3),
            total_duration=timedelta(minutes=2),
        )


def test_tool_proposal_freezes_arguments_and_validates_deadline() -> None:
    arguments: dict[str, object] = {"path": "docs/readme.md", "lines": [1, 2]}
    proposal = _proposal(arguments=arguments)
    arguments["path"] = "changed"

    assert proposal.arguments == {"path": "docs/readme.md", "lines": (1, 2)}
    with pytest.raises(TypeError):
        proposal.arguments["new"] = True  # type: ignore[index]
    with pytest.raises(ValueError, match="deadline"):
        _proposal(deadline=NOW)


def test_invocation_requires_server_resolved_resource() -> None:
    proposal = _proposal()
    request = ToolInvocationRequest(
        run_id=proposal.run_id,
        step_id=proposal.step_id,
        call_id=proposal.call_id,
        tool_id=proposal.tool_id,
        arguments=proposal.arguments,
        resolved_resource="workspace:docs/readme.md",
        created_at=NOW,
        deadline=NOW + timedelta(minutes=1),
    )

    assert request.resolved_resource == "workspace:docs/readme.md"
    assert request.arguments == proposal.arguments
    with pytest.raises(ValueError, match="resolved_resource"):
        ToolInvocationRequest(
            run_id=proposal.run_id,
            step_id=proposal.step_id,
            call_id=proposal.call_id,
            tool_id=proposal.tool_id,
            arguments=proposal.arguments,
            resolved_resource="../../unsafe path",
            created_at=NOW,
            deadline=NOW + timedelta(minutes=1),
        )


def test_tool_result_enforces_terminal_payload_semantics() -> None:
    proposal = _proposal()
    output: dict[str, object] = {"found": True, "lines": ["one", "two"]}
    result = ToolInvocationResult(
        run_id=proposal.run_id,
        step_id=proposal.step_id,
        call_id=proposal.call_id,
        tool_id=proposal.tool_id,
        status=ToolResultStatus.SUCCEEDED,
        output=output,  # type: ignore[arg-type]
        started_at=NOW,
        completed_at=NOW + timedelta(seconds=1),
    )
    output["found"] = False

    assert result.output == {"found": True, "lines": ("one", "two")}
    with pytest.raises(ValueError, match="require output"):
        ToolInvocationResult(
            run_id=proposal.run_id,
            step_id=proposal.step_id,
            call_id=proposal.call_id,
            tool_id=proposal.tool_id,
            status=ToolResultStatus.SUCCEEDED,
            started_at=NOW,
            completed_at=NOW,
        )
    with pytest.raises(ValueError, match="require error_code"):
        ToolInvocationResult(
            run_id=proposal.run_id,
            step_id=proposal.step_id,
            call_id=proposal.call_id,
            tool_id=proposal.tool_id,
            status=ToolResultStatus.FAILED,
            started_at=NOW,
            completed_at=NOW,
        )


def test_agent_run_request_freezes_messages_and_metadata() -> None:
    messages = [AgentMessage(AgentMessageRole.USER, "hello")]
    metadata = {"tenant": "demo"}
    request = AgentRunRequest(
        agent_id=AgentId("assistant"),
        provider_id=ModelProviderId("deterministic"),
        model_id=ModelId("planner"),
        messages=messages,
        metadata=metadata,
        created_at=NOW,
        deadline=NOW + timedelta(minutes=5),
    )
    messages.append(AgentMessage(AgentMessageRole.USER, "changed"))
    metadata["tenant"] = "changed"

    assert len(request.messages) == 1
    assert request.metadata == {"tenant": "demo"}
    with pytest.raises(ValueError, match="messages"):
        AgentRunRequest(
            agent_id=AgentId("assistant"),
            provider_id=ModelProviderId("deterministic"),
            model_id=ModelId("planner"),
            messages=(),
            created_at=NOW,
            deadline=NOW + timedelta(minutes=5),
        )


def test_run_result_and_snapshot_are_content_free_and_terminal() -> None:
    run_id = AgentRunId()
    result = AgentRunResult(
        run_id=run_id,
        status=AgentRunStatus.COMPLETED,
        model_turns=2,
        tool_calls=1,
        final_output="done",
        started_at=NOW,
        completed_at=NOW + timedelta(seconds=2),
    )
    snapshot = AgentSnapshot(
        run_id=run_id,
        status=AgentRunStatus.INFERENCING,
        model_turns=1,
        tool_calls=0,
        created_at=NOW,
        updated_at=NOW + timedelta(seconds=1),
    )

    assert result.final_output == "done"
    assert snapshot.status is AgentRunStatus.INFERENCING
    assert AgentRunStatus.COMPLETED.terminal is True
    assert AgentRunStatus.INFERENCING.terminal is False
    with pytest.raises(ValueError, match="terminal"):
        AgentRunResult(
            run_id=run_id,
            status=AgentRunStatus.INFERENCING,
            model_turns=1,
            tool_calls=0,
            started_at=NOW,
            completed_at=NOW,
        )
    with pytest.raises(ValueError, match="require error_code"):
        AgentRunResult(
            run_id=run_id,
            status=AgentRunStatus.FAILED,
            model_turns=1,
            tool_calls=0,
            started_at=NOW,
            completed_at=NOW,
        )


def test_safe_errors_expose_only_stable_categories() -> None:
    missing = ToolNotFoundError()
    cancelled = AgentCancelledError()

    assert missing.code is AgentErrorCode.TOOL_NOT_FOUND
    assert str(missing) == "tool was not found"
    assert cancelled.code is AgentErrorCode.CANCELLED
    assert "prompt" not in str(missing)
    assert "argument" not in str(cancelled)


def test_effect_classification_is_finite() -> None:
    assert tuple(ToolEffect) == (
        ToolEffect.READ_ONLY,
        ToolEffect.REVERSIBLE_WRITE,
        ToolEffect.IRREVERSIBLE_WRITE,
        ToolEffect.EXTERNAL_COMMUNICATION,
    )
