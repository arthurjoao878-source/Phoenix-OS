from datetime import UTC, datetime, timedelta

import pytest

from phoenix_os.agent import (
    AgentMalformedProposalError,
    AgentMessage,
    AgentMessageRole,
    AgentModelTurnAdapter,
    AgentModelTurnKind,
    AgentModelTurnRequest,
    AgentRunId,
    AgentStepId,
    DeterministicFinalTurn,
    DeterministicModelTurnAdapter,
    DeterministicReadOnlyTool,
    DeterministicSideEffectTool,
    DeterministicToolTurn,
    ToolCallId,
    ToolDescriptor,
    ToolEffect,
    ToolExecutionError,
    ToolId,
    ToolInputSchema,
    ToolInvocationRequest,
    ToolOutputSchema,
    ToolResultStatus,
    ToolSchema,
    ToolSchemaType,
)

NOW = datetime(2026, 7, 27, 12, tzinfo=UTC)


def _schema(name: str) -> ToolSchema:
    return ToolSchema(
        kind=ToolSchemaType.OBJECT,
        properties={name: ToolSchema(kind=ToolSchemaType.STRING, max_length=128)},
        required=frozenset({name}),
    )


def _descriptor(tool_id: str, *, adapter_id: str = "deterministic-read-only") -> ToolDescriptor:
    return ToolDescriptor(
        tool_id=ToolId(tool_id),
        name=f"Tool {tool_id}",
        description="Deterministic test-only tool.",
        input_schema=ToolInputSchema(_schema("key")),
        output_schema=ToolOutputSchema(_schema("value")),
        effect=ToolEffect.READ_ONLY,
        approval_may_be_required=False,
        max_input_bytes=4_096,
        max_output_bytes=4_096,
        timeout=timedelta(seconds=5),
        resolver_id=f"resolver.{tool_id}",
        adapter_id=adapter_id,
    )


def _turn_request(*tools: ToolDescriptor) -> AgentModelTurnRequest:
    return AgentModelTurnRequest(
        run_id=AgentRunId(),
        step_id=AgentStepId(),
        messages=(AgentMessage(AgentMessageRole.USER, "perform the reviewed task"),),
        tools=tools,
        created_at=NOW,
        deadline=NOW + timedelta(seconds=30),
    )


def _invocation(tool_id: str) -> ToolInvocationRequest:
    return ToolInvocationRequest(
        run_id=AgentRunId(),
        step_id=AgentStepId(),
        call_id=ToolCallId(),
        tool_id=ToolId(tool_id),
        arguments={"key": "alpha"},
        resolved_resource=f"fixture:{tool_id}",
        created_at=NOW,
        deadline=NOW + timedelta(seconds=5),
    )


@pytest.mark.asyncio
async def test_deterministic_model_turn_adapter_replays_tool_then_final() -> None:
    descriptor = _descriptor("lookup")
    tool_turn = DeterministicToolTurn(ToolId("lookup"), {"key": "alpha"})
    adapter = DeterministicModelTurnAdapter((tool_turn, DeterministicFinalTurn("completed")))
    first_request = _turn_request(descriptor)
    second_request = _turn_request(descriptor)

    first = await adapter.complete_turn(first_request)
    second = await adapter.complete_turn(second_request)

    assert isinstance(adapter, AgentModelTurnAdapter)
    assert first.kind is AgentModelTurnKind.TOOL_PROPOSAL
    assert first.proposal is not None
    assert first.proposal.call_id == tool_turn.call_id
    assert first.proposal.arguments == {"key": "alpha"}
    assert second.kind is AgentModelTurnKind.FINAL_OUTPUT
    assert second.final_output == "completed"
    assert adapter.requests == (first_request, second_request)
    assert adapter.remaining_turns == 0


@pytest.mark.asyncio
async def test_deterministic_model_turn_rejects_unadmitted_tool() -> None:
    adapter = DeterministicModelTurnAdapter(
        (DeterministicToolTurn(ToolId("hidden"), {"key": "alpha"}),)
    )

    with pytest.raises(AgentMalformedProposalError):
        await adapter.complete_turn(_turn_request(_descriptor("visible")))


@pytest.mark.asyncio
async def test_deterministic_model_turn_fails_closed_when_exhausted() -> None:
    adapter = DeterministicModelTurnAdapter((DeterministicFinalTurn("done"),))
    request = _turn_request()

    await adapter.complete_turn(request)
    with pytest.raises(AgentMalformedProposalError):
        await adapter.complete_turn(request)


def test_model_turn_contract_rejects_duplicate_or_disabled_tools() -> None:
    descriptor = _descriptor("lookup")

    with pytest.raises(ValueError, match="duplicate"):
        _turn_request(descriptor, descriptor)


@pytest.mark.asyncio
async def test_read_only_fake_tool_returns_fixed_immutable_output() -> None:
    caller_owned = {"value": "fixed"}
    adapter = DeterministicReadOnlyTool("lookup", caller_owned)
    request = _invocation("lookup")
    caller_owned["value"] = "changed"

    result = await adapter.invoke(request)

    assert result.status is ToolResultStatus.SUCCEEDED
    assert result.output == {"value": "fixed"}
    assert adapter.output == {"value": "fixed"}
    assert adapter.requests == (request,)
    with pytest.raises(TypeError):
        adapter.output["value"] = "changed"  # type: ignore[index]


@pytest.mark.asyncio
async def test_side_effect_fake_tool_records_exactly_one_effect_per_call() -> None:
    adapter = DeterministicSideEffectTool(
        "messages.send",
        {"value": "sent"},
        adapter_id="deterministic-side-effect",
    )
    first = _invocation("messages.send")
    second = _invocation("messages.send")

    await adapter.invoke(first)
    await adapter.invoke(second)

    assert adapter.effect_count == 2
    assert adapter.effects == (first.call_id, second.call_id)
    assert adapter.requests == (first, second)


@pytest.mark.asyncio
async def test_fake_tool_rejects_mismatched_tool_identifier() -> None:
    adapter = DeterministicReadOnlyTool("lookup", {"value": "fixed"})

    with pytest.raises(ToolExecutionError):
        await adapter.invoke(_invocation("other"))
