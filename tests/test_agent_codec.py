import json
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from phoenix_os.agent import (
    MAX_AGENT_PROPOSAL_DOCUMENT_BYTES,
    AgentCodecError,
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
    ToolId,
    ToolInputSchema,
    ToolInvocationRequest,
    ToolInvocationResult,
    ToolOutputSchema,
    ToolResultStatus,
    ToolSchema,
    ToolSchemaType,
    decode_agent_run_request,
    decode_agent_run_result,
    decode_agent_snapshot,
    decode_tool_call_proposal,
    decode_tool_input_schema,
    decode_tool_invocation_request,
    decode_tool_invocation_result,
    decode_tool_output_schema,
    encode_agent_run_request,
    encode_agent_run_result,
    encode_agent_snapshot,
    encode_tool_call_proposal,
    encode_tool_input_schema,
    encode_tool_invocation_request,
    encode_tool_invocation_result,
    encode_tool_output_schema,
)
from phoenix_os.inference import ModelId, ModelProviderId

NOW = datetime(2026, 7, 27, 12, tzinfo=UTC)
RUN_ID = AgentRunId(UUID("10000000-0000-0000-0000-000000000001"))
STEP_ID = AgentStepId(UUID("20000000-0000-0000-0000-000000000002"))
CALL_ID = ToolCallId(UUID("30000000-0000-0000-0000-000000000003"))


def _proposal() -> ToolCallProposal:
    return ToolCallProposal(
        run_id=RUN_ID,
        step_id=STEP_ID,
        call_id=CALL_ID,
        tool_id=ToolId("files.read"),
        arguments={"path": "docs/readme.md", "lines": [1, 2]},
        created_at=NOW,
        deadline=NOW + timedelta(minutes=1),
    )


def _run_request() -> AgentRunRequest:
    return AgentRunRequest(
        agent_id=AgentId("assistant"),
        provider_id=ModelProviderId("deterministic"),
        model_id=ModelId("planner"),
        messages=(
            AgentMessage(AgentMessageRole.SYSTEM, "bounded agent"),
            AgentMessage(AgentMessageRole.USER, "read the file"),
        ),
        limits=AgentLimits(max_model_turns=4, max_tool_calls=3),
        metadata={"tenant": "demo"},
        run_id=RUN_ID,
        created_at=NOW,
        deadline=NOW + timedelta(minutes=5),
    )


def _schema() -> ToolSchema:
    return ToolSchema(
        ToolSchemaType.OBJECT,
        properties={
            "path": ToolSchema(ToolSchemaType.STRING, min_length=1, max_length=128),
        },
        required=frozenset({"path"}),
    )


def test_schema_codecs_are_canonical_and_round_trip() -> None:
    input_schema = ToolInputSchema(_schema())
    output_schema = ToolOutputSchema(_schema())

    encoded_input = encode_tool_input_schema(input_schema)
    encoded_output = encode_tool_output_schema(output_schema)

    assert decode_tool_input_schema(encoded_input) == input_schema
    assert decode_tool_output_schema(encoded_output) == output_schema
    assert encoded_input == encode_tool_input_schema(input_schema)
    assert encoded_input.startswith(b'{"kind":"phoenix.agent.tool-input-schema"')


def test_proposal_invocation_and_result_codecs_round_trip() -> None:
    proposal = _proposal()
    invocation = ToolInvocationRequest(
        run_id=proposal.run_id,
        step_id=proposal.step_id,
        call_id=proposal.call_id,
        tool_id=proposal.tool_id,
        arguments=proposal.arguments,
        resolved_resource="workspace:docs/readme.md",
        created_at=NOW,
        deadline=NOW + timedelta(minutes=1),
    )
    result = ToolInvocationResult(
        run_id=proposal.run_id,
        step_id=proposal.step_id,
        call_id=proposal.call_id,
        tool_id=proposal.tool_id,
        status=ToolResultStatus.SUCCEEDED,
        output={"text": "hello", "lines": [1, 2]},
        started_at=NOW,
        completed_at=NOW + timedelta(seconds=1),
    )

    assert decode_tool_call_proposal(encode_tool_call_proposal(proposal)) == proposal
    assert decode_tool_invocation_request(encode_tool_invocation_request(invocation)) == invocation
    assert decode_tool_invocation_result(encode_tool_invocation_result(result)) == result


def test_run_request_result_and_snapshot_codecs_round_trip() -> None:
    request = _run_request()
    result = AgentRunResult(
        run_id=RUN_ID,
        status=AgentRunStatus.COMPLETED,
        model_turns=2,
        tool_calls=1,
        final_output="done",
        started_at=NOW,
        completed_at=NOW + timedelta(seconds=2),
        metadata={"tenant": "demo"},
    )
    snapshot = AgentSnapshot(
        run_id=RUN_ID,
        status=AgentRunStatus.INFERENCING,
        model_turns=1,
        tool_calls=0,
        created_at=NOW,
        updated_at=NOW + timedelta(seconds=1),
    )

    assert decode_agent_run_request(encode_agent_run_request(request)) == request
    assert decode_agent_run_result(encode_agent_run_result(result)) == result
    assert decode_agent_snapshot(encode_agent_snapshot(snapshot)) == snapshot


def test_decoder_rejects_noncanonical_unknown_and_wrong_kind_documents() -> None:
    encoded = encode_tool_call_proposal(_proposal())
    document = json.loads(encoded)

    pretty = json.dumps(document, indent=2).encode()
    with pytest.raises(AgentCodecError, match="canonical"):
        decode_tool_call_proposal(pretty)

    document["record"]["unexpected"] = True
    unknown = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    with pytest.raises(AgentCodecError, match="fields"):
        decode_tool_call_proposal(unknown)

    with pytest.raises(AgentCodecError, match="kind"):
        decode_tool_invocation_request(encoded)


def test_decoder_rejects_duplicate_keys_nonfinite_numbers_and_invalid_unicode() -> None:
    encoded = encode_tool_call_proposal(_proposal())
    duplicate = encoded.replace(
        b'"schema_version":1',
        b'"schema_version":1,"schema_version":1',
        1,
    )
    with pytest.raises(AgentCodecError, match="duplicate"):
        decode_tool_call_proposal(duplicate)

    nonfinite = encoded.replace(b'"lines":[1,2]', b'"lines":[NaN,2]', 1)
    with pytest.raises(AgentCodecError, match="non-finite"):
        decode_tool_call_proposal(nonfinite)

    invalid_unicode = encoded.replace(b"docs/readme.md", b"\\ud800", 1)
    with pytest.raises(AgentCodecError, match="Unicode"):
        decode_tool_call_proposal(invalid_unicode)


def test_decoder_rejects_malformed_and_oversized_documents_before_contract_use() -> None:
    with pytest.raises(AgentCodecError):
        decode_tool_call_proposal(b"")
    with pytest.raises(AgentCodecError):
        decode_tool_call_proposal(b"not-json")
    with pytest.raises(AgentCodecError):
        decode_tool_call_proposal(b"{" + b"x" * MAX_AGENT_PROPOSAL_DOCUMENT_BYTES)
