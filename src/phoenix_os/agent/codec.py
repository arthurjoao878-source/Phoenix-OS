"""Strict canonical codecs for Phoenix agent boundary contracts."""

from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import datetime, timedelta
from typing import NoReturn, cast
from uuid import UUID

from phoenix_os.agent.contracts import (
    AgentId,
    AgentJsonInput,
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
    ToolInvocationRequest,
    ToolInvocationResult,
    ToolResultStatus,
)
from phoenix_os.agent.errors import AgentCodecError, AgentSchemaError
from phoenix_os.agent.schemas import (
    ToolInputSchema,
    ToolOutputSchema,
    tool_schema_from_record,
    tool_schema_to_record,
)
from phoenix_os.inference.contracts import ModelId, ModelProviderId

_SCHEMA_VERSION = 1
_TOOL_INVOCATION_LEGACY_SCHEMA_VERSION = 1
_TOOL_INVOCATION_SCHEMA_VERSION = 2
_TOOL_INPUT_SCHEMA_KIND = "phoenix.agent.tool-input-schema"
_TOOL_OUTPUT_SCHEMA_KIND = "phoenix.agent.tool-output-schema"
_TOOL_PROPOSAL_KIND = "phoenix.agent.tool-call-proposal"
_TOOL_INVOCATION_KIND = "phoenix.agent.tool-invocation-request"
_TOOL_RESULT_KIND = "phoenix.agent.tool-invocation-result"
_RUN_REQUEST_KIND = "phoenix.agent.run-request"
_RUN_RESULT_KIND = "phoenix.agent.run-result"
_SNAPSHOT_KIND = "phoenix.agent.snapshot"

MAX_AGENT_SCHEMA_DOCUMENT_BYTES = 524_288
MAX_AGENT_PROPOSAL_DOCUMENT_BYTES = 2_097_152
MAX_AGENT_INVOCATION_DOCUMENT_BYTES = 2_097_152
MAX_AGENT_TOOL_RESULT_DOCUMENT_BYTES = 5_242_880
MAX_AGENT_RUN_REQUEST_DOCUMENT_BYTES = 5_242_880
MAX_AGENT_RUN_RESULT_DOCUMENT_BYTES = 2_097_152
MAX_AGENT_SNAPSHOT_DOCUMENT_BYTES = 65_536
MAX_AGENT_CODEC_JSON_DEPTH = 64
MAX_AGENT_CODEC_JSON_ITEMS = 65_536

_ENVELOPE_FIELDS = frozenset({"schema_version", "kind", "record"})
_PROPOSAL_FIELDS = frozenset(
    {
        "run_id",
        "step_id",
        "call_id",
        "tool_id",
        "arguments",
        "created_at",
        "deadline",
    }
)
_INVOCATION_V1_FIELDS = frozenset(_PROPOSAL_FIELDS | {"resolved_resource"})
_INVOCATION_FIELDS = frozenset(_INVOCATION_V1_FIELDS | {"agent_id"})
_TOOL_RESULT_FIELDS = frozenset(
    {
        "run_id",
        "step_id",
        "call_id",
        "tool_id",
        "status",
        "output",
        "error_code",
        "started_at",
        "completed_at",
    }
)
_RUN_REQUEST_FIELDS = frozenset(
    {
        "agent_id",
        "provider_id",
        "model_id",
        "messages",
        "limits",
        "metadata",
        "run_id",
        "created_at",
        "deadline",
    }
)
_RUN_RESULT_FIELDS = frozenset(
    {
        "run_id",
        "status",
        "model_turns",
        "tool_calls",
        "final_output",
        "error_code",
        "started_at",
        "completed_at",
        "metadata",
    }
)
_SNAPSHOT_FIELDS = frozenset(
    {
        "run_id",
        "status",
        "model_turns",
        "tool_calls",
        "created_at",
        "updated_at",
    }
)
_MESSAGE_FIELDS = frozenset({"role", "content", "tool_call_id", "metadata"})
_LIMIT_FIELDS = frozenset(
    {
        "max_steps",
        "max_model_turns",
        "max_tool_calls",
        "max_prompt_bytes",
        "max_model_output_bytes",
        "max_tool_result_bytes",
        "max_input_tokens",
        "max_output_tokens",
        "max_argument_bytes",
        "max_result_bytes",
        "max_structured_depth",
        "max_structured_items",
        "max_queue_depth",
        "max_concurrent_runs",
        "max_concurrent_model_calls",
        "max_concurrent_tool_calls",
        "model_turn_timeout_microseconds",
        "tool_call_timeout_microseconds",
        "approval_wait_timeout_microseconds",
        "total_duration_microseconds",
        "cancellation_grace_microseconds",
        "shutdown_grace_microseconds",
    }
)


def encode_tool_input_schema(schema: ToolInputSchema) -> bytes:
    if not isinstance(schema, ToolInputSchema):
        raise TypeError("schema must be ToolInputSchema")
    return _encode(
        _TOOL_INPUT_SCHEMA_KIND,
        tool_schema_to_record(schema.root),
        MAX_AGENT_SCHEMA_DOCUMENT_BYTES,
    )


def decode_tool_input_schema(encoded: bytes) -> ToolInputSchema:
    record = _decode(
        encoded,
        expected_kind=_TOOL_INPUT_SCHEMA_KIND,
        maximum_bytes=MAX_AGENT_SCHEMA_DOCUMENT_BYTES,
    )
    try:
        schema = ToolInputSchema(tool_schema_from_record(record))
    except AgentSchemaError as exception:
        raise AgentCodecError("tool input schema document is invalid") from exception
    except (TypeError, ValueError, OverflowError) as exception:
        raise AgentCodecError() from exception
    if encode_tool_input_schema(schema) != encoded:
        raise AgentCodecError("tool input schema document is not canonical")
    return schema


def encode_tool_output_schema(schema: ToolOutputSchema) -> bytes:
    if not isinstance(schema, ToolOutputSchema):
        raise TypeError("schema must be ToolOutputSchema")
    return _encode(
        _TOOL_OUTPUT_SCHEMA_KIND,
        tool_schema_to_record(schema.root),
        MAX_AGENT_SCHEMA_DOCUMENT_BYTES,
    )


def decode_tool_output_schema(encoded: bytes) -> ToolOutputSchema:
    record = _decode(
        encoded,
        expected_kind=_TOOL_OUTPUT_SCHEMA_KIND,
        maximum_bytes=MAX_AGENT_SCHEMA_DOCUMENT_BYTES,
    )
    try:
        schema = ToolOutputSchema(tool_schema_from_record(record))
    except AgentSchemaError as exception:
        raise AgentCodecError("tool output schema document is invalid") from exception
    except (TypeError, ValueError, OverflowError) as exception:
        raise AgentCodecError() from exception
    if encode_tool_output_schema(schema) != encoded:
        raise AgentCodecError("tool output schema document is not canonical")
    return schema


def encode_tool_call_proposal(proposal: ToolCallProposal) -> bytes:
    if not isinstance(proposal, ToolCallProposal):
        raise TypeError("proposal must be ToolCallProposal")
    return _encode(
        _TOOL_PROPOSAL_KIND,
        _proposal_record(proposal),
        MAX_AGENT_PROPOSAL_DOCUMENT_BYTES,
    )


def decode_tool_call_proposal(encoded: bytes) -> ToolCallProposal:
    record = _decode(
        encoded,
        expected_kind=_TOOL_PROPOSAL_KIND,
        maximum_bytes=MAX_AGENT_PROPOSAL_DOCUMENT_BYTES,
    )
    _require_exact_fields(record, _PROPOSAL_FIELDS, label="tool proposal record")
    try:
        proposal = ToolCallProposal(
            run_id=AgentRunId(_uuid(record, "run_id")),
            step_id=AgentStepId(_uuid(record, "step_id")),
            call_id=ToolCallId(_uuid(record, "call_id")),
            tool_id=ToolId(_string(record, "tool_id")),
            arguments=_structured_object(record.get("arguments"), label="arguments"),
            created_at=_datetime(record, "created_at"),
            deadline=_datetime(record, "deadline"),
        )
    except AgentCodecError:
        raise
    except (TypeError, ValueError, OverflowError) as exception:
        raise AgentCodecError() from exception
    if encode_tool_call_proposal(proposal) != encoded:
        raise AgentCodecError("tool proposal document is not canonical")
    return proposal


def encode_tool_invocation_request(request: ToolInvocationRequest) -> bytes:
    if not isinstance(request, ToolInvocationRequest):
        raise TypeError("request must be ToolInvocationRequest")
    return _encode(
        _TOOL_INVOCATION_KIND,
        _invocation_record(request),
        MAX_AGENT_INVOCATION_DOCUMENT_BYTES,
        schema_version=_TOOL_INVOCATION_SCHEMA_VERSION,
    )


def decode_tool_invocation_request(encoded: bytes) -> ToolInvocationRequest:
    schema_version, record = _decode_versioned(
        encoded,
        expected_kind=_TOOL_INVOCATION_KIND,
        maximum_bytes=MAX_AGENT_INVOCATION_DOCUMENT_BYTES,
        supported_schema_versions=frozenset(
            {
                _TOOL_INVOCATION_LEGACY_SCHEMA_VERSION,
                _TOOL_INVOCATION_SCHEMA_VERSION,
            }
        ),
    )
    fields = (
        _INVOCATION_V1_FIELDS
        if schema_version == _TOOL_INVOCATION_LEGACY_SCHEMA_VERSION
        else _INVOCATION_FIELDS
    )
    _require_exact_fields(record, fields, label="tool invocation record")
    try:
        request = ToolInvocationRequest(
            run_id=AgentRunId(_uuid(record, "run_id")),
            step_id=AgentStepId(_uuid(record, "step_id")),
            call_id=ToolCallId(_uuid(record, "call_id")),
            tool_id=ToolId(_string(record, "tool_id")),
            arguments=_structured_object(record.get("arguments"), label="arguments"),
            resolved_resource=_string(record, "resolved_resource"),
            created_at=_datetime(record, "created_at"),
            deadline=_datetime(record, "deadline"),
            agent_id=(
                None
                if schema_version == _TOOL_INVOCATION_LEGACY_SCHEMA_VERSION
                else AgentId(_string(record, "agent_id"))
            ),
        )
    except AgentCodecError:
        raise
    except (TypeError, ValueError, OverflowError) as exception:
        raise AgentCodecError() from exception

    if schema_version == _TOOL_INVOCATION_LEGACY_SCHEMA_VERSION:
        canonical = _encode(
            _TOOL_INVOCATION_KIND,
            _legacy_invocation_record(request),
            MAX_AGENT_INVOCATION_DOCUMENT_BYTES,
            schema_version=_TOOL_INVOCATION_LEGACY_SCHEMA_VERSION,
        )
    else:
        canonical = encode_tool_invocation_request(request)

    if canonical != encoded:
        raise AgentCodecError("tool invocation document is not canonical")
    return request


def encode_tool_invocation_result(result: ToolInvocationResult) -> bytes:
    if not isinstance(result, ToolInvocationResult):
        raise TypeError("result must be ToolInvocationResult")
    return _encode(
        _TOOL_RESULT_KIND,
        _tool_result_record(result),
        MAX_AGENT_TOOL_RESULT_DOCUMENT_BYTES,
    )


def decode_tool_invocation_result(encoded: bytes) -> ToolInvocationResult:
    record = _decode(
        encoded,
        expected_kind=_TOOL_RESULT_KIND,
        maximum_bytes=MAX_AGENT_TOOL_RESULT_DOCUMENT_BYTES,
    )
    _require_exact_fields(record, _TOOL_RESULT_FIELDS, label="tool result record")
    output_value = record.get("output")
    try:
        result = ToolInvocationResult(
            run_id=AgentRunId(_uuid(record, "run_id")),
            step_id=AgentStepId(_uuid(record, "step_id")),
            call_id=ToolCallId(_uuid(record, "call_id")),
            tool_id=ToolId(_string(record, "tool_id")),
            status=ToolResultStatus(_string(record, "status")),
            output=(
                None if output_value is None else _structured_object(output_value, label="output")
            ),
            error_code=_optional_string(record, "error_code"),
            started_at=_datetime(record, "started_at"),
            completed_at=_datetime(record, "completed_at"),
        )
    except AgentCodecError:
        raise
    except (TypeError, ValueError, OverflowError) as exception:
        raise AgentCodecError() from exception
    if encode_tool_invocation_result(result) != encoded:
        raise AgentCodecError("tool result document is not canonical")
    return result


def encode_agent_run_request(request: AgentRunRequest) -> bytes:
    if not isinstance(request, AgentRunRequest):
        raise TypeError("request must be AgentRunRequest")
    return _encode(
        _RUN_REQUEST_KIND,
        _run_request_record(request),
        MAX_AGENT_RUN_REQUEST_DOCUMENT_BYTES,
    )


def decode_agent_run_request(encoded: bytes) -> AgentRunRequest:
    record = _decode(
        encoded,
        expected_kind=_RUN_REQUEST_KIND,
        maximum_bytes=MAX_AGENT_RUN_REQUEST_DOCUMENT_BYTES,
    )
    _require_exact_fields(record, _RUN_REQUEST_FIELDS, label="agent run request record")
    messages_value = _list(record.get("messages"), label="messages")
    try:
        request = AgentRunRequest(
            agent_id=AgentId(_string(record, "agent_id")),
            provider_id=ModelProviderId(_string(record, "provider_id")),
            model_id=ModelId(_string(record, "model_id")),
            messages=tuple(
                _decode_message(_mapping(item, label="message")) for item in messages_value
            ),
            limits=_decode_limits(_mapping(record.get("limits"), label="limits")),
            metadata=_string_mapping(record.get("metadata"), label="metadata"),
            run_id=AgentRunId(_uuid(record, "run_id")),
            created_at=_datetime(record, "created_at"),
            deadline=_datetime(record, "deadline"),
        )
    except AgentCodecError:
        raise
    except (TypeError, ValueError, OverflowError) as exception:
        raise AgentCodecError() from exception
    if encode_agent_run_request(request) != encoded:
        raise AgentCodecError("agent run request document is not canonical")
    return request


def encode_agent_run_result(result: AgentRunResult) -> bytes:
    if not isinstance(result, AgentRunResult):
        raise TypeError("result must be AgentRunResult")
    return _encode(
        _RUN_RESULT_KIND,
        _run_result_record(result),
        MAX_AGENT_RUN_RESULT_DOCUMENT_BYTES,
    )


def decode_agent_run_result(encoded: bytes) -> AgentRunResult:
    record = _decode(
        encoded,
        expected_kind=_RUN_RESULT_KIND,
        maximum_bytes=MAX_AGENT_RUN_RESULT_DOCUMENT_BYTES,
    )
    _require_exact_fields(record, _RUN_RESULT_FIELDS, label="agent run result record")
    try:
        result = AgentRunResult(
            run_id=AgentRunId(_uuid(record, "run_id")),
            status=AgentRunStatus(_string(record, "status")),
            model_turns=_integer(record, "model_turns"),
            tool_calls=_integer(record, "tool_calls"),
            final_output=_optional_string(record, "final_output"),
            error_code=_optional_string(record, "error_code"),
            started_at=_datetime(record, "started_at"),
            completed_at=_datetime(record, "completed_at"),
            metadata=_string_mapping(record.get("metadata"), label="metadata"),
        )
    except AgentCodecError:
        raise
    except (TypeError, ValueError, OverflowError) as exception:
        raise AgentCodecError() from exception
    if encode_agent_run_result(result) != encoded:
        raise AgentCodecError("agent run result document is not canonical")
    return result


def encode_agent_snapshot(snapshot: AgentSnapshot) -> bytes:
    if not isinstance(snapshot, AgentSnapshot):
        raise TypeError("snapshot must be AgentSnapshot")
    return _encode(
        _SNAPSHOT_KIND,
        _snapshot_record(snapshot),
        MAX_AGENT_SNAPSHOT_DOCUMENT_BYTES,
    )


def decode_agent_snapshot(encoded: bytes) -> AgentSnapshot:
    record = _decode(
        encoded,
        expected_kind=_SNAPSHOT_KIND,
        maximum_bytes=MAX_AGENT_SNAPSHOT_DOCUMENT_BYTES,
    )
    _require_exact_fields(record, _SNAPSHOT_FIELDS, label="agent snapshot record")
    try:
        snapshot = AgentSnapshot(
            run_id=AgentRunId(_uuid(record, "run_id")),
            status=AgentRunStatus(_string(record, "status")),
            model_turns=_integer(record, "model_turns"),
            tool_calls=_integer(record, "tool_calls"),
            created_at=_datetime(record, "created_at"),
            updated_at=_datetime(record, "updated_at"),
        )
    except AgentCodecError:
        raise
    except (TypeError, ValueError, OverflowError) as exception:
        raise AgentCodecError() from exception
    if encode_agent_snapshot(snapshot) != encoded:
        raise AgentCodecError("agent snapshot document is not canonical")
    return snapshot


def canonical_tool_call_proposal_bytes(proposal: ToolCallProposal) -> bytes:
    return encode_tool_call_proposal(proposal)


def canonical_tool_invocation_request_bytes(request: ToolInvocationRequest) -> bytes:
    return encode_tool_invocation_request(request)


def canonical_tool_invocation_result_bytes(result: ToolInvocationResult) -> bytes:
    return encode_tool_invocation_result(result)


def canonical_agent_run_request_bytes(request: AgentRunRequest) -> bytes:
    return encode_agent_run_request(request)


def canonical_agent_run_result_bytes(result: AgentRunResult) -> bytes:
    return encode_agent_run_result(result)


def _proposal_record(proposal: ToolCallProposal) -> dict[str, object]:
    return {
        "run_id": str(proposal.run_id),
        "step_id": str(proposal.step_id),
        "call_id": str(proposal.call_id),
        "tool_id": str(proposal.tool_id),
        "arguments": _structured_to_builtin(proposal.arguments),
        "created_at": proposal.created_at.isoformat(),
        "deadline": proposal.deadline.isoformat(),
    }


def _legacy_invocation_record(request: ToolInvocationRequest) -> dict[str, object]:
    return {
        **_proposal_record(
            ToolCallProposal(
                run_id=request.run_id,
                step_id=request.step_id,
                call_id=request.call_id,
                tool_id=request.tool_id,
                arguments=request.arguments,
                created_at=request.created_at,
                deadline=request.deadline,
            )
        ),
        "resolved_resource": request.resolved_resource,
    }


def _invocation_record(request: ToolInvocationRequest) -> dict[str, object]:
    if request.agent_id is None:
        raise AgentCodecError("tool invocation request is missing agent binding")
    return {
        **_legacy_invocation_record(request),
        "agent_id": str(request.agent_id),
    }


def _tool_result_record(result: ToolInvocationResult) -> dict[str, object]:
    return {
        "run_id": str(result.run_id),
        "step_id": str(result.step_id),
        "call_id": str(result.call_id),
        "tool_id": str(result.tool_id),
        "status": result.status.value,
        "output": None if result.output is None else _structured_to_builtin(result.output),
        "error_code": result.error_code,
        "started_at": result.started_at.isoformat(),
        "completed_at": result.completed_at.isoformat(),
    }


def _run_request_record(request: AgentRunRequest) -> dict[str, object]:
    return {
        "agent_id": str(request.agent_id),
        "provider_id": str(request.provider_id),
        "model_id": str(request.model_id),
        "messages": [_message_record(message) for message in request.messages],
        "limits": _limits_record(request.limits),
        "metadata": dict(request.metadata),
        "run_id": str(request.run_id),
        "created_at": request.created_at.isoformat(),
        "deadline": request.deadline.isoformat(),
    }


def _run_result_record(result: AgentRunResult) -> dict[str, object]:
    return {
        "run_id": str(result.run_id),
        "status": result.status.value,
        "model_turns": result.model_turns,
        "tool_calls": result.tool_calls,
        "final_output": result.final_output,
        "error_code": result.error_code,
        "started_at": result.started_at.isoformat(),
        "completed_at": result.completed_at.isoformat(),
        "metadata": dict(result.metadata),
    }


def _snapshot_record(snapshot: AgentSnapshot) -> dict[str, object]:
    return {
        "run_id": str(snapshot.run_id),
        "status": snapshot.status.value,
        "model_turns": snapshot.model_turns,
        "tool_calls": snapshot.tool_calls,
        "created_at": snapshot.created_at.isoformat(),
        "updated_at": snapshot.updated_at.isoformat(),
    }


def _message_record(message: AgentMessage) -> dict[str, object]:
    return {
        "role": message.role.value,
        "content": message.content,
        "tool_call_id": None if message.tool_call_id is None else str(message.tool_call_id),
        "metadata": dict(message.metadata),
    }


def _decode_message(record: Mapping[str, object]) -> AgentMessage:
    _require_exact_fields(record, _MESSAGE_FIELDS, label="agent message record")
    call_id = _optional_string(record, "tool_call_id")
    return AgentMessage(
        role=AgentMessageRole(_string(record, "role")),
        content=_string(record, "content"),
        tool_call_id=None if call_id is None else ToolCallId(UUID(call_id)),
        metadata=_string_mapping(record.get("metadata"), label="message metadata"),
    )


def _limits_record(limits: AgentLimits) -> dict[str, object]:
    return {
        "max_steps": limits.max_steps,
        "max_model_turns": limits.max_model_turns,
        "max_tool_calls": limits.max_tool_calls,
        "max_prompt_bytes": limits.max_prompt_bytes,
        "max_model_output_bytes": limits.max_model_output_bytes,
        "max_tool_result_bytes": limits.max_tool_result_bytes,
        "max_input_tokens": limits.max_input_tokens,
        "max_output_tokens": limits.max_output_tokens,
        "max_argument_bytes": limits.max_argument_bytes,
        "max_result_bytes": limits.max_result_bytes,
        "max_structured_depth": limits.max_structured_depth,
        "max_structured_items": limits.max_structured_items,
        "max_queue_depth": limits.max_queue_depth,
        "max_concurrent_runs": limits.max_concurrent_runs,
        "max_concurrent_model_calls": limits.max_concurrent_model_calls,
        "max_concurrent_tool_calls": limits.max_concurrent_tool_calls,
        "model_turn_timeout_microseconds": _duration_microseconds(limits.model_turn_timeout),
        "tool_call_timeout_microseconds": _duration_microseconds(limits.tool_call_timeout),
        "approval_wait_timeout_microseconds": _duration_microseconds(limits.approval_wait_timeout),
        "total_duration_microseconds": _duration_microseconds(limits.total_duration),
        "cancellation_grace_microseconds": _duration_microseconds(limits.cancellation_grace),
        "shutdown_grace_microseconds": _duration_microseconds(limits.shutdown_grace),
    }


def _decode_limits(record: Mapping[str, object]) -> AgentLimits:
    _require_exact_fields(record, _LIMIT_FIELDS, label="agent limits record")
    return AgentLimits(
        max_steps=_integer(record, "max_steps"),
        max_model_turns=_integer(record, "max_model_turns"),
        max_tool_calls=_integer(record, "max_tool_calls"),
        max_prompt_bytes=_integer(record, "max_prompt_bytes"),
        max_model_output_bytes=_integer(record, "max_model_output_bytes"),
        max_tool_result_bytes=_integer(record, "max_tool_result_bytes"),
        max_input_tokens=_integer(record, "max_input_tokens"),
        max_output_tokens=_integer(record, "max_output_tokens"),
        max_argument_bytes=_integer(record, "max_argument_bytes"),
        max_result_bytes=_integer(record, "max_result_bytes"),
        max_structured_depth=_integer(record, "max_structured_depth"),
        max_structured_items=_integer(record, "max_structured_items"),
        max_queue_depth=_integer(record, "max_queue_depth"),
        max_concurrent_runs=_integer(record, "max_concurrent_runs"),
        max_concurrent_model_calls=_integer(record, "max_concurrent_model_calls"),
        max_concurrent_tool_calls=_integer(record, "max_concurrent_tool_calls"),
        model_turn_timeout=_microseconds_duration(record, "model_turn_timeout_microseconds"),
        tool_call_timeout=_microseconds_duration(record, "tool_call_timeout_microseconds"),
        approval_wait_timeout=_microseconds_duration(
            record,
            "approval_wait_timeout_microseconds",
        ),
        total_duration=_microseconds_duration(record, "total_duration_microseconds"),
        cancellation_grace=_microseconds_duration(
            record,
            "cancellation_grace_microseconds",
        ),
        shutdown_grace=_microseconds_duration(record, "shutdown_grace_microseconds"),
    )


def _duration_microseconds(value: timedelta) -> int:
    return (value.days * 86_400 + value.seconds) * 1_000_000 + value.microseconds


def _microseconds_duration(record: Mapping[str, object], key: str) -> timedelta:
    return timedelta(microseconds=_integer(record, key))


def _structured_to_builtin(value: object) -> object:
    if isinstance(value, Mapping):
        return {key: _structured_to_builtin(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_structured_to_builtin(item) for item in value]
    return value


def _encode(
    kind: str,
    record: Mapping[str, object],
    maximum_bytes: int,
    *,
    schema_version: int = _SCHEMA_VERSION,
) -> bytes:
    document = {
        "schema_version": schema_version,
        "kind": kind,
        "record": record,
    }
    try:
        encoded = json.dumps(
            document,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, OverflowError, UnicodeEncodeError) as exception:
        raise AgentCodecError() from exception
    if len(encoded) > maximum_bytes:
        raise AgentCodecError("agent document exceeds the maximum size")
    return encoded


def _decode(
    encoded: bytes,
    *,
    expected_kind: str,
    maximum_bytes: int,
) -> Mapping[str, object]:
    _, record = _decode_versioned(
        encoded,
        expected_kind=expected_kind,
        maximum_bytes=maximum_bytes,
        supported_schema_versions=frozenset({_SCHEMA_VERSION}),
    )
    return record


def _decode_versioned(
    encoded: bytes,
    *,
    expected_kind: str,
    maximum_bytes: int,
    supported_schema_versions: frozenset[int],
) -> tuple[int, Mapping[str, object]]:
    if not isinstance(encoded, bytes):
        raise TypeError("encoded agent document must be bytes")
    if not encoded or len(encoded) > maximum_bytes:
        raise AgentCodecError()
    try:
        decoded: object = json.loads(
            encoded.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_non_finite_constant,
        )
    except AgentCodecError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exception:
        raise AgentCodecError() from exception
    _inspect_json(decoded, depth=0, count=[0])
    envelope = _mapping(decoded, label="agent envelope")
    _require_exact_fields(envelope, _ENVELOPE_FIELDS, label="agent envelope")
    schema_version = _integer(envelope, "schema_version")
    if schema_version not in supported_schema_versions:
        raise AgentCodecError("unsupported agent schema version")
    if _string(envelope, "kind") != expected_kind:
        raise AgentCodecError("unexpected agent document kind")
    return schema_version, _mapping(envelope.get("record"), label="agent record")


def _reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise AgentCodecError("agent document contains duplicate object keys")
        result[key] = value
    return result


def _reject_non_finite_constant(value: str) -> NoReturn:
    raise AgentCodecError(f"non-finite JSON number is not allowed: {value}")


def _inspect_json(value: object, *, depth: int, count: list[int]) -> None:
    if depth > MAX_AGENT_CODEC_JSON_DEPTH:
        raise AgentCodecError("agent document exceeds the maximum JSON depth")
    count[0] += 1
    if count[0] > MAX_AGENT_CODEC_JSON_ITEMS:
        raise AgentCodecError("agent document exceeds the maximum JSON item count")
    if isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeEncodeError as exception:
            raise AgentCodecError("agent document contains invalid Unicode") from exception
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            _inspect_json(key, depth=depth + 1, count=count)
            _inspect_json(item, depth=depth + 1, count=count)
        return
    if isinstance(value, list):
        for item in value:
            _inspect_json(item, depth=depth + 1, count=count)


def _mapping(value: object, *, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise AgentCodecError(f"{label} must be an object")
    raw = cast(Mapping[object, object], value)
    if any(not isinstance(key, str) for key in raw):
        raise AgentCodecError(f"{label} keys must be strings")
    return cast(Mapping[str, object], raw)


def _list(value: object, *, label: str) -> list[object]:
    if not isinstance(value, list):
        raise AgentCodecError(f"{label} must be an array")
    return cast(list[object], value)


def _require_exact_fields(
    value: Mapping[str, object],
    expected: frozenset[str],
    *,
    label: str,
) -> None:
    if frozenset(value) != expected:
        raise AgentCodecError(f"{label} fields are invalid")


def _string(value: Mapping[str, object], key: str) -> str:
    item = value.get(key)
    if not isinstance(item, str):
        raise AgentCodecError(f"{key} must be a string")
    return item


def _optional_string(value: Mapping[str, object], key: str) -> str | None:
    item = value.get(key)
    if item is None:
        return None
    if not isinstance(item, str):
        raise AgentCodecError(f"{key} must be a string or null")
    return item


def _integer(value: Mapping[str, object], key: str) -> int:
    item = value.get(key)
    if isinstance(item, bool) or not isinstance(item, int):
        raise AgentCodecError(f"{key} must be an integer")
    return item


def _uuid(value: Mapping[str, object], key: str) -> UUID:
    try:
        return UUID(_string(value, key))
    except ValueError as exception:
        raise AgentCodecError(f"{key} must be a UUID") from exception


def _datetime(value: Mapping[str, object], key: str) -> datetime:
    try:
        return datetime.fromisoformat(_string(value, key))
    except ValueError as exception:
        raise AgentCodecError(f"{key} must be an ISO-8601 datetime") from exception


def _structured_object(
    value: object,
    *,
    label: str,
) -> Mapping[str, AgentJsonInput]:
    mapped = _mapping(value, label=label)
    return cast(Mapping[str, AgentJsonInput], mapped)


def _string_mapping(value: object, *, label: str) -> Mapping[str, str]:
    mapped = _mapping(value, label=label)
    if any(not isinstance(item, str) for item in mapped.values()):
        raise AgentCodecError(f"{label} values must be strings")
    return cast(Mapping[str, str], mapped)
