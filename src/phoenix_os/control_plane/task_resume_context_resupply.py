"""Bounded exact context-resupply envelope for RFC-0039 post-restart resume."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import NoReturn, cast

from phoenix_os.agent.codec import decode_agent_run_request, encode_agent_run_request
from phoenix_os.agent.contracts import AgentRunRequest
from phoenix_os.agent.errors import AgentCodecError
from phoenix_os.integrated_agent.codec import (
    decode_integrated_data_provenance,
    decode_integrated_task_request,
    decode_normalized_plan,
    encode_integrated_data_provenance,
    encode_integrated_task_request,
    encode_normalized_plan,
)
from phoenix_os.integrated_agent.contracts import (
    IntegratedBudgetUsage,
    IntegratedDataProvenance,
    IntegratedTaskRequest,
    NormalizedPlan,
)
from phoenix_os.integrated_agent.errors import IntegratedAgentCodecError

_SCHEMA_VERSION = 1
_KIND = "phoenix.rfc0039.task-resume-context-resupply"

MAX_TASK_RESUME_CONTEXT_DOCUMENT_BYTES = 8 * 1024 * 1024
MAX_TASK_RESUME_CONTEXT_JSON_DEPTH = 80
MAX_TASK_RESUME_CONTEXT_JSON_ITEMS = 262_144
MAX_TASK_RESUME_CONTEXT_JSON_KEY_CHARS = 256
MAX_TASK_RESUME_CONTEXT_JSON_STRING_CHARS = 5_242_880

_ENVELOPE_FIELDS = frozenset({"schema_version", "kind", "record"})
_RECORD_FIELDS = frozenset(
    {
        "task",
        "request",
        "provenance",
        "budget_usage",
        "plan",
    }
)
_BUDGET_FIELDS = frozenset(
    {
        "plan_revisions",
        "integrated_steps",
        "browser_operations",
        "network_operations",
        "memory_operations",
        "workspace_operations",
        "workspace_mutation_bytes",
        "host_operations",
    }
)


class TaskResumeContextCodecError(ValueError):
    """Content-free failure for invalid or non-canonical resume context."""


@dataclass(frozen=True, slots=True)
class TaskResumeContextResupply:
    """Exact reviewed content required to restore one paused durable task."""

    task: IntegratedTaskRequest = field(repr=False)
    request: AgentRunRequest = field(repr=False)
    provenance: IntegratedDataProvenance = field(repr=False)
    budget_usage: IntegratedBudgetUsage
    plan: NormalizedPlan | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.task, IntegratedTaskRequest):
            raise TypeError("task must be IntegratedTaskRequest")
        if not isinstance(self.request, AgentRunRequest):
            raise TypeError("request must be AgentRunRequest")
        if not isinstance(self.provenance, IntegratedDataProvenance):
            raise TypeError("provenance must be IntegratedDataProvenance")
        if not isinstance(self.budget_usage, IntegratedBudgetUsage):
            raise TypeError("budget_usage must be IntegratedBudgetUsage")
        if self.plan is not None and not isinstance(self.plan, NormalizedPlan):
            raise TypeError("plan must be NormalizedPlan or None")
        if self.plan is not None and self.plan.task_id != self.task.task_id:
            raise ValueError("plan task id must match the resupplied task")


def encode_task_resume_context_resupply(value: TaskResumeContextResupply) -> bytes:
    """Encode one exact resupply envelope without persisting protected content."""

    if not isinstance(value, TaskResumeContextResupply):
        raise TypeError("value must be TaskResumeContextResupply")

    record: dict[str, object] = {
        "task": _existing_document(
            encode_integrated_task_request(value.task),
            label="task",
        ),
        "request": _existing_document(
            encode_agent_run_request(value.request),
            label="request",
        ),
        "provenance": _existing_document(
            encode_integrated_data_provenance(value.provenance),
            label="provenance",
        ),
        "budget_usage": _budget_record(value.budget_usage),
        "plan": (
            None
            if value.plan is None
            else _existing_document(
                encode_normalized_plan(value.plan),
                label="plan",
            )
        ),
    }
    encoded = _canonical_json_bytes(
        {
            "schema_version": _SCHEMA_VERSION,
            "kind": _KIND,
            "record": record,
        }
    )
    if len(encoded) > MAX_TASK_RESUME_CONTEXT_DOCUMENT_BYTES:
        raise TaskResumeContextCodecError()
    return encoded


def decode_task_resume_context_resupply(encoded: bytes) -> TaskResumeContextResupply:
    """Decode only one canonical bounded context-resupply envelope."""

    envelope = _decode_envelope(encoded)
    record = _mapping(envelope["record"], label="record")
    _require_exact_fields(record, _RECORD_FIELDS)

    try:
        task = decode_integrated_task_request(
            _canonical_json_bytes(_mapping(record["task"], label="task"))
        )
        request = decode_agent_run_request(
            _canonical_json_bytes(_mapping(record["request"], label="request"))
        )
        provenance = decode_integrated_data_provenance(
            _canonical_json_bytes(_mapping(record["provenance"], label="provenance"))
        )
        budget_usage = _decode_budget(record["budget_usage"])

        raw_plan = record["plan"]
        plan = (
            None
            if raw_plan is None
            else decode_normalized_plan(_canonical_json_bytes(_mapping(raw_plan, label="plan")))
        )
        value = TaskResumeContextResupply(
            task=task,
            request=request,
            provenance=provenance,
            budget_usage=budget_usage,
            plan=plan,
        )
    except (AgentCodecError, IntegratedAgentCodecError) as exception:
        _raise_codec_error(exception)
    except (TypeError, ValueError, OverflowError) as exception:
        _raise_codec_error(exception)

    if encode_task_resume_context_resupply(value) != encoded:
        raise TaskResumeContextCodecError()
    return value


def canonical_task_resume_context_resupply_bytes(
    value: TaskResumeContextResupply,
) -> bytes:
    """Return the canonical transport bytes for one reviewed resupply."""

    return encode_task_resume_context_resupply(value)


def _decode_envelope(encoded: bytes) -> Mapping[str, object]:
    if not isinstance(encoded, bytes):
        raise TypeError("encoded document must be bytes")
    if not encoded or len(encoded) > MAX_TASK_RESUME_CONTEXT_DOCUMENT_BYTES:
        raise TaskResumeContextCodecError()

    try:
        text = encoded.decode("utf-8")
        decoded: object = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_pairs,
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        RecursionError,
        ValueError,
    ) as exception:
        _raise_codec_error(exception)

    _measure_json(decoded, depth=0, counter=[0])
    envelope = _mapping(decoded, label="envelope")
    _require_exact_fields(envelope, _ENVELOPE_FIELDS)
    if _integer(envelope["schema_version"], label="schema_version") != _SCHEMA_VERSION:
        raise TaskResumeContextCodecError()
    if _string(envelope["kind"], label="kind") != _KIND:
        raise TaskResumeContextCodecError()
    return envelope


def _existing_document(encoded: bytes, *, label: str) -> Mapping[str, object]:
    try:
        decoded: object = json.loads(
            encoded.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_pairs,
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        RecursionError,
        ValueError,
    ) as exception:
        _raise_codec_error(exception)
    return _mapping(decoded, label=label)


def _budget_record(value: IntegratedBudgetUsage) -> dict[str, int]:
    return {
        "plan_revisions": value.plan_revisions,
        "integrated_steps": value.integrated_steps,
        "browser_operations": value.browser_operations,
        "network_operations": value.network_operations,
        "memory_operations": value.memory_operations,
        "workspace_operations": value.workspace_operations,
        "workspace_mutation_bytes": value.workspace_mutation_bytes,
        "host_operations": value.host_operations,
    }


def _decode_budget(value: object) -> IntegratedBudgetUsage:
    record = _mapping(value, label="budget_usage")
    _require_exact_fields(record, _BUDGET_FIELDS)
    return IntegratedBudgetUsage(
        plan_revisions=_integer(record["plan_revisions"], label="plan_revisions"),
        integrated_steps=_integer(
            record["integrated_steps"],
            label="integrated_steps",
        ),
        browser_operations=_integer(
            record["browser_operations"],
            label="browser_operations",
        ),
        network_operations=_integer(
            record["network_operations"],
            label="network_operations",
        ),
        memory_operations=_integer(
            record["memory_operations"],
            label="memory_operations",
        ),
        workspace_operations=_integer(
            record["workspace_operations"],
            label="workspace_operations",
        ),
        workspace_mutation_bytes=_integer(
            record["workspace_mutation_bytes"],
            label="workspace_mutation_bytes",
        ),
        host_operations=_integer(
            record["host_operations"],
            label="host_operations",
        ),
    )


def _canonical_json_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, OverflowError) as exception:
        _raise_codec_error(exception)


def _mapping(value: object, *, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise TaskResumeContextCodecError()
    if any(not isinstance(key, str) for key in value):
        raise TaskResumeContextCodecError()
    return cast(Mapping[str, object], value)


def _string(value: object, *, label: str) -> str:
    del label
    if not isinstance(value, str):
        raise TaskResumeContextCodecError()
    return value


def _integer(value: object, *, label: str) -> int:
    del label
    if isinstance(value, bool) or not isinstance(value, int):
        raise TaskResumeContextCodecError()
    return value


def _require_exact_fields(
    value: Mapping[str, object],
    fields: frozenset[str],
) -> None:
    if set(value) != fields:
        raise TaskResumeContextCodecError()


def _reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise TaskResumeContextCodecError()
        value[key] = item
    return value


def _measure_json(value: object, *, depth: int, counter: list[int]) -> None:
    if depth > MAX_TASK_RESUME_CONTEXT_JSON_DEPTH:
        raise TaskResumeContextCodecError()
    counter[0] += 1
    if counter[0] > MAX_TASK_RESUME_CONTEXT_JSON_ITEMS:
        raise TaskResumeContextCodecError()

    if isinstance(value, str):
        if len(value) > MAX_TASK_RESUME_CONTEXT_JSON_STRING_CHARS:
            raise TaskResumeContextCodecError()
        return
    if value is None or isinstance(value, (bool, int, float)):
        return
    if isinstance(value, list):
        for item in value:
            _measure_json(item, depth=depth + 1, counter=counter)
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str) or len(key) > MAX_TASK_RESUME_CONTEXT_JSON_KEY_CHARS:
                raise TaskResumeContextCodecError()
            _measure_json(item, depth=depth + 1, counter=counter)
        return
    raise TaskResumeContextCodecError()


def _raise_codec_error(exception: BaseException) -> NoReturn:
    raise TaskResumeContextCodecError() from exception
