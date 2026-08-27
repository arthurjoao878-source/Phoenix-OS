"""Strict deterministic codecs for RFC-0036 integrated-agent data contracts."""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import NoReturn, cast
from uuid import UUID

from phoenix_os.integrated_agent.contracts import (
    IntegratedDataFlowDisposition,
    IntegratedDataFlowPolicy,
    IntegratedDataFlowRoute,
    IntegratedDataProvenance,
    IntegratedDataProvenanceAtom,
    IntegratedDataSink,
    IntegratedDataSourceKind,
    IntegratedResultAudience,
    IntegratedTaskId,
    IntegratedTaskInputReference,
    IntegratedTaskRequest,
    NormalizedPlan,
    PlanDigest,
    PlanProposal,
    PlanRevision,
)
from phoenix_os.integrated_agent.errors import IntegratedAgentCodecError

_SCHEMA_VERSION = 1
_TASK_REQUEST_KIND = "phoenix.integrated-agent.task-request"
_PLAN_PROPOSAL_KIND = "phoenix.integrated-agent.plan-proposal"
_NORMALIZED_PLAN_KIND = "phoenix.integrated-agent.normalized-plan"
_PROVENANCE_KIND = "phoenix.integrated-agent.provenance"
_RESULT_AUDIENCE_KIND = "phoenix.integrated-agent.result-audience"
_DATA_FLOW_POLICY_KIND = "phoenix.integrated-agent.data-flow-policy"

MAX_INTEGRATED_TASK_DOCUMENT_BYTES = 1_048_576
MAX_INTEGRATED_PLAN_DOCUMENT_BYTES = 1_048_576
MAX_INTEGRATED_PROVENANCE_DOCUMENT_BYTES = 262_144
MAX_INTEGRATED_POLICY_DOCUMENT_BYTES = 524_288
MAX_INTEGRATED_CODEC_JSON_DEPTH = 32
MAX_INTEGRATED_CODEC_JSON_ITEMS = 32_768
MAX_INTEGRATED_CODEC_STRING_CHARS = 262_144

_ENVELOPE_FIELDS = frozenset({"schema_version", "kind", "record"})
_TASK_FIELDS = frozenset({"task_id", "objective", "input_references"})
_REFERENCE_FIELDS = frozenset({"source_kind", "source_binding", "freshness_bindings"})
_PLAN_PROPOSAL_FIELDS = frozenset({"statements"})
_NORMALIZED_PLAN_FIELDS = frozenset({"task_id", "revision", "digest", "statements", "provenance"})
_PROVENANCE_FIELDS = frozenset({"atoms"})
_ATOM_FIELDS = frozenset({"source_kind", "source_binding", "freshness_bindings"})
_AUDIENCE_FIELDS = frozenset({"principal", "session_id"})
_POLICY_FIELDS = frozenset({"routes"})
_ROUTE_FIELDS = frozenset(
    {
        "route_id",
        "source_kind",
        "sink",
        "disposition",
        "source_scope",
        "required_freshness_bindings",
        "requires_audience_match",
    }
)


def _mapping(value: object, *, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise IntegratedAgentCodecError(f"{label} must be an object")
    if any(not isinstance(key, str) for key in value):
        raise IntegratedAgentCodecError(f"{label} keys must be strings")
    return cast(Mapping[str, object], value)


def _sequence(value: object, *, label: str) -> list[object]:
    if not isinstance(value, list):
        raise IntegratedAgentCodecError(f"{label} must be an array")
    return value


def _string(value: object, *, label: str) -> str:
    if not isinstance(value, str):
        raise IntegratedAgentCodecError(f"{label} must be a string")
    return value


def _int(value: object, *, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise IntegratedAgentCodecError(f"{label} must be an integer")
    return value


def _bool(value: object, *, label: str) -> bool:
    if not isinstance(value, bool):
        raise IntegratedAgentCodecError(f"{label} must be a boolean")
    return value


def _require_exact_fields(
    value: Mapping[str, object],
    *,
    fields: frozenset[str],
    label: str,
) -> None:
    unknown = set(value) - fields
    missing = fields - set(value)
    if unknown or missing:
        raise IntegratedAgentCodecError(f"{label} fields are invalid")


def _require_fields(
    value: Mapping[str, object],
    *,
    allowed: frozenset[str],
    required: frozenset[str],
    label: str,
) -> None:
    unknown = set(value) - allowed
    missing = required - set(value)
    if unknown or missing:
        raise IntegratedAgentCodecError(f"{label} fields are invalid")


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
        raise IntegratedAgentCodecError() from exception


def _reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise IntegratedAgentCodecError("integrated agent JSON contains duplicate keys")
        value[key] = item
    return value


def _measure_json(value: object, *, depth: int, counter: list[int]) -> None:
    if depth > MAX_INTEGRATED_CODEC_JSON_DEPTH:
        raise IntegratedAgentCodecError("integrated agent JSON exceeds maximum depth")
    counter[0] += 1
    if counter[0] > MAX_INTEGRATED_CODEC_JSON_ITEMS:
        raise IntegratedAgentCodecError("integrated agent JSON exceeds maximum item count")
    if isinstance(value, str):
        if len(value) > MAX_INTEGRATED_CODEC_STRING_CHARS:
            raise IntegratedAgentCodecError("integrated agent JSON string is too large")
        return
    if value is None or isinstance(value, (bool, int, float)):
        return
    if isinstance(value, list):
        for item in value:
            _measure_json(item, depth=depth + 1, counter=counter)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if len(key) > 256:
                raise IntegratedAgentCodecError("integrated agent JSON key is too large")
            _measure_json(item, depth=depth + 1, counter=counter)
        return
    raise IntegratedAgentCodecError("integrated agent JSON contains an unsupported value")


def _encode(kind: str, record: Mapping[str, object], maximum_bytes: int) -> bytes:
    encoded = _canonical_json_bytes(
        {
            "schema_version": _SCHEMA_VERSION,
            "kind": kind,
            "record": dict(record),
        }
    )
    if len(encoded) > maximum_bytes:
        raise IntegratedAgentCodecError("integrated agent document exceeds maximum size")
    return encoded


def _decode(
    encoded: bytes,
    *,
    expected_kind: str,
    maximum_bytes: int,
) -> Mapping[str, object]:
    if not isinstance(encoded, bytes):
        raise TypeError("encoded document must be bytes")
    if not encoded or len(encoded) > maximum_bytes:
        raise IntegratedAgentCodecError("integrated agent document size is invalid")
    try:
        text = encoded.decode("utf-8")
    except UnicodeDecodeError as exception:
        raise IntegratedAgentCodecError(
            "integrated agent document is not valid UTF-8"
        ) from exception
    try:
        decoded = json.loads(text, object_pairs_hook=_reject_duplicate_pairs)
    except IntegratedAgentCodecError:
        raise
    except (json.JSONDecodeError, ValueError, OverflowError) as exception:
        raise IntegratedAgentCodecError(
            "integrated agent document is not valid JSON"
        ) from exception
    _measure_json(decoded, depth=0, counter=[0])
    envelope = _mapping(decoded, label="integrated agent envelope")
    _require_exact_fields(envelope, fields=_ENVELOPE_FIELDS, label="integrated agent envelope")
    if _int(envelope["schema_version"], label="schema_version") != _SCHEMA_VERSION:
        raise IntegratedAgentCodecError("integrated agent schema version is unsupported")
    if _string(envelope["kind"], label="kind") != expected_kind:
        raise IntegratedAgentCodecError("integrated agent document kind is invalid")
    return _mapping(envelope["record"], label="integrated agent record")


def _uuid(value: object, *, label: str) -> UUID:
    raw = _string(value, label=label)
    try:
        parsed = UUID(raw)
    except ValueError as exception:
        raise IntegratedAgentCodecError(f"{label} is invalid") from exception
    if str(parsed) != raw:
        raise IntegratedAgentCodecError(f"{label} is not canonical")
    return parsed


def _raise_contract_error(exception: Exception) -> NoReturn:
    raise IntegratedAgentCodecError() from exception


def _reference_record(value: IntegratedTaskInputReference) -> dict[str, object]:
    return {
        "source_kind": value.source_kind.value,
        "source_binding": value.source_binding,
        "freshness_bindings": list(value.freshness_bindings),
    }


def _decode_reference(value: object) -> IntegratedTaskInputReference:
    record = _mapping(value, label="integrated task input reference")
    _require_exact_fields(
        record,
        fields=_REFERENCE_FIELDS,
        label="integrated task input reference",
    )
    return IntegratedTaskInputReference(
        source_kind=IntegratedDataSourceKind(_string(record["source_kind"], label="source_kind")),
        source_binding=_string(record["source_binding"], label="source_binding"),
        freshness_bindings=tuple(
            _string(item, label="freshness binding")
            for item in _sequence(record["freshness_bindings"], label="freshness_bindings")
        ),
    )


def _atom_record(value: IntegratedDataProvenanceAtom) -> dict[str, object]:
    return {
        "source_kind": value.source_kind.value,
        "source_binding": value.source_binding,
        "freshness_bindings": list(value.freshness_bindings),
    }


def _decode_atom(value: object) -> IntegratedDataProvenanceAtom:
    record = _mapping(value, label="integrated provenance atom")
    _require_exact_fields(record, fields=_ATOM_FIELDS, label="integrated provenance atom")
    return IntegratedDataProvenanceAtom(
        source_kind=IntegratedDataSourceKind(_string(record["source_kind"], label="source_kind")),
        source_binding=_string(record["source_binding"], label="source_binding"),
        freshness_bindings=tuple(
            _string(item, label="freshness binding")
            for item in _sequence(record["freshness_bindings"], label="freshness_bindings")
        ),
    )


def _provenance_record(value: IntegratedDataProvenance) -> dict[str, object]:
    return {"atoms": [_atom_record(item) for item in value.atoms]}


def _decode_provenance_record(value: object) -> IntegratedDataProvenance:
    record = _mapping(value, label="integrated provenance")
    _require_exact_fields(record, fields=_PROVENANCE_FIELDS, label="integrated provenance")
    return IntegratedDataProvenance(
        tuple(
            _decode_atom(item)
            for item in _sequence(record["atoms"], label="integrated provenance atoms")
        )
    )


def encode_integrated_task_request(value: IntegratedTaskRequest) -> bytes:
    if not isinstance(value, IntegratedTaskRequest):
        raise TypeError("value must be IntegratedTaskRequest")
    return _encode(
        _TASK_REQUEST_KIND,
        {
            "task_id": str(value.task_id),
            "objective": value.objective,
            "input_references": [_reference_record(item) for item in value.input_references],
        },
        MAX_INTEGRATED_TASK_DOCUMENT_BYTES,
    )


def decode_integrated_task_request(encoded: bytes) -> IntegratedTaskRequest:
    record = _decode(
        encoded,
        expected_kind=_TASK_REQUEST_KIND,
        maximum_bytes=MAX_INTEGRATED_TASK_DOCUMENT_BYTES,
    )
    try:
        _require_exact_fields(record, fields=_TASK_FIELDS, label="integrated task request")
        value = IntegratedTaskRequest(
            task_id=IntegratedTaskId(_uuid(record["task_id"], label="task_id")),
            objective=_string(record["objective"], label="objective"),
            input_references=tuple(
                _decode_reference(item)
                for item in _sequence(
                    record["input_references"],
                    label="integrated task input references",
                )
            ),
        )
    except IntegratedAgentCodecError:
        raise
    except (TypeError, ValueError, OverflowError) as exception:
        _raise_contract_error(exception)
    if encode_integrated_task_request(value) != encoded:
        raise IntegratedAgentCodecError("integrated task request is not canonical")
    return value


def encode_plan_proposal(value: PlanProposal) -> bytes:
    if not isinstance(value, PlanProposal):
        raise TypeError("value must be PlanProposal")
    return _encode(
        _PLAN_PROPOSAL_KIND,
        {"statements": list(value.statements)},
        MAX_INTEGRATED_PLAN_DOCUMENT_BYTES,
    )


def decode_plan_proposal(encoded: bytes) -> PlanProposal:
    record = _decode(
        encoded,
        expected_kind=_PLAN_PROPOSAL_KIND,
        maximum_bytes=MAX_INTEGRATED_PLAN_DOCUMENT_BYTES,
    )
    try:
        _require_exact_fields(record, fields=_PLAN_PROPOSAL_FIELDS, label="plan proposal")
        value = PlanProposal(
            tuple(
                _string(item, label="plan statement")
                for item in _sequence(record["statements"], label="plan statements")
            )
        )
    except IntegratedAgentCodecError:
        raise
    except (TypeError, ValueError, OverflowError) as exception:
        _raise_contract_error(exception)
    if encode_plan_proposal(value) != encoded:
        raise IntegratedAgentCodecError("plan proposal is not canonical")
    return value


def encode_integrated_data_provenance(value: IntegratedDataProvenance) -> bytes:
    if not isinstance(value, IntegratedDataProvenance):
        raise TypeError("value must be IntegratedDataProvenance")
    return _encode(
        _PROVENANCE_KIND,
        _provenance_record(value),
        MAX_INTEGRATED_PROVENANCE_DOCUMENT_BYTES,
    )


def decode_integrated_data_provenance(encoded: bytes) -> IntegratedDataProvenance:
    record = _decode(
        encoded,
        expected_kind=_PROVENANCE_KIND,
        maximum_bytes=MAX_INTEGRATED_PROVENANCE_DOCUMENT_BYTES,
    )
    try:
        value = _decode_provenance_record(record)
    except IntegratedAgentCodecError:
        raise
    except (TypeError, ValueError, OverflowError) as exception:
        _raise_contract_error(exception)
    if encode_integrated_data_provenance(value) != encoded:
        raise IntegratedAgentCodecError("integrated provenance document is not canonical")
    return value


def encode_normalized_plan(value: NormalizedPlan) -> bytes:
    if not isinstance(value, NormalizedPlan):
        raise TypeError("value must be NormalizedPlan")
    return _encode(
        _NORMALIZED_PLAN_KIND,
        {
            "task_id": str(value.task_id),
            "revision": value.revision.value,
            "digest": str(value.digest),
            "statements": list(value.statements),
            "provenance": _provenance_record(value.provenance),
        },
        MAX_INTEGRATED_PLAN_DOCUMENT_BYTES,
    )


def decode_normalized_plan(encoded: bytes) -> NormalizedPlan:
    record = _decode(
        encoded,
        expected_kind=_NORMALIZED_PLAN_KIND,
        maximum_bytes=MAX_INTEGRATED_PLAN_DOCUMENT_BYTES,
    )
    try:
        _require_exact_fields(
            record,
            fields=_NORMALIZED_PLAN_FIELDS,
            label="normalized plan",
        )
        value = NormalizedPlan(
            task_id=IntegratedTaskId(_uuid(record["task_id"], label="task_id")),
            revision=PlanRevision(_int(record["revision"], label="revision")),
            digest=PlanDigest(_string(record["digest"], label="digest")),
            statements=tuple(
                _string(item, label="plan statement")
                for item in _sequence(record["statements"], label="plan statements")
            ),
            provenance=_decode_provenance_record(record["provenance"]),
        )
    except IntegratedAgentCodecError:
        raise
    except (TypeError, ValueError, OverflowError) as exception:
        _raise_contract_error(exception)
    if encode_normalized_plan(value) != encoded:
        raise IntegratedAgentCodecError("normalized plan is not canonical")
    return value


def encode_integrated_result_audience(value: IntegratedResultAudience) -> bytes:
    if not isinstance(value, IntegratedResultAudience):
        raise TypeError("value must be IntegratedResultAudience")
    return _encode(
        _RESULT_AUDIENCE_KIND,
        {
            "principal": value.principal,
            "session_id": None if value.session_id is None else str(value.session_id),
        },
        MAX_INTEGRATED_PROVENANCE_DOCUMENT_BYTES,
    )


def decode_integrated_result_audience(encoded: bytes) -> IntegratedResultAudience:
    record = _decode(
        encoded,
        expected_kind=_RESULT_AUDIENCE_KIND,
        maximum_bytes=MAX_INTEGRATED_PROVENANCE_DOCUMENT_BYTES,
    )
    try:
        _require_exact_fields(record, fields=_AUDIENCE_FIELDS, label="result audience")
        raw_session = record["session_id"]
        session_id: UUID | None = (
            None if raw_session is None else _uuid(raw_session, label="session_id")
        )
        value = IntegratedResultAudience(
            principal=_string(record["principal"], label="principal"),
            session_id=session_id,
        )
    except IntegratedAgentCodecError:
        raise
    except (TypeError, ValueError, OverflowError) as exception:
        _raise_contract_error(exception)
    if encode_integrated_result_audience(value) != encoded:
        raise IntegratedAgentCodecError("result audience is not canonical")
    return value


def _route_record(value: IntegratedDataFlowRoute) -> dict[str, object]:
    return {
        "route_id": value.route_id,
        "source_kind": value.source_kind.value,
        "sink": value.sink.value,
        "disposition": value.disposition.value,
        "source_scope": value.source_scope,
        "required_freshness_bindings": list(value.required_freshness_bindings),
        "requires_audience_match": value.requires_audience_match,
    }


def encode_integrated_data_flow_policy(value: IntegratedDataFlowPolicy) -> bytes:
    if not isinstance(value, IntegratedDataFlowPolicy):
        raise TypeError("value must be IntegratedDataFlowPolicy")
    return _encode(
        _DATA_FLOW_POLICY_KIND,
        {"routes": [_route_record(item) for item in value.routes]},
        MAX_INTEGRATED_POLICY_DOCUMENT_BYTES,
    )


def decode_integrated_data_flow_policy(encoded: bytes) -> IntegratedDataFlowPolicy:
    record = _decode(
        encoded,
        expected_kind=_DATA_FLOW_POLICY_KIND,
        maximum_bytes=MAX_INTEGRATED_POLICY_DOCUMENT_BYTES,
    )
    try:
        _require_exact_fields(record, fields=_POLICY_FIELDS, label="data-flow policy")
        routes: list[IntegratedDataFlowRoute] = []
        for item in _sequence(record["routes"], label="data-flow routes"):
            route = _mapping(item, label="data-flow route")
            _require_exact_fields(route, fields=_ROUTE_FIELDS, label="data-flow route")
            routes.append(
                IntegratedDataFlowRoute(
                    route_id=_string(route["route_id"], label="route_id"),
                    source_kind=IntegratedDataSourceKind(
                        _string(route["source_kind"], label="source_kind")
                    ),
                    sink=IntegratedDataSink(_string(route["sink"], label="sink")),
                    disposition=IntegratedDataFlowDisposition(
                        _string(route["disposition"], label="disposition")
                    ),
                    source_scope=(
                        None
                        if route["source_scope"] is None
                        else _string(route["source_scope"], label="source_scope")
                    ),
                    required_freshness_bindings=tuple(
                        _string(item, label="required freshness binding")
                        for item in _sequence(
                            route["required_freshness_bindings"],
                            label="required_freshness_bindings",
                        )
                    ),
                    requires_audience_match=_bool(
                        route["requires_audience_match"],
                        label="requires_audience_match",
                    ),
                )
            )
        value = IntegratedDataFlowPolicy(tuple(routes))
    except IntegratedAgentCodecError:
        raise
    except (TypeError, ValueError, OverflowError) as exception:
        _raise_contract_error(exception)
    if encode_integrated_data_flow_policy(value) != encoded:
        raise IntegratedAgentCodecError("data-flow policy is not canonical")
    return value
