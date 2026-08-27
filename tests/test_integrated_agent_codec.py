import json
from uuid import UUID

import pytest

from phoenix_os.integrated_agent import (
    IntegratedAgentCodecError,
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
    PlanProposal,
    PlanRevision,
    decode_integrated_data_flow_policy,
    decode_integrated_data_provenance,
    decode_integrated_result_audience,
    decode_integrated_task_request,
    decode_normalized_plan,
    decode_plan_proposal,
    encode_integrated_data_flow_policy,
    encode_integrated_data_provenance,
    encode_integrated_result_audience,
    encode_integrated_task_request,
    encode_normalized_plan,
    encode_plan_proposal,
)


def _task() -> IntegratedTaskRequest:
    return IntegratedTaskRequest(
        task_id=IntegratedTaskId(UUID(int=11)),
        objective="Research reviewed suppliers and prepare a bounded report.",
        input_references=(
            IntegratedTaskInputReference(
                source_kind=IntegratedDataSourceKind.WORKSPACE,
                source_binding="workspace:team/parts",
                freshness_bindings=("version:5",),
            ),
        ),
    )


def _provenance() -> IntegratedDataProvenance:
    return IntegratedDataProvenance(
        (
            IntegratedDataProvenanceAtom(
                source_kind=IntegratedDataSourceKind.USER_TASK,
                source_binding="task:00000000-0000-0000-0000-00000000000b",
                freshness_bindings=("digest:sha256/" + "b" * 64,),
            ),
            IntegratedDataProvenanceAtom(
                source_kind=IntegratedDataSourceKind.BROWSER,
                source_binding="browser:profile/page-1",
                freshness_bindings=("generation:4", "revision:3"),
            ),
        )
    )


def test_task_plan_provenance_and_audience_codecs_round_trip_deterministically() -> None:
    task = _task()
    task_encoded = encode_integrated_task_request(task)
    assert decode_integrated_task_request(task_encoded) == task
    assert (
        encode_integrated_task_request(decode_integrated_task_request(task_encoded)) == task_encoded
    )

    proposal = PlanProposal(("research", "compare", "report"))
    proposal_encoded = encode_plan_proposal(proposal)
    assert decode_plan_proposal(proposal_encoded) == proposal

    provenance = _provenance()
    provenance_encoded = encode_integrated_data_provenance(provenance)
    assert decode_integrated_data_provenance(provenance_encoded) == provenance

    audience = IntegratedResultAudience("user@example.com", UUID(int=13))
    audience_encoded = encode_integrated_result_audience(audience)
    assert decode_integrated_result_audience(audience_encoded) == audience


def test_normalized_plan_codec_preserves_digest_revision_and_exact_provenance() -> None:
    plan = NormalizedPlan.create(
        task_id=IntegratedTaskId(UUID(int=12)),
        revision=PlanRevision(2),
        statements=("research", "report"),
        provenance=_provenance(),
    )
    encoded = encode_normalized_plan(plan)
    decoded = decode_normalized_plan(encoded)

    assert decoded == plan
    assert decoded.digest == plan.digest
    assert decoded.provenance == plan.provenance


def test_data_flow_policy_codec_preserves_fail_closed_route_vocabulary() -> None:
    policy = IntegratedDataFlowPolicy(
        (
            IntegratedDataFlowRoute(
                route_id="memory-network",
                source_kind=IntegratedDataSourceKind.MEMORY,
                sink=IntegratedDataSink.NETWORK,
                disposition=IntegratedDataFlowDisposition.DENY,
            ),
            IntegratedDataFlowRoute(
                route_id="workspace-result",
                source_kind=IntegratedDataSourceKind.WORKSPACE,
                sink=IntegratedDataSink.USER_RESULT,
                disposition=IntegratedDataFlowDisposition.ALLOW,
                requires_audience_match=True,
            ),
        )
    )
    encoded = encode_integrated_data_flow_policy(policy)
    assert decode_integrated_data_flow_policy(encoded) == policy


def test_codecs_reject_noncanonical_json_unknown_fields_wrong_kind_and_duplicate_keys() -> None:
    encoded = encode_integrated_task_request(_task())
    decoded = json.loads(encoded.decode("utf-8"))

    pretty = json.dumps(decoded, ensure_ascii=False, indent=2).encode("utf-8")
    with pytest.raises(IntegratedAgentCodecError, match="canonical"):
        decode_integrated_task_request(pretty)

    with_unknown = json.loads(encoded.decode("utf-8"))
    with_unknown["record"]["authority"] = "forbidden"
    bad = json.dumps(
        with_unknown,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    with pytest.raises(IntegratedAgentCodecError, match="fields"):
        decode_integrated_task_request(bad)

    wrong_kind = encoded.replace(
        b"phoenix.integrated-agent.task-request",
        b"phoenix.integrated-agent.plan-proposal",
    )
    with pytest.raises(IntegratedAgentCodecError, match="kind"):
        decode_integrated_task_request(wrong_kind)

    duplicate = (
        b'{"kind":"phoenix.integrated-agent.plan-proposal",'
        b'"record":{"statements":["one"]},'
        b'"schema_version":1,"schema_version":1}'
    )
    with pytest.raises(IntegratedAgentCodecError, match="duplicate"):
        decode_plan_proposal(duplicate)


def test_task_codec_rejects_noncanonical_uuid_and_contract_escape_hatches() -> None:
    encoded = encode_integrated_task_request(_task())
    document = json.loads(encoded.decode("utf-8"))
    document["record"]["task_id"] = "{00000000-0000-0000-0000-00000000000b}"
    malformed = json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    with pytest.raises(IntegratedAgentCodecError, match="canonical"):
        decode_integrated_task_request(malformed)

    document = json.loads(encoded.decode("utf-8"))
    document["record"]["input_references"][0]["source_binding"] = "https://example.com"
    malformed = json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    with pytest.raises(IntegratedAgentCodecError):
        decode_integrated_task_request(malformed)
