from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from phoenix_os.agent.contracts import (
    AgentId,
    AgentMessage,
    AgentMessageRole,
    AgentRunId,
    AgentRunRequest,
)
from phoenix_os.control_plane.task_resume_context_resupply import (
    MAX_TASK_RESUME_CONTEXT_DOCUMENT_BYTES,
    TaskResumeContextCodecError,
    TaskResumeContextResupply,
    canonical_task_resume_context_resupply_bytes,
    decode_task_resume_context_resupply,
    encode_task_resume_context_resupply,
)
from phoenix_os.inference.contracts import ModelId, ModelProviderId
from phoenix_os.integrated_agent.contracts import (
    IntegratedBudgetUsage,
    IntegratedDataProvenance,
    IntegratedDataProvenanceAtom,
    IntegratedDataSourceKind,
    IntegratedTaskId,
    IntegratedTaskRequest,
    NormalizedPlan,
    PlanRevision,
)

_NOW = datetime(2026, 9, 9, 18, 0, tzinfo=UTC)
_TASK_ID = IntegratedTaskId(UUID("71000000-0000-4000-8000-000000000001"))
_RUN_ID = AgentRunId(UUID("72000000-0000-4000-8000-000000000001"))


def _resupply(*, with_plan: bool = True) -> TaskResumeContextResupply:
    task = IntegratedTaskRequest(
        task_id=_TASK_ID,
        objective="continue the exact durable model turn",
    )
    request = AgentRunRequest(
        agent_id=AgentId("resume-agent"),
        provider_id=ModelProviderId("ollama-local"),
        model_id=ModelId("development"),
        messages=(
            AgentMessage(
                AgentMessageRole.USER,
                "continue the exact durable model turn",
            ),
        ),
        run_id=_RUN_ID,
        created_at=_NOW,
        deadline=_NOW + timedelta(minutes=5),
    )
    provenance = IntegratedDataProvenance(
        (
            IntegratedDataProvenanceAtom(
                source_kind=IntegratedDataSourceKind.USER_TASK,
                source_binding=f"integrated-task:{task.task_id}",
                freshness_bindings=(f"task-digest:{task.digest}",),
            ),
        )
    )
    plan = (
        NormalizedPlan.create(
            task_id=task.task_id,
            revision=PlanRevision(1),
            statements=("continue the restored model turn",),
            provenance=provenance,
        )
        if with_plan
        else None
    )
    return TaskResumeContextResupply(
        task=task,
        request=request,
        provenance=provenance,
        budget_usage=IntegratedBudgetUsage(
            plan_revisions=1,
            integrated_steps=2,
            browser_operations=3,
            network_operations=4,
            memory_operations=5,
            workspace_operations=6,
            workspace_mutation_bytes=7,
            host_operations=8,
        ),
        plan=plan,
    )


@pytest.mark.parametrize("with_plan", [False, True])
def test_resume_context_resupply_round_trips_canonically(
    with_plan: bool,
) -> None:
    value = _resupply(with_plan=with_plan)

    encoded = encode_task_resume_context_resupply(value)
    decoded = decode_task_resume_context_resupply(encoded)

    assert decoded == value
    assert canonical_task_resume_context_resupply_bytes(decoded) == encoded
    assert len(encoded) <= MAX_TASK_RESUME_CONTEXT_DOCUMENT_BYTES


def test_resume_context_resupply_preserves_all_budget_counters() -> None:
    decoded = decode_task_resume_context_resupply(encode_task_resume_context_resupply(_resupply()))

    assert decoded.budget_usage == IntegratedBudgetUsage(
        plan_revisions=1,
        integrated_steps=2,
        browser_operations=3,
        network_operations=4,
        memory_operations=5,
        workspace_operations=6,
        workspace_mutation_bytes=7,
        host_operations=8,
    )


def test_resume_context_resupply_rejects_noncanonical_json() -> None:
    encoded = encode_task_resume_context_resupply(_resupply())
    document = json.loads(encoded.decode("utf-8"))
    noncanonical = json.dumps(document, indent=2).encode("utf-8")

    with pytest.raises(TaskResumeContextCodecError):
        decode_task_resume_context_resupply(noncanonical)


def test_resume_context_resupply_rejects_duplicate_keys() -> None:
    encoded = (
        b'{"kind":"phoenix.rfc0039.task-resume-context-resupply",'
        b'"kind":"phoenix.rfc0039.task-resume-context-resupply",'
        b'"record":{},"schema_version":1}'
    )

    with pytest.raises(TaskResumeContextCodecError):
        decode_task_resume_context_resupply(encoded)


def test_resume_context_resupply_rejects_unknown_fields() -> None:
    encoded = encode_task_resume_context_resupply(_resupply())
    document = json.loads(encoded.decode("utf-8"))
    document["unexpected"] = True
    mutated = json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    with pytest.raises(TaskResumeContextCodecError):
        decode_task_resume_context_resupply(mutated)


def test_resume_context_resupply_rejects_wrong_nested_document_kind() -> None:
    encoded = encode_task_resume_context_resupply(_resupply())
    document = json.loads(encoded.decode("utf-8"))
    document["record"]["task"]["kind"] = "phoenix.integrated-agent.provenance"
    mutated = json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    with pytest.raises(TaskResumeContextCodecError):
        decode_task_resume_context_resupply(mutated)


def test_resume_context_resupply_rejects_document_overflow() -> None:
    encoded = b"x" * (MAX_TASK_RESUME_CONTEXT_DOCUMENT_BYTES + 1)

    with pytest.raises(TaskResumeContextCodecError):
        decode_task_resume_context_resupply(encoded)


def test_resume_context_resupply_rejects_cross_task_plan() -> None:
    value = _resupply(with_plan=False)
    other_task_id = IntegratedTaskId(UUID("71000000-0000-4000-8000-000000000002"))
    other_plan = NormalizedPlan.create(
        task_id=other_task_id,
        revision=PlanRevision(1),
        statements=("wrong task",),
        provenance=value.provenance,
    )

    with pytest.raises(ValueError, match="plan task id"):
        TaskResumeContextResupply(
            task=value.task,
            request=value.request,
            provenance=value.provenance,
            budget_usage=value.budget_usage,
            plan=other_plan,
        )
