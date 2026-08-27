from dataclasses import FrozenInstanceError, fields
from datetime import timedelta
from uuid import UUID

import pytest

from phoenix_os.integrated_agent import (
    MAX_INTEGRATED_PROVENANCE_ATOMS,
    IntegratedBudgetExtension,
    IntegratedBudgetUsage,
    IntegratedDataFlowDecision,
    IntegratedDataFlowDisposition,
    IntegratedDataFlowPolicy,
    IntegratedDataFlowRoute,
    IntegratedDataProvenance,
    IntegratedDataProvenanceAtom,
    IntegratedDataSink,
    IntegratedDataSourceKind,
    IntegratedEffectDisposition,
    IntegratedFailureClass,
    IntegratedOrchestrationPhase,
    IntegratedResultAudience,
    IntegratedTaskId,
    IntegratedTaskInputReference,
    IntegratedTaskRequest,
    NormalizedPlan,
    PlanProposal,
    PlanRevision,
)


def test_task_request_is_immutable_bounded_and_digest_is_exact_and_deterministic() -> None:
    task_id = IntegratedTaskId(UUID(int=1))
    reference = IntegratedTaskInputReference(
        source_kind=IntegratedDataSourceKind.WORKSPACE,
        source_binding="workspace:team/report",
        freshness_bindings=("version:7",),
    )
    request = IntegratedTaskRequest(
        task_id=task_id,
        objective="Compare the reviewed supplier data and prepare a report.",
        input_references=(reference,),
    )
    same = IntegratedTaskRequest(
        task_id=task_id,
        objective="Compare the reviewed supplier data and prepare a report.",
        input_references=(reference,),
    )

    assert request.digest == same.digest
    assert str(request.digest).startswith("sha256:")
    assert len(str(request.digest)) == 71
    assert request.objective not in repr(request)
    with pytest.raises(FrozenInstanceError):
        request.objective = "changed"  # type: ignore[misc]

    changed = IntegratedTaskRequest(
        task_id=task_id,
        objective="Prepare a different report.",
        input_references=(reference,),
    )
    assert changed.digest != request.digest

    changed_freshness = IntegratedTaskRequest(
        task_id=task_id,
        objective=request.objective,
        input_references=(
            IntegratedTaskInputReference(
                source_kind=IntegratedDataSourceKind.WORKSPACE,
                source_binding="workspace:team/report",
                freshness_bindings=("version:8",),
            ),
        ),
    )
    assert changed_freshness.digest != request.digest


def test_task_and_provenance_bindings_reject_url_path_and_noncanonical_escape_hatches() -> None:
    for binding in (
        "https://example.com/data",
        "/etc/passwd",
        r"C:\secret",
        "HasUppercase",
    ):
        with pytest.raises(ValueError):
            IntegratedTaskInputReference(
                source_kind=IntegratedDataSourceKind.WORKSPACE,
                source_binding=binding,
            )

    with pytest.raises(TypeError):
        IntegratedTaskId("not-a-uuid")  # type: ignore[arg-type]


def test_plan_contract_is_advisory_data_without_authority_or_execution_fields() -> None:
    proposal = PlanProposal(("research reviewed suppliers", "prepare report"))
    assert proposal.statements == ("research reviewed suppliers", "prepare report")

    names = {item.name for item in fields(PlanProposal)}
    for forbidden in (
        "authority",
        "approval",
        "credential",
        "profile",
        "resource",
        "callback",
        "executable",
        "workflow",
    ):
        assert forbidden not in names

    with pytest.raises(ValueError, match="at least one"):
        PlanProposal(())


def test_normalized_plan_digest_binds_task_revision_and_statements() -> None:
    task_id = IntegratedTaskId(UUID(int=2))
    provenance = IntegratedDataProvenance(
        (
            IntegratedDataProvenanceAtom(
                IntegratedDataSourceKind.USER_TASK,
                f"task:{task_id}",
                ("digest:sha256/" + "a" * 64,),
            ),
        )
    )
    plan = NormalizedPlan.create(
        task_id=task_id,
        revision=PlanRevision(1),
        statements=("research", "compare", "report"),
        provenance=provenance,
    )

    assert plan.revision == PlanRevision(1)
    assert str(plan.digest).startswith("sha256:")

    changed = NormalizedPlan.create(
        task_id=task_id,
        revision=PlanRevision(2),
        statements=plan.statements,
        provenance=provenance,
    )
    assert changed.digest != plan.digest


def test_provenance_is_exact_bounded_set_and_never_silently_truncates() -> None:
    atom = IntegratedDataProvenanceAtom(
        IntegratedDataSourceKind.MEMORY,
        "memory:private/record-1",
        ("generation:3", "scope:private"),
    )
    provenance = IntegratedDataProvenance((atom, atom))
    assert provenance.atoms == (atom,)

    atoms = tuple(
        IntegratedDataProvenanceAtom(
            IntegratedDataSourceKind.TOOL_RESULT,
            f"tool-result:attempt-{index}",
        )
        for index in range(MAX_INTEGRATED_PROVENANCE_ATOMS + 1)
    )
    with pytest.raises(ValueError, match="PROVENANCE_OVERFLOW"):
        IntegratedDataProvenance(atoms)

    with pytest.raises(ValueError, match="at least one"):
        IntegratedDataProvenance(())


def test_data_flow_decision_requires_exact_route_for_allow_but_default_deny_may_be_unrouted() -> (
    None
):
    denied = IntegratedDataFlowDecision(
        source_kind=IntegratedDataSourceKind.MEMORY,
        sink=IntegratedDataSink.NETWORK,
        disposition=IntegratedDataFlowDisposition.DENY,
    )
    assert denied.route_id is None

    allowed = IntegratedDataFlowDecision(
        source_kind=IntegratedDataSourceKind.BROWSER,
        sink=IntegratedDataSink.MODEL,
        disposition=IntegratedDataFlowDisposition.ALLOW,
        route_id="browser-model",
    )
    assert allowed.route_id == "browser-model"

    with pytest.raises(ValueError, match="exact route_id"):
        IntegratedDataFlowDecision(
            source_kind=IntegratedDataSourceKind.BROWSER,
            sink=IntegratedDataSink.MODEL,
            disposition=IntegratedDataFlowDisposition.ALLOW,
        )


def test_data_flow_policy_is_finite_default_deny_and_user_result_requires_audience_match() -> None:
    policy = IntegratedDataFlowPolicy(
        (
            IntegratedDataFlowRoute(
                route_id="browser-model",
                source_kind=IntegratedDataSourceKind.BROWSER,
                sink=IntegratedDataSink.MODEL,
                disposition=IntegratedDataFlowDisposition.ALLOW,
            ),
            IntegratedDataFlowRoute(
                route_id="memory-network",
                source_kind=IntegratedDataSourceKind.MEMORY,
                sink=IntegratedDataSink.NETWORK,
                disposition=IntegratedDataFlowDisposition.DENY,
            ),
            IntegratedDataFlowRoute(
                route_id="memory-result",
                source_kind=IntegratedDataSourceKind.MEMORY,
                sink=IntegratedDataSink.USER_RESULT,
                disposition=IntegratedDataFlowDisposition.ALLOW,
                requires_audience_match=True,
            ),
        )
    )

    assert policy.default_disposition is IntegratedDataFlowDisposition.DENY
    assert any(
        route.source_kind is IntegratedDataSourceKind.BROWSER
        and route.sink is IntegratedDataSink.MODEL
        and route.disposition is IntegratedDataFlowDisposition.ALLOW
        for route in policy.routes
    )

    scoped = IntegratedDataFlowPolicy(
        (
            IntegratedDataFlowRoute(
                route_id="memory-private-result",
                source_kind=IntegratedDataSourceKind.MEMORY,
                sink=IntegratedDataSink.USER_RESULT,
                disposition=IntegratedDataFlowDisposition.ALLOW,
                source_scope="memory:private",
                requires_audience_match=True,
            ),
            IntegratedDataFlowRoute(
                route_id="memory-team-result",
                source_kind=IntegratedDataSourceKind.MEMORY,
                sink=IntegratedDataSink.USER_RESULT,
                disposition=IntegratedDataFlowDisposition.ALLOW,
                source_scope="memory:team",
                requires_audience_match=True,
            ),
        )
    )
    assert len(scoped.routes) == 2

    with pytest.raises(ValueError, match="audience"):
        IntegratedDataFlowRoute(
            route_id="unsafe-result",
            source_kind=IntegratedDataSourceKind.MEMORY,
            sink=IntegratedDataSink.USER_RESULT,
            disposition=IntegratedDataFlowDisposition.ALLOW,
        )

    with pytest.raises(ValueError, match="duplicate"):
        IntegratedDataFlowPolicy(
            (
                IntegratedDataFlowRoute(
                    route_id="one",
                    source_kind=IntegratedDataSourceKind.MEMORY,
                    sink=IntegratedDataSink.MODEL,
                    disposition=IntegratedDataFlowDisposition.ALLOW,
                ),
                IntegratedDataFlowRoute(
                    route_id="two",
                    source_kind=IntegratedDataSourceKind.MEMORY,
                    sink=IntegratedDataSink.MODEL,
                    disposition=IntegratedDataFlowDisposition.DENY,
                ),
            )
        )


def test_result_audience_is_authenticated_identity_data_not_arbitrary_recipient_text() -> None:
    audience = IntegratedResultAudience("user@example.com", UUID(int=3))
    assert audience.principal == "user@example.com"
    assert audience.session_id == UUID(int=3)
    assert audience.principal not in repr(audience)

    with pytest.raises(ValueError):
        IntegratedResultAudience("   ")
    with pytest.raises(TypeError):
        IntegratedResultAudience("principal-1", "not-a-uuid")  # type: ignore[arg-type]


def test_integrated_budget_extension_is_separate_from_existing_agent_limits() -> None:
    budget = IntegratedBudgetExtension(
        total_duration=timedelta(minutes=5),
        max_plan_revisions=4,
        max_integrated_steps=12,
        max_browser_operations=5,
        max_network_operations=5,
        max_memory_operations=4,
        max_workspace_operations=4,
        max_workspace_mutation_bytes=1_000_000,
        max_host_operations=2,
    )
    usage = IntegratedBudgetUsage(workspace_mutation_bytes=100)

    assert budget.max_plan_revisions == 4
    assert usage.workspace_mutation_bytes == 100
    with pytest.raises(ValueError):
        IntegratedBudgetUsage(network_operations=-1)


def test_finite_effect_failure_and_phase_vocabularies_match_frozen_rfc_classes() -> None:
    assert {item.value for item in IntegratedEffectDisposition} == {
        "no_effect",
        "confirmed_effect",
        "indeterminate",
    }
    assert "provenance_overflow" in {item.value for item in IntegratedFailureClass}
    assert {item.value for item in IntegratedOrchestrationPhase} == {
        "created",
        "planning",
        "executing",
        "waiting",
        "terminal",
    }
