from uuid import UUID

import pytest

from phoenix_os.integrated_agent import (
    MAX_INTEGRATED_PROVENANCE_ATOMS,
    IntegratedAgentDataFlowDeniedError,
    IntegratedAgentProvenanceOverflowError,
    IntegratedDataFlowDisposition,
    IntegratedDataFlowGuard,
    IntegratedDataFlowPolicy,
    IntegratedDataFlowRoute,
    IntegratedDataProvenance,
    IntegratedDataProvenanceAtom,
    IntegratedDataSink,
    IntegratedDataSourceKind,
    integrated_provenance_union,
    integrated_result_audience,
)
from phoenix_os.policy import PrincipalType, SecurityContext


def _memory_atom(
    binding: str = "memory:private/record-1",
) -> IntegratedDataProvenanceAtom:
    return IntegratedDataProvenanceAtom(
        IntegratedDataSourceKind.MEMORY,
        binding,
        ("generation:3", "scope:private"),
    )


def test_guard_allows_one_exact_scope_and_freshness_route() -> None:
    guard = IntegratedDataFlowGuard(
        IntegratedDataFlowPolicy(
            (
                IntegratedDataFlowRoute(
                    route_id="memory-model",
                    source_kind=IntegratedDataSourceKind.MEMORY,
                    sink=IntegratedDataSink.MODEL,
                    disposition=IntegratedDataFlowDisposition.ALLOW,
                    source_scope="memory:private",
                    required_freshness_bindings=("generation:3",),
                ),
            )
        )
    )

    decisions = guard.admit(
        IntegratedDataProvenance((_memory_atom(),)),
        IntegratedDataSink.MODEL,
    )

    assert len(decisions) == 1
    assert decisions[0].route_id == "memory-model"
    assert decisions[0].disposition is IntegratedDataFlowDisposition.ALLOW


def test_guard_default_deny_and_explicit_deny_fail_closed() -> None:
    provenance = IntegratedDataProvenance((_memory_atom(),))
    default_guard = IntegratedDataFlowGuard(IntegratedDataFlowPolicy())

    with pytest.raises(IntegratedAgentDataFlowDeniedError):
        default_guard.admit(provenance, IntegratedDataSink.NETWORK)

    explicit_guard = IntegratedDataFlowGuard(
        IntegratedDataFlowPolicy(
            (
                IntegratedDataFlowRoute(
                    route_id="memory-network-deny",
                    source_kind=IntegratedDataSourceKind.MEMORY,
                    sink=IntegratedDataSink.NETWORK,
                    disposition=IntegratedDataFlowDisposition.DENY,
                    source_scope="memory:private",
                ),
            )
        )
    )
    decision = explicit_guard.decide(provenance, IntegratedDataSink.NETWORK)[0]
    assert decision.route_id == "memory-network-deny"
    assert decision.disposition is IntegratedDataFlowDisposition.DENY
    with pytest.raises(IntegratedAgentDataFlowDeniedError):
        explicit_guard.admit(provenance, IntegratedDataSink.NETWORK)


def test_guard_rejects_ambiguous_overlapping_routes_instead_of_choosing_one() -> None:
    guard = IntegratedDataFlowGuard(
        IntegratedDataFlowPolicy(
            (
                IntegratedDataFlowRoute(
                    route_id="memory-parent",
                    source_kind=IntegratedDataSourceKind.MEMORY,
                    sink=IntegratedDataSink.MODEL,
                    disposition=IntegratedDataFlowDisposition.ALLOW,
                    source_scope="memory:private",
                ),
                IntegratedDataFlowRoute(
                    route_id="memory-record",
                    source_kind=IntegratedDataSourceKind.MEMORY,
                    sink=IntegratedDataSink.MODEL,
                    disposition=IntegratedDataFlowDisposition.ALLOW,
                    source_scope="memory:private/record-1",
                ),
            )
        )
    )

    decisions = guard.decide(
        IntegratedDataProvenance((_memory_atom(),)),
        IntegratedDataSink.MODEL,
    )

    assert decisions[0].disposition is IntegratedDataFlowDisposition.DENY
    assert decisions[0].route_id is None
    with pytest.raises(IntegratedAgentDataFlowDeniedError):
        guard.admit(
            IntegratedDataProvenance((_memory_atom(),)),
            IntegratedDataSink.MODEL,
        )


def test_user_result_audience_is_derived_only_from_authenticated_context() -> None:
    guard = IntegratedDataFlowGuard(
        IntegratedDataFlowPolicy(
            (
                IntegratedDataFlowRoute(
                    route_id="memory-result",
                    source_kind=IntegratedDataSourceKind.MEMORY,
                    sink=IntegratedDataSink.USER_RESULT,
                    disposition=IntegratedDataFlowDisposition.ALLOW,
                    source_scope="memory:private",
                    requires_audience_match=True,
                ),
            )
        )
    )
    provenance = IntegratedDataProvenance((_memory_atom(),))
    unauthenticated = SecurityContext()
    authenticated = SecurityContext(
        principal="alice",
        principal_type=PrincipalType.USER,
        authenticated=True,
        session_id=UUID(int=7),
    )

    with pytest.raises(IntegratedAgentDataFlowDeniedError):
        guard.admit(
            provenance,
            IntegratedDataSink.USER_RESULT,
            context=unauthenticated,
        )

    decisions = guard.admit(
        provenance,
        IntegratedDataSink.USER_RESULT,
        context=authenticated,
    )
    audience = integrated_result_audience(authenticated)

    assert decisions[0].route_id == "memory-result"
    assert audience.principal == "alice"
    assert audience.session_id == UUID(int=7)


def test_provenance_union_is_conservative_and_overflow_never_truncates() -> None:
    memory = IntegratedDataProvenance((_memory_atom(),))
    model_atom = IntegratedDataProvenanceAtom(
        IntegratedDataSourceKind.MODEL_OUTPUT,
        "agent-run:run-1/step-1",
    )

    combined = integrated_provenance_union(memory, derived_atom=model_atom)

    assert _memory_atom() in combined.atoms
    assert model_atom in combined.atoms

    maximum = IntegratedDataProvenance(
        tuple(
            IntegratedDataProvenanceAtom(
                IntegratedDataSourceKind.TOOL_RESULT,
                f"tool-result:attempt-{index}",
            )
            for index in range(MAX_INTEGRATED_PROVENANCE_ATOMS)
        )
    )
    with pytest.raises(IntegratedAgentProvenanceOverflowError):
        integrated_provenance_union(
            maximum,
            derived_atom=IntegratedDataProvenanceAtom(
                IntegratedDataSourceKind.MODEL_OUTPUT,
                "agent-run:overflow/step-1",
            ),
        )


def test_persisted_integrated_provenance_round_trips_exactly() -> None:
    from phoenix_os.integrated_agent.data_flow import (
        integrated_provenance_from_persistence_attributes,
        integrated_provenance_to_persistence_attributes,
    )

    provenance = IntegratedDataProvenance(
        (
            IntegratedDataProvenanceAtom(
                IntegratedDataSourceKind.MEMORY,
                (
                    "agent-memory:research/scope:agent:assistant/"
                    "record:00000000-0000-0000-0000-000000000001"
                ),
                (
                    "content-digest:sha256:" + "a" * 64,
                    "version:7",
                ),
            ),
            IntegratedDataProvenanceAtom(
                IntegratedDataSourceKind.MODEL_OUTPUT,
                (
                    "agent-run:00000000-0000-0000-0000-000000000002/"
                    "step:00000000-0000-0000-0000-000000000003"
                ),
            ),
        )
    )

    attributes = integrated_provenance_to_persistence_attributes(provenance)
    restored = integrated_provenance_from_persistence_attributes(attributes)

    assert restored == provenance
    assert 1 <= len(attributes) <= 31
    assert all(len(value) <= 1_024 for value in attributes.values())


def test_persisted_integrated_provenance_overflow_never_truncates() -> None:
    from phoenix_os.integrated_agent.data_flow import (
        integrated_provenance_to_persistence_attributes,
    )

    provenance = IntegratedDataProvenance(
        tuple(
            IntegratedDataProvenanceAtom(
                IntegratedDataSourceKind.WORKSPACE,
                f"workspace:record-{index}/" + ("a" * 900),
                (f"version:{index + 1}",),
            )
            for index in range(40)
        )
    )

    with pytest.raises(IntegratedAgentProvenanceOverflowError):
        integrated_provenance_to_persistence_attributes(provenance)
