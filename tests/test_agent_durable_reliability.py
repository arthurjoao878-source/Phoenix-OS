from __future__ import annotations

from dataclasses import fields
from datetime import UTC, datetime, timedelta
from inspect import signature
from typing import cast

import pytest

from phoenix_os.agent.composition import AgentRuntimeStack, create_agent_runtime_stack
from phoenix_os.agent.durable_reliability import (
    NOOP_RELIABILITY_FAULT_INJECTOR,
    DurableMutationOutcome,
    ReliabilityFaultInjector,
    ReliabilityFaultPoint,
)
from phoenix_os.agent.durable_reliability_fake import (
    DeterministicReliabilityFaultInjector,
    DeterministicReliabilityInterleaving,
    DeterministicUtcClock,
    InjectedReliabilityFault,
    ReliabilityFaultPlanExhausted,
    ReliabilityFaultTrigger,
    ReliabilityInterleavingStep,
    UnexpectedReliabilityInterleaving,
)

_EXPECTED_FAULT_POINTS = (
    "checkpoint.before_encode",
    "checkpoint.after_encode",
    "checkpoint.before_store_mutation",
    "checkpoint.after_store_commit_before_ack",
    "checkpoint.after_ack",
    "lease.before_acquire",
    "lease.after_acquire",
    "lease.before_renew",
    "lease.after_renew",
    "recovery.after_candidate_read",
    "recovery.after_lease_acquire",
    "recovery.after_reread",
    "recovery.after_live_revalidation",
    "recovery.before_transition",
    "recovery.after_transition_commit",
    "attempt.after_prepared",
    "attempt.after_started",
    "attempt.after_external_return_before_terminal_record",
    "reconcile.before_mutation",
    "reconcile.after_mutation_commit",
    "retention.before_delete",
    "retention.after_delete_commit",
    "shutdown.after_admission_stop",
)


def test_rfc0037_mutation_outcomes_are_exact_internal_classifications() -> None:
    assert tuple(outcome.value for outcome in DurableMutationOutcome) == (
        "CONFIRMED_COMMITTED",
        "CONFIRMED_NOT_COMMITTED",
        "COMMIT_OUTCOME_UNKNOWN",
    )


def test_rfc0037_fault_point_identifiers_are_exact_and_phoenix_owned() -> None:
    assert tuple(point.value for point in ReliabilityFaultPoint) == _EXPECTED_FAULT_POINTS


def test_noop_fault_injector_is_structural_and_rejects_arbitrary_content() -> None:
    assert isinstance(NOOP_RELIABILITY_FAULT_INJECTOR, ReliabilityFaultInjector)
    NOOP_RELIABILITY_FAULT_INJECTOR.inject(ReliabilityFaultPoint.CHECKPOINT_BEFORE_ENCODE)

    with pytest.raises(TypeError, match="point must be ReliabilityFaultPoint"):
        NOOP_RELIABILITY_FAULT_INJECTOR.inject(
            cast(ReliabilityFaultPoint, "checkpoint.before_encode")
        )


def test_deterministic_injector_fires_only_at_configured_occurrence() -> None:
    point = ReliabilityFaultPoint.ATTEMPT_AFTER_STARTED
    injector = DeterministicReliabilityFaultInjector(
        (ReliabilityFaultTrigger(point=point, occurrence=2),),
        max_total_hits=4,
    )

    injector.inject(point)
    with pytest.raises(InjectedReliabilityFault) as raised:
        injector.inject(point)
    injector.inject(point)

    assert raised.value.point is point
    assert raised.value.occurrence == 2
    assert injector.pending_trigger_count == 0
    assert tuple(
        (observation.point, observation.occurrence, observation.injected)
        for observation in injector.observations
    ) == (
        (point, 1, False),
        (point, 2, True),
        (point, 3, False),
    )


@pytest.mark.parametrize("point", tuple(ReliabilityFaultPoint))
def test_every_baseline_fault_point_can_trigger_deterministically(
    point: ReliabilityFaultPoint,
) -> None:
    injector = DeterministicReliabilityFaultInjector((ReliabilityFaultTrigger(point),))

    with pytest.raises(InjectedReliabilityFault) as raised:
        injector.inject(point)

    assert raised.value.point is point
    assert raised.value.occurrence == 1


def test_deterministic_injector_is_finite_and_bounded() -> None:
    point = ReliabilityFaultPoint.RECOVERY_AFTER_REREAD
    injector = DeterministicReliabilityFaultInjector(max_total_hits=2)

    injector.inject(point)
    injector.inject(point)

    with pytest.raises(
        ReliabilityFaultPlanExhausted,
        match="deterministic reliability fault-hit bound exhausted",
    ):
        injector.inject(point)


def test_fault_plan_rejects_duplicates_and_unreachable_occurrences() -> None:
    point = ReliabilityFaultPoint.LEASE_AFTER_ACQUIRE
    trigger = ReliabilityFaultTrigger(point)

    with pytest.raises(ValueError, match="duplicate triggers"):
        DeterministicReliabilityFaultInjector((trigger, trigger))

    with pytest.raises(ValueError, match="exceeds max_total_hits"):
        DeterministicReliabilityFaultInjector(
            (ReliabilityFaultTrigger(point, occurrence=3),),
            max_total_hits=2,
        )


def test_fault_injector_surface_accepts_no_arbitrary_payload() -> None:
    parameters = tuple(signature(DeterministicReliabilityFaultInjector.inject).parameters)
    assert parameters == ("self", "point")


def test_deterministic_utc_clock_advances_manually_and_never_backward() -> None:
    start = datetime(2026, 8, 29, 12, 0, tzinfo=UTC)
    clock = DeterministicUtcClock(start)

    assert clock() == start
    assert clock.advance(timedelta(seconds=5)) == start + timedelta(seconds=5)
    assert clock.current == start + timedelta(seconds=5)

    with pytest.raises(ValueError, match="cannot move backward"):
        clock.advance(timedelta(microseconds=-1))


def test_deterministic_utc_clock_rejects_naive_time() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        DeterministicUtcClock(datetime(2026, 8, 29, 12, 0))


def test_deterministic_interleaving_requires_exact_finite_sequence() -> None:
    first = ReliabilityInterleavingStep(
        actor="recoverer-a",
        point=ReliabilityFaultPoint.RECOVERY_AFTER_CANDIDATE_READ,
    )
    second = ReliabilityInterleavingStep(
        actor="recoverer-b",
        point=ReliabilityFaultPoint.RECOVERY_AFTER_LEASE_ACQUIRE,
    )
    interleaving = DeterministicReliabilityInterleaving((first, second))

    assert not interleaving.complete
    assert list(interleaving.remaining) == [first, second]

    interleaving.arrive(first.actor, first.point)
    assert list(interleaving.remaining) == [second]

    interleaving.arrive(second.actor, second.point)
    assert interleaving.complete
    assert list(interleaving.remaining) == []


def test_deterministic_interleaving_fails_closed_on_wrong_or_extra_step() -> None:
    step = ReliabilityInterleavingStep(
        actor="recoverer-a",
        point=ReliabilityFaultPoint.RECOVERY_AFTER_REREAD,
    )
    interleaving = DeterministicReliabilityInterleaving((step,))

    with pytest.raises(UnexpectedReliabilityInterleaving, match="diverged"):
        interleaving.arrive("recoverer-b", step.point)

    interleaving.arrive(step.actor, step.point)

    with pytest.raises(UnexpectedReliabilityInterleaving, match="extra step"):
        interleaving.arrive(step.actor, step.point)


def test_fault_injector_is_absent_from_ordinary_production_composition() -> None:
    runtime_parameters = signature(create_agent_runtime_stack).parameters
    stack_fields = {field.name for field in fields(AgentRuntimeStack)}

    assert "reliability_fault_injector" not in runtime_parameters
    assert "fault_injector" not in runtime_parameters
    assert "reliability_fault_injector" not in stack_fields
    assert "fault_injector" not in stack_fields
