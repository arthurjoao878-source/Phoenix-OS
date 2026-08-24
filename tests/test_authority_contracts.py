from __future__ import annotations

from dataclasses import replace
from uuid import UUID

import pytest

from phoenix_os.authority import (
    BUILTIN_AUTHORITY_CATALOG,
    AuthorityDenialReason,
    AuthorityEffect,
    AuthorityFreshnessBinding,
    AuthorityIntent,
    AuthorityPathObservation,
    AuthoritySubject,
    InvalidAuthorityObservationError,
    UnknownAuthorityOperationError,
    authority_intent_fingerprint,
    authority_subject_fingerprint,
)
from phoenix_os.policy import PrincipalType

_DIGEST_A = "sha256:" + "a" * 64
_DIGEST_B = "sha256:" + "b" * 64
_SESSION = UUID("10000000-0000-4000-8000-000000000033")


def test_subject_fingerprint_binds_every_structural_authority_facet() -> None:
    base = AuthoritySubject(
        principal_type=PrincipalType.USER,
        principal="arthur",
        session_id=_SESSION,
        agent_id="assistant",
        run_id="run-33",
    )
    variants = (
        replace(base, principal="mallory"),
        replace(base, principal_type=PrincipalType.SERVICE),
        replace(base, session_id=UUID("20000000-0000-4000-8000-000000000033")),
        replace(base, agent_id="other-agent"),
        replace(base, run_id="other-run"),
    )
    fingerprints = {authority_subject_fingerprint(base)}
    fingerprints.update(authority_subject_fingerprint(item) for item in variants)
    assert len(fingerprints) == 1 + len(variants)


def test_intent_fingerprint_binds_action_resource_parameters_and_freshness() -> None:
    base = AuthorityIntent(
        action="host.process.list",
        canonical_resource="host-automation:host:desktop/processes",
        parameter_digest=_DIGEST_A,
        freshness_bindings=(AuthorityFreshnessBinding("host.epoch", "epoch-1"),),
    )
    variants = (
        replace(base, action="host.window.list"),
        replace(base, canonical_resource="host-automation:host:laptop/processes"),
        replace(base, parameter_digest=_DIGEST_B),
        replace(
            base,
            freshness_bindings=(AuthorityFreshnessBinding("host.epoch", "epoch-2"),),
        ),
    )
    fingerprints = {authority_intent_fingerprint(base)}
    fingerprints.update(authority_intent_fingerprint(item) for item in variants)
    assert len(fingerprints) == 1 + len(variants)


def test_closed_world_catalog_rejects_unknown_protected_operation() -> None:
    with pytest.raises(UnknownAuthorityOperationError):
        BUILTIN_AUTHORITY_CATALOG.require("host.shell.execute")


def test_catalog_rejects_path_not_ending_at_canonical_boundary() -> None:
    intent = AuthorityIntent(
        action="host.process.list",
        canonical_resource="host-automation:host:desktop/processes",
        parameter_digest=_DIGEST_A,
    )
    observation = AuthorityPathObservation(
        intent=intent,
        boundaries=("tool.invoke",),
        effect=AuthorityEffect.DENIED,
        denial_reason=AuthorityDenialReason.BOUNDARY_DENIED,
    )
    with pytest.raises(InvalidAuthorityObservationError):
        BUILTIN_AUTHORITY_CATALOG.validate_observation(observation)


def test_denied_observation_requires_explicit_safe_reason() -> None:
    intent = AuthorityIntent(
        action="host.process.list",
        canonical_resource="host-automation:host:desktop/processes",
        parameter_digest=_DIGEST_A,
    )
    with pytest.raises(ValueError, match="requires a denial reason"):
        AuthorityPathObservation(
            intent=intent,
            boundaries=("host.process.list",),
            effect=AuthorityEffect.DENIED,
        )


def test_network_http_request_catalog_entry_is_generation_bound_and_not_tool_mediated() -> None:
    action = "network.http.request"
    resource = "network-egress:payments/generation:7/operation:charge"
    entry = BUILTIN_AUTHORITY_CATALOG.require(action)

    assert entry.canonical_boundary == action
    assert entry.accepts_resource(resource)
    assert not entry.accepts_resource("network-egress:payments/generation:0/operation:charge")
    assert not entry.accepts_resource("network-egress:payments/operation:charge")
    assert not entry.accepts_resource(
        "network-egress:payments/generation:2147483648/operation:charge"
    )
    assert ("tool.invoke", action) not in BUILTIN_AUTHORITY_CATALOG.mediated_transitions

    intent = AuthorityIntent(
        action=action,
        canonical_resource=resource,
        parameter_digest=_DIGEST_A,
        freshness_bindings=(AuthorityFreshnessBinding("network.profile.generation", "payments:7"),),
    )
    BUILTIN_AUTHORITY_CATALOG.validate_observation(
        AuthorityPathObservation(
            intent=intent,
            boundaries=(action,),
            effect=AuthorityEffect.ALLOWED,
        )
    )
    with pytest.raises(InvalidAuthorityObservationError):
        BUILTIN_AUTHORITY_CATALOG.validate_observation(
            AuthorityPathObservation(
                intent=intent,
                boundaries=("tool.invoke", action),
                effect=AuthorityEffect.DENIED,
                denial_reason=AuthorityDenialReason.BOUNDARY_DENIED,
            )
        )
