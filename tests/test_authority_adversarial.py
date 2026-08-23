from __future__ import annotations

import pytest

from phoenix_os.authority import (
    BUILTIN_AUTHORITY_CATALOG,
    AuthorityDenialReason,
    AuthorityEffect,
    AuthorityIntent,
    AuthorityPathObservation,
    InvalidAuthorityObservationError,
    UnknownAuthorityOperationError,
)

_DIGEST = "sha256:" + "a" * 64


def _host_process_intent() -> AuthorityIntent:
    return AuthorityIntent(
        action="host.process.list",
        canonical_resource="host-automation:host:desktop/processes",
        parameter_digest=_DIGEST,
    )


def test_unreviewed_mediated_transition_fails_closed() -> None:
    observation = AuthorityPathObservation(
        intent=_host_process_intent(),
        boundaries=("agent.run", "host.process.list"),
        effect=AuthorityEffect.DENIED,
        denial_reason=AuthorityDenialReason.BOUNDARY_DENIED,
    )
    with pytest.raises(InvalidAuthorityObservationError):
        BUILTIN_AUTHORITY_CATALOG.validate_observation(observation)


def test_unknown_blocked_downstream_operation_fails_closed() -> None:
    observation = AuthorityPathObservation(
        intent=_host_process_intent(),
        boundaries=("host.process.list",),
        effect=AuthorityEffect.DENIED,
        denial_reason=AuthorityDenialReason.BOUNDARY_DENIED,
        blocked_downstream=("host.shell.execute",),
    )
    with pytest.raises(UnknownAuthorityOperationError):
        BUILTIN_AUTHORITY_CATALOG.validate_observation(observation)


def test_resource_rebinding_to_different_host_fails_catalog_validation() -> None:
    intent = AuthorityIntent(
        action="host.process.list",
        canonical_resource="host-automation:host:desktop/process:unexpected",
        parameter_digest=_DIGEST,
    )
    with pytest.raises(InvalidAuthorityObservationError):
        BUILTIN_AUTHORITY_CATALOG.validate_intent(intent)


def test_reviewed_tool_to_host_path_retains_final_canonical_boundary() -> None:
    observation = AuthorityPathObservation(
        intent=_host_process_intent(),
        boundaries=("tool.invoke", "host.process.list"),
        effect=AuthorityEffect.ALLOWED,
    )
    BUILTIN_AUTHORITY_CATALOG.validate_observation(observation)
    assert observation.boundaries[-1] == "host.process.list"
