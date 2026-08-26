from __future__ import annotations

from uuid import UUID

import pytest

from phoenix_os.authority import (
    BUILTIN_AUTHORITY_CATALOG,
    AuthorityConstraint,
    AuthorityDenialReason,
    AuthorityEffect,
    AuthorityFreshnessBinding,
    AuthorityIntent,
    AuthorityPathObservation,
    AuthoritySubject,
    AuthoritySubjectProjection,
)
from phoenix_os.authority.catalog import InvalidAuthorityObservationError
from phoenix_os.authority.redaction import project_observation, project_subject
from phoenix_os.policy import PrincipalType

_SESSION_ID = UUID("10000000-0000-0000-0000-000000000033")
_RECORD_ID = UUID("20000000-0000-0000-0000-000000000033")


def _subject() -> AuthoritySubject:
    return AuthoritySubject(
        principal_type=PrincipalType.SERVICE,
        principal="service:operator",
        session_id=_SESSION_ID,
        agent_id="assistant",
        run_id="30000000-0000-0000-0000-000000000033",
    )


def _intent(*, action: str, resource: str) -> AuthorityIntent:
    return AuthorityIntent(
        action=action,
        canonical_resource=resource,
        parameter_digest="sha256:" + "a" * 64,
        freshness_bindings=(AuthorityFreshnessBinding("memory.version", "7"),),
    )


def test_subject_projection_hashes_structural_session_identity() -> None:
    projected = project_subject(_subject())

    assert projected.principal_type is PrincipalType.SERVICE
    assert projected.principal == "service:operator"
    assert projected.agent_id == "assistant"
    assert projected.run_id == "30000000-0000-0000-0000-000000000033"
    assert projected.session_identity is not None
    assert projected.session_identity.startswith("sha256:")
    assert str(_SESSION_ID) not in repr(projected)


def test_tool_projection_never_exposes_resolved_resource_tail() -> None:
    secret_tail = "host-automation:host:desktop/application:credential-admin"
    observation = AuthorityPathObservation(
        intent=_intent(
            action="tool.invoke",
            resource=f"tool:host.app.launch/{secret_tail}",
        ),
        boundaries=("agent.run", "tool.invoke"),
        effect=AuthorityEffect.ALLOWED,
        constraints=(AuthorityConstraint.POLICY, AuthorityConstraint.CANONICAL_BOUNDARY),
    )

    projected = project_observation(observation, BUILTIN_AUTHORITY_CATALOG)

    assert projected.canonical_resource.startswith("tool:host.app.launch/resource:sha256:")
    assert secret_tail not in projected.canonical_resource
    assert "credential-admin" not in repr(projected)


def test_reviewed_content_free_resource_is_preserved() -> None:
    resource = f"agent-memory:composition/scope:agent:assistant/record:{_RECORD_ID}"
    observation = AuthorityPathObservation(
        intent=_intent(action="memory.write", resource=resource),
        boundaries=("agent.run", "tool.invoke", "memory.write"),
        effect=AuthorityEffect.DENIED,
        constraints=(AuthorityConstraint.POLICY,),
        denial_reason=AuthorityDenialReason.BOUNDARY_DENIED,
        blocked_downstream=("memory.delete",),
    )

    projected = project_observation(observation, BUILTIN_AUTHORITY_CATALOG)

    assert projected.canonical_resource == resource
    assert projected.denial_reason is AuthorityDenialReason.BOUNDARY_DENIED
    assert projected.blocked_downstream_alternatives == ("memory.delete",)


def test_resource_with_reviewed_prefix_but_unreviewed_shape_fails_closed() -> None:
    observation = AuthorityPathObservation(
        intent=_intent(
            action="host.clipboard.read",
            resource="host-automation:secret:credential-admin",
        ),
        boundaries=("host.clipboard.read",),
        effect=AuthorityEffect.ALLOWED,
    )

    with pytest.raises(InvalidAuthorityObservationError):
        project_observation(observation, BUILTIN_AUTHORITY_CATALOG)


def test_safe_projection_contract_rejects_raw_session_identity() -> None:
    projected = project_subject(_subject())

    with pytest.raises(ValueError, match="sha256"):
        AuthoritySubjectProjection(
            principal_type=projected.principal_type,
            principal=projected.principal,
            session_identity=str(_SESSION_ID),
            agent_id=projected.agent_id,
            run_id=projected.run_id,
        )


def test_redaction_does_not_project_parameter_or_freshness_identity() -> None:
    observation = AuthorityPathObservation(
        intent=_intent(
            action="memory.read",
            resource=(f"agent-memory:composition/scope:agent:assistant/record:{_RECORD_ID}"),
        ),
        boundaries=("memory.read",),
        effect=AuthorityEffect.ALLOWED,
    )

    projected = project_observation(observation, BUILTIN_AUTHORITY_CATALOG)

    assert not hasattr(projected, "parameter_digest")
    assert not hasattr(projected, "freshness_bindings")


def test_builtin_catalog_is_exact_closed_world_authority_inventory() -> None:
    assert set(BUILTIN_AUTHORITY_CATALOG.actions) == {
        "agent.run",
        "model.infer",
        "tool.invoke",
        "agent.delegate",
        "agent.resume",
        "agent.reconcile",
        "memory.search",
        "memory.read",
        "memory.write",
        "memory.delete",
        "memory.admin",
        "workspace.list",
        "workspace.read",
        "workspace.write",
        "workspace.delete",
        "workspace.import",
        "workspace.export",
        "workspace.admin",
        "host.process.list",
        "host.window.list",
        "host.app.launch",
        "host.window.focus",
        "host.app.close",
        "host.clipboard.write",
        "host.clipboard.read",
        "network.http.request",
        "browser.session.open",
        "browser.session.close",
        "browser.page.navigate",
        "browser.page.read",
        "browser.element.fill",
        "browser.element.click",
        "authority.inspect",
        "authority.explain",
    }


def test_observation_must_terminate_at_canonical_boundary() -> None:
    observation = AuthorityPathObservation(
        intent=_intent(
            action="host.clipboard.write",
            resource="host-automation:host:desktop/clipboard:text",
        ),
        boundaries=("agent.run", "tool.invoke"),
        effect=AuthorityEffect.DENIED,
        denial_reason=AuthorityDenialReason.BOUNDARY_DENIED,
    )

    with pytest.raises(InvalidAuthorityObservationError, match="canonical boundary"):
        project_observation(observation, BUILTIN_AUTHORITY_CATALOG)


def test_reviewed_nested_mediated_path_is_accepted() -> None:
    observation = AuthorityPathObservation(
        intent=_intent(
            action="host.clipboard.write",
            resource="host-automation:host:desktop/clipboard:text",
        ),
        boundaries=(
            "agent.resume",
            "agent.run",
            "tool.invoke",
            "host.clipboard.write",
        ),
        effect=AuthorityEffect.ALLOWED,
        constraints=(AuthorityConstraint.CANONICAL_BOUNDARY,),
    )

    projected = project_observation(observation, BUILTIN_AUTHORITY_CATALOG)

    assert projected.authority_path == observation.boundaries


def test_known_but_unreviewed_mediated_transition_fails_closed() -> None:
    observation = AuthorityPathObservation(
        intent=_intent(
            action="host.clipboard.write",
            resource="host-automation:host:desktop/clipboard:text",
        ),
        boundaries=("authority.inspect", "host.clipboard.write"),
        effect=AuthorityEffect.ALLOWED,
    )

    with pytest.raises(InvalidAuthorityObservationError, match="unreviewed mediated transition"):
        project_observation(observation, BUILTIN_AUTHORITY_CATALOG)


def test_workspace_export_does_not_imply_host_authority() -> None:
    observation = AuthorityPathObservation(
        intent=_intent(
            action="host.clipboard.write",
            resource="host-automation:host:desktop/clipboard:text",
        ),
        boundaries=("workspace.export", "host.clipboard.write"),
        effect=AuthorityEffect.ALLOWED,
    )

    with pytest.raises(InvalidAuthorityObservationError, match="unreviewed mediated transition"):
        project_observation(observation, BUILTIN_AUTHORITY_CATALOG)


def test_host_application_close_uses_exact_process_resource_grammar() -> None:
    process_resource = "host-automation:host:desktop/process:40000000-0000-0000-0000-000000000033"
    observation = AuthorityPathObservation(
        intent=_intent(action="host.app.close", resource=process_resource),
        boundaries=("host.app.close",),
        effect=AuthorityEffect.ALLOWED,
    )

    projected = project_observation(observation, BUILTIN_AUTHORITY_CATALOG)

    assert projected.canonical_resource == process_resource

    wrong_resource = "host-automation:host:desktop/application:editor"
    invalid = AuthorityPathObservation(
        intent=_intent(action="host.app.close", resource=wrong_resource),
        boundaries=("host.app.close",),
        effect=AuthorityEffect.ALLOWED,
    )
    with pytest.raises(InvalidAuthorityObservationError, match="resource grammar"):
        project_observation(invalid, BUILTIN_AUTHORITY_CATALOG)


def test_maximum_tool_resolved_resource_remains_inspectable() -> None:
    resolved_resource = "a" * 1024
    observation = AuthorityPathObservation(
        intent=_intent(
            action="tool.invoke",
            resource=f"tool:custom/{resolved_resource}",
        ),
        boundaries=("agent.run", "tool.invoke"),
        effect=AuthorityEffect.ALLOWED,
    )

    projected = project_observation(observation, BUILTIN_AUTHORITY_CATALOG)

    assert projected.canonical_resource.startswith("tool:custom/resource:sha256:")
    assert resolved_resource not in projected.canonical_resource


def test_canonical_resource_rejects_policy_wildcards() -> None:
    with pytest.raises(ValueError, match="canonical authority resource"):
        _intent(
            action="tool.invoke",
            resource="tool:custom/host:*",
        )
