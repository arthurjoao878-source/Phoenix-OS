from __future__ import annotations

from datetime import datetime
from types import MappingProxyType
from uuid import uuid4

import pytest

from phoenix_os import (
    PolicyDecision,
    PolicyEffect,
    PolicyRequest,
    PolicyRule,
    PolicySnapshot,
    PrincipalType,
    SecurityContext,
)


def test_security_context_is_normalized_and_immutable() -> None:
    context = SecurityContext(
        principal=" Arthur ",
        principal_type=PrincipalType.USER,
        authenticated=True,
        roles=frozenset({" Admin "}),
        permissions=frozenset({" Files.Read "}),
        scopes=frozenset({" Workspace "}),
        attributes={" Tenant ": " phoenix "},
        correlation_id=" request-1 ",
    )

    assert context.principal == "Arthur"
    assert context.roles == frozenset({"admin"})
    assert context.permissions == frozenset({"files.read"})
    assert context.scopes == frozenset({"workspace"})
    assert context.attributes == {"tenant": "phoenix"}
    assert isinstance(context.attributes, MappingProxyType)
    assert context.correlation_id == "request-1"


def test_anonymous_principal_cannot_be_authenticated() -> None:
    with pytest.raises(ValueError, match="anonymous"):
        SecurityContext(authenticated=True)


def test_security_context_rejects_blank_values() -> None:
    with pytest.raises(ValueError, match="principal"):
        SecurityContext(principal=" ")
    with pytest.raises(ValueError, match="correlation"):
        SecurityContext(correlation_id=" ")
    with pytest.raises(ValueError, match="blank"):
        SecurityContext(roles=frozenset({""}))
    with pytest.raises(ValueError, match="blank"):
        SecurityContext(attributes={"tenant": ""})


def test_policy_request_normalizes_and_freezes_attributes() -> None:
    request = PolicyRequest(
        " Capability.Invoke ",
        " Capability:Demo.Answer ",
        attributes={" Risk ": " safe "},
    )

    assert request.action == "capability.invoke"
    assert request.resource == "capability:demo.answer"
    assert request.attributes == {"risk": "safe"}
    assert isinstance(request.attributes, MappingProxyType)


def test_policy_request_rejects_invalid_names_and_naive_time() -> None:
    with pytest.raises(ValueError, match="policy action"):
        PolicyRequest("bad action", "resource")
    with pytest.raises(ValueError, match="timezone"):
        PolicyRequest("read", "resource", created_at=datetime.now())


def test_policy_rule_normalizes_matchers_and_requirements() -> None:
    rule = PolicyRule(
        " Allow.Admin ",
        PolicyEffect.ALLOW,
        actions=frozenset({" State.* "}),
        resources=frozenset({" State:Profile:* "}),
        principals=frozenset({" Arthur* "}),
        principal_types=frozenset({PrincipalType.USER}),
        required_roles=frozenset({" Admin "}),
        required_permissions=frozenset({" State.Read "}),
        required_scopes=frozenset({" Profile "}),
        attribute_equals={" Tenant ": " phoenix "},
        metadata={" Owner ": " security "},
    )

    assert rule.rule_id == "allow.admin"
    assert rule.actions == frozenset({"state.*"})
    assert rule.resources == frozenset({"state:profile:*"})
    assert rule.principals == frozenset({"arthur*"})
    assert rule.required_roles == frozenset({"admin"})
    assert rule.required_permissions == frozenset({"state.read"})
    assert rule.required_scopes == frozenset({"profile"})
    assert rule.attribute_equals == {"tenant": "phoenix"}
    assert rule.metadata == {"owner": "security"}


def test_policy_rule_defaults_match_all() -> None:
    rule = PolicyRule("default", PolicyEffect.DENY)
    assert rule.actions == frozenset({"*"})
    assert rule.resources == frozenset({"*"})
    assert rule.principals == frozenset({"*"})


def test_policy_rule_rejects_invalid_or_empty_matchers() -> None:
    with pytest.raises(ValueError, match="rule id"):
        PolicyRule("bad id", PolicyEffect.DENY)
    with pytest.raises(ValueError, match="must not be empty"):
        PolicyRule("empty", PolicyEffect.DENY, actions=frozenset())


def test_policy_decision_requires_explanation_and_freezes_metadata() -> None:
    request_id = uuid4()
    decision = PolicyDecision(
        request_id,
        PolicyEffect.ALLOW,
        " allowed ",
        metadata={" Rule ": " one "},
    )
    assert decision.reason == "allowed"
    assert decision.metadata == {"rule": "one"}
    with pytest.raises(ValueError, match="reason"):
        PolicyDecision(request_id, PolicyEffect.DENY, " ")


def test_policy_snapshot_is_immutable_value_contract() -> None:
    snapshot = PolicySnapshot(False, ("one", "two"), 3, 1, 1, 1)
    assert snapshot.rules == ("one", "two")
    assert snapshot.evaluations == 3
