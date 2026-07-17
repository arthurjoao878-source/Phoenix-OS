from __future__ import annotations

import pytest

from phoenix_os import (
    EventBus,
    InMemorySink,
    ObservabilityHub,
    PolicyConfirmationRequiredError,
    PolicyDeniedError,
    PolicyEffect,
    PolicyEngine,
    PolicyEngineClosedError,
    PolicyRequest,
    PolicyRule,
    PolicyRuleAlreadyRegisteredError,
    PolicyRuleNotFoundError,
    PrincipalType,
    SecurityContext,
)


def user_context(**changes: object) -> SecurityContext:
    values: dict[str, object] = {
        "principal": "arthur",
        "principal_type": PrincipalType.USER,
        "authenticated": True,
        "roles": frozenset({"user"}),
        "permissions": frozenset(),
        "scopes": frozenset(),
        "attributes": {},
    }
    values.update(changes)
    return SecurityContext(**values)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_default_is_deny_with_explanation() -> None:
    engine = PolicyEngine()
    decision = await engine.evaluate(PolicyRequest("files.read", "file:report"))
    assert decision.effect is PolicyEffect.DENY
    assert decision.rule_id is None
    assert "default deny" in decision.reason


@pytest.mark.asyncio
async def test_registration_listing_removal_and_duplicates() -> None:
    low = PolicyRule("low", PolicyEffect.ALLOW, priority=1)
    high = PolicyRule("high", PolicyEffect.DENY, priority=10)
    engine = PolicyEngine((low,))
    registration = await engine.register(high)
    assert [rule.rule_id for rule in await engine.list_rules()] == ["high", "low"]
    with pytest.raises(PolicyRuleAlreadyRegisteredError):
        await engine.register(high)
    assert await engine.describe("LOW") is low
    with pytest.raises(PolicyRuleNotFoundError):
        await engine.describe("missing")
    assert await engine.unregister(registration)
    assert not await engine.unregister(registration)


@pytest.mark.asyncio
async def test_higher_priority_rule_wins() -> None:
    engine = PolicyEngine(
        (
            PolicyRule("allow", PolicyEffect.ALLOW, priority=100),
            PolicyRule("deny", PolicyEffect.DENY, priority=1),
        )
    )
    decision = await engine.evaluate(PolicyRequest("read", "resource"))
    assert decision.effect is PolicyEffect.ALLOW
    assert decision.rule_id == "allow"
    assert decision.matched_rules == ("allow", "deny")


@pytest.mark.asyncio
async def test_deny_wins_when_priority_is_equal() -> None:
    engine = PolicyEngine(
        (
            PolicyRule("allow", PolicyEffect.ALLOW, priority=5),
            PolicyRule("deny", PolicyEffect.DENY, priority=5),
        )
    )
    decision = await engine.evaluate(PolicyRequest("read", "resource"))
    assert decision.effect is PolicyEffect.DENY
    assert decision.rule_id == "deny"


@pytest.mark.asyncio
async def test_confirmation_is_required_then_satisfied() -> None:
    engine = PolicyEngine((PolicyRule("confirm", PolicyEffect.REQUIRE_CONFIRMATION),))
    request = PolicyRequest("system.restart", "system:host", user_context())
    decision = await engine.evaluate(request)
    assert decision.effect is PolicyEffect.REQUIRE_CONFIRMATION
    with pytest.raises(PolicyConfirmationRequiredError):
        await engine.enforce(request)

    confirmed = PolicyRequest(
        "system.restart",
        "system:host",
        user_context(confirmed=True),
    )
    decision = await engine.enforce(confirmed)
    assert decision.effect is PolicyEffect.ALLOW
    assert decision.confirmation_satisfied


@pytest.mark.asyncio
async def test_enforce_raises_structured_denial() -> None:
    engine = PolicyEngine((PolicyRule("deny", PolicyEffect.DENY, reason="blocked"),))
    with pytest.raises(PolicyDeniedError) as captured:
        await engine.enforce(PolicyRequest("read", "resource"))
    assert captured.value.decision.rule_id == "deny"
    assert str(captured.value) == "blocked"


@pytest.mark.asyncio
async def test_rule_matches_identity_sets_and_attributes() -> None:
    engine = PolicyEngine(
        (
            PolicyRule(
                "specific",
                PolicyEffect.ALLOW,
                actions=frozenset({"state.*"}),
                resources=frozenset({"state:profile:*"}),
                principals=frozenset({"arth*"}),
                principal_types=frozenset({PrincipalType.USER}),
                required_roles=frozenset({"admin"}),
                required_permissions=frozenset({"state.read"}),
                required_scopes=frozenset({"profile"}),
                authenticated=True,
                attribute_equals={"tenant": "phoenix"},
            ),
        )
    )
    context = user_context(
        roles=frozenset({"admin"}),
        permissions=frozenset({"state.read"}),
        scopes=frozenset({"profile"}),
        attributes={"tenant": "phoenix"},
    )
    decision = await engine.evaluate(PolicyRequest("state.read", "state:profile:arthur", context))
    assert decision.effect is PolicyEffect.ALLOW


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "context,attributes",
    [
        (user_context(roles=frozenset()), {}),
        (user_context(permissions=frozenset()), {"tenant": "phoenix"}),
        (user_context(scopes=frozenset()), {"tenant": "phoenix"}),
        (user_context(attributes={"tenant": "other"}), {}),
    ],
)
async def test_unmet_requirements_do_not_match(
    context: SecurityContext,
    attributes: dict[str, str],
) -> None:
    rule = PolicyRule(
        "specific",
        PolicyEffect.ALLOW,
        required_roles=frozenset({"admin"}),
        required_permissions=frozenset({"read"}),
        required_scopes=frozenset({"workspace"}),
        attribute_equals={"tenant": "phoenix"},
    )
    engine = PolicyEngine((rule,))
    decision = await engine.evaluate(PolicyRequest("read", "resource", context, attributes))
    assert decision.effect is PolicyEffect.DENY


@pytest.mark.asyncio
async def test_request_attributes_override_context_attributes() -> None:
    engine = PolicyEngine(
        (
            PolicyRule(
                "tenant",
                PolicyEffect.ALLOW,
                attribute_equals={"tenant": "phoenix"},
            ),
        )
    )
    context = user_context(attributes={"tenant": "other"})
    decision = await engine.evaluate(
        PolicyRequest("read", "resource", context, {"tenant": "phoenix"})
    )
    assert decision.effect is PolicyEffect.ALLOW


@pytest.mark.asyncio
async def test_snapshot_counts_decisions() -> None:
    engine = PolicyEngine(
        (
            PolicyRule("allow", PolicyEffect.ALLOW, actions=frozenset({"read"})),
            PolicyRule(
                "confirm",
                PolicyEffect.REQUIRE_CONFIRMATION,
                actions=frozenset({"write"}),
            ),
        )
    )
    await engine.evaluate(PolicyRequest("read", "resource"))
    await engine.evaluate(PolicyRequest("write", "resource"))
    await engine.evaluate(PolicyRequest("delete", "resource"))
    snapshot = await engine.snapshot()
    assert snapshot.evaluations == 3
    assert snapshot.allowed == 1
    assert snapshot.confirmations == 1
    assert snapshot.denied == 1


@pytest.mark.asyncio
async def test_events_and_observability_receive_redacted_decision_data() -> None:
    bus = EventBus()
    seen: list[object] = []
    await bus.subscribe("policy.evaluated", seen.append)
    sink = InMemorySink()
    hub = ObservabilityHub((sink,))
    engine = PolicyEngine((PolicyRule("deny", PolicyEffect.DENY),), events=bus, observability=hub)

    await engine.evaluate(PolicyRequest("read", "resource", user_context()))

    assert len(seen) == 1
    snapshot = await sink.snapshot()
    assert len(snapshot.records) == 3


@pytest.mark.asyncio
async def test_close_clears_rules_and_rejects_use() -> None:
    engine = PolicyEngine((PolicyRule("allow", PolicyEffect.ALLOW),))
    await engine.close()
    assert (await engine.snapshot()).closed
    with pytest.raises(PolicyEngineClosedError):
        await engine.evaluate(PolicyRequest("read", "resource"))
    with pytest.raises(PolicyEngineClosedError):
        await engine.register(PolicyRule("other", PolicyEffect.ALLOW))
