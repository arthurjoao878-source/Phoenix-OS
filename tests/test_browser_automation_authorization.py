from __future__ import annotations

import hashlib
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from phoenix_os.authority import BUILTIN_AUTHORITY_CATALOG
from phoenix_os.browser_automation import (
    BROWSER_ELEMENT_CLICK_ACTION,
    BROWSER_ELEMENT_FILL_ACTION,
    BROWSER_PAGE_NAVIGATE_ACTION,
    BROWSER_PAGE_READ_ACTION,
    BROWSER_SESSION_CLOSE_ACTION,
    BROWSER_SESSION_OPEN_ACTION,
    BrowserAdapterId,
    BrowserAuthorizationRejectedError,
    BrowserDestinationMode,
    BrowserElementId,
    BrowserNavigationRequest,
    BrowserNavigationTarget,
    BrowserNavigationTargetId,
    BrowserOrigin,
    BrowserPageDescriptor,
    BrowserPageId,
    BrowserPageRevision,
    BrowserPreparedEffect,
    BrowserPreparedEffectKind,
    BrowserProfile,
    BrowserProfileId,
    BrowserSessionDescriptor,
    BrowserSessionId,
    PolicyEngineBrowserAuthorizer,
    browser_element_click_intent,
    browser_element_fill_intent,
    browser_element_resource,
    browser_page_navigate_intent,
    browser_page_read_intent,
    browser_page_resource,
    browser_profile_resource,
    browser_session_close_intent,
    browser_session_open_intent,
    browser_session_resource,
    derive_browser_redirect_request,
)
from phoenix_os.policy import (
    PolicyDecision,
    PolicyEffect,
    PolicyEngine,
    PolicyRequest,
    PolicyRule,
    PrincipalType,
    SecurityContext,
)

_NOW = datetime(2026, 8, 25, 8, tzinfo=UTC)
_PROFILE_ID = BrowserProfileId("browser-main")
_SESSION_ID = BrowserSessionId(UUID("35000000-0000-4000-8000-000000000001"))
_PAGE_ID = BrowserPageId(UUID("35000000-0000-4000-8000-000000000002"))
_ELEMENT_ID = BrowserElementId(UUID("35000000-0000-4000-8000-000000000003"))
_PREPARED_TOKEN = UUID("35000000-0000-4000-8000-000000000004")
_PRINCIPAL = "service:browser-requester"

_BROWSER_ACTIONS = (
    BROWSER_SESSION_OPEN_ACTION,
    BROWSER_SESSION_CLOSE_ACTION,
    BROWSER_PAGE_NAVIGATE_ACTION,
    BROWSER_PAGE_READ_ACTION,
    BROWSER_ELEMENT_FILL_ACTION,
    BROWSER_ELEMENT_CLICK_ACTION,
)


class RecordingPolicyEngine(PolicyEngine):
    def __init__(self, rules: tuple[PolicyRule, ...]) -> None:
        super().__init__(rules)
        self.enforced: list[PolicyRequest] = []

    async def enforce(self, request: PolicyRequest) -> PolicyDecision:
        self.enforced.append(request)
        return await super().enforce(request)


class NeverPolicyEngine(PolicyEngine):
    def __init__(self) -> None:
        super().__init__()
        self.calls = 0

    async def enforce(self, request: PolicyRequest) -> PolicyDecision:
        del request
        self.calls += 1
        raise AssertionError("policy must not be reached for an invalid exact browser binding")


def _target(path: str = "/start") -> BrowserNavigationTarget:
    return BrowserNavigationTarget(
        target_id=BrowserNavigationTargetId("start"),
        origin=BrowserOrigin(BrowserDestinationMode.HOSTED_HTTPS, "example.com"),
        request_target=path,
    )


def _profile(
    *,
    generation: int = 7,
    target: BrowserNavigationTarget | None = None,
) -> BrowserProfile:
    selected = _target() if target is None else target
    return BrowserProfile(
        profile_id=_PROFILE_ID,
        generation=generation,
        adapter_id=BrowserAdapterId("deterministic"),
        allowed_origins=(selected.origin,),
        initial_targets=(selected,),
    )


def _session(
    *,
    generation: int = 7,
    session_id: BrowserSessionId = _SESSION_ID,
) -> BrowserSessionDescriptor:
    return BrowserSessionDescriptor(
        profile_id=_PROFILE_ID,
        profile_generation=generation,
        session_id=session_id,
        page_id=_PAGE_ID,
        created_at=_NOW,
        expires_at=_NOW + timedelta(minutes=10),
    )


def _page(
    *,
    revision: int = 3,
    session_id: BrowserSessionId = _SESSION_ID,
) -> BrowserPageDescriptor:
    return BrowserPageDescriptor(
        session_id=session_id,
        page_id=_PAGE_ID,
        revision=BrowserPageRevision(revision),
    )


def _prepared_fill(*, revision: int = 3, digest: str | None = None) -> BrowserPreparedEffect:
    exact_digest = digest or "sha256:" + hashlib.sha256(b"secret user text").hexdigest()
    return BrowserPreparedEffect(
        token=_PREPARED_TOKEN,
        kind=BrowserPreparedEffectKind.FILL,
        session_id=_SESSION_ID,
        page_id=_PAGE_ID,
        revision=BrowserPageRevision(revision),
        element_id=_ELEMENT_ID,
        input_digest=exact_digest,
    )


def _prepared_click(*, revision: int = 3) -> BrowserPreparedEffect:
    return BrowserPreparedEffect(
        token=_PREPARED_TOKEN,
        kind=BrowserPreparedEffectKind.CLICK,
        session_id=_SESSION_ID,
        page_id=_PAGE_ID,
        revision=BrowserPageRevision(revision),
        element_id=_ELEMENT_ID,
    )


def _context(*, confirmed: bool = False) -> SecurityContext:
    return SecurityContext(
        principal=_PRINCIPAL,
        principal_type=PrincipalType.SERVICE,
        authenticated=True,
        confirmed=confirmed,
    )


def _allow_rule(action: str, resource: str) -> PolicyRule:
    return PolicyRule(
        rule_id=f"allow-{action.replace('.', '-')}",
        effect=PolicyEffect.ALLOW,
        actions=frozenset({action}),
        resources=frozenset({resource}),
        principals=frozenset({_PRINCIPAL}),
        authenticated=True,
    )


def test_browser_catalog_has_exact_six_independent_canonical_actions() -> None:
    profile = _profile()
    session = _session()
    page = _page()
    prepared = _prepared_fill()
    resources = {
        BROWSER_SESSION_OPEN_ACTION: browser_profile_resource(profile),
        BROWSER_SESSION_CLOSE_ACTION: browser_session_resource(profile, session),
        BROWSER_PAGE_NAVIGATE_ACTION: browser_page_resource(profile, session, page),
        BROWSER_PAGE_READ_ACTION: browser_page_resource(profile, session, page),
        BROWSER_ELEMENT_FILL_ACTION: browser_element_resource(profile, session, page, prepared),
        BROWSER_ELEMENT_CLICK_ACTION: browser_element_resource(profile, session, page, prepared),
    }

    for action, resource in resources.items():
        entry = BUILTIN_AUTHORITY_CATALOG.require(action)
        assert entry.canonical_boundary == action
        assert entry.accepts_resource(resource)

    assert "browser.execute" not in BUILTIN_AUTHORITY_CATALOG.actions
    transitions = BUILTIN_AUTHORITY_CATALOG.mediated_transitions
    assert not any(
        left in _BROWSER_ACTIONS or right in _BROWSER_ACTIONS for left, right in transitions
    )


def test_browser_resource_grammar_is_generation_session_revision_and_element_exact() -> None:
    profile = _profile()
    session = _session()
    page = _page()
    prepared = _prepared_fill()

    assert browser_profile_resource(profile) == "browser:browser-main/generation:7"
    assert browser_session_resource(profile, session) == (
        "browser:browser-main/generation:7/session:35000000-0000-4000-8000-000000000001"
    )
    assert browser_page_resource(profile, session, page) == (
        "browser:browser-main/generation:7/session:35000000-0000-4000-8000-000000000001"
        "/page:35000000-0000-4000-8000-000000000002/revision:3"
    )
    assert browser_element_resource(profile, session, page, prepared).endswith(
        "/element:35000000-0000-4000-8000-000000000003"
    )

    page_entry = BUILTIN_AUTHORITY_CATALOG.require(BROWSER_PAGE_READ_ACTION)
    element_entry = BUILTIN_AUTHORITY_CATALOG.require(BROWSER_ELEMENT_FILL_ACTION)
    assert not page_entry.accepts_resource(browser_profile_resource(profile))
    assert not element_entry.accepts_resource(browser_page_resource(profile, session, page))
    assert not page_entry.accepts_resource(
        browser_page_resource(profile, session, page) + "/extra:x"
    )


def test_all_browser_intents_are_catalog_valid_and_action_distinct() -> None:
    profile = _profile()
    session = _session()
    page = _page()
    target = profile.initial_targets[0]
    fill = _prepared_fill()
    click = _prepared_click()

    intents = (
        browser_session_open_intent(profile, session),
        browser_session_close_intent(profile, session),
        browser_page_navigate_intent(profile, session, page, target),
        browser_page_read_intent(profile, session, page),
        browser_element_fill_intent(profile, session, page, fill),
        browser_element_click_intent(profile, session, page, click),
    )

    assert tuple(item.action for item in intents) == _BROWSER_ACTIONS
    for intent in intents:
        assert BUILTIN_AUTHORITY_CATALOG.validate_intent(intent).action == intent.action
        assert intent.parameter_digest.startswith("sha256:")
        assert intent.freshness_bindings


def test_profile_configuration_and_generation_are_bound_into_browser_intents() -> None:
    old = _profile(generation=7)
    new = _profile(generation=8)
    old_session = _session(generation=7)
    new_session = _session(generation=8)

    old_intent = browser_session_open_intent(old, old_session)
    new_intent = browser_session_open_intent(new, new_session)

    assert old_intent.canonical_resource != new_intent.canonical_resource
    assert old_intent.parameter_digest != new_intent.parameter_digest
    assert old_intent.freshness_bindings != new_intent.freshness_bindings

    changed = replace(old, adapter_id=BrowserAdapterId("other-reviewed-adapter"))
    assert (
        browser_session_open_intent(changed, old_session).parameter_digest
        != old_intent.parameter_digest
    )


def test_navigation_intent_rejects_unconfigured_target_substitution() -> None:
    profile = _profile()
    forged = _target("/other")

    with pytest.raises(BrowserAuthorizationRejectedError):
        browser_page_navigate_intent(profile, _session(), _page(), forged)


def test_redirect_navigation_intent_binds_exact_candidate_and_hop_count() -> None:
    profile = _profile()
    session = _session()
    page = _page()
    initial = BrowserNavigationRequest.from_target(profile.initial_targets[0])
    redirected = derive_browser_redirect_request(profile, initial, "/next")

    initial_intent = browser_page_navigate_intent(profile, session, page, initial)
    redirected_intent = browser_page_navigate_intent(profile, session, page, redirected)

    assert initial_intent.parameter_digest != redirected_intent.parameter_digest
    changed = replace(redirected, request_target="/other")
    assert (
        browser_page_navigate_intent(profile, session, page, changed).parameter_digest
        != redirected_intent.parameter_digest
    )

    over_limit = replace(redirected, redirect_count=profile.limits.max_redirects + 1)
    with pytest.raises(BrowserAuthorizationRejectedError):
        browser_page_navigate_intent(profile, session, page, over_limit)

    forged_initial = replace(initial, request_target="/response-granted")
    with pytest.raises(BrowserAuthorizationRejectedError):
        browser_page_navigate_intent(profile, session, page, forged_initial)


def test_session_page_and_prepared_stale_bindings_fail_closed() -> None:
    profile = _profile()
    session = _session()
    page = _page()

    with pytest.raises(BrowserAuthorizationRejectedError):
        browser_page_read_intent(profile, replace(session, profile_generation=8), page)

    with pytest.raises(BrowserAuthorizationRejectedError):
        browser_page_read_intent(
            profile,
            session,
            _page(session_id=BrowserSessionId(UUID("35000000-0000-4000-8000-000000000099"))),
        )

    with pytest.raises(BrowserAuthorizationRejectedError):
        browser_element_fill_intent(profile, session, page, _prepared_fill(revision=2))


def test_fill_and_click_authority_are_not_interchangeable() -> None:
    profile = _profile()
    session = _session()
    page = _page()

    with pytest.raises(BrowserAuthorizationRejectedError):
        browser_element_fill_intent(profile, session, page, _prepared_click())
    with pytest.raises(BrowserAuthorizationRejectedError):
        browser_element_click_intent(profile, session, page, _prepared_fill())


def test_fill_intent_binds_digest_without_plaintext() -> None:
    profile = _profile()
    session = _session()
    page = _page()
    first = _prepared_fill()
    second = replace(first, input_digest="sha256:" + hashlib.sha256(b"different").hexdigest())

    first_intent = browser_element_fill_intent(profile, session, page, first)
    second_intent = browser_element_fill_intent(profile, session, page, second)

    assert first_intent.parameter_digest != second_intent.parameter_digest
    assert "secret user text" not in repr(first_intent)
    assert first.input_digest is not None
    assert first.input_digest not in first_intent.canonical_resource


@pytest.mark.asyncio
async def test_policy_authorizer_enforces_exact_page_read_and_clears_confirmation() -> None:
    profile = _profile()
    session = _session()
    page = _page()
    resource = browser_page_resource(profile, session, page)
    policy = RecordingPolicyEngine((_allow_rule(BROWSER_PAGE_READ_ACTION, resource),))

    intent = await PolicyEngineBrowserAuthorizer(policy).authorize_page_read(
        profile,
        session,
        page,
        _context(confirmed=True),
    )

    assert intent.action == BROWSER_PAGE_READ_ACTION
    assert len(policy.enforced) == 1
    request = policy.enforced[0]
    assert request.action == BROWSER_PAGE_READ_ACTION
    assert request.resource == resource
    assert request.context.confirmed is False
    assert request.context.principal == _PRINCIPAL
    assert request.attributes["page_revision"] == "3"
    assert request.attributes["intent_parameter_digest"] == intent.parameter_digest
    assert "example.com" not in repr(request.attributes)
    assert "/start" not in repr(request.attributes)


@pytest.mark.asyncio
async def test_tool_or_other_browser_action_does_not_imply_click_authority() -> None:
    profile = _profile()
    session = _session()
    page = _page()
    prepared = _prepared_click()
    click_resource = browser_element_resource(profile, session, page, prepared)
    policy = PolicyEngine(
        (
            PolicyRule(
                rule_id="allow-other-boundaries-only",
                effect=PolicyEffect.ALLOW,
                actions=frozenset({"tool.invoke", BROWSER_PAGE_READ_ACTION}),
                resources=frozenset(
                    {
                        f"tool:browser/{click_resource}",
                        browser_page_resource(profile, session, page),
                    }
                ),
                principals=frozenset({_PRINCIPAL}),
                authenticated=True,
            ),
        )
    )

    with pytest.raises(BrowserAuthorizationRejectedError):
        await PolicyEngineBrowserAuthorizer(policy).authorize_element_click(
            profile,
            session,
            page,
            prepared,
            _context(),
        )


@pytest.mark.asyncio
async def test_generic_confirmation_does_not_satisfy_browser_confirmation_rule() -> None:
    profile = _profile()
    session = _session()
    resource = browser_session_resource(profile, session)
    policy = PolicyEngine(
        (
            PolicyRule(
                rule_id="confirm-browser-close",
                effect=PolicyEffect.REQUIRE_CONFIRMATION,
                actions=frozenset({BROWSER_SESSION_CLOSE_ACTION}),
                resources=frozenset({resource}),
                principals=frozenset({_PRINCIPAL}),
                authenticated=True,
            ),
        )
    )

    with pytest.raises(BrowserAuthorizationRejectedError):
        await PolicyEngineBrowserAuthorizer(policy).authorize_session_close(
            profile,
            session,
            _context(confirmed=True),
        )


@pytest.mark.asyncio
async def test_invalid_exact_binding_and_unauthenticated_context_fail_before_policy() -> None:
    profile = _profile()
    page = _page()

    policy = NeverPolicyEngine()
    with pytest.raises(BrowserAuthorizationRejectedError):
        await PolicyEngineBrowserAuthorizer(policy).authorize_page_read(
            profile,
            _session(generation=8),
            page,
            _context(),
        )
    assert policy.calls == 0

    with pytest.raises(BrowserAuthorizationRejectedError):
        await PolicyEngineBrowserAuthorizer(policy).authorize_page_read(
            profile,
            _session(),
            page,
            SecurityContext(),
        )
    assert policy.calls == 0


def test_browser_authorizer_has_no_generic_authorize_escape_hatch() -> None:
    authorizer = PolicyEngineBrowserAuthorizer(PolicyEngine())

    assert not hasattr(authorizer, "authorize")
    assert not hasattr(authorizer, "execute")


def test_browser_authorization_error_is_content_free() -> None:
    rendered = str(BrowserAuthorizationRejectedError())

    assert rendered == "browser operation authorization failed"
    assert "example.com" not in rendered
    assert "/start" not in rendered
    assert "browser-main" not in rendered
