from __future__ import annotations

import hashlib
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest

from phoenix_os.agent.contracts import (
    AgentId,
    AgentJsonInput,
    AgentRunId,
    AgentStepId,
    ToolCallId,
    ToolId,
    ToolInvocationRequest,
    ToolResultStatus,
)
from phoenix_os.agent.errors import AgentSchemaError, ToolExecutionError
from phoenix_os.agent.schemas import validate_tool_input
from phoenix_os.authority import AuthorityIntent
from phoenix_os.browser_automation.adapter import (
    BrowserPreparedEffect,
    BrowserPreparedEffectKind,
)
from phoenix_os.browser_automation.agent_tools import (
    BrowserToolAdapter,
    BrowserToolBinding,
    browser_tool_descriptor,
    browser_tool_resolver,
    browser_tool_resource,
)
from phoenix_os.browser_automation.authorization import (
    BROWSER_PAGE_READ_ACTION,
    BROWSER_SESSION_OPEN_ACTION,
    browser_element_click_intent,
    browser_element_fill_intent,
    browser_page_navigate_intent,
    browser_page_read_intent,
    browser_session_close_intent,
    browser_session_open_intent,
)
from phoenix_os.browser_automation.contracts import (
    BrowserAdapterId,
    BrowserElementAction,
    BrowserElementId,
    BrowserElementKind,
    BrowserNavigationTargetId,
    BrowserPageDescriptor,
    BrowserPageId,
    BrowserPageRevision,
    BrowserProfileId,
    BrowserSessionDescriptor,
    BrowserSessionId,
)
from phoenix_os.browser_automation.errors import BrowserAutomationIndeterminateEffectError
from phoenix_os.browser_automation.fake import (
    DeterministicBrowserAdapter,
    DeterministicBrowserElement,
    DeterministicBrowserPage,
)
from phoenix_os.browser_automation.profiles import (
    BrowserClickRequest,
    BrowserDestinationMode,
    BrowserNavigationRequest,
    BrowserNavigationTarget,
    BrowserOrigin,
    BrowserProfile,
    BrowserProfileLimits,
    BrowserRequestMethod,
    derive_browser_click_redirect_request,
)
from phoenix_os.browser_automation.service import BrowserAutomationService
from phoenix_os.policy import PrincipalType, SecurityContext

_NOW = datetime(2026, 8, 26, 12, tzinfo=UTC)
_PROFILE_ID = BrowserProfileId("browser-main")
_ADAPTER_ID = BrowserAdapterId("deterministic-browser")
_AGENT = AgentId("agent.browser")
_OTHER_AGENT = AgentId("agent.other")
_RUN_1 = AgentRunId(UUID("56000000-0000-4000-8000-000000000001"))
_RUN_2 = AgentRunId(UUID("56000000-0000-4000-8000-000000000002"))


class ProfileSource:
    def __init__(self, profile: BrowserProfile) -> None:
        self.profile = profile

    def require_profile(self, profile_id: BrowserProfileId) -> BrowserProfile:
        if profile_id != self.profile.profile_id:
            raise KeyError(profile_id)
        return self.profile


class Freshness:
    async def validate(self, context: SecurityContext) -> None:
        if not context.authenticated:
            raise RuntimeError("stale")


class AllowingAuthorizer:
    async def authorize_session_open(
        self,
        profile: BrowserProfile,
        session: BrowserSessionDescriptor,
        context: SecurityContext,
    ) -> AuthorityIntent:
        del context
        return browser_session_open_intent(profile, session)

    async def authorize_session_close(
        self,
        profile: BrowserProfile,
        session: BrowserSessionDescriptor,
        context: SecurityContext,
    ) -> AuthorityIntent:
        del context
        return browser_session_close_intent(profile, session)

    async def authorize_page_navigate(
        self,
        profile: BrowserProfile,
        session: BrowserSessionDescriptor,
        page: BrowserPageDescriptor,
        request: BrowserNavigationRequest,
        context: SecurityContext,
    ) -> AuthorityIntent:
        del context
        return browser_page_navigate_intent(profile, session, page, request)

    async def authorize_page_read(
        self,
        profile: BrowserProfile,
        session: BrowserSessionDescriptor,
        page: BrowserPageDescriptor,
        context: SecurityContext,
    ) -> AuthorityIntent:
        del context
        return browser_page_read_intent(profile, session, page)

    async def authorize_element_fill(
        self,
        profile: BrowserProfile,
        session: BrowserSessionDescriptor,
        page: BrowserPageDescriptor,
        prepared: BrowserPreparedEffect,
        context: SecurityContext,
    ) -> AuthorityIntent:
        del context
        return browser_element_fill_intent(profile, session, page, prepared)

    async def authorize_element_click(
        self,
        profile: BrowserProfile,
        session: BrowserSessionDescriptor,
        page: BrowserPageDescriptor,
        prepared: BrowserPreparedEffect,
        context: SecurityContext,
    ) -> AuthorityIntent:
        del context
        return browser_element_click_intent(profile, session, page, prepared)


class Resolver:
    def __init__(self, values: dict[str, tuple[str, ...]] | None = None) -> None:
        self.values = {"example.com": ("93.184.216.34",)} if values is None else values
        self.calls: list[str] = []

    async def resolve(
        self,
        host: str,
        port: int,
        *,
        max_addresses: int,
    ) -> tuple[str, ...]:
        del port, max_addresses
        self.calls.append(host)
        return self.values[host]


def _context() -> SecurityContext:
    return SecurityContext(
        principal="user:owner",
        principal_type=PrincipalType.USER,
        authenticated=True,
        session_id=UUID("57000000-0000-4000-8000-000000000001"),
    )


def _profile(
    *,
    extra_origin: BrowserOrigin | None = None,
    max_redirects: int = 5,
) -> BrowserProfile:
    origin = BrowserOrigin(BrowserDestinationMode.HOSTED_HTTPS, "example.com")
    origins = (origin,) if extra_origin is None else (origin, extra_origin)
    return BrowserProfile(
        profile_id=_PROFILE_ID,
        generation=7,
        adapter_id=_ADAPTER_ID,
        allowed_origins=origins,
        initial_targets=(
            BrowserNavigationTarget(
                BrowserNavigationTargetId("start"),
                origin,
                "/start",
            ),
        ),
        limits=BrowserProfileLimits(
            max_snapshot_title_chars=128,
            max_snapshot_text_chars=2048,
            max_snapshot_text_bytes=4096,
            max_snapshot_elements=16,
            max_element_name_chars=128,
            max_element_value_chars=128,
            max_fill_text_chars=128,
            max_fill_text_bytes=1024,
            max_redirects=max_redirects,
            session_ttl_seconds=60.0,
            operation_timeout_seconds=10.0,
            max_concurrent_sessions=8,
        ),
    )


def _remote_page(request: BrowserClickRequest) -> DeterministicBrowserPage:
    return DeterministicBrowserPage(
        title="before",
        text="before",
        elements=(
            DeterministicBrowserElement(
                key="go",
                kind=BrowserElementKind.LINK,
                name="Go",
                actions=(BrowserElementAction.CLICK,),
                click_request=request,
            ),
        ),
    )


def _local_page() -> DeterministicBrowserPage:
    return DeterministicBrowserPage(
        title="before",
        text="before",
        elements=(
            DeterministicBrowserElement(
                key="toggle",
                kind=BrowserElementKind.CHECKBOX,
                name="Toggle",
                actions=(BrowserElementAction.CLICK,),
            ),
        ),
    )


def _service(
    profile: BrowserProfile,
    adapter: DeterministicBrowserAdapter,
    resolver: Resolver | None = None,
) -> BrowserAutomationService:
    return BrowserAutomationService(
        profiles=ProfileSource(profile),
        adapter_id=_ADAPTER_ID,
        adapter=adapter,
        authorizer=AllowingAuthorizer(),
        freshness=Freshness(),
        network_resolver=resolver,
        clock=lambda: _NOW,
    )


async def _opened_remote(
    *,
    request: BrowserClickRequest,
    click_redirects: tuple[tuple[int, str], ...] = (),
    profile: BrowserProfile | None = None,
    resolver: Resolver | None = None,
) -> tuple[BrowserAutomationService, BrowserPageDescriptor, DeterministicBrowserAdapter]:
    selected = _profile() if profile is None else profile
    adapter = DeterministicBrowserAdapter(
        initial_page=_remote_page(request),
        click_redirects=click_redirects,
    )
    service = _service(selected, adapter, resolver or Resolver())
    opened = await service.open_session(_PROFILE_ID, _context())
    return service, opened.page, adapter


@pytest.mark.asyncio
async def test_local_click_requires_no_network_and_advances_once() -> None:
    profile = _profile()
    adapter = DeterministicBrowserAdapter(initial_page=_local_page())
    service = _service(profile, adapter)
    opened = await service.open_session(_PROFILE_ID, _context())
    element = (await service.read_page(opened.page, _context())).elements[0]
    final_calls = 0

    async def final_admission() -> None:
        nonlocal final_calls
        final_calls += 1

    result = await service.click_element(
        opened.page,
        element.element_id,
        _context(),
        final_admission=final_admission,
    )

    assert result.effect_started is True
    assert result.revision is not None
    assert result.revision.value == opened.page.revision.value + 1
    assert final_calls == 1


@pytest.mark.asyncio
async def test_remote_click_binds_exact_request_and_advances_once() -> None:
    origin = BrowserOrigin(BrowserDestinationMode.HOSTED_HTTPS, "example.com")
    request = BrowserClickRequest(origin=origin, request_target="/next")
    service, page, _ = await _opened_remote(request=request)
    element = (await service.read_page(page, _context())).elements[0]
    final_calls = 0

    async def final_admission() -> None:
        nonlocal final_calls
        final_calls += 1

    result = await service.click_element(
        page,
        element.element_id,
        _context(),
        final_admission=final_admission,
    )

    assert result.effect_started is True
    assert result.revision is not None
    assert result.revision.value == page.revision.value + 1
    assert final_calls == 1


@pytest.mark.asyncio
async def test_click_redirect_re_admits_every_hop_and_revalidates_tool_boundary() -> None:
    origin = BrowserOrigin(BrowserDestinationMode.HOSTED_HTTPS, "example.com")
    request = BrowserClickRequest(origin=origin, request_target="/next")
    resolver = Resolver()
    service, page, _ = await _opened_remote(
        request=request,
        click_redirects=((302, "/after"),),
        resolver=resolver,
    )
    element = (await service.read_page(page, _context())).elements[0]
    calls = 0

    async def final_admission() -> None:
        nonlocal calls
        calls += 1

    result = await service.click_element(
        page,
        element.element_id,
        _context(),
        final_admission=final_admission,
    )

    assert result.revision is not None and result.revision.value == page.revision.value + 1
    assert resolver.calls == ["example.com", "example.com"]
    assert calls == 2


@pytest.mark.asyncio
async def test_click_unsafe_redirect_after_first_request_is_indeterminate() -> None:
    origin = BrowserOrigin(BrowserDestinationMode.HOSTED_HTTPS, "example.com")
    other = BrowserOrigin(BrowserDestinationMode.HOSTED_HTTPS, "other.example")
    profile = _profile(extra_origin=other)
    request = BrowserClickRequest(origin=origin, request_target="/next")
    resolver = Resolver(
        {
            "example.com": ("93.184.216.34",),
            "other.example": ("127.0.0.1",),
        }
    )
    service, page, adapter = await _opened_remote(
        request=request,
        click_redirects=((302, "https://other.example/blocked"),),
        profile=profile,
        resolver=resolver,
    )
    element = (await service.read_page(page, _context())).elements[0]

    with pytest.raises(BrowserAutomationIndeterminateEffectError):
        await service.click_element(page, element.element_id, _context())

    assert adapter.session_count == 0


def test_post_redirect_semantics_are_finite_and_fail_closed() -> None:
    profile = _profile()
    origin = profile.allowed_origins[0]
    body_digest = "sha256:" + hashlib.sha256(b"a=1").hexdigest()
    post = BrowserClickRequest(
        origin=origin,
        request_target="/submit",
        method=BrowserRequestMethod.POST,
        body_digest=body_digest,
    )

    see_other = derive_browser_click_redirect_request(profile, post, "/done", 303)
    assert see_other.method is BrowserRequestMethod.GET
    assert see_other.body_digest is None

    replay = derive_browser_click_redirect_request(profile, post, "/again", 307)
    assert replay.method is BrowserRequestMethod.POST
    assert replay.body_digest == body_digest

    with pytest.raises(ValueError):
        derive_browser_click_redirect_request(profile, post, "/ambiguous", 302)


def test_click_authority_digest_changes_with_exact_remote_effect_plan() -> None:
    profile = _profile()
    origin = profile.allowed_origins[0]
    session = BrowserSessionDescriptor(
        profile_id=profile.profile_id,
        profile_generation=profile.generation,
        session_id=BrowserSessionId(),
        page_id=BrowserPageId(),
        created_at=_NOW,
        expires_at=_NOW + timedelta(seconds=30),
    )
    page = BrowserPageDescriptor(
        session_id=session.session_id,
        page_id=session.page_id,
        revision=BrowserPageRevision(1),
    )
    first = BrowserPreparedEffect(
        token=uuid4(),
        kind=BrowserPreparedEffectKind.CLICK,
        session_id=session.session_id,
        page_id=session.page_id,
        revision=page.revision,
        element_id=BrowserElementId(),
        request=BrowserClickRequest(origin=origin, request_target="/a"),
    )
    second = BrowserPreparedEffect(
        token=first.token,
        kind=first.kind,
        session_id=first.session_id,
        page_id=first.page_id,
        revision=first.revision,
        element_id=first.element_id,
        request=BrowserClickRequest(origin=origin, request_target="/b"),
    )

    assert (
        browser_element_click_intent(profile, session, page, first).parameter_digest
        != browser_element_click_intent(profile, session, page, second).parameter_digest
    )


def _binding(
    *,
    action: str,
    tool_id: str,
    profile: BrowserProfile,
) -> BrowserToolBinding:
    return BrowserToolBinding(
        agent_id=_AGENT,
        tool_id=ToolId(tool_id),
        browser_action=action,
        profile_id=profile.profile_id,
        profile_generation=profile.generation,
    )


def _tool_request(
    binding: BrowserToolBinding,
    *,
    run_id: AgentRunId,
    arguments: Mapping[str, AgentJsonInput],
    agent_id: AgentId = _AGENT,
) -> ToolInvocationRequest:
    return ToolInvocationRequest(
        agent_id=agent_id,
        run_id=run_id,
        step_id=AgentStepId(),
        call_id=ToolCallId(),
        tool_id=binding.tool_id,
        arguments=arguments,
        resolved_resource=browser_tool_resource(binding),
        created_at=_NOW,
        deadline=_NOW + timedelta(seconds=10),
    )


@pytest.mark.asyncio
async def test_browser_tool_binding_rejects_wrong_agent_and_escape_arguments() -> None:
    profile = _profile()
    adapter = DeterministicBrowserAdapter(initial_page=DeterministicBrowserPage())
    service = _service(profile, adapter, Resolver())
    binding = _binding(
        action=BROWSER_SESSION_OPEN_ACTION,
        tool_id="browser.open",
        profile=profile,
    )
    descriptor = browser_tool_descriptor(binding, profile)
    resolver = browser_tool_resolver(binding)
    assert resolver.resolve_resource({}) == browser_tool_resource(binding)

    with pytest.raises(AgentSchemaError):
        validate_tool_input(descriptor.input_schema, {"url": "https://evil.example"})

    tool = BrowserToolAdapter(service, binding=binding, profile=profile)
    request = _tool_request(binding, run_id=_RUN_1, arguments={}, agent_id=_OTHER_AGENT)

    async def final_admission() -> None:
        return None

    with pytest.raises(ToolExecutionError):
        await tool.invoke_with_context_and_final_admission(
            request,
            _context(),
            final_admission,
        )


@pytest.mark.asyncio
async def test_tool_opened_session_is_bound_to_exact_agent_run() -> None:
    profile = _profile()
    browser_adapter = DeterministicBrowserAdapter(initial_page=DeterministicBrowserPage())
    service = _service(profile, browser_adapter, Resolver())

    open_binding = _binding(
        action=BROWSER_SESSION_OPEN_ACTION,
        tool_id="browser.open",
        profile=profile,
    )
    read_binding = _binding(
        action=BROWSER_PAGE_READ_ACTION,
        tool_id="browser.read",
        profile=profile,
    )
    open_tool = BrowserToolAdapter(service, binding=open_binding, profile=profile)
    read_tool = BrowserToolAdapter(service, binding=read_binding, profile=profile)

    final_calls = 0

    async def final_admission() -> None:
        nonlocal final_calls
        final_calls += 1

    opened = await open_tool.invoke_with_context_and_final_admission(
        _tool_request(open_binding, run_id=_RUN_1, arguments={}),
        _context(),
        final_admission,
    )
    assert opened.status is ToolResultStatus.SUCCEEDED
    assert opened.output is not None
    session_id = opened.output["session_id"]
    page_id = opened.output["page_id"]
    revision = opened.output["revision"]
    assert isinstance(session_id, str)
    assert isinstance(page_id, str)
    assert isinstance(revision, int) and not isinstance(revision, bool)

    args: dict[str, AgentJsonInput] = {
        "session_id": session_id,
        "page_id": page_id,
        "revision": revision,
    }
    with pytest.raises(ToolExecutionError):
        await read_tool.invoke_with_context_and_final_admission(
            _tool_request(read_binding, run_id=_RUN_2, arguments=args),
            _context(),
            final_admission,
        )

    same_run = await read_tool.invoke_with_context_and_final_admission(
        _tool_request(read_binding, run_id=_RUN_1, arguments=args),
        _context(),
        final_admission,
    )
    assert same_run.status is ToolResultStatus.SUCCEEDED
    assert final_calls == 2
