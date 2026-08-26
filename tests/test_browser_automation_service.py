from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from phoenix_os.authority import AuthorityIntent
from phoenix_os.browser_automation.adapter import (
    BrowserAdapterCommitResult,
    BrowserNavigationCommitResult,
    BrowserPreparedEffect,
    BrowserPreparedNavigation,
    BrowserPreparedNavigationPlan,
)
from phoenix_os.browser_automation.authorization import (
    BrowserAuthorizer,
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
    BrowserFillInput,
    BrowserNavigationTargetId,
    BrowserPageDescriptor,
    BrowserPageRevision,
    BrowserPageSnapshot,
    BrowserProfileId,
    BrowserSessionDescriptor,
    BrowserSessionId,
)
from phoenix_os.browser_automation.errors import (
    BrowserAutomationAdapterError,
    BrowserAutomationCancelledError,
    BrowserAutomationIndeterminateEffectError,
    BrowserAutomationLimitExceededError,
    BrowserAutomationOperationDisabledError,
    BrowserAutomationRejectedError,
    BrowserAutomationStaleError,
    BrowserAutomationTargetNotFoundError,
    BrowserAutomationTimeoutError,
)
from phoenix_os.browser_automation.fake import (
    DeterministicBrowserAdapter,
    DeterministicBrowserElement,
    DeterministicBrowserPage,
)
from phoenix_os.browser_automation.network import BrowserNetworkResolver
from phoenix_os.browser_automation.profiles import (
    BrowserDestinationMode,
    BrowserNavigationRequest,
    BrowserNavigationTarget,
    BrowserOrigin,
    BrowserProfile,
    BrowserProfileLimits,
)
from phoenix_os.browser_automation.service import (
    BrowserAutomationCancellationToken,
    BrowserAutomationService,
    BrowserSessionOpenResult,
)
from phoenix_os.policy import PrincipalType, SecurityContext

_NOW = datetime(2026, 8, 25, 12, tzinfo=UTC)
_ADAPTER_ID = BrowserAdapterId("deterministic-browser")
_PROFILE_ID = BrowserProfileId("browser-main")
_SESSION_A = UUID("45000000-0000-4000-8000-000000000001")
_SESSION_B = UUID("45000000-0000-4000-8000-000000000002")


@dataclass
class MutableClock:
    value: datetime = _NOW

    def __call__(self) -> datetime:
        return self.value


class MutableProfileSource:
    def __init__(self, profile: BrowserProfile) -> None:
        self.profile = profile

    def require_profile(self, profile_id: BrowserProfileId) -> BrowserProfile:
        if profile_id != self.profile.profile_id:
            raise KeyError(profile_id)
        return self.profile


class OneShotProfileSnapshotSource(MutableProfileSource):
    def __init__(self, profile: BrowserProfile) -> None:
        super().__init__(profile)
        self._snapshot_once: BrowserProfile | None = None

    def snapshot_once(self, profile: BrowserProfile) -> None:
        self._snapshot_once = profile

    def require_profile(self, profile_id: BrowserProfileId) -> BrowserProfile:
        if self._snapshot_once is not None:
            profile = self._snapshot_once
            self._snapshot_once = None
            if profile_id != profile.profile_id:
                raise KeyError(profile_id)
            return profile
        return super().require_profile(profile_id)


class RecordingFreshness:
    def __init__(self) -> None:
        self.calls = 0
        self.active = True
        self.hook: Callable[[int], Awaitable[None] | None] | None = None

    async def validate(self, context: SecurityContext) -> None:
        del context
        self.calls += 1
        if self.hook is not None:
            result = self.hook(self.calls)
            if result is not None:
                await result
        if not self.active:
            raise RuntimeError("revoked")


class RecordingAuthorizer:
    def __init__(self) -> None:
        self.calls: list[str] = []
        self.deny: set[str] = set()
        self.hook: Callable[..., Awaitable[None] | None] | None = None
        self.wrong_fill_intent = False

    async def _before(self, name: str, *args: object) -> None:
        self.calls.append(name)
        if self.hook is not None:
            result = self.hook(name, *args)
            if result is not None:
                await result
        if name in self.deny:
            raise RuntimeError("denied")

    async def authorize_session_open(
        self,
        profile: BrowserProfile,
        session: BrowserSessionDescriptor,
        context: SecurityContext,
    ) -> AuthorityIntent:
        await self._before("open", profile, session, context)
        return browser_session_open_intent(profile, session)

    async def authorize_session_close(
        self,
        profile: BrowserProfile,
        session: BrowserSessionDescriptor,
        context: SecurityContext,
    ) -> AuthorityIntent:
        await self._before("close", profile, session, context)
        return browser_session_close_intent(profile, session)

    async def authorize_page_navigate(
        self,
        profile: BrowserProfile,
        session: BrowserSessionDescriptor,
        page: BrowserPageDescriptor,
        request: BrowserNavigationRequest,
        context: SecurityContext,
    ) -> AuthorityIntent:
        await self._before("navigate", profile, session, page, request, context)
        return browser_page_navigate_intent(profile, session, page, request)

    async def authorize_page_read(
        self,
        profile: BrowserProfile,
        session: BrowserSessionDescriptor,
        page: BrowserPageDescriptor,
        context: SecurityContext,
    ) -> AuthorityIntent:
        await self._before("read", profile, session, page, context)
        return browser_page_read_intent(profile, session, page)

    async def authorize_element_fill(
        self,
        profile: BrowserProfile,
        session: BrowserSessionDescriptor,
        page: BrowserPageDescriptor,
        prepared: BrowserPreparedEffect,
        context: SecurityContext,
    ) -> AuthorityIntent:
        await self._before("fill", profile, session, page, prepared, context)
        if self.wrong_fill_intent:
            return browser_page_read_intent(profile, session, page)
        return browser_element_fill_intent(profile, session, page, prepared)

    async def authorize_element_click(
        self,
        profile: BrowserProfile,
        session: BrowserSessionDescriptor,
        page: BrowserPageDescriptor,
        prepared: BrowserPreparedEffect,
        context: SecurityContext,
    ) -> AuthorityIntent:
        await self._before("click", profile, session, page, prepared, context)
        return browser_element_click_intent(profile, session, page, prepared)


class CountingAdapter(DeterministicBrowserAdapter):
    def __init__(
        self,
        *,
        adapter_id: BrowserAdapterId | str = "deterministic-browser",
        initial_page: DeterministicBrowserPage | None = None,
        redirect_locations: tuple[str, ...] = (),
    ) -> None:
        super().__init__(
            adapter_id=adapter_id,
            initial_page=initial_page,
            redirect_locations=redirect_locations,
        )
        self.snapshot_calls = 0
        self.prepare_navigation_calls = 0
        self.commit_navigation_calls = 0
        self.prepare_fill_calls = 0
        self.commit_calls = 0

    async def snapshot(self, page: BrowserPageDescriptor) -> BrowserPageSnapshot:
        self.snapshot_calls += 1
        return await super().snapshot(page)

    async def prepare_navigation(
        self,
        page: BrowserPageDescriptor,
        request: BrowserNavigationRequest,
    ) -> BrowserPreparedNavigationPlan:
        self.prepare_navigation_calls += 1
        return await super().prepare_navigation(page, request)

    async def commit_navigation(
        self,
        prepared: BrowserPreparedNavigation,
    ) -> BrowserNavigationCommitResult:
        self.commit_navigation_calls += 1
        return await super().commit_navigation(prepared)

    async def prepare_fill(
        self,
        page: BrowserPageDescriptor,
        element_id: BrowserElementId,
        value: BrowserFillInput,
    ) -> BrowserPreparedEffect:
        self.prepare_fill_calls += 1
        return await super().prepare_fill(page, element_id, value)

    async def commit_prepared(
        self,
        prepared: BrowserPreparedEffect,
    ) -> BrowserAdapterCommitResult:
        self.commit_calls += 1
        return await super().commit_prepared(prepared)


class RaisingAfterNavigationCommitAdapter(CountingAdapter):
    async def commit_navigation(
        self,
        prepared: BrowserPreparedNavigation,
    ) -> BrowserNavigationCommitResult:
        self.commit_navigation_calls += 1
        await DeterministicBrowserAdapter.commit_navigation(self, prepared)
        raise BrowserAutomationAdapterError()


class StaticBrowserResolver:
    def __init__(
        self,
        addresses: tuple[str, ...] | dict[str, tuple[str, ...]],
    ) -> None:
        self.addresses = addresses
        self.calls: list[tuple[str, int, int]] = []

    async def resolve(
        self,
        host: str,
        port: int,
        *,
        max_addresses: int,
    ) -> tuple[str, ...]:
        self.calls.append((host, port, max_addresses))
        if isinstance(self.addresses, dict):
            try:
                return self.addresses[host]
            except KeyError:
                raise OSError("resolver host not configured") from None
        return self.addresses


class RevokingSnapshotAdapter(CountingAdapter):
    def __init__(
        self,
        freshness: RecordingFreshness,
        *,
        adapter_id: BrowserAdapterId | str = "deterministic-browser",
        initial_page: DeterministicBrowserPage | None = None,
    ) -> None:
        super().__init__(adapter_id=adapter_id, initial_page=initial_page)
        self._freshness = freshness

    async def snapshot(self, page: BrowserPageDescriptor) -> BrowserPageSnapshot:
        snapshot = await super().snapshot(page)
        self._freshness.active = False
        return snapshot


class OversizedSnapshotAdapter(CountingAdapter):
    async def snapshot(self, page: BrowserPageDescriptor) -> BrowserPageSnapshot:
        self.snapshot_calls += 1
        return BrowserPageSnapshot(
            session_id=page.session_id,
            page_id=page.page_id,
            revision=page.revision,
            title="too-long",
            text="",
            elements=(),
            created_at=_NOW,
        )


class RaisingAfterCommitAdapter(CountingAdapter):
    async def commit_prepared(
        self,
        prepared: BrowserPreparedEffect,
    ) -> BrowserAdapterCommitResult:
        self.commit_calls += 1
        await DeterministicBrowserAdapter.commit_prepared(self, prepared)
        raise BrowserAutomationAdapterError()


class BlockingAfterCommitAdapter(CountingAdapter):
    def __init__(
        self,
        *,
        adapter_id: BrowserAdapterId | str = "deterministic-browser",
        initial_page: DeterministicBrowserPage | None = None,
    ) -> None:
        super().__init__(adapter_id=adapter_id, initial_page=initial_page)
        self.effect_started = asyncio.Event()
        self.release = asyncio.Event()

    async def commit_prepared(
        self,
        prepared: BrowserPreparedEffect,
    ) -> BrowserAdapterCommitResult:
        self.commit_calls += 1
        result = await DeterministicBrowserAdapter.commit_prepared(self, prepared)
        self.effect_started.set()
        await self.release.wait()
        return result


class BlockingCloseAdapter(CountingAdapter):
    def __init__(
        self,
        *,
        adapter_id: BrowserAdapterId | str = "deterministic-browser",
        initial_page: DeterministicBrowserPage | None = None,
    ) -> None:
        super().__init__(adapter_id=adapter_id, initial_page=initial_page)
        self.close_started = asyncio.Event()
        self.release_close = asyncio.Event()

    async def close_session(self, session_id: BrowserSessionId) -> None:
        self.close_started.set()
        await self.release_close.wait()
        await super().close_session(session_id)


class BlockingDiscardAdapter(CountingAdapter):
    def __init__(
        self,
        *,
        adapter_id: BrowserAdapterId | str = "deterministic-browser",
        initial_page: DeterministicBrowserPage | None = None,
    ) -> None:
        super().__init__(adapter_id=adapter_id, initial_page=initial_page)
        self.discard_started = asyncio.Event()
        self.release_discard = asyncio.Event()

    async def discard_prepared(self, prepared: BrowserPreparedEffect) -> None:
        self.discard_started.set()
        await self.release_discard.wait()
        await super().discard_prepared(prepared)


class SuppressingCancellationSnapshotAdapter(CountingAdapter):
    def __init__(
        self,
        *,
        adapter_id: BrowserAdapterId | str = "deterministic-browser",
        initial_page: DeterministicBrowserPage | None = None,
    ) -> None:
        super().__init__(adapter_id=adapter_id, initial_page=initial_page)
        self.snapshot_started = asyncio.Event()
        self.cancel_suppressed = asyncio.Event()
        self.release_snapshot = asyncio.Event()

    async def snapshot(self, page: BrowserPageDescriptor) -> BrowserPageSnapshot:
        self.snapshot_calls += 1
        self.snapshot_started.set()
        try:
            await self.release_snapshot.wait()
        except asyncio.CancelledError:
            self.cancel_suppressed.set()
            await self.release_snapshot.wait()
        return await DeterministicBrowserAdapter.snapshot(self, page)


class SuppressingCancellationCloseAdapter(CountingAdapter):
    def __init__(
        self,
        *,
        adapter_id: BrowserAdapterId | str = "deterministic-browser",
        initial_page: DeterministicBrowserPage | None = None,
    ) -> None:
        super().__init__(adapter_id=adapter_id, initial_page=initial_page)
        self.close_started = asyncio.Event()
        self.cancel_suppressed = asyncio.Event()
        self.release_close = asyncio.Event()

    async def close_session(self, session_id: BrowserSessionId) -> None:
        self.close_started.set()
        try:
            await self.release_close.wait()
        except asyncio.CancelledError:
            self.cancel_suppressed.set()
            await self.release_close.wait()
        await super().close_session(session_id)


class SuppressingCancellationCommitAdapter(CountingAdapter):
    def __init__(
        self,
        *,
        adapter_id: BrowserAdapterId | str = "deterministic-browser",
        initial_page: DeterministicBrowserPage | None = None,
    ) -> None:
        super().__init__(adapter_id=adapter_id, initial_page=initial_page)
        self.effect_started = asyncio.Event()
        self.cancel_suppressed = asyncio.Event()
        self.release_commit = asyncio.Event()

    async def commit_prepared(
        self,
        prepared: BrowserPreparedEffect,
    ) -> BrowserAdapterCommitResult:
        self.commit_calls += 1
        result = await DeterministicBrowserAdapter.commit_prepared(self, prepared)
        self.effect_started.set()
        try:
            await self.release_commit.wait()
        except asyncio.CancelledError:
            self.cancel_suppressed.set()
            await self.release_commit.wait()
        return result


async def _drain_abandoned_tasks(service: BrowserAutomationService) -> None:
    for _ in range(100):
        if not service._abandoned_tasks:
            return
        await asyncio.sleep(0.01)
    assert not service._abandoned_tasks


def _page_seed() -> DeterministicBrowserPage:
    return DeterministicBrowserPage(
        title="Local page",
        text="safe local content",
        elements=(
            DeterministicBrowserElement(
                key="name",
                kind=BrowserElementKind.TEXT_INPUT,
                name="Name",
                value="before",
                actions=(BrowserElementAction.FILL,),
            ),
            DeterministicBrowserElement(
                key="submit",
                kind=BrowserElementKind.BUTTON,
                name="Submit",
                actions=(BrowserElementAction.CLICK,),
            ),
        ),
    )


def _profile(
    *,
    generation: int = 7,
    max_concurrent_sessions: int = 8,
    max_snapshot_title_chars: int = 128,
    max_fill_text_chars: int = 128,
    max_redirects: int = 5,
    extra_origin: BrowserOrigin | None = None,
    session_ttl_seconds: float = 60.0,
    operation_timeout_seconds: float = 10.0,
) -> BrowserProfile:
    origin = BrowserOrigin(BrowserDestinationMode.HOSTED_HTTPS, "example.com")
    allowed_origins = (origin,) if extra_origin is None else (origin, extra_origin)
    return BrowserProfile(
        profile_id=_PROFILE_ID,
        generation=generation,
        adapter_id=_ADAPTER_ID,
        allowed_origins=allowed_origins,
        initial_targets=(
            BrowserNavigationTarget(
                target_id=BrowserNavigationTargetId("start"),
                origin=origin,
                request_target="/start",
            ),
        ),
        limits=BrowserProfileLimits(
            max_snapshot_title_chars=max_snapshot_title_chars,
            max_snapshot_text_chars=4096,
            max_snapshot_text_bytes=8192,
            max_snapshot_elements=16,
            max_element_name_chars=128,
            max_element_value_chars=128,
            max_fill_text_chars=max_fill_text_chars,
            max_fill_text_bytes=4096,
            max_redirects=max_redirects,
            session_ttl_seconds=session_ttl_seconds,
            operation_timeout_seconds=operation_timeout_seconds,
            max_concurrent_sessions=max_concurrent_sessions,
        ),
    )


def _context(
    *,
    principal: str = "user:owner",
    session_id: UUID = _SESSION_A,
) -> SecurityContext:
    return SecurityContext(
        principal=principal,
        principal_type=PrincipalType.USER,
        authenticated=True,
        session_id=session_id,
    )


def _service(
    *,
    profile: BrowserProfile | None = None,
    adapter: DeterministicBrowserAdapter | None = None,
    authorizer: RecordingAuthorizer | None = None,
    freshness: RecordingFreshness | None = None,
    network_resolver: BrowserNetworkResolver | None = None,
    clock: MutableClock | None = None,
) -> tuple[
    BrowserAutomationService,
    MutableProfileSource,
    DeterministicBrowserAdapter,
    RecordingAuthorizer,
    RecordingFreshness,
    MutableClock,
]:
    selected_profile = _profile() if profile is None else profile
    source = MutableProfileSource(selected_profile)
    selected_adapter = CountingAdapter(initial_page=_page_seed()) if adapter is None else adapter
    selected_authorizer = RecordingAuthorizer() if authorizer is None else authorizer
    selected_freshness = RecordingFreshness() if freshness is None else freshness
    selected_clock = MutableClock() if clock is None else clock
    service = BrowserAutomationService(
        profiles=source,
        adapter_id=_ADAPTER_ID,
        adapter=selected_adapter,
        authorizer=selected_authorizer,
        freshness=selected_freshness,
        network_resolver=network_resolver,
        clock=selected_clock,
    )
    return (
        service,
        source,
        selected_adapter,
        selected_authorizer,
        selected_freshness,
        selected_clock,
    )


@pytest.mark.asyncio
async def test_open_session_is_server_owned_generation_bound_and_exactly_authorized() -> None:
    service, _, adapter, authorizer, freshness, _ = _service()

    result = await service.open_session(_PROFILE_ID, _context())

    assert isinstance(result, BrowserSessionOpenResult)
    assert result.session.profile_id == _PROFILE_ID
    assert result.session.profile_generation == 7
    assert result.page.session_id == result.session.session_id
    assert result.page.page_id == result.session.page_id
    assert result.page.revision == BrowserPageRevision(1)
    assert adapter.session_count == 1
    assert authorizer.calls == ["open"]
    assert freshness.calls == 1


@pytest.mark.asyncio
async def test_read_page_reauthorizes_after_snapshot_before_disclosure() -> None:
    service, _, adapter, authorizer, freshness, _ = _service()
    opened = await service.open_session(_PROFILE_ID, _context())
    authorizer.calls.clear()
    freshness.calls = 0

    snapshot = await service.read_page(opened.page, _context())

    assert snapshot.text == "safe local content"
    assert authorizer.calls == ["read", "read"]
    assert freshness.calls == 2
    assert isinstance(adapter, CountingAdapter)
    assert adapter.snapshot_calls == 1


@pytest.mark.asyncio
async def test_revocation_after_snapshot_blocks_content_disclosure() -> None:
    freshness = RecordingFreshness()
    adapter = RevokingSnapshotAdapter(freshness, initial_page=_page_seed())
    service, _, _, authorizer, _, _ = _service(adapter=adapter, freshness=freshness)
    opened = await service.open_session(_PROFILE_ID, _context())
    authorizer.calls.clear()
    freshness.calls = 0

    with pytest.raises(BrowserAutomationRejectedError):
        await service.read_page(opened.page, _context())

    assert authorizer.calls == ["read"]
    assert freshness.calls == 2


@pytest.mark.asyncio
async def test_cross_subject_or_session_identity_never_uses_opaque_id_as_authority() -> None:
    service, _, adapter, _, _, _ = _service()
    opened = await service.open_session(_PROFILE_ID, _context())
    assert isinstance(adapter, CountingAdapter)
    before = adapter.snapshot_calls

    with pytest.raises(BrowserAutomationRejectedError):
        await service.read_page(
            opened.page,
            _context(principal="user:other", session_id=_SESSION_B),
        )

    assert adapter.snapshot_calls == before


@pytest.mark.asyncio
async def test_profile_generation_drift_invalidates_and_cleans_session() -> None:
    service, source, adapter, _, _, _ = _service()
    opened = await service.open_session(_PROFILE_ID, _context())
    source.profile = _profile(generation=8)

    with pytest.raises(BrowserAutomationStaleError):
        await service.read_page(opened.page, _context())

    assert adapter.session_count == 0


@pytest.mark.asyncio
async def test_same_generation_security_relevant_profile_drift_is_stale() -> None:
    service, source, adapter, _, _, _ = _service()
    opened = await service.open_session(_PROFILE_ID, _context())
    source.profile = _profile(generation=7, max_fill_text_chars=64)

    with pytest.raises(BrowserAutomationStaleError):
        await service.read_page(opened.page, _context())

    assert adapter.session_count == 0


@pytest.mark.asyncio
async def test_session_expiry_is_stale_and_cleanup_releases_adapter_state() -> None:
    clock = MutableClock()
    service, _, adapter, _, _, _ = _service(
        profile=_profile(session_ttl_seconds=2.0, operation_timeout_seconds=1.0),
        clock=clock,
    )
    opened = await service.open_session(_PROFILE_ID, _context())
    clock.value += timedelta(seconds=3)

    with pytest.raises(BrowserAutomationStaleError):
        await service.read_page(opened.page, _context())

    assert adapter.session_count == 0


@pytest.mark.asyncio
async def test_service_rechecks_profile_specific_snapshot_limits() -> None:
    adapter = OversizedSnapshotAdapter(initial_page=_page_seed())
    service, _, _, _, _, _ = _service(
        profile=_profile(max_snapshot_title_chars=3),
        adapter=adapter,
    )
    opened = await service.open_session(_PROFILE_ID, _context())

    with pytest.raises(BrowserAutomationAdapterError):
        await service.read_page(opened.page, _context())

    assert adapter.session_count == 0


@pytest.mark.asyncio
async def test_navigation_is_server_owned_network_admitted_and_advances_one_revision() -> None:
    resolver = StaticBrowserResolver(("8.8.8.8",))
    adapter = CountingAdapter(initial_page=_page_seed())
    service, _, _, authorizer, freshness, _ = _service(
        adapter=adapter,
        network_resolver=resolver,
    )
    opened = await service.open_session(_PROFILE_ID, _context())
    authorizer.calls.clear()
    freshness.calls = 0

    result = await service.navigate(
        opened.page,
        BrowserNavigationTargetId("start"),
        _context(),
    )

    assert resolver.calls == [("example.com", 443, 16)]
    assert authorizer.calls == ["navigate"]
    assert freshness.calls == 1
    assert adapter.prepare_navigation_calls == 1
    assert adapter.commit_navigation_calls == 1
    assert result.effect_started is True
    assert result.revision == BrowserPageRevision(2)

    with pytest.raises(BrowserAutomationStaleError):
        await service.read_page(opened.page, _context())

    current_page = BrowserPageDescriptor(
        session_id=opened.page.session_id,
        page_id=opened.page.page_id,
        revision=BrowserPageRevision(2),
    )
    snapshot = await service.read_page(current_page, _context())
    assert snapshot.title == ""
    assert snapshot.text == ""
    assert snapshot.elements == ()


@pytest.mark.asyncio
async def test_navigation_follows_same_origin_redirect_with_fresh_admission_per_hop() -> None:
    resolver = StaticBrowserResolver(("8.8.8.8",))
    adapter = CountingAdapter(
        initial_page=_page_seed(),
        redirect_locations=("/next?step=1",),
    )
    service, _, _, authorizer, freshness, _ = _service(
        adapter=adapter,
        network_resolver=resolver,
    )
    opened = await service.open_session(_PROFILE_ID, _context())
    authorizer.calls.clear()
    freshness.calls = 0

    result = await service.navigate(
        opened.page,
        BrowserNavigationTargetId("start"),
        _context(),
    )

    assert resolver.calls == [
        ("example.com", 443, 16),
        ("example.com", 443, 16),
    ]
    assert authorizer.calls == ["navigate", "navigate"]
    assert freshness.calls == 2
    assert adapter.prepare_navigation_calls == 2
    assert adapter.commit_navigation_calls == 2
    assert result.revision == BrowserPageRevision(2)


@pytest.mark.asyncio
async def test_navigation_follows_cross_origin_redirect_only_when_exactly_allowed() -> None:
    second = BrowserOrigin(BrowserDestinationMode.HOSTED_HTTPS, "cdn.example.com")
    profile = _profile(extra_origin=second)
    resolver = StaticBrowserResolver(
        {
            "example.com": ("8.8.8.8",),
            "cdn.example.com": ("1.1.1.1",),
        }
    )
    adapter = CountingAdapter(
        initial_page=_page_seed(),
        redirect_locations=("https://cdn.example.com/final",),
    )
    service, _, _, authorizer, _, _ = _service(
        profile=profile,
        adapter=adapter,
        network_resolver=resolver,
    )
    opened = await service.open_session(_PROFILE_ID, _context())
    authorizer.calls.clear()

    result = await service.navigate(
        opened.page,
        BrowserNavigationTargetId("start"),
        _context(),
    )

    assert resolver.calls == [
        ("example.com", 443, 16),
        ("cdn.example.com", 443, 16),
    ]
    assert authorizer.calls == ["navigate", "navigate"]
    assert adapter.commit_navigation_calls == 2
    assert result.revision == BrowserPageRevision(2)


@pytest.mark.asyncio
async def test_navigation_redirect_cannot_grant_an_unconfigured_origin() -> None:
    resolver = StaticBrowserResolver(("8.8.8.8",))
    adapter = CountingAdapter(
        initial_page=_page_seed(),
        redirect_locations=("https://evil.example.net/next",),
    )
    service, _, _, _, _, _ = _service(
        adapter=adapter,
        network_resolver=resolver,
    )
    opened = await service.open_session(_PROFILE_ID, _context())

    with pytest.raises(BrowserAutomationIndeterminateEffectError):
        await service.navigate(
            opened.page,
            BrowserNavigationTargetId("start"),
            _context(),
        )

    assert resolver.calls == [("example.com", 443, 16)]
    assert adapter.prepare_navigation_calls == 1
    assert adapter.commit_navigation_calls == 1
    assert not service._sessions


@pytest.mark.asyncio
async def test_navigation_redirect_dns_rejection_after_first_request_is_indeterminate() -> None:
    second = BrowserOrigin(BrowserDestinationMode.HOSTED_HTTPS, "cdn.example.com")
    profile = _profile(extra_origin=second)
    resolver = StaticBrowserResolver(
        {
            "example.com": ("8.8.8.8",),
            "cdn.example.com": ("10.0.0.1",),
        }
    )
    adapter = CountingAdapter(
        initial_page=_page_seed(),
        redirect_locations=("https://cdn.example.com/final",),
    )
    service, _, _, _, _, _ = _service(
        profile=profile,
        adapter=adapter,
        network_resolver=resolver,
    )
    opened = await service.open_session(_PROFILE_ID, _context())

    with pytest.raises(BrowserAutomationIndeterminateEffectError):
        await service.navigate(
            opened.page,
            BrowserNavigationTargetId("start"),
            _context(),
        )

    assert resolver.calls == [
        ("example.com", 443, 16),
        ("cdn.example.com", 443, 16),
    ]
    assert adapter.prepare_navigation_calls == 2
    assert adapter.commit_navigation_calls == 1
    assert adapter.prepared_count == 0
    assert not service._sessions


@pytest.mark.asyncio
async def test_navigation_redirect_limit_is_finite_and_never_retries_a_hop() -> None:
    resolver = StaticBrowserResolver(("8.8.8.8",))
    adapter = CountingAdapter(
        initial_page=_page_seed(),
        redirect_locations=("/one", "/two"),
    )
    service, _, _, _, _, _ = _service(
        profile=_profile(max_redirects=1),
        adapter=adapter,
        network_resolver=resolver,
    )
    opened = await service.open_session(_PROFILE_ID, _context())

    with pytest.raises(BrowserAutomationIndeterminateEffectError):
        await service.navigate(
            opened.page,
            BrowserNavigationTargetId("start"),
            _context(),
        )

    assert resolver.calls == [
        ("example.com", 443, 16),
        ("example.com", 443, 16),
    ]
    assert adapter.prepare_navigation_calls == 2
    assert adapter.commit_navigation_calls == 2
    assert not service._sessions


@pytest.mark.asyncio
async def test_navigation_unknown_target_fails_before_adapter_or_network() -> None:
    resolver = StaticBrowserResolver(("8.8.8.8",))
    adapter = CountingAdapter(initial_page=_page_seed())
    service, _, _, _, _, _ = _service(
        adapter=adapter,
        network_resolver=resolver,
    )
    opened = await service.open_session(_PROFILE_ID, _context())

    with pytest.raises(BrowserAutomationTargetNotFoundError):
        await service.navigate(
            opened.page,
            BrowserNavigationTargetId("missing"),
            _context(),
        )

    assert adapter.prepare_navigation_calls == 0
    assert adapter.commit_navigation_calls == 0
    assert resolver.calls == []


@pytest.mark.asyncio
async def test_navigation_unsafe_dns_answer_rejects_before_remote_commit() -> None:
    resolver = StaticBrowserResolver(("10.0.0.1",))
    adapter = CountingAdapter(initial_page=_page_seed())
    service, _, _, _, _, _ = _service(
        adapter=adapter,
        network_resolver=resolver,
    )
    opened = await service.open_session(_PROFILE_ID, _context())

    with pytest.raises(BrowserAutomationRejectedError):
        await service.navigate(
            opened.page,
            BrowserNavigationTargetId("start"),
            _context(),
        )

    assert adapter.prepare_navigation_calls == 1
    assert adapter.commit_navigation_calls == 0
    assert adapter.prepared_count == 0
    unchanged = await service.read_page(opened.page, _context())
    assert unchanged.text == "safe local content"


@pytest.mark.asyncio
async def test_navigation_authority_denial_discards_without_remote_commit() -> None:
    resolver = StaticBrowserResolver(("8.8.8.8",))
    adapter = CountingAdapter(initial_page=_page_seed())
    authorizer = RecordingAuthorizer()
    authorizer.deny.add("navigate")
    service, _, _, _, _, _ = _service(
        adapter=adapter,
        authorizer=authorizer,
        network_resolver=resolver,
    )
    opened = await service.open_session(_PROFILE_ID, _context())

    with pytest.raises(BrowserAutomationRejectedError):
        await service.navigate(
            opened.page,
            BrowserNavigationTargetId("start"),
            _context(),
        )

    assert resolver.calls == [("example.com", 443, 16)]
    assert adapter.commit_navigation_calls == 0
    assert adapter.prepared_count == 0


@pytest.mark.asyncio
async def test_navigation_requires_explicit_reviewed_network_resolver() -> None:
    adapter = CountingAdapter(initial_page=_page_seed())
    service, _, _, _, _, _ = _service(adapter=adapter)
    opened = await service.open_session(_PROFILE_ID, _context())

    with pytest.raises(BrowserAutomationOperationDisabledError):
        await service.navigate(
            opened.page,
            BrowserNavigationTargetId("start"),
            _context(),
        )

    assert adapter.prepare_navigation_calls == 1
    assert adapter.commit_navigation_calls == 0
    assert adapter.prepared_count == 0


@pytest.mark.asyncio
async def test_navigation_failure_after_possible_request_is_indeterminate() -> None:
    resolver = StaticBrowserResolver(("8.8.8.8",))
    adapter = RaisingAfterNavigationCommitAdapter(initial_page=_page_seed())
    service, _, _, _, _, _ = _service(
        adapter=adapter,
        network_resolver=resolver,
    )
    opened = await service.open_session(_PROFILE_ID, _context())

    with pytest.raises(BrowserAutomationIndeterminateEffectError):
        await service.navigate(
            opened.page,
            BrowserNavigationTargetId("start"),
            _context(),
        )

    assert adapter.commit_navigation_calls == 1
    assert not service._sessions


@pytest.mark.asyncio
async def test_fill_prepare_is_zero_effect_then_commit_advances_exactly_one_revision() -> None:
    adapter = CountingAdapter(initial_page=_page_seed())
    authorizer = RecordingAuthorizer()
    service, _, _, _, _, _ = _service(adapter=adapter, authorizer=authorizer)
    opened = await service.open_session(_PROFILE_ID, _context())
    before = await service.read_page(opened.page, _context())
    element = before.elements[0]
    observed_during_authority: list[str | None] = []

    async def hook(name: str, *args: object) -> None:
        if name == "fill":
            prepared = args[3]
            assert isinstance(prepared, BrowserPreparedEffect)
            assert prepared.input_digest == BrowserFillInput("after").digest
            assert "after" not in repr(prepared)
            current = await adapter.snapshot(opened.page)
            observed_during_authority.append(current.elements[0].value)

    authorizer.hook = hook
    result = await service.fill_element(
        opened.page,
        element.element_id,
        BrowserFillInput("after"),
        _context(),
    )

    assert observed_during_authority == ["before"]
    assert result.effect_started is True
    assert result.revision == BrowserPageRevision(2)
    assert adapter.prepare_fill_calls == 1
    assert adapter.commit_calls == 1
    with pytest.raises(BrowserAutomationStaleError):
        await service.read_page(opened.page, _context())
    current_page = BrowserPageDescriptor(
        session_id=opened.page.session_id,
        page_id=opened.page.page_id,
        revision=BrowserPageRevision(2),
    )
    after = await service.read_page(current_page, _context())
    assert after.elements[0].value == "after"
    assert after.elements[0].element_id != element.element_id


@pytest.mark.asyncio
async def test_fill_authority_rejection_after_prepare_discards_without_effect() -> None:
    adapter = CountingAdapter(initial_page=_page_seed())
    authorizer = RecordingAuthorizer()
    authorizer.deny.add("fill")
    service, _, _, _, _, _ = _service(adapter=adapter, authorizer=authorizer)
    opened = await service.open_session(_PROFILE_ID, _context())
    snapshot = await service.read_page(opened.page, _context())

    with pytest.raises(BrowserAutomationRejectedError):
        await service.fill_element(
            opened.page,
            snapshot.elements[0].element_id,
            BrowserFillInput("denied"),
            _context(),
        )

    assert adapter.commit_calls == 0
    assert adapter.prepared_count == 0
    unchanged = await service.read_page(opened.page, _context())
    assert unchanged.elements[0].value == "before"


@pytest.mark.asyncio
async def test_cancellation_after_prepare_never_commits_past_cancellation_boundary() -> None:
    adapter = CountingAdapter(initial_page=_page_seed())
    freshness = RecordingFreshness()
    token = BrowserAutomationCancellationToken()

    service, _, _, _, _, _ = _service(adapter=adapter, freshness=freshness)
    opened = await service.open_session(_PROFILE_ID, _context())
    snapshot = await service.read_page(opened.page, _context())
    # open=1, read=2+3; reset the hook threshold against current count.
    threshold = freshness.calls + 1
    freshness.hook = lambda call: token.cancel() if call == threshold else None

    with pytest.raises(BrowserAutomationCancelledError):
        await service.fill_element(
            opened.page,
            snapshot.elements[0].element_id,
            BrowserFillInput("cancelled"),
            _context(),
            cancellation=token,
        )

    assert adapter.commit_calls == 0
    # No untrusted cleanup wait may extend the cancellation boundary. Any residual
    # prepared token stays adapter-internal and cannot be committed through the service.
    assert adapter.prepared_count == 1


@pytest.mark.asyncio
async def test_deadline_expiring_during_final_authority_never_commits_past_deadline() -> None:
    adapter = CountingAdapter(initial_page=_page_seed())
    authorizer = RecordingAuthorizer()
    clock = MutableClock()
    service, _, _, _, _, _ = _service(
        adapter=adapter,
        authorizer=authorizer,
        clock=clock,
    )
    opened = await service.open_session(_PROFILE_ID, _context())
    snapshot = await service.read_page(opened.page, _context())

    def expire(name: str, *args: object) -> None:
        del args
        if name == "fill":
            clock.value += timedelta(seconds=20)

    authorizer.hook = expire
    with pytest.raises(BrowserAutomationTimeoutError):
        await service.fill_element(
            opened.page,
            snapshot.elements[0].element_id,
            BrowserFillInput("late"),
            _context(),
        )

    assert adapter.commit_calls == 0
    # The expired deadline forbids waiting for adapter cleanup after the decision.
    assert adapter.prepared_count == 1


@pytest.mark.asyncio
async def test_operation_timeout_uses_monotonic_total_budget_even_with_fixed_wall_clock() -> None:
    freshness = RecordingFreshness()

    async def slow(_: int) -> None:
        await asyncio.sleep(0.04)

    service, _, _, _, _, _ = _service(
        profile=_profile(
            session_ttl_seconds=2.0,
            operation_timeout_seconds=0.05,
        ),
        freshness=freshness,
    )
    opened = await service.open_session(_PROFILE_ID, _context())
    freshness.hook = slow

    with pytest.raises(BrowserAutomationTimeoutError):
        await service.read_page(opened.page, _context())


@pytest.mark.asyncio
async def test_wrong_authorizer_intent_cannot_substitute_page_read_for_fill() -> None:
    adapter = CountingAdapter(initial_page=_page_seed())
    authorizer = RecordingAuthorizer()
    authorizer.wrong_fill_intent = True
    service, _, _, _, _, _ = _service(adapter=adapter, authorizer=authorizer)
    opened = await service.open_session(_PROFILE_ID, _context())
    snapshot = await service.read_page(opened.page, _context())

    with pytest.raises(BrowserAutomationRejectedError):
        await service.fill_element(
            opened.page,
            snapshot.elements[0].element_id,
            BrowserFillInput("wrong-authority"),
            _context(),
        )

    assert adapter.commit_calls == 0
    assert adapter.prepared_count == 0


@pytest.mark.asyncio
async def test_old_element_and_revision_are_stale_after_successful_fill() -> None:
    service, _, _, _, _, _ = _service()
    opened = await service.open_session(_PROFILE_ID, _context())
    snapshot = await service.read_page(opened.page, _context())
    old_element = snapshot.elements[0].element_id
    result = await service.fill_element(
        opened.page,
        old_element,
        BrowserFillInput("new"),
        _context(),
    )
    assert result.revision == BrowserPageRevision(2)

    with pytest.raises(BrowserAutomationStaleError):
        await service.fill_element(
            opened.page,
            old_element,
            BrowserFillInput("again"),
            _context(),
        )


@pytest.mark.asyncio
async def test_profile_fill_limit_is_checked_before_adapter_preparation() -> None:
    adapter = CountingAdapter(initial_page=_page_seed())
    service, _, _, _, _, _ = _service(
        profile=_profile(max_fill_text_chars=3),
        adapter=adapter,
    )
    opened = await service.open_session(_PROFILE_ID, _context())
    snapshot = await service.read_page(opened.page, _context())

    with pytest.raises(BrowserAutomationLimitExceededError):
        await service.fill_element(
            opened.page,
            snapshot.elements[0].element_id,
            BrowserFillInput("four"),
            _context(),
        )

    assert adapter.prepare_fill_calls == 0


@pytest.mark.asyncio
async def test_max_concurrent_sessions_is_race_safe_and_released_on_close() -> None:
    profile = _profile(max_concurrent_sessions=1)
    service, _, adapter, _, _, _ = _service(profile=profile)
    first = await service.open_session(_PROFILE_ID, _context())

    with pytest.raises(BrowserAutomationLimitExceededError):
        await service.open_session(_PROFILE_ID, _context())

    await service.close_session(first.session.session_id, _context())
    second = await service.open_session(_PROFILE_ID, _context())
    assert second.session.session_id != first.session.session_id
    assert adapter.session_count == 1


@pytest.mark.asyncio
async def test_concurrent_open_reservation_never_exceeds_profile_limit() -> None:
    profile = _profile(max_concurrent_sessions=1)
    authorizer = RecordingAuthorizer()
    entered = asyncio.Event()
    release = asyncio.Event()

    async def hold_first_open(name: str, *args: object) -> None:
        del args
        if name == "open" and not entered.is_set():
            entered.set()
            await release.wait()

    authorizer.hook = hold_first_open
    service, _, adapter, _, _, _ = _service(profile=profile, authorizer=authorizer)
    first_task = asyncio.create_task(service.open_session(_PROFILE_ID, _context()))
    await entered.wait()

    with pytest.raises(BrowserAutomationLimitExceededError):
        await service.open_session(_PROFILE_ID, _context())

    release.set()
    first = await first_task
    assert first.session.profile_id == _PROFILE_ID
    assert adapter.session_count == 1


@pytest.mark.asyncio
async def test_expired_session_cannot_pin_profile_capacity_across_subjects() -> None:
    profile = _profile(max_concurrent_sessions=1)
    service, _, adapter, _, _, clock = _service(profile=profile)
    first = await service.open_session(_PROFILE_ID, _context(principal="user:attacker"))

    clock.value = first.session.expires_at + timedelta(microseconds=1)
    second = await service.open_session(
        _PROFILE_ID,
        _context(principal="user:owner", session_id=_SESSION_B),
    )

    assert second.session.session_id != first.session.session_id
    assert adapter.session_count == 1


@pytest.mark.asyncio
async def test_same_generation_profile_drift_cannot_pin_profile_capacity() -> None:
    profile = _profile(max_concurrent_sessions=1)
    service, source, adapter, _, _, _ = _service(profile=profile)
    first = await service.open_session(_PROFILE_ID, _context())

    source.profile = _profile(
        generation=profile.generation,
        max_concurrent_sessions=1,
        max_snapshot_title_chars=64,
    )
    second = await service.open_session(_PROFILE_ID, _context())

    assert second.session.session_id != first.session.session_id
    assert adapter.session_count == 1


@pytest.mark.asyncio
async def test_stale_reap_obeys_requested_deadline_before_new_open() -> None:
    profile = _profile(
        max_concurrent_sessions=1,
        operation_timeout_seconds=5.0,
        session_ttl_seconds=10.0,
    )
    adapter = BlockingCloseAdapter(initial_page=_page_seed())
    service, _, _, _, _, clock = _service(profile=profile, adapter=adapter)
    first = await service.open_session(_PROFILE_ID, _context(principal="user:attacker"))
    clock.value = first.session.expires_at + timedelta(microseconds=1)

    with pytest.raises(BrowserAutomationTimeoutError):
        await asyncio.wait_for(
            service.open_session(
                _PROFILE_ID,
                _context(principal="user:owner", session_id=_SESSION_B),
                deadline=clock.value + timedelta(milliseconds=50),
            ),
            timeout=0.5,
        )

    assert adapter.close_started.is_set()
    assert adapter.session_count == 1
    with pytest.raises(BrowserAutomationOperationDisabledError):
        await service.read_page(first.page, _context(principal="user:attacker"))


@pytest.mark.asyncio
async def test_stale_reap_obeys_cancellation_while_adapter_close_waits() -> None:
    profile = _profile(
        max_concurrent_sessions=1,
        operation_timeout_seconds=5.0,
        session_ttl_seconds=10.0,
    )
    adapter = BlockingCloseAdapter(initial_page=_page_seed())
    service, _, _, _, _, clock = _service(profile=profile, adapter=adapter)
    first = await service.open_session(_PROFILE_ID, _context(principal="user:attacker"))
    clock.value = first.session.expires_at + timedelta(microseconds=1)
    cancellation = BrowserAutomationCancellationToken()

    opening = asyncio.create_task(
        service.open_session(
            _PROFILE_ID,
            _context(principal="user:owner", session_id=_SESSION_B),
            cancellation=cancellation,
        )
    )
    await asyncio.wait_for(adapter.close_started.wait(), timeout=0.5)
    cancellation.cancel()

    with pytest.raises(BrowserAutomationCancelledError):
        await asyncio.wait_for(opening, timeout=0.5)

    assert adapter.session_count == 1
    assert service._quarantined is True
    with pytest.raises(BrowserAutomationOperationDisabledError):
        await service.open_session(_PROFILE_ID, _context())


@pytest.mark.asyncio
async def test_reap_rechecks_current_profile_before_internal_cleanup() -> None:
    profile = _profile(max_concurrent_sessions=1)
    source = OneShotProfileSnapshotSource(profile)
    service, _, adapter, _, _, _ = _service(profile=profile)
    service._profiles = source
    first = await service.open_session(_PROFILE_ID, _context())

    drift = _profile(
        generation=profile.generation,
        max_concurrent_sessions=1,
        max_snapshot_title_chars=64,
    )
    source.snapshot_once(drift)

    with pytest.raises(BrowserAutomationLimitExceededError):
        await service.open_session(_PROFILE_ID, _context())

    assert adapter.session_count == 1
    snapshot = await service.read_page(first.page, _context())
    assert snapshot.page_id == first.page.page_id


@pytest.mark.asyncio
async def test_direct_close_deadline_interruption_always_quarantines() -> None:
    adapter = BlockingCloseAdapter(initial_page=_page_seed())
    service, _, _, _, _, _ = _service(
        profile=_profile(operation_timeout_seconds=5.0),
        adapter=adapter,
    )
    opened = await service.open_session(_PROFILE_ID, _context())

    with pytest.raises(BrowserAutomationTimeoutError):
        await asyncio.wait_for(
            service.close_session(
                opened.session.session_id,
                _context(),
                deadline=_NOW + timedelta(milliseconds=50),
            ),
            timeout=0.5,
        )

    assert adapter.close_started.is_set()
    assert service._quarantined is True
    assert not service._sessions
    with pytest.raises(BrowserAutomationOperationDisabledError):
        await service.open_session(_PROFILE_ID, _context())


@pytest.mark.asyncio
async def test_discard_interrupted_by_cancellation_always_quarantines() -> None:
    adapter = BlockingDiscardAdapter(initial_page=_page_seed())
    authorizer = RecordingAuthorizer()
    authorizer.deny.add("fill")
    service, _, _, _, _, _ = _service(adapter=adapter, authorizer=authorizer)
    opened = await service.open_session(_PROFILE_ID, _context())
    snapshot = await service.read_page(opened.page, _context())
    cancellation = BrowserAutomationCancellationToken()

    filling = asyncio.create_task(
        service.fill_element(
            opened.page,
            snapshot.elements[0].element_id,
            BrowserFillInput("denied"),
            _context(),
            cancellation=cancellation,
        )
    )
    await asyncio.wait_for(adapter.discard_started.wait(), timeout=0.5)
    cancellation.cancel()

    with pytest.raises(BrowserAutomationRejectedError):
        await asyncio.wait_for(filling, timeout=0.5)

    assert service._quarantined is True
    assert not service._sessions
    with pytest.raises(BrowserAutomationOperationDisabledError):
        await service.open_session(_PROFILE_ID, _context())


@pytest.mark.asyncio
async def test_noncooperative_snapshot_deadline_returns_finitely_and_quarantines() -> None:
    adapter = SuppressingCancellationSnapshotAdapter(initial_page=_page_seed())
    service, _, _, _, _, _ = _service(
        profile=_profile(operation_timeout_seconds=0.05),
        adapter=adapter,
    )
    opened = await service.open_session(_PROFILE_ID, _context())

    try:
        with pytest.raises(BrowserAutomationTimeoutError):
            await asyncio.wait_for(
                service.read_page(opened.page, _context()),
                timeout=0.5,
            )

        assert adapter.snapshot_started.is_set()
        await asyncio.wait_for(adapter.cancel_suppressed.wait(), timeout=0.5)
        assert service._quarantined is True
        assert not service._sessions
        assert len(service._abandoned_tasks) == 1
        with pytest.raises(BrowserAutomationOperationDisabledError):
            await service.open_session(_PROFILE_ID, _context())
    finally:
        adapter.release_snapshot.set()
        await _drain_abandoned_tasks(service)


@pytest.mark.asyncio
async def test_external_task_cancellation_never_waits_for_noncooperative_snapshot() -> None:
    adapter = SuppressingCancellationSnapshotAdapter(initial_page=_page_seed())
    service, _, _, _, _, _ = _service(adapter=adapter)
    opened = await service.open_session(_PROFILE_ID, _context())
    reading = asyncio.create_task(service.read_page(opened.page, _context()))
    await asyncio.wait_for(adapter.snapshot_started.wait(), timeout=0.5)
    reading.cancel()

    try:
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(reading, timeout=0.5)
        await asyncio.wait_for(adapter.cancel_suppressed.wait(), timeout=0.5)
        assert service._quarantined is True
        assert not service._sessions
        assert len(service._abandoned_tasks) == 1
    finally:
        adapter.release_snapshot.set()
        await _drain_abandoned_tasks(service)


@pytest.mark.asyncio
async def test_noncooperative_reap_cleanup_cancellation_returns_finitely_and_quarantines() -> None:
    profile = _profile(
        max_concurrent_sessions=1,
        operation_timeout_seconds=5.0,
        session_ttl_seconds=10.0,
    )
    adapter = SuppressingCancellationCloseAdapter(initial_page=_page_seed())
    service, _, _, _, _, clock = _service(profile=profile, adapter=adapter)
    first = await service.open_session(_PROFILE_ID, _context(principal="user:attacker"))
    clock.value = first.session.expires_at + timedelta(microseconds=1)
    cancellation = BrowserAutomationCancellationToken()

    opening = asyncio.create_task(
        service.open_session(
            _PROFILE_ID,
            _context(principal="user:owner", session_id=_SESSION_B),
            cancellation=cancellation,
        )
    )
    await asyncio.wait_for(adapter.close_started.wait(), timeout=0.5)
    cancellation.cancel()

    try:
        with pytest.raises(BrowserAutomationCancelledError):
            await asyncio.wait_for(opening, timeout=0.5)
        await asyncio.wait_for(adapter.cancel_suppressed.wait(), timeout=0.5)
        assert service._quarantined is True
        assert not service._sessions
        assert len(service._abandoned_tasks) == 1
        with pytest.raises(BrowserAutomationOperationDisabledError):
            await service.open_session(_PROFILE_ID, _context())
    finally:
        adapter.release_close.set()
        await _drain_abandoned_tasks(service)


@pytest.mark.asyncio
async def test_noncooperative_commit_cancellation_is_finite_indeterminate_and_quarantined() -> None:
    adapter = SuppressingCancellationCommitAdapter(initial_page=_page_seed())
    service, _, _, _, _, _ = _service(adapter=adapter)
    opened = await service.open_session(_PROFILE_ID, _context())
    snapshot = await service.read_page(opened.page, _context())
    cancellation = BrowserAutomationCancellationToken()

    filling = asyncio.create_task(
        service.fill_element(
            opened.page,
            snapshot.elements[0].element_id,
            BrowserFillInput("ambiguous"),
            _context(),
            cancellation=cancellation,
        )
    )
    await asyncio.wait_for(adapter.effect_started.wait(), timeout=0.5)
    cancellation.cancel()

    try:
        with pytest.raises(BrowserAutomationIndeterminateEffectError):
            await asyncio.wait_for(filling, timeout=0.5)
        await asyncio.wait_for(adapter.cancel_suppressed.wait(), timeout=0.5)
        assert adapter.commit_calls == 1
        assert service._quarantined is True
        assert not service._sessions
        assert len(service._abandoned_tasks) == 1
        with pytest.raises(BrowserAutomationOperationDisabledError):
            await service.read_page(opened.page, _context())
    finally:
        adapter.release_commit.set()
        await _drain_abandoned_tasks(service)


@pytest.mark.asyncio
async def test_close_requires_independent_current_authority_and_denial_keeps_session() -> None:
    authorizer = RecordingAuthorizer()
    service, _, adapter, _, _, _ = _service(authorizer=authorizer)
    opened = await service.open_session(_PROFILE_ID, _context())
    authorizer.deny.add("close")

    with pytest.raises(BrowserAutomationRejectedError):
        await service.close_session(opened.session.session_id, _context())

    assert adapter.session_count == 1
    snapshot = await service.read_page(opened.page, _context())
    assert snapshot.page_id == opened.page.page_id


@pytest.mark.asyncio
async def test_exception_after_commit_is_indeterminate_and_poisoned_without_retry() -> None:
    adapter = RaisingAfterCommitAdapter(initial_page=_page_seed())
    service, _, _, _, _, _ = _service(adapter=adapter)
    opened = await service.open_session(_PROFILE_ID, _context())
    snapshot = await service.read_page(opened.page, _context())

    with pytest.raises(BrowserAutomationIndeterminateEffectError):
        await service.fill_element(
            opened.page,
            snapshot.elements[0].element_id,
            BrowserFillInput("ambiguous"),
            _context(),
        )

    assert adapter.commit_calls == 1
    assert adapter.session_count == 0
    with pytest.raises(BrowserAutomationTargetNotFoundError):
        await service.read_page(opened.page, _context())


@pytest.mark.asyncio
async def test_cancellation_after_effect_start_is_indeterminate_and_quarantines_without_wait() -> (
    None
):
    adapter = BlockingAfterCommitAdapter(initial_page=_page_seed())
    service, _, _, _, _, _ = _service(adapter=adapter)
    opened = await service.open_session(_PROFILE_ID, _context())
    snapshot = await service.read_page(opened.page, _context())
    token = BrowserAutomationCancellationToken()

    task = asyncio.create_task(
        service.fill_element(
            opened.page,
            snapshot.elements[0].element_id,
            BrowserFillInput("ambiguous"),
            _context(),
            cancellation=token,
        )
    )
    await adapter.effect_started.wait()
    token.cancel()

    with pytest.raises(BrowserAutomationIndeterminateEffectError):
        await task

    assert adapter.commit_calls == 1
    assert service._quarantined is True
    assert not service._sessions


def test_s6_service_surface_allows_only_controlled_click_and_navigation() -> None:
    service, _, _, _, _, _ = _service()

    assert hasattr(service, "navigate")
    assert hasattr(service, "click_element")
    for name in (
        "navigate_page",
        "click",
        "execute",
        "fetch",
        "request",
        "_bind_runtime_lifecycle",
        "snapshot_service",
    ):
        assert not hasattr(service, name)

    assert isinstance(service._authorizer, BrowserAuthorizer)


def test_s4_public_surface_exports_only_explicit_service_primitives() -> None:
    import phoenix_os.browser_automation as browser

    assert browser.BrowserAutomationCancellationToken is BrowserAutomationCancellationToken
    assert browser.BrowserAutomationService is BrowserAutomationService
    assert browser.BrowserSessionOpenResult is BrowserSessionOpenResult
    assert "BrowserProfileSource" in browser.__all__
    assert "browser.execute" not in browser.__all__
