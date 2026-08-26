"""Deterministic in-memory browser adapter for RFC-0035 tests and security validation."""

from __future__ import annotations

import re
from dataclasses import dataclass
from uuid import NAMESPACE_URL, UUID, uuid5

from phoenix_os.browser_automation.adapter import (
    BrowserAdapterCommitResult,
    BrowserNavigationCommitResult,
    BrowserPreparedEffect,
    BrowserPreparedEffectKind,
    BrowserPreparedNavigation,
    BrowserPreparedNavigationPlan,
)
from phoenix_os.browser_automation.contracts import (
    MAX_BROWSER_PAGE_REVISION,
    BrowserAdapterId,
    BrowserElementAction,
    BrowserElementDescriptor,
    BrowserElementId,
    BrowserElementKind,
    BrowserFillInput,
    BrowserPageDescriptor,
    BrowserPageRevision,
    BrowserPageSnapshot,
    BrowserSessionDescriptor,
    BrowserSessionId,
)
from phoenix_os.browser_automation.errors import (
    BrowserAutomationAdapterError,
    BrowserAutomationLimitExceededError,
    BrowserAutomationOperationDisabledError,
    BrowserAutomationStaleError,
    BrowserAutomationTargetNotFoundError,
)
from phoenix_os.browser_automation.profiles import BrowserNavigationRequest, BrowserProfile

_FAKE_ELEMENT_KEY_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,127})$")


@dataclass(frozen=True, slots=True)
class DeterministicBrowserElement:
    """Server-test-owned fake element definition; key is never exposed in page snapshots."""

    key: str
    kind: BrowserElementKind
    name: str = ""
    value: str | None = None
    actions: tuple[BrowserElementAction, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.key, str):
            raise TypeError("deterministic browser element key must be a string")
        key = self.key.strip().lower()
        if _FAKE_ELEMENT_KEY_PATTERN.fullmatch(key) is None:
            raise ValueError("deterministic browser element key is invalid")
        descriptor = BrowserElementDescriptor(
            element_id=BrowserElementId(UUID(int=0)),
            kind=self.kind,
            name=self.name,
            value=self.value,
            actions=self.actions,
        )
        object.__setattr__(self, "key", key)
        object.__setattr__(self, "kind", descriptor.kind)
        object.__setattr__(self, "name", descriptor.name)
        object.__setattr__(self, "value", descriptor.value)
        object.__setattr__(self, "actions", descriptor.actions)


@dataclass(frozen=True, slots=True)
class DeterministicBrowserPage:
    """Network-free initial page state for the deterministic adapter."""

    title: str = ""
    text: str = ""
    elements: tuple[DeterministicBrowserElement, ...] = ()

    def __post_init__(self) -> None:
        elements = tuple(self.elements)
        if any(not isinstance(item, DeterministicBrowserElement) for item in elements):
            raise TypeError("elements must contain DeterministicBrowserElement values")
        keys = tuple(item.key for item in elements)
        if len(keys) != len(set(keys)):
            raise ValueError("deterministic browser page contains duplicate element keys")
        object.__setattr__(self, "elements", elements)


@dataclass(slots=True)
class _ElementState:
    key: str
    kind: BrowserElementKind
    name: str
    value: str | None
    actions: tuple[BrowserElementAction, ...]


@dataclass(slots=True)
class _SessionState:
    profile: BrowserProfile
    descriptor: BrowserSessionDescriptor
    revision: int
    title: str
    text: str
    elements: dict[str, _ElementState]
    navigation_redirect_index: int


@dataclass(slots=True)
class _PreparedState:
    public: BrowserPreparedEffect
    element_key: str
    fill_value: str | None


@dataclass(slots=True)
class _PreparedNavigationState:
    public: BrowserPreparedNavigationPlan
    request: BrowserNavigationRequest


class DeterministicBrowserAdapter:
    """Network-free fake that proves stale-safe opaque identity and prepare/commit ordering."""

    def __init__(
        self,
        *,
        adapter_id: BrowserAdapterId | str = "deterministic-browser",
        initial_page: DeterministicBrowserPage | None = None,
        redirect_locations: tuple[str, ...] = (),
    ) -> None:
        self._adapter_id = (
            adapter_id if isinstance(adapter_id, BrowserAdapterId) else BrowserAdapterId(adapter_id)
        )
        selected_page = DeterministicBrowserPage() if initial_page is None else initial_page
        if not isinstance(selected_page, DeterministicBrowserPage):
            raise TypeError("initial_page must be DeterministicBrowserPage or None")
        if not isinstance(redirect_locations, tuple):
            raise TypeError("redirect_locations must be a tuple")
        if any(not isinstance(item, str) for item in redirect_locations):
            raise TypeError("redirect_locations must contain strings")
        self._initial_page = selected_page
        self._redirect_locations = redirect_locations
        self._sessions: dict[BrowserSessionId, _SessionState] = {}
        self._prepared: dict[UUID, _PreparedState] = {}
        self._prepared_navigation: dict[UUID, _PreparedNavigationState] = {}
        self._prepare_sequence = 0
        self._closed = False

    @property
    def adapter_id(self) -> BrowserAdapterId:
        return self._adapter_id

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def session_count(self) -> int:
        return len(self._sessions)

    @property
    def prepared_count(self) -> int:
        return len(self._prepared) + len(self._prepared_navigation)

    async def open_session(
        self,
        profile: BrowserProfile,
        session: BrowserSessionDescriptor,
    ) -> BrowserPageDescriptor:
        self._ensure_open()
        if not isinstance(profile, BrowserProfile):
            raise TypeError("profile must be BrowserProfile")
        if not isinstance(session, BrowserSessionDescriptor):
            raise TypeError("session must be BrowserSessionDescriptor")
        if profile.adapter_id != self._adapter_id:
            raise BrowserAutomationOperationDisabledError()
        if (
            session.profile_id != profile.profile_id
            or session.profile_generation != profile.generation
        ):
            raise BrowserAutomationStaleError()
        if session.session_id in self._sessions:
            raise BrowserAutomationStaleError()

        state = _SessionState(
            profile=profile,
            descriptor=session,
            revision=1,
            title=self._initial_page.title,
            text=self._initial_page.text,
            elements={
                item.key: _ElementState(
                    key=item.key,
                    kind=item.kind,
                    name=item.name,
                    value=item.value,
                    actions=item.actions,
                )
                for item in self._initial_page.elements
            },
            navigation_redirect_index=0,
        )
        self._sessions[session.session_id] = state
        return self._page_descriptor(state)

    async def close_session(self, session_id: BrowserSessionId) -> None:
        self._ensure_open()
        if not isinstance(session_id, BrowserSessionId):
            raise TypeError("session_id must be BrowserSessionId")
        if self._sessions.pop(session_id, None) is None:
            raise BrowserAutomationTargetNotFoundError()
        stale_tokens = tuple(
            token
            for token, prepared in self._prepared.items()
            if prepared.public.session_id == session_id
        )
        for token in stale_tokens:
            del self._prepared[token]
        stale_navigation_tokens = tuple(
            token
            for token, prepared in self._prepared_navigation.items()
            if prepared.public.session_id == session_id
        )
        for token in stale_navigation_tokens:
            del self._prepared_navigation[token]

    async def snapshot(self, page: BrowserPageDescriptor) -> BrowserPageSnapshot:
        self._ensure_open()
        state = self._require_page(page)
        elements = tuple(
            self._descriptor_for(state, item)
            for item in sorted(state.elements.values(), key=lambda value: value.key)
        )
        limits = state.profile.limits
        if len(state.title) > limits.max_snapshot_title_chars:
            raise BrowserAutomationAdapterError()
        if len(state.text) > limits.max_snapshot_text_chars:
            raise BrowserAutomationAdapterError()
        if len(state.text.encode("utf-8")) > limits.max_snapshot_text_bytes:
            raise BrowserAutomationAdapterError()
        if len(elements) > limits.max_snapshot_elements:
            raise BrowserAutomationAdapterError()
        return BrowserPageSnapshot(
            session_id=page.session_id,
            page_id=page.page_id,
            revision=page.revision,
            title=state.title,
            text=state.text,
            elements=elements,
            created_at=state.descriptor.created_at,
        )

    async def prepare_navigation(
        self,
        page: BrowserPageDescriptor,
        request: BrowserNavigationRequest,
    ) -> BrowserPreparedNavigationPlan:
        self._ensure_open()
        if not isinstance(request, BrowserNavigationRequest):
            raise TypeError("request must be BrowserNavigationRequest")
        state = self._require_page(page)
        try:
            configured = state.profile.require_target(request.target_id)
        except KeyError:
            raise BrowserAutomationTargetNotFoundError() from None
        if request.origin not in state.profile.allowed_origins:
            raise BrowserAutomationStaleError()
        if request.redirect_count > state.profile.limits.max_redirects:
            raise BrowserAutomationStaleError()
        if request.redirect_count == 0 and (
            request.origin != configured.origin
            or request.request_target != configured.request_target
        ):
            raise BrowserAutomationStaleError()
        return self._record_navigation_plan(page, request)

    async def prepare_fill(
        self,
        page: BrowserPageDescriptor,
        element_id: BrowserElementId,
        value: BrowserFillInput,
    ) -> BrowserPreparedEffect:
        self._ensure_open()
        if not isinstance(element_id, BrowserElementId):
            raise TypeError("element_id must be BrowserElementId")
        if not isinstance(value, BrowserFillInput):
            raise TypeError("value must be BrowserFillInput")
        state = self._require_page(page)
        if len(value.value) > state.profile.limits.max_fill_text_chars:
            raise BrowserAutomationLimitExceededError()
        if len(value.value.encode("utf-8")) > state.profile.limits.max_fill_text_bytes:
            raise BrowserAutomationLimitExceededError()
        element = self._resolve_element(state, page.revision, element_id)
        if BrowserElementAction.FILL not in element.actions:
            raise BrowserAutomationOperationDisabledError()
        return self._record_prepared(
            state,
            page,
            element,
            BrowserPreparedEffectKind.FILL,
            input_digest=value.digest,
            fill_value=value.value,
        )

    async def prepare_click(
        self,
        page: BrowserPageDescriptor,
        element_id: BrowserElementId,
    ) -> BrowserPreparedEffect:
        self._ensure_open()
        if not isinstance(element_id, BrowserElementId):
            raise TypeError("element_id must be BrowserElementId")
        state = self._require_page(page)
        element = self._resolve_element(state, page.revision, element_id)
        if BrowserElementAction.CLICK not in element.actions:
            raise BrowserAutomationOperationDisabledError()
        return self._record_prepared(
            state,
            page,
            element,
            BrowserPreparedEffectKind.CLICK,
            input_digest=None,
            fill_value=None,
        )

    async def commit_navigation(
        self,
        prepared: BrowserPreparedNavigation,
    ) -> BrowserNavigationCommitResult:
        self._ensure_open()
        if not isinstance(prepared, BrowserPreparedNavigation):
            raise TypeError("prepared must be BrowserPreparedNavigation")
        record = self._prepared_navigation.pop(prepared.token, None)
        if record is None or record.public != prepared.plan:
            raise BrowserAutomationStaleError()
        state = self._sessions.get(prepared.session_id)
        if state is None:
            raise BrowserAutomationStaleError()
        page = self._page_descriptor(state)
        if page.page_id != prepared.page_id or page.revision != prepared.revision:
            raise BrowserAutomationStaleError()
        try:
            configured = state.profile.require_target(prepared.request.target_id)
        except KeyError:
            raise BrowserAutomationStaleError() from None
        if record.request != prepared.request:
            raise BrowserAutomationStaleError()
        if prepared.request.origin not in state.profile.allowed_origins:
            raise BrowserAutomationStaleError()
        if prepared.request.redirect_count == 0 and (
            prepared.request.origin != configured.origin
            or prepared.request.request_target != configured.request_target
        ):
            raise BrowserAutomationStaleError()
        if (
            prepared.destination.profile_id != state.profile.profile_id
            or prepared.destination.profile_generation != state.profile.generation
            or prepared.destination.origin != prepared.request.origin
        ):
            raise BrowserAutomationStaleError()
        if state.revision >= MAX_BROWSER_PAGE_REVISION:
            raise BrowserAutomationAdapterError()

        if state.navigation_redirect_index < len(self._redirect_locations):
            location = self._redirect_locations[state.navigation_redirect_index]
            state.navigation_redirect_index += 1
            return BrowserNavigationCommitResult(
                prepared_token=prepared.token,
                redirect_location=location,
                effect_started=True,
            )

        # This fake is intentionally network-free. Only the final document replacement
        # advances the single visible page revision; redirect hops do not.
        state.navigation_redirect_index = 0
        state.title = ""
        state.text = ""
        state.elements.clear()
        state.revision += 1
        return BrowserNavigationCommitResult(
            prepared_token=prepared.token,
            page=self._page_descriptor(state),
            effect_started=True,
        )

    async def commit_prepared(
        self,
        prepared: BrowserPreparedEffect,
    ) -> BrowserAdapterCommitResult:
        self._ensure_open()
        if not isinstance(prepared, BrowserPreparedEffect):
            raise TypeError("prepared must be BrowserPreparedEffect")
        record = self._prepared.pop(prepared.token, None)
        if record is None or record.public != prepared:
            raise BrowserAutomationStaleError()
        state = self._sessions.get(prepared.session_id)
        if state is None:
            raise BrowserAutomationStaleError()
        page = self._page_descriptor(state)
        if (
            page.page_id != prepared.page_id
            or page.revision != prepared.revision
            or self._element_id(state, prepared.revision, record.element_key) != prepared.element_id
        ):
            raise BrowserAutomationStaleError()

        element = state.elements.get(record.element_key)
        if element is None:
            raise BrowserAutomationStaleError()
        if state.revision >= MAX_BROWSER_PAGE_REVISION:
            raise BrowserAutomationAdapterError()
        if prepared.kind is BrowserPreparedEffectKind.FILL:
            if record.fill_value is None:
                raise BrowserAutomationAdapterError()
            element.value = record.fill_value
        elif prepared.kind is not BrowserPreparedEffectKind.CLICK:
            raise BrowserAutomationAdapterError()

        state.revision += 1
        next_page = self._page_descriptor(state)
        return BrowserAdapterCommitResult(
            prepared_token=prepared.token,
            page=next_page,
            effect_started=True,
        )

    async def discard_prepared(self, prepared: BrowserPreparedEffect) -> None:
        self._ensure_open()
        if not isinstance(prepared, BrowserPreparedEffect):
            raise TypeError("prepared must be BrowserPreparedEffect")
        record = self._prepared.get(prepared.token)
        if record is None or record.public != prepared:
            raise BrowserAutomationStaleError()
        del self._prepared[prepared.token]

    async def discard_navigation(self, prepared: BrowserPreparedNavigationPlan) -> None:
        self._ensure_open()
        if not isinstance(prepared, BrowserPreparedNavigationPlan):
            raise TypeError("prepared must be BrowserPreparedNavigationPlan")
        record = self._prepared_navigation.get(prepared.token)
        if record is None or record.public != prepared:
            raise BrowserAutomationStaleError()
        del self._prepared_navigation[prepared.token]

    async def aclose(self) -> None:
        if self._closed:
            return
        self._prepared.clear()
        self._prepared_navigation.clear()
        self._sessions.clear()
        self._closed = True

    def _record_navigation_plan(
        self,
        page: BrowserPageDescriptor,
        request: BrowserNavigationRequest,
    ) -> BrowserPreparedNavigationPlan:
        token = uuid5(
            NAMESPACE_URL,
            "|".join(
                (
                    "phoenix-browser-navigation",
                    str(self._adapter_id),
                    str(page.session_id),
                    str(page.page_id),
                    str(page.revision),
                    str(request.target_id),
                    request.origin.canonical,
                    request.request_target,
                    str(request.redirect_count),
                    str(self._prepare_sequence),
                )
            ),
        )
        self._prepare_sequence += 1
        public = BrowserPreparedNavigationPlan(
            token=token,
            session_id=page.session_id,
            page_id=page.page_id,
            revision=page.revision,
            request=request,
        )
        self._prepared_navigation[token] = _PreparedNavigationState(
            public=public,
            request=request,
        )
        return public

    def _record_prepared(
        self,
        state: _SessionState,
        page: BrowserPageDescriptor,
        element: _ElementState,
        kind: BrowserPreparedEffectKind,
        *,
        input_digest: str | None,
        fill_value: str | None,
    ) -> BrowserPreparedEffect:
        token = uuid5(
            NAMESPACE_URL,
            "|".join(
                (
                    "phoenix-browser-prepared",
                    str(self._adapter_id),
                    str(page.session_id),
                    str(page.page_id),
                    str(page.revision),
                    element.key,
                    kind.value,
                    str(self._prepare_sequence),
                )
            ),
        )
        self._prepare_sequence += 1
        public = BrowserPreparedEffect(
            token=token,
            kind=kind,
            session_id=page.session_id,
            page_id=page.page_id,
            revision=page.revision,
            element_id=self._element_id(state, page.revision, element.key),
            input_digest=input_digest,
        )
        self._prepared[token] = _PreparedState(
            public=public,
            element_key=element.key,
            fill_value=fill_value,
        )
        return public

    def _require_page(self, page: BrowserPageDescriptor) -> _SessionState:
        if not isinstance(page, BrowserPageDescriptor):
            raise TypeError("page must be BrowserPageDescriptor")
        state = self._sessions.get(page.session_id)
        if state is None:
            raise BrowserAutomationTargetNotFoundError()
        current = self._page_descriptor(state)
        if current.page_id != page.page_id or current.revision != page.revision:
            raise BrowserAutomationStaleError()
        return state

    def _resolve_element(
        self,
        state: _SessionState,
        revision: BrowserPageRevision,
        element_id: BrowserElementId,
    ) -> _ElementState:
        for element in state.elements.values():
            if self._element_id(state, revision, element.key) == element_id:
                return element
        raise BrowserAutomationStaleError()

    def _descriptor_for(
        self,
        state: _SessionState,
        element: _ElementState,
    ) -> BrowserElementDescriptor:
        revision = BrowserPageRevision(state.revision)
        limits = state.profile.limits
        if len(element.name) > limits.max_element_name_chars:
            raise BrowserAutomationAdapterError()
        if element.value is not None and len(element.value) > limits.max_element_value_chars:
            raise BrowserAutomationAdapterError()
        return BrowserElementDescriptor(
            element_id=self._element_id(state, revision, element.key),
            kind=element.kind,
            name=element.name,
            value=element.value,
            actions=element.actions,
        )

    def _element_id(
        self,
        state: _SessionState,
        revision: BrowserPageRevision,
        key: str,
    ) -> BrowserElementId:
        value = uuid5(
            NAMESPACE_URL,
            "|".join(
                (
                    "phoenix-browser-element",
                    str(self._adapter_id),
                    str(state.descriptor.session_id),
                    str(state.descriptor.page_id),
                    str(revision),
                    key,
                )
            ),
        )
        return BrowserElementId(value)

    def _page_descriptor(self, state: _SessionState) -> BrowserPageDescriptor:
        return BrowserPageDescriptor(
            session_id=state.descriptor.session_id,
            page_id=state.descriptor.page_id,
            revision=BrowserPageRevision(state.revision),
        )

    def _ensure_open(self) -> None:
        if self._closed:
            raise BrowserAutomationAdapterError()
