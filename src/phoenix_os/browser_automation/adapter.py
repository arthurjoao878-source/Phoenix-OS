"""Reviewed adapter boundary for RFC-0035 secure browser automation."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol, runtime_checkable
from uuid import UUID

from phoenix_os.browser_automation.contracts import (
    BrowserElementId,
    BrowserFillInput,
    BrowserPageDescriptor,
    BrowserPageId,
    BrowserPageRevision,
    BrowserPageSnapshot,
    BrowserSessionDescriptor,
    BrowserSessionId,
)
from phoenix_os.browser_automation.network import BrowserDestinationAdmission
from phoenix_os.browser_automation.profiles import (
    MAX_BROWSER_REDIRECT_LOCATION_LENGTH,
    BrowserClickRequest,
    BrowserNavigationRequest,
    BrowserProfile,
)

_SHA256_DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")


class BrowserPreparedEffectKind(StrEnum):
    """Finite adapter-level effects prepared without performing the effect."""

    FILL = "fill"
    CLICK = "click"


@dataclass(frozen=True, slots=True)
class BrowserPreparedEffect:
    """Opaque zero-effect readiness record bound to one exact page revision and element."""

    token: UUID
    kind: BrowserPreparedEffectKind
    session_id: BrowserSessionId
    page_id: BrowserPageId
    revision: BrowserPageRevision
    element_id: BrowserElementId
    input_digest: str | None = None
    request: BrowserClickRequest | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.token, UUID):
            raise TypeError("prepared browser effect token must be UUID")
        kind = BrowserPreparedEffectKind(self.kind)
        if not isinstance(self.session_id, BrowserSessionId):
            raise TypeError("session_id must be BrowserSessionId")
        if not isinstance(self.page_id, BrowserPageId):
            raise TypeError("page_id must be BrowserPageId")
        if not isinstance(self.revision, BrowserPageRevision):
            raise TypeError("revision must be BrowserPageRevision")
        if not isinstance(self.element_id, BrowserElementId):
            raise TypeError("element_id must be BrowserElementId")
        if self.input_digest is not None:
            if not isinstance(self.input_digest, str):
                raise TypeError("input_digest must be a string or None")
            if _SHA256_DIGEST_PATTERN.fullmatch(self.input_digest) is None:
                raise ValueError("input_digest must be an exact SHA-256 digest")
        request = self.request
        if request is not None and not isinstance(request, BrowserClickRequest):
            raise TypeError("request must be BrowserClickRequest or None")
        if kind is BrowserPreparedEffectKind.FILL:
            if self.input_digest is None:
                raise ValueError("prepared fill effect requires an exact input digest")
            if request is not None:
                raise ValueError("prepared fill effect cannot contain a click request")
        if kind is BrowserPreparedEffectKind.CLICK and self.input_digest is not None:
            raise ValueError("prepared click effect cannot contain fill input material")
        object.__setattr__(self, "kind", kind)


@dataclass(frozen=True, slots=True)
class BrowserPreparedClickRequest:
    """Final zero-effect click-request readiness with exact admitted destination pins."""

    effect: BrowserPreparedEffect
    request: BrowserClickRequest
    destination: BrowserDestinationAdmission

    def __post_init__(self) -> None:
        if not isinstance(self.effect, BrowserPreparedEffect):
            raise TypeError("effect must be BrowserPreparedEffect")
        if self.effect.kind is not BrowserPreparedEffectKind.CLICK:
            raise ValueError("prepared click request requires a click effect")
        if self.effect.request is None:
            raise ValueError("prepared click request requires a remote click plan")
        if not isinstance(self.request, BrowserClickRequest):
            raise TypeError("request must be BrowserClickRequest")
        if not isinstance(self.destination, BrowserDestinationAdmission):
            raise TypeError("destination must be BrowserDestinationAdmission")
        if self.destination.origin != self.request.origin:
            raise ValueError("click destination origin must match the exact request")
        if self.request.redirect_count == 0 and self.request != self.effect.request:
            raise ValueError("initial click request must match the prepared root request")

    @property
    def token(self) -> UUID:
        return self.effect.token

    @property
    def session_id(self) -> BrowserSessionId:
        return self.effect.session_id

    @property
    def page_id(self) -> BrowserPageId:
        return self.effect.page_id

    @property
    def revision(self) -> BrowserPageRevision:
        return self.effect.revision

    @property
    def element_id(self) -> BrowserElementId:
        return self.effect.element_id


@dataclass(frozen=True, slots=True)
class BrowserClickCommitResult:
    """One started click-derived top-level request result without content disclosure."""

    prepared_token: UUID
    page: BrowserPageDescriptor | None = None
    redirect_location: str | None = field(default=None, repr=False)
    redirect_status: int | None = None
    effect_started: bool = True

    def __post_init__(self) -> None:
        if not isinstance(self.prepared_token, UUID):
            raise TypeError("prepared_token must be UUID")
        if self.page is not None and not isinstance(self.page, BrowserPageDescriptor):
            raise TypeError("page must be BrowserPageDescriptor or None")
        if self.redirect_location is not None:
            if not isinstance(self.redirect_location, str):
                raise TypeError("redirect_location must be a string or None")
            if (
                not self.redirect_location
                or len(self.redirect_location) > MAX_BROWSER_REDIRECT_LOCATION_LENGTH
            ):
                raise ValueError("redirect location size is outside supported bounds")
        if (self.page is None) == (self.redirect_location is None):
            raise ValueError("click request result must contain exactly one page or redirect")
        if self.redirect_location is None:
            if self.redirect_status is not None:
                raise ValueError("final click result cannot contain redirect_status")
        elif (
            isinstance(self.redirect_status, bool)
            or not isinstance(self.redirect_status, int)
            or self.redirect_status not in {301, 302, 303, 307, 308}
        ):
            raise ValueError("redirect click result requires a supported redirect status")
        if self.effect_started is not True:
            raise ValueError("click request result must represent a request that started")


@dataclass(frozen=True, slots=True)
class BrowserPreparedNavigationPlan:
    """Adapter-owned zero-effect plan for one exact top-level navigation request."""

    token: UUID
    session_id: BrowserSessionId
    page_id: BrowserPageId
    revision: BrowserPageRevision
    request: BrowserNavigationRequest

    def __post_init__(self) -> None:
        if not isinstance(self.token, UUID):
            raise TypeError("prepared browser navigation token must be UUID")
        if not isinstance(self.session_id, BrowserSessionId):
            raise TypeError("session_id must be BrowserSessionId")
        if not isinstance(self.page_id, BrowserPageId):
            raise TypeError("page_id must be BrowserPageId")
        if not isinstance(self.revision, BrowserPageRevision):
            raise TypeError("revision must be BrowserPageRevision")
        if not isinstance(self.request, BrowserNavigationRequest):
            raise TypeError("request must be BrowserNavigationRequest")


@dataclass(frozen=True, slots=True)
class BrowserPreparedNavigation:
    """Final zero-effect navigation readiness with exact admitted destination pins."""

    plan: BrowserPreparedNavigationPlan
    destination: BrowserDestinationAdmission

    def __post_init__(self) -> None:
        if not isinstance(self.plan, BrowserPreparedNavigationPlan):
            raise TypeError("plan must be BrowserPreparedNavigationPlan")
        if not isinstance(self.destination, BrowserDestinationAdmission):
            raise TypeError("destination must be BrowserDestinationAdmission")
        if self.destination.origin != self.plan.request.origin:
            raise ValueError("navigation destination origin must match the prepared request")

    @property
    def token(self) -> UUID:
        return self.plan.token

    @property
    def session_id(self) -> BrowserSessionId:
        return self.plan.session_id

    @property
    def page_id(self) -> BrowserPageId:
        return self.plan.page_id

    @property
    def revision(self) -> BrowserPageRevision:
        return self.plan.revision

    @property
    def request(self) -> BrowserNavigationRequest:
        return self.plan.request


@dataclass(frozen=True, slots=True)
class BrowserNavigationCommitResult:
    """One started top-level request result without remote document disclosure."""

    prepared_token: UUID
    page: BrowserPageDescriptor | None = None
    redirect_location: str | None = field(default=None, repr=False)
    effect_started: bool = True

    def __post_init__(self) -> None:
        if not isinstance(self.prepared_token, UUID):
            raise TypeError("prepared_token must be UUID")
        if self.page is not None and not isinstance(self.page, BrowserPageDescriptor):
            raise TypeError("page must be BrowserPageDescriptor or None")
        if self.redirect_location is not None:
            if not isinstance(self.redirect_location, str):
                raise TypeError("redirect_location must be a string or None")
            if (
                not self.redirect_location
                or len(self.redirect_location) > MAX_BROWSER_REDIRECT_LOCATION_LENGTH
            ):
                raise ValueError("redirect location size is outside supported bounds")
        if (self.page is None) == (self.redirect_location is None):
            raise ValueError("navigation result must contain exactly one page or redirect")
        if self.effect_started is not True:
            raise ValueError("navigation result must represent a request that started")


@dataclass(frozen=True, slots=True)
class BrowserAdapterCommitResult:
    """Content-minimized adapter commit result after one local browser effect."""

    prepared_token: UUID
    page: BrowserPageDescriptor
    effect_started: bool = True

    def __post_init__(self) -> None:
        if not isinstance(self.prepared_token, UUID):
            raise TypeError("prepared_token must be UUID")
        if not isinstance(self.page, BrowserPageDescriptor):
            raise TypeError("page must be BrowserPageDescriptor")
        if self.effect_started is not True:
            raise ValueError("adapter commit result must represent an effect that started")


@runtime_checkable
class BrowserAdapter(Protocol):
    """Browser adapter contract with explicit zero-effect preparation and one-shot commit."""

    async def open_session(
        self,
        profile: BrowserProfile,
        session: BrowserSessionDescriptor,
    ) -> BrowserPageDescriptor:
        """Create adapter-owned ephemeral state without remote navigation or content fetch."""
        ...

    async def close_session(self, session_id: BrowserSessionId) -> None:
        """Discard one ephemeral adapter session and any uncommitted readiness state."""
        ...

    async def snapshot(self, page: BrowserPageDescriptor) -> BrowserPageSnapshot:
        """Return bounded untrusted page data for the exact current revision."""
        ...

    async def prepare_navigation(
        self,
        page: BrowserPageDescriptor,
        request: BrowserNavigationRequest,
    ) -> BrowserPreparedNavigationPlan:
        """Resolve one top-level request readiness without DNS, bytes, or page mutation."""
        ...

    async def prepare_fill(
        self,
        page: BrowserPageDescriptor,
        element_id: BrowserElementId,
        value: BrowserFillInput,
    ) -> BrowserPreparedEffect:
        """Resolve one exact fill intent without changing visible page state."""
        ...

    async def prepare_click(
        self,
        page: BrowserPageDescriptor,
        element_id: BrowserElementId,
    ) -> BrowserPreparedEffect:
        """Resolve one exact click intent without changing visible page state."""
        ...

    async def commit_navigation(
        self,
        prepared: BrowserPreparedNavigation,
    ) -> BrowserNavigationCommitResult:
        """Use only admitted pins, preserve TLS host, ignore proxies, and never auto-follow."""
        ...

    async def commit_click_request(
        self,
        prepared: BrowserPreparedClickRequest,
    ) -> BrowserClickCommitResult:
        """Commit one exact admitted click-derived request without auto-following redirects."""
        ...

    async def commit_prepared(
        self,
        prepared: BrowserPreparedEffect,
    ) -> BrowserAdapterCommitResult:
        """Commit one already prepared local effect exactly once."""
        ...

    async def discard_prepared(self, prepared: BrowserPreparedEffect) -> None:
        """Discard zero-effect readiness without performing the prepared effect."""
        ...

    async def discard_navigation(self, prepared: BrowserPreparedNavigationPlan) -> None:
        """Discard zero-effect navigation readiness without emitting request bytes."""
        ...


@runtime_checkable
class BrowserAdapterLifecycle(Protocol):
    """Optional bounded adapter-owned shutdown surface for Runtime ownership."""

    async def aclose(self) -> None:
        """Release all adapter-owned ephemeral browser state without remote effects."""
        ...
