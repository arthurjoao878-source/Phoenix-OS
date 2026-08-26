"""Reviewed adapter boundary for RFC-0035 secure browser automation."""

from __future__ import annotations

import re
from dataclasses import dataclass
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
from phoenix_os.browser_automation.profiles import BrowserProfile

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
        if kind is BrowserPreparedEffectKind.FILL and self.input_digest is None:
            raise ValueError("prepared fill effect requires an exact input digest")
        if kind is BrowserPreparedEffectKind.CLICK and self.input_digest is not None:
            raise ValueError("prepared click effect cannot contain fill input material")
        object.__setattr__(self, "kind", kind)


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

    async def commit_prepared(
        self,
        prepared: BrowserPreparedEffect,
    ) -> BrowserAdapterCommitResult:
        """Commit one already prepared local effect exactly once."""
        ...

    async def discard_prepared(self, prepared: BrowserPreparedEffect) -> None:
        """Discard zero-effect readiness without performing the prepared effect."""
        ...
