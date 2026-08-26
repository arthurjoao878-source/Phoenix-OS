"""Immutable public contracts for secure Phoenix browser automation."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID, uuid4

MAX_BROWSER_IDENTIFIER_LENGTH = 128
MAX_BROWSER_PAGE_REVISION = 2_147_483_647
MAX_BROWSER_SNAPSHOT_TITLE_CHARS = 4_096
MAX_BROWSER_SNAPSHOT_TEXT_CHARS = 262_144
MAX_BROWSER_SNAPSHOT_TEXT_BYTES = 1_048_576
MAX_BROWSER_SNAPSHOT_ELEMENTS = 2_048
MAX_BROWSER_ELEMENT_NAME_CHARS = 2_048
MAX_BROWSER_ELEMENT_VALUE_CHARS = 16_384
MAX_BROWSER_FILL_TEXT_CHARS = 65_536
MAX_BROWSER_FILL_TEXT_BYTES = 196_608

_IDENTIFIER_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,127})$")


def _normalize_identifier(value: str, *, label: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{label} must be a string")
    normalized = value.strip().lower()
    if len(normalized) > MAX_BROWSER_IDENTIFIER_LENGTH:
        raise ValueError(f"{label} exceeds the maximum length")
    if _IDENTIFIER_PATTERN.fullmatch(normalized) is None:
        raise ValueError(
            f"{label} must use lowercase ASCII letters, digits, dot, underscore, or hyphen"
        )
    return normalized


def _require_uuid(value: UUID, *, label: str) -> None:
    if not isinstance(value, UUID):
        raise TypeError(f"{label} must be UUID")


def _positive_int(value: int, *, label: str, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{label} must be an integer")
    if value <= 0 or value > maximum:
        raise ValueError(f"{label} is outside supported bounds")
    return value


def _require_aware(value: datetime, *, label: str) -> None:
    if not isinstance(value, datetime):
        raise TypeError(f"{label} must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")


def _bounded_unicode(
    value: str,
    *,
    label: str,
    maximum_chars: int,
    maximum_bytes: int | None = None,
) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{label} must be a string")
    if len(value) > maximum_chars:
        raise ValueError(f"{label} exceeds the maximum character count")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exception:
        raise ValueError(f"{label} is not valid Unicode") from exception
    if maximum_bytes is not None and len(encoded) > maximum_bytes:
        raise ValueError(f"{label} exceeds the maximum byte count")
    return value


@dataclass(frozen=True, slots=True, order=True)
class BrowserProfileId:
    """Stable server-owned identity for one configured browser profile."""

    value: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "value",
            _normalize_identifier(self.value, label="browser profile id"),
        )

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True, order=True)
class BrowserAdapterId:
    """Stable server-owned identity for one reviewed browser adapter configuration."""

    value: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "value",
            _normalize_identifier(self.value, label="browser adapter id"),
        )

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True, order=True)
class BrowserNavigationTargetId:
    """Stable server-owned identity for one initial navigation target."""

    value: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "value",
            _normalize_identifier(self.value, label="browser navigation target id"),
        )

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True, order=True)
class BrowserSessionId:
    """Opaque Phoenix browser-session identity; never bearer authority."""

    value: UUID = field(default_factory=uuid4)

    def __post_init__(self) -> None:
        _require_uuid(self.value, label="browser session id")

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True, order=True)
class BrowserPageId:
    """Opaque Phoenix page identity for the one page owned by a browser session."""

    value: UUID = field(default_factory=uuid4)

    def __post_init__(self) -> None:
        _require_uuid(self.value, label="browser page id")

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True, order=True)
class BrowserElementId:
    """Opaque Phoenix element identity bound later to one exact page revision."""

    value: UUID = field(default_factory=uuid4)

    def __post_init__(self) -> None:
        _require_uuid(self.value, label="browser element id")

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True, order=True)
class BrowserPageRevision:
    """Positive Phoenix-owned freshness identity for one exact page state."""

    value: int

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "value",
            _positive_int(
                self.value,
                label="browser page revision",
                maximum=MAX_BROWSER_PAGE_REVISION,
            ),
        )

    def __str__(self) -> str:
        return str(self.value)


class BrowserElementKind(StrEnum):
    """Finite element kinds exposed by the content-minimized page snapshot."""

    LINK = "link"
    BUTTON = "button"
    SUBMIT = "submit"
    TEXT_INPUT = "text_input"
    TEXT_AREA = "text_area"
    CHECKBOX = "checkbox"
    RADIO = "radio"


class BrowserElementAction(StrEnum):
    """Finite interaction hints; these are data and never authorization."""

    CLICK = "click"
    FILL = "fill"


class BrowserOperationOutcome(StrEnum):
    """Finite public operation result classes without remote/native details."""

    SUCCEEDED = "succeeded"
    REJECTED = "rejected"
    STALE = "stale"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"
    FAILED = "failed"
    INDETERMINATE = "indeterminate"


_ALLOWED_ACTIONS: dict[BrowserElementKind, frozenset[BrowserElementAction]] = {
    BrowserElementKind.LINK: frozenset({BrowserElementAction.CLICK}),
    BrowserElementKind.BUTTON: frozenset({BrowserElementAction.CLICK}),
    BrowserElementKind.SUBMIT: frozenset({BrowserElementAction.CLICK}),
    BrowserElementKind.TEXT_INPUT: frozenset({BrowserElementAction.FILL}),
    BrowserElementKind.TEXT_AREA: frozenset({BrowserElementAction.FILL}),
    BrowserElementKind.CHECKBOX: frozenset({BrowserElementAction.CLICK}),
    BrowserElementKind.RADIO: frozenset({BrowserElementAction.CLICK}),
}


@dataclass(frozen=True, slots=True)
class BrowserFillInput:
    """Bounded Unicode caller data for a future exact fill operation."""

    value: str = field(repr=False)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "value",
            _bounded_unicode(
                self.value,
                label="browser fill input",
                maximum_chars=MAX_BROWSER_FILL_TEXT_CHARS,
                maximum_bytes=MAX_BROWSER_FILL_TEXT_BYTES,
            ),
        )

    @property
    def digest(self) -> str:
        """Deterministic exact-input digest used by later authority intent binding."""

        return f"sha256:{hashlib.sha256(self.value.encode('utf-8')).hexdigest()}"


@dataclass(frozen=True, slots=True)
class BrowserSessionDescriptor:
    """Content-minimized session state; identity is data rather than bearer authority."""

    profile_id: BrowserProfileId
    profile_generation: int
    session_id: BrowserSessionId
    page_id: BrowserPageId
    created_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        if not isinstance(self.profile_id, BrowserProfileId):
            raise TypeError("profile_id must be BrowserProfileId")
        _positive_int(
            self.profile_generation,
            label="browser profile generation",
            maximum=2_147_483_647,
        )
        if not isinstance(self.session_id, BrowserSessionId):
            raise TypeError("session_id must be BrowserSessionId")
        if not isinstance(self.page_id, BrowserPageId):
            raise TypeError("page_id must be BrowserPageId")
        _require_aware(self.created_at, label="created_at")
        _require_aware(self.expires_at, label="expires_at")
        if self.expires_at <= self.created_at:
            raise ValueError("browser session expiry must be after creation")


@dataclass(frozen=True, slots=True)
class BrowserPageDescriptor:
    """Opaque page identity plus the exact current Phoenix freshness revision."""

    session_id: BrowserSessionId
    page_id: BrowserPageId
    revision: BrowserPageRevision

    def __post_init__(self) -> None:
        if not isinstance(self.session_id, BrowserSessionId):
            raise TypeError("session_id must be BrowserSessionId")
        if not isinstance(self.page_id, BrowserPageId):
            raise TypeError("page_id must be BrowserPageId")
        if not isinstance(self.revision, BrowserPageRevision):
            raise TypeError("revision must be BrowserPageRevision")


@dataclass(frozen=True, slots=True)
class BrowserElementDescriptor:
    """Reviewed untrusted element data bound by its containing page snapshot."""

    element_id: BrowserElementId
    kind: BrowserElementKind
    name: str = ""
    value: str | None = field(default=None, repr=False)
    actions: tuple[BrowserElementAction, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.element_id, BrowserElementId):
            raise TypeError("element_id must be BrowserElementId")
        kind = BrowserElementKind(self.kind)
        name = _bounded_unicode(
            self.name,
            label="browser element name",
            maximum_chars=MAX_BROWSER_ELEMENT_NAME_CHARS,
        )
        value = self.value
        if value is not None:
            value = _bounded_unicode(
                value,
                label="browser element value",
                maximum_chars=MAX_BROWSER_ELEMENT_VALUE_CHARS,
            )
            if kind not in {BrowserElementKind.TEXT_INPUT, BrowserElementKind.TEXT_AREA}:
                raise ValueError("browser element value is exposed only for reviewed text inputs")

        supplied_actions = tuple(self.actions)
        normalized_actions = tuple(BrowserElementAction(item) for item in supplied_actions)
        if len(normalized_actions) != len(set(normalized_actions)):
            raise ValueError("browser element actions contain duplicates")
        allowed = _ALLOWED_ACTIONS[kind]
        if any(action not in allowed for action in normalized_actions):
            raise ValueError("browser element action is incompatible with element kind")

        object.__setattr__(self, "kind", kind)
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "value", value)
        object.__setattr__(self, "actions", normalized_actions)


@dataclass(frozen=True, slots=True)
class BrowserPageSnapshot:
    """Bounded untrusted page observation with no raw HTML, cookies, or authority objects."""

    session_id: BrowserSessionId
    page_id: BrowserPageId
    revision: BrowserPageRevision
    title: str = ""
    text: str = ""
    elements: tuple[BrowserElementDescriptor, ...] = ()
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        if not isinstance(self.session_id, BrowserSessionId):
            raise TypeError("session_id must be BrowserSessionId")
        if not isinstance(self.page_id, BrowserPageId):
            raise TypeError("page_id must be BrowserPageId")
        if not isinstance(self.revision, BrowserPageRevision):
            raise TypeError("revision must be BrowserPageRevision")
        title = _bounded_unicode(
            self.title,
            label="browser page title",
            maximum_chars=MAX_BROWSER_SNAPSHOT_TITLE_CHARS,
        )
        text = _bounded_unicode(
            self.text,
            label="browser page text",
            maximum_chars=MAX_BROWSER_SNAPSHOT_TEXT_CHARS,
            maximum_bytes=MAX_BROWSER_SNAPSHOT_TEXT_BYTES,
        )
        elements = tuple(self.elements)
        if len(elements) > MAX_BROWSER_SNAPSHOT_ELEMENTS:
            raise ValueError("browser page snapshot contains too many elements")
        if any(not isinstance(item, BrowserElementDescriptor) for item in elements):
            raise TypeError("elements must contain BrowserElementDescriptor values")
        element_ids = tuple(item.element_id for item in elements)
        if len(element_ids) != len(set(element_ids)):
            raise ValueError("browser page snapshot contains duplicate element ids")
        _require_aware(self.created_at, label="created_at")

        object.__setattr__(self, "title", title)
        object.__setattr__(self, "text", text)
        object.__setattr__(self, "elements", elements)


@dataclass(frozen=True, slots=True)
class BrowserOperationResult:
    """Content-minimized result metadata; remote/page content is disclosed separately."""

    operation_id: UUID
    outcome: BrowserOperationOutcome
    session_id: BrowserSessionId | None = None
    page_id: BrowserPageId | None = None
    revision: BrowserPageRevision | None = None
    effect_started: bool = False
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        _require_uuid(self.operation_id, label="operation_id")
        outcome = BrowserOperationOutcome(self.outcome)
        if self.session_id is not None and not isinstance(self.session_id, BrowserSessionId):
            raise TypeError("session_id must be BrowserSessionId or None")
        if self.page_id is not None and not isinstance(self.page_id, BrowserPageId):
            raise TypeError("page_id must be BrowserPageId or None")
        if self.revision is not None and not isinstance(self.revision, BrowserPageRevision):
            raise TypeError("revision must be BrowserPageRevision or None")
        if not isinstance(self.effect_started, bool):
            raise TypeError("effect_started must be a boolean")
        _require_aware(self.created_at, label="created_at")

        if outcome is BrowserOperationOutcome.INDETERMINATE and not self.effect_started:
            raise ValueError("indeterminate browser result requires effect_started")
        if self.effect_started and outcome not in {
            BrowserOperationOutcome.SUCCEEDED,
            BrowserOperationOutcome.INDETERMINATE,
        }:
            raise ValueError("post-effect browser failure must be represented as indeterminate")

        object.__setattr__(self, "outcome", outcome)
