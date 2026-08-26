from dataclasses import FrozenInstanceError, fields
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from phoenix_os.browser_automation import (
    MAX_BROWSER_FILL_TEXT_CHARS,
    MAX_BROWSER_SNAPSHOT_ELEMENTS,
    BrowserAdapterId,
    BrowserElementAction,
    BrowserElementDescriptor,
    BrowserElementId,
    BrowserElementKind,
    BrowserFillInput,
    BrowserNavigationTargetId,
    BrowserOperationOutcome,
    BrowserOperationResult,
    BrowserPageDescriptor,
    BrowserPageId,
    BrowserPageRevision,
    BrowserPageSnapshot,
    BrowserProfileId,
    BrowserSessionDescriptor,
    BrowserSessionId,
)

_NOW = datetime(2026, 8, 25, 3, tzinfo=UTC)


def test_server_owned_and_opaque_browser_identifiers_are_typed_and_bounded() -> None:
    assert str(BrowserProfileId(" Docs.Profile ")) == "docs.profile"
    assert str(BrowserAdapterId(" Deterministic.Fake ")) == "deterministic.fake"
    assert str(BrowserNavigationTargetId(" Home_Page ")) == "home_page"

    for value in ("", "has space", "/absolute", "https://example.com", "shell&escape"):
        with pytest.raises(ValueError):
            BrowserProfileId(value)

    session = BrowserSessionId(UUID(int=1))
    page = BrowserPageId(UUID(int=2))
    element = BrowserElementId(UUID(int=3))
    assert str(session) == str(UUID(int=1))
    assert str(page) == str(UUID(int=2))
    assert str(element) == str(UUID(int=3))

    with pytest.raises(TypeError):
        BrowserSessionId("not-a-uuid")  # type: ignore[arg-type]


def test_page_revision_is_positive_and_boolean_is_not_an_integer_revision() -> None:
    assert BrowserPageRevision(7).value == 7
    with pytest.raises(ValueError):
        BrowserPageRevision(0)
    with pytest.raises(TypeError):
        BrowserPageRevision(True)


def test_fill_input_is_bounded_immutable_data_with_exact_digest_and_redacted_repr() -> None:
    value = BrowserFillInput("hello")

    assert value.digest == (
        "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    )
    assert "hello" not in repr(value)
    with pytest.raises(FrozenInstanceError):
        value.value = "changed"  # type: ignore[misc]
    with pytest.raises(ValueError, match="byte count"):
        BrowserFillInput("😀" * MAX_BROWSER_FILL_TEXT_CHARS)


def test_element_surface_is_finite_and_omits_password_file_and_selector_escape_hatches() -> None:
    assert "password" not in {kind.value for kind in BrowserElementKind}
    assert "file" not in {kind.value for kind in BrowserElementKind}

    names = {item.name for item in fields(BrowserElementDescriptor)}
    for forbidden in (
        "selector",
        "xpath",
        "coordinates",
        "x",
        "y",
        "native_handle",
        "html",
        "script",
    ):
        assert forbidden not in names

    descriptor = BrowserElementDescriptor(
        element_id=BrowserElementId(UUID(int=4)),
        kind=BrowserElementKind.TEXT_INPUT,
        name="Search",
        value="phoenix",
        actions=(BrowserElementAction.FILL,),
    )
    assert descriptor.actions == (BrowserElementAction.FILL,)
    assert "phoenix" not in repr(descriptor)

    with pytest.raises(ValueError, match="incompatible"):
        BrowserElementDescriptor(
            element_id=BrowserElementId(UUID(int=5)),
            kind=BrowserElementKind.TEXT_INPUT,
            actions=(BrowserElementAction.CLICK,),
        )
    with pytest.raises(ValueError, match="reviewed text inputs"):
        BrowserElementDescriptor(
            element_id=BrowserElementId(UUID(int=6)),
            kind=BrowserElementKind.BUTTON,
            value="secret",
        )


def test_page_snapshot_is_bounded_immutable_and_contains_no_raw_browser_state_fields() -> None:
    session_id = BrowserSessionId(UUID(int=7))
    page_id = BrowserPageId(UUID(int=8))
    revision = BrowserPageRevision(1)
    element = BrowserElementDescriptor(
        element_id=BrowserElementId(UUID(int=9)),
        kind=BrowserElementKind.LINK,
        name="Docs",
        actions=(BrowserElementAction.CLICK,),
    )
    snapshot = BrowserPageSnapshot(
        session_id=session_id,
        page_id=page_id,
        revision=revision,
        title="Phoenix",
        text="Documentation",
        elements=(element,),
        created_at=_NOW,
    )

    assert snapshot.elements == (element,)
    names = {item.name for item in fields(BrowserPageSnapshot)}
    for forbidden in (
        "html",
        "dom",
        "cookies",
        "storage",
        "headers",
        "credentials",
        "certificate",
        "native_handle",
    ):
        assert forbidden not in names

    with pytest.raises(ValueError, match="duplicate element"):
        BrowserPageSnapshot(
            session_id=session_id,
            page_id=page_id,
            revision=revision,
            elements=(element, element),
        )
    with pytest.raises(ValueError, match="too many elements"):
        BrowserPageSnapshot(
            session_id=session_id,
            page_id=page_id,
            revision=revision,
            elements=tuple(
                BrowserElementDescriptor(
                    element_id=BrowserElementId(UUID(int=index + 20)),
                    kind=BrowserElementKind.BUTTON,
                )
                for index in range(MAX_BROWSER_SNAPSHOT_ELEMENTS + 1)
            ),
        )


def test_session_and_page_descriptors_bind_generation_and_exact_page_revision() -> None:
    session_id = BrowserSessionId(UUID(int=10))
    page_id = BrowserPageId(UUID(int=11))
    descriptor = BrowserSessionDescriptor(
        profile_id=BrowserProfileId("docs"),
        profile_generation=3,
        session_id=session_id,
        page_id=page_id,
        created_at=_NOW,
        expires_at=_NOW + timedelta(minutes=10),
    )
    page = BrowserPageDescriptor(
        session_id=session_id,
        page_id=page_id,
        revision=BrowserPageRevision(2),
    )

    assert descriptor.profile_generation == 3
    assert page.revision == BrowserPageRevision(2)

    with pytest.raises(ValueError, match="expiry"):
        BrowserSessionDescriptor(
            profile_id=BrowserProfileId("docs"),
            profile_generation=1,
            session_id=session_id,
            page_id=page_id,
            created_at=_NOW,
            expires_at=_NOW,
        )


def test_operation_result_enforces_indeterminate_post_effect_semantics() -> None:
    result = BrowserOperationResult(
        operation_id=UUID(int=12),
        outcome=BrowserOperationOutcome.INDETERMINATE,
        effect_started=True,
        created_at=_NOW,
    )
    assert result.outcome is BrowserOperationOutcome.INDETERMINATE

    with pytest.raises(ValueError, match="requires effect_started"):
        BrowserOperationResult(
            operation_id=UUID(int=13),
            outcome=BrowserOperationOutcome.INDETERMINATE,
            effect_started=False,
        )
    with pytest.raises(ValueError, match="post-effect"):
        BrowserOperationResult(
            operation_id=UUID(int=14),
            outcome=BrowserOperationOutcome.FAILED,
            effect_started=True,
        )
