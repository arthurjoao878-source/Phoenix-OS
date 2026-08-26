from dataclasses import fields
from uuid import UUID

import pytest

from phoenix_os.browser_automation.adapter import (
    BrowserAdapter,
    BrowserAdapterCommitResult,
    BrowserPreparedEffect,
    BrowserPreparedEffectKind,
)
from phoenix_os.browser_automation.contracts import (
    BrowserElementId,
    BrowserPageDescriptor,
    BrowserPageId,
    BrowserPageRevision,
    BrowserSessionId,
)


def _prepared(*, kind: BrowserPreparedEffectKind, digest: str | None) -> BrowserPreparedEffect:
    return BrowserPreparedEffect(
        token=UUID(int=1),
        kind=kind,
        session_id=BrowserSessionId(UUID(int=2)),
        page_id=BrowserPageId(UUID(int=3)),
        revision=BrowserPageRevision(4),
        element_id=BrowserElementId(UUID(int=5)),
        input_digest=digest,
    )


def test_prepared_effect_is_content_minimized_exact_revision_data() -> None:
    names = {item.name for item in fields(BrowserPreparedEffect)}
    assert names == {
        "token",
        "kind",
        "session_id",
        "page_id",
        "revision",
        "element_id",
        "input_digest",
    }
    for forbidden in (
        "url",
        "selector",
        "xpath",
        "coordinate",
        "script",
        "javascript",
        "cookie",
        "password",
        "credential",
        "native_handle",
    ):
        assert forbidden not in names


def test_fill_preparation_requires_digest_and_click_cannot_carry_fill_data() -> None:
    digest = "sha256:" + ("a" * 64)
    assert _prepared(kind=BrowserPreparedEffectKind.FILL, digest=digest).input_digest == digest
    assert _prepared(kind=BrowserPreparedEffectKind.CLICK, digest=None).input_digest is None

    with pytest.raises(ValueError, match="requires an exact input digest"):
        _prepared(kind=BrowserPreparedEffectKind.FILL, digest=None)
    with pytest.raises(ValueError, match="cannot contain fill input"):
        _prepared(kind=BrowserPreparedEffectKind.CLICK, digest=digest)
    for invalid in ("sha256:short", "sha256:" + ("g" * 64), "SHA256:" + ("a" * 64)):
        with pytest.raises(ValueError, match="exact SHA-256"):
            _prepared(kind=BrowserPreparedEffectKind.FILL, digest=invalid)


def test_adapter_commit_result_requires_effect_started_and_exact_page_identity() -> None:
    page = BrowserPageDescriptor(
        session_id=BrowserSessionId(UUID(int=10)),
        page_id=BrowserPageId(UUID(int=11)),
        revision=BrowserPageRevision(2),
    )
    result = BrowserAdapterCommitResult(prepared_token=UUID(int=12), page=page)
    assert result.effect_started is True
    assert result.page == page

    with pytest.raises(ValueError, match="effect that started"):
        BrowserAdapterCommitResult(
            prepared_token=UUID(int=12),
            page=page,
            effect_started=False,
        )


def test_browser_adapter_protocol_exposes_no_generic_escape_hatch() -> None:
    members = set(BrowserAdapter.__dict__)
    assert {
        "open_session",
        "close_session",
        "snapshot",
        "prepare_fill",
        "prepare_click",
        "commit_prepared",
        "discard_prepared",
    } <= members
    for forbidden in (
        "evaluate",
        "execute_script",
        "cdp",
        "devtools",
        "select",
        "xpath",
        "coordinate_click",
        "open_url",
        "fetch",
        "download",
        "upload",
    ):
        assert forbidden not in members
