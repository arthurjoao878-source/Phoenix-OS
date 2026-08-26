from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from phoenix_os.browser_automation.adapter import BrowserAdapter, BrowserPreparedEffectKind
from phoenix_os.browser_automation.contracts import (
    BrowserAdapterId,
    BrowserElementAction,
    BrowserElementKind,
    BrowserFillInput,
    BrowserNavigationTargetId,
    BrowserPageId,
    BrowserProfileId,
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
from phoenix_os.browser_automation.fake import (
    DeterministicBrowserAdapter,
    DeterministicBrowserElement,
    DeterministicBrowserPage,
)
from phoenix_os.browser_automation.profiles import (
    BrowserDestinationMode,
    BrowserNavigationTarget,
    BrowserNetworkPolicy,
    BrowserOrigin,
    BrowserProfile,
    BrowserProfileLimits,
)

_NOW = datetime(2026, 8, 25, 4, tzinfo=UTC)


def _profile(
    *,
    adapter_id: str = "deterministic-browser",
    max_fill_text_chars: int = 32_768,
) -> BrowserProfile:
    origin = BrowserOrigin(BrowserDestinationMode.HOSTED_HTTPS, "example.com")
    return BrowserProfile(
        profile_id=BrowserProfileId("browser-test"),
        generation=3,
        adapter_id=BrowserAdapterId(adapter_id),
        allowed_origins=(origin,),
        initial_targets=(
            BrowserNavigationTarget(
                BrowserNavigationTargetId("home"),
                origin,
                "/",
            ),
        ),
        network_policy=BrowserNetworkPolicy(allow_public_networks=True),
        limits=BrowserProfileLimits(max_fill_text_chars=max_fill_text_chars),
    )


def _session() -> BrowserSessionDescriptor:
    return BrowserSessionDescriptor(
        profile_id=BrowserProfileId("browser-test"),
        profile_generation=3,
        session_id=BrowserSessionId(UUID(int=101)),
        page_id=BrowserPageId(UUID(int=102)),
        created_at=_NOW,
        expires_at=_NOW + timedelta(minutes=10),
    )


def _page_seed() -> DeterministicBrowserPage:
    return DeterministicBrowserPage(
        title="Fixture",
        text="Untrusted fixture content",
        elements=(
            DeterministicBrowserElement(
                "name",
                BrowserElementKind.TEXT_INPUT,
                name="Name",
                value="before",
                actions=(BrowserElementAction.FILL,),
            ),
            DeterministicBrowserElement(
                "submit",
                BrowserElementKind.BUTTON,
                name="Submit",
                actions=(BrowserElementAction.CLICK,),
            ),
        ),
    )


@pytest.mark.asyncio
async def test_fake_implements_reviewed_adapter_without_network_or_production_engine() -> None:
    adapter = DeterministicBrowserAdapter(initial_page=_page_seed())
    assert isinstance(adapter, BrowserAdapter)
    assert adapter.adapter_id == BrowserAdapterId("deterministic-browser")
    assert adapter.session_count == 0
    assert adapter.prepared_count == 0

    page = await adapter.open_session(_profile(), _session())
    assert page.revision.value == 1
    assert adapter.session_count == 1

    snapshot = await adapter.snapshot(page)
    assert snapshot.title == "Fixture"
    assert snapshot.text == "Untrusted fixture content"
    assert [item.name for item in snapshot.elements] == ["Name", "Submit"]


@pytest.mark.asyncio
async def test_prepare_fill_is_zero_visible_effect_and_keeps_plaintext_out_of_prepared_record() -> (
    None
):
    adapter = DeterministicBrowserAdapter(initial_page=_page_seed())
    page = await adapter.open_session(_profile(), _session())
    before = await adapter.snapshot(page)
    input_element = before.elements[0]

    prepared = await adapter.prepare_fill(
        page,
        input_element.element_id,
        BrowserFillInput("after"),
    )
    during = await adapter.snapshot(page)

    assert prepared.kind is BrowserPreparedEffectKind.FILL
    assert prepared.input_digest == BrowserFillInput("after").digest
    assert "after" not in repr(prepared)
    assert during == before
    assert adapter.prepared_count == 1

    await adapter.discard_prepared(prepared)
    assert await adapter.snapshot(page) == before
    assert adapter.prepared_count == 0


@pytest.mark.asyncio
async def test_commit_fill_advances_revision_rotates_element_ids_and_rejects_stale_reuse() -> None:
    adapter = DeterministicBrowserAdapter(initial_page=_page_seed())
    page1 = await adapter.open_session(_profile(), _session())
    snapshot1 = await adapter.snapshot(page1)
    input1 = snapshot1.elements[0]
    prepared = await adapter.prepare_fill(page1, input1.element_id, BrowserFillInput("after"))

    result = await adapter.commit_prepared(prepared)
    assert result.effect_started is True
    assert result.page.revision.value == 2
    assert adapter.prepared_count == 0

    snapshot2 = await adapter.snapshot(result.page)
    input2 = snapshot2.elements[0]
    assert input2.value == "after"
    assert input2.element_id != input1.element_id

    with pytest.raises(BrowserAutomationStaleError):
        await adapter.snapshot(page1)
    with pytest.raises(BrowserAutomationStaleError):
        await adapter.commit_prepared(prepared)
    with pytest.raises(BrowserAutomationStaleError):
        await adapter.prepare_fill(result.page, input1.element_id, BrowserFillInput("again"))


@pytest.mark.asyncio
async def test_commit_one_prepared_effect_stales_other_same_revision_readiness() -> None:
    adapter = DeterministicBrowserAdapter(initial_page=_page_seed())
    page = await adapter.open_session(_profile(), _session())
    snapshot = await adapter.snapshot(page)
    fill = await adapter.prepare_fill(page, snapshot.elements[0].element_id, BrowserFillInput("x"))
    click = await adapter.prepare_click(page, snapshot.elements[1].element_id)

    committed = await adapter.commit_prepared(click)
    assert committed.page.revision.value == 2
    with pytest.raises(BrowserAutomationStaleError):
        await adapter.commit_prepared(fill)


@pytest.mark.asyncio
async def test_click_prepare_is_zero_effect_and_commit_is_local_one_shot() -> None:
    adapter = DeterministicBrowserAdapter(initial_page=_page_seed())
    page = await adapter.open_session(_profile(), _session())
    before = await adapter.snapshot(page)
    button = before.elements[1]

    prepared = await adapter.prepare_click(page, button.element_id)
    assert prepared.kind is BrowserPreparedEffectKind.CLICK
    assert prepared.input_digest is None
    assert await adapter.snapshot(page) == before

    committed = await adapter.commit_prepared(prepared)
    assert committed.page.revision.value == 2
    with pytest.raises(BrowserAutomationStaleError):
        await adapter.commit_prepared(prepared)


@pytest.mark.asyncio
async def test_profile_adapter_generation_and_session_identity_are_exact() -> None:
    adapter = DeterministicBrowserAdapter(initial_page=_page_seed())

    with pytest.raises(BrowserAutomationOperationDisabledError):
        await adapter.open_session(_profile(adapter_id="other-adapter"), _session())

    wrong_generation = BrowserSessionDescriptor(
        profile_id=BrowserProfileId("browser-test"),
        profile_generation=2,
        session_id=BrowserSessionId(UUID(int=201)),
        page_id=BrowserPageId(UUID(int=202)),
        created_at=_NOW,
        expires_at=_NOW + timedelta(minutes=10),
    )
    with pytest.raises(BrowserAutomationStaleError):
        await adapter.open_session(_profile(), wrong_generation)

    await adapter.open_session(_profile(), _session())
    with pytest.raises(BrowserAutomationStaleError):
        await adapter.open_session(_profile(), _session())


@pytest.mark.asyncio
async def test_profile_fill_limit_is_enforced_before_preparation() -> None:
    adapter = DeterministicBrowserAdapter(initial_page=_page_seed())
    page = await adapter.open_session(_profile(max_fill_text_chars=1), _session())
    snapshot = await adapter.snapshot(page)

    with pytest.raises(BrowserAutomationLimitExceededError):
        await adapter.prepare_fill(
            page,
            snapshot.elements[0].element_id,
            BrowserFillInput("too long"),
        )
    assert adapter.prepared_count == 0
    assert await adapter.snapshot(page) == snapshot


@pytest.mark.asyncio
async def test_close_and_adapter_shutdown_discard_ephemeral_state_and_readiness() -> None:
    adapter = DeterministicBrowserAdapter(initial_page=_page_seed())
    page = await adapter.open_session(_profile(), _session())
    snapshot = await adapter.snapshot(page)
    prepared = await adapter.prepare_click(page, snapshot.elements[1].element_id)

    await adapter.close_session(page.session_id)
    assert adapter.session_count == 0
    assert adapter.prepared_count == 0
    with pytest.raises(BrowserAutomationTargetNotFoundError):
        await adapter.snapshot(page)
    with pytest.raises(BrowserAutomationStaleError):
        await adapter.commit_prepared(prepared)

    await adapter.aclose()
    assert adapter.closed is True
    with pytest.raises(BrowserAutomationAdapterError):
        await adapter.open_session(_profile(), _session())


@pytest.mark.asyncio
async def test_opaque_element_and_prepared_ids_are_deterministic_but_revision_scoped() -> None:
    first = DeterministicBrowserAdapter(initial_page=_page_seed())
    second = DeterministicBrowserAdapter(initial_page=_page_seed())

    page_a = await first.open_session(_profile(), _session())
    page_b = await second.open_session(_profile(), _session())
    snapshot_a = await first.snapshot(page_a)
    snapshot_b = await second.snapshot(page_b)

    assert [item.element_id for item in snapshot_a.elements] == [
        item.element_id for item in snapshot_b.elements
    ]

    prepared_a = await first.prepare_click(page_a, snapshot_a.elements[1].element_id)
    prepared_b = await second.prepare_click(page_b, snapshot_b.elements[1].element_id)
    assert prepared_a.token == prepared_b.token

    page2 = (await first.commit_prepared(prepared_a)).page
    snapshot2 = await first.snapshot(page2)
    assert [item.element_id for item in snapshot2.elements] != [
        item.element_id for item in snapshot_a.elements
    ]
