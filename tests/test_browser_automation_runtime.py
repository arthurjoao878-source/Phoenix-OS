from __future__ import annotations

import pytest

from phoenix_os import (
    AllowAllAuthorizer,
    CapabilityRegistry,
    EventBus,
    Kernel,
    PhoenixRuntime,
    Router,
    RuntimeStartError,
    RuntimeState,
)
from phoenix_os.authority import AuthorityIntent
from phoenix_os.browser_automation import (
    BrowserAdapterId,
    BrowserAdapterLifecycle,
    BrowserAutomationService,
    BrowserNavigationRequest,
    BrowserPageDescriptor,
    BrowserPreparedEffect,
    BrowserProfile,
    BrowserProfileId,
    BrowserSessionDescriptor,
    DeterministicBrowserAdapter,
    browser_automation_runtime_component_spec,
)
from phoenix_os.policy import SecurityContext


class _Profiles:
    def require_profile(self, profile_id: BrowserProfileId) -> BrowserProfile:
        raise KeyError(profile_id)


class _Authorizer:
    async def authorize_session_open(
        self,
        profile: BrowserProfile,
        session: BrowserSessionDescriptor,
        context: SecurityContext,
    ) -> AuthorityIntent:
        del profile, session, context
        raise AssertionError("runtime lifecycle must not authorize browser work")

    async def authorize_session_close(
        self,
        profile: BrowserProfile,
        session: BrowserSessionDescriptor,
        context: SecurityContext,
    ) -> AuthorityIntent:
        del profile, session, context
        raise AssertionError("runtime lifecycle must not authorize browser work")

    async def authorize_page_navigate(
        self,
        profile: BrowserProfile,
        session: BrowserSessionDescriptor,
        page: BrowserPageDescriptor,
        request: BrowserNavigationRequest,
        context: SecurityContext,
    ) -> AuthorityIntent:
        del profile, session, page, request, context
        raise AssertionError("runtime lifecycle must not authorize browser work")

    async def authorize_page_read(
        self,
        profile: BrowserProfile,
        session: BrowserSessionDescriptor,
        page: BrowserPageDescriptor,
        context: SecurityContext,
    ) -> AuthorityIntent:
        del profile, session, page, context
        raise AssertionError("runtime lifecycle must not authorize browser work")

    async def authorize_element_fill(
        self,
        profile: BrowserProfile,
        session: BrowserSessionDescriptor,
        page: BrowserPageDescriptor,
        prepared: BrowserPreparedEffect,
        context: SecurityContext,
    ) -> AuthorityIntent:
        del profile, session, page, prepared, context
        raise AssertionError("runtime lifecycle must not authorize browser work")

    async def authorize_element_click(
        self,
        profile: BrowserProfile,
        session: BrowserSessionDescriptor,
        page: BrowserPageDescriptor,
        prepared: BrowserPreparedEffect,
        context: SecurityContext,
    ) -> AuthorityIntent:
        del profile, session, page, prepared, context
        raise AssertionError("runtime lifecycle must not authorize browser work")


class _Freshness:
    async def validate(self, context: SecurityContext) -> None:
        del context
        raise AssertionError("runtime lifecycle must not validate browser authority")


def _service() -> BrowserAutomationService:
    adapter = DeterministicBrowserAdapter()
    return BrowserAutomationService(
        profiles=_Profiles(),
        adapter_id=BrowserAdapterId("deterministic-browser"),
        adapter=adapter,
        authorizer=_Authorizer(),
        freshness=_Freshness(),
    )


def _runtime(
    service: BrowserAutomationService,
    *,
    exposed_service: BrowserAutomationService | None = None,
) -> PhoenixRuntime:
    events = EventBus()
    kernel = Kernel(
        router=Router(),
        authorizer=AllowAllAuthorizer(),
        events=events,
    )
    capabilities = CapabilityRegistry(events=events)
    return PhoenixRuntime(
        kernel=kernel,
        events=events,
        capabilities=capabilities,
        components=(browser_automation_runtime_component_spec(service),),
        services={"browser_automation": service if exposed_service is None else exposed_service},
    )


@pytest.mark.asyncio
async def test_runtime_owned_browser_service_is_available_only_while_running() -> None:
    service = _service()
    runtime = _runtime(service)

    before = await service.snapshot()
    assert before.runtime_managed is True
    assert before.available is False
    assert before.active_sessions == 0

    await runtime.start()
    running = await service.snapshot()
    assert runtime.state is RuntimeState.RUNNING
    assert running.available is True
    assert running.closed is False

    await runtime.stop()
    stopped = await service.snapshot()
    assert (await runtime.snapshot()).state is RuntimeState.STOPPED
    assert stopped.available is False
    assert stopped.closed is True
    assert stopped.active_operations == 0
    assert stopped.active_sessions == 0


@pytest.mark.asyncio
async def test_runtime_component_rejects_browser_service_identity_mismatch() -> None:
    owned = _service()
    exposed = _service()
    runtime = _runtime(owned, exposed_service=exposed)

    with pytest.raises(RuntimeStartError):
        await runtime.start()

    assert runtime.state is RuntimeState.FAILED
    assert (await owned.snapshot()).available is False
    assert (await exposed.snapshot()).available is True

    await runtime.stop()
    await owned.close()
    await exposed.close()


def test_browser_service_cannot_be_bound_to_two_runtime_components() -> None:
    service = _service()
    browser_automation_runtime_component_spec(service)
    with pytest.raises(RuntimeError, match="already Runtime-owned"):
        browser_automation_runtime_component_spec(service)


def test_deterministic_browser_adapter_exposes_bounded_lifecycle_close() -> None:
    assert isinstance(DeterministicBrowserAdapter(), BrowserAdapterLifecycle)
