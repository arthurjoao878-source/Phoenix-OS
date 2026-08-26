from __future__ import annotations

from dataclasses import fields

import pytest

from phoenix_os.authority import AuthorityIntent
from phoenix_os.browser_automation import (
    BROWSER_HEALTH_READ_PERMISSION,
    BROWSER_HEALTH_RESOURCE,
    BrowserAdapterId,
    BrowserAutomationAdministration,
    BrowserAutomationAdministrationAccessDeniedError,
    BrowserAutomationService,
    BrowserNavigationRequest,
    BrowserPageDescriptor,
    BrowserPreparedEffect,
    BrowserProfile,
    BrowserProfileId,
    BrowserSessionDescriptor,
    DeterministicBrowserAdapter,
)
from phoenix_os.policy import PrincipalType, SecurityContext


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
        raise AssertionError("health-only test must not authorize browser work")

    async def authorize_session_close(
        self,
        profile: BrowserProfile,
        session: BrowserSessionDescriptor,
        context: SecurityContext,
    ) -> AuthorityIntent:
        del profile, session, context
        raise AssertionError("health-only test must not authorize browser work")

    async def authorize_page_navigate(
        self,
        profile: BrowserProfile,
        session: BrowserSessionDescriptor,
        page: BrowserPageDescriptor,
        request: BrowserNavigationRequest,
        context: SecurityContext,
    ) -> AuthorityIntent:
        del profile, session, page, request, context
        raise AssertionError("health-only test must not authorize browser work")

    async def authorize_page_read(
        self,
        profile: BrowserProfile,
        session: BrowserSessionDescriptor,
        page: BrowserPageDescriptor,
        context: SecurityContext,
    ) -> AuthorityIntent:
        del profile, session, page, context
        raise AssertionError("health-only test must not authorize browser work")

    async def authorize_element_fill(
        self,
        profile: BrowserProfile,
        session: BrowserSessionDescriptor,
        page: BrowserPageDescriptor,
        prepared: BrowserPreparedEffect,
        context: SecurityContext,
    ) -> AuthorityIntent:
        del profile, session, page, prepared, context
        raise AssertionError("health-only test must not authorize browser work")

    async def authorize_element_click(
        self,
        profile: BrowserProfile,
        session: BrowserSessionDescriptor,
        page: BrowserPageDescriptor,
        prepared: BrowserPreparedEffect,
        context: SecurityContext,
    ) -> AuthorityIntent:
        del profile, session, page, prepared, context
        raise AssertionError("health-only test must not authorize browser work")


class _Freshness:
    async def validate(self, context: SecurityContext) -> None:
        del context
        raise AssertionError("health-only test must not validate browser authority")


def _service() -> BrowserAutomationService:
    return BrowserAutomationService(
        profiles=_Profiles(),
        adapter_id=BrowserAdapterId("deterministic-browser"),
        adapter=DeterministicBrowserAdapter(),
        authorizer=_Authorizer(),
        freshness=_Freshness(),
    )


def _user_context(*, permission: bool = True) -> SecurityContext:
    permissions = frozenset({BROWSER_HEALTH_READ_PERMISSION}) if permission else frozenset()
    return SecurityContext(
        principal="alice",
        principal_type=PrincipalType.USER,
        authenticated=True,
        permissions=permissions,
    )


@pytest.mark.asyncio
async def test_browser_administration_returns_only_bounded_service_health() -> None:
    service = _service()
    administration = BrowserAutomationAdministration(service)

    result = await administration.snapshot(_user_context())

    runtime = result.runtime
    assert runtime.available is True
    assert runtime.closed is False
    assert runtime.closing is False
    assert runtime.runtime_managed is False
    assert runtime.quarantined is False
    assert runtime.active_operations == 0
    assert runtime.active_sessions == 0
    assert {item.name for item in fields(runtime)} == {
        "closed",
        "closing",
        "available",
        "runtime_managed",
        "quarantined",
        "active_operations",
        "active_sessions",
        "schema_version",
    }

    serialized = repr(result).lower()
    for forbidden in (
        "profile_id",
        "session_id",
        "page_id",
        "element_id",
        "origin",
        "host=",
        "port=",
        "cookie",
        "body",
        "authorization",
        "authorityintent",
    ):
        assert forbidden not in serialized

    await service.close()


@pytest.mark.asyncio
async def test_browser_administration_requires_exact_health_permission() -> None:
    service = _service()
    administration = BrowserAutomationAdministration(service)

    with pytest.raises(BrowserAutomationAdministrationAccessDeniedError):
        await administration.snapshot(_user_context(permission=False))

    with pytest.raises(BrowserAutomationAdministrationAccessDeniedError):
        await administration.snapshot(
            SecurityContext(
                principal="anonymous",
                principal_type=PrincipalType.USER,
                authenticated=False,
                permissions=frozenset({BROWSER_HEALTH_READ_PERMISSION}),
            )
        )

    service_context = SecurityContext(
        principal="service:operator",
        principal_type=PrincipalType.SERVICE,
        authenticated=True,
        permissions=frozenset({BROWSER_HEALTH_READ_PERMISSION}),
        attributes={"resource": BROWSER_HEALTH_RESOURCE},
    )
    assert (await administration.snapshot(service_context)).runtime.available is True

    wrong_resource = SecurityContext(
        principal="service:operator",
        principal_type=PrincipalType.SERVICE,
        authenticated=True,
        permissions=frozenset({BROWSER_HEALTH_READ_PERMISSION}),
        attributes={"resource": "browser-automation:other"},
    )
    with pytest.raises(BrowserAutomationAdministrationAccessDeniedError):
        await administration.snapshot(wrong_resource)

    await service.close()
