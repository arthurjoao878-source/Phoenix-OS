from __future__ import annotations

from dataclasses import fields

import pytest

from phoenix_os.authority import AuthorityIntent
from phoenix_os.network_egress import (
    NETWORK_EGRESS_HEALTH_READ_PERMISSION,
    NETWORK_EGRESS_HEALTH_RESOURCE,
    NetworkEgressAdministration,
    NetworkEgressAdministrationAccessDeniedError,
    NetworkEgressOperation,
    NetworkEgressProfile,
    NetworkEgressProfileId,
    NetworkEgressService,
    NetworkHttpRequest,
)
from phoenix_os.policy import PrincipalType, SecurityContext


class _Profiles:
    def require_profile(self, profile_id: NetworkEgressProfileId) -> NetworkEgressProfile:
        raise KeyError(profile_id)


class _Authorizer:
    async def authorize(
        self,
        request: NetworkHttpRequest,
        profile: NetworkEgressProfile,
        operation: NetworkEgressOperation,
        context: SecurityContext,
    ) -> AuthorityIntent:
        del request, profile, operation, context
        raise AssertionError("health inspection must not authorize network effects")


class _Freshness:
    async def validate(self, context: SecurityContext) -> None:
        del context
        raise AssertionError("health inspection must not validate request authority")


def _service() -> NetworkEgressService:
    return NetworkEgressService(
        profiles=_Profiles(),
        authorizer=_Authorizer(),
        freshness=_Freshness(),
    )


def _user_context(*, permission: bool = True) -> SecurityContext:
    permissions = frozenset({NETWORK_EGRESS_HEALTH_READ_PERMISSION}) if permission else frozenset()
    return SecurityContext(
        principal="alice",
        principal_type=PrincipalType.USER,
        authenticated=True,
        permissions=permissions,
    )


@pytest.mark.asyncio
async def test_network_administration_returns_only_bounded_service_health() -> None:
    service = _service()
    administration = NetworkEgressAdministration(service)

    result = await administration.snapshot(_user_context())

    runtime = result.runtime
    assert runtime.available is True
    assert runtime.closed is False
    assert runtime.closing is False
    assert runtime.runtime_managed is False
    assert runtime.active_requests == 0
    assert {item.name for item in fields(runtime)} == {
        "limits",
        "closed",
        "closing",
        "available",
        "runtime_managed",
        "active_requests",
        "schema_version",
    }
    serialized = repr(result).lower()
    for forbidden in (
        "profile_id",
        "operation_id",
        "host=",
        "port=",
        "secret",
        "credential",
        "address",
    ):
        assert forbidden not in serialized

    await service.close()


@pytest.mark.asyncio
async def test_network_administration_requires_exact_health_permission() -> None:
    service = _service()
    administration = NetworkEgressAdministration(service)

    with pytest.raises(NetworkEgressAdministrationAccessDeniedError):
        await administration.snapshot(_user_context(permission=False))
    with pytest.raises(NetworkEgressAdministrationAccessDeniedError):
        await administration.snapshot(
            SecurityContext(
                principal="anonymous",
                principal_type=PrincipalType.USER,
                authenticated=False,
                permissions=frozenset({NETWORK_EGRESS_HEALTH_READ_PERMISSION}),
            )
        )

    service_context = SecurityContext(
        principal="service:operator",
        principal_type=PrincipalType.SERVICE,
        authenticated=True,
        permissions=frozenset({NETWORK_EGRESS_HEALTH_READ_PERMISSION}),
        attributes={"resource": NETWORK_EGRESS_HEALTH_RESOURCE},
    )
    assert (await administration.snapshot(service_context)).runtime.available is True

    wrong_resource = SecurityContext(
        principal="service:operator",
        principal_type=PrincipalType.SERVICE,
        authenticated=True,
        permissions=frozenset({NETWORK_EGRESS_HEALTH_READ_PERMISSION}),
        attributes={"resource": "network-egress:other"},
    )
    with pytest.raises(NetworkEgressAdministrationAccessDeniedError):
        await administration.snapshot(wrong_resource)

    await service.close()
