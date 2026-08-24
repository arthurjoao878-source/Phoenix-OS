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
from phoenix_os.network_egress import (
    NetworkEgressOperation,
    NetworkEgressProfile,
    NetworkEgressProfileId,
    NetworkEgressService,
    NetworkHttpRequest,
    network_egress_runtime_component_spec,
)
from phoenix_os.policy import SecurityContext


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
        raise AssertionError("runtime lifecycle must not authorize a network request")


class _Freshness:
    async def validate(self, context: SecurityContext) -> None:
        del context
        raise AssertionError("runtime lifecycle must not validate request authority")


def _service() -> NetworkEgressService:
    return NetworkEgressService(
        profiles=_Profiles(),
        authorizer=_Authorizer(),
        freshness=_Freshness(),
    )


def _runtime(
    service: NetworkEgressService,
    *,
    exposed_service: NetworkEgressService | None = None,
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
        components=(network_egress_runtime_component_spec(service),),
        services={"network_egress": service if exposed_service is None else exposed_service},
    )


@pytest.mark.asyncio
async def test_runtime_owned_network_service_is_available_only_while_running() -> None:
    service = _service()
    runtime = _runtime(service)

    before = await service.snapshot()
    assert before.runtime_managed is True
    assert before.available is False

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


@pytest.mark.asyncio
async def test_runtime_component_rejects_service_identity_mismatch() -> None:
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


def test_network_service_cannot_be_bound_to_two_runtime_components() -> None:
    service = _service()
    network_egress_runtime_component_spec(service)
    with pytest.raises(RuntimeError, match="already Runtime-owned"):
        network_egress_runtime_component_spec(service)
