from __future__ import annotations

from collections.abc import Mapping
from http import HTTPStatus

import pytest

from phoenix_os.capabilities import CapabilityRegistry
from phoenix_os.configuration import (
    ConfigLoader,
    ConfigSchema,
    MappingConfigSource,
    RuntimeAssembler,
)
from phoenix_os.control_plane.network_contracts import (
    ControlPlaneNetworkPolicy,
)
from phoenix_os.control_plane.operator_memory import (
    InMemoryControlPlaneOperatorRegistry,
)
from phoenix_os.control_plane.service_account_lifecycle import (
    ControlPlaneServiceAccountLifecycleService,
)
from phoenix_os.control_plane.service_account_machine_http import (
    ControlPlaneServiceAccountMachineHttpAdapter,
    ControlPlaneServiceAccountMachineRequest,
    ControlPlaneServiceAccountMachineRoute,
)
from phoenix_os.control_plane.service_account_memory import (
    InMemoryControlPlaneServiceAccountRepository,
)
from phoenix_os.control_plane.service_account_policy import (
    ControlPlaneServiceAccountApiContext,
)
from phoenix_os.control_plane.service_account_state import (
    StateControlPlaneServiceAccountRepository,
)
from phoenix_os.events import EventBus
from phoenix_os.kernel import AllowAllAuthorizer, Kernel, Router
from phoenix_os.policy import (
    PolicyEffect,
    PolicyEngine,
    PolicyRule,
)
from phoenix_os.runtime import (
    PhoenixRuntime,
    RuntimeServiceNotFoundError,
)
from phoenix_os.state import MemoryStateStore

_PATH = "/v1/control-plane/machine/jobs"


class _Handler:
    async def __call__(
        self,
        context: ControlPlaneServiceAccountApiContext,
        request: ControlPlaneServiceAccountMachineRequest,
    ) -> tuple[
        HTTPStatus,
        Mapping[str, object],
        dict[str, str],
    ]:
        del context, request

        return (
            HTTPStatus.OK,
            {
                "schema_version": 1,
            },
            {},
        )


def _route() -> ControlPlaneServiceAccountMachineRoute:
    return ControlPlaneServiceAccountMachineRoute(
        method="GET",
        path=_PATH,
        action="jobs.read",
        resource="jobs",
        handler=_Handler(),
    )


def _policy(
    events: EventBus,
) -> PolicyEngine:
    return PolicyEngine(
        (
            PolicyRule(
                "allow-service-account-runtime",
                PolicyEffect.ALLOW,
            ),
        ),
        events=events,
    )


async def _runtime(
    *,
    enabled: bool = False,
    state: MemoryStateStore | None = None,
    repository: InMemoryControlPlaneServiceAccountRepository | None = None,
    machine_routes: tuple[
        ControlPlaneServiceAccountMachineRoute,
        ...,
    ] = (),
    network_policy: ControlPlaneNetworkPolicy | None = None,
    policy: PolicyEngine | None = None,
) -> PhoenixRuntime:
    events = EventBus()

    configuration = await ConfigLoader(
        ConfigSchema(()),
        (MappingConfigSource({}),),
    ).load()

    return await RuntimeAssembler(
        kernel=Kernel(
            router=Router(),
            authorizer=AllowAllAuthorizer(),
            events=events,
        ),
        events=events,
        capabilities=CapabilityRegistry(
            events=events,
        ),
        configuration=configuration,
        state=state,
        policy=policy,
        control_plane_operator_registry=(InMemoryControlPlaneOperatorRegistry()),
        control_plane_service_accounts_enabled=enabled,
        control_plane_service_account_repository=repository,
        control_plane_service_account_machine_routes=machine_routes,
        control_plane_service_account_audit_secret=(
            b"a" * 32 if enabled or repository is not None or machine_routes else None
        ),
        control_plane_service_account_replay_secret=(
            b"r" * 32 if enabled or repository is not None or machine_routes else None
        ),
        control_plane_network_policy=network_policy,
        control_plane_command_recovery_poll_interval=3600,
        control_plane_command_retention_poll_interval=3600,
    ).assemble()


@pytest.mark.asyncio
async def test_default_keeps_service_accounts_disabled() -> None:
    runtime = await _runtime()

    with pytest.raises(
        RuntimeServiceNotFoundError,
    ):
        runtime.service("control_plane.service-accounts")


@pytest.mark.asyncio
async def test_enabled_without_state_uses_memory_repository() -> None:
    runtime = await _runtime(
        enabled=True,
    )

    repository = runtime.service("control_plane.service-account-repository")

    lifecycle = runtime.service("control_plane.service-account-lifecycle")

    assert isinstance(
        repository,
        InMemoryControlPlaneServiceAccountRepository,
    )

    assert isinstance(
        lifecycle,
        ControlPlaneServiceAccountLifecycleService,
    )

    await runtime.start()

    assert not lifecycle.closed
    assert not repository.closed

    await runtime.stop()

    assert lifecycle.closed
    assert repository.closed


@pytest.mark.asyncio
async def test_enabled_with_state_uses_durable_repository() -> None:
    runtime = await _runtime(
        enabled=True,
        state=MemoryStateStore(),
    )

    repository = runtime.service("control_plane.service-account-repository")

    assert isinstance(
        repository,
        StateControlPlaneServiceAccountRepository,
    )

    await runtime.start()
    await runtime.stop()

    assert repository.closed


@pytest.mark.asyncio
async def test_explicit_repository_is_preserved() -> None:
    repository = InMemoryControlPlaneServiceAccountRepository()

    runtime = await _runtime(
        repository=repository,
    )

    assert runtime.service("control_plane.service-account-repository") is repository

    assert runtime.service("control_plane.service-accounts") is not None

    await runtime.start()
    await runtime.stop()

    assert repository.closed


@pytest.mark.asyncio
async def test_machine_routes_are_forwarded_and_exposed() -> None:
    events = EventBus()
    policy = _policy(events)

    configuration = await ConfigLoader(
        ConfigSchema(()),
        (MappingConfigSource({}),),
    ).load()

    runtime = await RuntimeAssembler(
        kernel=Kernel(
            router=Router(),
            authorizer=AllowAllAuthorizer(),
            events=events,
        ),
        events=events,
        capabilities=CapabilityRegistry(
            events=events,
        ),
        configuration=configuration,
        policy=policy,
        control_plane_operator_registry=(InMemoryControlPlaneOperatorRegistry()),
        control_plane_service_account_machine_routes=(_route(),),
        control_plane_service_account_audit_secret=(b"a" * 32),
        control_plane_service_account_replay_secret=(b"r" * 32),
        control_plane_network_policy=(
            ControlPlaneNetworkPolicy(
                port=8080,
                public_origin=("http://127.0.0.1:8080"),
            )
        ),
        control_plane_command_recovery_poll_interval=3600,
        control_plane_command_retention_poll_interval=3600,
    ).assemble()

    machine_http = runtime.service("control_plane.service-account-machine-http")

    assert isinstance(
        machine_http,
        ControlPlaneServiceAccountMachineHttpAdapter,
    )

    assert machine_http.handles(_PATH)

    assert not machine_http.handles(f"{_PATH}/extra")


@pytest.mark.asyncio
async def test_machine_routes_require_policy_and_network() -> None:
    events = EventBus()

    configuration = await ConfigLoader(
        ConfigSchema(()),
        (MappingConfigSource({}),),
    ).load()

    kernel = Kernel(
        router=Router(),
        authorizer=AllowAllAuthorizer(),
        events=events,
    )

    capabilities = CapabilityRegistry(
        events=events,
    )

    with pytest.raises(
        ValueError,
        match="secure network policy",
    ):
        RuntimeAssembler(
            kernel=kernel,
            events=events,
            capabilities=capabilities,
            configuration=configuration,
            control_plane_operator_registry=(InMemoryControlPlaneOperatorRegistry()),
            control_plane_service_account_machine_routes=(_route(),),
        )

    with pytest.raises(
        ValueError,
        match="PolicyEngine",
    ):
        RuntimeAssembler(
            kernel=kernel,
            events=events,
            capabilities=capabilities,
            configuration=configuration,
            control_plane_operator_registry=(InMemoryControlPlaneOperatorRegistry()),
            control_plane_service_account_machine_routes=(_route(),),
            control_plane_network_policy=(
                ControlPlaneNetworkPolicy(
                    port=8080,
                    public_origin=("http://127.0.0.1:8080"),
                )
            ),
        )
