from __future__ import annotations

import socket

import pytest

from phoenix_os import (
    AllowAllAuthorizer,
    CapabilityRegistry,
    ConfigLoader,
    ConfigSchema,
    ControlPlaneExposureMode,
    ControlPlaneNetworkPolicy,
    ControlPlaneOperatorToken,
    ControlPlaneSecureHttpServer,
    ControlPlaneTlsMode,
    ControlPlaneTlsPolicy,
    EventBus,
    Kernel,
    MappingConfigSource,
    PhoenixRuntime,
    Router,
    RuntimeAssembler,
)
from phoenix_os.control_plane import AdminTokenAuthenticator, ControlPlaneHttpState


def _free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


async def _runtime(
    policy: ControlPlaneNetworkPolicy,
    *,
    legacy: bool = False,
) -> PhoenixRuntime:
    events = EventBus()
    configuration = await ConfigLoader(
        ConfigSchema(()),
        (MappingConfigSource({}),),
    ).load()
    arguments: dict[str, object] = {
        "kernel": Kernel(
            router=Router(),
            authorizer=AllowAllAuthorizer(),
            events=events,
        ),
        "events": events,
        "capabilities": CapabilityRegistry(events=events),
        "configuration": configuration,
        "control_plane_network_policy": policy,
    }
    if legacy:
        arguments["control_plane_authenticator"] = AdminTokenAuthenticator(
            "legacy-runtime-token-0123456789abcdef"
        )
    else:
        arguments["control_plane_operator_token"] = ControlPlaneOperatorToken(
            "runtime-network-token-0123456789abcdef"
        )
    return await RuntimeAssembler(**arguments).assemble()  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_runtime_owns_explicit_loopback_network_policy_lifecycle() -> None:
    port = _free_loopback_port()
    policy = ControlPlaneNetworkPolicy(
        bind_host="127.0.0.1",
        port=port,
        public_origin=f"http://127.0.0.1:{port}",
    )
    runtime = await _runtime(policy)
    secure_http = runtime.service("control_plane.secure-http")

    assert isinstance(secure_http, ControlPlaneSecureHttpServer)
    assert runtime.service("control_plane.network") is policy
    assert runtime.service("control_plane.network-guard") is secure_http.network_guard

    await runtime.start()
    running = await secure_http.secure_snapshot()
    assert running.transport.state is ControlPlaneHttpState.RUNNING
    assert running.transport.host == "127.0.0.1"
    assert running.transport.port == port
    assert running.network.exposure is ControlPlaneExposureMode.LOOPBACK
    assert running.tls is None

    await runtime.stop()
    stopped = await secure_http.secure_snapshot()
    assert stopped.transport.state is ControlPlaneHttpState.STOPPED
    assert stopped.guard.closed


@pytest.mark.asyncio
async def test_runtime_builds_remote_tls_security_services_before_start() -> None:
    policy = ControlPlaneNetworkPolicy(
        exposure=ControlPlaneExposureMode.REMOTE,
        bind_host="0.0.0.0",
        port=8443,
        public_origin="https://admin.example.test:8443",
        tls=ControlPlaneTlsPolicy(
            mode=ControlPlaneTlsMode.SERVER,
            certificate_file="/etc/phoenix/tls/server.crt",
            private_key_file="/etc/phoenix/tls/server.key",
        ),
        allowed_client_networks=("203.0.113.0/24",),
        secure_cookies=True,
    )
    runtime = await _runtime(policy)
    secure_http = runtime.service("control_plane.secure-http")

    assert isinstance(secure_http, ControlPlaneSecureHttpServer)
    assert secure_http.remote_login is runtime.service("control_plane.remote-login")
    assert secure_http.remote_audit is runtime.service("control_plane.remote-audit")
    snapshot = await secure_http.secure_snapshot()
    assert snapshot.network.exposure is ControlPlaneExposureMode.REMOTE
    assert snapshot.network.tls.mode is ControlPlaneTlsMode.SERVER
    assert snapshot.remote_login is not None
    assert snapshot.remote_audit is not None

    await secure_http.stop()


@pytest.mark.asyncio
async def test_runtime_rejects_remote_policy_with_legacy_authenticator() -> None:
    policy = ControlPlaneNetworkPolicy(
        exposure=ControlPlaneExposureMode.REMOTE,
        bind_host="0.0.0.0",
        port=8443,
        public_origin="https://admin.example.test:8443",
        tls=ControlPlaneTlsPolicy(
            mode=ControlPlaneTlsMode.SERVER,
            certificate_file="/etc/phoenix/tls/server.crt",
            private_key_file="/etc/phoenix/tls/server.key",
        ),
        allowed_client_networks=("203.0.113.0/24",),
        secure_cookies=True,
    )

    with pytest.raises(ValueError, match="durable operator"):
        await _runtime(policy, legacy=True)


@pytest.mark.asyncio
async def test_runtime_rejects_ephemeral_explicit_network_policy() -> None:
    events = EventBus()
    configuration = await ConfigLoader(
        ConfigSchema(()),
        (MappingConfigSource({}),),
    ).load()

    with pytest.raises(ValueError, match="fixed nonzero port"):
        RuntimeAssembler(
            kernel=Kernel(
                router=Router(),
                authorizer=AllowAllAuthorizer(),
                events=events,
            ),
            events=events,
            capabilities=CapabilityRegistry(events=events),
            configuration=configuration,
            control_plane_operator_token=ControlPlaneOperatorToken(
                "runtime-network-token-0123456789abcdef"
            ),
            control_plane_network_policy=ControlPlaneNetworkPolicy(),
        )
