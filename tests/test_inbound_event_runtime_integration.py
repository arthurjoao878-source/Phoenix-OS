from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

import pytest

from phoenix_os.capabilities import CapabilityRegistry
from phoenix_os.configuration import Configuration, RuntimeAssembler
from phoenix_os.control_plane import (
    CONTROL_PLANE_INBOUND_MACHINE_BASE_PATH,
    AdminTokenAuthenticator,
    ControlPlaneInboundManagementHttpAdapter,
    ControlPlaneNetworkPolicy,
    ControlPlaneOperatorToken,
)
from phoenix_os.control_plane.service_account_machine_http import (
    ControlPlaneServiceAccountMachineHttpAdapter,
)
from phoenix_os.events import EventBus
from phoenix_os.inbound_events import (
    InboundEventSchema,
    InboundRuntimeBundle,
    InboundRuntimeState,
    create_in_memory_inbound_repositories,
)
from phoenix_os.kernel import AllowAllAuthorizer, Kernel, Router
from phoenix_os.policy import PolicyEngine
from phoenix_os.secrets import SecretsManager

_RFC = (
    Path(__file__).resolve().parents[1]
    / "docs"
    / "rfcs"
    / "RFC-0025-secure-inbound-event-gateway-and-external-event-sources.md"
)


class _Normalizer:
    schema = InboundEventSchema(
        event_type="release.completed",
        event_schema_version=1,
        internal_event_type="external.release.completed",
        required_fields=frozenset({"release", "status"}),
    )

    def normalize(
        self,
        payload: Mapping[str, object],
    ) -> Mapping[str, object]:
        return dict(payload)


def _assembler(
    *,
    enabled: bool,
    durable_operator: bool = False,
    service_accounts: bool = False,
    machine_administration: bool = False,
    secure_network: bool = False,
) -> RuntimeAssembler:
    events = EventBus()
    arguments: dict[str, object] = {
        "kernel": Kernel(
            router=Router(),
            authorizer=AllowAllAuthorizer(),
            events=events,
        ),
        "events": events,
        "capabilities": CapabilityRegistry(events=events),
        "configuration": Configuration({}, {}),
        "secrets": SecretsManager(),
        "policy": PolicyEngine(),
        "inbound_events_enabled": enabled,
        "inbound_event_normalizers": ((_Normalizer(),) if enabled else ()),
        "inbound_publisher_poll_interval": 60.0,
        "inbound_recovery_poll_interval": 60.0,
        "control_plane_service_accounts_enabled": service_accounts,
        "inbound_service_account_administration_enabled": (machine_administration),
    }
    if durable_operator:
        arguments["control_plane_operator_token"] = ControlPlaneOperatorToken("O" * 32)
    else:
        arguments["control_plane_authenticator"] = AdminTokenAuthenticator("A" * 32)
    if secure_network:
        arguments["control_plane_network_policy"] = ControlPlaneNetworkPolicy(
            port=45125,
            public_origin="http://127.0.0.1:45125",
        )
    return RuntimeAssembler(**arguments)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_disabled_runtime_registers_no_inbound_services() -> None:
    runtime = await _assembler(enabled=False).assemble()
    snapshot = await runtime.snapshot()

    assert "inbound" not in runtime.services
    assert all(not name.startswith("inbound") for name in snapshot.components)

    await runtime.stop()


def test_inbound_options_require_explicit_enablement() -> None:
    events = EventBus()
    with pytest.raises(
        ValueError,
        match="require inbound_events_enabled",
    ):
        RuntimeAssembler(
            kernel=Kernel(
                router=Router(),
                authorizer=AllowAllAuthorizer(),
                events=events,
            ),
            events=events,
            capabilities=CapabilityRegistry(events=events),
            configuration=Configuration({}, {}),
            control_plane_authenticator=AdminTokenAuthenticator("A" * 32),
            inbound_event_normalizers=(_Normalizer(),),
        )


@pytest.mark.parametrize(
    ("secrets", "policy", "normalizers", "authenticator", "message"),
    (
        (
            None,
            PolicyEngine(),
            (_Normalizer(),),
            AdminTokenAuthenticator("A" * 32),
            "SecretsManager",
        ),
        (
            SecretsManager(),
            None,
            (_Normalizer(),),
            AdminTokenAuthenticator("A" * 32),
            "PolicyEngine",
        ),
        (
            SecretsManager(),
            PolicyEngine(),
            (),
            AdminTokenAuthenticator("A" * 32),
            "at least one normalizer",
        ),
        (
            SecretsManager(),
            PolicyEngine(),
            (_Normalizer(),),
            None,
            "control-plane listener",
        ),
    ),
)
def test_enabled_inbound_requires_reviewed_runtime_boundaries(
    secrets: SecretsManager | None,
    policy: PolicyEngine | None,
    normalizers: tuple[_Normalizer, ...],
    authenticator: AdminTokenAuthenticator | None,
    message: str,
) -> None:
    events = EventBus()
    with pytest.raises(ValueError, match=message):
        RuntimeAssembler(
            kernel=Kernel(
                router=Router(),
                authorizer=AllowAllAuthorizer(),
                events=events,
            ),
            events=events,
            capabilities=CapabilityRegistry(events=events),
            configuration=Configuration({}, {}),
            secrets=secrets,
            policy=policy,
            control_plane_authenticator=authenticator,
            inbound_events_enabled=True,
            inbound_event_normalizers=normalizers,
        )


def test_custom_inbound_repositories_are_atomic_as_a_trio() -> None:
    events = EventBus()
    repositories = create_in_memory_inbound_repositories()
    with pytest.raises(
        ValueError,
        match="all three repositories",
    ):
        RuntimeAssembler(
            kernel=Kernel(
                router=Router(),
                authorizer=AllowAllAuthorizer(),
                events=events,
            ),
            events=events,
            capabilities=CapabilityRegistry(events=events),
            configuration=Configuration({}, {}),
            secrets=SecretsManager(),
            policy=PolicyEngine(),
            control_plane_authenticator=AdminTokenAuthenticator("A" * 32),
            inbound_events_enabled=True,
            inbound_event_normalizers=(_Normalizer(),),
            inbound_source_repository=repositories.sources,
        )


@pytest.mark.asyncio
async def test_runtime_exposes_owned_inbound_services_and_order() -> None:
    runtime = await _assembler(enabled=True).assemble()
    bundle = runtime.service("inbound")
    assert isinstance(bundle, InboundRuntimeBundle)

    assert runtime.service("inbound.sources") is bundle.sources
    assert runtime.service("inbound.events") is bundle.events
    assert runtime.service("inbound.replay") is bundle.replay
    assert runtime.service("inbound.schemas") is bundle.schemas
    assert runtime.service("inbound.ingress") is bundle.ingress
    assert runtime.service("inbound.publisher") is bundle.publisher
    assert runtime.service("inbound.recovery") is bundle.recovery
    assert runtime.service("inbound.manager") is bundle.manager
    assert runtime.service("inbound.owner") is bundle.owner
    assert runtime.service("control_plane.inbound-http") is bundle.ingress
    assert "control_plane.inbound-management-http" not in (runtime.services)

    snapshot = await runtime.snapshot()
    owner_index = snapshot.components.index("inbound")
    publisher_index = snapshot.components.index("inbound.publisher")
    recovery_index = snapshot.components.index("inbound.recovery")
    http_index = snapshot.components.index("control_plane.http")
    assert owner_index < publisher_index < recovery_index < http_index
    assert "inbound.http" not in snapshot.components

    await runtime.start()
    owner = await bundle.owner.snapshot()
    assert owner.state is InboundRuntimeState.RUNNING

    await runtime.stop()

    stopped = await bundle.owner.snapshot()
    assert stopped.state is InboundRuntimeState.STOPPED
    assert bundle.ingress.closed
    assert bundle.publisher.closed
    assert bundle.recovery.closed
    assert bundle.manager.closed


@pytest.mark.asyncio
async def test_durable_operator_mode_wires_inbound_management() -> None:
    runtime = await _assembler(
        enabled=True,
        durable_operator=True,
    ).assemble()
    bundle = runtime.service("inbound")
    assert isinstance(bundle, InboundRuntimeBundle)

    assert runtime.service("control_plane.inbound") is bundle.manager
    adapter = runtime.service("control_plane.inbound-management-http")
    assert isinstance(
        adapter,
        ControlPlaneInboundManagementHttpAdapter,
    )
    assert adapter.manager is bundle.manager

    await runtime.stop()


def test_machine_administration_requires_explicit_service_accounts() -> None:
    with pytest.raises(
        ValueError,
        match="requires service accounts",
    ):
        _assembler(
            enabled=True,
            durable_operator=True,
            service_accounts=False,
            machine_administration=True,
            secure_network=True,
        )


def test_machine_administration_requires_secure_network_policy() -> None:
    with pytest.raises(
        ValueError,
        match="secure network policy",
    ):
        _assembler(
            enabled=True,
            durable_operator=True,
            service_accounts=True,
            machine_administration=True,
            secure_network=False,
        )


@pytest.mark.asyncio
async def test_service_account_security_binds_without_machine_admin() -> None:
    runtime = await _assembler(
        enabled=True,
        durable_operator=True,
        service_accounts=True,
    ).assemble()
    bundle = runtime.service("inbound")
    assert isinstance(bundle, InboundRuntimeBundle)

    snapshot = await bundle.owner.snapshot()
    assert snapshot.service_account_security_bound
    assert "control_plane.service-account-machine-http" not in runtime.services

    await runtime.stop()


@pytest.mark.asyncio
async def test_machine_routes_are_opt_in_and_share_secure_listener() -> None:
    runtime = await _assembler(
        enabled=True,
        durable_operator=True,
        service_accounts=True,
        machine_administration=True,
        secure_network=True,
    ).assemble()
    bundle = runtime.service("inbound")
    assert isinstance(bundle, InboundRuntimeBundle)

    machine_http = runtime.service("control_plane.service-account-machine-http")
    assert isinstance(
        machine_http,
        ControlPlaneServiceAccountMachineHttpAdapter,
    )
    assert machine_http.handles(f"{CONTROL_PLANE_INBOUND_MACHINE_BASE_PATH}/source")
    assert runtime.service("control_plane.inbound-http") is (bundle.ingress)
    assert "control_plane.secure-http" in runtime.services

    snapshot = await bundle.owner.snapshot()
    assert snapshot.service_account_security_bound

    await runtime.stop()


def test_rfc_marks_runtime_ownership_complete() -> None:
    rfc = _RFC.read_text(encoding="utf-8")
    assert "- [x] RuntimeAssembler integration and lifecycle ownership" in rfc
    assert "RuntimeAssembler now owns the optional inbound subsystem" in rfc
