from __future__ import annotations

from collections.abc import Mapping
from http import HTTPStatus
from typing import cast

import pytest

from phoenix_os.capabilities import (
    CapabilityRegistry,
)
from phoenix_os.control_plane.auth import (
    AdminTokenAuthenticator,
)
from phoenix_os.control_plane.network_contracts import (
    ControlPlaneNetworkPolicy,
)
from phoenix_os.control_plane.operator_memory import (
    InMemoryControlPlaneOperatorRegistry,
)
from phoenix_os.control_plane.runtime import (
    ControlPlaneRuntimeStack,
)
from phoenix_os.control_plane.service_account_machine_http import (
    ControlPlaneServiceAccountMachineRequest,
    ControlPlaneServiceAccountMachineRoute,
)
from phoenix_os.control_plane.service_account_memory import (
    InMemoryControlPlaneServiceAccountRepository,
)
from phoenix_os.control_plane.service_account_policy import (
    ControlPlaneServiceAccountApiContext,
)
from phoenix_os.events import EventBus
from phoenix_os.policy import (
    PolicyEffect,
    PolicyEngine,
    PolicyRule,
)

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


def _policy() -> PolicyEngine:
    return PolicyEngine(
        (
            PolicyRule(
                "allow-service-account-runtime",
                PolicyEffect.ALLOW,
            ),
        )
    )


def test_service_accounts_require_operator_mode() -> None:
    with pytest.raises(
        ValueError,
        match=("service accounts require durable operator mode"),
    ):
        ControlPlaneRuntimeStack.create(
            event_bus=EventBus(),
            capabilities=CapabilityRegistry(),
            authenticator=cast(
                AdminTokenAuthenticator,
                object(),
            ),
            service_account_repository=(InMemoryControlPlaneServiceAccountRepository()),
        )


def test_runtime_stack_wires_human_administration() -> None:
    repository = InMemoryControlPlaneServiceAccountRepository()

    stack = ControlPlaneRuntimeStack.create(
        event_bus=EventBus(),
        capabilities=CapabilityRegistry(),
        operator_registry=(InMemoryControlPlaneOperatorRegistry()),
        service_account_repository=repository,
        service_account_audit_secret=b"a" * 32,
        service_account_replay_secret=b"r" * 32,
    )

    assert stack.service_accounts is not None
    assert stack.service_accounts_owner is not None

    assert stack.service_accounts.repository is repository

    assert stack.http._service_account_http is stack.service_accounts.http

    assert stack.secure_http is None
    assert stack.service_accounts.machine_http is None


def test_machine_routes_require_secure_transport() -> None:
    with pytest.raises(
        ValueError,
        match=("machine routes require a secure network policy"),
    ):
        ControlPlaneRuntimeStack.create(
            event_bus=EventBus(),
            capabilities=CapabilityRegistry(),
            operator_registry=(InMemoryControlPlaneOperatorRegistry()),
            service_account_repository=(InMemoryControlPlaneServiceAccountRepository()),
            service_account_machine_routes=(_route(),),
            policy_engine=_policy(),
        )


def test_runtime_stack_wires_secure_machine_http() -> None:
    stack = ControlPlaneRuntimeStack.create(
        event_bus=EventBus(),
        capabilities=CapabilityRegistry(),
        operator_registry=(InMemoryControlPlaneOperatorRegistry()),
        service_account_repository=(InMemoryControlPlaneServiceAccountRepository()),
        service_account_machine_routes=(_route(),),
        service_account_audit_secret=b"a" * 32,
        service_account_replay_secret=b"r" * 32,
        policy_engine=_policy(),
        network_policy=ControlPlaneNetworkPolicy(
            port=8080,
            public_origin=("http://127.0.0.1:8080"),
        ),
    )

    assert stack.service_accounts is not None
    assert stack.service_accounts.machine_http is not None
    assert stack.secure_http is not None

    assert stack.secure_http._service_account_machine_http is stack.service_accounts.machine_http

    assert stack.secure_http._service_account_http is stack.service_accounts.http

    assert stack.service_accounts.machine_http.handles(_PATH)
