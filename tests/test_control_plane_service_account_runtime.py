from __future__ import annotations

from collections.abc import Mapping
from http import HTTPStatus
from typing import cast

import pytest

from phoenix_os.control_plane.csrf import (
    ControlPlaneBrowserOrigin,
)
from phoenix_os.control_plane.durable_session_access import (
    ControlPlaneDurableSessionAuthentication,
)
from phoenix_os.control_plane.service_account_http import (
    ControlPlaneServiceAccountCsrfVerifier,
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
from phoenix_os.control_plane.service_account_runtime import (
    ControlPlaneServiceAccountRuntimeOwner,
    ControlPlaneServiceAccountStepUpVerifier,
    create_control_plane_service_account_runtime,
)
from phoenix_os.control_plane.step_up import (
    ControlPlaneStepUpAction,
)
from phoenix_os.events import EventBus
from phoenix_os.policy import (
    PolicyEffect,
    PolicyEngine,
    PolicyRule,
)

_PATH = "/v1/control-plane/machine/jobs"


class _Boundary:
    async def verify_csrf(
        self,
        token_value: str | None,
        session: ControlPlaneDurableSessionAuthentication,
        *,
        supplied_origin: ControlPlaneBrowserOrigin,
        expected_origin: ControlPlaneBrowserOrigin,
    ) -> object:
        del (
            token_value,
            session,
            supplied_origin,
            expected_origin,
        )

        return object()


class _StepUp:
    async def verify(
        self,
        token_value: str | None,
        session: ControlPlaneDurableSessionAuthentication,
        action: ControlPlaneStepUpAction,
    ) -> object:
        del (
            token_value,
            session,
            action,
        )

        return object()


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
                "allow-service-accounts",
                PolicyEffect.ALLOW,
            ),
        )
    )


def test_bundle_uses_one_shared_repository() -> None:
    repository = InMemoryControlPlaneServiceAccountRepository()

    bundle = create_control_plane_service_account_runtime(
        repository=repository,
        events=EventBus(),
        boundary=cast(
            ControlPlaneServiceAccountCsrfVerifier,
            _Boundary(),
        ),
        step_up=cast(
            ControlPlaneServiceAccountStepUpVerifier,
            _StepUp(),
        ),
        audit_secret=b"a" * 32,
        replay_secret=b"r" * 32,
    )

    assert bundle.repository is repository

    assert bundle.administration.repository is repository

    assert bundle.administration.lifecycle is bundle.lifecycle

    assert bundle.authentication.throttle is bundle.throttle

    assert bundle.request_security.replay is bundle.replay

    assert bundle.policy is None
    assert bundle.machine_http is None


def test_machine_routes_require_policy_engine() -> None:
    with pytest.raises(
        ValueError,
        match="machine routes require a PolicyEngine",
    ):
        create_control_plane_service_account_runtime(
            repository=(InMemoryControlPlaneServiceAccountRepository()),
            events=EventBus(),
            boundary=cast(
                ControlPlaneServiceAccountCsrfVerifier,
                _Boundary(),
            ),
            step_up=cast(
                ControlPlaneServiceAccountStepUpVerifier,
                _StepUp(),
            ),
            machine_routes=(_route(),),
        )


def test_machine_routes_are_composed() -> None:
    bundle = create_control_plane_service_account_runtime(
        repository=(InMemoryControlPlaneServiceAccountRepository()),
        events=EventBus(),
        boundary=cast(
            ControlPlaneServiceAccountCsrfVerifier,
            _Boundary(),
        ),
        step_up=cast(
            ControlPlaneServiceAccountStepUpVerifier,
            _StepUp(),
        ),
        policy_engine=_policy(),
        machine_routes=(_route(),),
        audit_secret=b"a" * 32,
        replay_secret=b"r" * 32,
    )

    assert bundle.policy is not None
    assert bundle.machine_http is not None
    assert bundle.machine_http.handles(_PATH)

    assert not bundle.machine_http.handles(f"{_PATH}/extra")


@pytest.mark.asyncio
async def test_runtime_owner_closes_owned_services() -> None:
    repository = InMemoryControlPlaneServiceAccountRepository()

    bundle = create_control_plane_service_account_runtime(
        repository=repository,
        events=EventBus(),
        boundary=cast(
            ControlPlaneServiceAccountCsrfVerifier,
            _Boundary(),
        ),
        step_up=cast(
            ControlPlaneServiceAccountStepUpVerifier,
            _StepUp(),
        ),
        audit_secret=b"a" * 32,
        replay_secret=b"r" * 32,
    )

    owner = ControlPlaneServiceAccountRuntimeOwner(bundle)

    await owner.start()

    assert not bundle.lifecycle.closed
    assert not bundle.throttle.closed
    assert not bundle.replay.closed
    assert not repository.closed

    await owner.stop()

    assert bundle.lifecycle.closed
    assert bundle.throttle.closed
    assert bundle.replay.closed
    assert repository.closed
