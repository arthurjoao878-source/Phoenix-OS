from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Protocol

from phoenix_os.control_plane.durable_session_access import (
    ControlPlaneDurableSessionAuthentication,
)
from phoenix_os.control_plane.service_account_admin import (
    ControlPlaneServiceAccountAdministration,
)
from phoenix_os.control_plane.service_account_audit import (
    ControlPlaneServiceAccountAudit,
    ControlPlaneServiceAccountAuditProtector,
)
from phoenix_os.control_plane.service_account_authentication import (
    ControlPlaneServiceAccountAuthenticator,
)
from phoenix_os.control_plane.service_account_contracts import (
    ControlPlaneServiceAccountRepository,
)
from phoenix_os.control_plane.service_account_http import (
    ControlPlaneServiceAccountCsrfVerifier,
    ControlPlaneServiceAccountHttpAdapter,
)
from phoenix_os.control_plane.service_account_lifecycle import (
    ControlPlaneServiceAccountLifecycleService,
)
from phoenix_os.control_plane.service_account_machine_http import (
    ControlPlaneServiceAccountMachineHttpAdapter,
    ControlPlaneServiceAccountMachineRoute,
)
from phoenix_os.control_plane.service_account_policy import (
    ControlPlaneServiceAccountPolicyAuthorizer,
)
from phoenix_os.control_plane.service_account_replay import (
    ControlPlaneServiceAccountReplayPolicy,
    ControlPlaneServiceAccountReplayProtector,
    ControlPlaneServiceAccountRequestSecurityService,
)
from phoenix_os.control_plane.service_account_throttling import (
    ControlPlaneServiceAccountAuthenticationService,
    ControlPlaneServiceAccountAuthenticationThrottle,
    ControlPlaneServiceAccountThrottlePolicy,
)
from phoenix_os.control_plane.step_up import (
    ControlPlaneStepUpAction,
)
from phoenix_os.events import EventBus
from phoenix_os.policy import PolicyEngine


class ControlPlaneServiceAccountStepUpVerifier(Protocol):
    """Verify an action-bound human step-up proof."""

    async def verify(
        self,
        token_value: str | None,
        session: ControlPlaneDurableSessionAuthentication,
        action: ControlPlaneStepUpAction,
    ) -> object: ...


@dataclass(frozen=True, slots=True)
class ControlPlaneServiceAccountRuntimeBundle:
    """All services that share one account repository."""

    repository: ControlPlaneServiceAccountRepository
    lifecycle: ControlPlaneServiceAccountLifecycleService
    audit: ControlPlaneServiceAccountAudit
    administration: ControlPlaneServiceAccountAdministration
    http: ControlPlaneServiceAccountHttpAdapter
    authenticator: ControlPlaneServiceAccountAuthenticator
    throttle: ControlPlaneServiceAccountAuthenticationThrottle
    authentication: ControlPlaneServiceAccountAuthenticationService
    replay: ControlPlaneServiceAccountReplayProtector
    request_security: ControlPlaneServiceAccountRequestSecurityService
    policy: ControlPlaneServiceAccountPolicyAuthorizer | None
    machine_http: ControlPlaneServiceAccountMachineHttpAdapter | None


class ControlPlaneServiceAccountRuntimeOwner:
    """Own runtime lifecycle for the composed security services."""

    def __init__(
        self,
        bundle: ControlPlaneServiceAccountRuntimeBundle,
    ) -> None:
        if not isinstance(
            bundle,
            ControlPlaneServiceAccountRuntimeBundle,
        ):
            raise TypeError("service-account runtime owner requires a runtime bundle")

        self._bundle = bundle

    @property
    def bundle(
        self,
    ) -> ControlPlaneServiceAccountRuntimeBundle:
        return self._bundle

    async def start(
        self,
        context: object = None,
    ) -> None:
        await self._bundle.lifecycle.start(context)

    async def stop(
        self,
        context: object = None,
    ) -> None:
        del context

        await self._bundle.request_security.close()
        await self._bundle.throttle.close()
        await self._bundle.lifecycle.close()
        await self._bundle.repository.close()


def create_control_plane_service_account_runtime(
    *,
    repository: ControlPlaneServiceAccountRepository,
    events: EventBus,
    boundary: ControlPlaneServiceAccountCsrfVerifier,
    step_up: ControlPlaneServiceAccountStepUpVerifier,
    policy_engine: PolicyEngine | None = None,
    machine_routes: tuple[
        ControlPlaneServiceAccountMachineRoute,
        ...,
    ] = (),
    throttle_policy: (ControlPlaneServiceAccountThrottlePolicy | None) = None,
    replay_policy: (ControlPlaneServiceAccountReplayPolicy | None) = None,
    audit_secret: (bytes | bytearray | memoryview | None) = None,
    replay_secret: (bytes | bytearray | memoryview | None) = None,
) -> ControlPlaneServiceAccountRuntimeBundle:
    """Compose one coherent service-account security stack."""

    if not isinstance(
        events,
        EventBus,
    ):
        raise TypeError("service-account runtime requires an EventBus")

    if machine_routes and policy_engine is None:
        raise ValueError("machine routes require a PolicyEngine")

    lifecycle = ControlPlaneServiceAccountLifecycleService(
        repository=repository,
    )

    audit = ControlPlaneServiceAccountAudit(
        events,
        ControlPlaneServiceAccountAuditProtector(_secret(audit_secret)),
    )

    administration = ControlPlaneServiceAccountAdministration(
        repository=repository,
        lifecycle=lifecycle,
        audit=audit,
    )

    http = ControlPlaneServiceAccountHttpAdapter(
        administration=administration,
        boundary=boundary,
        step_up=step_up,
    )

    authenticator = ControlPlaneServiceAccountAuthenticator(repository)

    throttle = ControlPlaneServiceAccountAuthenticationThrottle(throttle_policy)

    authentication = ControlPlaneServiceAccountAuthenticationService(
        authenticator,
        throttle,
    )

    replay = ControlPlaneServiceAccountReplayProtector(
        _secret(replay_secret),
        replay_policy,
    )

    request_security = ControlPlaneServiceAccountRequestSecurityService(
        authentication,
        replay,
    )

    policy = (
        None if policy_engine is None else ControlPlaneServiceAccountPolicyAuthorizer(policy_engine)
    )

    machine_http = None

    if machine_routes:
        assert policy is not None

        machine_http = ControlPlaneServiceAccountMachineHttpAdapter(
            authentication=request_security,
            policy=policy,
            audit=audit,
            routes=machine_routes,
        )

    return ControlPlaneServiceAccountRuntimeBundle(
        repository=repository,
        lifecycle=lifecycle,
        audit=audit,
        administration=administration,
        http=http,
        authenticator=authenticator,
        throttle=throttle,
        authentication=authentication,
        replay=replay,
        request_security=request_security,
        policy=policy,
        machine_http=machine_http,
    )


def _secret(
    value: (bytes | bytearray | memoryview | None),
) -> bytes:
    return secrets.token_bytes(32) if value is None else bytes(value)
