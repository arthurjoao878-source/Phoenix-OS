from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from phoenix_os.control_plane import (
    ControlPlaneClientIdentity,
    ControlPlaneNetworkRequestContext,
    ControlPlaneServiceAccountAuthenticationService,
    ControlPlaneServiceAccountAuthenticationThrottle,
    ControlPlaneServiceAccountThrottleBlockedError,
    ControlPlaneServiceAccountThrottleBlockReason,
    ControlPlaneServiceAccountThrottleClosedError,
    ControlPlaneServiceAccountThrottlePolicy,
    ControlPlaneTlsPolicy,
    control_plane_service_account_authentication_context,
)
from phoenix_os.control_plane.service_account_authentication import (
    ControlPlaneServiceAccountAuthentication,
    ControlPlaneServiceAccountAuthenticationContext,
)

_NOW = datetime(
    2026,
    7,
    20,
    12,
    tzinfo=UTC,
)
_ACCOUNT_ID = UUID("10000000-0000-0000-0000-000000000001")
_OTHER_ACCOUNT_ID = UUID("10000000-0000-0000-0000-000000000002")
_TOKEN_ID = UUID("20000000-0000-0000-0000-000000000001")


class _Clock:
    def __init__(self) -> None:
        self.value = 0.0

    def now(self) -> float:
        return self.value

    def advance(
        self,
        seconds: float,
    ) -> None:
        self.value += seconds


class _Writer:
    def __init__(
        self,
        address: str,
    ) -> None:
        self._address = address

    def get_extra_info(
        self,
        name: str,
        default: object = None,
    ) -> object:
        if name == "peername":
            return (
                self._address,
                443,
            )

        return default


class _Resolver:
    def __init__(
        self,
        evidence: (ControlPlaneServiceAccountAuthentication | None),
    ) -> None:
        self.evidence = evidence
        self.calls = 0

    async def authenticate(
        self,
        authorization: str | None,
        *,
        context: (ControlPlaneServiceAccountAuthenticationContext | None) = None,
    ) -> ControlPlaneServiceAccountAuthentication | None:
        del context
        self.calls += 1

        if authorization != "Bearer valid":
            return None

        return self.evidence


def _transport_context(
    address: str = "8.8.8.8",
) -> ControlPlaneServiceAccountAuthenticationContext:
    network = ControlPlaneNetworkRequestContext(
        identity=ControlPlaneClientIdentity(
            address=address,
            peer_address=address,
        ),
        host="api.example.test",
        origin=None,
    )

    return control_plane_service_account_authentication_context(
        network,
        _Writer(address),
        tls_policy=ControlPlaneTlsPolicy(),
    )


def _evidence(
    account_id: UUID = _ACCOUNT_ID,
) -> ControlPlaneServiceAccountAuthentication:
    return ControlPlaneServiceAccountAuthentication(
        service_account_id=account_id,
        token_id=_TOKEN_ID,
        account_name="release.bot",
        scopes=frozenset(
            {
                "jobs.read",
            }
        ),
        resources=frozenset(
            {
                "job:*",
            }
        ),
        token_version=1,
        account_revision=1,
        token_revision=1,
        authenticated_at=_NOW,
        expires_at=_NOW + timedelta(hours=1),
    )


@pytest.mark.parametrize(
    "changes",
    [
        {
            "client_attempts": 0,
        },
        {
            "account_attempts": 0,
        },
        {
            "window": 0,
        },
        {
            "window": float("inf"),
        },
        {
            "client_capacity": 0,
        },
        {
            "account_capacity": 0,
        },
    ],
)
def test_throttle_policy_rejects_invalid_bounds(
    changes: dict[str, object],
) -> None:
    with pytest.raises(ValueError):
        ControlPlaneServiceAccountThrottlePolicy(
            **changes,  # type: ignore[arg-type]
        )


@pytest.mark.asyncio
async def test_client_throttle_blocks_after_limit() -> None:
    clock = _Clock()
    throttle = ControlPlaneServiceAccountAuthenticationThrottle(
        ControlPlaneServiceAccountThrottlePolicy(
            client_attempts=2,
        ),
        clock=clock,
    )
    context = _transport_context()

    await throttle.consume_client(context)
    await throttle.consume_client(context)

    with pytest.raises(
        ControlPlaneServiceAccountThrottleBlockedError,
    ) as captured:
        await throttle.consume_client(context)

    assert captured.value.reason is ControlPlaneServiceAccountThrottleBlockReason.CLIENT

    snapshot = await throttle.snapshot()

    assert snapshot.client_attempts == 3
    assert snapshot.client_blocks == 1
    assert snapshot.account_attempts == 0
    assert snapshot.tracked_clients == 1
    assert snapshot.last_block is ControlPlaneServiceAccountThrottleBlockReason.CLIENT
    assert "8.8.8.8" not in repr(snapshot)


@pytest.mark.asyncio
async def test_account_throttle_is_independent() -> None:
    throttle = ControlPlaneServiceAccountAuthenticationThrottle(
        ControlPlaneServiceAccountThrottlePolicy(
            account_attempts=1,
        )
    )

    await throttle.consume_account(_ACCOUNT_ID)

    with pytest.raises(
        ControlPlaneServiceAccountThrottleBlockedError,
    ) as captured:
        await throttle.consume_account(_ACCOUNT_ID)

    assert captured.value.reason is ControlPlaneServiceAccountThrottleBlockReason.ACCOUNT

    snapshot = await throttle.snapshot()

    assert snapshot.account_attempts == 2
    assert snapshot.account_blocks == 1
    assert snapshot.client_attempts == 0
    assert snapshot.tracked_accounts == 1


@pytest.mark.asyncio
async def test_different_clients_have_independent_windows() -> None:
    throttle = ControlPlaneServiceAccountAuthenticationThrottle(
        ControlPlaneServiceAccountThrottlePolicy(
            client_attempts=1,
        )
    )

    await throttle.consume_client(_transport_context("8.8.8.8"))
    await throttle.consume_client(_transport_context("1.1.1.1"))

    snapshot = await throttle.snapshot()

    assert snapshot.client_attempts == 2
    assert snapshot.client_blocks == 0
    assert snapshot.tracked_clients == 2


@pytest.mark.asyncio
async def test_different_accounts_have_independent_windows() -> None:
    throttle = ControlPlaneServiceAccountAuthenticationThrottle(
        ControlPlaneServiceAccountThrottlePolicy(
            account_attempts=1,
        )
    )

    await throttle.consume_account(_ACCOUNT_ID)
    await throttle.consume_account(_OTHER_ACCOUNT_ID)

    snapshot = await throttle.snapshot()

    assert snapshot.account_attempts == 2
    assert snapshot.account_blocks == 0
    assert snapshot.tracked_accounts == 2


@pytest.mark.asyncio
async def test_capacity_fails_closed_and_recovers() -> None:
    clock = _Clock()
    throttle = ControlPlaneServiceAccountAuthenticationThrottle(
        ControlPlaneServiceAccountThrottlePolicy(
            window=10,
            client_capacity=1,
        ),
        clock=clock,
    )

    await throttle.consume_client(_transport_context("8.8.8.8"))

    with pytest.raises(
        ControlPlaneServiceAccountThrottleBlockedError,
    ) as captured:
        await throttle.consume_client(_transport_context("1.1.1.1"))

    assert captured.value.reason is ControlPlaneServiceAccountThrottleBlockReason.CAPACITY

    clock.advance(11)

    await throttle.consume_client(_transport_context("1.1.1.1"))

    snapshot = await throttle.snapshot()

    assert snapshot.capacity_blocks == 1
    assert snapshot.tracked_clients == 1


@pytest.mark.asyncio
async def test_closed_throttle_fails_closed() -> None:
    throttle = ControlPlaneServiceAccountAuthenticationThrottle()

    await throttle.consume_client(_transport_context())
    await throttle.close()

    with pytest.raises(
        ControlPlaneServiceAccountThrottleClosedError,
    ):
        await throttle.consume_client(_transport_context())

    snapshot = await throttle.snapshot()

    assert snapshot.closed
    assert snapshot.tracked_clients == 0
    assert snapshot.tracked_accounts == 0


@pytest.mark.asyncio
async def test_invalid_bearer_consumes_only_client_limit() -> None:
    resolver = _Resolver(_evidence())
    throttle = ControlPlaneServiceAccountAuthenticationThrottle()
    service = ControlPlaneServiceAccountAuthenticationService(
        resolver,
        throttle,
    )

    result = await service.authenticate(
        "Bearer invalid",
        context=_transport_context(),
    )

    assert result is None
    assert resolver.calls == 1

    snapshot = await service.snapshot()

    assert snapshot.client_attempts == 1
    assert snapshot.account_attempts == 0


@pytest.mark.asyncio
async def test_valid_bearer_consumes_both_limits() -> None:
    evidence = _evidence()
    resolver = _Resolver(evidence)
    service = ControlPlaneServiceAccountAuthenticationService(
        resolver,
        ControlPlaneServiceAccountAuthenticationThrottle(),
    )

    result = await service.authenticate(
        "Bearer valid",
        context=_transport_context(),
    )

    assert result is evidence

    snapshot = await service.snapshot()

    assert snapshot.client_attempts == 1
    assert snapshot.account_attempts == 1
    assert snapshot.client_blocks == 0
    assert snapshot.account_blocks == 0


@pytest.mark.asyncio
async def test_client_block_prevents_authenticator_lookup() -> None:
    resolver = _Resolver(_evidence())
    service = ControlPlaneServiceAccountAuthenticationService(
        resolver,
        ControlPlaneServiceAccountAuthenticationThrottle(
            ControlPlaneServiceAccountThrottlePolicy(
                client_attempts=1,
            )
        ),
    )
    context = _transport_context()

    assert (
        await service.authenticate(
            "Bearer invalid",
            context=context,
        )
        is None
    )

    assert (
        await service.authenticate(
            "Bearer valid",
            context=context,
        )
        is None
    )

    assert resolver.calls == 1

    snapshot = await service.snapshot()

    assert snapshot.client_blocks == 1
    assert snapshot.account_attempts == 0


@pytest.mark.asyncio
async def test_account_block_uses_generic_authentication_failure() -> None:
    resolver = _Resolver(_evidence())
    service = ControlPlaneServiceAccountAuthenticationService(
        resolver,
        ControlPlaneServiceAccountAuthenticationThrottle(
            ControlPlaneServiceAccountThrottlePolicy(
                client_attempts=10,
                account_attempts=1,
            )
        ),
    )
    context = _transport_context()

    assert (
        await service.authenticate(
            "Bearer valid",
            context=context,
        )
        is not None
    )

    assert (
        await service.authenticate(
            "Bearer valid",
            context=context,
        )
        is None
    )

    assert resolver.calls == 2

    snapshot = await service.snapshot()

    assert snapshot.account_attempts == 2
    assert snapshot.account_blocks == 1


@pytest.mark.asyncio
async def test_authentication_service_requires_transport_context() -> None:
    service = ControlPlaneServiceAccountAuthenticationService(
        _Resolver(_evidence()),
        ControlPlaneServiceAccountAuthenticationThrottle(),
    )

    with pytest.raises(
        TypeError,
        match="trusted transport context",
    ):
        await service.authenticate(
            "Bearer valid",
            context=None,  # type: ignore[arg-type]
        )


@pytest.mark.asyncio
async def test_snapshot_contains_no_identifiers() -> None:
    throttle = ControlPlaneServiceAccountAuthenticationThrottle()

    await throttle.consume_client(_transport_context())
    await throttle.consume_account(_ACCOUNT_ID)

    rendered = repr(await throttle.snapshot())

    assert "8.8.8.8" not in rendered
    assert str(_ACCOUNT_ID) not in rendered
    assert "release.bot" not in rendered
    assert "Bearer" not in rendered


@pytest.mark.asyncio
async def test_service_close_closes_throttle() -> None:
    service = ControlPlaneServiceAccountAuthenticationService(
        _Resolver(_evidence()),
        ControlPlaneServiceAccountAuthenticationThrottle(),
    )

    await service.close()

    assert service.throttle.closed

    assert (
        await service.authenticate(
            "Bearer valid",
            context=_transport_context(),
        )
        is None
    )


def test_throttling_exports_are_public() -> None:
    import phoenix_os.control_plane as control_plane

    assert (
        control_plane.ControlPlaneServiceAccountAuthenticationThrottle
        is ControlPlaneServiceAccountAuthenticationThrottle
    )
    assert (
        control_plane.ControlPlaneServiceAccountAuthenticationService
        is ControlPlaneServiceAccountAuthenticationService
    )
    assert (
        control_plane.ControlPlaneServiceAccountThrottlePolicy
        is ControlPlaneServiceAccountThrottlePolicy
    )
