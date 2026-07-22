from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from phoenix_os.control_plane import (
    ControlPlaneClientIdentity,
    ControlPlaneNetworkRequestContext,
    ControlPlaneServiceAccountReplayPolicy,
    ControlPlaneServiceAccountReplayProtector,
    ControlPlaneServiceAccountReplayRejectedError,
    ControlPlaneServiceAccountReplayRejectionReason,
    ControlPlaneServiceAccountReplayRequest,
    ControlPlaneServiceAccountRequestNonce,
    ControlPlaneServiceAccountRequestSecurityService,
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
_TOKEN_ID = UUID("20000000-0000-0000-0000-000000000001")
_OTHER_TOKEN_ID = UUID("20000000-0000-0000-0000-000000000002")
_EMPTY_DIGEST = hashlib.sha256(b"").hexdigest()


class _Clock:
    def __init__(self) -> None:
        self.value = _NOW

    def __call__(self) -> datetime:
        return self.value

    def advance(
        self,
        seconds: int,
    ) -> None:
        self.value += timedelta(seconds=seconds)


class _Writer:
    def get_extra_info(
        self,
        name: str,
        default: object = None,
    ) -> object:
        if name == "peername":
            return (
                "8.8.8.8",
                443,
            )

        return default


class _AuthenticationBoundary:
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
        context: (ControlPlaneServiceAccountAuthenticationContext),
    ) -> ControlPlaneServiceAccountAuthentication | None:
        del context
        self.calls += 1

        if authorization != "Bearer valid":
            return None

        return self.evidence


def _authentication(
    token_id: UUID = _TOKEN_ID,
) -> ControlPlaneServiceAccountAuthentication:
    return ControlPlaneServiceAccountAuthentication(
        service_account_id=_ACCOUNT_ID,
        token_id=token_id,
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


def _request(
    nonce: str = "request-nonce-0001",
    *,
    issued_at: datetime = _NOW,
    target: str = "/v1/machine/jobs?limit=10",
) -> ControlPlaneServiceAccountReplayRequest:
    return ControlPlaneServiceAccountReplayRequest(
        nonce=ControlPlaneServiceAccountRequestNonce(nonce),
        issued_at=issued_at,
        method="POST",
        target=target,
        body_digest=_EMPTY_DIGEST,
    )


def _transport_context() -> ControlPlaneServiceAccountAuthenticationContext:
    network = ControlPlaneNetworkRequestContext(
        identity=ControlPlaneClientIdentity(
            address="8.8.8.8",
            peer_address="8.8.8.8",
        ),
        host="api.example.test",
        origin=None,
    )

    return control_plane_service_account_authentication_context(
        network,
        _Writer(),
        tls_policy=ControlPlaneTlsPolicy(),
    )


def test_nonce_and_request_redact_values() -> None:
    nonce = ControlPlaneServiceAccountRequestNonce("request-nonce-secret")
    request = _request(
        nonce.value,
        target="/v1/private?secret=value",
    )

    rendered = repr(
        (
            nonce,
            request,
        )
    )

    assert "request-nonce-secret" not in rendered
    assert "secret=value" not in rendered
    assert _EMPTY_DIGEST not in rendered
    assert str(nonce) == "<redacted>"


@pytest.mark.asyncio
async def test_exact_replay_is_rejected_generically() -> None:
    clock = _Clock()
    protector = ControlPlaneServiceAccountReplayProtector(
        b"R" * 32,
        clock=clock,
    )
    authentication = _authentication()
    request = _request()

    await protector.admit(
        authentication,
        request,
    )

    with pytest.raises(
        ControlPlaneServiceAccountReplayRejectedError,
    ) as captured:
        await protector.admit(
            authentication,
            request,
        )

    assert str(captured.value) == ("service-account request rejected")
    assert captured.value.reason is ControlPlaneServiceAccountReplayRejectionReason.REPLAY

    snapshot = await protector.snapshot()

    assert snapshot.attempts == 2
    assert snapshot.accepted == 1
    assert snapshot.replay_rejections == 1
    assert snapshot.tracked_requests == 1


@pytest.mark.asyncio
async def test_nonce_reuse_with_changed_request_is_rejected() -> None:
    clock = _Clock()
    protector = ControlPlaneServiceAccountReplayProtector(
        b"R" * 32,
        clock=clock,
    )
    authentication = _authentication()

    await protector.admit(
        authentication,
        _request(),
    )

    with pytest.raises(
        ControlPlaneServiceAccountReplayRejectedError,
    ) as captured:
        await protector.admit(
            authentication,
            _request(
                target="/v1/machine/jobs?limit=11",
            ),
        )

    assert captured.value.reason is ControlPlaneServiceAccountReplayRejectionReason.NONCE_REUSE


@pytest.mark.asyncio
async def test_same_nonce_is_isolated_by_token() -> None:
    protector = ControlPlaneServiceAccountReplayProtector(
        b"R" * 32,
        clock=_Clock(),
    )
    request = _request()

    await protector.admit(
        _authentication(_TOKEN_ID),
        request,
    )
    await protector.admit(
        _authentication(_OTHER_TOKEN_ID),
        request,
    )

    snapshot = await protector.snapshot()

    assert snapshot.accepted == 2
    assert snapshot.tracked_requests == 2


@pytest.mark.asyncio
async def test_different_nonce_allows_same_request() -> None:
    protector = ControlPlaneServiceAccountReplayProtector(
        b"R" * 32,
        clock=_Clock(),
    )
    authentication = _authentication()

    await protector.admit(
        authentication,
        _request("request-nonce-0001"),
    )
    await protector.admit(
        authentication,
        _request("request-nonce-0002"),
    )

    assert (await protector.snapshot()).accepted == 2


@pytest.mark.asyncio
async def test_stale_and_future_requests_are_generic() -> None:
    clock = _Clock()
    protector = ControlPlaneServiceAccountReplayProtector(
        b"R" * 32,
        ControlPlaneServiceAccountReplayPolicy(
            window=timedelta(seconds=10),
            future_skew=timedelta(seconds=2),
        ),
        clock=clock,
    )

    with pytest.raises(
        ControlPlaneServiceAccountReplayRejectedError,
    ) as stale:
        await protector.admit(
            _authentication(),
            _request(
                "request-nonce-stale1",
                issued_at=_NOW - timedelta(seconds=11),
            ),
        )

    with pytest.raises(
        ControlPlaneServiceAccountReplayRejectedError,
    ) as future:
        await protector.admit(
            _authentication(),
            _request(
                "request-nonce-future",
                issued_at=_NOW + timedelta(seconds=3),
            ),
        )

    assert str(stale.value) == str(future.value)
    assert stale.value.reason is ControlPlaneServiceAccountReplayRejectionReason.STALE
    assert future.value.reason is ControlPlaneServiceAccountReplayRejectionReason.FUTURE


@pytest.mark.asyncio
async def test_capacity_recovers_after_window() -> None:
    clock = _Clock()
    protector = ControlPlaneServiceAccountReplayProtector(
        b"R" * 32,
        ControlPlaneServiceAccountReplayPolicy(
            window=timedelta(seconds=10),
            future_skew=timedelta(0),
            capacity=1,
        ),
        clock=clock,
    )
    authentication = _authentication()

    await protector.admit(
        authentication,
        _request("request-nonce-0001"),
    )

    with pytest.raises(
        ControlPlaneServiceAccountReplayRejectedError,
    ) as captured:
        await protector.admit(
            authentication,
            _request("request-nonce-0002"),
        )

    assert captured.value.reason is ControlPlaneServiceAccountReplayRejectionReason.CAPACITY

    clock.advance(11)

    await protector.admit(
        authentication,
        _request(
            "request-nonce-0003",
            issued_at=clock.value,
        ),
    )

    snapshot = await protector.snapshot()

    assert snapshot.capacity_rejections == 1
    assert snapshot.accepted == 2
    assert snapshot.tracked_requests == 1


@pytest.mark.asyncio
async def test_snapshot_contains_no_identifiers() -> None:
    protector = ControlPlaneServiceAccountReplayProtector(
        b"R" * 32,
        clock=_Clock(),
    )

    await protector.admit(
        _authentication(),
        _request(
            "request-nonce-private",
            target="/v1/private?secret=value",
        ),
    )

    rendered = repr(await protector.snapshot())

    assert "request-nonce-private" not in rendered
    assert "secret=value" not in rendered
    assert str(_TOKEN_ID) not in rendered
    assert "release.bot" not in rendered


@pytest.mark.asyncio
async def test_closed_protector_fails_closed() -> None:
    protector = ControlPlaneServiceAccountReplayProtector(
        b"R" * 32,
        clock=_Clock(),
    )

    await protector.admit(
        _authentication(),
        _request(),
    )
    await protector.close()

    with pytest.raises(
        ControlPlaneServiceAccountReplayRejectedError,
    ) as captured:
        await protector.admit(
            _authentication(),
            _request("request-nonce-0002"),
        )

    assert captured.value.reason is ControlPlaneServiceAccountReplayRejectionReason.CLOSED

    snapshot = await protector.snapshot()

    assert snapshot.closed
    assert snapshot.tracked_requests == 0


@pytest.mark.asyncio
async def test_request_security_uses_same_none_for_replay() -> None:
    evidence = _authentication()
    boundary = _AuthenticationBoundary(evidence)
    service = ControlPlaneServiceAccountRequestSecurityService(
        boundary,
        ControlPlaneServiceAccountReplayProtector(
            b"R" * 32,
            clock=_Clock(),
        ),
    )
    context = _transport_context()
    request = _request()

    assert (
        await service.authenticate(
            "Bearer invalid",
            context=context,
            request=request,
        )
        is None
    )

    assert (
        await service.authenticate(
            "Bearer valid",
            context=context,
            request=request,
        )
        is evidence
    )

    assert (
        await service.authenticate(
            "Bearer valid",
            context=context,
            request=request,
        )
        is None
    )

    assert boundary.calls == 3


def test_replay_exports_are_public() -> None:
    import phoenix_os.control_plane as control_plane

    assert (
        control_plane.ControlPlaneServiceAccountReplayProtector
        is ControlPlaneServiceAccountReplayProtector
    )
    assert (
        control_plane.ControlPlaneServiceAccountReplayRequest
        is ControlPlaneServiceAccountReplayRequest
    )
    assert (
        control_plane.ControlPlaneServiceAccountRequestSecurityService
        is ControlPlaneServiceAccountRequestSecurityService
    )
