from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

import pytest

from phoenix_os.control_plane import (
    ControlPlaneServiceAccountAuthenticationContext,
    ControlPlaneServiceAccountAuthenticator,
    ControlPlaneServiceAccountTransportContextError,
    control_plane_service_account_authentication_context,
)
from phoenix_os.control_plane.network_contracts import (
    ControlPlaneClientIdentity,
    ControlPlaneClientIdentitySource,
    ControlPlaneTlsMode,
    ControlPlaneTlsPolicy,
)
from phoenix_os.control_plane.network_guard import (
    ControlPlaneNetworkRequestContext,
)
from phoenix_os.control_plane.service_account_contracts import (
    ControlPlaneApiTokenRestriction,
    ControlPlaneServiceAccountRepository,
)
from phoenix_os.control_plane.service_account_lifecycle import (
    ControlPlaneApiTokenGrant,
    ControlPlaneServiceAccountLifecycleService,
)
from phoenix_os.control_plane.service_account_memory import (
    InMemoryControlPlaneServiceAccountRepository,
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
_TOKEN = "phx_sa_" + ("A" * 48)
_CERTIFICATE = b"phoenix-client-certificate-der"
_CERTIFICATE_DIGEST = hashlib.sha256(_CERTIFICATE).hexdigest()


class _SslObject:
    def __init__(
        self,
        certificate: bytes | None,
    ) -> None:
        self._certificate = certificate

    def getpeercert(
        self,
        binary_form: bool = False,
    ) -> object:
        assert binary_form
        return self._certificate


class _Writer:
    def __init__(
        self,
        *,
        peer_address: str,
        ssl_object: object | None = None,
    ) -> None:
        self._values: dict[str, object] = {
            "peername": (
                peer_address,
                8443,
            ),
            "ssl_object": ssl_object,
        }

    def get_extra_info(
        self,
        name: str,
        default: object = None,
    ) -> object:
        return self._values.get(
            name,
            default,
        )


def _direct_context(
    address: str,
) -> ControlPlaneNetworkRequestContext:
    return ControlPlaneNetworkRequestContext(
        identity=ControlPlaneClientIdentity(
            address=address,
            peer_address=address,
        ),
        host="admin.example.com:8443",
        origin=None,
    )


def _forwarded_context(
    address: str,
    *,
    peer_address: str = "10.0.0.10",
) -> ControlPlaneNetworkRequestContext:
    return ControlPlaneNetworkRequestContext(
        identity=ControlPlaneClientIdentity(
            address=address,
            peer_address=peer_address,
            source=(ControlPlaneClientIdentitySource.FORWARDED),
            forwarded_chain=(
                address,
                peer_address,
            ),
            trusted_proxy=True,
        ),
        host="admin.example.com:8443",
        origin=None,
    )


def _mutual_policy(
    tmp_path: Path,
) -> ControlPlaneTlsPolicy:
    return ControlPlaneTlsPolicy(
        mode=ControlPlaneTlsMode.MUTUAL,
        certificate_file=str((tmp_path / "server.crt").resolve()),
        private_key_file=str((tmp_path / "server.key").resolve()),
        client_ca_file=str((tmp_path / "client-ca.crt").resolve()),
    )


async def _grant(
    restriction: ControlPlaneApiTokenRestriction,
) -> tuple[
    ControlPlaneServiceAccountRepository,
    ControlPlaneApiTokenGrant,
]:
    repository = InMemoryControlPlaneServiceAccountRepository()
    service = ControlPlaneServiceAccountLifecycleService(
        repository=repository,
        clock=lambda: _NOW,
        token_factory=lambda: _TOKEN,
        account_id_factory=lambda: _ACCOUNT_ID,
        token_id_factory=lambda: _TOKEN_ID,
    )
    account = await service.create_account(
        name="release.bot",
        display_name="Release Bot",
    )
    grant = await service.issue_token(
        account.id,
        label="Release Token",
        scopes=frozenset({"jobs.read"}),
        resources=frozenset({"job:*"}),
        restriction=restriction,
        expires_at=_NOW + timedelta(days=1),
    )

    return repository, grant


def test_context_cannot_be_created_from_arbitrary_values() -> None:
    with pytest.raises(
        TypeError,
        match="trusted transport factory",
    ):
        ControlPlaneServiceAccountAuthenticationContext(
            client_address="203.0.113.10",
            peer_address="203.0.113.10",
            identity_source=(ControlPlaneClientIdentitySource.DIRECT),
        )


def test_plain_transport_context_uses_real_peer() -> None:
    context = control_plane_service_account_authentication_context(
        _direct_context("203.0.113.10"),
        _Writer(peer_address="203.0.113.10"),
        tls_policy=ControlPlaneTlsPolicy(),
    )

    assert context.client_address == "203.0.113.10"
    assert context.peer_address == "203.0.113.10"
    assert context.identity_source is ControlPlaneClientIdentitySource.DIRECT
    assert not context.mutual_tls


def test_forwarded_context_uses_guard_resolved_client() -> None:
    context = control_plane_service_account_authentication_context(
        _forwarded_context("203.0.113.20"),
        _Writer(peer_address="10.0.0.10"),
        tls_policy=ControlPlaneTlsPolicy(),
    )

    assert context.client_address == "203.0.113.20"
    assert context.peer_address == "10.0.0.10"
    assert context.identity_source is ControlPlaneClientIdentitySource.FORWARDED


def test_context_rejects_network_and_socket_mismatch() -> None:
    with pytest.raises(
        ControlPlaneServiceAccountTransportContextError,
        match="does not match",
    ):
        control_plane_service_account_authentication_context(
            _direct_context("203.0.113.10"),
            _Writer(peer_address="203.0.113.11"),
            tls_policy=ControlPlaneTlsPolicy(),
        )


def test_mutual_tls_context_hashes_peer_der(
    tmp_path: Path,
) -> None:
    context = control_plane_service_account_authentication_context(
        _direct_context("203.0.113.10"),
        _Writer(
            peer_address="203.0.113.10",
            ssl_object=_SslObject(_CERTIFICATE),
        ),
        tls_policy=_mutual_policy(tmp_path),
    )

    assert context.mutual_tls
    assert context.mutual_tls_certificate_sha256 == _CERTIFICATE_DIGEST
    assert _CERTIFICATE_DIGEST not in repr(context)


def test_mutual_tls_context_fails_without_certificate(
    tmp_path: Path,
) -> None:
    with pytest.raises(
        ControlPlaneServiceAccountTransportContextError,
        match="certificate",
    ):
        control_plane_service_account_authentication_context(
            _direct_context("203.0.113.10"),
            _Writer(
                peer_address="203.0.113.10",
                ssl_object=_SslObject(None),
            ),
            tls_policy=_mutual_policy(tmp_path),
        )


@pytest.mark.asyncio
async def test_client_network_restriction_uses_resolved_address() -> None:
    repository, grant = await _grant(
        ControlPlaneApiTokenRestriction(
            allowed_client_networks=("203.0.113.0/24",),
        )
    )
    authenticator = ControlPlaneServiceAccountAuthenticator(
        repository,
        clock=lambda: _NOW,
    )
    accepted_context = control_plane_service_account_authentication_context(
        _forwarded_context("203.0.113.20"),
        _Writer(peer_address="10.0.0.10"),
        tls_policy=ControlPlaneTlsPolicy(),
    )
    rejected_context = control_plane_service_account_authentication_context(
        _forwarded_context("198.51.100.20"),
        _Writer(peer_address="10.0.0.10"),
        tls_policy=ControlPlaneTlsPolicy(),
    )
    authorization = f"Bearer {grant.token.value}"

    accepted = await authenticator.authenticate(
        authorization,
        context=accepted_context,
    )

    assert accepted is not None
    assert accepted.restriction_applied

    assert (
        await authenticator.authenticate(
            authorization,
            context=rejected_context,
        )
        is None
    )
    assert await authenticator.authenticate(authorization) is None


@pytest.mark.asyncio
async def test_mtls_binding_requires_exact_peer_certificate(
    tmp_path: Path,
) -> None:
    repository, grant = await _grant(
        ControlPlaneApiTokenRestriction(
            mutual_tls_certificate_sha256=(_CERTIFICATE_DIGEST),
        )
    )
    authenticator = ControlPlaneServiceAccountAuthenticator(
        repository,
        clock=lambda: _NOW,
    )
    policy = _mutual_policy(tmp_path)
    accepted_context = control_plane_service_account_authentication_context(
        _direct_context("203.0.113.10"),
        _Writer(
            peer_address="203.0.113.10",
            ssl_object=_SslObject(_CERTIFICATE),
        ),
        tls_policy=policy,
    )
    rejected_context = control_plane_service_account_authentication_context(
        _direct_context("203.0.113.10"),
        _Writer(
            peer_address="203.0.113.10",
            ssl_object=_SslObject(b"different-certificate"),
        ),
        tls_policy=policy,
    )
    authorization = f"Bearer {grant.token.value}"

    accepted = await authenticator.authenticate(
        authorization,
        context=accepted_context,
    )

    assert accepted is not None
    assert accepted.restriction_applied

    assert (
        await authenticator.authenticate(
            authorization,
            context=rejected_context,
        )
        is None
    )


def test_transport_exports_are_public() -> None:
    import phoenix_os.control_plane as control_plane

    assert (
        control_plane.ControlPlaneServiceAccountAuthenticationContext
        is ControlPlaneServiceAccountAuthenticationContext
    )
    assert (
        control_plane.ControlPlaneServiceAccountTransportContextError
        is ControlPlaneServiceAccountTransportContextError
    )
    assert (
        control_plane.control_plane_service_account_authentication_context
        is control_plane_service_account_authentication_context
    )
