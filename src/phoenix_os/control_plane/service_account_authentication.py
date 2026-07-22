from __future__ import annotations

import hashlib
import hmac
import re
from collections.abc import Callable
from dataclasses import InitVar, dataclass, field, replace
from datetime import UTC, datetime
from ipaddress import ip_address, ip_network
from typing import Protocol
from uuid import UUID

from phoenix_os.control_plane.errors import (
    ControlPlaneApiTokenConflictError,
)
from phoenix_os.control_plane.network_contracts import (
    ControlPlaneClientIdentitySource,
    ControlPlaneTlsPolicy,
)
from phoenix_os.control_plane.network_guard import (
    ControlPlaneNetworkRequestContext,
)
from phoenix_os.control_plane.service_account_contracts import (
    ControlPlaneApiToken,
    ControlPlaneApiTokenMetadata,
    ControlPlaneApiTokenStatus,
    ControlPlaneServiceAccountRepository,
)

_compare_digest = hmac.compare_digest

ControlPlaneServiceAccountAuthenticationClock = Callable[
    [],
    datetime,
]

_DUMMY_TOKEN_DIGEST = hashlib.sha256(b"phoenix-service-account-authentication-dummy:v1").hexdigest()

_DUMMY_SERVICE_ACCOUNT_ID = UUID("00000000-0000-0000-0000-000000000000")


def _utc_now() -> datetime:
    return datetime.now(UTC)


_CONTEXT_AUTHORITY = object()
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")


class ControlPlaneServiceAccountTransportContextError(ValueError):
    """Trusted transport facts are absent or inconsistent."""


class _ControlPlaneServiceAccountTransportWriter(Protocol):
    def get_extra_info(
        self,
        name: str,
        default: object = None,
    ) -> object: ...


@dataclass(frozen=True, slots=True)
class ControlPlaneServiceAccountAuthenticationContext:
    """Trusted network and mTLS facts for one HTTP request."""

    client_address: str
    peer_address: str
    identity_source: ControlPlaneClientIdentitySource
    mutual_tls_certificate_sha256: str | None = field(
        default=None,
        repr=False,
    )
    schema_version: int = 1
    _authority: InitVar[object] = None

    def __post_init__(
        self,
        _authority: object,
    ) -> None:
        if _authority is not _CONTEXT_AUTHORITY:
            raise TypeError(
                "service-account authentication context "
                "must come from the trusted transport factory"
            )

        client_address = str(ip_address(self.client_address))
        peer_address = str(ip_address(self.peer_address))
        identity_source = ControlPlaneClientIdentitySource(self.identity_source)

        if (
            identity_source is ControlPlaneClientIdentitySource.DIRECT
            and client_address != peer_address
        ):
            raise ValueError("direct service-account client must match its transport peer")

        fingerprint = self.mutual_tls_certificate_sha256

        if fingerprint is not None:
            fingerprint = fingerprint.strip().lower()

            if _SHA256_PATTERN.fullmatch(fingerprint) is None:
                raise ValueError("mutual TLS certificate fingerprint must be a SHA-256 digest")

        if self.schema_version != 1:
            raise ValueError("unsupported service-account authentication context schema version")

        object.__setattr__(
            self,
            "client_address",
            client_address,
        )
        object.__setattr__(
            self,
            "peer_address",
            peer_address,
        )
        object.__setattr__(
            self,
            "identity_source",
            identity_source,
        )
        object.__setattr__(
            self,
            "mutual_tls_certificate_sha256",
            fingerprint,
        )

    @property
    def mutual_tls(self) -> bool:
        return self.mutual_tls_certificate_sha256 is not None


def control_plane_service_account_authentication_context(
    network_context: ControlPlaneNetworkRequestContext,
    writer: _ControlPlaneServiceAccountTransportWriter,
    *,
    tls_policy: ControlPlaneTlsPolicy,
) -> ControlPlaneServiceAccountAuthenticationContext:
    """Bind guard-approved identity to the real socket and mTLS peer."""

    if not isinstance(
        network_context,
        ControlPlaneNetworkRequestContext,
    ):
        raise TypeError("network context has an invalid type")

    if not isinstance(
        tls_policy,
        ControlPlaneTlsPolicy,
    ):
        raise TypeError("TLS policy has an invalid type")

    peer_address = _transport_peer_address(writer.get_extra_info("peername"))

    if peer_address != network_context.identity.peer_address:
        raise (
            ControlPlaneServiceAccountTransportContextError(
                "network identity does not match the transport peer"
            )
        )

    certificate_fingerprint: str | None = None

    if tls_policy.mutual_tls:
        ssl_object = writer.get_extra_info("ssl_object")

        if ssl_object is None:
            raise (
                ControlPlaneServiceAccountTransportContextError(
                    "mutual TLS transport state is unavailable"
                )
            )

        get_peer_certificate = getattr(
            ssl_object,
            "getpeercert",
            None,
        )

        if not callable(get_peer_certificate):
            raise (
                ControlPlaneServiceAccountTransportContextError(
                    "mutual TLS peer certificate is unavailable"
                )
            )

        try:
            certificate = get_peer_certificate(binary_form=True)
        except Exception as exception:
            raise (
                ControlPlaneServiceAccountTransportContextError(
                    "mutual TLS peer certificate could not be read"
                )
            ) from exception

        if not isinstance(certificate, bytes) or not certificate:
            raise (
                ControlPlaneServiceAccountTransportContextError(
                    "mutual TLS peer certificate is unavailable"
                )
            )

        certificate_fingerprint = hashlib.sha256(certificate).hexdigest()

    return ControlPlaneServiceAccountAuthenticationContext(
        client_address=(network_context.identity.address),
        peer_address=peer_address,
        identity_source=(network_context.identity.source),
        mutual_tls_certificate_sha256=(certificate_fingerprint),
        _authority=_CONTEXT_AUTHORITY,
    )


def _transport_peer_address(
    peername: object,
) -> str:
    if not isinstance(peername, tuple) or not peername or not isinstance(peername[0], str):
        raise ControlPlaneServiceAccountTransportContextError(
            "transport peer address is unavailable"
        )

    try:
        return str(ip_address(peername[0]))
    except ValueError as exception:
        raise (
            ControlPlaneServiceAccountTransportContextError("transport peer address is invalid")
        ) from exception


@dataclass(frozen=True, slots=True)
class ControlPlaneServiceAccountAuthentication:
    """Credential-free evidence for an accepted machine bearer."""

    service_account_id: UUID
    token_id: UUID
    account_name: str
    scopes: frozenset[str]
    resources: frozenset[str]
    token_version: int
    account_revision: int
    token_revision: int
    authenticated_at: datetime
    expires_at: datetime
    restriction_applied: bool = False
    schema_version: int = 1

    def __post_init__(self) -> None:
        account_name = self.account_name.strip().lower()
        scopes = frozenset(self.scopes)
        resources = frozenset(self.resources)

        if not account_name:
            raise ValueError("authenticated service-account name must not be blank")

        if not scopes or any(not scope.strip() for scope in scopes):
            raise ValueError("authenticated service-account scopes must not be blank")

        if not resources or any(not resource.strip() for resource in resources):
            raise ValueError("authenticated service-account resources must not be blank")

        if (
            min(
                self.token_version,
                self.account_revision,
                self.token_revision,
            )
            <= 0
        ):
            raise ValueError("authenticated service-account versions must be positive")

        if self.authenticated_at.tzinfo is None or self.expires_at.tzinfo is None:
            raise ValueError("service-account authentication times must be timezone-aware")

        if self.authenticated_at >= self.expires_at:
            raise ValueError("expired API token cannot produce authentication evidence")

        if self.schema_version != 1:
            raise ValueError("unsupported service-account authentication schema version")

        object.__setattr__(
            self,
            "account_name",
            account_name,
        )
        object.__setattr__(
            self,
            "scopes",
            scopes,
        )
        object.__setattr__(
            self,
            "resources",
            resources,
        )

    @property
    def principal_name(self) -> str:
        """Return a namespace-separated machine identity."""

        return f"service-account:{self.account_name}"


class ControlPlaneServiceAccountAuthenticator:
    """Authenticate machine bearers without operator authority."""

    def __init__(
        self,
        repository: ControlPlaneServiceAccountRepository,
        *,
        clock: (ControlPlaneServiceAccountAuthenticationClock) = _utc_now,
    ) -> None:
        if not callable(clock):
            raise TypeError("service-account authentication clock must be callable")

        self._repository = repository
        self._clock = clock

    async def authenticate(
        self,
        authorization: str | None,
        *,
        context: (ControlPlaneServiceAccountAuthenticationContext | None) = None,
    ) -> ControlPlaneServiceAccountAuthentication | None:
        """Return None for every credential or state mismatch."""

        if context is not None and not isinstance(
            context,
            ControlPlaneServiceAccountAuthenticationContext,
        ):
            raise TypeError("service-account authentication context has an invalid type")

        candidate_digest, syntactically_valid = _authorization_digest(authorization)

        metadata = await self._repository.get_token_by_digest(candidate_digest)

        account_id = _DUMMY_SERVICE_ACCOUNT_ID if metadata is None else metadata.service_account_id

        account = await self._repository.get_account(account_id)

        expected_digest = _DUMMY_TOKEN_DIGEST if metadata is None else metadata.token_digest

        digest_matches = _compare_digest(
            candidate_digest,
            expected_digest,
        )

        authenticated_at = self._clock()

        if authenticated_at.tzinfo is None:
            raise ValueError(
                "service-account authentication clock must return a timezone-aware datetime"
            )

        if not syntactically_valid or metadata is None or not digest_matches:
            return None

        if not metadata.authenticatable_at(authenticated_at):
            if (
                metadata.status is ControlPlaneApiTokenStatus.ACTIVE
                and authenticated_at >= metadata.expires_at
            ):
                await self._persist_expired(
                    metadata,
                    now=authenticated_at,
                )

            return None

        if account is None or not account.status.authenticatable:
            return None

        if not _restrictions_allow(
            metadata,
            context,
        ):
            return None

        return ControlPlaneServiceAccountAuthentication(
            service_account_id=account.id,
            token_id=metadata.id,
            account_name=account.name,
            scopes=metadata.scopes,
            resources=metadata.resources,
            token_version=metadata.token_version,
            account_revision=account.revision,
            token_revision=metadata.revision,
            authenticated_at=authenticated_at,
            expires_at=metadata.expires_at,
            restriction_applied=(metadata.restriction.restricted),
        )

    async def _persist_expired(
        self,
        metadata: ControlPlaneApiTokenMetadata,
        *,
        now: datetime,
    ) -> None:
        replacement = replace(
            metadata,
            status=ControlPlaneApiTokenStatus.EXPIRED,
            revoked_at=None,
            updated_at=max(
                now,
                metadata.expires_at,
            ),
            revision=metadata.revision + 1,
        )

        try:
            await self._repository.replace_token(
                replacement,
                expected_revision=metadata.revision,
            )
        except ControlPlaneApiTokenConflictError:
            # A concurrent request already reconciled it.
            return


def _authorization_digest(
    authorization: str | None,
) -> tuple[str, bool]:
    if (
        not isinstance(authorization, str)
        or not authorization
        or len(authorization) > 256
        or authorization != authorization.strip()
        or "\r" in authorization
        or "\n" in authorization
    ):
        return _DUMMY_TOKEN_DIGEST, False

    parts = authorization.split(" ", 1)

    if len(parts) != 2:
        return _DUMMY_TOKEN_DIGEST, False

    scheme, supplied = parts

    if scheme.lower() != "bearer" or not supplied or supplied != supplied.strip():
        return _DUMMY_TOKEN_DIGEST, False

    try:
        token = ControlPlaneApiToken(supplied)
    except ValueError:
        return _DUMMY_TOKEN_DIGEST, False

    return token.digest, True


def _restrictions_allow(
    metadata: ControlPlaneApiTokenMetadata,
    context: (ControlPlaneServiceAccountAuthenticationContext | None),
) -> bool:
    restriction = metadata.restriction

    if restriction.allowed_client_networks:
        if context is None:
            return False

        address = ip_address(context.client_address)

        allowed = any(
            (network.version == address.version and address in network)
            for network in (
                ip_network(value, strict=True) for value in (restriction.allowed_client_networks)
            )
        )

        if not allowed:
            return False

    expected_certificate = restriction.mutual_tls_certificate_sha256

    if expected_certificate is not None:
        if context is None or context.mutual_tls_certificate_sha256 is None:
            return False

        if not _compare_digest(
            context.mutual_tls_certificate_sha256,
            expected_certificate,
        ):
            return False

    return True
