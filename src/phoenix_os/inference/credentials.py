"""Exact-version credential leasing for model provider adapters."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import timedelta
from uuid import UUID

from phoenix_os.configuration import SecretValue
from phoenix_os.inference.errors import InferenceCredentialUnavailableError
from phoenix_os.policy import PrincipalType, SecurityContext
from phoenix_os.secrets import (
    PhoenixSecretsError,
    SecretLease,
    SecretRef,
    SecretsManager,
)

MAX_INFERENCE_CREDENTIAL_LEASE_TTL = timedelta(minutes=5)


@dataclass(frozen=True, slots=True)
class ModelCredentialPolicy:
    """Exact secret reference and bounded lease duration for one provider."""

    secret_ref: SecretRef
    lease_ttl: timedelta = timedelta(seconds=30)

    def __post_init__(self) -> None:
        if not isinstance(self.secret_ref, SecretRef):
            raise TypeError("secret_ref must be SecretRef")
        if self.secret_ref.version is None:
            raise ValueError("model credentials require an exact secret version")
        if not isinstance(self.lease_ttl, timedelta):
            raise TypeError("lease_ttl must be timedelta")
        if self.lease_ttl <= timedelta(0):
            raise ValueError("model credential lease_ttl must be positive")
        if self.lease_ttl > MAX_INFERENCE_CREDENTIAL_LEASE_TTL:
            raise ValueError("model credential lease_ttl exceeds the supported maximum")


@dataclass(frozen=True, slots=True)
class InferenceCredentialLease:
    """Temporary redacted credential material delivered to one trusted adapter."""

    id: UUID
    ref: SecretRef
    value: SecretValue = field(repr=False)
    expires_in: timedelta

    def __post_init__(self) -> None:
        if not isinstance(self.id, UUID):
            raise TypeError("credential lease id must be UUID")
        if not isinstance(self.ref, SecretRef) or self.ref.version is None:
            raise ValueError("credential lease requires an exact SecretRef")
        if not isinstance(self.value, SecretValue):
            raise TypeError("credential lease value must be SecretValue")
        if not isinstance(self.expires_in, timedelta) or self.expires_in <= timedelta(0):
            raise ValueError("credential lease expires_in must be positive")


class InferenceCredentialBroker:
    """Lease and revoke provider credentials through one trusted Runtime identity."""

    def __init__(
        self,
        secrets: SecretsManager,
        context: SecurityContext,
    ) -> None:
        if not isinstance(secrets, SecretsManager):
            raise TypeError("secrets must be SecretsManager")
        if not isinstance(context, SecurityContext):
            raise TypeError("context must be SecurityContext")
        if not context.authenticated:
            raise ValueError("credential broker context must be authenticated")
        if context.principal_type not in {PrincipalType.SYSTEM, PrincipalType.SERVICE}:
            raise ValueError("credential broker requires a system or service principal")
        self._secrets = secrets
        self._context = context

    @asynccontextmanager
    async def lease(
        self,
        policy: ModelCredentialPolicy,
    ) -> AsyncIterator[InferenceCredentialLease]:
        if not isinstance(policy, ModelCredentialPolicy):
            raise TypeError("policy must be ModelCredentialPolicy")

        lease: SecretLease
        try:
            lease = await self._secrets.lease(
                policy.secret_ref,
                self._context,
                ttl=policy.lease_ttl,
            )
            credential = InferenceCredentialLease(
                id=lease.id,
                ref=lease.ref,
                value=lease.value,
                expires_in=lease.expires_at - lease.issued_at,
            )
        except (PhoenixSecretsError, ValueError, TypeError) as exception:
            raise InferenceCredentialUnavailableError() from exception

        try:
            yield credential
        finally:
            try:
                revoked = await self._secrets.revoke_lease(
                    lease.id,
                    self._context,
                    reason="inference invocation completed",
                )
            except PhoenixSecretsError as exception:
                raise InferenceCredentialUnavailableError() from exception
            if not revoked:
                raise InferenceCredentialUnavailableError()
