"""Constant-time bearer authentication for identified local operators."""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

from phoenix_os.control_plane.auth import ControlPlanePrincipal
from phoenix_os.control_plane.operator_contracts import (
    ControlPlaneOperatorRegistry,
    ControlPlaneOperatorToken,
)

type ControlPlaneOperatorAuthenticationClock = Callable[[], datetime]

_DUMMY_TOKEN_DIGEST = hashlib.sha256(bytes(32)).hexdigest()


def _utc_now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class ControlPlaneOperatorAuthentication:
    """Safe identity evidence produced for one accepted operator bearer."""

    operator_id: UUID
    principal: ControlPlanePrincipal
    token_version: int
    authenticated_at: datetime
    schema_version: int = 1

    def __post_init__(self) -> None:
        if self.token_version <= 0:
            raise ValueError("operator authentication token version must be positive")
        if self.authenticated_at.tzinfo is None:
            raise ValueError("operator authentication time must be timezone-aware")
        if self.schema_version != 1:
            raise ValueError("unsupported control-plane operator authentication schema version")


class ControlPlaneOperatorAuthenticator:
    """Resolve local bearer digests and compare credentials without plaintext retention."""

    def __init__(
        self,
        registry: ControlPlaneOperatorRegistry,
        *,
        clock: ControlPlaneOperatorAuthenticationClock = _utc_now,
    ) -> None:
        if not callable(clock):
            raise TypeError("operator authentication clock must be callable")
        self._registry = registry
        self._clock = clock

    async def authenticate(
        self,
        authorization: str | None,
    ) -> ControlPlaneOperatorAuthentication | None:
        """Return identified operator evidence or ``None`` for every credential mismatch."""

        candidate_digest, syntactically_valid = _authorization_digest(authorization)
        record = await self._registry.get_by_token_digest(candidate_digest)
        expected_digest = record.token_digest if record is not None else _DUMMY_TOKEN_DIGEST
        digest_matches = hmac.compare_digest(candidate_digest, expected_digest)

        if (
            not syntactically_valid
            or record is None
            or not digest_matches
            or not record.status.authenticatable
        ):
            return None

        authenticated_at = self._clock()
        if authenticated_at.tzinfo is None:
            raise ValueError("operator authentication clock must return a timezone-aware datetime")
        return ControlPlaneOperatorAuthentication(
            operator_id=record.id,
            principal=record.principal(),
            token_version=record.token_version,
            authenticated_at=authenticated_at,
        )


def _authorization_digest(authorization: str | None) -> tuple[str, bool]:
    if authorization is None or len(authorization) > 256:
        return _DUMMY_TOKEN_DIGEST, False
    parts = authorization.split(" ", 1)
    if len(parts) != 2:
        return _DUMMY_TOKEN_DIGEST, False
    scheme, supplied = parts
    if scheme.lower() != "bearer" or not supplied or supplied != supplied.strip():
        return _DUMMY_TOKEN_DIGEST, False
    try:
        token = ControlPlaneOperatorToken(supplied)
    except ValueError:
        return _DUMMY_TOKEN_DIGEST, False
    return token.digest, True
