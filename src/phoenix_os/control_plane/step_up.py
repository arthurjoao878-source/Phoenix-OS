"""Recent durable-credential confirmation for high-risk operator actions."""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from uuid import UUID

from phoenix_os.control_plane.durable_session_access import (
    ControlPlaneDurableSessionAuthentication,
)
from phoenix_os.control_plane.durable_session_contracts import (
    ControlPlaneDurableSessionRecord,
    ControlPlaneDurableSessionRepository,
    ControlPlaneDurableSessionStatus,
)
from phoenix_os.control_plane.errors import ControlPlaneStepUpRejectedError
from phoenix_os.control_plane.operator_authentication import ControlPlaneOperatorAuthenticator
from phoenix_os.control_plane.operator_contracts import (
    ControlPlaneOperatorRecord,
    ControlPlaneOperatorRegistry,
    ControlPlaneOperatorStatus,
)

DEFAULT_CONTROL_PLANE_STEP_UP_WINDOW = timedelta(minutes=5)
MAX_CONTROL_PLANE_STEP_UP_WINDOW = timedelta(minutes=30)
MAX_CONTROL_PLANE_STEP_UP_TOKEN_BYTES = 1024

_NONCE_PATTERN = re.compile(r"[A-Za-z0-9_-]{16,128}\Z")
_SIGNATURE_PATTERN = re.compile(r"[A-Za-z0-9_-]{43}\Z")

type ControlPlaneStepUpClock = Callable[[], datetime]
type ControlPlaneStepUpNonceSource = Callable[[int], bytes]


class ControlPlaneStepUpAction(StrEnum):
    """Reviewed high-risk operator mutations requiring recent authentication."""

    CREATE_MAINTAINER = "create-maintainer"
    UPDATE_ACCESS = "update-access"
    ROTATE_CREDENTIAL = "rotate-credential"
    REVOKE_OPERATOR = "revoke-operator"
    REVOKE_OPERATOR_SESSIONS = "revoke-operator-sessions"
    ISSUE_API_TOKEN = "issue-api-token"
    ROTATE_API_TOKEN = "rotate-api-token"
    REVOKE_API_TOKEN = "revoke-api-token"
    ENABLE_SERVICE_ACCOUNT = "enable-service-account"
    REVOKE_SERVICE_ACCOUNT = "revoke-service-account"


@dataclass(frozen=True, slots=True)
class ControlPlaneStepUpPolicy:
    """Bounded recent-authentication window."""

    window: timedelta = DEFAULT_CONTROL_PLANE_STEP_UP_WINDOW
    schema_version: int = 1

    def __post_init__(self) -> None:
        if self.window <= timedelta(0) or self.window > MAX_CONTROL_PLANE_STEP_UP_WINDOW:
            raise ValueError("step-up window is outside supported bounds")
        if self.schema_version != 1:
            raise ValueError("unsupported step-up policy schema version")


@dataclass(frozen=True, slots=True, repr=False)
class ControlPlaneStepUpToken:
    """Signed recent-authentication proof redacted from logs and representations."""

    value: str = field(repr=False)

    def __post_init__(self) -> None:
        try:
            encoded = self.value.encode("ascii")
        except UnicodeEncodeError as exception:
            raise ValueError("step-up token must contain ASCII only") from exception
        if not encoded or len(encoded) > MAX_CONTROL_PLANE_STEP_UP_TOKEN_BYTES:
            raise ValueError("step-up token has an invalid length")

    def __repr__(self) -> str:
        return "ControlPlaneStepUpToken(<redacted>)"

    def __str__(self) -> str:
        return "<redacted>"


@dataclass(frozen=True, slots=True)
class ControlPlaneStepUpEvidence:
    """Safe proof metadata returned after successful verification."""

    session_id: UUID
    operator_id: UUID
    action: ControlPlaneStepUpAction
    authenticated_at: datetime
    expires_at: datetime
    operator_revision: int
    operator_token_version: int
    session_generation: int
    schema_version: int = 1

    def __post_init__(self) -> None:
        object.__setattr__(self, "action", ControlPlaneStepUpAction(self.action))
        for label, value in (
            ("authenticated_at", self.authenticated_at),
            ("expires_at", self.expires_at),
        ):
            if value.tzinfo is None:
                raise ValueError(f"step-up {label} must be timezone-aware")
        if self.expires_at <= self.authenticated_at:
            raise ValueError("step-up expiry must follow authentication")
        if self.operator_revision <= 0 or self.operator_token_version <= 0:
            raise ValueError("step-up operator bindings must be positive")
        if self.session_generation <= 0:
            raise ValueError("step-up session generation must be positive")
        if self.schema_version != 1:
            raise ValueError("unsupported step-up evidence schema version")


@dataclass(frozen=True, slots=True)
class ControlPlaneStepUpGrant:
    """One-time signed proof and its safe metadata."""

    token: ControlPlaneStepUpToken = field(repr=False)
    evidence: ControlPlaneStepUpEvidence
    schema_version: int = 1

    def __post_init__(self) -> None:
        if self.schema_version != 1:
            raise ValueError("unsupported step-up grant schema version")


@dataclass(frozen=True, slots=True)
class ControlPlaneStepUpSnapshot:
    """Credential-free counters for recent-authentication operations."""

    confirmed: int
    verified: int
    rejected: int

    def __post_init__(self) -> None:
        if min(self.confirmed, self.verified, self.rejected) < 0:
            raise ValueError("step-up counters cannot be negative")


class ControlPlaneOperatorStepUpService:
    """Confirm the durable operator credential and sign a session/action-bound proof."""

    def __init__(
        self,
        *,
        authenticator: ControlPlaneOperatorAuthenticator,
        registry: ControlPlaneOperatorRegistry,
        repository: ControlPlaneDurableSessionRepository,
        secret: bytes,
        policy: ControlPlaneStepUpPolicy | None = None,
        clock: ControlPlaneStepUpClock | None = None,
        nonce_source: ControlPlaneStepUpNonceSource = secrets.token_bytes,
    ) -> None:
        if len(secret) < 32:
            raise ValueError("step-up signing secret must contain at least 32 bytes")
        if not callable(nonce_source):
            raise TypeError("step-up nonce source must be callable")
        self._authenticator = authenticator
        self._registry = registry
        self._repository = repository
        self._secret = bytes(secret)
        self._policy = ControlPlaneStepUpPolicy() if policy is None else policy
        self._clock = _utc_now if clock is None else clock
        self._nonce_source = nonce_source
        self._confirmed = 0
        self._verified = 0
        self._rejected = 0

    async def confirm(
        self,
        session: ControlPlaneDurableSessionAuthentication,
        durable_authorization: str | None,
        action: ControlPlaneStepUpAction,
    ) -> ControlPlaneStepUpGrant:
        """Reauthenticate the same operator and issue an action-specific recent proof."""

        action = ControlPlaneStepUpAction(action)
        operator_evidence = await self._authenticator.authenticate(durable_authorization)
        try:
            record, operator = await self._current_bindings(session)
            if (
                operator_evidence is None
                or operator_evidence.operator_id != session.operator_id
                or operator_evidence.principal.name != session.principal.name
                or operator_evidence.token_version != operator.token_version
            ):
                raise ValueError("credential mismatch")
            now = self._now()
            expires_at = now + self._policy.window
            evidence = ControlPlaneStepUpEvidence(
                session_id=session.session_id,
                operator_id=session.operator_id,
                action=action,
                authenticated_at=now,
                expires_at=expires_at,
                operator_revision=record.operator_revision,
                operator_token_version=record.operator_token_version,
                session_generation=record.generation,
            )
            nonce = _encode(self._nonce_source(24))
            if _NONCE_PATTERN.fullmatch(nonce) is None:
                raise ValueError("invalid nonce")
            material = _material(evidence, nonce)
            signature = _encode(hmac.new(self._secret, material, hashlib.sha256).digest())
            token = ControlPlaneStepUpToken(
                ".".join(
                    (
                        "v1",
                        evidence.session_id.hex,
                        evidence.operator_id.hex,
                        str(evidence.session_generation),
                        str(evidence.operator_revision),
                        str(evidence.operator_token_version),
                        evidence.action.value,
                        str(int(evidence.authenticated_at.timestamp())),
                        str(int(evidence.expires_at.timestamp())),
                        nonce,
                        signature,
                    )
                )
            )
        except (TypeError, ValueError) as exception:
            self._rejected += 1
            raise ControlPlaneStepUpRejectedError("step-up authentication rejected") from exception
        self._confirmed += 1
        return ControlPlaneStepUpGrant(token=token, evidence=evidence)

    async def verify(
        self,
        token_value: str | None,
        session: ControlPlaneDurableSessionAuthentication,
        action: ControlPlaneStepUpAction,
    ) -> ControlPlaneStepUpEvidence:
        """Verify signature, recent window, action, session generation, and operator bindings."""

        action = ControlPlaneStepUpAction(action)
        try:
            token = ControlPlaneStepUpToken(token_value or "")
            evidence, nonce, supplied_signature = _parse(token)
            expected_signature = _encode(
                hmac.new(self._secret, _material(evidence, nonce), hashlib.sha256).digest()
            )
            if not hmac.compare_digest(supplied_signature, expected_signature):
                raise ValueError("signature mismatch")
            now = self._now()
            if now < evidence.authenticated_at or now >= evidence.expires_at:
                raise ValueError("proof outside recent-authentication window")
            if evidence.expires_at - evidence.authenticated_at > self._policy.window:
                raise ValueError("proof exceeds configured window")
            if (
                evidence.session_id != session.session_id
                or evidence.operator_id != session.operator_id
                or evidence.session_generation != session.generation
                or evidence.action is not action
            ):
                raise ValueError("proof binding mismatch")
            record, _ = await self._current_bindings(session)
            if (
                evidence.operator_revision != record.operator_revision
                or evidence.operator_token_version != record.operator_token_version
            ):
                raise ValueError("proof operator binding is stale")
        except (TypeError, ValueError) as exception:
            self._rejected += 1
            raise ControlPlaneStepUpRejectedError("step-up authentication rejected") from exception
        self._verified += 1
        return evidence

    def snapshot(self) -> ControlPlaneStepUpSnapshot:
        return ControlPlaneStepUpSnapshot(
            confirmed=self._confirmed,
            verified=self._verified,
            rejected=self._rejected,
        )

    async def _current_bindings(
        self,
        session: ControlPlaneDurableSessionAuthentication,
    ) -> tuple[ControlPlaneDurableSessionRecord, ControlPlaneOperatorRecord]:
        record = await self._repository.get(session.session_id)
        operator = await self._registry.get(session.operator_id)
        if (
            record is None
            or record.status is not ControlPlaneDurableSessionStatus.ACTIVE
            or record.operator_id != session.operator_id
            or record.username != session.principal.name
            or record.generation != session.generation
            or operator is None
            or operator.status is not ControlPlaneOperatorStatus.ACTIVE
            or operator.username != session.principal.name
            or operator.revision != record.operator_revision
            or operator.token_version != record.operator_token_version
        ):
            raise ValueError("session or operator binding is stale")
        return record, operator

    def _now(self) -> datetime:
        now = self._clock()
        if now.tzinfo is None:
            raise ValueError("step-up clock must return a timezone-aware datetime")
        return datetime.fromtimestamp(int(now.timestamp()), UTC)


def _parse(
    token: ControlPlaneStepUpToken,
) -> tuple[ControlPlaneStepUpEvidence, str, str]:
    parts = token.value.split(".")
    if len(parts) != 11 or parts[0] != "v1":
        raise ValueError("invalid step-up token")
    session_id = UUID(hex=parts[1])
    operator_id = UUID(hex=parts[2])
    if session_id.hex != parts[1] or operator_id.hex != parts[2]:
        raise ValueError("noncanonical UUID")
    generation = _positive_integer(parts[3])
    operator_revision = _positive_integer(parts[4])
    token_version = _positive_integer(parts[5])
    action = ControlPlaneStepUpAction(parts[6])
    authenticated_at = datetime.fromtimestamp(_nonnegative_integer(parts[7]), UTC)
    expires_at = datetime.fromtimestamp(_nonnegative_integer(parts[8]), UTC)
    nonce = parts[9]
    signature = parts[10]
    if _NONCE_PATTERN.fullmatch(nonce) is None or _SIGNATURE_PATTERN.fullmatch(signature) is None:
        raise ValueError("invalid nonce or signature")
    return (
        ControlPlaneStepUpEvidence(
            session_id=session_id,
            operator_id=operator_id,
            action=action,
            authenticated_at=authenticated_at,
            expires_at=expires_at,
            operator_revision=operator_revision,
            operator_token_version=token_version,
            session_generation=generation,
        ),
        nonce,
        signature,
    )


def _material(evidence: ControlPlaneStepUpEvidence, nonce: str) -> bytes:
    return (
        "phoenix-step-up:v1:"
        f"{evidence.session_id.hex}:{evidence.operator_id.hex}:"
        f"{evidence.session_generation}:{evidence.operator_revision}:"
        f"{evidence.operator_token_version}:{evidence.action.value}:"
        f"{int(evidence.authenticated_at.timestamp())}:"
        f"{int(evidence.expires_at.timestamp())}:{nonce}"
    ).encode("ascii")


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _positive_integer(value: str) -> int:
    result = int(value)
    if result <= 0 or str(result) != value:
        raise ValueError("value must be a canonical positive integer")
    return result


def _nonnegative_integer(value: str) -> int:
    result = int(value)
    if result < 0 or str(result) != value:
        raise ValueError("value must be a canonical nonnegative integer")
    return result


def _utc_now() -> datetime:
    return datetime.now(UTC)
