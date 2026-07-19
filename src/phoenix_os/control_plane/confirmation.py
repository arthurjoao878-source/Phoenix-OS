"""One-time cryptographic confirmations for destructive control-plane commands."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Protocol
from uuid import UUID

from phoenix_os.control_plane.auth import ControlPlanePrincipal
from phoenix_os.control_plane.commands import (
    ControlPlaneCommandAction,
    ControlPlaneCommandIntent,
)
from phoenix_os.control_plane.csrf import ControlPlaneNonceSource, ControlPlaneProtectionClock
from phoenix_os.control_plane.errors import (
    ControlPlaneConfirmationCapacityError,
    ControlPlaneConfirmationNotRequiredError,
    ControlPlaneConfirmationRejectedError,
    ControlPlaneConfirmationStoreClosedError,
)

_PROOF_PATTERN = re.compile(r"v1\.[0-9]{1,12}\.[A-Za-z0-9_-]{43}\.[A-Za-z0-9_-]{43}\Z")
_COMPONENT_PATTERN = re.compile(r"[A-Za-z0-9_-]{43}\Z")


def _utc_now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True, slots=True, repr=False)
class ControlPlaneConfirmationProof:
    """Opaque signed proof redacted from repr, str, logs, and receipts."""

    value: str = field(repr=False)

    def __post_init__(self) -> None:
        if self.value != self.value.strip() or _PROOF_PATTERN.fullmatch(self.value) is None:
            raise ValueError("confirmation proof has an invalid format")
        try:
            self.value.encode("ascii")
        except UnicodeEncodeError as exception:
            raise ValueError("confirmation proof must contain ASCII characters only") from exception

    @property
    def digest(self) -> bytes:
        return hashlib.sha256(self.value.encode("ascii")).digest()

    def __repr__(self) -> str:
        return "ControlPlaneConfirmationProof(<redacted>)"

    def __str__(self) -> str:
        return "<redacted>"


@dataclass(frozen=True, slots=True)
class ControlPlaneConfirmationChallenge:
    """Safe challenge metadata for one exact destructive command intent."""

    command_id: UUID
    action: ControlPlaneCommandAction
    target: str
    issued_at: datetime
    expires_at: datetime
    proof: ControlPlaneConfirmationProof = field(repr=False)
    schema_version: int = 1

    def __post_init__(self) -> None:
        action = ControlPlaneCommandAction(self.action)
        target = self.target.strip()
        if self.schema_version != 1:
            raise ValueError("unsupported confirmation challenge schema version")
        if not action.destructive:
            raise ValueError("confirmation challenge requires a destructive action")
        if not target:
            raise ValueError("confirmation challenge target must not be blank")
        _require_aware(self.issued_at, "issued_at")
        _require_aware(self.expires_at, "expires_at")
        if self.expires_at <= self.issued_at:
            raise ValueError("confirmation challenge expiry must follow issuance")
        object.__setattr__(self, "action", action)
        object.__setattr__(self, "target", target)


@dataclass(frozen=True, slots=True)
class ControlPlaneConfirmationVerification:
    """Safe result returned after a proof is validated and consumed once."""

    command_id: UUID
    action: ControlPlaneCommandAction
    target: str
    confirmed_at: datetime
    schema_version: int = 1

    def __post_init__(self) -> None:
        action = ControlPlaneCommandAction(self.action)
        target = self.target.strip()
        if self.schema_version != 1:
            raise ValueError("unsupported confirmation verification schema version")
        if not action.destructive:
            raise ValueError("confirmation verification requires a destructive action")
        if not target:
            raise ValueError("confirmation verification target must not be blank")
        _require_aware(self.confirmed_at, "confirmed_at")
        object.__setattr__(self, "action", action)
        object.__setattr__(self, "target", target)


@dataclass(frozen=True, slots=True)
class ControlPlaneConfirmationSnapshot:
    """Bounded confirmation-manager counters without proof or command fingerprints."""

    closed: bool
    entries: int
    active: int
    consumed: int
    capacity: int

    def __post_init__(self) -> None:
        if min(self.entries, self.active, self.consumed) < 0 or self.capacity <= 0:
            raise ValueError("confirmation counters cannot be negative")
        if self.entries > self.capacity or self.active + self.consumed != self.entries:
            raise ValueError("confirmation counters are inconsistent")


class ControlPlaneConfirmationService(Protocol):
    @property
    def closed(self) -> bool: ...

    async def issue(
        self,
        principal: ControlPlanePrincipal,
        intent: ControlPlaneCommandIntent,
    ) -> ControlPlaneConfirmationChallenge: ...

    async def verify_and_consume(
        self,
        principal: ControlPlanePrincipal,
        intent: ControlPlaneCommandIntent,
        proof: ControlPlaneConfirmationProof,
    ) -> ControlPlaneConfirmationVerification: ...

    async def snapshot(self) -> ControlPlaneConfirmationSnapshot: ...

    async def close(self) -> None: ...


@dataclass(slots=True)
class _ConfirmationEntry:
    binding_digest: bytes
    issued_at: datetime
    expires_at: datetime
    consumed: bool = False


class InMemoryControlPlaneConfirmationService:
    """Issue bounded HMAC proofs and reject expiration, mismatch, and replay."""

    def __init__(
        self,
        secret: bytes | bytearray | memoryview,
        *,
        capacity: int = 1024,
        ttl: timedelta = timedelta(minutes=2),
        future_skew: timedelta = timedelta(seconds=5),
        clock: ControlPlaneProtectionClock = _utc_now,
        nonce_source: ControlPlaneNonceSource = secrets.token_bytes,
    ) -> None:
        key = bytes(secret)
        if len(key) < 32 or len(key) > 128:
            raise ValueError("confirmation secret must contain between 32 and 128 bytes")
        if capacity <= 0 or capacity > 100_000:
            raise ValueError("confirmation capacity must be between 1 and 100000")
        if ttl <= timedelta(0) or ttl > timedelta(minutes=10):
            raise ValueError("confirmation TTL must be between zero and ten minutes")
        if future_skew < timedelta(0) or future_skew > timedelta(minutes=1):
            raise ValueError("confirmation future skew must be between zero and one minute")
        if not callable(clock) or not callable(nonce_source):
            raise TypeError("confirmation clock and nonce source must be callable")
        self._secret = key
        self._capacity = capacity
        self._ttl = ttl
        self._future_skew = future_skew
        self._clock = clock
        self._nonce_source = nonce_source
        self._entries: dict[bytes, _ConfirmationEntry] = {}
        self._closed = False
        self._lock = asyncio.Lock()

    @property
    def closed(self) -> bool:
        return self._closed

    async def issue(
        self,
        principal: ControlPlanePrincipal,
        intent: ControlPlaneCommandIntent,
    ) -> ControlPlaneConfirmationChallenge:
        self._require_destructive(intent)
        issued_at = _whole_second(self._clock())
        nonce = self._nonce_source(32)
        if not isinstance(nonce, bytes) or len(nonce) != 32:
            raise ValueError("confirmation nonce source must return exactly 32 bytes")
        timestamp = str(int(issued_at.timestamp()))
        nonce_text = _encode_component(nonce)
        signature = self._signature(principal, intent, timestamp, nonce_text)
        proof = ControlPlaneConfirmationProof(f"v1.{timestamp}.{nonce_text}.{signature}")
        expires_at = issued_at + self._ttl
        binding_digest = self._binding_digest(principal, intent)
        async with self._lock:
            self._require_open()
            self._ensure_capacity(issued_at)
            self._entries[proof.digest] = _ConfirmationEntry(
                binding_digest=binding_digest,
                issued_at=issued_at,
                expires_at=expires_at,
            )
        return ControlPlaneConfirmationChallenge(
            command_id=intent.id,
            action=intent.action,
            target=intent.target,
            issued_at=issued_at,
            expires_at=expires_at,
            proof=proof,
        )

    async def verify_and_consume(
        self,
        principal: ControlPlanePrincipal,
        intent: ControlPlaneCommandIntent,
        proof: ControlPlaneConfirmationProof,
    ) -> ControlPlaneConfirmationVerification:
        self._require_destructive(intent)
        now = _whole_second(self._clock())
        try:
            version, timestamp, nonce, supplied_signature = proof.value.split(".")
            if version != "v1" or _COMPONENT_PATTERN.fullmatch(nonce) is None:
                raise ValueError
            issued_at = datetime.fromtimestamp(int(timestamp), UTC)
            if issued_at > now + self._future_skew or now >= issued_at + self._ttl:
                raise ValueError
            expected = self._signature(principal, intent, timestamp, nonce)
            if not hmac.compare_digest(supplied_signature, expected):
                raise ValueError
        except (OverflowError, TypeError, ValueError) as exception:
            raise ControlPlaneConfirmationRejectedError(
                "command confirmation failed"
            ) from exception

        async with self._lock:
            self._require_open()
            entry = self._entries.get(proof.digest)
            binding = self._binding_digest(principal, intent)
            if (
                entry is None
                or entry.consumed
                or now >= entry.expires_at
                or not hmac.compare_digest(entry.binding_digest, binding)
            ):
                raise ControlPlaneConfirmationRejectedError("command confirmation failed")
            entry.consumed = True
        return ControlPlaneConfirmationVerification(
            command_id=intent.id,
            action=intent.action,
            target=intent.target,
            confirmed_at=now,
        )

    async def snapshot(self) -> ControlPlaneConfirmationSnapshot:
        async with self._lock:
            active = sum(not entry.consumed for entry in self._entries.values())
            return ControlPlaneConfirmationSnapshot(
                closed=self._closed,
                entries=len(self._entries),
                active=active,
                consumed=len(self._entries) - active,
                capacity=self._capacity,
            )

    async def close(self) -> None:
        async with self._lock:
            self._closed = True
            self._entries.clear()

    def _ensure_capacity(self, now: datetime) -> None:
        if len(self._entries) < self._capacity:
            return
        removable = [
            (digest, entry)
            for digest, entry in self._entries.items()
            if entry.consumed or now >= entry.expires_at
        ]
        if not removable:
            raise ControlPlaneConfirmationCapacityError(
                "confirmation capacity is occupied by active challenges"
            )
        digest, _ = min(
            removable,
            key=lambda item: (item[1].issued_at, item[0]),
        )
        del self._entries[digest]

    def _signature(
        self,
        principal: ControlPlanePrincipal,
        intent: ControlPlaneCommandIntent,
        timestamp: str,
        nonce: str,
    ) -> str:
        material = self._binding_material(principal, intent, timestamp, nonce)
        return _encode_component(hmac.new(self._secret, material, hashlib.sha256).digest())

    @staticmethod
    def _binding_digest(
        principal: ControlPlanePrincipal,
        intent: ControlPlaneCommandIntent,
    ) -> bytes:
        material = (
            f"phoenix-confirm-binding:v1:{principal.name}:{intent.id.hex}:"
            f"{intent.action.value}:{intent.target}:{intent.fingerprint}:"
            f"{intent.idempotency_key.digest.hex()}"
        ).encode()
        return hashlib.sha256(material).digest()

    @staticmethod
    def _binding_material(
        principal: ControlPlanePrincipal,
        intent: ControlPlaneCommandIntent,
        timestamp: str,
        nonce: str,
    ) -> bytes:
        return (
            f"phoenix-confirm:v1:{principal.name}:{intent.id.hex}:{intent.action.value}:"
            f"{intent.target}:{intent.fingerprint}:{intent.idempotency_key.digest.hex()}:"
            f"{timestamp}:{nonce}"
        ).encode()

    @staticmethod
    def _require_destructive(intent: ControlPlaneCommandIntent) -> None:
        if not intent.action.destructive:
            raise ControlPlaneConfirmationNotRequiredError(
                "command action does not require destructive confirmation"
            )

    def _require_open(self) -> None:
        if self._closed:
            raise ControlPlaneConfirmationStoreClosedError("confirmation service is closed")


def _encode_component(value: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _whole_second(value: datetime) -> datetime:
    _require_aware(value, "clock result")
    return datetime.fromtimestamp(int(value.timestamp()), UTC)


def _require_aware(value: datetime, label: str) -> None:
    if value.tzinfo is None:
        raise ValueError(f"{label} must be timezone-aware")
