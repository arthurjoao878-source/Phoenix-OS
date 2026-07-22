from __future__ import annotations

import asyncio
import hashlib
import hmac
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Protocol

from phoenix_os.control_plane.service_account_authentication import (
    ControlPlaneServiceAccountAuthentication,
    ControlPlaneServiceAccountAuthenticationContext,
)

DEFAULT_CONTROL_PLANE_SERVICE_ACCOUNT_REPLAY_WINDOW = timedelta(minutes=5)
DEFAULT_CONTROL_PLANE_SERVICE_ACCOUNT_REPLAY_FUTURE_SKEW = timedelta(seconds=30)
DEFAULT_CONTROL_PLANE_SERVICE_ACCOUNT_REPLAY_CAPACITY = 10_000

MAX_CONTROL_PLANE_SERVICE_ACCOUNT_REPLAY_WINDOW = timedelta(hours=1)
MAX_CONTROL_PLANE_SERVICE_ACCOUNT_REPLAY_FUTURE_SKEW = timedelta(minutes=5)
MAX_CONTROL_PLANE_SERVICE_ACCOUNT_REPLAY_CAPACITY = 1_000_000
MAX_CONTROL_PLANE_SERVICE_ACCOUNT_REQUEST_TARGET_BYTES = 2048

_NONCE_PATTERN = re.compile(r"[A-Za-z0-9._:-]{16,128}\Z")
_DIGEST_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
_METHOD_PATTERN = re.compile(r"[A-Z]{3,16}\Z")

ControlPlaneServiceAccountReplayClock = Callable[
    [],
    datetime,
]


class ControlPlaneServiceAccountReplayRejectionReason(StrEnum):
    """Identifier-free replay rejection categories."""

    REPLAY = "replay"
    NONCE_REUSE = "nonce-reuse"
    STALE = "stale"
    FUTURE = "future"
    CAPACITY = "capacity"
    CLOSED = "closed"


class ControlPlaneServiceAccountReplayRejectedError(RuntimeError):
    """One generic public failure for replay admission."""

    def __init__(
        self,
        reason: (ControlPlaneServiceAccountReplayRejectionReason),
    ) -> None:
        self.reason = ControlPlaneServiceAccountReplayRejectionReason(reason)
        super().__init__("service-account request rejected")


@dataclass(frozen=True, slots=True)
class ControlPlaneServiceAccountRequestNonce:
    """Opaque nonce never retained in plaintext."""

    value: str = field(repr=False)

    def __post_init__(self) -> None:
        if not isinstance(
            self.value,
            str,
        ):
            raise TypeError("service-account request nonce must be str")

        if self.value != self.value.strip():
            raise ValueError("service-account request nonce is invalid")

        try:
            self.value.encode("ascii")
        except UnicodeEncodeError as exception:
            raise ValueError("service-account request nonce is invalid") from exception

        if _NONCE_PATTERN.fullmatch(self.value) is None:
            raise ValueError("service-account request nonce is invalid")

    def __repr__(self) -> str:
        return "ControlPlaneServiceAccountRequestNonce(<redacted>)"

    def __str__(self) -> str:
        return "<redacted>"


@dataclass(frozen=True, slots=True)
class ControlPlaneServiceAccountReplayRequest:
    """Canonical request evidence for replay admission."""

    nonce: ControlPlaneServiceAccountRequestNonce
    issued_at: datetime
    method: str
    target: str = field(repr=False)
    body_digest: str = field(repr=False)
    schema_version: int = 1

    def __post_init__(self) -> None:
        if not isinstance(
            self.nonce,
            ControlPlaneServiceAccountRequestNonce,
        ):
            raise TypeError("service-account replay request requires a validated nonce")

        if self.issued_at.tzinfo is None:
            raise ValueError("service-account replay issued_at must be timezone-aware")

        if not isinstance(
            self.method,
            str,
        ):
            raise TypeError("service-account replay method must be str")

        method = self.method.strip()

        if method != self.method or _METHOD_PATTERN.fullmatch(method) is None:
            raise ValueError("service-account replay method is invalid")

        if not isinstance(
            self.target,
            str,
        ):
            raise TypeError("service-account replay target must be str")

        target = self.target.strip()

        try:
            encoded_target = target.encode("ascii")
        except UnicodeEncodeError as exception:
            raise ValueError("service-account replay target is invalid") from exception

        if (
            not target
            or target != self.target
            or not target.startswith("/")
            or target.startswith("//")
            or "#" in target
            or len(encoded_target) > MAX_CONTROL_PLANE_SERVICE_ACCOUNT_REQUEST_TARGET_BYTES
            or any(ord(character) < 32 or ord(character) == 127 for character in target)
        ):
            raise ValueError("service-account replay target is invalid")

        if not isinstance(
            self.body_digest,
            str,
        ):
            raise TypeError("service-account replay body digest must be str")

        digest = self.body_digest.strip().lower()

        if digest != self.body_digest or _DIGEST_PATTERN.fullmatch(digest) is None:
            raise ValueError("service-account replay body digest is invalid")

        if self.schema_version != 1:
            raise ValueError("unsupported service-account replay request schema version")

        object.__setattr__(
            self,
            "method",
            method,
        )
        object.__setattr__(
            self,
            "target",
            target,
        )
        object.__setattr__(
            self,
            "body_digest",
            digest,
        )

    def __repr__(self) -> str:
        return f"ControlPlaneServiceAccountReplayRequest(method={self.method!r}, <redacted>)"


@dataclass(frozen=True, slots=True)
class ControlPlaneServiceAccountReplayPolicy:
    """Bounded freshness and fingerprint capacity."""

    window: timedelta = DEFAULT_CONTROL_PLANE_SERVICE_ACCOUNT_REPLAY_WINDOW
    future_skew: timedelta = DEFAULT_CONTROL_PLANE_SERVICE_ACCOUNT_REPLAY_FUTURE_SKEW
    capacity: int = DEFAULT_CONTROL_PLANE_SERVICE_ACCOUNT_REPLAY_CAPACITY

    def __post_init__(self) -> None:
        if not isinstance(
            self.window,
            timedelta,
        ):
            raise TypeError("service-account replay window must be timedelta")

        if not isinstance(
            self.future_skew,
            timedelta,
        ):
            raise TypeError("service-account replay future skew must be timedelta")

        if (
            self.window <= timedelta(0)
            or self.window > MAX_CONTROL_PLANE_SERVICE_ACCOUNT_REPLAY_WINDOW
        ):
            raise ValueError("service-account replay window is outside supported bounds")

        if (
            self.future_skew < timedelta(0)
            or self.future_skew > MAX_CONTROL_PLANE_SERVICE_ACCOUNT_REPLAY_FUTURE_SKEW
            or self.future_skew > self.window
        ):
            raise ValueError("service-account replay future skew is outside supported bounds")

        if not (1 <= self.capacity <= MAX_CONTROL_PLANE_SERVICE_ACCOUNT_REPLAY_CAPACITY):
            raise ValueError("service-account replay capacity is outside supported bounds")


@dataclass(frozen=True, slots=True)
class ControlPlaneServiceAccountReplaySnapshot:
    """Identifier-free replay counters."""

    closed: bool
    attempts: int
    accepted: int
    replay_rejections: int
    nonce_reuse_rejections: int
    stale_rejections: int
    future_rejections: int
    capacity_rejections: int
    tracked_requests: int
    capacity: int
    window_seconds: int
    future_skew_seconds: int
    last_rejection: ControlPlaneServiceAccountReplayRejectionReason | None = None
    schema_version: int = 1

    def __post_init__(self) -> None:
        counters = (
            self.attempts,
            self.accepted,
            self.replay_rejections,
            self.nonce_reuse_rejections,
            self.stale_rejections,
            self.future_rejections,
            self.capacity_rejections,
            self.tracked_requests,
        )

        if any(value < 0 for value in counters):
            raise ValueError("service-account replay counters cannot be negative")

        rejected = (
            self.replay_rejections
            + self.nonce_reuse_rejections
            + self.stale_rejections
            + self.future_rejections
            + self.capacity_rejections
        )

        if self.accepted + rejected != self.attempts:
            raise ValueError("service-account replay counters are inconsistent")

        if not (1 <= self.capacity <= MAX_CONTROL_PLANE_SERVICE_ACCOUNT_REPLAY_CAPACITY):
            raise ValueError("service-account replay snapshot capacity is invalid")

        if (
            self.tracked_requests > self.capacity
            or self.window_seconds <= 0
            or self.future_skew_seconds < 0
        ):
            raise ValueError("service-account replay snapshot is invalid")

        rejection = (
            None
            if self.last_rejection is None
            else ControlPlaneServiceAccountReplayRejectionReason(self.last_rejection)
        )

        if self.schema_version != 1:
            raise ValueError("unsupported service-account replay snapshot schema version")

        object.__setattr__(
            self,
            "last_rejection",
            rejection,
        )


class ControlPlaneServiceAccountAuthenticationBoundary(Protocol):
    async def authenticate(
        self,
        authorization: str | None,
        *,
        context: (ControlPlaneServiceAccountAuthenticationContext),
    ) -> ControlPlaneServiceAccountAuthentication | None: ...


class ControlPlaneServiceAccountReplayProtector:
    """Retain only protected nonce and request fingerprints."""

    def __init__(
        self,
        secret: bytes | bytearray | memoryview,
        policy: (ControlPlaneServiceAccountReplayPolicy | None) = None,
        *,
        clock: (ControlPlaneServiceAccountReplayClock) = lambda: datetime.now(UTC),
    ) -> None:
        key = bytes(secret)

        if len(key) < 32 or len(key) > 128:
            raise ValueError("service-account replay secret must contain 32 to 128 bytes")

        if not callable(clock):
            raise TypeError("service-account replay clock must be callable")

        self._secret = key
        self._policy = policy or ControlPlaneServiceAccountReplayPolicy()
        self._clock = clock

        self._entries: dict[
            str,
            tuple[str, datetime],
        ] = {}

        self._closed = False
        self._attempts = 0
        self._accepted = 0
        self._rejections = {
            reason: 0
            for reason in (
                ControlPlaneServiceAccountReplayRejectionReason.REPLAY,
                ControlPlaneServiceAccountReplayRejectionReason.NONCE_REUSE,
                ControlPlaneServiceAccountReplayRejectionReason.STALE,
                ControlPlaneServiceAccountReplayRejectionReason.FUTURE,
                ControlPlaneServiceAccountReplayRejectionReason.CAPACITY,
            )
        }
        self._last_rejection: ControlPlaneServiceAccountReplayRejectionReason | None = None
        self._lock = asyncio.Lock()

    @property
    def policy(
        self,
    ) -> ControlPlaneServiceAccountReplayPolicy:
        return self._policy

    @property
    def closed(self) -> bool:
        return self._closed

    async def admit(
        self,
        authentication: (ControlPlaneServiceAccountAuthentication),
        request: ControlPlaneServiceAccountReplayRequest,
    ) -> None:
        if not isinstance(
            authentication,
            ControlPlaneServiceAccountAuthentication,
        ):
            raise TypeError("service-account replay requires authentication evidence")

        if not isinstance(
            request,
            ControlPlaneServiceAccountReplayRequest,
        ):
            raise TypeError("service-account replay requires request evidence")

        now = self._now()
        issued_at = request.issued_at.astimezone(UTC)

        async with self._lock:
            if self._closed:
                self._last_rejection = ControlPlaneServiceAccountReplayRejectionReason.CLOSED
                raise (
                    ControlPlaneServiceAccountReplayRejectedError(
                        ControlPlaneServiceAccountReplayRejectionReason.CLOSED
                    )
                )

            self._purge(now)
            self._attempts += 1

            if issued_at < now - self._policy.window:
                self._reject(ControlPlaneServiceAccountReplayRejectionReason.STALE)

            if issued_at > now + self._policy.future_skew:
                self._reject(ControlPlaneServiceAccountReplayRejectionReason.FUTURE)

            nonce_fingerprint = self._nonce_fingerprint(
                authentication,
                request,
            )
            request_fingerprint = self._request_fingerprint(
                authentication,
                request,
            )

            existing = self._entries.get(nonce_fingerprint)

            if existing is not None:
                reason = (
                    ControlPlaneServiceAccountReplayRejectionReason.REPLAY
                    if hmac.compare_digest(
                        existing[0],
                        request_fingerprint,
                    )
                    else ControlPlaneServiceAccountReplayRejectionReason.NONCE_REUSE
                )
                self._reject(reason)

            if len(self._entries) >= self._policy.capacity:
                self._reject(ControlPlaneServiceAccountReplayRejectionReason.CAPACITY)

            self._entries[nonce_fingerprint] = (
                request_fingerprint,
                issued_at + self._policy.window,
            )
            self._accepted += 1

    async def snapshot(
        self,
    ) -> ControlPlaneServiceAccountReplaySnapshot:
        now = self._now()

        async with self._lock:
            self._purge(now)

            return ControlPlaneServiceAccountReplaySnapshot(
                closed=self._closed,
                attempts=self._attempts,
                accepted=self._accepted,
                replay_rejections=self._rejections[
                    ControlPlaneServiceAccountReplayRejectionReason.REPLAY
                ],
                nonce_reuse_rejections=self._rejections[
                    ControlPlaneServiceAccountReplayRejectionReason.NONCE_REUSE
                ],
                stale_rejections=self._rejections[
                    ControlPlaneServiceAccountReplayRejectionReason.STALE
                ],
                future_rejections=self._rejections[
                    ControlPlaneServiceAccountReplayRejectionReason.FUTURE
                ],
                capacity_rejections=self._rejections[
                    ControlPlaneServiceAccountReplayRejectionReason.CAPACITY
                ],
                tracked_requests=len(self._entries),
                capacity=self._policy.capacity,
                window_seconds=int(self._policy.window.total_seconds()),
                future_skew_seconds=int(self._policy.future_skew.total_seconds()),
                last_rejection=self._last_rejection,
            )

    async def close(self) -> None:
        async with self._lock:
            self._closed = True
            self._entries.clear()

    def _reject(
        self,
        reason: (ControlPlaneServiceAccountReplayRejectionReason),
    ) -> None:
        self._rejections[reason] += 1
        self._last_rejection = reason

        raise (ControlPlaneServiceAccountReplayRejectedError(reason))

    def _nonce_fingerprint(
        self,
        authentication: (ControlPlaneServiceAccountAuthentication),
        request: ControlPlaneServiceAccountReplayRequest,
    ) -> str:
        material = (
            f"phoenix-sa-replay-nonce:v1:{authentication.token_id.hex}:{request.nonce.value}"
        ).encode("ascii")

        return hmac.new(
            self._secret,
            material,
            hashlib.sha256,
        ).hexdigest()

    def _request_fingerprint(
        self,
        authentication: (ControlPlaneServiceAccountAuthentication),
        request: ControlPlaneServiceAccountReplayRequest,
    ) -> str:
        material = "\x00".join(
            (
                "phoenix-sa-replay-request:v1",
                authentication.token_id.hex,
                request.nonce.value,
                request.issued_at.astimezone(UTC).isoformat(),
                request.method,
                request.target,
                request.body_digest,
            )
        ).encode("utf-8")

        return hmac.new(
            self._secret,
            material,
            hashlib.sha256,
        ).hexdigest()

    def _purge(
        self,
        now: datetime,
    ) -> None:
        expired = [
            fingerprint
            for fingerprint, (
                _,
                expires_at,
            ) in self._entries.items()
            if expires_at < now
        ]

        for fingerprint in expired:
            del self._entries[fingerprint]

    def _now(self) -> datetime:
        now = self._clock()

        if now.tzinfo is None:
            raise ValueError("service-account replay clock must return timezone-aware datetime")

        return now.astimezone(UTC)


class ControlPlaneServiceAccountRequestSecurityService:
    """Combine authentication and replay admission."""

    def __init__(
        self,
        authentication: (ControlPlaneServiceAccountAuthenticationBoundary),
        replay: ControlPlaneServiceAccountReplayProtector,
    ) -> None:
        if not callable(
            getattr(
                authentication,
                "authenticate",
                None,
            )
        ):
            raise TypeError("service-account request security requires authentication")

        if not isinstance(
            replay,
            ControlPlaneServiceAccountReplayProtector,
        ):
            raise TypeError("service-account request security requires replay protector")

        self._authentication = authentication
        self._replay = replay

    @property
    def replay(
        self,
    ) -> ControlPlaneServiceAccountReplayProtector:
        return self._replay

    async def authenticate(
        self,
        authorization: str | None,
        *,
        context: (ControlPlaneServiceAccountAuthenticationContext),
        request: ControlPlaneServiceAccountReplayRequest,
    ) -> ControlPlaneServiceAccountAuthentication | None:
        if not isinstance(
            context,
            ControlPlaneServiceAccountAuthenticationContext,
        ):
            raise TypeError("service-account request security requires trusted transport context")

        if not isinstance(
            request,
            ControlPlaneServiceAccountReplayRequest,
        ):
            raise TypeError("service-account request security requires replay request evidence")

        evidence = await self._authentication.authenticate(
            authorization,
            context=context,
        )

        if evidence is None:
            return None

        try:
            await self._replay.admit(
                evidence,
                request,
            )
        except ControlPlaneServiceAccountReplayRejectedError:
            return None

        return evidence

    async def snapshot(
        self,
    ) -> ControlPlaneServiceAccountReplaySnapshot:
        return await self._replay.snapshot()

    async def close(self) -> None:
        await self._replay.close()
