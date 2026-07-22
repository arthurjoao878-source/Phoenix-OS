from __future__ import annotations

import asyncio
import math
import time
from collections import deque
from collections.abc import Hashable
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, TypeVar
from uuid import UUID

from phoenix_os.control_plane.service_account_authentication import (
    ControlPlaneServiceAccountAuthentication,
    ControlPlaneServiceAccountAuthenticationContext,
)

DEFAULT_CONTROL_PLANE_SERVICE_ACCOUNT_CLIENT_ATTEMPTS = 300
DEFAULT_CONTROL_PLANE_SERVICE_ACCOUNT_ACCOUNT_ATTEMPTS = 600
DEFAULT_CONTROL_PLANE_SERVICE_ACCOUNT_THROTTLE_WINDOW = 60.0
DEFAULT_CONTROL_PLANE_SERVICE_ACCOUNT_CLIENT_CAPACITY = 4096
DEFAULT_CONTROL_PLANE_SERVICE_ACCOUNT_ACCOUNT_CAPACITY = 4096

MAX_CONTROL_PLANE_SERVICE_ACCOUNT_AUTH_ATTEMPTS = 100_000
MAX_CONTROL_PLANE_SERVICE_ACCOUNT_THROTTLE_WINDOW = 3600.0
MAX_CONTROL_PLANE_SERVICE_ACCOUNT_THROTTLE_CAPACITY = 100_000

_Key = TypeVar(
    "_Key",
    bound=Hashable,
)


class ControlPlaneServiceAccountThrottleBlockReason(StrEnum):
    """Allowlisted throttling dimensions without identities."""

    CLIENT = "client"
    ACCOUNT = "account"
    CAPACITY = "capacity"
    CLOSED = "closed"


@dataclass(frozen=True, slots=True)
class ControlPlaneServiceAccountThrottleBlockedError(RuntimeError):
    """Generic authentication rejection with an internal dimension."""

    reason: ControlPlaneServiceAccountThrottleBlockReason

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "reason",
            ControlPlaneServiceAccountThrottleBlockReason(self.reason),
        )

    def __str__(self) -> str:
        return "service-account authentication rejected"


class ControlPlaneServiceAccountThrottleClosedError(RuntimeError):
    """A closed authentication throttle fails closed."""


class ControlPlaneServiceAccountThrottleClock(Protocol):
    """Monotonic clock used by authentication windows."""

    def now(self) -> float: ...


class _SystemThrottleClock:
    def now(self) -> float:
        return time.monotonic()


@dataclass(frozen=True, slots=True)
class ControlPlaneServiceAccountThrottlePolicy:
    """Independent bounded client and account limits."""

    client_attempts: int = DEFAULT_CONTROL_PLANE_SERVICE_ACCOUNT_CLIENT_ATTEMPTS
    account_attempts: int = DEFAULT_CONTROL_PLANE_SERVICE_ACCOUNT_ACCOUNT_ATTEMPTS
    window: float = DEFAULT_CONTROL_PLANE_SERVICE_ACCOUNT_THROTTLE_WINDOW
    client_capacity: int = DEFAULT_CONTROL_PLANE_SERVICE_ACCOUNT_CLIENT_CAPACITY
    account_capacity: int = DEFAULT_CONTROL_PLANE_SERVICE_ACCOUNT_ACCOUNT_CAPACITY

    def __post_init__(self) -> None:
        if not (1 <= self.client_attempts <= MAX_CONTROL_PLANE_SERVICE_ACCOUNT_AUTH_ATTEMPTS):
            raise ValueError(
                "service-account client authentication limit is outside supported bounds"
            )

        if not (1 <= self.account_attempts <= MAX_CONTROL_PLANE_SERVICE_ACCOUNT_AUTH_ATTEMPTS):
            raise ValueError(
                "service-account account authentication limit is outside supported bounds"
            )

        if not math.isfinite(self.window) or not (
            0 < self.window <= MAX_CONTROL_PLANE_SERVICE_ACCOUNT_THROTTLE_WINDOW
        ):
            raise ValueError("service-account authentication window is outside supported bounds")

        for value, label in (
            (
                self.client_capacity,
                "client",
            ),
            (
                self.account_capacity,
                "account",
            ),
        ):
            if not (1 <= value <= MAX_CONTROL_PLANE_SERVICE_ACCOUNT_THROTTLE_CAPACITY):
                raise ValueError(
                    f"service-account {label} throttle capacity is outside supported bounds"
                )


@dataclass(frozen=True, slots=True)
class ControlPlaneServiceAccountThrottleSnapshot:
    """Identifier-free throttle counters safe for diagnostics."""

    closed: bool
    client_attempts: int
    account_attempts: int
    client_blocks: int
    account_blocks: int
    capacity_blocks: int
    tracked_clients: int
    tracked_accounts: int
    client_limit: int
    account_limit: int
    client_capacity: int
    account_capacity: int
    window_seconds: float
    last_block: ControlPlaneServiceAccountThrottleBlockReason | None = None
    schema_version: int = 1

    def __post_init__(self) -> None:
        counters = (
            self.client_attempts,
            self.account_attempts,
            self.client_blocks,
            self.account_blocks,
            self.capacity_blocks,
            self.tracked_clients,
            self.tracked_accounts,
        )

        if any(value < 0 for value in counters):
            raise ValueError("service-account throttle counters cannot be negative")

        if self.tracked_clients > self.client_capacity:
            raise ValueError("tracked service-account clients exceed configured capacity")

        if self.tracked_accounts > self.account_capacity:
            raise ValueError("tracked service accounts exceed configured capacity")

        if not (1 <= self.client_limit <= MAX_CONTROL_PLANE_SERVICE_ACCOUNT_AUTH_ATTEMPTS):
            raise ValueError("service-account client limit is invalid")

        if not (1 <= self.account_limit <= MAX_CONTROL_PLANE_SERVICE_ACCOUNT_AUTH_ATTEMPTS):
            raise ValueError("service-account account limit is invalid")

        for value in (
            self.client_capacity,
            self.account_capacity,
        ):
            if not (1 <= value <= MAX_CONTROL_PLANE_SERVICE_ACCOUNT_THROTTLE_CAPACITY):
                raise ValueError("service-account throttle capacity is invalid")

        if not math.isfinite(self.window_seconds) or not (
            0 < self.window_seconds <= MAX_CONTROL_PLANE_SERVICE_ACCOUNT_THROTTLE_WINDOW
        ):
            raise ValueError("service-account throttle window is invalid")

        block = (
            None
            if self.last_block is None
            else ControlPlaneServiceAccountThrottleBlockReason(self.last_block)
        )

        if self.schema_version != 1:
            raise ValueError("unsupported service-account throttle snapshot schema version")

        object.__setattr__(
            self,
            "last_block",
            block,
        )


class ControlPlaneServiceAccountAuthenticationResolver(Protocol):
    """Authenticate one bearer using trusted transport facts."""

    async def authenticate(
        self,
        authorization: str | None,
        *,
        context: (ControlPlaneServiceAccountAuthenticationContext | None) = None,
    ) -> ControlPlaneServiceAccountAuthentication | None: ...


class ControlPlaneServiceAccountAuthenticationThrottle:
    """Independent sliding windows for clients and accounts."""

    def __init__(
        self,
        policy: (ControlPlaneServiceAccountThrottlePolicy | None) = None,
        *,
        clock: (ControlPlaneServiceAccountThrottleClock | None) = None,
    ) -> None:
        self._policy = policy or ControlPlaneServiceAccountThrottlePolicy()
        self._clock = clock or _SystemThrottleClock()

        self._client_buckets: dict[
            str,
            deque[float],
        ] = {}
        self._account_buckets: dict[
            UUID,
            deque[float],
        ] = {}

        self._closed = False
        self._client_attempts = 0
        self._account_attempts = 0
        self._client_blocks = 0
        self._account_blocks = 0
        self._capacity_blocks = 0
        self._last_block: ControlPlaneServiceAccountThrottleBlockReason | None = None
        self._lock = asyncio.Lock()

    @property
    def policy(
        self,
    ) -> ControlPlaneServiceAccountThrottlePolicy:
        return self._policy

    @property
    def closed(self) -> bool:
        return self._closed

    async def consume_client(
        self,
        context: ControlPlaneServiceAccountAuthenticationContext,
    ) -> None:
        """Consume one attempt for a trusted canonical client."""

        if not isinstance(
            context,
            ControlPlaneServiceAccountAuthenticationContext,
        ):
            raise TypeError("service-account client throttling requires trusted transport context")

        await self._consume(
            buckets=self._client_buckets,
            key=context.client_address,
            limit=self._policy.client_attempts,
            capacity=self._policy.client_capacity,
            dimension=(ControlPlaneServiceAccountThrottleBlockReason.CLIENT),
        )

    async def consume_account(
        self,
        service_account_id: UUID,
    ) -> None:
        """Consume one attempt after stable account resolution."""

        if not isinstance(service_account_id, UUID):
            raise TypeError("service-account throttling requires a UUID account identity")

        await self._consume(
            buckets=self._account_buckets,
            key=service_account_id,
            limit=self._policy.account_attempts,
            capacity=self._policy.account_capacity,
            dimension=(ControlPlaneServiceAccountThrottleBlockReason.ACCOUNT),
        )

    async def snapshot(
        self,
    ) -> ControlPlaneServiceAccountThrottleSnapshot:
        now = self._validated_now()

        async with self._lock:
            self._purge(
                self._client_buckets,
                now,
            )
            self._purge(
                self._account_buckets,
                now,
            )

            return ControlPlaneServiceAccountThrottleSnapshot(
                closed=self._closed,
                client_attempts=self._client_attempts,
                account_attempts=self._account_attempts,
                client_blocks=self._client_blocks,
                account_blocks=self._account_blocks,
                capacity_blocks=self._capacity_blocks,
                tracked_clients=len(self._client_buckets),
                tracked_accounts=len(self._account_buckets),
                client_limit=self._policy.client_attempts,
                account_limit=self._policy.account_attempts,
                client_capacity=self._policy.client_capacity,
                account_capacity=self._policy.account_capacity,
                window_seconds=self._policy.window,
                last_block=self._last_block,
            )

    async def close(self) -> None:
        async with self._lock:
            self._closed = True
            self._client_buckets.clear()
            self._account_buckets.clear()

    async def _consume(
        self,
        *,
        buckets: dict[_Key, deque[float]],
        key: _Key,
        limit: int,
        capacity: int,
        dimension: (ControlPlaneServiceAccountThrottleBlockReason),
    ) -> None:
        now = self._validated_now()

        async with self._lock:
            if self._closed:
                self._last_block = ControlPlaneServiceAccountThrottleBlockReason.CLOSED
                raise (
                    ControlPlaneServiceAccountThrottleClosedError(
                        "service-account authentication throttle is closed"
                    )
                )

            self._purge(
                self._client_buckets,
                now,
            )
            self._purge(
                self._account_buckets,
                now,
            )

            if dimension is ControlPlaneServiceAccountThrottleBlockReason.CLIENT:
                self._client_attempts += 1
            else:
                self._account_attempts += 1

            bucket = buckets.get(key)

            if bucket is None:
                if len(buckets) >= capacity:
                    self._capacity_blocks += 1
                    self._last_block = ControlPlaneServiceAccountThrottleBlockReason.CAPACITY
                    raise (
                        ControlPlaneServiceAccountThrottleBlockedError(
                            ControlPlaneServiceAccountThrottleBlockReason.CAPACITY
                        )
                    )

                bucket = deque()
                buckets[key] = bucket

            cutoff = now - self._policy.window

            while bucket and bucket[0] <= cutoff:
                bucket.popleft()

            if len(bucket) >= limit:
                if dimension is ControlPlaneServiceAccountThrottleBlockReason.CLIENT:
                    self._client_blocks += 1
                else:
                    self._account_blocks += 1

                self._last_block = dimension

                raise (ControlPlaneServiceAccountThrottleBlockedError(dimension))

            bucket.append(now)

    def _purge(
        self,
        buckets: dict[_Key, deque[float]],
        now: float,
    ) -> None:
        cutoff = now - self._policy.window
        expired: list[_Key] = []

        for key, bucket in buckets.items():
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()

            if not bucket:
                expired.append(key)

        for key in expired:
            del buckets[key]

    def _validated_now(self) -> float:
        now = self._clock.now()

        if not math.isfinite(now):
            raise RuntimeError("service-account throttle clock returned a non-finite value")

        return now


class ControlPlaneServiceAccountAuthenticationService:
    """Authenticate only after independent client/account admission."""

    def __init__(
        self,
        authenticator: (ControlPlaneServiceAccountAuthenticationResolver),
        throttle: (ControlPlaneServiceAccountAuthenticationThrottle),
    ) -> None:
        if not callable(
            getattr(
                authenticator,
                "authenticate",
                None,
            )
        ):
            raise TypeError("service-account authentication service requires an authenticator")

        if not isinstance(
            throttle,
            ControlPlaneServiceAccountAuthenticationThrottle,
        ):
            raise TypeError("service-account authentication service requires a throttle")

        self._authenticator = authenticator
        self._throttle = throttle

    @property
    def throttle(
        self,
    ) -> ControlPlaneServiceAccountAuthenticationThrottle:
        return self._throttle

    async def authenticate(
        self,
        authorization: str | None,
        *,
        context: ControlPlaneServiceAccountAuthenticationContext,
    ) -> ControlPlaneServiceAccountAuthentication | None:
        """Return one generic None for authentication or throttle rejection."""

        if not isinstance(
            context,
            ControlPlaneServiceAccountAuthenticationContext,
        ):
            raise TypeError(
                "service-account authentication service requires trusted transport context"
            )

        try:
            await self._throttle.consume_client(context)
        except (
            ControlPlaneServiceAccountThrottleBlockedError,
            ControlPlaneServiceAccountThrottleClosedError,
        ):
            return None

        evidence = await self._authenticator.authenticate(
            authorization,
            context=context,
        )

        if evidence is None:
            return None

        try:
            await self._throttle.consume_account(evidence.service_account_id)
        except (
            ControlPlaneServiceAccountThrottleBlockedError,
            ControlPlaneServiceAccountThrottleClosedError,
        ):
            return None

        return evidence

    async def snapshot(
        self,
    ) -> ControlPlaneServiceAccountThrottleSnapshot:
        return await self._throttle.snapshot()

    async def close(self) -> None:
        await self._throttle.close()
