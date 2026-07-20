"""Stateless origin-bound CSRF tokens for the local dashboard command API."""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import re
import secrets
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit

from phoenix_os.control_plane.auth import ControlPlanePrincipal
from phoenix_os.control_plane.errors import ControlPlaneCsrfRejectedError
from phoenix_os.control_plane.network_contracts import (
    ControlPlaneNetworkConfigurationError,
    ControlPlanePublicOrigin,
)

_TOKEN_PATTERN = re.compile(r"v1\.[0-9]{1,12}\.[A-Za-z0-9_-]{43}\.[A-Za-z0-9_-]{43}\Z")
_TOKEN_COMPONENT_PATTERN = re.compile(r"[A-Za-z0-9_-]{43}\Z")


type ControlPlaneProtectionClock = Callable[[], datetime]
type ControlPlaneNonceSource = Callable[[int], bytes]


def _utc_now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class ControlPlaneBrowserOrigin:
    """Canonical loopback-HTTP or public-HTTPS origin accepted from browsers."""

    value: str

    def __post_init__(self) -> None:
        raw = self.value.strip()
        if raw != self.value or not raw:
            raise ValueError("browser origin must not contain surrounding whitespace")
        parsed = urlsplit(raw)
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("browser origin must not contain user information")
        if parsed.path or parsed.query or parsed.fragment:
            raise ValueError("browser origin must not contain a path, query, or fragment")
        try:
            public = ControlPlanePublicOrigin(raw)
        except ControlPlaneNetworkConfigurationError as exception:
            raise ValueError("browser origin is invalid") from exception
        if public.scheme == "http":
            try:
                address = ipaddress.ip_address(public.host)
            except ValueError as exception:
                raise ValueError(
                    "HTTP browser origin host must be a literal IP address"
                ) from exception
            if not address.is_loopback:
                raise ValueError("HTTP browser origin host must be loopback")
        object.__setattr__(self, "value", public.value)

    @property
    def scheme(self) -> str:
        return urlsplit(self.value).scheme

    @property
    def secure(self) -> bool:
        return self.scheme == "https"

    @property
    def loopback(self) -> bool:
        host = urlsplit(self.value).hostname
        if host is None:  # pragma: no cover - protected by construction
            raise AssertionError("validated browser origin lost its host")
        if host == "localhost":
            return True
        try:
            return ipaddress.ip_address(host).is_loopback
        except ValueError:
            return False

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True, repr=False)
class ControlPlaneCsrfToken:
    """Opaque browser token whose value is redacted from ordinary representations."""

    value: str = field(repr=False)

    def __post_init__(self) -> None:
        if self.value != self.value.strip() or _TOKEN_PATTERN.fullmatch(self.value) is None:
            raise ValueError("CSRF token has an invalid format")
        try:
            self.value.encode("ascii")
        except UnicodeEncodeError as exception:
            raise ValueError("CSRF token must contain ASCII characters only") from exception

    @property
    def digest(self) -> bytes:
        return hashlib.sha256(self.value.encode("ascii")).digest()

    def __repr__(self) -> str:
        return "ControlPlaneCsrfToken(<redacted>)"

    def __str__(self) -> str:
        return "<redacted>"


@dataclass(frozen=True, slots=True)
class ControlPlaneCsrfVerification:
    """Safe result proving exact principal and origin validation."""

    principal: str
    origin: ControlPlaneBrowserOrigin
    issued_at: datetime
    expires_at: datetime
    schema_version: int = 1

    def __post_init__(self) -> None:
        principal = self.principal.strip()
        if self.schema_version != 1:
            raise ValueError("unsupported CSRF verification schema version")
        if not principal:
            raise ValueError("CSRF verification principal must not be blank")
        _require_aware(self.issued_at, "issued_at")
        _require_aware(self.expires_at, "expires_at")
        if self.expires_at <= self.issued_at:
            raise ValueError("CSRF verification expiry must follow issuance")
        object.__setattr__(self, "principal", principal)


class ControlPlaneCsrfProtector:
    """Issue and verify short-lived HMAC tokens bound to principal and exact origin."""

    def __init__(
        self,
        secret: bytes | bytearray | memoryview,
        *,
        ttl: timedelta = timedelta(minutes=10),
        future_skew: timedelta = timedelta(seconds=5),
        clock: ControlPlaneProtectionClock = _utc_now,
        nonce_source: ControlPlaneNonceSource = secrets.token_bytes,
    ) -> None:
        key = bytes(secret)
        if len(key) < 32 or len(key) > 128:
            raise ValueError("CSRF secret must contain between 32 and 128 bytes")
        if ttl <= timedelta(0) or ttl > timedelta(hours=1):
            raise ValueError("CSRF token TTL must be between zero and one hour")
        if future_skew < timedelta(0) or future_skew > timedelta(minutes=1):
            raise ValueError("CSRF future skew must be between zero and one minute")
        if not callable(clock) or not callable(nonce_source):
            raise TypeError("CSRF clock and nonce source must be callable")
        self._secret = key
        self._ttl = ttl
        self._future_skew = future_skew
        self._clock = clock
        self._nonce_source = nonce_source

    def issue(
        self,
        principal: ControlPlanePrincipal,
        origin: ControlPlaneBrowserOrigin,
    ) -> ControlPlaneCsrfToken:
        issued_at = _whole_second(self._clock())
        nonce = self._nonce_source(32)
        if not isinstance(nonce, bytes) or len(nonce) != 32:
            raise ValueError("CSRF nonce source must return exactly 32 bytes")
        timestamp = str(int(issued_at.timestamp()))
        nonce_text = _encode_component(nonce)
        signature = self._signature(principal.name, origin.value, timestamp, nonce_text)
        return ControlPlaneCsrfToken(f"v1.{timestamp}.{nonce_text}.{signature}")

    def verify(
        self,
        token: ControlPlaneCsrfToken,
        principal: ControlPlanePrincipal,
        origin: ControlPlaneBrowserOrigin,
    ) -> ControlPlaneCsrfVerification:
        try:
            version, timestamp, nonce, supplied_signature = token.value.split(".")
            if version != "v1" or _TOKEN_COMPONENT_PATTERN.fullmatch(nonce) is None:
                raise ValueError
            issued_at = datetime.fromtimestamp(int(timestamp), UTC)
            now = self._validated_now()
            expires_at = issued_at + self._ttl
            if issued_at > now + self._future_skew or now >= expires_at:
                raise ValueError
            expected = self._signature(principal.name, origin.value, timestamp, nonce)
            if not hmac.compare_digest(supplied_signature, expected):
                raise ValueError
        except (OverflowError, TypeError, ValueError) as exception:
            raise ControlPlaneCsrfRejectedError("CSRF validation failed") from exception
        return ControlPlaneCsrfVerification(
            principal=principal.name,
            origin=origin,
            issued_at=issued_at,
            expires_at=expires_at,
        )

    def _signature(self, principal: str, origin: str, timestamp: str, nonce: str) -> str:
        material = f"phoenix-csrf:v1:{principal}:{origin}:{timestamp}:{nonce}".encode()
        return _encode_component(hmac.new(self._secret, material, hashlib.sha256).digest())

    def _validated_now(self) -> datetime:
        return _whole_second(self._clock())


def _encode_component(value: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _whole_second(value: datetime) -> datetime:
    _require_aware(value, "clock result")
    return datetime.fromtimestamp(int(value.timestamp()), UTC)


def _require_aware(value: datetime, label: str) -> None:
    if value.tzinfo is None:
        raise ValueError(f"{label} must be timezone-aware")
