"""HttpOnly cookie and session-bound CSRF transport for durable operator sessions."""

from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit
from uuid import UUID

from phoenix_os.control_plane.csrf import ControlPlaneBrowserOrigin
from phoenix_os.control_plane.durable_session_access import (
    ControlPlaneDurableSessionAccessService,
    ControlPlaneDurableSessionAuthentication,
    ControlPlaneDurableSessionGrant,
)
from phoenix_os.control_plane.durable_session_contracts import (
    ControlPlaneDurableSessionRecord,
    ControlPlaneDurableSessionRepository,
    ControlPlaneDurableSessionStatus,
)
from phoenix_os.control_plane.errors import (
    ControlPlaneDurableSessionCsrfRejectedError,
    ControlPlaneDurableSessionHttpRejectedError,
)
from phoenix_os.control_plane.operator_authentication import ControlPlaneOperatorAuthenticator

DEFAULT_DURABLE_SESSION_COOKIE_NAME = "phoenix_session"
MAX_DURABLE_SESSION_COOKIE_HEADER_BYTES = 4096
MAX_DURABLE_SESSION_CSRF_TOKEN_BYTES = 512

_COOKIE_NAME_PATTERN = re.compile(r"[A-Za-z][A-Za-z0-9_-]{2,63}\Z")
_CSRF_SECRET_PATTERN = re.compile(r"[A-Za-z0-9._~-]{32,128}\Z")
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")


@dataclass(frozen=True, slots=True)
class ControlPlaneDurableSessionCookiePolicy:
    """Host-only cookie policy for the loopback dashboard."""

    name: str = DEFAULT_DURABLE_SESSION_COOKIE_NAME
    path: str = "/"
    same_site: str = "Strict"
    http_only: bool = True
    secure: bool = False
    schema_version: int = 1

    def __post_init__(self) -> None:
        name = self.name.strip()
        if _COOKIE_NAME_PATTERN.fullmatch(name) is None:
            raise ValueError("durable session cookie name is invalid")
        if self.path != "/":
            raise ValueError("durable session cookie must be scoped to the root path")
        if self.same_site != "Strict":
            raise ValueError("durable session cookie must use SameSite=Strict")
        if not self.http_only:
            raise ValueError("durable session cookie must be HttpOnly")
        if self.schema_version != 1:
            raise ValueError("unsupported durable session cookie policy schema version")
        object.__setattr__(self, "name", name)


@dataclass(frozen=True, slots=True, repr=False)
class ControlPlaneDurableSessionCsrfToken:
    """Browser-readable CSRF evidence redacted from string representations."""

    value: str = field(repr=False)

    def __post_init__(self) -> None:
        if not self.value or len(self.value.encode("ascii", errors="ignore")) > (
            MAX_DURABLE_SESSION_CSRF_TOKEN_BYTES
        ):
            raise ValueError("durable session CSRF token has an invalid length")
        try:
            self.value.encode("ascii")
        except UnicodeEncodeError as exception:
            raise ValueError("durable session CSRF token must contain ASCII only") from exception

    def __repr__(self) -> str:
        return "ControlPlaneDurableSessionCsrfToken(<redacted>)"

    def __str__(self) -> str:
        return "<redacted>"


@dataclass(frozen=True, slots=True)
class ControlPlaneDurableSessionHttpLogin:
    """One-time HTTP material emitted after durable operator login."""

    authentication: ControlPlaneDurableSessionAuthentication
    csrf_token: ControlPlaneDurableSessionCsrfToken = field(repr=False)
    response_headers: tuple[tuple[str, str], ...] = field(repr=False)
    schema_version: int = 1

    def __post_init__(self) -> None:
        if not self.response_headers:
            raise ValueError("durable session HTTP login requires response headers")
        if self.schema_version != 1:
            raise ValueError("unsupported durable session HTTP login schema version")


@dataclass(frozen=True, slots=True)
class ControlPlaneDurableSessionHttpAuthentication:
    """Authenticated cookie session and optional rotation response material."""

    authentication: ControlPlaneDurableSessionAuthentication
    rotated_csrf_token: ControlPlaneDurableSessionCsrfToken | None = field(
        default=None,
        repr=False,
    )
    response_headers: tuple[tuple[str, str], ...] = field(default=(), repr=False)
    schema_version: int = 1

    def __post_init__(self) -> None:
        if self.authentication.rotated != (self.rotated_csrf_token is not None):
            raise ValueError("durable session rotation response is inconsistent")
        if self.authentication.rotated != bool(self.response_headers):
            raise ValueError("durable session rotation headers are inconsistent")
        if self.schema_version != 1:
            raise ValueError("unsupported durable session HTTP authentication schema version")


class ControlPlaneDurableSessionHttpBoundary:
    """Exchange durable credentials for host-only cookies and verify rotating CSRF evidence."""

    def __init__(
        self,
        *,
        authenticator: ControlPlaneOperatorAuthenticator,
        access: ControlPlaneDurableSessionAccessService,
        repository: ControlPlaneDurableSessionRepository,
        cookie_policy: ControlPlaneDurableSessionCookiePolicy | None = None,
    ) -> None:
        self._authenticator = authenticator
        self._access = access
        self._repository = repository
        self._cookie = (
            ControlPlaneDurableSessionCookiePolicy() if cookie_policy is None else cookie_policy
        )

    @property
    def cookie_policy(self) -> ControlPlaneDurableSessionCookiePolicy:
        return self._cookie

    async def login(
        self,
        authorization: str | None,
        *,
        origin: ControlPlaneBrowserOrigin,
    ) -> ControlPlaneDurableSessionHttpLogin:
        """Authenticate a durable credential and issue an HttpOnly session cookie."""

        evidence = await self._authenticator.authenticate(authorization)
        if evidence is None:
            raise ControlPlaneDurableSessionHttpRejectedError("operator login rejected")
        grant = await self._access.issue(evidence)
        authentication = _authentication_from_grant(grant, evidence.principal)
        csrf_token = _csrf_token(grant, origin)
        return ControlPlaneDurableSessionHttpLogin(
            authentication=authentication,
            csrf_token=csrf_token,
            response_headers=(
                ("Set-Cookie", self._set_cookie(grant)),
                ("X-Phoenix-CSRF", csrf_token.value),
                ("Cache-Control", "no-store"),
            ),
        )

    async def authenticate(
        self,
        cookie_header: str | None,
        *,
        origin: ControlPlaneBrowserOrigin,
    ) -> ControlPlaneDurableSessionHttpAuthentication:
        """Authenticate one cookie and emit replacement material only after rotation."""

        token = self._cookie_value(cookie_header)
        authentication = await self._access.authenticate(token)
        if authentication is None:
            raise ControlPlaneDurableSessionHttpRejectedError("session authentication rejected")
        grant = authentication.rotated_grant
        if grant is None:
            return ControlPlaneDurableSessionHttpAuthentication(authentication=authentication)
        csrf_token = _csrf_token(grant, origin)
        return ControlPlaneDurableSessionHttpAuthentication(
            authentication=authentication,
            rotated_csrf_token=csrf_token,
            response_headers=(
                ("Set-Cookie", self._set_cookie(grant)),
                ("X-Phoenix-CSRF", csrf_token.value),
                ("Cache-Control", "no-store"),
            ),
        )

    async def verify_csrf(
        self,
        token_value: str | None,
        authentication: ControlPlaneDurableSessionAuthentication,
        *,
        supplied_origin: ControlPlaneBrowserOrigin,
        expected_origin: ControlPlaneBrowserOrigin,
    ) -> ControlPlaneDurableSessionRecord:
        """Verify exact origin, session generation, and persisted CSRF digest in constant time."""

        try:
            if supplied_origin != expected_origin:
                raise ValueError("origin mismatch")
            token = ControlPlaneDurableSessionCsrfToken(token_value or "")
            session_id, generation, origin_digest, secret = _parse_csrf_token(token)
            expected_origin_digest = hashlib.sha256(
                expected_origin.value.encode("ascii")
            ).hexdigest()
            if not hmac.compare_digest(origin_digest, expected_origin_digest):
                raise ValueError("origin binding mismatch")
            if session_id != authentication.session_id or generation != authentication.generation:
                raise ValueError("session binding mismatch")
            record = await self._repository.get(session_id)
            if (
                record is None
                or record.status is not ControlPlaneDurableSessionStatus.ACTIVE
                or record.operator_id != authentication.operator_id
                or record.generation != authentication.generation
                or not hmac.compare_digest(
                    hashlib.sha256(secret.encode("ascii")).hexdigest(),
                    record.csrf_digest,
                )
            ):
                raise ValueError("CSRF evidence mismatch")
        except (TypeError, ValueError) as exception:
            raise ControlPlaneDurableSessionCsrfRejectedError(
                "durable session CSRF validation failed"
            ) from exception
        return record

    async def logout(self, cookie_header: str | None) -> tuple[bool, tuple[tuple[str, str], ...]]:
        """Persist logout and always clear the browser cookie without revealing lookup results."""

        token = self._cookie_value_or_none(cookie_header)
        changed = await self._access.logout(token)
        return changed, (
            ("Set-Cookie", self.clear_cookie()),
            ("Cache-Control", "no-store"),
        )

    def clear_cookie(self) -> str:
        attributes = [
            f"{self._cookie.name}=",
            f"Path={self._cookie.path}",
            "HttpOnly",
            "SameSite=Strict",
            "Max-Age=0",
            "Expires=Thu, 01 Jan 1970 00:00:00 GMT",
        ]
        if self._cookie.secure:
            attributes.append("Secure")
        return "; ".join(attributes)

    def _set_cookie(self, grant: ControlPlaneDurableSessionGrant) -> str:
        max_age = max(0, int((grant.absolute_expires_at - grant.issued_at).total_seconds()))
        attributes = [
            f"{self._cookie.name}={grant.token.value}",
            f"Path={self._cookie.path}",
            "HttpOnly",
            "SameSite=Strict",
            f"Max-Age={max_age}",
        ]
        if self._cookie.secure:
            attributes.append("Secure")
        return "; ".join(attributes)

    def _cookie_value(self, cookie_header: str | None) -> str:
        value = self._cookie_value_or_none(cookie_header)
        if value is None:
            raise ControlPlaneDurableSessionHttpRejectedError("session authentication rejected")
        return value

    def _cookie_value_or_none(self, cookie_header: str | None) -> str | None:
        if cookie_header is None:
            return None
        try:
            encoded = cookie_header.encode("ascii")
        except UnicodeEncodeError as exception:
            raise ControlPlaneDurableSessionHttpRejectedError(
                "session authentication rejected"
            ) from exception
        if not encoded or len(encoded) > MAX_DURABLE_SESSION_COOKIE_HEADER_BYTES:
            raise ControlPlaneDurableSessionHttpRejectedError("session authentication rejected")
        found: str | None = None
        for component in cookie_header.split(";"):
            part = component.strip()
            if not part or "=" not in part:
                raise ControlPlaneDurableSessionHttpRejectedError("session authentication rejected")
            name, value = part.split("=", 1)
            if name.strip() != name or not name:
                raise ControlPlaneDurableSessionHttpRejectedError("session authentication rejected")
            if name == self._cookie.name:
                if found is not None or not value:
                    raise ControlPlaneDurableSessionHttpRejectedError(
                        "session authentication rejected"
                    )
                found = value
        return found


def _csrf_token(
    grant: ControlPlaneDurableSessionGrant,
    origin: ControlPlaneBrowserOrigin,
) -> ControlPlaneDurableSessionCsrfToken:
    origin_digest = hashlib.sha256(origin.value.encode("ascii")).hexdigest()
    return ControlPlaneDurableSessionCsrfToken(
        f"v1.{grant.session_id.hex}.{grant.generation}.{origin_digest}.{grant.csrf_secret.value}"
    )


def _parse_csrf_token(
    token: ControlPlaneDurableSessionCsrfToken,
) -> tuple[UUID, int, str, str]:
    parts = token.value.split(".", 4)
    if len(parts) != 5 or parts[0] != "v1":
        raise ValueError("invalid CSRF token")
    session_id = UUID(hex=parts[1])
    if str(session_id).replace("-", "") != parts[1]:
        raise ValueError("noncanonical session id")
    generation = int(parts[2])
    if generation <= 0 or str(generation) != parts[2]:
        raise ValueError("invalid generation")
    origin_digest = parts[3]
    if _SHA256_PATTERN.fullmatch(origin_digest) is None:
        raise ValueError("invalid origin digest")
    secret = parts[4]
    if _CSRF_SECRET_PATTERN.fullmatch(secret) is None:
        raise ValueError("invalid CSRF secret")
    return session_id, generation, origin_digest, secret


def _authentication_from_grant(
    grant: ControlPlaneDurableSessionGrant,
    principal: object,
) -> ControlPlaneDurableSessionAuthentication:
    from phoenix_os.control_plane.auth import ControlPlanePrincipal

    if not isinstance(principal, ControlPlanePrincipal):
        raise TypeError("operator principal is invalid")
    return ControlPlaneDurableSessionAuthentication(
        session_id=grant.session_id,
        operator_id=grant.operator_id,
        principal=principal,
        generation=grant.generation,
        authenticated_at=grant.issued_at,
        absolute_expires_at=grant.absolute_expires_at,
        idle_expires_at=grant.idle_expires_at,
    )


def origin_from_loopback_url(value: str) -> ControlPlaneBrowserOrigin:
    """Normalize one exact HTTP loopback origin without accepting paths or credentials."""

    parsed = urlsplit(value)
    if parsed.scheme != "http" or parsed.username or parsed.password:
        raise ValueError("durable session origin must be an HTTP loopback origin")
    if parsed.path or parsed.query or parsed.fragment or parsed.port is None:
        raise ValueError("durable session origin must not contain a path, query, or fragment")
    return ControlPlaneBrowserOrigin(value)
