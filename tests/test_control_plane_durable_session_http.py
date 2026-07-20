from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from phoenix_os.control_plane.csrf import ControlPlaneBrowserOrigin
from phoenix_os.control_plane.durable_session_access import ControlPlaneDurableSessionAccessService
from phoenix_os.control_plane.durable_session_contracts import (
    ControlPlaneDurableSessionPolicy,
    ControlPlaneDurableSessionStatus,
)
from phoenix_os.control_plane.durable_session_http import (
    ControlPlaneDurableSessionCookiePolicy,
    ControlPlaneDurableSessionCsrfToken,
    ControlPlaneDurableSessionHttpBoundary,
    origin_from_loopback_url,
    origin_from_public_origin,
)
from phoenix_os.control_plane.durable_session_memory import (
    InMemoryControlPlaneDurableSessionRepository,
)
from phoenix_os.control_plane.errors import (
    ControlPlaneDurableSessionCsrfRejectedError,
    ControlPlaneDurableSessionHttpRejectedError,
)
from phoenix_os.control_plane.network_contracts import ControlPlanePublicOrigin
from phoenix_os.control_plane.operator_authentication import ControlPlaneOperatorAuthenticator
from phoenix_os.control_plane.operator_contracts import (
    ControlPlaneOperatorRecord,
    ControlPlaneOperatorRole,
    ControlPlaneOperatorToken,
)
from phoenix_os.control_plane.operator_memory import InMemoryControlPlaneOperatorRegistry

NOW = datetime(2026, 7, 19, 19, 0, tzinfo=UTC)
ORIGIN = ControlPlaneBrowserOrigin("http://127.0.0.1:8080")
OTHER_ORIGIN = ControlPlaneBrowserOrigin("http://127.0.0.1:8081")
OPERATOR_ID = UUID(int=810)
OPERATOR_TOKEN = ControlPlaneOperatorToken("durable-http-operator-token-0123456789abcdef")
POLICY = ControlPlaneDurableSessionPolicy(
    absolute_ttl=timedelta(hours=1),
    idle_ttl=timedelta(minutes=20),
    rotation_interval=timedelta(minutes=10),
)


class _Clock:
    def __init__(self) -> None:
        self.now = NOW

    def __call__(self) -> datetime:
        return self.now


class _Secrets:
    def __init__(self, prefix: str) -> None:
        self.prefix = prefix
        self.counter = 0

    def __call__(self) -> str:
        self.counter += 1
        return f"{self.prefix}-{self.counter:048d}"


async def _boundary(
    *,
    cookie_policy: ControlPlaneDurableSessionCookiePolicy | None = None,
    public_origin: ControlPlanePublicOrigin | str | None = None,
) -> tuple[
    ControlPlaneDurableSessionHttpBoundary,
    InMemoryControlPlaneDurableSessionRepository,
    _Clock,
]:
    registry = InMemoryControlPlaneOperatorRegistry()
    await registry.add(
        ControlPlaneOperatorRecord(
            id=OPERATOR_ID,
            username="alice",
            display_name="Alice",
            role=ControlPlaneOperatorRole.MAINTAINER,
            token_digest=OPERATOR_TOKEN.digest,
            created_at=NOW,
            updated_at=NOW,
        )
    )
    repository = InMemoryControlPlaneDurableSessionRepository()
    clock = _Clock()
    access = ControlPlaneDurableSessionAccessService(
        registry=registry,
        repository=repository,
        policy=POLICY,
        clock=clock,
        token_factory=_Secrets("session"),
        csrf_factory=_Secrets("csrf"),
    )
    boundary = ControlPlaneDurableSessionHttpBoundary(
        authenticator=ControlPlaneOperatorAuthenticator(registry, clock=clock),
        access=access,
        repository=repository,
        cookie_policy=cookie_policy,
        public_origin=public_origin,
    )
    return boundary, repository, clock


def _header(headers: tuple[tuple[str, str], ...], name: str) -> str:
    values = [value for key, value in headers if key == name]
    assert len(values) == 1
    return values[0]


def _cookie_value(set_cookie: str, name: str = "phoenix_session") -> str:
    first = set_cookie.split(";", 1)[0]
    cookie_name, value = first.split("=", 1)
    assert cookie_name == name
    return value


@pytest.mark.parametrize(
    "kwargs",
    [
        {"name": "bad cookie"},
        {"path": "/dashboard"},
        {"same_site": "Lax"},
        {"http_only": False},
        {"schema_version": 2},
    ],
)
def test_cookie_policy_rejects_unsafe_configuration(kwargs: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        ControlPlaneDurableSessionCookiePolicy(**kwargs)  # type: ignore[arg-type]


def test_cookie_policy_tracks_public_origin_scheme() -> None:
    local = ControlPlaneDurableSessionCookiePolicy.for_public_origin("http://127.0.0.1:8080")
    remote = ControlPlaneDurableSessionCookiePolicy.for_public_origin("https://admin.example.com")

    assert not local.secure
    assert remote.secure
    local.validate_for_origin("http://127.0.0.1:8080")
    remote.validate_for_origin("https://admin.example.com")
    with pytest.raises(ValueError, match="Secure"):
        local.validate_for_origin("https://admin.example.com")


@pytest.mark.asyncio
async def test_bound_https_origin_requires_secure_cookie_policy() -> None:
    with pytest.raises(ValueError, match="Secure"):
        await _boundary(public_origin="https://admin.example.com")


@pytest.mark.asyncio
async def test_bound_https_origin_issues_secure_cookie_without_repeating_origin() -> None:
    boundary, _, _ = await _boundary(
        cookie_policy=ControlPlaneDurableSessionCookiePolicy(secure=True),
        public_origin="https://admin.example.com:8443",
    )

    login = await boundary.login(f"Bearer {OPERATOR_TOKEN.value}")

    assert boundary.public_origin == ControlPlaneBrowserOrigin("https://admin.example.com:8443")
    assert "Secure" in _header(login.response_headers, "Set-Cookie")
    with pytest.raises(ControlPlaneDurableSessionHttpRejectedError, match="origin"):
        await boundary.login(
            f"Bearer {OPERATOR_TOKEN.value}",
            origin=ControlPlaneBrowserOrigin("https://other.example.com"),
        )


@pytest.mark.asyncio
async def test_bound_https_csrf_rejects_another_public_origin() -> None:
    origin = ControlPlaneBrowserOrigin("https://admin.example.com")
    boundary, _, _ = await _boundary(
        cookie_policy=ControlPlaneDurableSessionCookiePolicy(secure=True),
        public_origin=origin.value,
    )
    login = await boundary.login(f"Bearer {OPERATOR_TOKEN.value}")

    with pytest.raises(ControlPlaneDurableSessionCsrfRejectedError):
        await boundary.verify_csrf(
            login.csrf_token.value,
            login.authentication,
            supplied_origin=ControlPlaneBrowserOrigin("https://other.example.com"),
            expected_origin=origin,
        )


def test_csrf_token_is_redacted() -> None:
    token = ControlPlaneDurableSessionCsrfToken("x" * 32)

    assert str(token) == "<redacted>"
    assert repr(token) == "ControlPlaneDurableSessionCsrfToken(<redacted>)"
    assert token.value not in repr(token)


@pytest.mark.asyncio
async def test_login_uses_http_only_strict_host_cookie_and_browser_csrf_header() -> None:
    boundary, repository, _ = await _boundary()

    login = await boundary.login(f"Bearer {OPERATOR_TOKEN.value}", origin=ORIGIN)

    set_cookie = _header(login.response_headers, "Set-Cookie")
    assert "Path=/" in set_cookie
    assert "HttpOnly" in set_cookie
    assert "SameSite=Strict" in set_cookie
    assert "Max-Age=3600" in set_cookie
    assert "Domain=" not in set_cookie
    assert "Secure" not in set_cookie
    assert _header(login.response_headers, "X-Phoenix-CSRF") == login.csrf_token.value
    assert _header(login.response_headers, "Cache-Control") == "no-store"
    assert login.authentication.principal.name == "alice"
    record = await repository.get(login.authentication.session_id)
    assert record is not None
    assert record.token_digest not in repr(login)
    assert _cookie_value(set_cookie) not in repr(login)


@pytest.mark.asyncio
async def test_secure_cookie_policy_appends_secure_without_domain() -> None:
    boundary, _, _ = await _boundary(
        cookie_policy=ControlPlaneDurableSessionCookiePolicy(secure=True)
    )

    login = await boundary.login(f"Bearer {OPERATOR_TOKEN.value}", origin=ORIGIN)
    set_cookie = _header(login.response_headers, "Set-Cookie")

    assert "Secure" in set_cookie
    assert "Domain=" not in set_cookie


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "authorization",
    [None, "", "Basic value", "Bearer unknown-credential-0123456789abcdef"],
)
async def test_login_uses_one_generic_rejection(authorization: str | None) -> None:
    boundary, _, _ = await _boundary()

    with pytest.raises(ControlPlaneDurableSessionHttpRejectedError) as captured:
        await boundary.login(authorization, origin=ORIGIN)

    assert str(captured.value) == "operator login rejected"


@pytest.mark.asyncio
async def test_cookie_authentication_returns_no_replacement_before_rotation() -> None:
    boundary, _, clock = await _boundary()
    login = await boundary.login(f"Bearer {OPERATOR_TOKEN.value}", origin=ORIGIN)
    cookie = _cookie_value(_header(login.response_headers, "Set-Cookie"))
    clock.now += timedelta(minutes=5)

    result = await boundary.authenticate(f"other=1; phoenix_session={cookie}", origin=ORIGIN)

    assert result.authentication.session_id == login.authentication.session_id
    assert not result.authentication.rotated
    assert result.rotated_csrf_token is None
    assert result.response_headers == ()


@pytest.mark.asyncio
async def test_due_cookie_authentication_rotates_token_and_csrf_together() -> None:
    boundary, repository, clock = await _boundary()
    login = await boundary.login(f"Bearer {OPERATOR_TOKEN.value}", origin=ORIGIN)
    old_cookie = _cookie_value(_header(login.response_headers, "Set-Cookie"))
    clock.now += timedelta(minutes=10)

    result = await boundary.authenticate(f"phoenix_session={old_cookie}", origin=ORIGIN)

    assert result.authentication.rotated
    assert result.rotated_csrf_token is not None
    replacement = _cookie_value(_header(result.response_headers, "Set-Cookie"))
    assert replacement != old_cookie
    assert _header(result.response_headers, "X-Phoenix-CSRF") == (result.rotated_csrf_token.value)
    old_record = await repository.get(login.authentication.session_id)
    assert old_record is not None
    assert old_record.status is ControlPlaneDurableSessionStatus.ROTATED
    assert result.authentication.session_id != login.authentication.session_id

    with pytest.raises(ControlPlaneDurableSessionHttpRejectedError):
        await boundary.authenticate(f"phoenix_session={old_cookie}", origin=ORIGIN)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "cookie_header",
    [
        None,
        "",
        "flag",
        "phoenix_session=",
        "phoenix_session=a; phoenix_session=b",
        " phoenix_session=value",
        "x=" + "a" * 5000,
        "phoenix_session=válido",
    ],
)
async def test_cookie_parser_fails_closed(cookie_header: str | None) -> None:
    boundary, _, _ = await _boundary()

    with pytest.raises(ControlPlaneDurableSessionHttpRejectedError):
        await boundary.authenticate(cookie_header, origin=ORIGIN)


@pytest.mark.asyncio
async def test_session_bound_csrf_verifies_exact_session_generation_origin_and_digest() -> None:
    boundary, _, _ = await _boundary()
    login = await boundary.login(f"Bearer {OPERATOR_TOKEN.value}", origin=ORIGIN)

    record = await boundary.verify_csrf(
        login.csrf_token.value,
        login.authentication,
        supplied_origin=ORIGIN,
        expected_origin=ORIGIN,
    )

    assert record.id == login.authentication.session_id


@pytest.mark.asyncio
@pytest.mark.parametrize("mutation", ["origin", "secret", "session", "generation", "format"])
async def test_session_bound_csrf_rejects_every_binding_mismatch(mutation: str) -> None:
    boundary, _, _ = await _boundary()
    login = await boundary.login(f"Bearer {OPERATOR_TOKEN.value}", origin=ORIGIN)
    token = login.csrf_token.value
    supplied_origin = ORIGIN
    if mutation == "origin":
        supplied_origin = OTHER_ORIGIN
    elif mutation == "secret":
        token = token[:-1] + ("A" if token[-1] != "A" else "B")
    elif mutation == "session":
        parts = token.split(".", 4)
        parts[1] = UUID(int=999).hex
        token = ".".join(parts)
    elif mutation == "generation":
        parts = token.split(".", 4)
        parts[2] = "2"
        token = ".".join(parts)
    else:
        token = "invalid"

    with pytest.raises(ControlPlaneDurableSessionCsrfRejectedError):
        await boundary.verify_csrf(
            token,
            login.authentication,
            supplied_origin=supplied_origin,
            expected_origin=ORIGIN,
        )


@pytest.mark.asyncio
async def test_rotated_csrf_invalidates_previous_generation() -> None:
    boundary, _, clock = await _boundary()
    login = await boundary.login(f"Bearer {OPERATOR_TOKEN.value}", origin=ORIGIN)
    old_cookie = _cookie_value(_header(login.response_headers, "Set-Cookie"))
    clock.now += timedelta(minutes=10)
    rotated = await boundary.authenticate(f"phoenix_session={old_cookie}", origin=ORIGIN)
    assert rotated.rotated_csrf_token is not None

    with pytest.raises(ControlPlaneDurableSessionCsrfRejectedError):
        await boundary.verify_csrf(
            login.csrf_token.value,
            rotated.authentication,
            supplied_origin=ORIGIN,
            expected_origin=ORIGIN,
        )
    record = await boundary.verify_csrf(
        rotated.rotated_csrf_token.value,
        rotated.authentication,
        supplied_origin=ORIGIN,
        expected_origin=ORIGIN,
    )
    assert record.id == rotated.authentication.session_id


@pytest.mark.asyncio
async def test_logout_persists_revocation_and_always_clears_cookie() -> None:
    boundary, repository, _ = await _boundary()
    login = await boundary.login(f"Bearer {OPERATOR_TOKEN.value}", origin=ORIGIN)
    cookie = _cookie_value(_header(login.response_headers, "Set-Cookie"))

    changed, headers = await boundary.logout(f"phoenix_session={cookie}")

    assert changed
    clear = _header(headers, "Set-Cookie")
    assert "Max-Age=0" in clear
    assert "HttpOnly" in clear
    assert "SameSite=Strict" in clear
    record = await repository.get(login.authentication.session_id)
    assert record is not None
    assert record.status is ControlPlaneDurableSessionStatus.REVOKED

    changed_again, second_headers = await boundary.logout(f"phoenix_session={cookie}")
    assert not changed_again
    assert _header(second_headers, "Set-Cookie") == clear


@pytest.mark.parametrize(
    "value",
    [
        "http://127.0.0.1:8080",
        "http://[::1]:8080",
    ],
)
def test_origin_helper_accepts_exact_loopback_origins(value: str) -> None:
    assert origin_from_loopback_url(value).value == value


@pytest.mark.parametrize(
    "value",
    [
        "https://127.0.0.1:8080",
        "http://127.0.0.1",
        "http://user@127.0.0.1:8080",
        "http://127.0.0.1:8080/path",
        "http://example.com:8080",
    ],
)
def test_origin_helper_rejects_non_exact_loopback_origins(value: str) -> None:
    with pytest.raises(ValueError):
        origin_from_loopback_url(value)


def test_public_origin_helper_accepts_https_and_normalizes_default_port() -> None:
    assert origin_from_public_origin("https://Admin.Example.com:443").value == (
        "https://admin.example.com"
    )


def test_public_origin_helper_rejects_non_loopback_http() -> None:
    with pytest.raises(ValueError, match="loopback"):
        origin_from_public_origin("http://192.0.2.10:8080")
