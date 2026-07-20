from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from phoenix_os.control_plane import (
    CONTROL_PLANE_READ_PERMISSION,
    ControlPlaneBrowserOrigin,
    ControlPlaneCsrfProtector,
    ControlPlaneCsrfRejectedError,
    ControlPlaneCsrfToken,
    ControlPlanePrincipal,
)

_NOW = datetime(2026, 7, 19, 4, 0, tzinfo=UTC)
_SECRET = b"c" * 32
_ORIGIN = ControlPlaneBrowserOrigin("http://127.0.0.1:8765")
_PRINCIPAL = ControlPlanePrincipal("operator", frozenset({CONTROL_PLANE_READ_PERMISSION}))


class _Clock:
    def __init__(self, value: datetime = _NOW) -> None:
        self.value = value

    def __call__(self) -> datetime:
        return self.value


def _nonce(size: int) -> bytes:
    assert size == 32
    return b"n" * size


@pytest.mark.parametrize(
    ("raw", "canonical"),
    [
        ("http://127.0.0.1", "http://127.0.0.1"),
        ("http://127.0.0.1:8765", "http://127.0.0.1:8765"),
        ("http://[::1]", "http://[::1]"),
        ("http://[0:0:0:0:0:0:0:1]:8765", "http://[::1]:8765"),
        ("https://Admin.Example.com:443", "https://admin.example.com"),
        ("https://[2001:db8::1]:8443", "https://[2001:db8::1]:8443"),
    ],
)
def test_browser_origin_accepts_and_canonicalizes_loopback(raw: str, canonical: str) -> None:
    assert str(ControlPlaneBrowserOrigin(raw)) == canonical


@pytest.mark.parametrize(
    "raw",
    [
        "http://localhost:8765",
        "http://192.168.1.10:8765",
        "http://127.0.0.1:8765/",
        "http://127.0.0.1:8765/path",
        "http://127.0.0.1:8765?query=1",
        "http://user@127.0.0.1:8765",
        " http://127.0.0.1:8765",
        "http://127.0.0.1:0",
        "http://127.0.0.1:99999",
        "https://example.com/path",
        "https://user@example.com",
    ],
)
def test_browser_origin_rejects_non_exact_loopback_origins(raw: str) -> None:
    with pytest.raises(ValueError, match="origin"):
        ControlPlaneBrowserOrigin(raw)


def test_browser_origin_reports_secure_and_loopback_facts() -> None:
    remote = ControlPlaneBrowserOrigin("https://admin.example.com")
    local = ControlPlaneBrowserOrigin("http://127.0.0.1:8765")

    assert remote.secure
    assert not remote.loopback
    assert not local.secure
    assert local.loopback


def test_csrf_token_redacts_representation_and_has_stable_digest() -> None:
    protector = ControlPlaneCsrfProtector(
        _SECRET,
        clock=lambda: _NOW,
        nonce_source=_nonce,
    )
    token = protector.issue(_PRINCIPAL, _ORIGIN)

    assert token.digest == ControlPlaneCsrfToken(token.value).digest
    assert token.value not in repr(token)
    assert token.value not in str(token)


@pytest.mark.parametrize("secret", [b"short", b"x" * 129])
def test_csrf_protector_rejects_unsafe_secret_sizes(secret: bytes) -> None:
    with pytest.raises(ValueError, match="secret"):
        ControlPlaneCsrfProtector(secret)


@pytest.mark.parametrize(
    "ttl",
    [timedelta(0), timedelta(seconds=-1), timedelta(hours=1, seconds=1)],
)
def test_csrf_protector_rejects_unsafe_ttl(ttl: timedelta) -> None:
    with pytest.raises(ValueError, match="TTL"):
        ControlPlaneCsrfProtector(_SECRET, ttl=ttl)


def test_csrf_protector_issues_and_verifies_exact_binding() -> None:
    protector = ControlPlaneCsrfProtector(
        _SECRET,
        clock=lambda: _NOW,
        nonce_source=_nonce,
    )
    token = protector.issue(_PRINCIPAL, _ORIGIN)

    verification = protector.verify(token, _PRINCIPAL, _ORIGIN)

    assert verification.principal == "operator"
    assert verification.origin == _ORIGIN
    assert verification.issued_at == _NOW
    assert verification.expires_at == _NOW + timedelta(minutes=10)


def test_csrf_protector_rejects_other_principal() -> None:
    protector = ControlPlaneCsrfProtector(
        _SECRET,
        clock=lambda: _NOW,
        nonce_source=_nonce,
    )
    token = protector.issue(_PRINCIPAL, _ORIGIN)

    with pytest.raises(ControlPlaneCsrfRejectedError, match="validation failed"):
        protector.verify(token, ControlPlanePrincipal("other"), _ORIGIN)


def test_csrf_protector_rejects_other_origin() -> None:
    protector = ControlPlaneCsrfProtector(
        _SECRET,
        clock=lambda: _NOW,
        nonce_source=_nonce,
    )
    token = protector.issue(_PRINCIPAL, _ORIGIN)

    with pytest.raises(ControlPlaneCsrfRejectedError, match="validation failed"):
        protector.verify(
            token,
            _PRINCIPAL,
            ControlPlaneBrowserOrigin("http://127.0.0.1:9999"),
        )


def test_csrf_protector_rejects_other_secret() -> None:
    issuer = ControlPlaneCsrfProtector(_SECRET, clock=lambda: _NOW, nonce_source=_nonce)
    verifier = ControlPlaneCsrfProtector(b"d" * 32, clock=lambda: _NOW)

    with pytest.raises(ControlPlaneCsrfRejectedError, match="validation failed"):
        verifier.verify(issuer.issue(_PRINCIPAL, _ORIGIN), _PRINCIPAL, _ORIGIN)


def test_csrf_protector_rejects_tampered_signature() -> None:
    protector = ControlPlaneCsrfProtector(
        _SECRET,
        clock=lambda: _NOW,
        nonce_source=_nonce,
    )
    token = protector.issue(_PRINCIPAL, _ORIGIN)
    replacement = "A" if token.value[-1] != "A" else "B"
    tampered = ControlPlaneCsrfToken(token.value[:-1] + replacement)

    with pytest.raises(ControlPlaneCsrfRejectedError, match="validation failed"):
        protector.verify(tampered, _PRINCIPAL, _ORIGIN)


def test_csrf_protector_rejects_expired_token() -> None:
    clock = _Clock()
    protector = ControlPlaneCsrfProtector(
        _SECRET,
        ttl=timedelta(seconds=30),
        clock=clock,
        nonce_source=_nonce,
    )
    token = protector.issue(_PRINCIPAL, _ORIGIN)
    clock.value = _NOW + timedelta(seconds=30)

    with pytest.raises(ControlPlaneCsrfRejectedError, match="validation failed"):
        protector.verify(token, _PRINCIPAL, _ORIGIN)


def test_csrf_protector_allows_small_future_clock_skew() -> None:
    issuer = ControlPlaneCsrfProtector(
        _SECRET,
        clock=lambda: _NOW + timedelta(seconds=4),
        nonce_source=_nonce,
    )
    verifier = ControlPlaneCsrfProtector(_SECRET, clock=lambda: _NOW)

    verification = verifier.verify(issuer.issue(_PRINCIPAL, _ORIGIN), _PRINCIPAL, _ORIGIN)

    assert verification.issued_at == _NOW + timedelta(seconds=4)


def test_csrf_protector_rejects_large_future_clock_skew() -> None:
    issuer = ControlPlaneCsrfProtector(
        _SECRET,
        clock=lambda: _NOW + timedelta(seconds=6),
        nonce_source=_nonce,
    )
    verifier = ControlPlaneCsrfProtector(_SECRET, clock=lambda: _NOW)

    with pytest.raises(ControlPlaneCsrfRejectedError, match="validation failed"):
        verifier.verify(issuer.issue(_PRINCIPAL, _ORIGIN), _PRINCIPAL, _ORIGIN)


def test_csrf_protector_rejects_naive_clock() -> None:
    protector = ControlPlaneCsrfProtector(
        _SECRET,
        clock=lambda: datetime(2026, 7, 19, 4, 0),
        nonce_source=_nonce,
    )

    with pytest.raises(ValueError, match="timezone-aware"):
        protector.issue(_PRINCIPAL, _ORIGIN)


def test_csrf_protector_rejects_invalid_nonce_source() -> None:
    protector = ControlPlaneCsrfProtector(
        _SECRET,
        clock=lambda: _NOW,
        nonce_source=lambda _: b"short",
    )

    with pytest.raises(ValueError, match="exactly 32 bytes"):
        protector.issue(_PRINCIPAL, _ORIGIN)
