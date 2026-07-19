from __future__ import annotations

import pytest

from phoenix_os.control_plane import (
    AdminTokenAuthenticator,
    ControlPlanePrincipal,
)

_TOKEN = "a" * 32


def test_control_plane_principal_normalizes_name_and_permissions() -> None:
    principal = ControlPlanePrincipal(
        " dashboard ",
        frozenset({" control-plane.read ", "audit.read"}),
    )

    assert principal.name == "dashboard"
    assert principal.permissions == frozenset({"control-plane.read", "audit.read"})


def test_control_plane_principal_requires_read_permission() -> None:
    with pytest.raises(ValueError, match=r"requires control-plane\.read"):
        ControlPlanePrincipal("dashboard", frozenset({"audit.read"}))


@pytest.mark.parametrize(
    "token, message",
    [
        ("short", "at least 32"),
        (" " + _TOKEN, "surrounding whitespace"),
        (_TOKEN + " ", "surrounding whitespace"),
        ("á" * 32, "ASCII"),
    ],
)
def test_admin_token_authenticator_rejects_unsafe_tokens(token: str, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        AdminTokenAuthenticator(token)


def test_admin_token_authenticator_accepts_exact_bearer_token() -> None:
    authenticator = AdminTokenAuthenticator(_TOKEN)

    principal = authenticator.authenticate(f"bEaReR {_TOKEN}")

    assert principal is authenticator.principal
    assert principal is not None
    assert principal.name == "phoenix.dashboard"


@pytest.mark.parametrize(
    "authorization",
    [
        None,
        "",
        _TOKEN,
        f"Basic {_TOKEN}",
        "Bearer wrong",
        f"Bearer  {_TOKEN}",
        f"Bearer {_TOKEN} ",
        "Bearer " + ("á" * 32),
    ],
)
def test_admin_token_authenticator_rejects_invalid_authorization(
    authorization: str | None,
) -> None:
    authenticator = AdminTokenAuthenticator(_TOKEN)

    assert authenticator.authenticate(authorization) is None
