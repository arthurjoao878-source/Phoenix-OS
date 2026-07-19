from __future__ import annotations

import json
from datetime import UTC, datetime
from http import HTTPStatus
from typing import cast
from uuid import uuid4

import pytest

from phoenix_os.control_plane.auth import ControlPlanePrincipal
from phoenix_os.control_plane.csrf import ControlPlaneBrowserOrigin, ControlPlaneCsrfProtector
from phoenix_os.control_plane.operator_api import ControlPlaneOperatorApi
from phoenix_os.control_plane.operator_authentication import ControlPlaneOperatorAuthenticator
from phoenix_os.control_plane.operator_contracts import (
    ControlPlaneOperatorRecord,
    ControlPlaneOperatorRole,
    ControlPlaneOperatorToken,
)
from phoenix_os.control_plane.operator_http import (
    ControlPlaneOperatorHttpAdapter,
    ControlPlaneOperatorSessionAuthenticator,
)
from phoenix_os.control_plane.operator_management import ControlPlaneOperatorManager
from phoenix_os.control_plane.operator_memory import InMemoryControlPlaneOperatorRegistry
from phoenix_os.control_plane.operator_sessions import (
    ControlPlaneOperatorAccessService,
    ControlPlaneOperatorLoginRateLimiter,
    InMemoryControlPlaneOperatorSessionStore,
)
from phoenix_os.events import EventBus

_NOW = datetime(2026, 7, 19, 21, tzinfo=UTC)
_ORIGIN = ControlPlaneBrowserOrigin("http://127.0.0.1:8080")
_MAINTAINER_TOKEN = ControlPlaneOperatorToken("operator-http-maintainer-0123456789abcdef")


class _Clock:
    def __call__(self) -> datetime:
        return _NOW


async def _adapter() -> tuple[
    ControlPlaneOperatorHttpAdapter,
    ControlPlaneOperatorAccessService,
    ControlPlanePrincipal,
    str,
]:
    registry = InMemoryControlPlaneOperatorRegistry()
    record = ControlPlaneOperatorRecord(
        id=uuid4(),
        username="maintainer",
        display_name="Maintainer",
        role=ControlPlaneOperatorRole.MAINTAINER,
        token_digest=_MAINTAINER_TOKEN.digest,
        created_at=_NOW,
        updated_at=_NOW,
    )
    await registry.add(record)
    events = EventBus()
    clock = _Clock()
    session_counter = iter(range(1, 100))
    access = ControlPlaneOperatorAccessService(
        registry=registry,
        authenticator=ControlPlaneOperatorAuthenticator(registry, clock=clock),
        sessions=InMemoryControlPlaneOperatorSessionStore(),
        rate_limiter=ControlPlaneOperatorLoginRateLimiter(),
        events=events,
        clock=clock,
        token_factory=lambda: f"operator-http-session-{next(session_counter):032d}",
    )
    csrf = ControlPlaneCsrfProtector(
        b"c" * 32,
        clock=clock,
        nonce_source=lambda size: b"n" * size,
    )
    api = ControlPlaneOperatorApi(
        registry=registry,
        manager=ControlPlaneOperatorManager(registry, clock=clock),
        access=access,
        events=events,
        clock=clock,
    )
    adapter = ControlPlaneOperatorHttpAdapter(api=api, access=access, csrf=csrf)
    grant = await access.login(f"Bearer {_MAINTAINER_TOKEN.value}")
    principal = record.principal()
    csrf_value = csrf.issue(principal, _ORIGIN).value
    return adapter, access, principal, grant.token.value + "|" + csrf_value


def _headers(session_token: str, csrf: str) -> dict[str, tuple[str, ...]]:
    return {
        "authorization": (f"Bearer {session_token}",),
        "origin": (_ORIGIN.value,),
        "x-phoenix-csrf": (csrf,),
    }


def _body(value: object) -> bytes:
    return json.dumps(value).encode()


@pytest.mark.asyncio
async def test_public_login_exchanges_long_lived_credential_for_session() -> None:
    adapter, _, _, _ = await _adapter()

    status, payload, headers = await adapter.dispatch_public(
        method="POST",
        authorization=f"Bearer {_MAINTAINER_TOKEN.value}",
        body=b"",
        query={},
    )

    assert status is HTTPStatus.OK
    assert payload["username"] == "maintainer"
    assert isinstance(payload["session_token"], str)
    assert _MAINTAINER_TOKEN.value not in repr(payload)
    assert headers["Cache-Control"] == "no-store"


@pytest.mark.asyncio
async def test_public_login_uses_generic_unauthorized_response() -> None:
    adapter, _, _, _ = await _adapter()

    status, payload, headers = await adapter.dispatch_public(
        method="POST",
        authorization="Bearer unknown-credential-0123456789abcdef",
        body=b"",
        query={},
    )

    assert status is HTTPStatus.UNAUTHORIZED
    assert payload == {"error": "unauthorized"}
    assert "Bearer" in headers["WWW-Authenticate"]


@pytest.mark.asyncio
async def test_session_authenticator_returns_identified_principal() -> None:
    _, access, _, packed = await _adapter()
    session_token, _ = packed.split("|", 1)

    principal = await ControlPlaneOperatorSessionAuthenticator(access).authenticate(
        f"Bearer {session_token}"
    )

    assert principal is not None
    assert principal.name == "maintainer"
    assert "control-plane.operators.create" in principal.permissions


@pytest.mark.asyncio
async def test_me_route_returns_only_current_identity_and_permissions() -> None:
    adapter, _, principal, packed = await _adapter()
    session_token, _ = packed.split("|", 1)

    status, payload, _ = await adapter.dispatch(
        principal=principal,
        authorization=f"Bearer {session_token}",
        method="GET",
        path="/v1/control-plane/operator/me",
        query={},
        headers={"authorization": (f"Bearer {session_token}",)},
        body=b"",
        server_origin=_ORIGIN,
    )

    assert status is HTTPStatus.OK
    assert payload["username"] == "maintainer"
    permissions = cast(list[str], payload["permissions"])
    assert "control-plane.read" in permissions
    assert "operator_id" not in payload


@pytest.mark.asyncio
async def test_operator_create_requires_csrf() -> None:
    adapter, _, principal, packed = await _adapter()
    session_token, _ = packed.split("|", 1)

    status, payload, _ = await adapter.dispatch(
        principal=principal,
        authorization=f"Bearer {session_token}",
        method="POST",
        path="/v1/control-plane/operators",
        query={},
        headers={"authorization": (f"Bearer {session_token}",)},
        body=_body(
            {
                "username": "alice",
                "display_name": "Alice",
                "role": "viewer",
            }
        ),
        server_origin=_ORIGIN,
    )

    assert status is HTTPStatus.FORBIDDEN
    assert payload == {"error": "request_rejected"}


@pytest.mark.asyncio
async def test_operator_create_returns_one_time_generated_credential() -> None:
    adapter, _, principal, packed = await _adapter()
    session_token, csrf = packed.split("|", 1)

    status, payload, headers = await adapter.dispatch(
        principal=principal,
        authorization=f"Bearer {session_token}",
        method="POST",
        path="/v1/control-plane/operators",
        query={},
        headers=_headers(session_token, csrf),
        body=_body(
            {
                "username": "alice",
                "display_name": "Alice Viewer",
                "role": "viewer",
            }
        ),
        server_origin=_ORIGIN,
    )

    assert status is HTTPStatus.CREATED
    assert payload["username"] == "alice"
    assert len(str(payload["token"])) >= 32
    assert "token_digest" not in payload
    assert headers["Cache-Control"] == "no-store"


@pytest.mark.asyncio
async def test_operator_list_is_paginated_and_digest_free() -> None:
    adapter, _, principal, packed = await _adapter()
    session_token, _ = packed.split("|", 1)

    status, payload, _ = await adapter.dispatch(
        principal=principal,
        authorization=f"Bearer {session_token}",
        method="GET",
        path="/v1/control-plane/operators",
        query={"limit": ("10",)},
        headers={"authorization": (f"Bearer {session_token}",)},
        body=b"",
        server_origin=_ORIGIN,
    )

    assert status is HTTPStatus.OK
    page = cast(dict[str, object], payload["page"])
    items = cast(list[dict[str, object]], payload["items"])
    assert page["total"] == 1
    assert items[0]["username"] == "maintainer"
    assert "token_digest" not in repr(payload)


@pytest.mark.asyncio
async def test_operator_lifecycle_route_uses_revision_and_safe_receipt() -> None:
    adapter, _, principal, packed = await _adapter()
    session_token, csrf = packed.split("|", 1)
    create_status, created, _ = await adapter.dispatch(
        principal=principal,
        authorization=f"Bearer {session_token}",
        method="POST",
        path="/v1/control-plane/operators",
        query={},
        headers=_headers(session_token, csrf),
        body=_body(
            {
                "username": "alice",
                "display_name": "Alice",
                "role": "viewer",
            }
        ),
        server_origin=_ORIGIN,
    )
    assert create_status is HTTPStatus.CREATED

    status, payload, _ = await adapter.dispatch(
        principal=principal,
        authorization=f"Bearer {session_token}",
        method="POST",
        path=f"/v1/control-plane/operators/{created['operator_id']}/disable",
        query={},
        headers=_headers(session_token, csrf),
        body=_body({"expected_revision": created["revision"]}),
        server_origin=_ORIGIN,
    )

    assert status is HTTPStatus.OK
    assert payload["status"] == "disabled"
    assert payload["result_code"] == "operator.disabled"
    assert "token" not in payload


@pytest.mark.asyncio
async def test_logout_revokes_current_session() -> None:
    adapter, access, principal, packed = await _adapter()
    session_token, _ = packed.split("|", 1)

    status, payload, _ = await adapter.dispatch(
        principal=principal,
        authorization=f"Bearer {session_token}",
        method="POST",
        path="/v1/control-plane/operator/logout",
        query={},
        headers={"authorization": (f"Bearer {session_token}",)},
        body=b"",
        server_origin=_ORIGIN,
    )

    assert status is HTTPStatus.OK
    assert payload["logged_out"] is True
    assert await access.authenticate(f"Bearer {session_token}") is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("method", "body", "query"),
    [
        ("GET", b"", {}),
        ("POST", b"{}", {}),
        ("POST", b"", {"x": ("1",)}),
    ],
)
async def test_public_login_rejects_noncanonical_request_shape(
    method: str,
    body: bytes,
    query: dict[str, tuple[str, ...]],
) -> None:
    adapter, _, _, _ = await _adapter()
    status, payload, _ = await adapter.dispatch_public(
        method=method,
        authorization=f"Bearer {_MAINTAINER_TOKEN.value}",
        body=body,
        query=query,
    )
    assert status is HTTPStatus.BAD_REQUEST
    assert payload == {"error": "invalid_request"}
