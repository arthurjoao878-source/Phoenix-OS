from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from phoenix_os.control_plane.auth import ControlPlanePrincipal
from phoenix_os.control_plane.errors import (
    ControlPlaneOperatorAlreadyExistsError,
    ControlPlaneOperatorConflictError,
    ControlPlaneOperatorPermissionDeniedError,
    ControlPlaneOperatorStateError,
)
from phoenix_os.control_plane.operator_api import (
    ControlPlaneOperatorApi,
    ControlPlaneOperatorCredentialGrant,
    ControlPlaneOperatorView,
)
from phoenix_os.control_plane.operator_authentication import ControlPlaneOperatorAuthenticator
from phoenix_os.control_plane.operator_contracts import (
    ControlPlaneOperatorPageRequest,
    ControlPlaneOperatorRecord,
    ControlPlaneOperatorRole,
    ControlPlaneOperatorStatus,
    ControlPlaneOperatorToken,
)
from phoenix_os.control_plane.operator_management import ControlPlaneOperatorManager
from phoenix_os.control_plane.operator_memory import InMemoryControlPlaneOperatorRegistry
from phoenix_os.control_plane.operator_sessions import (
    ControlPlaneOperatorAccessService,
    ControlPlaneOperatorLoginRateLimiter,
    InMemoryControlPlaneOperatorSessionStore,
)
from phoenix_os.control_plane.serialization import (
    operator_credential_grant_to_dict,
    operator_view_to_dict,
)
from phoenix_os.events import Event, EventBus

_NOW = datetime(2026, 7, 19, 20, tzinfo=UTC)
_MAINTAINER = ControlPlanePrincipal(
    "maintainer",
    ControlPlaneOperatorRole.MAINTAINER.permissions,
)
_TOKEN = ControlPlaneOperatorToken("operator-api-token-0123456789abcdef")
_NEW_TOKEN = ControlPlaneOperatorToken("operator-api-token-fedcba9876543210")


class _Clock:
    def __init__(self, value: datetime = _NOW) -> None:
        self.value = value

    def __call__(self) -> datetime:
        return self.value


async def _stack(
    *,
    capacity: int = 100,
) -> tuple[
    InMemoryControlPlaneOperatorRegistry,
    ControlPlaneOperatorAccessService,
    ControlPlaneOperatorApi,
    EventBus,
]:
    registry = InMemoryControlPlaneOperatorRegistry(capacity=capacity)
    events = EventBus()
    clock = _Clock()
    access = ControlPlaneOperatorAccessService(
        registry=registry,
        authenticator=ControlPlaneOperatorAuthenticator(registry, clock=clock),
        sessions=InMemoryControlPlaneOperatorSessionStore(),
        rate_limiter=ControlPlaneOperatorLoginRateLimiter(),
        events=events,
        clock=clock,
        token_factory=lambda: "session-token-0123456789abcdef0123456789",
    )
    api = ControlPlaneOperatorApi(
        registry=registry,
        manager=ControlPlaneOperatorManager(registry, clock=clock),
        access=access,
        events=events,
        clock=clock,
    )
    return registry, access, api, events


async def _record(
    registry: InMemoryControlPlaneOperatorRegistry,
    *,
    username: str = "alice",
    token: ControlPlaneOperatorToken = _TOKEN,
    role: ControlPlaneOperatorRole = ControlPlaneOperatorRole.OPERATOR,
) -> ControlPlaneOperatorRecord:
    record = ControlPlaneOperatorRecord(
        id=uuid4(),
        username=username,
        display_name=username.title(),
        role=role,
        token_digest=token.digest,
        created_at=_NOW,
        updated_at=_NOW,
    )
    await registry.add(record)
    return record


@pytest.mark.asyncio
async def test_create_operator_returns_one_time_credential_and_safe_view() -> None:
    registry, _, api, _ = await _stack()

    grant = await api.create_operator(
        _MAINTAINER,
        username="alice",
        display_name="Alice Operator",
        role=ControlPlaneOperatorRole.OPERATOR,
        token=_TOKEN,
    )

    assert isinstance(grant, ControlPlaneOperatorCredentialGrant)
    assert grant.operator.username == "alice"
    assert grant.token is _TOKEN
    assert _TOKEN.value not in repr(grant)
    stored = await registry.get(grant.operator.operator_id)
    assert stored is not None
    assert stored.token_digest == _TOKEN.digest
    assert _TOKEN.value not in repr(stored)


@pytest.mark.asyncio
async def test_operator_serializers_are_allowlisted_and_credential_free_except_grant() -> None:
    _, _, api, _ = await _stack()
    grant = await api.create_operator(
        _MAINTAINER,
        username="alice",
        display_name="Alice Operator",
        role=ControlPlaneOperatorRole.VIEWER,
        token=_TOKEN,
    )

    view_payload = operator_view_to_dict(grant.operator)
    grant_payload = operator_credential_grant_to_dict(grant)

    assert "token_digest" not in view_payload
    assert "token" not in view_payload
    assert _TOKEN.digest not in repr(view_payload)
    assert grant_payload["token"] == _TOKEN.value
    assert "token_digest" not in grant_payload


@pytest.mark.asyncio
async def test_list_operators_requires_exact_read_permission() -> None:
    _, _, api, _ = await _stack()
    viewer = ControlPlanePrincipal("viewer")

    with pytest.raises(ControlPlaneOperatorPermissionDeniedError):
        await api.list_operators(viewer)


@pytest.mark.asyncio
async def test_list_operators_returns_deterministic_safe_page() -> None:
    registry, _, api, _ = await _stack()
    await _record(registry, username="zoe")
    await _record(
        registry,
        username="alice",
        token=ControlPlaneOperatorToken("alice-api-token-0123456789abcdef"),
    )

    page = await api.list_operators(
        _MAINTAINER,
        ControlPlaneOperatorPageRequest(limit=10),
    )

    assert [item.username for item in page.items] == ["alice", "zoe"]
    assert all(isinstance(item, ControlPlaneOperatorView) for item in page.items)
    assert page.page.total == 2


@pytest.mark.asyncio
async def test_create_operator_rejects_duplicate_username() -> None:
    registry, _, api, _ = await _stack()
    await _record(registry)

    with pytest.raises(ControlPlaneOperatorAlreadyExistsError):
        await api.create_operator(
            _MAINTAINER,
            username="ALICE",
            display_name="Duplicate",
            role=ControlPlaneOperatorRole.VIEWER,
            token=_NEW_TOKEN,
        )


@pytest.mark.asyncio
async def test_update_operator_changes_role_and_additive_permissions() -> None:
    registry, _, api, _ = await _stack()
    record = await _record(registry)

    view = await api.update_operator(
        _MAINTAINER,
        record.id,
        expected_revision=1,
        display_name="Alice Maintainer",
        role=ControlPlaneOperatorRole.MAINTAINER,
        additional_permissions=frozenset({"audit.read"}),
    )

    assert view.display_name == "Alice Maintainer"
    assert view.role is ControlPlaneOperatorRole.MAINTAINER
    assert "audit.read" in view.effective_permissions
    assert view.revision == 2


@pytest.mark.asyncio
async def test_update_operator_uses_optimistic_revision() -> None:
    registry, _, api, _ = await _stack()
    record = await _record(registry)

    with pytest.raises(ControlPlaneOperatorConflictError, match="revision"):
        await api.update_operator(
            _MAINTAINER,
            record.id,
            expected_revision=2,
            display_name="Alice",
            role=record.role,
        )


@pytest.mark.asyncio
async def test_rotate_credential_invalidates_existing_sessions() -> None:
    registry, access, api, _ = await _stack()
    record = await _record(registry)
    session = await access.login(f"Bearer {_TOKEN.value}")

    grant = await api.rotate_credential(
        _MAINTAINER,
        record.id,
        _NEW_TOKEN,
        expected_revision=1,
    )

    assert grant.result_code == "operator.credential-rotated"
    assert grant.operator.token_version == 2
    assert await access.authenticate(f"Bearer {session.token.value}") is None
    assert (
        await ControlPlaneOperatorAuthenticator(registry).authenticate(f"Bearer {_NEW_TOKEN.value}")
        is not None
    )


@pytest.mark.asyncio
async def test_rotate_permission_does_not_require_separate_session_revoke_grant() -> None:
    registry, access, api, _ = await _stack()
    record = await _record(registry)
    session = await access.login(f"Bearer {_TOKEN.value}")
    credential_rotator = ControlPlanePrincipal(
        "credential-rotator",
        frozenset({"control-plane.read", "control-plane.operators.rotate"}),
    )

    grant = await api.rotate_credential(
        credential_rotator,
        record.id,
        _NEW_TOKEN,
        expected_revision=1,
    )

    assert grant.operator.token_version == 2
    assert await access.authenticate(f"Bearer {session.token.value}") is None


@pytest.mark.asyncio
async def test_disable_operator_revokes_sessions_and_reactivation_is_explicit() -> None:
    registry, access, api, _ = await _stack()
    record = await _record(registry)
    session = await access.login(f"Bearer {_TOKEN.value}")

    disabled = await api.disable(_MAINTAINER, record.id, expected_revision=1)
    assert disabled.status is ControlPlaneOperatorStatus.DISABLED
    assert await access.authenticate(f"Bearer {session.token.value}") is None

    active = await api.reactivate(_MAINTAINER, record.id, expected_revision=2)
    assert active.status is ControlPlaneOperatorStatus.ACTIVE


@pytest.mark.asyncio
async def test_revoke_operator_is_terminal() -> None:
    registry, _, api, _ = await _stack()
    record = await _record(registry)

    receipt = await api.revoke(_MAINTAINER, record.id, expected_revision=1)

    assert receipt.status is ControlPlaneOperatorStatus.REVOKED
    with pytest.raises(ControlPlaneOperatorStateError):
        await api.reactivate(_MAINTAINER, record.id, expected_revision=2)


@pytest.mark.asyncio
async def test_revoked_operator_profile_is_immutable() -> None:
    registry, _, api, _ = await _stack()
    record = await _record(registry)
    await api.revoke(_MAINTAINER, record.id, expected_revision=1)

    with pytest.raises(ControlPlaneOperatorStateError, match="revoked"):
        await api.update_operator(
            _MAINTAINER,
            record.id,
            expected_revision=2,
            display_name="Rewritten Identity",
            role=ControlPlaneOperatorRole.VIEWER,
        )


@pytest.mark.asyncio
async def test_management_events_do_not_contain_credentials_or_digests() -> None:
    _, _, api, events = await _stack()
    captured: list[Event] = []
    await events.subscribe("*", captured.append)

    await api.create_operator(
        _MAINTAINER,
        username="alice",
        display_name="Alice",
        role=ControlPlaneOperatorRole.VIEWER,
        token=_TOKEN,
    )

    serialized = repr([dict(event.payload) for event in captured])
    assert _TOKEN.value not in serialized
    assert _TOKEN.digest not in serialized
    assert captured[-1].name == "control-plane.operator.management.created"


@pytest.mark.asyncio
async def test_create_operator_permission_is_not_implied_by_read_permission() -> None:
    _, _, api, _ = await _stack()
    reader = ControlPlanePrincipal(
        "reader",
        frozenset({"control-plane.read", "control-plane.operators.read"}),
    )

    with pytest.raises(ControlPlaneOperatorPermissionDeniedError):
        await api.create_operator(
            reader,
            username="alice",
            display_name="Alice",
            role=ControlPlaneOperatorRole.VIEWER,
            token=_TOKEN,
        )
