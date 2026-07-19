from __future__ import annotations

import asyncio
import hashlib
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest

from phoenix_os.control_plane.errors import (
    ControlPlaneOperatorAlreadyExistsError,
    ControlPlaneOperatorConflictError,
    ControlPlaneOperatorNotFoundError,
    ControlPlaneOperatorStateError,
)
from phoenix_os.control_plane.operator_authentication import ControlPlaneOperatorAuthenticator
from phoenix_os.control_plane.operator_contracts import (
    CONTROL_PLANE_OPERATORS_REVOKE_PERMISSION,
    ControlPlaneOperatorRecord,
    ControlPlaneOperatorRole,
    ControlPlaneOperatorStatus,
    ControlPlaneOperatorToken,
)
from phoenix_os.control_plane.operator_management import (
    ControlPlaneOperatorManager,
    ControlPlaneOperatorMutationAction,
    ControlPlaneOperatorMutationReceipt,
)
from phoenix_os.control_plane.operator_memory import InMemoryControlPlaneOperatorRegistry

_NOW = datetime(2026, 7, 19, 17, tzinfo=UTC)
_LATER = _NOW + timedelta(minutes=1)
_TOKEN = ControlPlaneOperatorToken("alice-token-0123456789abcdef-manager")
_ROTATED = ControlPlaneOperatorToken("alice-rotated-0123456789abcdef-manager")
_OTHER = ControlPlaneOperatorToken("other-token-0123456789abcdef-manager")


def _record(
    username: str = "alice",
    *,
    operator_id: UUID | None = None,
    token: ControlPlaneOperatorToken = _TOKEN,
    status: ControlPlaneOperatorStatus = ControlPlaneOperatorStatus.ACTIVE,
    disabled_at: datetime | None = None,
    revoked_at: datetime | None = None,
    updated_at: datetime = _NOW,
    revision: int = 1,
    token_version: int = 1,
) -> ControlPlaneOperatorRecord:
    return ControlPlaneOperatorRecord(
        id=operator_id or uuid4(),
        username=username,
        display_name=username.title(),
        role=ControlPlaneOperatorRole.MAINTAINER,
        token_digest=token.digest,
        created_at=_NOW,
        updated_at=updated_at,
        status=status,
        disabled_at=disabled_at,
        revoked_at=revoked_at,
        revision=revision,
        token_version=token_version,
    )


@pytest.mark.parametrize(
    ("action", "result_code"),
    [
        (ControlPlaneOperatorMutationAction.ROTATE_CREDENTIAL, "operator.credential-rotated"),
        (ControlPlaneOperatorMutationAction.DISABLE, "operator.disabled"),
        (ControlPlaneOperatorMutationAction.REACTIVATE, "operator.reactivated"),
        (ControlPlaneOperatorMutationAction.REVOKE, "operator.revoked"),
    ],
)
def test_mutation_actions_have_allowlisted_result_codes(
    action: ControlPlaneOperatorMutationAction,
    result_code: str,
) -> None:
    assert action.result_code == result_code


@pytest.mark.asyncio
async def test_manager_rotates_credential_atomically() -> None:
    registry = InMemoryControlPlaneOperatorRegistry()
    record = _record()
    await registry.add(record)
    manager = ControlPlaneOperatorManager(registry, clock=lambda: _LATER)

    receipt = await manager.rotate_credential(record.id, _ROTATED, expected_revision=1)
    updated = await registry.get(record.id)

    assert updated is not None
    assert updated.token_digest == _ROTATED.digest
    assert updated.token_version == 2
    assert updated.revision == 2
    assert updated.updated_at == _LATER
    assert updated.status is ControlPlaneOperatorStatus.ACTIVE
    assert await registry.get_by_token_digest(_TOKEN.digest) is None
    assert await registry.get_by_token_digest(_ROTATED.digest) == updated
    assert receipt == ControlPlaneOperatorMutationReceipt(
        operator_id=record.id,
        username="alice",
        action=ControlPlaneOperatorMutationAction.ROTATE_CREDENTIAL,
        status=ControlPlaneOperatorStatus.ACTIVE,
        token_version=2,
        revision=2,
        changed_at=_LATER,
        result_code="operator.credential-rotated",
    )
    assert _ROTATED.value not in repr(receipt)
    assert _ROTATED.digest not in repr(receipt)


@pytest.mark.asyncio
async def test_rotation_invalidates_old_authentication_and_accepts_new_token() -> None:
    registry = InMemoryControlPlaneOperatorRegistry()
    record = _record()
    await registry.add(record)
    authenticator = ControlPlaneOperatorAuthenticator(registry, clock=lambda: _LATER)
    manager = ControlPlaneOperatorManager(registry, clock=lambda: _LATER)

    assert await authenticator.authenticate(f"Bearer {_TOKEN.value}") is not None
    await manager.rotate_credential(record.id, _ROTATED, expected_revision=1)
    assert await authenticator.authenticate(f"Bearer {_TOKEN.value}") is None
    current = await authenticator.authenticate(f"Bearer {_ROTATED.value}")
    assert current is not None
    assert current.operator_id == record.id
    assert current.token_version == 2


@pytest.mark.asyncio
async def test_manager_can_rotate_disabled_operator_without_reactivating() -> None:
    registry = InMemoryControlPlaneOperatorRegistry()
    record = _record(
        status=ControlPlaneOperatorStatus.DISABLED,
        disabled_at=_NOW,
    )
    await registry.add(record)
    receipt = await ControlPlaneOperatorManager(
        registry,
        clock=lambda: _LATER,
    ).rotate_credential(record.id, _ROTATED, expected_revision=1)
    updated = await registry.get(record.id)
    assert updated is not None
    assert updated.status is ControlPlaneOperatorStatus.DISABLED
    assert updated.disabled_at == _NOW
    assert receipt.status is ControlPlaneOperatorStatus.DISABLED


@pytest.mark.asyncio
async def test_manager_rejects_rotation_for_revoked_operator() -> None:
    registry = InMemoryControlPlaneOperatorRegistry()
    record = _record(status=ControlPlaneOperatorStatus.REVOKED, revoked_at=_NOW)
    await registry.add(record)
    with pytest.raises(ControlPlaneOperatorStateError, match="revoked"):
        await ControlPlaneOperatorManager(
            registry,
            clock=lambda: _LATER,
        ).rotate_credential(record.id, _ROTATED, expected_revision=1)


@pytest.mark.asyncio
async def test_manager_rejects_reusing_current_credential() -> None:
    registry = InMemoryControlPlaneOperatorRegistry()
    record = _record()
    await registry.add(record)
    with pytest.raises(ControlPlaneOperatorStateError, match="different"):
        await ControlPlaneOperatorManager(
            registry,
            clock=lambda: _LATER,
        ).rotate_credential(record.id, _TOKEN, expected_revision=1)


@pytest.mark.asyncio
async def test_manager_rejects_duplicate_credential_owned_by_another_operator() -> None:
    registry = InMemoryControlPlaneOperatorRegistry()
    alice = _record()
    bob = _record("bob", token=_OTHER)
    await registry.add(alice)
    await registry.add(bob)
    with pytest.raises(ControlPlaneOperatorAlreadyExistsError, match="digest"):
        await ControlPlaneOperatorManager(
            registry,
            clock=lambda: _LATER,
        ).rotate_credential(alice.id, _OTHER, expected_revision=1)


@pytest.mark.asyncio
async def test_manager_propagates_stale_rotation_revision() -> None:
    registry = InMemoryControlPlaneOperatorRegistry()
    record = _record()
    await registry.add(record)
    with pytest.raises(ControlPlaneOperatorConflictError, match="revision"):
        await ControlPlaneOperatorManager(
            registry,
            clock=lambda: _LATER,
        ).rotate_credential(record.id, _ROTATED, expected_revision=2)


@pytest.mark.asyncio
async def test_manager_disables_active_operator() -> None:
    registry = InMemoryControlPlaneOperatorRegistry()
    record = _record()
    await registry.add(record)
    receipt = await ControlPlaneOperatorManager(
        registry,
        clock=lambda: _LATER,
    ).disable(record.id, expected_revision=1)
    updated = await registry.get(record.id)
    assert updated is not None
    assert updated.status is ControlPlaneOperatorStatus.DISABLED
    assert updated.disabled_at == _LATER
    assert updated.revoked_at is None
    assert updated.revision == 2
    assert updated.token_version == 1
    assert receipt.result_code == "operator.disabled"
    assert (
        await ControlPlaneOperatorAuthenticator(
            registry,
            clock=lambda: _LATER,
        ).authenticate(f"Bearer {_TOKEN.value}")
        is None
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status", "disabled_at", "revoked_at"),
    [
        (ControlPlaneOperatorStatus.DISABLED, _NOW, None),
        (ControlPlaneOperatorStatus.REVOKED, None, _NOW),
    ],
)
async def test_manager_rejects_disabling_inactive_operator(
    status: ControlPlaneOperatorStatus,
    disabled_at: datetime | None,
    revoked_at: datetime | None,
) -> None:
    registry = InMemoryControlPlaneOperatorRegistry()
    record = _record(status=status, disabled_at=disabled_at, revoked_at=revoked_at)
    await registry.add(record)
    with pytest.raises(ControlPlaneOperatorStateError, match="active"):
        await ControlPlaneOperatorManager(
            registry,
            clock=lambda: _LATER,
        ).disable(record.id, expected_revision=1)


@pytest.mark.asyncio
async def test_manager_reactivates_disabled_operator() -> None:
    registry = InMemoryControlPlaneOperatorRegistry()
    record = _record(status=ControlPlaneOperatorStatus.DISABLED, disabled_at=_NOW)
    await registry.add(record)
    receipt = await ControlPlaneOperatorManager(
        registry,
        clock=lambda: _LATER,
    ).reactivate(record.id, expected_revision=1)
    updated = await registry.get(record.id)
    assert updated is not None
    assert updated.status is ControlPlaneOperatorStatus.ACTIVE
    assert updated.disabled_at is None
    assert updated.revoked_at is None
    assert receipt.result_code == "operator.reactivated"
    assert (
        await ControlPlaneOperatorAuthenticator(
            registry,
            clock=lambda: _LATER,
        ).authenticate(f"Bearer {_TOKEN.value}")
        is not None
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status", "revoked_at"),
    [
        (ControlPlaneOperatorStatus.ACTIVE, None),
        (ControlPlaneOperatorStatus.REVOKED, _NOW),
    ],
)
async def test_manager_rejects_reactivation_except_from_disabled(
    status: ControlPlaneOperatorStatus,
    revoked_at: datetime | None,
) -> None:
    registry = InMemoryControlPlaneOperatorRegistry()
    record = _record(status=status, revoked_at=revoked_at)
    await registry.add(record)
    with pytest.raises(ControlPlaneOperatorStateError, match="disabled"):
        await ControlPlaneOperatorManager(
            registry,
            clock=lambda: _LATER,
        ).reactivate(record.id, expected_revision=1)


@pytest.mark.asyncio
async def test_manager_revokes_active_operator_terminally() -> None:
    registry = InMemoryControlPlaneOperatorRegistry()
    record = _record()
    await registry.add(record)
    receipt = await ControlPlaneOperatorManager(
        registry,
        clock=lambda: _LATER,
    ).revoke(record.id, expected_revision=1)
    updated = await registry.get(record.id)
    assert updated is not None
    assert updated.status is ControlPlaneOperatorStatus.REVOKED
    assert updated.revoked_at == _LATER
    assert updated.disabled_at is None
    assert receipt.result_code == "operator.revoked"
    assert (
        await ControlPlaneOperatorAuthenticator(
            registry,
            clock=lambda: _LATER,
        ).authenticate(f"Bearer {_TOKEN.value}")
        is None
    )
    with pytest.raises(ControlPlaneOperatorStateError):
        await ControlPlaneOperatorManager(
            registry,
            clock=lambda: _LATER,
        ).reactivate(record.id, expected_revision=2)


@pytest.mark.asyncio
async def test_manager_revokes_disabled_operator_and_preserves_disable_time() -> None:
    registry = InMemoryControlPlaneOperatorRegistry()
    record = _record(status=ControlPlaneOperatorStatus.DISABLED, disabled_at=_NOW)
    await registry.add(record)
    await ControlPlaneOperatorManager(
        registry,
        clock=lambda: _LATER,
    ).revoke(record.id, expected_revision=1)
    updated = await registry.get(record.id)
    assert updated is not None
    assert updated.status is ControlPlaneOperatorStatus.REVOKED
    assert updated.disabled_at == _NOW
    assert updated.revoked_at == _LATER


@pytest.mark.asyncio
async def test_manager_rejects_repeated_revocation() -> None:
    registry = InMemoryControlPlaneOperatorRegistry()
    record = _record(status=ControlPlaneOperatorStatus.REVOKED, revoked_at=_NOW)
    await registry.add(record)
    with pytest.raises(ControlPlaneOperatorStateError, match="already"):
        await ControlPlaneOperatorManager(
            registry,
            clock=lambda: _LATER,
        ).revoke(record.id, expected_revision=1)


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["rotate", "disable", "reactivate", "revoke"])
async def test_manager_rejects_unknown_operator(operation: str) -> None:
    manager = ControlPlaneOperatorManager(
        InMemoryControlPlaneOperatorRegistry(),
        clock=lambda: _LATER,
    )
    operator_id = uuid4()
    with pytest.raises(ControlPlaneOperatorNotFoundError):
        if operation == "rotate":
            await manager.rotate_credential(operator_id, _ROTATED, expected_revision=1)
        elif operation == "disable":
            await manager.disable(operator_id, expected_revision=1)
        elif operation == "reactivate":
            await manager.reactivate(operator_id, expected_revision=1)
        else:
            await manager.revoke(operator_id, expected_revision=1)


@pytest.mark.asyncio
async def test_manager_rejects_naive_clock() -> None:
    registry = InMemoryControlPlaneOperatorRegistry()
    record = _record()
    await registry.add(record)
    manager = ControlPlaneOperatorManager(
        registry,
        clock=lambda: datetime(2026, 7, 19, 18),
    )
    with pytest.raises(ValueError, match="timezone-aware"):
        await manager.disable(record.id, expected_revision=1)


@pytest.mark.asyncio
async def test_manager_rejects_backwards_clock() -> None:
    registry = InMemoryControlPlaneOperatorRegistry()
    record = _record(updated_at=_LATER)
    await registry.add(record)
    manager = ControlPlaneOperatorManager(registry, clock=lambda: _NOW)
    with pytest.raises(ControlPlaneOperatorConflictError, match="backwards"):
        await manager.disable(record.id, expected_revision=1)


@pytest.mark.asyncio
async def test_concurrent_status_mutations_commit_only_once() -> None:
    registry = InMemoryControlPlaneOperatorRegistry()
    record = _record()
    await registry.add(record)
    manager = ControlPlaneOperatorManager(registry, clock=lambda: _LATER)
    results = await asyncio.gather(
        manager.disable(record.id, expected_revision=1),
        manager.revoke(record.id, expected_revision=1),
        return_exceptions=True,
    )
    assert sum(isinstance(result, ControlPlaneOperatorMutationReceipt) for result in results) == 1
    assert sum(isinstance(result, ControlPlaneOperatorConflictError) for result in results) == 1
    current = await registry.get(record.id)
    assert current is not None
    assert current.revision == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("expected_revision", [0, -1])
async def test_manager_requires_positive_expected_revision(expected_revision: int) -> None:
    registry = InMemoryControlPlaneOperatorRegistry()
    record = _record()
    await registry.add(record)
    manager = ControlPlaneOperatorManager(registry, clock=lambda: _LATER)
    with pytest.raises(ValueError, match="expected_revision"):
        await manager.disable(record.id, expected_revision=expected_revision)


def test_manager_requires_callable_clock() -> None:
    registry = InMemoryControlPlaneOperatorRegistry()
    with pytest.raises(TypeError, match="clock"):
        ControlPlaneOperatorManager(registry, clock=None)  # type: ignore[arg-type]


def test_maintainer_role_includes_operator_revocation_permission() -> None:
    assert (
        CONTROL_PLANE_OPERATORS_REVOKE_PERMISSION in ControlPlaneOperatorRole.MAINTAINER.permissions
    )


@pytest.mark.parametrize(
    "kwargs",
    [
        {"username": " "},
        {"token_version": 0},
        {"revision": 0},
        {"changed_at": datetime(2026, 7, 19, 17)},
        {"result_code": "operator.wrong"},
        {"status": ControlPlaneOperatorStatus.ACTIVE},
        {"schema_version": 2},
    ],
)
def test_mutation_receipt_rejects_invalid_fields(kwargs: dict[str, object]) -> None:
    values: dict[str, object] = {
        "operator_id": uuid4(),
        "username": "alice",
        "action": ControlPlaneOperatorMutationAction.DISABLE,
        "status": ControlPlaneOperatorStatus.DISABLED,
        "token_version": 1,
        "revision": 2,
        "changed_at": _LATER,
        "result_code": "operator.disabled",
    }
    values.update(kwargs)
    with pytest.raises(ValueError):
        ControlPlaneOperatorMutationReceipt(**values)  # type: ignore[arg-type]


def test_mutation_receipt_normalizes_username_and_enum_values() -> None:
    receipt = ControlPlaneOperatorMutationReceipt(
        operator_id=uuid4(),
        username=" Alice ",
        action=ControlPlaneOperatorMutationAction.DISABLE,
        status=ControlPlaneOperatorStatus.DISABLED,
        token_version=1,
        revision=2,
        changed_at=_LATER,
        result_code="operator.disabled",
    )
    assert receipt.username == "alice"


def test_rotation_tokens_have_distinct_digests() -> None:
    assert hashlib.sha256(_TOKEN.value.encode("ascii")).hexdigest() != _ROTATED.digest
