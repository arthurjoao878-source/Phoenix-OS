from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from phoenix_os.control_plane.errors import (
    ControlPlaneApiTokenAlreadyExistsError,
)
from phoenix_os.control_plane.service_account_contracts import (
    ControlPlaneApiToken,
    ControlPlaneApiTokenMetadata,
    ControlPlaneApiTokenStatus,
    ControlPlaneServiceAccountRecord,
)
from phoenix_os.control_plane.service_account_lifecycle import (
    ControlPlaneServiceAccountLifecycleService,
)
from phoenix_os.control_plane.service_account_memory import (
    InMemoryControlPlaneServiceAccountRepository,
)
from phoenix_os.control_plane.service_account_state import (
    StateControlPlaneServiceAccountRepository,
)
from phoenix_os.state import MemoryStateStore

_NOW = datetime(2026, 7, 20, 12, tzinfo=UTC)
_ACCOUNT_ID = UUID("10000000-0000-0000-0000-000000000001")
_TOKEN_ID = UUID("20000000-0000-0000-0000-000000000002")
_SUCCESSOR_ID = UUID("30000000-0000-0000-0000-000000000003")
_FIRST = ControlPlaneApiToken("phx_sa_" + ("A" * 48))
_SECOND = ControlPlaneApiToken("phx_sa_" + ("B" * 48))


def _account() -> ControlPlaneServiceAccountRecord:
    return ControlPlaneServiceAccountRecord(
        id=_ACCOUNT_ID,
        name="release.bot",
        display_name="Release Bot",
        created_at=_NOW,
        updated_at=_NOW,
    )


def _token() -> ControlPlaneApiTokenMetadata:
    return ControlPlaneApiTokenMetadata(
        id=_TOKEN_ID,
        service_account_id=_ACCOUNT_ID,
        label="Release Token",
        token_digest=_FIRST.digest,
        scopes=frozenset({"jobs.read"}),
        issued_at=_NOW,
        expires_at=_NOW + timedelta(days=30),
        updated_at=_NOW,
    )


@pytest.mark.parametrize(
    "kind",
    ["memory", "state"],
)
@pytest.mark.asyncio
async def test_repository_rotation_is_atomic(
    kind: str,
) -> None:
    repository = (
        InMemoryControlPlaneServiceAccountRepository()
        if kind == "memory"
        else StateControlPlaneServiceAccountRepository(MemoryStateStore())
    )

    account = _account()
    current = _token()
    rotated_at = _NOW + timedelta(minutes=1)

    predecessor = replace(
        current,
        status=ControlPlaneApiTokenStatus.REVOKED,
        revoked_at=rotated_at,
        updated_at=rotated_at,
        revision=2,
    )

    successor = ControlPlaneApiTokenMetadata(
        id=_SUCCESSOR_ID,
        service_account_id=_ACCOUNT_ID,
        label=current.label,
        token_digest=_SECOND.digest,
        scopes=current.scopes,
        resources=current.resources,
        restriction=current.restriction,
        issued_at=rotated_at,
        expires_at=rotated_at + timedelta(days=30),
        updated_at=rotated_at,
        rotated_from=current.id,
        token_version=2,
    )

    await repository.add_account(account)
    await repository.add_token(current)

    rotation = await repository.rotate_token(
        predecessor,
        successor,
        expected_revision=1,
    )

    assert rotation.predecessor == predecessor
    assert rotation.successor == successor
    assert await repository.get_token(current.id) == predecessor
    assert await repository.get_token(successor.id) == successor


@pytest.mark.parametrize(
    "kind",
    ["memory", "state"],
)
@pytest.mark.asyncio
async def test_failed_rotation_does_not_revoke_original(
    kind: str,
) -> None:
    repository = (
        InMemoryControlPlaneServiceAccountRepository()
        if kind == "memory"
        else StateControlPlaneServiceAccountRepository(MemoryStateStore())
    )

    current = _token()
    rotated_at = _NOW + timedelta(minutes=1)

    await repository.add_account(_account())
    await repository.add_token(current)

    duplicate = ControlPlaneApiTokenMetadata(
        id=_SUCCESSOR_ID,
        service_account_id=_ACCOUNT_ID,
        label="Existing",
        token_digest=_SECOND.digest,
        scopes=frozenset({"jobs.read"}),
        issued_at=_NOW + timedelta(seconds=1),
        expires_at=_NOW + timedelta(days=1),
        updated_at=_NOW + timedelta(seconds=1),
    )
    await repository.add_token(duplicate)

    predecessor = replace(
        current,
        status=ControlPlaneApiTokenStatus.REVOKED,
        revoked_at=rotated_at,
        updated_at=rotated_at,
        revision=2,
    )

    successor = replace(
        duplicate,
        id=UUID("40000000-0000-0000-0000-000000000004"),
        label=current.label,
        issued_at=rotated_at,
        expires_at=rotated_at + timedelta(days=1),
        updated_at=rotated_at,
        rotated_from=current.id,
        token_version=2,
    )

    with pytest.raises(ControlPlaneApiTokenAlreadyExistsError):
        await repository.rotate_token(
            predecessor,
            successor,
            expected_revision=1,
        )

    assert await repository.get_token(current.id) == current


@pytest.mark.asyncio
async def test_lifecycle_returns_only_successor_secret() -> None:
    repository = InMemoryControlPlaneServiceAccountRepository()

    token_values = iter(
        (
            _FIRST.value,
            _SECOND.value,
        )
    )
    token_ids = iter(
        (
            _TOKEN_ID,
            _SUCCESSOR_ID,
        )
    )
    now = [_NOW]

    service = ControlPlaneServiceAccountLifecycleService(
        repository=repository,
        clock=lambda: now[0],
        token_factory=lambda: next(token_values),
        account_id_factory=lambda: _ACCOUNT_ID,
        token_id_factory=lambda: next(token_ids),
    )

    account = await service.create_account(
        name="release.bot",
        display_name="Release Bot",
    )

    original = await service.issue_token(
        account.id,
        label="Release Token",
        scopes=frozenset({"jobs.read"}),
        expires_at=_NOW + timedelta(days=30),
    )

    now[0] += timedelta(minutes=1)

    successor = await service.rotate_token(
        original.metadata.id,
        expires_at=now[0] + timedelta(days=30),
    )

    assert successor.token.value == _SECOND.value
    assert successor.metadata.rotated_from == original.metadata.id
    assert successor.metadata.token_version == 2

    stored_original = await repository.get_token(original.metadata.id)

    assert stored_original is not None
    assert stored_original.status is ControlPlaneApiTokenStatus.REVOKED
    assert _FIRST.value not in repr(successor)
