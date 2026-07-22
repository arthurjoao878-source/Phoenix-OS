from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from phoenix_os.control_plane.service_account_contracts import (
    MAX_CONTROL_PLANE_API_TOKEN_ROTATION_OVERLAP,
    ControlPlaneApiTokenStatus,
    ControlPlaneServiceAccountRepository,
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

_NOW = datetime(
    2026,
    7,
    20,
    12,
    tzinfo=UTC,
)
_ACCOUNT_ID = UUID("10000000-0000-0000-0000-000000000001")
_ORIGINAL_TOKEN_ID = UUID("20000000-0000-0000-0000-000000000002")
_SUCCESSOR_TOKEN_ID = UUID("30000000-0000-0000-0000-000000000003")
_ORIGINAL_TOKEN = "phx_sa_" + ("A" * 48)
_SUCCESSOR_TOKEN = "phx_sa_" + ("B" * 48)


def _repository(
    kind: str,
) -> ControlPlaneServiceAccountRepository:
    if kind == "memory":
        return InMemoryControlPlaneServiceAccountRepository()

    if kind == "state":
        return StateControlPlaneServiceAccountRepository(MemoryStateStore())

    raise AssertionError(f"unknown repository kind: {kind}")


def _service(
    repository: ControlPlaneServiceAccountRepository,
    now: list[datetime],
) -> ControlPlaneServiceAccountLifecycleService:
    token_ids = iter(
        (
            _ORIGINAL_TOKEN_ID,
            _SUCCESSOR_TOKEN_ID,
        )
    )
    token_values = iter(
        (
            _ORIGINAL_TOKEN,
            _SUCCESSOR_TOKEN,
        )
    )

    return ControlPlaneServiceAccountLifecycleService(
        repository=repository,
        clock=lambda: now[0],
        token_factory=lambda: next(token_values),
        account_id_factory=lambda: _ACCOUNT_ID,
        token_id_factory=lambda: next(token_ids),
    )


@pytest.mark.parametrize(
    "kind",
    ["memory", "state"],
)
@pytest.mark.asyncio
async def test_overlap_keeps_predecessor_active_until_deadline(
    kind: str,
) -> None:
    repository = _repository(kind)
    now = [_NOW]
    service = _service(repository, now)

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

    now[0] += timedelta(hours=1)
    overlap = timedelta(minutes=15)

    successor = await service.rotate_token(
        original.metadata.id,
        expires_at=now[0] + timedelta(days=30),
        overlap=overlap,
    )

    predecessor = await repository.get_token(original.metadata.id)

    assert predecessor is not None
    assert predecessor.status is ControlPlaneApiTokenStatus.ACTIVE
    assert predecessor.revoked_at is None
    assert predecessor.expires_at == now[0] + overlap
    assert predecessor.updated_at == now[0]
    assert predecessor.revision == 2

    assert predecessor.authenticatable_at(now[0] + timedelta(minutes=14))
    assert not predecessor.authenticatable_at(now[0] + overlap)

    assert successor.metadata.rotated_from == predecessor.id
    assert successor.metadata.token_version == 2


@pytest.mark.parametrize(
    "kind",
    ["memory", "state"],
)
@pytest.mark.asyncio
async def test_overlap_never_extends_original_expiration(
    kind: str,
) -> None:
    repository = _repository(kind)
    now = [_NOW]
    service = _service(repository, now)

    account = await service.create_account(
        name="release.bot",
        display_name="Release Bot",
    )
    original_expiration = _NOW + timedelta(minutes=10)

    original = await service.issue_token(
        account.id,
        label="Short Token",
        scopes=frozenset({"jobs.read"}),
        expires_at=original_expiration,
    )

    now[0] += timedelta(minutes=5)

    await service.rotate_token(
        original.metadata.id,
        expires_at=now[0] + timedelta(days=1),
        overlap=timedelta(minutes=15),
    )

    predecessor = await repository.get_token(original.metadata.id)

    assert predecessor is not None
    assert predecessor.expires_at == original_expiration
    assert predecessor.status is ControlPlaneApiTokenStatus.ACTIVE


@pytest.mark.asyncio
async def test_overlap_bounds_are_enforced() -> None:
    repository = _repository("memory")
    now = [_NOW]
    service = _service(repository, now)

    account = await service.create_account(
        name="release.bot",
        display_name="Release Bot",
    )
    original = await service.issue_token(
        account.id,
        label="Release Token",
        scopes=frozenset({"jobs.read"}),
        expires_at=_NOW + timedelta(days=2),
    )

    with pytest.raises(
        ValueError,
        match="negative",
    ):
        await service.rotate_token(
            original.metadata.id,
            expires_at=_NOW + timedelta(days=2),
            overlap=timedelta(seconds=-1),
        )

    with pytest.raises(
        ValueError,
        match="maximum",
    ):
        await service.rotate_token(
            original.metadata.id,
            expires_at=_NOW + timedelta(days=2),
            overlap=(MAX_CONTROL_PLANE_API_TOKEN_ROTATION_OVERLAP + timedelta(seconds=1)),
        )


@pytest.mark.asyncio
async def test_state_restart_preserves_overlap_deadline() -> None:
    store = MemoryStateStore()
    repository = StateControlPlaneServiceAccountRepository(store)
    now = [_NOW]
    service = _service(repository, now)

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
    overlap_deadline = now[0] + timedelta(minutes=10)

    await service.rotate_token(
        original.metadata.id,
        expires_at=now[0] + timedelta(days=30),
        overlap=timedelta(minutes=10),
    )

    recovered = StateControlPlaneServiceAccountRepository(store)
    predecessor = await recovered.get_token(original.metadata.id)

    assert predecessor is not None
    assert predecessor.status is ControlPlaneApiTokenStatus.ACTIVE
    assert predecessor.expires_at == overlap_deadline
    assert predecessor.revision == 2
