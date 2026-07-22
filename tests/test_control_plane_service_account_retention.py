from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from phoenix_os.control_plane.errors import (
    ControlPlaneApiTokenConflictError,
    ControlPlaneApiTokenNotFoundError,
    ControlPlaneServiceAccountNotFoundError,
)
from phoenix_os.control_plane.service_account_contracts import (
    MAX_CONTROL_PLANE_API_TOKENS_PER_ACCOUNT,
    ControlPlaneApiTokenStatus,
    ControlPlaneServiceAccountRecord,
    ControlPlaneServiceAccountRepository,
)
from phoenix_os.control_plane.service_account_lifecycle import (
    ControlPlaneApiTokenGrant,
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
_UNKNOWN_ACCOUNT_ID = UUID("10000000-0000-0000-0000-000000000099")

_TOKEN_IDS = tuple(UUID(f"20000000-0000-0000-0000-{index:012d}") for index in range(1, 13))

_TOKEN_VALUES = tuple("phx_sa_" + (character * 48) for character in "ABCDEFGHIJKL")


def _repository(
    kind: str,
    *,
    store: MemoryStateStore | None = None,
) -> ControlPlaneServiceAccountRepository:
    if kind == "memory":
        return InMemoryControlPlaneServiceAccountRepository(max_tokens_per_account=12)

    if kind == "state":
        return StateControlPlaneServiceAccountRepository(
            store or MemoryStateStore(),
            max_tokens_per_account=12,
        )

    raise AssertionError(f"unknown repository kind: {kind}")


def _service(
    repository: ControlPlaneServiceAccountRepository,
    now: list[datetime],
) -> ControlPlaneServiceAccountLifecycleService:
    token_ids = iter(_TOKEN_IDS)
    token_values = iter(_TOKEN_VALUES)

    return ControlPlaneServiceAccountLifecycleService(
        repository=repository,
        clock=lambda: now[0],
        token_factory=lambda: next(token_values),
        account_id_factory=lambda: _ACCOUNT_ID,
        token_id_factory=lambda: next(token_ids),
    )


async def _create_account(
    service: ControlPlaneServiceAccountLifecycleService,
) -> ControlPlaneServiceAccountRecord:
    return await service.create_account(
        name="release.bot",
        display_name="Release Bot",
    )


async def _issue_and_revoke(
    service: ControlPlaneServiceAccountLifecycleService,
    account_id: UUID,
    now: list[datetime],
    *,
    label: str,
) -> ControlPlaneApiTokenGrant:
    grant = await service.issue_token(
        account_id,
        label=label,
        scopes=frozenset({"jobs.read"}),
        expires_at=now[0] + timedelta(days=1),
    )

    now[0] += timedelta(minutes=1)

    assert await service.revoke_token(grant.metadata.id)

    return grant


@pytest.mark.parametrize(
    "kind",
    ["memory", "state"],
)
@pytest.mark.asyncio
async def test_retention_keeps_newest_terminal_records(
    kind: str,
) -> None:
    repository = _repository(kind)
    now = [_NOW]
    service = _service(repository, now)
    account = await _create_account(service)

    grants = []

    for index in range(4):
        grants.append(
            await _issue_and_revoke(
                service,
                account.id,
                now,
                label=f"Token {index}",
            )
        )

        now[0] += timedelta(minutes=1)

    assert (
        await service.prune_terminal_token_history(
            account.id,
            retain=2,
        )
        == 2
    )

    assert await repository.get_token(grants[0].metadata.id) is None
    assert await repository.get_token(grants[1].metadata.id) is None
    assert await repository.get_token(grants[2].metadata.id) is not None
    assert await repository.get_token(grants[3].metadata.id) is not None

    for grant in grants[:2]:
        assert await repository.get_token_by_digest(grant.metadata.token_digest) is None


@pytest.mark.parametrize(
    "kind",
    ["memory", "state"],
)
@pytest.mark.asyncio
async def test_retention_never_deletes_active_tokens(
    kind: str,
) -> None:
    repository = _repository(kind)
    now = [_NOW]
    service = _service(repository, now)
    account = await _create_account(service)

    revoked = await _issue_and_revoke(
        service,
        account.id,
        now,
        label="Revoked Token",
    )

    active = await service.issue_token(
        account.id,
        label="Active Token",
        scopes=frozenset({"jobs.read"}),
        expires_at=now[0] + timedelta(days=1),
    )

    assert (
        await service.prune_terminal_token_history(
            account.id,
            retain=0,
        )
        == 1
    )

    assert await repository.get_token(revoked.metadata.id) is None

    stored_active = await repository.get_token(active.metadata.id)

    assert stored_active is not None
    assert stored_active.status is ControlPlaneApiTokenStatus.ACTIVE


@pytest.mark.parametrize(
    "kind",
    ["memory", "state"],
)
@pytest.mark.asyncio
async def test_retention_reconciles_elapsed_tokens(
    kind: str,
) -> None:
    repository = _repository(kind)
    now = [_NOW]
    service = _service(repository, now)
    account = await _create_account(service)

    grant = await service.issue_token(
        account.id,
        label="Elapsed Token",
        scopes=frozenset({"jobs.read"}),
        expires_at=_NOW + timedelta(minutes=1),
    )

    now[0] += timedelta(minutes=2)

    assert (
        await service.prune_terminal_token_history(
            account.id,
            retain=0,
        )
        == 1
    )

    assert await repository.get_token(grant.metadata.id) is None
    assert await repository.get_token_by_digest(grant.metadata.token_digest) is None


@pytest.mark.parametrize(
    "kind",
    ["memory", "state"],
)
@pytest.mark.asyncio
async def test_rotation_lineage_is_protected(
    kind: str,
) -> None:
    repository = _repository(kind)
    now = [_NOW]
    service = _service(repository, now)
    account = await _create_account(service)

    original = await service.issue_token(
        account.id,
        label="Original Token",
        scopes=frozenset({"jobs.read"}),
        expires_at=_NOW + timedelta(days=1),
    )

    now[0] += timedelta(minutes=1)

    successor = await service.rotate_token(
        original.metadata.id,
        expires_at=now[0] + timedelta(days=1),
    )

    now[0] += timedelta(minutes=1)

    assert await service.revoke_token(successor.metadata.id)

    isolated = await _issue_and_revoke(
        service,
        account.id,
        now,
        label="Isolated Token",
    )

    assert (
        await service.prune_terminal_token_history(
            account.id,
            retain=0,
        )
        == 1
    )

    assert await repository.get_token(original.metadata.id) is not None
    assert await repository.get_token(successor.metadata.id) is not None
    assert await repository.get_token(isolated.metadata.id) is None


@pytest.mark.parametrize(
    "kind",
    ["memory", "state"],
)
@pytest.mark.asyncio
async def test_repository_delete_requires_terminal_revision(
    kind: str,
) -> None:
    repository = _repository(kind)
    now = [_NOW]
    service = _service(repository, now)
    account = await _create_account(service)

    grant = await service.issue_token(
        account.id,
        label="Direct Delete Token",
        scopes=frozenset({"jobs.read"}),
        expires_at=_NOW + timedelta(days=1),
    )

    with pytest.raises(
        ControlPlaneApiTokenConflictError,
        match="active",
    ):
        await repository.delete_terminal_token(
            grant.metadata.id,
            expected_revision=1,
        )

    now[0] += timedelta(minutes=1)

    assert await service.revoke_token(grant.metadata.id)

    stored = await repository.get_token(grant.metadata.id)

    assert stored is not None

    with pytest.raises(
        ControlPlaneApiTokenConflictError,
        match="revision",
    ):
        await repository.delete_terminal_token(
            stored.id,
            expected_revision=1,
        )

    await repository.delete_terminal_token(
        stored.id,
        expected_revision=stored.revision,
    )

    with pytest.raises(ControlPlaneApiTokenNotFoundError):
        await repository.delete_terminal_token(
            stored.id,
            expected_revision=stored.revision,
        )


@pytest.mark.asyncio
async def test_retention_validates_policy_bounds() -> None:
    repository = _repository("memory")
    service = _service(
        repository,
        [_NOW],
    )
    account = await _create_account(service)

    with pytest.raises(TypeError):
        await service.prune_terminal_token_history(
            account.id,
            retain=True,
        )

    with pytest.raises(
        ValueError,
        match="between",
    ):
        await service.prune_terminal_token_history(
            account.id,
            retain=-1,
        )

    with pytest.raises(
        ValueError,
        match="between",
    ):
        await service.prune_terminal_token_history(
            account.id,
            retain=(MAX_CONTROL_PLANE_API_TOKENS_PER_ACCOUNT + 1),
        )


@pytest.mark.asyncio
async def test_retention_requires_existing_account() -> None:
    repository = _repository("memory")
    service = _service(
        repository,
        [_NOW],
    )

    with pytest.raises(ControlPlaneServiceAccountNotFoundError):
        await service.prune_terminal_token_history(_UNKNOWN_ACCOUNT_ID)


@pytest.mark.asyncio
async def test_state_restart_preserves_pruned_history() -> None:
    store = MemoryStateStore()
    repository = _repository(
        "state",
        store=store,
    )
    now = [_NOW]
    service = _service(repository, now)
    account = await _create_account(service)

    grants = []

    for index in range(3):
        grants.append(
            await _issue_and_revoke(
                service,
                account.id,
                now,
                label=f"Persisted Token {index}",
            )
        )

        now[0] += timedelta(minutes=1)

    assert (
        await service.prune_terminal_token_history(
            account.id,
            retain=1,
        )
        == 2
    )

    recovered = StateControlPlaneServiceAccountRepository(
        store,
        max_tokens_per_account=12,
    )

    for grant in grants[:2]:
        assert await recovered.get_token(grant.metadata.id) is None
        assert await recovered.get_token_by_digest(grant.metadata.token_digest) is None

    assert await recovered.get_token(grants[2].metadata.id) is not None

    snapshot = await recovered.snapshot()

    assert snapshot.tokens == 1
    assert snapshot.revoked_tokens == 1
