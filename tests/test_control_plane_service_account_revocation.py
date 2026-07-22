from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from phoenix_os.control_plane.errors import (
    ControlPlaneServiceAccountNotFoundError,
)
from phoenix_os.control_plane.service_account_contracts import (
    ControlPlaneApiTokenStatus,
    ControlPlaneServiceAccountRecord,
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
_UNKNOWN_ACCOUNT_ID = UUID("10000000-0000-0000-0000-000000000099")
_TOKEN_IDS = (
    UUID("20000000-0000-0000-0000-000000000001"),
    UUID("20000000-0000-0000-0000-000000000002"),
    UUID("20000000-0000-0000-0000-000000000003"),
    UUID("20000000-0000-0000-0000-000000000004"),
)
_TOKEN_VALUES = (
    "phx_sa_" + ("A" * 48),
    "phx_sa_" + ("B" * 48),
    "phx_sa_" + ("C" * 48),
    "phx_sa_" + ("D" * 48),
)


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


@pytest.mark.parametrize(
    "kind",
    ["memory", "state"],
)
@pytest.mark.asyncio
async def test_individual_revocation_is_idempotent(
    kind: str,
) -> None:
    repository = _repository(kind)
    now = [_NOW]
    service = _service(repository, now)
    account = await _create_account(service)

    grant = await service.issue_token(
        account.id,
        label="Release Token",
        scopes=frozenset({"jobs.read"}),
        expires_at=_NOW + timedelta(days=1),
    )

    now[0] += timedelta(minutes=1)

    assert await service.revoke_token(grant.metadata.id)
    assert not await service.revoke_token(grant.metadata.id)

    stored = await repository.get_token(grant.metadata.id)

    assert stored is not None
    assert stored.status is ControlPlaneApiTokenStatus.REVOKED
    assert stored.revoked_at == now[0]
    assert stored.updated_at == now[0]
    assert stored.revision == 2


@pytest.mark.parametrize(
    "kind",
    ["memory", "state"],
)
@pytest.mark.asyncio
async def test_missing_token_revocation_is_generic(
    kind: str,
) -> None:
    repository = _repository(kind)
    service = _service(
        repository,
        [_NOW],
    )

    assert not await service.revoke_token(_TOKEN_IDS[0])


@pytest.mark.parametrize(
    "kind",
    ["memory", "state"],
)
@pytest.mark.asyncio
async def test_elapsed_token_becomes_expired_not_revoked(
    kind: str,
) -> None:
    repository = _repository(kind)
    now = [_NOW]
    service = _service(repository, now)
    account = await _create_account(service)

    grant = await service.issue_token(
        account.id,
        label="Short Token",
        scopes=frozenset({"jobs.read"}),
        expires_at=_NOW + timedelta(minutes=1),
    )

    now[0] += timedelta(minutes=2)

    assert not await service.revoke_token(grant.metadata.id)

    stored = await repository.get_token(grant.metadata.id)

    assert stored is not None
    assert stored.status is ControlPlaneApiTokenStatus.EXPIRED
    assert stored.revoked_at is None
    assert stored.updated_at == now[0]
    assert stored.revision == 2


@pytest.mark.parametrize(
    "kind",
    ["memory", "state"],
)
@pytest.mark.asyncio
async def test_account_wide_revocation_reconciles_expiry(
    kind: str,
) -> None:
    repository = _repository(kind)
    now = [_NOW]
    service = _service(repository, now)
    account = await _create_account(service)

    long_lived = await service.issue_token(
        account.id,
        label="Long Token",
        scopes=frozenset({"jobs.read"}),
        expires_at=_NOW + timedelta(days=1),
    )
    short_lived = await service.issue_token(
        account.id,
        label="Short Token",
        scopes=frozenset({"jobs.read"}),
        expires_at=_NOW + timedelta(minutes=1),
    )

    now[0] += timedelta(minutes=2)

    assert await service.revoke_account_tokens(account.id) == 1

    assert await service.revoke_account_tokens(account.id) == 0

    stored_long = await repository.get_token(long_lived.metadata.id)
    stored_short = await repository.get_token(short_lived.metadata.id)

    assert stored_long is not None
    assert stored_short is not None

    assert stored_long.status is ControlPlaneApiTokenStatus.REVOKED
    assert stored_short.status is ControlPlaneApiTokenStatus.EXPIRED


@pytest.mark.parametrize(
    "kind",
    ["memory", "state"],
)
@pytest.mark.asyncio
async def test_expiry_reconciliation_is_idempotent(
    kind: str,
) -> None:
    repository = _repository(kind)
    now = [_NOW]
    service = _service(repository, now)
    account = await _create_account(service)

    first = await service.issue_token(
        account.id,
        label="First Token",
        scopes=frozenset({"jobs.read"}),
        expires_at=_NOW + timedelta(minutes=1),
    )
    second = await service.issue_token(
        account.id,
        label="Second Token",
        scopes=frozenset({"jobs.read"}),
        expires_at=_NOW + timedelta(minutes=2),
    )

    now[0] += timedelta(minutes=3)

    assert await service.reconcile_expired_tokens(account.id) == 2
    assert await service.reconcile_expired_tokens(account.id) == 0

    for token_id in (
        first.metadata.id,
        second.metadata.id,
    ):
        stored = await repository.get_token(token_id)

        assert stored is not None
        assert stored.status is ControlPlaneApiTokenStatus.EXPIRED


@pytest.mark.parametrize(
    "operation",
    [
        "revoke",
        "reconcile",
    ],
)
@pytest.mark.asyncio
async def test_account_operations_require_existing_account(
    operation: str,
) -> None:
    repository = _repository("memory")
    service = _service(
        repository,
        [_NOW],
    )

    with pytest.raises(ControlPlaneServiceAccountNotFoundError):
        if operation == "revoke":
            await service.revoke_account_tokens(_UNKNOWN_ACCOUNT_ID)
        else:
            await service.reconcile_expired_tokens(_UNKNOWN_ACCOUNT_ID)


@pytest.mark.asyncio
async def test_state_restart_preserves_terminal_states() -> None:
    store = MemoryStateStore()
    repository = StateControlPlaneServiceAccountRepository(store)
    now = [_NOW]
    service = _service(repository, now)
    account = await _create_account(service)

    revoked = await service.issue_token(
        account.id,
        label="Revoked Token",
        scopes=frozenset({"jobs.read"}),
        expires_at=_NOW + timedelta(days=1),
    )
    expired = await service.issue_token(
        account.id,
        label="Expired Token",
        scopes=frozenset({"jobs.read"}),
        expires_at=_NOW + timedelta(minutes=1),
    )

    now[0] += timedelta(minutes=2)

    assert await service.revoke_token(revoked.metadata.id)
    assert await service.reconcile_expired_tokens(account.id) == 1

    recovered = StateControlPlaneServiceAccountRepository(store)

    recovered_revoked = await recovered.get_token(revoked.metadata.id)
    recovered_expired = await recovered.get_token(expired.metadata.id)

    assert recovered_revoked is not None
    assert recovered_expired is not None

    assert recovered_revoked.status is ControlPlaneApiTokenStatus.REVOKED
    assert recovered_expired.status is ControlPlaneApiTokenStatus.EXPIRED


@pytest.mark.parametrize(
    "kind",
    ["memory", "state"],
)
@pytest.mark.asyncio
async def test_overlap_predecessor_can_be_reconciled(
    kind: str,
) -> None:
    repository = _repository(kind)
    now = [_NOW]
    service = _service(repository, now)
    account = await _create_account(service)

    original = await service.issue_token(
        account.id,
        label="Release Token",
        scopes=frozenset({"jobs.read"}),
        expires_at=_NOW + timedelta(days=1),
    )

    now[0] += timedelta(minutes=1)

    successor = await service.rotate_token(
        original.metadata.id,
        expires_at=now[0] + timedelta(days=1),
        overlap=timedelta(minutes=5),
    )

    now[0] += timedelta(minutes=6)

    assert await service.reconcile_expired_tokens(account.id) == 1

    predecessor = await repository.get_token(original.metadata.id)
    stored_successor = await repository.get_token(successor.metadata.id)

    assert predecessor is not None
    assert stored_successor is not None

    assert predecessor.status is ControlPlaneApiTokenStatus.EXPIRED
    assert stored_successor.status is ControlPlaneApiTokenStatus.ACTIVE
