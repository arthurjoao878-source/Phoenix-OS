from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from phoenix_os.control_plane.errors import (
    ControlPlaneServiceAccountConflictError,
    ControlPlaneServiceAccountNotFoundError,
)
from phoenix_os.control_plane.service_account_contracts import (
    ControlPlaneApiTokenStatus,
    ControlPlaneServiceAccountRecord,
    ControlPlaneServiceAccountRepository,
    ControlPlaneServiceAccountStatus,
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
_UNKNOWN_ID = UUID("10000000-0000-0000-0000-000000000099")
_TOKEN_IDS = (
    UUID("20000000-0000-0000-0000-000000000001"),
    UUID("20000000-0000-0000-0000-000000000002"),
    UUID("20000000-0000-0000-0000-000000000003"),
)
_TOKEN_VALUES = (
    "phx_sa_" + ("A" * 48),
    "phx_sa_" + ("B" * 48),
    "phx_sa_" + ("C" * 48),
)


def _repository(
    kind: str,
) -> ControlPlaneServiceAccountRepository:
    if kind == "memory":
        return InMemoryControlPlaneServiceAccountRepository()

    return StateControlPlaneServiceAccountRepository(MemoryStateStore())


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
async def test_disable_account_revokes_active_tokens(
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

    disabled = await service.disable_account(account.id)

    assert disabled.status is ControlPlaneServiceAccountStatus.DISABLED
    assert disabled.disabled_at == now[0]
    assert disabled.revision == 2

    token = await repository.get_token(grant.metadata.id)

    assert token is not None
    assert token.status is ControlPlaneApiTokenStatus.REVOKED

    again = await service.disable_account(account.id)

    assert again == disabled


@pytest.mark.parametrize(
    "kind",
    ["memory", "state"],
)
@pytest.mark.asyncio
async def test_disabled_account_can_be_safely_enabled(
    kind: str,
) -> None:
    repository = _repository(kind)
    now = [_NOW]
    service = _service(repository, now)
    account = await _create_account(service)

    old_token = await service.issue_token(
        account.id,
        label="Old Token",
        scopes=frozenset({"jobs.read"}),
        expires_at=_NOW + timedelta(days=1),
    )

    now[0] += timedelta(minutes=1)

    disabled = await service.disable_account(account.id)

    now[0] += timedelta(minutes=1)

    enabled = await service.enable_account(account.id)

    assert enabled.status is ControlPlaneServiceAccountStatus.ACTIVE
    assert enabled.disabled_at is None
    assert enabled.revoked_at is None
    assert enabled.revision == disabled.revision + 1

    persisted_old = await repository.get_token(old_token.metadata.id)

    assert persisted_old is not None
    assert persisted_old.status is ControlPlaneApiTokenStatus.REVOKED

    new_token = await service.issue_token(
        enabled.id,
        label="New Token",
        scopes=frozenset({"jobs.read"}),
        expires_at=now[0] + timedelta(days=1),
    )

    assert new_token.metadata.status is ControlPlaneApiTokenStatus.ACTIVE


@pytest.mark.parametrize(
    "kind",
    ["memory", "state"],
)
@pytest.mark.asyncio
async def test_enable_refuses_remaining_active_token(
    kind: str,
) -> None:
    repository = _repository(kind)
    now = [_NOW]
    service = _service(repository, now)
    account = await _create_account(service)

    await service.issue_token(
        account.id,
        label="Unsafe Token",
        scopes=frozenset({"jobs.read"}),
        expires_at=_NOW + timedelta(days=1),
    )

    now[0] += timedelta(minutes=1)

    disabled = replace(
        account,
        status=ControlPlaneServiceAccountStatus.DISABLED,
        disabled_at=now[0],
        updated_at=now[0],
        revision=2,
    )

    await repository.replace_account(
        disabled,
        expected_revision=1,
    )

    with pytest.raises(
        ControlPlaneServiceAccountConflictError,
        match="active API tokens",
    ):
        await service.enable_account(account.id)


@pytest.mark.parametrize(
    "kind",
    ["memory", "state"],
)
@pytest.mark.asyncio
async def test_revoke_account_is_terminal_and_invalidates_tokens(
    kind: str,
) -> None:
    repository = _repository(kind)
    now = [_NOW]
    service = _service(repository, now)
    account = await _create_account(service)

    token = await service.issue_token(
        account.id,
        label="Release Token",
        scopes=frozenset({"jobs.read"}),
        expires_at=_NOW + timedelta(days=1),
    )

    now[0] += timedelta(minutes=1)

    revoked = await service.revoke_account(account.id)

    assert revoked.status is ControlPlaneServiceAccountStatus.REVOKED
    assert revoked.revoked_at == now[0]
    assert revoked.disabled_at is None
    assert revoked.revision == 2

    stored_token = await repository.get_token(token.metadata.id)

    assert stored_token is not None
    assert stored_token.status is ControlPlaneApiTokenStatus.REVOKED

    again = await service.revoke_account(account.id)

    assert again == revoked

    with pytest.raises(
        ControlPlaneServiceAccountConflictError,
        match="cannot be enabled",
    ):
        await service.enable_account(account.id)

    with pytest.raises(
        ControlPlaneServiceAccountConflictError,
        match="cannot be updated",
    ):
        await service.update_account(
            account.id,
            display_name="Changed",
        )


@pytest.mark.parametrize(
    "kind",
    ["memory", "state"],
)
@pytest.mark.asyncio
async def test_disable_reconciles_elapsed_token(
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

    await service.disable_account(account.id)

    stored = await repository.get_token(grant.metadata.id)

    assert stored is not None
    assert stored.status is ControlPlaneApiTokenStatus.EXPIRED


@pytest.mark.parametrize(
    "operation",
    [
        "disable",
        "enable",
        "revoke",
    ],
)
@pytest.mark.asyncio
async def test_account_status_operations_require_existing_account(
    operation: str,
) -> None:
    repository = _repository("memory")
    service = _service(
        repository,
        [_NOW],
    )

    with pytest.raises(ControlPlaneServiceAccountNotFoundError):
        if operation == "disable":
            await service.disable_account(_UNKNOWN_ID)
        elif operation == "enable":
            await service.enable_account(_UNKNOWN_ID)
        else:
            await service.revoke_account(_UNKNOWN_ID)


@pytest.mark.asyncio
async def test_state_restart_preserves_account_status() -> None:
    store = MemoryStateStore()
    repository = StateControlPlaneServiceAccountRepository(store)
    now = [_NOW]
    service = _service(repository, now)
    account = await _create_account(service)

    now[0] += timedelta(minutes=1)

    revoked = await service.revoke_account(account.id)

    recovered = StateControlPlaneServiceAccountRepository(store)
    persisted = await recovered.get_account(account.id)

    assert persisted == revoked
    assert persisted is not None
    assert persisted.status is ControlPlaneServiceAccountStatus.REVOKED
