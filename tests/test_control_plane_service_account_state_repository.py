from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest

from phoenix_os.control_plane.errors import (
    ControlPlaneServiceAccountAlreadyExistsError,
    ControlPlaneServiceAccountCapacityError,
    ControlPlaneServiceAccountConflictError,
    ControlPlaneServiceAccountCorruptionError,
    ControlPlaneServiceAccountNotFoundError,
    ControlPlaneServiceAccountRepositoryClosedError,
)
from phoenix_os.control_plane.service_account_contracts import (
    MAX_CONTROL_PLANE_API_TOKENS_PER_ACCOUNT,
    MAX_CONTROL_PLANE_SERVICE_ACCOUNT_CAPACITY,
    ControlPlaneServiceAccountPageRequest,
    ControlPlaneServiceAccountRecord,
    ControlPlaneServiceAccountStatus,
)
from phoenix_os.control_plane.service_account_state import (
    StateControlPlaneServiceAccountRepository,
)
from phoenix_os.state import (
    ABSENT_VERSION,
    MemoryStateStore,
    StateKey,
)

_NOW = datetime(2026, 7, 20, 12, tzinfo=UTC)
_NAMESPACE = "control-plane-service-accounts"


def _account(
    name: str = "release.bot",
    *,
    account_id: UUID | None = None,
    status: ControlPlaneServiceAccountStatus = (ControlPlaneServiceAccountStatus.ACTIVE),
    disabled_at: datetime | None = None,
    revoked_at: datetime | None = None,
    created_at: datetime = _NOW,
    updated_at: datetime = _NOW,
    revision: int = 1,
) -> ControlPlaneServiceAccountRecord:
    return ControlPlaneServiceAccountRecord(
        id=account_id or uuid4(),
        name=name,
        display_name=name.replace(".", " ").title(),
        created_at=created_at,
        updated_at=updated_at,
        status=status,
        disabled_at=disabled_at,
        revoked_at=revoked_at,
        revision=revision,
    )


def _record_key(
    account_id: UUID,
) -> StateKey[dict[str, object]]:
    return StateKey(
        _NAMESPACE,
        f"record_{account_id.hex}",
        dict,
    )


def _name_key(
    name: str,
) -> StateKey[dict[str, object]]:
    return StateKey(
        _NAMESPACE,
        f"name_{name}",
        dict,
    )


@pytest.mark.parametrize(
    ("account_capacity", "token_capacity"),
    [
        (0, 1),
        (-1, 1),
        (
            MAX_CONTROL_PLANE_SERVICE_ACCOUNT_CAPACITY + 1,
            1,
        ),
        (1, 0),
        (1, -1),
        (
            1,
            MAX_CONTROL_PLANE_API_TOKENS_PER_ACCOUNT + 1,
        ),
    ],
)
def test_state_repository_rejects_invalid_capacity(
    account_capacity: int,
    token_capacity: int,
) -> None:
    with pytest.raises(ValueError, match="capacity"):
        StateControlPlaneServiceAccountRepository(
            MemoryStateStore(),
            account_capacity=account_capacity,
            max_tokens_per_account=token_capacity,
        )


def test_state_repository_normalizes_namespace() -> None:
    repository = StateControlPlaneServiceAccountRepository(
        MemoryStateStore(),
        namespace=(" CONTROL-PLANE-SERVICE-ACCOUNTS "),
    )

    assert not repository.closed


@pytest.mark.asyncio
async def test_state_repository_adds_and_reads_indexes() -> None:
    repository = StateControlPlaneServiceAccountRepository(MemoryStateStore())
    account = _account()

    await repository.add_account(account)

    assert await repository.get_account(account.id) == account
    assert await repository.get_account_by_name(" RELEASE.BOT ") == account


@pytest.mark.asyncio
async def test_state_repository_returns_none_for_unknown() -> None:
    repository = StateControlPlaneServiceAccountRepository(MemoryStateStore())

    assert await repository.get_account(uuid4()) is None
    assert await repository.get_account_by_name("missing") is None


@pytest.mark.asyncio
async def test_state_repository_survives_restart() -> None:
    store = MemoryStateStore()
    first = StateControlPlaneServiceAccountRepository(store)
    account = _account()

    await first.add_account(account)
    await first.close()

    second = StateControlPlaneServiceAccountRepository(store)

    assert await second.get_account(account.id) == account
    assert await second.get_account_by_name(account.name) == account


@pytest.mark.asyncio
async def test_state_repository_rejects_duplicate_id() -> None:
    repository = StateControlPlaneServiceAccountRepository(MemoryStateStore())
    account_id = uuid4()

    await repository.add_account(
        _account(
            "release.bot",
            account_id=account_id,
        )
    )

    with pytest.raises(
        ControlPlaneServiceAccountAlreadyExistsError,
        match="id",
    ):
        await repository.add_account(
            _account(
                "backup.bot",
                account_id=account_id,
            )
        )


@pytest.mark.asyncio
async def test_state_repository_rejects_duplicate_name() -> None:
    repository = StateControlPlaneServiceAccountRepository(MemoryStateStore())

    await repository.add_account(_account("release.bot"))

    with pytest.raises(
        ControlPlaneServiceAccountAlreadyExistsError,
        match="name",
    ):
        await repository.add_account(_account("RELEASE.BOT"))


@pytest.mark.asyncio
async def test_state_repository_enforces_capacity() -> None:
    repository = StateControlPlaneServiceAccountRepository(
        MemoryStateStore(),
        account_capacity=1,
    )

    await repository.add_account(_account("release.bot"))

    with pytest.raises(ControlPlaneServiceAccountCapacityError):
        await repository.add_account(_account("backup.bot"))


@pytest.mark.asyncio
async def test_concurrent_duplicate_add_is_atomic() -> None:
    repository = StateControlPlaneServiceAccountRepository(MemoryStateStore())
    first = _account("release.bot")
    second = _account("release.bot")

    results = await asyncio.gather(
        repository.add_account(first),
        repository.add_account(second),
        return_exceptions=True,
    )

    assert sum(result is None for result in results) == 1
    assert (
        sum(
            isinstance(
                result,
                ControlPlaneServiceAccountAlreadyExistsError,
            )
            for result in results
        )
        == 1
    )


@pytest.mark.asyncio
async def test_state_repository_lists_and_paginates() -> None:
    repository = StateControlPlaneServiceAccountRepository(MemoryStateStore())

    for name in (
        "delta.bot",
        "alpha.bot",
        "charlie.bot",
        "bravo.bot",
    ):
        await repository.add_account(_account(name))

    first = await repository.list_accounts(ControlPlaneServiceAccountPageRequest(limit=2))
    second = await repository.list_accounts(
        ControlPlaneServiceAccountPageRequest(
            offset=2,
            limit=2,
        )
    )

    assert tuple(item.name for item in first.items) == (
        "alpha.bot",
        "bravo.bot",
    )
    assert first.page.next_offset == 2

    assert tuple(item.name for item in second.items) == (
        "charlie.bot",
        "delta.bot",
    )
    assert second.page.next_offset is None


@pytest.mark.asyncio
async def test_state_repository_replaces_account() -> None:
    repository = StateControlPlaneServiceAccountRepository(MemoryStateStore())
    account = _account()

    await repository.add_account(account)

    updated = replace(
        account,
        display_name="Release Automation",
        updated_at=_NOW + timedelta(seconds=1),
        revision=2,
    )

    result = await repository.replace_account(
        updated,
        expected_revision=1,
    )

    assert result == updated
    assert await repository.get_account(account.id) == updated


@pytest.mark.asyncio
async def test_replace_updates_name_index() -> None:
    repository = StateControlPlaneServiceAccountRepository(MemoryStateStore())
    account = _account("release.bot")

    await repository.add_account(account)

    updated = replace(
        account,
        name="deploy.bot",
        updated_at=_NOW + timedelta(seconds=1),
        revision=2,
    )

    await repository.replace_account(
        updated,
        expected_revision=1,
    )

    assert await repository.get_account_by_name("release.bot") is None
    assert await repository.get_account_by_name("deploy.bot") == updated


@pytest.mark.asyncio
async def test_replace_survives_restart() -> None:
    store = MemoryStateStore()
    repository = StateControlPlaneServiceAccountRepository(store)
    account = _account()

    await repository.add_account(account)

    updated = replace(
        account,
        display_name="Updated Bot",
        updated_at=_NOW + timedelta(seconds=1),
        revision=2,
    )

    await repository.replace_account(
        updated,
        expected_revision=1,
    )

    recovered = StateControlPlaneServiceAccountRepository(store)

    assert await recovered.get_account(account.id) == updated


@pytest.mark.asyncio
async def test_replace_rejects_unknown_account() -> None:
    repository = StateControlPlaneServiceAccountRepository(MemoryStateStore())

    with pytest.raises(ControlPlaneServiceAccountNotFoundError):
        await repository.replace_account(
            _account(revision=2),
            expected_revision=1,
        )


@pytest.mark.asyncio
async def test_replace_rejects_stale_revision() -> None:
    repository = StateControlPlaneServiceAccountRepository(MemoryStateStore())
    account = _account()

    await repository.add_account(account)

    updated = replace(
        account,
        updated_at=_NOW + timedelta(seconds=1),
        revision=2,
    )

    with pytest.raises(
        ControlPlaneServiceAccountConflictError,
        match="revision",
    ):
        await repository.replace_account(
            updated,
            expected_revision=2,
        )


@pytest.mark.asyncio
async def test_replace_rejects_revision_jump() -> None:
    repository = StateControlPlaneServiceAccountRepository(MemoryStateStore())
    account = _account()

    await repository.add_account(account)

    updated = replace(
        account,
        updated_at=_NOW + timedelta(seconds=1),
        revision=3,
    )

    with pytest.raises(
        ControlPlaneServiceAccountConflictError,
        match="increment",
    ):
        await repository.replace_account(
            updated,
            expected_revision=1,
        )


@pytest.mark.asyncio
async def test_replace_rejects_duplicate_name() -> None:
    repository = StateControlPlaneServiceAccountRepository(MemoryStateStore())
    first = _account("first.bot")
    second = _account("second.bot")

    await repository.add_account(first)
    await repository.add_account(second)

    updated = replace(
        first,
        name="second.bot",
        updated_at=_NOW + timedelta(seconds=1),
        revision=2,
    )

    with pytest.raises(
        ControlPlaneServiceAccountAlreadyExistsError,
        match="name",
    ):
        await repository.replace_account(
            updated,
            expected_revision=1,
        )


@pytest.mark.asyncio
async def test_snapshot_reports_persisted_statuses() -> None:
    repository = StateControlPlaneServiceAccountRepository(
        MemoryStateStore(),
        account_capacity=10,
        max_tokens_per_account=4,
    )

    await repository.add_account(_account("active.bot"))
    await repository.add_account(
        _account(
            "disabled.bot",
            status=(ControlPlaneServiceAccountStatus.DISABLED),
            disabled_at=_NOW,
        )
    )
    await repository.add_account(
        _account(
            "revoked.bot",
            status=(ControlPlaneServiceAccountStatus.REVOKED),
            revoked_at=_NOW,
        )
    )

    snapshot = await repository.snapshot()

    assert snapshot.accounts == 3
    assert (
        snapshot.active_accounts,
        snapshot.disabled_accounts,
        snapshot.revoked_accounts,
    ) == (1, 1, 1)
    assert snapshot.account_capacity == 10
    assert snapshot.max_tokens_per_account == 4


@pytest.mark.asyncio
async def test_close_preserves_persisted_state() -> None:
    store = MemoryStateStore()
    repository = StateControlPlaneServiceAccountRepository(store)
    account = _account()

    await repository.add_account(account)
    await repository.close()
    await repository.close()

    snapshot = await repository.snapshot()

    assert snapshot.closed
    assert snapshot.accounts == 1
    assert not store.closed


@pytest.mark.asyncio
async def test_operations_reject_after_close() -> None:
    repository = StateControlPlaneServiceAccountRepository(MemoryStateStore())
    account = _account()

    await repository.add_account(account)
    await repository.close()

    with pytest.raises(ControlPlaneServiceAccountRepositoryClosedError):
        await repository.get_account(account.id)

    with pytest.raises(ControlPlaneServiceAccountRepositoryClosedError):
        await repository.get_account_by_name(account.name)

    with pytest.raises(ControlPlaneServiceAccountRepositoryClosedError):
        await repository.list_accounts()

    with pytest.raises(ControlPlaneServiceAccountRepositoryClosedError):
        await repository.add_account(_account("backup.bot"))


@pytest.mark.asyncio
async def test_missing_name_index_is_corruption() -> None:
    store = MemoryStateStore()
    repository = StateControlPlaneServiceAccountRepository(store)
    account = _account()

    await repository.add_account(account)

    stored_index = await store.get(_name_key(account.name))
    assert stored_index is not None

    await store.delete(
        _name_key(account.name),
        expected_version=stored_index.version,
    )

    with pytest.raises(
        ControlPlaneServiceAccountCorruptionError,
        match="incomplete",
    ):
        await repository.get_account(account.id)


@pytest.mark.asyncio
async def test_name_index_mismatch_is_corruption() -> None:
    store = MemoryStateStore()
    repository = StateControlPlaneServiceAccountRepository(store)
    account = _account()

    await repository.add_account(account)

    stored_index = await store.get(_name_key(account.name))
    assert stored_index is not None

    altered = dict(stored_index.value)
    altered["revision"] = 2

    await store.put(
        _name_key(account.name),
        altered,
        expected_version=stored_index.version,
    )

    with pytest.raises(
        ControlPlaneServiceAccountCorruptionError,
        match="do not match",
    ):
        await repository.get_account(account.id)


@pytest.mark.asyncio
async def test_orphan_name_index_is_corruption() -> None:
    store = MemoryStateStore()
    repository = StateControlPlaneServiceAccountRepository(store)
    account = _account()

    await store.put(
        _name_key(account.name),
        {
            "schema_version": 1,
            "kind": ("phoenix.control-plane.service-account.name-index"),
            "service_account_id": str(account.id),
            "name": account.name,
            "revision": 1,
            "record_digest": "0" * 64,
        },
        expected_version=ABSENT_VERSION,
    )

    with pytest.raises(
        ControlPlaneServiceAccountCorruptionError,
        match="incomplete",
    ):
        await repository.list_accounts()


@pytest.mark.asyncio
async def test_wrong_record_key_is_corruption() -> None:
    store = MemoryStateStore()
    repository = StateControlPlaneServiceAccountRepository(store)
    account = _account()

    await repository.add_account(account)

    stored_record = await store.get(_record_key(account.id))
    assert stored_record is not None

    wrong_id = uuid4()

    await store.put(
        _record_key(wrong_id),
        dict(stored_record.value),
        expected_version=ABSENT_VERSION,
    )

    with pytest.raises(
        ControlPlaneServiceAccountCorruptionError,
        match="state key",
    ):
        await repository.list_accounts()
