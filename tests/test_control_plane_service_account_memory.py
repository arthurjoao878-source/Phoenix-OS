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
from phoenix_os.control_plane.service_account_memory import (
    InMemoryControlPlaneServiceAccountRepository,
)

_NOW = datetime(2026, 7, 20, 12, tzinfo=UTC)


def _account(
    name: str,
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
def test_repository_rejects_invalid_capacity(
    account_capacity: int,
    token_capacity: int,
) -> None:
    with pytest.raises(ValueError, match="capacity"):
        InMemoryControlPlaneServiceAccountRepository(
            account_capacity=account_capacity,
            max_tokens_per_account=token_capacity,
        )


@pytest.mark.asyncio
async def test_repository_adds_and_reads_account() -> None:
    repository = InMemoryControlPlaneServiceAccountRepository()
    account = _account("release.bot")

    await repository.add_account(account)

    assert await repository.get_account(account.id) is account
    assert await repository.get_account_by_name(" RELEASE.BOT ") is account


@pytest.mark.asyncio
async def test_repository_returns_none_for_unknown() -> None:
    repository = InMemoryControlPlaneServiceAccountRepository()

    assert await repository.get_account(uuid4()) is None
    assert await repository.get_account_by_name("missing") is None


@pytest.mark.asyncio
async def test_repository_rejects_duplicate_id() -> None:
    repository = InMemoryControlPlaneServiceAccountRepository()
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
async def test_repository_rejects_duplicate_name() -> None:
    repository = InMemoryControlPlaneServiceAccountRepository()

    await repository.add_account(_account("release.bot"))

    with pytest.raises(
        ControlPlaneServiceAccountAlreadyExistsError,
        match="name",
    ):
        await repository.add_account(_account("RELEASE.BOT"))


@pytest.mark.asyncio
async def test_repository_enforces_capacity() -> None:
    repository = InMemoryControlPlaneServiceAccountRepository(account_capacity=1)

    await repository.add_account(_account("release.bot"))

    with pytest.raises(ControlPlaneServiceAccountCapacityError):
        await repository.add_account(_account("backup.bot"))


@pytest.mark.asyncio
async def test_repository_lists_accounts_in_order() -> None:
    repository = InMemoryControlPlaneServiceAccountRepository()

    for name in (
        "charlie.bot",
        "alpha.bot",
        "bravo.bot",
    ):
        await repository.add_account(_account(name))

    page = await repository.list_accounts()

    assert tuple(item.name for item in page.items) == (
        "alpha.bot",
        "bravo.bot",
        "charlie.bot",
    )
    assert page.page.total == 3
    assert page.page.next_offset is None


@pytest.mark.asyncio
async def test_repository_paginates_accounts() -> None:
    repository = InMemoryControlPlaneServiceAccountRepository()

    for name in (
        "delta.bot",
        "alpha.bot",
        "charlie.bot",
        "bravo.bot",
    ):
        await repository.add_account(_account(name))

    first = await repository.list_accounts(
        ControlPlaneServiceAccountPageRequest(
            offset=0,
            limit=2,
        )
    )
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
async def test_repository_replaces_account() -> None:
    repository = InMemoryControlPlaneServiceAccountRepository()
    account = _account("release.bot")

    await repository.add_account(account)

    updated = replace(
        account,
        name="deploy.bot",
        display_name="Deploy Bot",
        updated_at=_NOW + timedelta(seconds=1),
        revision=2,
    )

    result = await repository.replace_account(
        updated,
        expected_revision=1,
    )

    assert result is updated
    assert await repository.get_account_by_name("release.bot") is None
    assert await repository.get_account_by_name("deploy.bot") is updated


@pytest.mark.asyncio
async def test_replace_rejects_unknown_account() -> None:
    repository = InMemoryControlPlaneServiceAccountRepository()

    with pytest.raises(ControlPlaneServiceAccountNotFoundError):
        await repository.replace_account(
            _account(
                "release.bot",
                revision=2,
            ),
            expected_revision=1,
        )


@pytest.mark.asyncio
async def test_replace_rejects_stale_revision() -> None:
    repository = InMemoryControlPlaneServiceAccountRepository()
    account = _account("release.bot")

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
async def test_replace_requires_next_revision() -> None:
    repository = InMemoryControlPlaneServiceAccountRepository()
    account = _account("release.bot")

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
async def test_replace_rejects_changed_created_at() -> None:
    repository = InMemoryControlPlaneServiceAccountRepository()
    account = _account("release.bot")

    await repository.add_account(account)

    updated = replace(
        account,
        created_at=_NOW - timedelta(seconds=1),
        updated_at=_NOW + timedelta(seconds=1),
        revision=2,
    )

    with pytest.raises(
        ControlPlaneServiceAccountConflictError,
        match="created_at",
    ):
        await repository.replace_account(
            updated,
            expected_revision=1,
        )


@pytest.mark.asyncio
async def test_replace_rejects_backwards_time() -> None:
    repository = InMemoryControlPlaneServiceAccountRepository()
    account = _account(
        "release.bot",
        updated_at=_NOW + timedelta(seconds=2),
    )

    await repository.add_account(account)

    updated = replace(
        account,
        updated_at=_NOW + timedelta(seconds=1),
        revision=2,
    )

    with pytest.raises(
        ControlPlaneServiceAccountConflictError,
        match="backwards",
    ):
        await repository.replace_account(
            updated,
            expected_revision=1,
        )


@pytest.mark.asyncio
async def test_replace_rejects_taken_name() -> None:
    repository = InMemoryControlPlaneServiceAccountRepository()
    release = _account("release.bot")
    backup = _account("backup.bot")

    await repository.add_account(release)
    await repository.add_account(backup)

    updated = replace(
        release,
        name="backup.bot",
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
async def test_snapshot_reports_account_statuses() -> None:
    repository = InMemoryControlPlaneServiceAccountRepository(
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
    assert snapshot.tokens == 0
    assert snapshot.account_capacity == 10
    assert snapshot.max_tokens_per_account == 4
    assert not snapshot.closed


@pytest.mark.asyncio
async def test_close_clears_state_and_is_idempotent() -> None:
    repository = InMemoryControlPlaneServiceAccountRepository()

    await repository.add_account(_account("release.bot"))

    await repository.close()
    await repository.close()

    snapshot = await repository.snapshot()

    assert snapshot.closed
    assert snapshot.accounts == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "operation",
    [
        "get",
        "name",
        "list",
        "add",
        "replace",
    ],
)
async def test_operations_reject_after_close(
    operation: str,
) -> None:
    repository = InMemoryControlPlaneServiceAccountRepository()
    account = _account("release.bot")

    await repository.add_account(account)
    await repository.close()

    with pytest.raises(ControlPlaneServiceAccountRepositoryClosedError):
        if operation == "get":
            await repository.get_account(account.id)
        elif operation == "name":
            await repository.get_account_by_name(account.name)
        elif operation == "list":
            await repository.list_accounts()
        elif operation == "add":
            await repository.add_account(_account("backup.bot"))
        else:
            await repository.replace_account(
                replace(
                    account,
                    updated_at=(_NOW + timedelta(seconds=1)),
                    revision=2,
                ),
                expected_revision=1,
            )


@pytest.mark.asyncio
async def test_concurrent_duplicate_adds_are_serialized() -> None:
    repository = InMemoryControlPlaneServiceAccountRepository()

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

    assert (await repository.snapshot()).accounts == 1
