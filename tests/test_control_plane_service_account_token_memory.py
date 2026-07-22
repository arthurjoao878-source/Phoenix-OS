from __future__ import annotations

import asyncio
import hashlib
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest

from phoenix_os.control_plane.errors import (
    ControlPlaneApiTokenAlreadyExistsError,
    ControlPlaneApiTokenCapacityError,
    ControlPlaneApiTokenConflictError,
    ControlPlaneApiTokenNotFoundError,
    ControlPlaneServiceAccountNotFoundError,
    ControlPlaneServiceAccountRepositoryClosedError,
)
from phoenix_os.control_plane.service_account_contracts import (
    ControlPlaneApiTokenMetadata,
    ControlPlaneApiTokenStatus,
    ControlPlaneServiceAccountPageRequest,
    ControlPlaneServiceAccountRecord,
)
from phoenix_os.control_plane.service_account_memory import (
    InMemoryControlPlaneServiceAccountRepository,
)

_NOW = datetime(2026, 7, 20, 12, tzinfo=UTC)


def _digest(seed: str) -> str:
    return hashlib.sha256(seed.encode("ascii")).hexdigest()


def _account(
    name: str = "release.bot",
    *,
    account_id: UUID | None = None,
) -> ControlPlaneServiceAccountRecord:
    return ControlPlaneServiceAccountRecord(
        id=account_id or uuid4(),
        name=name,
        display_name=name.replace(".", " ").title(),
        created_at=_NOW,
        updated_at=_NOW,
    )


def _token(
    account_id: UUID,
    seed: str,
    *,
    token_id: UUID | None = None,
    label: str | None = None,
    issued_at: datetime = _NOW,
    expires_at: datetime = (_NOW + timedelta(days=30)),
    updated_at: datetime = _NOW,
    status: ControlPlaneApiTokenStatus = (ControlPlaneApiTokenStatus.ACTIVE),
    revoked_at: datetime | None = None,
    revision: int = 1,
) -> ControlPlaneApiTokenMetadata:
    return ControlPlaneApiTokenMetadata(
        id=token_id or uuid4(),
        service_account_id=account_id,
        label=label or f"{seed.title()} Token",
        token_digest=_digest(seed),
        scopes=frozenset({"jobs.read", "jobs.create"}),
        resources=frozenset({"job:*"}),
        issued_at=issued_at,
        expires_at=expires_at,
        updated_at=updated_at,
        status=status,
        revoked_at=revoked_at,
        revision=revision,
    )


async def _repository_with_account(
    *,
    max_tokens: int = 8,
) -> tuple[
    InMemoryControlPlaneServiceAccountRepository,
    ControlPlaneServiceAccountRecord,
]:
    repository = InMemoryControlPlaneServiceAccountRepository(max_tokens_per_account=max_tokens)
    account = _account()
    await repository.add_account(account)
    return repository, account


@pytest.mark.asyncio
async def test_repository_adds_and_reads_token() -> None:
    repository, account = await _repository_with_account()
    metadata = _token(account.id, "first")

    await repository.add_token(metadata)

    assert await repository.get_token(metadata.id) is metadata
    assert await repository.get_token_by_digest(metadata.token_digest.upper()) is metadata


@pytest.mark.asyncio
async def test_repository_returns_none_for_unknown_token() -> None:
    repository, _ = await _repository_with_account()

    assert await repository.get_token(uuid4()) is None
    assert await repository.get_token_by_digest(_digest("missing")) is None


@pytest.mark.asyncio
async def test_add_token_requires_existing_account() -> None:
    repository = InMemoryControlPlaneServiceAccountRepository()

    with pytest.raises(ControlPlaneServiceAccountNotFoundError):
        await repository.add_token(_token(uuid4(), "orphan"))


@pytest.mark.asyncio
async def test_repository_rejects_duplicate_token_id() -> None:
    repository, account = await _repository_with_account()
    token_id = uuid4()

    await repository.add_token(
        _token(
            account.id,
            "first",
            token_id=token_id,
        )
    )

    with pytest.raises(
        ControlPlaneApiTokenAlreadyExistsError,
        match="id",
    ):
        await repository.add_token(
            _token(
                account.id,
                "second",
                token_id=token_id,
            )
        )


@pytest.mark.asyncio
async def test_repository_rejects_duplicate_digest() -> None:
    repository, account = await _repository_with_account()

    await repository.add_token(_token(account.id, "shared"))

    with pytest.raises(
        ControlPlaneApiTokenAlreadyExistsError,
        match="digest",
    ):
        await repository.add_token(_token(account.id, "shared"))


@pytest.mark.asyncio
async def test_repository_enforces_per_account_capacity() -> None:
    repository, account = await _repository_with_account(max_tokens=1)

    await repository.add_token(_token(account.id, "first"))

    with pytest.raises(ControlPlaneApiTokenCapacityError):
        await repository.add_token(_token(account.id, "second"))


@pytest.mark.asyncio
async def test_token_capacity_is_independent_per_account() -> None:
    repository = InMemoryControlPlaneServiceAccountRepository(max_tokens_per_account=1)
    first_account = _account("first.bot")
    second_account = _account("second.bot")

    await repository.add_account(first_account)
    await repository.add_account(second_account)

    await repository.add_token(_token(first_account.id, "first"))
    await repository.add_token(_token(second_account.id, "second"))

    assert (await repository.snapshot()).tokens == 2


@pytest.mark.asyncio
async def test_repository_lists_only_account_tokens() -> None:
    repository = InMemoryControlPlaneServiceAccountRepository()
    first_account = _account("first.bot")
    second_account = _account("second.bot")

    await repository.add_account(first_account)
    await repository.add_account(second_account)

    first = _token(
        first_account.id,
        "first",
        issued_at=_NOW,
    )
    second = _token(
        first_account.id,
        "second",
        issued_at=_NOW + timedelta(seconds=1),
        updated_at=_NOW + timedelta(seconds=1),
        expires_at=_NOW + timedelta(days=31),
    )
    foreign = _token(
        second_account.id,
        "foreign",
    )

    await repository.add_token(second)
    await repository.add_token(foreign)
    await repository.add_token(first)

    page = await repository.list_tokens(first_account.id)

    assert page.items == (first, second)
    assert page.page.total == 2


@pytest.mark.asyncio
async def test_repository_paginates_tokens() -> None:
    repository, account = await _repository_with_account()

    tokens = []

    for index in range(4):
        issued_at = _NOW + timedelta(seconds=index)
        metadata = _token(
            account.id,
            f"token-{index}",
            issued_at=issued_at,
            updated_at=issued_at,
            expires_at=(_NOW + timedelta(days=30 + index)),
        )
        tokens.append(metadata)
        await repository.add_token(metadata)

    first = await repository.list_tokens(
        account.id,
        ControlPlaneServiceAccountPageRequest(
            offset=0,
            limit=2,
        ),
    )
    second = await repository.list_tokens(
        account.id,
        ControlPlaneServiceAccountPageRequest(
            offset=2,
            limit=2,
        ),
    )

    assert first.items == tuple(tokens[:2])
    assert first.page.next_offset == 2
    assert second.items == tuple(tokens[2:])
    assert second.page.next_offset is None


@pytest.mark.asyncio
async def test_list_tokens_rejects_unknown_account() -> None:
    repository = InMemoryControlPlaneServiceAccountRepository()

    with pytest.raises(ControlPlaneServiceAccountNotFoundError):
        await repository.list_tokens(uuid4())


@pytest.mark.asyncio
async def test_repository_replaces_token_status() -> None:
    repository, account = await _repository_with_account()
    metadata = _token(account.id, "first")

    await repository.add_token(metadata)

    revoked_at = _NOW + timedelta(seconds=1)
    replacement = replace(
        metadata,
        status=ControlPlaneApiTokenStatus.REVOKED,
        revoked_at=revoked_at,
        updated_at=revoked_at,
        revision=2,
    )

    result = await repository.replace_token(
        replacement,
        expected_revision=1,
    )

    assert result is replacement
    assert await repository.get_token(metadata.id) is replacement


@pytest.mark.asyncio
async def test_replace_rejects_unknown_token() -> None:
    repository, account = await _repository_with_account()

    with pytest.raises(ControlPlaneApiTokenNotFoundError):
        await repository.replace_token(
            _token(
                account.id,
                "missing",
                revision=2,
            ),
            expected_revision=1,
        )


@pytest.mark.asyncio
async def test_replace_rejects_stale_revision() -> None:
    repository, account = await _repository_with_account()
    metadata = _token(account.id, "first")

    await repository.add_token(metadata)

    replacement = replace(
        metadata,
        updated_at=_NOW + timedelta(seconds=1),
        revision=2,
    )

    with pytest.raises(
        ControlPlaneApiTokenConflictError,
        match="revision",
    ):
        await repository.replace_token(
            replacement,
            expected_revision=2,
        )


@pytest.mark.asyncio
async def test_replace_requires_exact_next_revision() -> None:
    repository, account = await _repository_with_account()
    metadata = _token(account.id, "first")

    await repository.add_token(metadata)

    replacement = replace(
        metadata,
        updated_at=_NOW + timedelta(seconds=1),
        revision=3,
    )

    with pytest.raises(
        ControlPlaneApiTokenConflictError,
        match="increment",
    ):
        await repository.replace_token(
            replacement,
            expected_revision=1,
        )


@pytest.mark.asyncio
async def test_replace_rejects_backwards_time() -> None:
    repository, account = await _repository_with_account()
    metadata = _token(
        account.id,
        "first",
        updated_at=_NOW + timedelta(seconds=2),
    )

    await repository.add_token(metadata)

    replacement = replace(
        metadata,
        updated_at=_NOW + timedelta(seconds=1),
        revision=2,
    )

    with pytest.raises(
        ControlPlaneApiTokenConflictError,
        match="backwards",
    ):
        await repository.replace_token(
            replacement,
            expected_revision=1,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "field",
    [
        "service_account_id",
        "token_digest",
        "label",
        "scopes",
        "resources",
        "expires_at",
    ],
)
async def test_replace_rejects_immutable_changes(
    field: str,
) -> None:
    repository, account = await _repository_with_account()
    metadata = _token(account.id, "first")

    await repository.add_token(metadata)

    updated_at = _NOW + timedelta(seconds=1)

    if field == "service_account_id":
        replacement = replace(
            metadata,
            service_account_id=uuid4(),
            updated_at=updated_at,
            revision=2,
        )
    elif field == "token_digest":
        replacement = replace(
            metadata,
            token_digest=_digest("rotated"),
            updated_at=updated_at,
            revision=2,
        )
    elif field == "label":
        replacement = replace(
            metadata,
            label="Changed Token",
            updated_at=updated_at,
            revision=2,
        )
    elif field == "scopes":
        replacement = replace(
            metadata,
            scopes=frozenset({"jobs.read"}),
            updated_at=updated_at,
            revision=2,
        )
    elif field == "resources":
        replacement = replace(
            metadata,
            resources=frozenset({"workflow:*"}),
            updated_at=updated_at,
            revision=2,
        )
    else:
        replacement = replace(
            metadata,
            expires_at=metadata.expires_at + timedelta(days=1),
            updated_at=updated_at,
            revision=2,
        )

    with pytest.raises(
        ControlPlaneApiTokenConflictError,
        match="immutable",
    ):
        await repository.replace_token(
            replacement,
            expected_revision=1,
        )


@pytest.mark.asyncio
async def test_snapshot_reports_token_statuses() -> None:
    repository, account = await _repository_with_account()

    active = _token(account.id, "active")

    revoked_at = _NOW + timedelta(seconds=1)
    revoked = _token(
        account.id,
        "revoked",
        status=ControlPlaneApiTokenStatus.REVOKED,
        revoked_at=revoked_at,
        updated_at=revoked_at,
    )

    expires_at = _NOW + timedelta(days=1)
    expired = _token(
        account.id,
        "expired",
        status=ControlPlaneApiTokenStatus.EXPIRED,
        expires_at=expires_at,
        updated_at=expires_at,
    )

    await repository.add_token(active)
    await repository.add_token(revoked)
    await repository.add_token(expired)

    snapshot = await repository.snapshot()

    assert snapshot.tokens == 3
    assert (
        snapshot.active_tokens,
        snapshot.revoked_tokens,
        snapshot.expired_tokens,
    ) == (1, 1, 1)


@pytest.mark.asyncio
async def test_close_clears_token_state() -> None:
    repository, account = await _repository_with_account()
    metadata = _token(account.id, "first")

    await repository.add_token(metadata)
    await repository.close()
    await repository.close()

    snapshot = await repository.snapshot()

    assert snapshot.closed
    assert snapshot.accounts == 0
    assert snapshot.tokens == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "operation",
    [
        "get",
        "digest",
        "list",
        "add",
        "replace",
    ],
)
async def test_token_operations_reject_after_close(
    operation: str,
) -> None:
    repository, account = await _repository_with_account()
    metadata = _token(account.id, "first")

    await repository.add_token(metadata)
    await repository.close()

    with pytest.raises(ControlPlaneServiceAccountRepositoryClosedError):
        if operation == "get":
            await repository.get_token(metadata.id)
        elif operation == "digest":
            await repository.get_token_by_digest(metadata.token_digest)
        elif operation == "list":
            await repository.list_tokens(account.id)
        elif operation == "add":
            await repository.add_token(_token(account.id, "second"))
        else:
            await repository.replace_token(
                replace(
                    metadata,
                    updated_at=(_NOW + timedelta(seconds=1)),
                    revision=2,
                ),
                expected_revision=1,
            )


@pytest.mark.asyncio
async def test_concurrent_duplicate_digests_are_serialized() -> None:
    repository, account = await _repository_with_account()

    first = _token(account.id, "shared")
    second = _token(account.id, "shared")

    results = await asyncio.gather(
        repository.add_token(first),
        repository.add_token(second),
        return_exceptions=True,
    )

    assert sum(result is None for result in results) == 1

    assert (
        sum(
            isinstance(
                result,
                ControlPlaneApiTokenAlreadyExistsError,
            )
            for result in results
        )
        == 1
    )

    assert (await repository.snapshot()).tokens == 1
