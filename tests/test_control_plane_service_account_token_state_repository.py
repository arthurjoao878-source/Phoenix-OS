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
    ControlPlaneServiceAccountCorruptionError,
    ControlPlaneServiceAccountNotFoundError,
    ControlPlaneServiceAccountRepositoryClosedError,
)
from phoenix_os.control_plane.service_account_contracts import (
    ControlPlaneApiTokenMetadata,
    ControlPlaneApiTokenStatus,
    ControlPlaneServiceAccountPageRequest,
    ControlPlaneServiceAccountRecord,
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
        label=f"{seed.title()} Token",
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


def _token_record_key(
    token_id: UUID,
) -> StateKey[dict[str, object]]:
    return StateKey(
        _NAMESPACE,
        f"token_record_{token_id.hex}",
        dict,
    )


def _token_digest_key(
    digest: str,
) -> StateKey[dict[str, object]]:
    return StateKey(
        _NAMESPACE,
        f"token_digest_{digest}",
        dict,
    )


async def _repository_with_account(
    *,
    max_tokens: int = 8,
) -> tuple[
    StateControlPlaneServiceAccountRepository,
    MemoryStateStore,
    ControlPlaneServiceAccountRecord,
]:
    store = MemoryStateStore()
    repository = StateControlPlaneServiceAccountRepository(
        store,
        max_tokens_per_account=max_tokens,
    )
    account = _account()
    await repository.add_account(account)

    return repository, store, account


@pytest.mark.asyncio
async def test_state_repository_adds_and_reads_token() -> None:
    repository, _, account = await _repository_with_account()
    metadata = _token(account.id, "first")

    await repository.add_token(metadata)

    assert await repository.get_token(metadata.id) == metadata
    assert await repository.get_token_by_digest(metadata.token_digest.upper()) == metadata


@pytest.mark.asyncio
async def test_state_repository_returns_none_for_unknown() -> None:
    repository, _, _ = await _repository_with_account()

    assert await repository.get_token(uuid4()) is None
    assert await repository.get_token_by_digest(_digest("missing")) is None


@pytest.mark.asyncio
async def test_add_token_requires_account() -> None:
    repository = StateControlPlaneServiceAccountRepository(MemoryStateStore())

    with pytest.raises(ControlPlaneServiceAccountNotFoundError):
        await repository.add_token(_token(uuid4(), "orphan"))


@pytest.mark.asyncio
async def test_state_repository_rejects_duplicate_id() -> None:
    repository, _, account = await _repository_with_account()
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
async def test_state_repository_rejects_duplicate_digest() -> None:
    repository, _, account = await _repository_with_account()

    await repository.add_token(_token(account.id, "shared"))

    with pytest.raises(
        ControlPlaneApiTokenAlreadyExistsError,
        match="digest",
    ):
        await repository.add_token(_token(account.id, "shared"))


@pytest.mark.asyncio
async def test_state_repository_enforces_token_capacity() -> None:
    repository, _, account = await _repository_with_account(max_tokens=1)

    await repository.add_token(_token(account.id, "first"))

    with pytest.raises(ControlPlaneApiTokenCapacityError):
        await repository.add_token(_token(account.id, "second"))


@pytest.mark.asyncio
async def test_state_repository_survives_restart() -> None:
    repository, store, account = await _repository_with_account()
    metadata = _token(account.id, "first")

    await repository.add_token(metadata)
    await repository.close()

    recovered = StateControlPlaneServiceAccountRepository(store)

    assert await recovered.get_token(metadata.id) == metadata
    assert await recovered.get_token_by_digest(metadata.token_digest) == metadata


@pytest.mark.asyncio
async def test_state_repository_lists_and_paginates_tokens() -> None:
    repository, _, account = await _repository_with_account()
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
        ControlPlaneServiceAccountPageRequest(limit=2),
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
    repository = StateControlPlaneServiceAccountRepository(MemoryStateStore())

    with pytest.raises(ControlPlaneServiceAccountNotFoundError):
        await repository.list_tokens(uuid4())


@pytest.mark.asyncio
async def test_state_repository_replaces_token_status() -> None:
    repository, _, account = await _repository_with_account()
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

    assert result == replacement
    assert await repository.get_token(metadata.id) == replacement


@pytest.mark.asyncio
async def test_replace_token_rejects_unknown() -> None:
    repository, _, account = await _repository_with_account()

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
async def test_replace_token_rejects_stale_revision() -> None:
    repository, _, account = await _repository_with_account()
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
async def test_replace_token_rejects_revision_jump() -> None:
    repository, _, account = await _repository_with_account()
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
async def test_replace_token_rejects_immutable_digest() -> None:
    repository, _, account = await _repository_with_account()
    metadata = _token(account.id, "first")
    await repository.add_token(metadata)

    replacement = replace(
        metadata,
        token_digest=_digest("changed"),
        updated_at=_NOW + timedelta(seconds=1),
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
async def test_concurrent_duplicate_digest_is_atomic() -> None:
    repository, _, account = await _repository_with_account()
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


@pytest.mark.asyncio
async def test_snapshot_reports_token_statuses() -> None:
    repository, _, account = await _repository_with_account()

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
async def test_token_operations_reject_after_close() -> None:
    repository, _, account = await _repository_with_account()
    metadata = _token(account.id, "first")
    await repository.add_token(metadata)
    await repository.close()

    with pytest.raises(ControlPlaneServiceAccountRepositoryClosedError):
        await repository.get_token(metadata.id)

    with pytest.raises(ControlPlaneServiceAccountRepositoryClosedError):
        await repository.get_token_by_digest(metadata.token_digest)

    with pytest.raises(ControlPlaneServiceAccountRepositoryClosedError):
        await repository.list_tokens(account.id)


@pytest.mark.asyncio
async def test_missing_digest_index_is_corruption() -> None:
    repository, store, account = await _repository_with_account()
    metadata = _token(account.id, "first")
    await repository.add_token(metadata)

    stored_index = await store.get(_token_digest_key(metadata.token_digest))
    assert stored_index is not None

    await store.delete(
        _token_digest_key(metadata.token_digest),
        expected_version=stored_index.version,
    )

    with pytest.raises(
        ControlPlaneServiceAccountCorruptionError,
        match="incomplete",
    ):
        await repository.get_token(metadata.id)


@pytest.mark.asyncio
async def test_digest_index_mismatch_is_corruption() -> None:
    repository, store, account = await _repository_with_account()
    metadata = _token(account.id, "first")
    await repository.add_token(metadata)

    stored_index = await store.get(_token_digest_key(metadata.token_digest))
    assert stored_index is not None

    altered = dict(stored_index.value)
    altered["revision"] = 2

    await store.put(
        _token_digest_key(metadata.token_digest),
        altered,
        expected_version=stored_index.version,
    )

    with pytest.raises(
        ControlPlaneServiceAccountCorruptionError,
        match="do not match",
    ):
        await repository.get_token(metadata.id)


@pytest.mark.asyncio
async def test_orphan_digest_index_is_corruption() -> None:
    repository, store, account = await _repository_with_account()
    metadata = _token(account.id, "orphan")

    await store.put(
        _token_digest_key(metadata.token_digest),
        {
            "schema_version": 1,
            "kind": ("phoenix.control-plane.service-account.api-token.digest-index"),
            "token_id": str(metadata.id),
            "service_account_id": str(account.id),
            "token_digest": metadata.token_digest,
            "token_version": 1,
            "revision": 1,
            "record_digest": "0" * 64,
        },
        expected_version=ABSENT_VERSION,
    )

    with pytest.raises(
        ControlPlaneServiceAccountCorruptionError,
        match="incomplete",
    ):
        await repository.list_tokens(account.id)


@pytest.mark.asyncio
async def test_wrong_token_record_key_is_corruption() -> None:
    repository, store, account = await _repository_with_account()
    metadata = _token(account.id, "first")
    await repository.add_token(metadata)

    stored_record = await store.get(_token_record_key(metadata.id))
    assert stored_record is not None

    await store.put(
        _token_record_key(uuid4()),
        dict(stored_record.value),
        expected_version=ABSENT_VERSION,
    )

    with pytest.raises(
        ControlPlaneServiceAccountCorruptionError,
        match="state key",
    ):
        await repository.list_tokens(account.id)
