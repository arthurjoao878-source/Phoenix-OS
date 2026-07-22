from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

import phoenix_os.control_plane as control_plane
from phoenix_os.control_plane.errors import (
    ControlPlaneServiceAccountConflictError,
    ControlPlaneServiceAccountLifecycleClosedError,
    ControlPlaneServiceAccountNotFoundError,
)
from phoenix_os.control_plane.service_account_contracts import (
    MAX_CONTROL_PLANE_API_TOKEN_LIFETIME,
    ControlPlaneApiToken,
    ControlPlaneApiTokenMetadata,
    ControlPlaneServiceAccountRecord,
    ControlPlaneServiceAccountRepository,
    ControlPlaneServiceAccountStatus,
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
    canonical_control_plane_api_token_record_bytes,
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
_TOKEN_ID = UUID("20000000-0000-0000-0000-000000000002")
_TOKEN_VALUE = "phx_sa_" + ("A" * 48)


@dataclass
class _MutableClock:
    current: datetime

    def __call__(self) -> datetime:
        return self.current


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
    clock: _MutableClock,
) -> ControlPlaneServiceAccountLifecycleService:
    return ControlPlaneServiceAccountLifecycleService(
        repository=repository,
        clock=clock,
        token_factory=lambda: _TOKEN_VALUE,
        account_id_factory=lambda: _ACCOUNT_ID,
        token_id_factory=lambda: _TOKEN_ID,
    )


def test_public_api_exports_lifecycle_service() -> None:
    assert control_plane.ControlPlaneApiTokenGrant is ControlPlaneApiTokenGrant
    assert (
        control_plane.ControlPlaneServiceAccountLifecycleService
        is ControlPlaneServiceAccountLifecycleService
    )
    assert hasattr(
        control_plane,
        ("ControlPlaneServiceAccountLifecycleClosedError"),
    )


def test_token_grant_redacts_plaintext() -> None:
    token = ControlPlaneApiToken(_TOKEN_VALUE)
    metadata = ControlPlaneApiTokenMetadata(
        id=_TOKEN_ID,
        service_account_id=_ACCOUNT_ID,
        label="Release Token",
        token_digest=token.digest,
        scopes=frozenset({"jobs.read"}),
        issued_at=_NOW,
        expires_at=_NOW + timedelta(days=1),
        updated_at=_NOW,
    )
    grant = ControlPlaneApiTokenGrant(
        metadata=metadata,
        token=token,
    )

    assert _TOKEN_VALUE not in repr(grant)
    assert "phx_sa_" not in repr(grant)
    assert str(grant.token) == "<redacted>"


def test_token_grant_rejects_digest_mismatch() -> None:
    token = ControlPlaneApiToken(_TOKEN_VALUE)
    metadata = ControlPlaneApiTokenMetadata(
        id=_TOKEN_ID,
        service_account_id=_ACCOUNT_ID,
        label="Release Token",
        token_digest="0" * 64,
        scopes=frozenset({"jobs.read"}),
        issued_at=_NOW,
        expires_at=_NOW + timedelta(days=1),
        updated_at=_NOW,
    )

    with pytest.raises(
        ValueError,
        match="does not match",
    ):
        ControlPlaneApiTokenGrant(
            metadata=metadata,
            token=token,
        )


@pytest.mark.parametrize(
    "kind",
    ["memory", "state"],
)
@pytest.mark.asyncio
async def test_create_account_persists(
    kind: str,
) -> None:
    repository = _repository(kind)
    clock = _MutableClock(_NOW)
    service = _service(repository, clock)

    account = await service.create_account(
        name=" Release.Bot ",
        display_name="Release Automation",
    )

    assert account.id == _ACCOUNT_ID
    assert account.name == "release.bot"
    assert await repository.get_account(account.id) == account


@pytest.mark.parametrize(
    "kind",
    ["memory", "state"],
)
@pytest.mark.asyncio
async def test_update_account_increments_revision(
    kind: str,
) -> None:
    repository = _repository(kind)
    clock = _MutableClock(_NOW)
    service = _service(repository, clock)

    account = await service.create_account(
        name="release.bot",
        display_name="Release Bot",
    )

    clock.current += timedelta(seconds=1)

    updated = await service.update_account(
        account.id,
        name="deploy.bot",
        display_name="Deployment Bot",
    )

    assert updated.name == "deploy.bot"
    assert updated.display_name == "Deployment Bot"
    assert updated.revision == 2
    assert updated.updated_at == clock.current
    assert await repository.get_account_by_name("release.bot") is None
    assert await repository.get_account_by_name("deploy.bot") == updated


@pytest.mark.asyncio
async def test_update_account_requires_change() -> None:
    repository = _repository("memory")
    clock = _MutableClock(_NOW)
    service = _service(repository, clock)

    account = await service.create_account(
        name="release.bot",
        display_name="Release Bot",
    )

    with pytest.raises(
        ValueError,
        match="at least one",
    ):
        await service.update_account(account.id)

    with pytest.raises(
        ValueError,
        match="does not change",
    ):
        await service.update_account(
            account.id,
            name="release.bot",
        )


@pytest.mark.asyncio
async def test_update_unknown_account_is_rejected() -> None:
    repository = _repository("memory")
    service = _service(
        repository,
        _MutableClock(_NOW),
    )

    with pytest.raises(ControlPlaneServiceAccountNotFoundError):
        await service.update_account(
            _ACCOUNT_ID,
            display_name="Missing",
        )


@pytest.mark.asyncio
async def test_revoked_account_cannot_be_updated() -> None:
    repository = _repository("memory")
    revoked = ControlPlaneServiceAccountRecord(
        id=_ACCOUNT_ID,
        name="release.bot",
        display_name="Release Bot",
        created_at=_NOW,
        updated_at=_NOW,
        status=(ControlPlaneServiceAccountStatus.REVOKED),
        revoked_at=_NOW,
    )
    await repository.add_account(revoked)

    service = _service(
        repository,
        _MutableClock(_NOW),
    )

    with pytest.raises(
        ControlPlaneServiceAccountConflictError,
        match="revoked",
    ):
        await service.update_account(
            revoked.id,
            display_name="Changed",
        )


@pytest.mark.parametrize(
    "kind",
    ["memory", "state"],
)
@pytest.mark.asyncio
async def test_issue_token_discloses_once_and_persists_digest(
    kind: str,
) -> None:
    repository = _repository(kind)
    clock = _MutableClock(_NOW)
    service = _service(repository, clock)

    account = await service.create_account(
        name="release.bot",
        display_name="Release Bot",
    )

    grant = await service.issue_token(
        account.id,
        label="Release Token",
        scopes=frozenset(
            {
                "jobs.create",
                "jobs.read",
            }
        ),
        resources=frozenset(
            {
                "job:*",
                "workflow:release",
            }
        ),
        expires_at=_NOW + timedelta(days=30),
    )

    assert grant.token.value == _TOKEN_VALUE
    assert grant.metadata.token_digest == grant.token.digest

    stored = await repository.get_token(grant.metadata.id)

    assert stored == grant.metadata
    assert not hasattr(stored, "value")
    assert _TOKEN_VALUE not in repr(stored)
    assert _TOKEN_VALUE.encode("ascii") not in (
        canonical_control_plane_api_token_record_bytes(grant.metadata)
    )


@pytest.mark.asyncio
async def test_issue_token_requires_existing_account() -> None:
    repository = _repository("memory")
    service = _service(
        repository,
        _MutableClock(_NOW),
    )

    with pytest.raises(ControlPlaneServiceAccountNotFoundError):
        await service.issue_token(
            _ACCOUNT_ID,
            label="Missing",
            scopes=frozenset({"jobs.read"}),
            expires_at=_NOW + timedelta(days=1),
        )


@pytest.mark.parametrize(
    "status",
    [
        ControlPlaneServiceAccountStatus.DISABLED,
        ControlPlaneServiceAccountStatus.REVOKED,
    ],
)
@pytest.mark.asyncio
async def test_inactive_account_cannot_issue_token(
    status: ControlPlaneServiceAccountStatus,
) -> None:
    repository = _repository("memory")

    account = ControlPlaneServiceAccountRecord(
        id=_ACCOUNT_ID,
        name="release.bot",
        display_name="Release Bot",
        created_at=_NOW,
        updated_at=_NOW,
        status=status,
        disabled_at=(_NOW if status is ControlPlaneServiceAccountStatus.DISABLED else None),
        revoked_at=(_NOW if status is ControlPlaneServiceAccountStatus.REVOKED else None),
    )
    await repository.add_account(account)

    service = _service(
        repository,
        _MutableClock(_NOW),
    )

    with pytest.raises(
        ControlPlaneServiceAccountConflictError,
        match="inactive",
    ):
        await service.issue_token(
            account.id,
            label="Rejected",
            scopes=frozenset({"jobs.read"}),
            expires_at=_NOW + timedelta(days=1),
        )


@pytest.mark.asyncio
async def test_token_expiration_is_mandatory_and_future() -> None:
    repository = _repository("memory")
    service = _service(
        repository,
        _MutableClock(_NOW),
    )
    account = await service.create_account(
        name="release.bot",
        display_name="Release Bot",
    )

    with pytest.raises(
        ValueError,
        match="expires_at",
    ):
        await service.issue_token(
            account.id,
            label="Expired",
            scopes=frozenset({"jobs.read"}),
            expires_at=_NOW,
        )


@pytest.mark.asyncio
async def test_token_lifetime_is_bounded() -> None:
    repository = _repository("memory")
    service = _service(
        repository,
        _MutableClock(_NOW),
    )
    account = await service.create_account(
        name="release.bot",
        display_name="Release Bot",
    )

    with pytest.raises(
        ValueError,
        match="lifetime",
    ):
        await service.issue_token(
            account.id,
            label="Too Long",
            scopes=frozenset({"jobs.read"}),
            expires_at=(_NOW + MAX_CONTROL_PLANE_API_TOKEN_LIFETIME + timedelta(seconds=1)),
        )


@pytest.mark.asyncio
async def test_invalid_token_factory_output_is_rejected() -> None:
    repository = _repository("memory")
    service = ControlPlaneServiceAccountLifecycleService(
        repository=repository,
        clock=lambda: _NOW,
        token_factory=lambda: "invalid",
        account_id_factory=lambda: _ACCOUNT_ID,
        token_id_factory=lambda: _TOKEN_ID,
    )
    account = await service.create_account(
        name="release.bot",
        display_name="Release Bot",
    )

    with pytest.raises(
        ValueError,
        match="phx_sa_",
    ):
        await service.issue_token(
            account.id,
            label="Invalid",
            scopes=frozenset({"jobs.read"}),
            expires_at=_NOW + timedelta(days=1),
        )


@pytest.mark.asyncio
async def test_snapshot_contains_only_counters() -> None:
    repository = _repository("memory")
    clock = _MutableClock(_NOW)
    service = _service(repository, clock)

    account = await service.create_account(
        name="release.bot",
        display_name="Release Bot",
    )

    clock.current += timedelta(seconds=1)

    await service.update_account(
        account.id,
        display_name="Release Automation",
    )

    await service.issue_token(
        account.id,
        label="Release Token",
        scopes=frozenset({"jobs.read"}),
        expires_at=_NOW + timedelta(days=1),
    )

    snapshot = await service.snapshot()

    assert snapshot.accounts_created == 1
    assert snapshot.accounts_updated == 1
    assert snapshot.tokens_issued == 1
    assert _TOKEN_VALUE not in repr(snapshot)


@pytest.mark.asyncio
async def test_close_preserves_borrowed_repository() -> None:
    repository = _repository("memory")
    service = _service(
        repository,
        _MutableClock(_NOW),
    )

    await service.close()
    await service.close()

    snapshot = await service.snapshot()

    assert snapshot.closed
    assert not repository.closed

    with pytest.raises(ControlPlaneServiceAccountLifecycleClosedError):
        await service.create_account(
            name="release.bot",
            display_name="Release Bot",
        )


@pytest.mark.asyncio
async def test_naive_clock_is_rejected() -> None:
    repository = _repository("memory")
    service = ControlPlaneServiceAccountLifecycleService(
        repository=repository,
        clock=lambda: datetime(
            2026,
            7,
            20,
            12,
        ),
    )

    with pytest.raises(
        ValueError,
        match="timezone-aware",
    ):
        await service.create_account(
            name="release.bot",
            display_name="Release Bot",
        )


@pytest.mark.asyncio
async def test_state_repository_recovers_issued_metadata() -> None:
    store = MemoryStateStore()
    repository = StateControlPlaneServiceAccountRepository(store)
    service = _service(
        repository,
        _MutableClock(_NOW),
    )

    account = await service.create_account(
        name="release.bot",
        display_name="Release Bot",
    )
    grant = await service.issue_token(
        account.id,
        label="Release Token",
        scopes=frozenset({"jobs.read"}),
        expires_at=_NOW + timedelta(days=30),
    )

    recovered = StateControlPlaneServiceAccountRepository(store)

    assert await recovered.get_account(account.id) == account
    assert await recovered.get_token(grant.metadata.id) == grant.metadata


def test_lifecycle_snapshot_rejects_negative_counts() -> None:
    with pytest.raises(
        ValueError,
        match="negative",
    ):
        (
            control_plane.ControlPlaneServiceAccountLifecycleSnapshot(
                closed=False,
                accounts_created=-1,
                accounts_updated=0,
                tokens_issued=0,
            )
        )


def test_grant_metadata_remains_credential_safe() -> None:
    token = ControlPlaneApiToken(_TOKEN_VALUE)
    metadata = ControlPlaneApiTokenMetadata(
        id=_TOKEN_ID,
        service_account_id=_ACCOUNT_ID,
        label="Release Token",
        token_digest=token.digest,
        scopes=frozenset({"jobs.read"}),
        issued_at=_NOW,
        expires_at=_NOW + timedelta(days=1),
        updated_at=_NOW,
    )

    changed = replace(
        metadata,
        label="Renamed Token",
    )

    assert changed.token_digest == token.digest
    assert _TOKEN_VALUE not in repr(changed)
