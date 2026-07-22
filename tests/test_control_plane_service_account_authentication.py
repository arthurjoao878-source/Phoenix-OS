from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

import phoenix_os.control_plane.service_account_authentication as auth_module
from phoenix_os.control_plane import (
    ControlPlaneServiceAccountAuthentication,
    ControlPlaneServiceAccountAuthenticator,
)
from phoenix_os.control_plane.service_account_contracts import (
    ControlPlaneApiTokenRestriction,
    ControlPlaneApiTokenStatus,
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
_TOKEN_IDS = tuple(UUID(f"20000000-0000-0000-0000-{index:012d}") for index in range(1, 7))
_TOKEN_VALUES = tuple("phx_sa_" + (character * 48) for character in "ABCDEF")
_UNKNOWN_TOKEN = "phx_sa_" + ("Z" * 48)


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


async def _setup(
    kind: str,
    now: list[datetime],
    *,
    expires_at: datetime | None = None,
    restriction: (ControlPlaneApiTokenRestriction | None) = None,
) -> tuple[
    ControlPlaneServiceAccountRepository,
    ControlPlaneServiceAccountLifecycleService,
    ControlPlaneServiceAccountRecord,
    ControlPlaneApiTokenGrant,
]:
    repository = _repository(kind)
    service = _service(repository, now)
    account = await service.create_account(
        name="release.bot",
        display_name="Release Bot",
    )
    grant = await service.issue_token(
        account.id,
        label="Release Token",
        scopes=frozenset({"jobs.read"}),
        resources=frozenset({"job:*"}),
        restriction=restriction,
        expires_at=(now[0] + timedelta(days=1) if expires_at is None else expires_at),
    )

    return (
        repository,
        service,
        account,
        grant,
    )


@pytest.mark.parametrize(
    "kind",
    ["memory", "state"],
)
@pytest.mark.asyncio
async def test_authenticates_valid_machine_bearer(
    kind: str,
) -> None:
    now = [_NOW]
    repository, _, account, grant = await _setup(
        kind,
        now,
    )
    authenticator = ControlPlaneServiceAccountAuthenticator(
        repository,
        clock=lambda: now[0],
    )

    evidence = await authenticator.authenticate(f"Bearer {grant.token.value}")

    assert isinstance(
        evidence,
        ControlPlaneServiceAccountAuthentication,
    )
    assert evidence.service_account_id == account.id
    assert evidence.token_id == grant.metadata.id
    assert evidence.account_name == "release.bot"
    assert evidence.principal_name == ("service-account:release.bot")
    assert evidence.scopes == frozenset({"jobs.read"})
    assert evidence.resources == frozenset({"job:*"})
    assert evidence.token_version == 1
    assert evidence.account_revision == 1
    assert evidence.token_revision == 1
    assert evidence.authenticated_at == now[0]

    rendered = repr(evidence)

    assert grant.token.value not in rendered
    assert grant.metadata.token_digest not in rendered


@pytest.mark.parametrize(
    "authorization",
    [
        None,
        "",
        "Bearer",
        f"Basic {_UNKNOWN_TOKEN}",
        f" Bearer {_UNKNOWN_TOKEN}",
        f"Bearer  {_UNKNOWN_TOKEN}",
        f"Bearer {_UNKNOWN_TOKEN} ",
        f"Bearer\t{_UNKNOWN_TOKEN}",
        "Bearer wrong-prefix",
        f"Bearer {_UNKNOWN_TOKEN}",
        "Bearer " + ("A" * 300),
    ],
)
@pytest.mark.asyncio
async def test_failures_are_generic(
    authorization: str | None,
) -> None:
    now = [_NOW]
    repository, _, _, _ = await _setup(
        "memory",
        now,
    )
    authenticator = ControlPlaneServiceAccountAuthenticator(
        repository,
        clock=lambda: now[0],
    )

    assert await authenticator.authenticate(authorization) is None


@pytest.mark.parametrize(
    "kind",
    ["memory", "state"],
)
@pytest.mark.asyncio
async def test_revoked_token_is_rejected(
    kind: str,
) -> None:
    now = [_NOW]
    repository, service, _, grant = await _setup(
        kind,
        now,
    )
    authenticator = ControlPlaneServiceAccountAuthenticator(
        repository,
        clock=lambda: now[0],
    )

    now[0] += timedelta(minutes=1)

    assert await service.revoke_token(grant.metadata.id)

    assert await authenticator.authenticate(f"Bearer {grant.token.value}") is None


@pytest.mark.parametrize(
    "kind",
    ["memory", "state"],
)
@pytest.mark.asyncio
async def test_expired_token_is_reconciled(
    kind: str,
) -> None:
    now = [_NOW]
    repository, _, _, grant = await _setup(
        kind,
        now,
        expires_at=_NOW + timedelta(minutes=1),
    )
    authenticator = ControlPlaneServiceAccountAuthenticator(
        repository,
        clock=lambda: now[0],
    )

    now[0] += timedelta(minutes=2)

    assert await authenticator.authenticate(f"Bearer {grant.token.value}") is None

    stored = await repository.get_token(grant.metadata.id)

    assert stored is not None
    assert stored.status is ControlPlaneApiTokenStatus.EXPIRED
    assert stored.updated_at == now[0]
    assert stored.revision == 2


@pytest.mark.parametrize(
    ("kind", "status"),
    [
        (
            "memory",
            ControlPlaneServiceAccountStatus.DISABLED,
        ),
        (
            "memory",
            ControlPlaneServiceAccountStatus.REVOKED,
        ),
        (
            "state",
            ControlPlaneServiceAccountStatus.DISABLED,
        ),
        (
            "state",
            ControlPlaneServiceAccountStatus.REVOKED,
        ),
    ],
)
@pytest.mark.asyncio
async def test_inactive_account_is_rejected(
    kind: str,
    status: ControlPlaneServiceAccountStatus,
) -> None:
    now = [_NOW]
    repository, _, account, grant = await _setup(
        kind,
        now,
    )
    now[0] += timedelta(minutes=1)

    replacement = replace(
        account,
        status=status,
        disabled_at=(now[0] if status is ControlPlaneServiceAccountStatus.DISABLED else None),
        revoked_at=(now[0] if status is ControlPlaneServiceAccountStatus.REVOKED else None),
        updated_at=now[0],
        revision=2,
    )

    await repository.replace_account(
        replacement,
        expected_revision=1,
    )

    authenticator = ControlPlaneServiceAccountAuthenticator(
        repository,
        clock=lambda: now[0],
    )

    assert await authenticator.authenticate(f"Bearer {grant.token.value}") is None


@pytest.mark.parametrize(
    "kind",
    ["memory", "state"],
)
@pytest.mark.asyncio
async def test_restricted_token_fails_closed(
    kind: str,
) -> None:
    now = [_NOW]
    restriction = ControlPlaneApiTokenRestriction(
        allowed_client_networks=("10.0.0.0/8",),
    )
    repository, _, _, grant = await _setup(
        kind,
        now,
        restriction=restriction,
    )
    authenticator = ControlPlaneServiceAccountAuthenticator(
        repository,
        clock=lambda: now[0],
    )

    assert await authenticator.authenticate(f"Bearer {grant.token.value}") is None


@pytest.mark.parametrize(
    "kind",
    ["memory", "state"],
)
@pytest.mark.asyncio
async def test_rotation_overlap_accepts_both_until_expiry(
    kind: str,
) -> None:
    now = [_NOW]
    repository, service, _, original = await _setup(
        kind,
        now,
    )

    now[0] += timedelta(minutes=1)

    successor = await service.rotate_token(
        original.metadata.id,
        expires_at=now[0] + timedelta(days=1),
        overlap=timedelta(minutes=5),
    )
    authenticator = ControlPlaneServiceAccountAuthenticator(
        repository,
        clock=lambda: now[0],
    )

    assert await authenticator.authenticate(f"Bearer {original.token.value}") is not None
    assert await authenticator.authenticate(f"Bearer {successor.token.value}") is not None

    now[0] += timedelta(minutes=6)

    assert await authenticator.authenticate(f"Bearer {original.token.value}") is None
    assert await authenticator.authenticate(f"Bearer {successor.token.value}") is not None


@pytest.mark.asyncio
async def test_digest_compare_runs_for_hit_and_miss(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = [_NOW]
    repository, _, _, grant = await _setup(
        "memory",
        now,
    )
    authenticator = ControlPlaneServiceAccountAuthenticator(
        repository,
        clock=lambda: now[0],
    )
    original_compare = auth_module._compare_digest
    calls: list[tuple[str, str]] = []

    def tracked(
        left: str,
        right: str,
    ) -> bool:
        calls.append((left, right))
        return original_compare(left, right)

    monkeypatch.setattr(
        auth_module,
        "_compare_digest",
        tracked,
    )

    assert await authenticator.authenticate(f"Bearer {_UNKNOWN_TOKEN}") is None

    miss_calls = len(calls)

    assert miss_calls >= 1

    assert await authenticator.authenticate(f"Bearer {grant.token.value}") is not None
    assert len(calls) > miss_calls


@pytest.mark.asyncio
async def test_clock_must_be_timezone_aware() -> None:
    now = [_NOW]
    repository, _, _, grant = await _setup(
        "memory",
        now,
    )
    authenticator = ControlPlaneServiceAccountAuthenticator(
        repository,
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
        await authenticator.authenticate(f"Bearer {grant.token.value}")


def test_authentication_exports_are_public() -> None:
    import phoenix_os.control_plane as control_plane

    assert (
        control_plane.ControlPlaneServiceAccountAuthenticator
        is ControlPlaneServiceAccountAuthenticator
    )
    assert (
        control_plane.ControlPlaneServiceAccountAuthentication
        is ControlPlaneServiceAccountAuthentication
    )
