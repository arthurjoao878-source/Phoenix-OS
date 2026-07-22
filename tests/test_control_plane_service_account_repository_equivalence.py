from __future__ import annotations

import hashlib
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

import phoenix_os.control_plane as control_plane
from phoenix_os.control_plane.service_account_contracts import (
    ControlPlaneApiTokenMetadata,
    ControlPlaneApiTokenStatus,
    ControlPlaneServiceAccountRecord,
    ControlPlaneServiceAccountRepository,
)
from phoenix_os.control_plane.service_account_memory import (
    InMemoryControlPlaneServiceAccountRepository,
)
from phoenix_os.control_plane.service_account_state import (
    StateControlPlaneServiceAccountRepository,
)
from phoenix_os.state import MemoryStateStore

_NOW = datetime(2026, 7, 20, 12, tzinfo=UTC)
_ACCOUNT_ID = UUID("10000000-0000-0000-0000-000000000001")
_TOKEN_ID = UUID("20000000-0000-0000-0000-000000000002")


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("ascii")).hexdigest()


def _account() -> ControlPlaneServiceAccountRecord:
    return ControlPlaneServiceAccountRecord(
        id=_ACCOUNT_ID,
        name="release.bot",
        display_name="Release Bot",
        created_at=_NOW,
        updated_at=_NOW,
    )


def _token() -> ControlPlaneApiTokenMetadata:
    return ControlPlaneApiTokenMetadata(
        id=_TOKEN_ID,
        service_account_id=_ACCOUNT_ID,
        label="Release Token",
        token_digest=_digest("release-token"),
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
        issued_at=_NOW,
        expires_at=_NOW + timedelta(days=30),
        updated_at=_NOW,
    )


def _repositories() -> tuple[
    ControlPlaneServiceAccountRepository,
    ...,
]:
    return (
        InMemoryControlPlaneServiceAccountRepository(),
        StateControlPlaneServiceAccountRepository(MemoryStateStore()),
    )


def _typecheck_protocol_conformance() -> None:
    memory_repository: ControlPlaneServiceAccountRepository = (
        InMemoryControlPlaneServiceAccountRepository()
    )

    state_repository: ControlPlaneServiceAccountRepository = (
        StateControlPlaneServiceAccountRepository(MemoryStateStore())
    )

    _ = memory_repository, state_repository


def test_control_plane_package_exports_service_account_api() -> None:
    expected = (
        "ControlPlaneApiToken",
        "ControlPlaneApiTokenMetadata",
        "ControlPlaneApiTokenPage",
        "ControlPlaneApiTokenRestriction",
        "ControlPlaneApiTokenStatus",
        "ControlPlaneServiceAccountPage",
        "ControlPlaneServiceAccountPageInfo",
        "ControlPlaneServiceAccountPageRequest",
        "ControlPlaneServiceAccountRecord",
        "ControlPlaneServiceAccountRegistrySnapshot",
        "ControlPlaneServiceAccountRepository",
        "ControlPlaneServiceAccountStatus",
        "InMemoryControlPlaneServiceAccountRepository",
        "StateControlPlaneServiceAccountRepository",
        "canonical_control_plane_api_token_record_bytes",
        "canonical_control_plane_service_account_record_bytes",
        "control_plane_api_token_record_digest",
        "control_plane_service_account_record_digest",
        "ControlPlaneApiTokenAlreadyExistsError",
        "ControlPlaneApiTokenCapacityError",
        "ControlPlaneApiTokenConflictError",
        "ControlPlaneApiTokenNotFoundError",
        "ControlPlaneServiceAccountAlreadyExistsError",
        "ControlPlaneServiceAccountCapacityError",
        "ControlPlaneServiceAccountConflictError",
        "ControlPlaneServiceAccountCorruptionError",
        "ControlPlaneServiceAccountNotFoundError",
        "ControlPlaneServiceAccountPersistenceError",
        "ControlPlaneServiceAccountRepositoryClosedError",
        "ControlPlaneServiceAccountSchemaError",
    )

    missing = tuple(name for name in expected if not hasattr(control_plane, name))

    assert missing == ()


@pytest.mark.asyncio
async def test_repositories_have_equivalent_lifecycle() -> None:
    repositories = _repositories()
    account = _account()
    token = _token()

    initial_results: list[tuple[object, ...]] = []

    for repository in repositories:
        await repository.add_account(account)
        await repository.add_token(token)

        initial_results.append(
            (
                await repository.get_account(account.id),
                await repository.get_account_by_name(" RELEASE.BOT "),
                await repository.get_token(token.id),
                await repository.get_token_by_digest(token.token_digest.upper()),
                await repository.list_accounts(),
                await repository.list_tokens(account.id),
                await repository.snapshot(),
            )
        )

    assert initial_results[0] == initial_results[1]

    account_update = replace(
        account,
        display_name="Release Automation",
        updated_at=_NOW + timedelta(seconds=1),
        revision=2,
    )

    revoked_at = _NOW + timedelta(seconds=2)
    token_update = replace(
        token,
        status=ControlPlaneApiTokenStatus.REVOKED,
        revoked_at=revoked_at,
        updated_at=revoked_at,
        revision=2,
    )

    updated_results: list[tuple[object, ...]] = []

    for repository in repositories:
        assert (
            await repository.replace_account(
                account_update,
                expected_revision=1,
            )
            == account_update
        )
        assert (
            await repository.replace_token(
                token_update,
                expected_revision=1,
            )
            == token_update
        )

        updated_results.append(
            (
                await repository.get_account(account.id),
                await repository.get_token(token.id),
                await repository.list_accounts(),
                await repository.list_tokens(account.id),
                await repository.snapshot(),
            )
        )

    assert updated_results[0] == updated_results[1]

    for repository in repositories:
        await repository.close()


@pytest.mark.asyncio
async def test_repositories_match_missing_lookups() -> None:
    missing_account_id = UUID("30000000-0000-0000-0000-000000000003")
    missing_token_id = UUID("40000000-0000-0000-0000-000000000004")
    missing_digest = _digest("missing-token")

    results: list[tuple[object, ...]] = []

    for repository in _repositories():
        results.append(
            (
                await repository.get_account(missing_account_id),
                await repository.get_account_by_name("missing.bot"),
                await repository.get_token(missing_token_id),
                await repository.get_token_by_digest(missing_digest),
            )
        )

    assert results == [
        (None, None, None, None),
        (None, None, None, None),
    ]
