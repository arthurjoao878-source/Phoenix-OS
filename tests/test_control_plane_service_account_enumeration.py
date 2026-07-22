from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from phoenix_os.control_plane.service_account_authentication import (
    ControlPlaneServiceAccountAuthenticator,
)
from phoenix_os.control_plane.service_account_contracts import (
    ControlPlaneApiTokenMetadata,
    ControlPlaneServiceAccountRecord,
)
from phoenix_os.control_plane.service_account_lifecycle import (
    ControlPlaneApiTokenGrant,
    ControlPlaneServiceAccountLifecycleService,
)
from phoenix_os.control_plane.service_account_memory import (
    InMemoryControlPlaneServiceAccountRepository,
)

_NOW = datetime(
    2026,
    7,
    20,
    12,
    tzinfo=UTC,
)

_ACCOUNT_ID = UUID("10000000-0000-0000-0000-000000000001")
_TOKEN_ID = UUID("20000000-0000-0000-0000-000000000001")


class _Clock:
    def __init__(self) -> None:
        self.calls = 0

    def __call__(self) -> datetime:
        self.calls += 1
        return _NOW


class _TracingRepository(InMemoryControlPlaneServiceAccountRepository):
    def __init__(self) -> None:
        super().__init__()
        self.lookups: list[str] = []

    async def get_token_by_digest(
        self,
        token_digest: str,
    ) -> ControlPlaneApiTokenMetadata | None:
        self.lookups.append("token")

        return await super().get_token_by_digest(token_digest)

    async def get_account(
        self,
        service_account_id: UUID,
    ) -> ControlPlaneServiceAccountRecord | None:
        self.lookups.append("account")

        return await super().get_account(service_account_id)


@dataclass(slots=True)
class _Stack:
    repository: _TracingRepository
    lifecycle: ControlPlaneServiceAccountLifecycleService
    authenticator: ControlPlaneServiceAccountAuthenticator
    account: ControlPlaneServiceAccountRecord
    grant: ControlPlaneApiTokenGrant
    clock: _Clock


async def _stack() -> _Stack:
    repository = _TracingRepository()
    clock = _Clock()

    lifecycle = ControlPlaneServiceAccountLifecycleService(
        repository=repository,
        clock=lambda: _NOW,
        account_id_factory=lambda: _ACCOUNT_ID,
        token_id_factory=lambda: _TOKEN_ID,
        token_factory=lambda: "phx_sa_" + "A" * 48,
    )

    account = await lifecycle.create_account(
        name="release.bot",
        display_name="Release Bot",
    )

    grant = await lifecycle.issue_token(
        account.id,
        label="automation",
        scopes=frozenset(
            {
                "jobs.read",
            }
        ),
        expires_at=_NOW + timedelta(hours=1),
    )

    authenticator = ControlPlaneServiceAccountAuthenticator(
        repository,
        clock=clock,
    )

    repository.lookups.clear()

    return _Stack(
        repository=repository,
        lifecycle=lifecycle,
        authenticator=authenticator,
        account=account,
        grant=grant,
        clock=clock,
    )


@pytest.mark.asyncio
async def test_valid_unknown_and_malformed_candidates_use_same_lookup_shape() -> None:
    stack = await _stack()

    result = await stack.authenticator.authenticate(f"Bearer {stack.grant.token.value}")

    assert result is not None
    assert stack.repository.lookups == [
        "token",
        "account",
    ]
    assert stack.clock.calls == 1

    stack.repository.lookups.clear()

    result = await stack.authenticator.authenticate("Bearer phx_sa_" + "B" * 48)

    assert result is None
    assert stack.repository.lookups == [
        "token",
        "account",
    ]
    assert stack.clock.calls == 2

    stack.repository.lookups.clear()

    result = await stack.authenticator.authenticate("Bearer malformed")

    assert result is None
    assert stack.repository.lookups == [
        "token",
        "account",
    ]
    assert stack.clock.calls == 3


@pytest.mark.asyncio
async def test_missing_authorization_uses_same_lookup_shape() -> None:
    stack = await _stack()

    result = await stack.authenticator.authenticate(None)

    assert result is None
    assert stack.repository.lookups == [
        "token",
        "account",
    ]
    assert stack.clock.calls == 1


@pytest.mark.asyncio
async def test_disabled_account_remains_generic_after_uniform_lookup() -> None:
    stack = await _stack()

    await stack.lifecycle.disable_account(stack.account.id)

    stack.repository.lookups.clear()

    result = await stack.authenticator.authenticate(f"Bearer {stack.grant.token.value}")

    assert result is None
    assert stack.repository.lookups == [
        "token",
        "account",
    ]
    assert stack.clock.calls == 1


@pytest.mark.asyncio
async def test_repeated_unknown_candidates_never_change_public_result() -> None:
    stack = await _stack()

    candidates = (
        None,
        "",
        "Basic credentials",
        "Bearer malformed",
        "Bearer phx_sa_" + "C" * 48,
    )

    for candidate in candidates:
        stack.repository.lookups.clear()

        assert await stack.authenticator.authenticate(candidate) is None

        assert stack.repository.lookups == [
            "token",
            "account",
        ]
