from __future__ import annotations

import asyncio
import hmac
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from phoenix_os.control_plane import (
    ControlPlaneDurableCsrfSecret,
    ControlPlaneDurableSessionAccessClosedError,
    ControlPlaneDurableSessionAccessService,
    ControlPlaneDurableSessionAuthentication,
    ControlPlaneDurableSessionConflictError,
    ControlPlaneDurableSessionPolicy,
    ControlPlaneDurableSessionStatus,
    ControlPlaneDurableSessionTerminationReason,
    ControlPlaneDurableSessionToken,
    ControlPlaneOperatorAuthentication,
    ControlPlaneOperatorRecord,
    ControlPlaneOperatorRole,
    ControlPlaneOperatorStatus,
    ControlPlaneOperatorToken,
    InMemoryControlPlaneDurableSessionRepository,
    InMemoryControlPlaneOperatorRegistry,
    StateControlPlaneDurableSessionRepository,
)
from phoenix_os.state import MemoryStateStore

NOW = datetime(2026, 7, 19, 18, 0, tzinfo=UTC)
OPERATOR_ID = UUID(int=700)
OPERATOR_TOKEN = ControlPlaneOperatorToken("operator-token-0123456789abcdef-0001")
POLICY = ControlPlaneDurableSessionPolicy(
    absolute_ttl=timedelta(hours=2),
    idle_ttl=timedelta(minutes=20),
    rotation_interval=timedelta(minutes=10),
)


class _Clock:
    def __init__(self, now: datetime = NOW) -> None:
        self.now = now

    def __call__(self) -> datetime:
        return self.now


class _Secrets:
    def __init__(self, prefix: str) -> None:
        self.prefix = prefix
        self.value = 0

    def __call__(self) -> str:
        self.value += 1
        return f"{self.prefix}-{self.value:048d}"


def _operator(
    *,
    status: ControlPlaneOperatorStatus = ControlPlaneOperatorStatus.ACTIVE,
    role: ControlPlaneOperatorRole = ControlPlaneOperatorRole.MAINTAINER,
    token_version: int = 1,
    revision: int = 1,
    updated_at: datetime = NOW,
) -> ControlPlaneOperatorRecord:
    return ControlPlaneOperatorRecord(
        id=OPERATOR_ID,
        username="alice",
        display_name="Alice",
        role=role,
        token_digest=OPERATOR_TOKEN.digest,
        created_at=NOW,
        updated_at=updated_at,
        status=status,
        disabled_at=updated_at if status is ControlPlaneOperatorStatus.DISABLED else None,
        revoked_at=updated_at if status is ControlPlaneOperatorStatus.REVOKED else None,
        token_version=token_version,
        revision=revision,
    )


def _evidence(record: ControlPlaneOperatorRecord) -> ControlPlaneOperatorAuthentication:
    return ControlPlaneOperatorAuthentication(
        operator_id=record.id,
        principal=record.principal(),
        token_version=record.token_version,
        authenticated_at=NOW,
    )


async def _service(
    *,
    clock: _Clock | None = None,
    repository: InMemoryControlPlaneDurableSessionRepository | None = None,
    operator: ControlPlaneOperatorRecord | None = None,
) -> tuple[
    ControlPlaneDurableSessionAccessService,
    InMemoryControlPlaneOperatorRegistry,
    InMemoryControlPlaneDurableSessionRepository,
    _Clock,
]:
    resolved_clock = _Clock() if clock is None else clock
    registry = InMemoryControlPlaneOperatorRegistry()
    await registry.add(_operator() if operator is None else operator)
    resolved_repository = (
        InMemoryControlPlaneDurableSessionRepository() if repository is None else repository
    )
    service = ControlPlaneDurableSessionAccessService(
        registry=registry,
        repository=resolved_repository,
        policy=POLICY,
        clock=resolved_clock,
        token_factory=_Secrets("session"),
        csrf_factory=_Secrets("csrf"),
    )
    return service, registry, resolved_repository, resolved_clock


@pytest.mark.asyncio
async def test_issue_persists_only_digests_and_returns_redacted_secrets() -> None:
    service, registry, repository, _ = await _service()
    operator = await registry.get(OPERATOR_ID)
    assert operator is not None

    grant = await service.issue(_evidence(operator))
    record = await repository.get(grant.session_id)

    assert record is not None
    assert record.token_digest == grant.token.digest
    assert record.csrf_digest == grant.csrf_secret.digest
    assert grant.token.value not in repr(record)
    assert grant.csrf_secret.value not in repr(record)
    assert repr(grant.token) == "ControlPlaneDurableSessionToken(<redacted>)"
    assert repr(grant.csrf_secret) == "ControlPlaneDurableCsrfSecret(<redacted>)"
    assert record.operator_revision == operator.revision
    assert record.operator_token_version == operator.token_version


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["missing", "disabled", "token", "permissions"])
async def test_issue_rejects_stale_operator_evidence(change: str) -> None:
    service, registry, _, _ = await _service()
    operator = await registry.get(OPERATOR_ID)
    assert operator is not None
    evidence = _evidence(operator)
    if change == "missing":
        await registry.close()
        registry = InMemoryControlPlaneOperatorRegistry()
        service = ControlPlaneDurableSessionAccessService(
            registry=registry,
            repository=InMemoryControlPlaneDurableSessionRepository(),
            policy=POLICY,
            clock=lambda: NOW,
            token_factory=_Secrets("session"),
            csrf_factory=_Secrets("csrf"),
        )
    else:
        updated_at = NOW + timedelta(seconds=1)
        if change == "disabled":
            replacement = replace(
                operator,
                status=ControlPlaneOperatorStatus.DISABLED,
                disabled_at=updated_at,
                updated_at=updated_at,
                revision=2,
            )
        elif change == "token":
            replacement = replace(
                operator,
                token_digest=ControlPlaneOperatorToken("replacement-token-0123456789abcdef").digest,
                token_version=2,
                updated_at=updated_at,
                revision=2,
            )
        else:
            replacement = replace(
                operator,
                role=ControlPlaneOperatorRole.VIEWER,
                updated_at=updated_at,
                revision=2,
            )
        await registry.replace(replacement, expected_revision=1)

    with pytest.raises(ControlPlaneDurableSessionConflictError):
        await service.issue(evidence)


@pytest.mark.asyncio
async def test_authenticate_touches_idle_expiry_and_returns_current_principal() -> None:
    service, registry, repository, clock = await _service()
    operator = await registry.get(OPERATOR_ID)
    assert operator is not None
    grant = await service.issue(_evidence(operator))
    before = await repository.get(grant.session_id)
    assert before is not None
    clock.now += timedelta(minutes=5)

    authentication = await service.authenticate(grant.token.value)
    after = await repository.get(grant.session_id)

    assert authentication is not None
    assert not authentication.rotated
    assert authentication.principal == operator.principal()
    assert authentication.authenticated_at == clock.now
    assert after is not None
    assert after.last_seen_at == clock.now
    assert after.idle_expires_at == clock.now + POLICY.idle_ttl
    assert after.revision == before.revision + 1


@pytest.mark.asyncio
async def test_authentication_uses_constant_time_compare_for_hit_and_miss(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, registry, _, _ = await _service()
    operator = await registry.get(OPERATOR_ID)
    assert operator is not None
    grant = await service.issue(_evidence(operator))
    calls: list[tuple[str, str]] = []
    original = hmac.compare_digest

    def recording(left: str, right: str) -> bool:
        calls.append((left, right))
        return original(left, right)

    monkeypatch.setattr(
        "phoenix_os.control_plane.durable_session_access.hmac.compare_digest",
        recording,
    )

    assert await service.authenticate("unknown-session-token-0000000000000000") is None
    assert await service.authenticate(grant.token.value) is not None
    assert len(calls) >= 2
    assert all(len(left) == 64 and len(right) == 64 for left, right in calls)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "value",
    [None, "", "short", " token-0000000000000000000000000000", "á" * 40],
)
async def test_authentication_rejects_malformed_tokens_generically(value: str | None) -> None:
    service, _, _, _ = await _service()
    assert await service.authenticate(value) is None


@pytest.mark.asyncio
async def test_idle_expiration_is_persisted_and_rejected() -> None:
    service, registry, repository, clock = await _service()
    operator = await registry.get(OPERATOR_ID)
    assert operator is not None
    grant = await service.issue(_evidence(operator))
    clock.now += POLICY.idle_ttl

    assert await service.authenticate(grant.token.value) is None
    record = await repository.get(grant.session_id)
    assert record is not None
    assert record.status is ControlPlaneDurableSessionStatus.EXPIRED
    assert record.termination_reason is ControlPlaneDurableSessionTerminationReason.IDLE_TIMEOUT


@pytest.mark.asyncio
async def test_absolute_expiration_wins_when_both_deadlines_are_reached() -> None:
    service, registry, repository, clock = await _service()
    operator = await registry.get(OPERATOR_ID)
    assert operator is not None
    grant = await service.issue(_evidence(operator))
    clock.now += POLICY.absolute_ttl

    assert await service.authenticate(grant.token.value) is None
    record = await repository.get(grant.session_id)
    assert record is not None
    assert record.termination_reason is ControlPlaneDurableSessionTerminationReason.ABSOLUTE_TIMEOUT


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("change", "reason"),
    [
        ("disabled", ControlPlaneDurableSessionTerminationReason.OPERATOR_INACTIVE),
        ("revoked", ControlPlaneDurableSessionTerminationReason.OPERATOR_INACTIVE),
        ("credential", ControlPlaneDurableSessionTerminationReason.CREDENTIAL_ROTATED),
        ("role", ControlPlaneDurableSessionTerminationReason.PERMISSIONS_CHANGED),
    ],
)
async def test_authentication_invalidates_stale_operator_binding(
    change: str,
    reason: ControlPlaneDurableSessionTerminationReason,
) -> None:
    service, registry, repository, clock = await _service()
    operator = await registry.get(OPERATOR_ID)
    assert operator is not None
    grant = await service.issue(_evidence(operator))
    clock.now += timedelta(seconds=1)
    if change == "disabled":
        replacement = replace(
            operator,
            status=ControlPlaneOperatorStatus.DISABLED,
            disabled_at=clock.now,
            updated_at=clock.now,
            revision=2,
        )
    elif change == "revoked":
        replacement = replace(
            operator,
            status=ControlPlaneOperatorStatus.REVOKED,
            revoked_at=clock.now,
            updated_at=clock.now,
            revision=2,
        )
    elif change == "credential":
        replacement = replace(
            operator,
            token_digest=ControlPlaneOperatorToken("rotated-token-0123456789abcdef-0001").digest,
            token_version=2,
            updated_at=clock.now,
            revision=2,
        )
    else:
        replacement = replace(
            operator,
            role=ControlPlaneOperatorRole.VIEWER,
            updated_at=clock.now,
            revision=2,
        )
    await registry.replace(replacement, expected_revision=1)

    assert await service.authenticate(grant.token.value) is None
    record = await repository.get(grant.session_id)
    assert record is not None
    assert record.status is ControlPlaneDurableSessionStatus.REVOKED
    assert record.termination_reason is reason


@pytest.mark.asyncio
async def test_periodic_rotation_preserves_absolute_expiry() -> None:
    service, registry, repository, clock = await _service()
    operator = await registry.get(OPERATOR_ID)
    assert operator is not None
    grant = await service.issue(_evidence(operator))
    clock.now += POLICY.rotation_interval

    authentication = await service.authenticate(grant.token.value)

    assert authentication is not None
    assert authentication.rotated
    successor_grant = authentication.rotated_grant
    assert successor_grant is not None
    assert successor_grant.generation == 2
    assert successor_grant.absolute_expires_at == grant.absolute_expires_at
    assert successor_grant.token.digest != grant.token.digest
    assert successor_grant.csrf_secret.digest != grant.csrf_secret.digest
    previous = await repository.get(grant.session_id)
    successor = await repository.get(successor_grant.session_id)
    assert previous is not None and successor is not None
    assert previous.status is ControlPlaneDurableSessionStatus.ROTATED
    assert previous.successor_session_id == successor.id
    assert successor.predecessor_session_id == previous.id


@pytest.mark.asyncio
async def test_rotated_predecessor_cannot_be_replayed_or_rotated_again() -> None:
    service, registry, repository, clock = await _service()
    operator = await registry.get(OPERATOR_ID)
    assert operator is not None
    grant = await service.issue(_evidence(operator))
    clock.now += POLICY.rotation_interval
    authentication = await service.authenticate(grant.token.value)
    assert authentication is not None and authentication.rotated_grant is not None
    snapshot_before = await repository.snapshot()

    assert await service.authenticate(grant.token.value) is None
    snapshot_after = await repository.snapshot()

    assert snapshot_after.entries == snapshot_before.entries
    assert snapshot_after.rotated == 1
    assert snapshot_after.active == 1


@pytest.mark.asyncio
async def test_rotated_successor_authenticates_and_refreshes_activity() -> None:
    service, registry, repository, clock = await _service()
    operator = await registry.get(OPERATOR_ID)
    assert operator is not None
    grant = await service.issue(_evidence(operator))
    clock.now += POLICY.rotation_interval
    rotated = await service.authenticate(grant.token.value)
    assert rotated is not None and rotated.rotated_grant is not None
    successor = rotated.rotated_grant
    clock.now += timedelta(minutes=1)

    authentication = await service.authenticate(successor.token.value)
    record = await repository.get(successor.session_id)

    assert authentication is not None
    assert authentication.generation == 2
    assert not authentication.rotated
    assert record is not None and record.last_seen_at == clock.now


@pytest.mark.asyncio
async def test_concurrent_rotation_allows_only_one_successor() -> None:
    service, registry, repository, clock = await _service()
    operator = await registry.get(OPERATOR_ID)
    assert operator is not None
    grant = await service.issue(_evidence(operator))
    clock.now += POLICY.rotation_interval

    first, second = await asyncio.gather(
        service.authenticate(grant.token.value),
        service.authenticate(grant.token.value),
    )

    accepted = [result for result in (first, second) if result is not None]
    assert len(accepted) == 1
    assert accepted[0].rotated
    snapshot = await repository.snapshot()
    assert snapshot.entries == 2
    assert snapshot.active == 1
    assert snapshot.rotated == 1


@pytest.mark.asyncio
async def test_logout_and_individual_revocation_are_idempotently_generic() -> None:
    service, registry, repository, _ = await _service()
    operator = await registry.get(OPERATOR_ID)
    assert operator is not None
    first = await service.issue(_evidence(operator))
    second = await service.issue(_evidence(operator))

    assert await service.logout(first.token.value)
    assert not await service.logout(first.token.value)
    assert await service.revoke_session(second.session_id)
    assert not await service.revoke_session(second.session_id)
    first_record = await repository.get(first.session_id)
    second_record = await repository.get(second.session_id)
    assert first_record is not None and second_record is not None
    assert first_record.termination_reason is ControlPlaneDurableSessionTerminationReason.LOGOUT
    assert second_record.termination_reason is (
        ControlPlaneDurableSessionTerminationReason.ADMINISTRATIVE
    )


@pytest.mark.asyncio
async def test_global_operator_revocation_terminates_every_active_session() -> None:
    service, registry, repository, _ = await _service()
    operator = await registry.get(OPERATOR_ID)
    assert operator is not None
    grants = [await service.issue(_evidence(operator)) for _ in range(3)]

    changed = await service.revoke_operator_sessions(
        OPERATOR_ID,
        reason=ControlPlaneDurableSessionTerminationReason.ROLE_CHANGED,
    )

    assert changed == 3
    for grant in grants:
        record = await repository.get(grant.session_id)
        assert record is not None
        assert record.termination_reason is ControlPlaneDurableSessionTerminationReason.ROLE_CHANGED
    assert await service.revoke_operator_sessions(OPERATOR_ID) == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "reason",
    [
        ControlPlaneDurableSessionTerminationReason.IDLE_TIMEOUT,
        ControlPlaneDurableSessionTerminationReason.ABSOLUTE_TIMEOUT,
        ControlPlaneDurableSessionTerminationReason.TOKEN_ROTATED,
    ],
)
async def test_expiration_and_rotation_reasons_cannot_be_used_for_revocation(
    reason: ControlPlaneDurableSessionTerminationReason,
) -> None:
    service, _, _, _ = await _service()
    with pytest.raises(ValueError):
        await service.revoke_session(UUID(int=1), reason=reason)
    with pytest.raises(ValueError):
        await service.revoke_operator_sessions(OPERATOR_ID, reason=reason)


@pytest.mark.asyncio
async def test_access_snapshot_contains_only_bounded_counters() -> None:
    service, registry, _, clock = await _service()
    operator = await registry.get(OPERATOR_ID)
    assert operator is not None
    grant = await service.issue(_evidence(operator))
    assert await service.authenticate("unknown-session-token-0000000000000000") is None
    clock.now += POLICY.rotation_interval
    assert await service.authenticate(grant.token.value) is not None
    rotated = await service.snapshot()

    assert rotated.issued == 1
    assert rotated.authenticated == 1
    assert rotated.rotated == 1
    assert rotated.rejected == 1
    assert "token" not in repr(rotated).lower()
    assert "digest" not in repr(rotated).lower()


@pytest.mark.asyncio
async def test_close_borrows_registry_and_repository_lifecycles() -> None:
    service, registry, repository, _ = await _service()
    await service.close()

    with pytest.raises(ControlPlaneDurableSessionAccessClosedError):
        await service.authenticate("session-token-000000000000000000000000")
    assert not registry.closed
    assert not repository.closed
    assert (await service.snapshot()).closed


@pytest.mark.asyncio
async def test_state_backed_session_authenticates_after_repository_restart() -> None:
    store = MemoryStateStore()
    registry = InMemoryControlPlaneOperatorRegistry()
    operator = _operator()
    await registry.add(operator)
    first_repository = StateControlPlaneDurableSessionRepository(store)
    clock = _Clock()
    service = ControlPlaneDurableSessionAccessService(
        registry=registry,
        repository=first_repository,
        policy=POLICY,
        clock=clock,
        token_factory=_Secrets("session"),
        csrf_factory=_Secrets("csrf"),
    )
    grant = await service.issue(_evidence(operator))
    await first_repository.close()
    second_repository = StateControlPlaneDurableSessionRepository(store)
    restarted = ControlPlaneDurableSessionAccessService(
        registry=registry,
        repository=second_repository,
        policy=POLICY,
        clock=clock,
        token_factory=_Secrets("next-session"),
        csrf_factory=_Secrets("next-csrf"),
    )
    clock.now += timedelta(minutes=1)

    authentication = await restarted.authenticate(grant.token.value)

    assert authentication is not None
    persisted = await second_repository.get(grant.session_id)
    assert persisted is not None and persisted.last_seen_at == clock.now


@pytest.mark.asyncio
async def test_identical_token_and_csrf_factories_fail_closed() -> None:
    registry = InMemoryControlPlaneOperatorRegistry()
    operator = _operator()
    await registry.add(operator)

    def factory() -> str:
        return "same-secret-00000000000000000000000000000000"

    service = ControlPlaneDurableSessionAccessService(
        registry=registry,
        repository=InMemoryControlPlaneDurableSessionRepository(),
        policy=POLICY,
        clock=lambda: NOW,
        token_factory=factory,
        csrf_factory=factory,
    )
    with pytest.raises(ControlPlaneDurableSessionConflictError):
        await service.issue(_evidence(operator))


def test_grant_and_authentication_reject_inconsistent_values() -> None:
    token = ControlPlaneDurableSessionToken("session-token-000000000000000000000000")
    csrf = ControlPlaneDurableCsrfSecret("csrf-secret-00000000000000000000000000")
    with pytest.raises(ValueError):
        from phoenix_os.control_plane import ControlPlaneDurableSessionGrant

        ControlPlaneDurableSessionGrant(
            session_id=UUID(int=1),
            operator_id=OPERATOR_ID,
            username="alice",
            token=token,
            csrf_secret=csrf,
            generation=0,
            issued_at=NOW,
            absolute_expires_at=NOW + timedelta(hours=1),
            idle_expires_at=NOW + timedelta(minutes=10),
            rotate_after=NOW + timedelta(minutes=5),
        )
    with pytest.raises(ValueError):
        ControlPlaneDurableSessionAuthentication(
            session_id=UUID(int=1),
            operator_id=OPERATOR_ID,
            principal=_operator().principal(),
            generation=1,
            authenticated_at=NOW + timedelta(hours=1),
            absolute_expires_at=NOW + timedelta(hours=1),
            idle_expires_at=NOW + timedelta(hours=1),
        )


@pytest.mark.asyncio
async def test_naive_clock_is_rejected() -> None:
    service, registry, _, clock = await _service()
    operator = await registry.get(OPERATOR_ID)
    assert operator is not None
    clock.now = datetime(2026, 7, 19, 18, 0)
    with pytest.raises(ValueError):
        await service.issue(_evidence(operator))
