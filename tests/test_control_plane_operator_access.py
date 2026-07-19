from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest

from phoenix_os.audit import AuditCategory, default_journal_event
from phoenix_os.control_plane.auth import ControlPlanePrincipal
from phoenix_os.control_plane.errors import (
    ControlPlaneOperatorAccessRejectedError,
    ControlPlaneOperatorPermissionDeniedError,
    ControlPlaneOperatorRateLimitCapacityError,
    ControlPlaneOperatorSessionStoreClosedError,
)
from phoenix_os.control_plane.operator_authentication import ControlPlaneOperatorAuthenticator
from phoenix_os.control_plane.operator_contracts import (
    CONTROL_PLANE_OPERATOR_SESSIONS_REVOKE_PERMISSION,
    ControlPlaneOperatorRecord,
    ControlPlaneOperatorRole,
    ControlPlaneOperatorStatus,
    ControlPlaneOperatorToken,
)
from phoenix_os.control_plane.operator_memory import InMemoryControlPlaneOperatorRegistry
from phoenix_os.control_plane.operator_sessions import (
    ControlPlaneOperatorAccessService,
    ControlPlaneOperatorAccessSnapshot,
    ControlPlaneOperatorLoginRateLimiter,
    ControlPlaneOperatorRateLimitSnapshot,
    ControlPlaneOperatorSessionRevocationReason,
    ControlPlaneOperatorSessionStatus,
    ControlPlaneOperatorSessionToken,
    InMemoryControlPlaneOperatorSessionStore,
)
from phoenix_os.events import Event, EventBus

_NOW = datetime(2026, 7, 19, 19, tzinfo=UTC)
_OPERATOR_TOKEN = ControlPlaneOperatorToken("alice-token-0123456789abcdef-operator")
_SESSION_VALUE = "temporary-session-token-0123456789abcdef"


class _Clock:
    def __init__(self, value: datetime = _NOW) -> None:
        self.value = value

    def __call__(self) -> datetime:
        return self.value


async def _record(
    registry: InMemoryControlPlaneOperatorRegistry,
    *,
    operator_id: UUID | None = None,
    status: ControlPlaneOperatorStatus = ControlPlaneOperatorStatus.ACTIVE,
    disabled_at: datetime | None = None,
    revoked_at: datetime | None = None,
    token_version: int = 1,
) -> ControlPlaneOperatorRecord:
    record = ControlPlaneOperatorRecord(
        id=operator_id or uuid4(),
        username="alice",
        display_name="Alice Operator",
        role=ControlPlaneOperatorRole.MAINTAINER,
        token_digest=_OPERATOR_TOKEN.digest,
        created_at=_NOW,
        updated_at=_NOW,
        status=status,
        disabled_at=disabled_at,
        revoked_at=revoked_at,
        token_version=token_version,
    )
    await registry.add(record)
    return record


def _service(
    registry: InMemoryControlPlaneOperatorRegistry,
    *,
    clock: _Clock | None = None,
    events: EventBus | None = None,
    sessions: InMemoryControlPlaneOperatorSessionStore | None = None,
    limiter: ControlPlaneOperatorLoginRateLimiter | None = None,
    ttl: timedelta = timedelta(minutes=30),
) -> tuple[
    ControlPlaneOperatorAccessService,
    _Clock,
    EventBus,
    InMemoryControlPlaneOperatorSessionStore,
    ControlPlaneOperatorLoginRateLimiter,
]:
    resolved_clock = clock or _Clock()
    resolved_events = events or EventBus()
    resolved_sessions = sessions or InMemoryControlPlaneOperatorSessionStore()
    resolved_limiter = limiter or ControlPlaneOperatorLoginRateLimiter()
    return (
        ControlPlaneOperatorAccessService(
            registry=registry,
            authenticator=ControlPlaneOperatorAuthenticator(
                registry,
                clock=resolved_clock,
            ),
            sessions=resolved_sessions,
            rate_limiter=resolved_limiter,
            events=resolved_events,
            ttl=ttl,
            clock=resolved_clock,
            token_factory=lambda: _SESSION_VALUE,
        ),
        resolved_clock,
        resolved_events,
        resolved_sessions,
        resolved_limiter,
    )


@pytest.mark.asyncio
async def test_login_issues_redacted_bounded_session_and_safe_events() -> None:
    registry = InMemoryControlPlaneOperatorRegistry()
    record = await _record(registry)
    service, _, events, sessions, _ = _service(registry)
    captured: list[Event] = []
    await events.subscribe("*", captured.append)

    grant = await service.login(f"Bearer {_OPERATOR_TOKEN.value}")

    assert grant.operator_id == record.id
    assert grant.username == "alice"
    assert grant.expires_at - grant.issued_at == timedelta(minutes=30)
    assert _SESSION_VALUE not in repr(grant)
    stored = await sessions.get(grant.session_id)
    assert stored is not None
    assert stored.token_digest == ControlPlaneOperatorSessionToken(_SESSION_VALUE).digest
    assert [event.name for event in captured] == [
        "control-plane.operator.authentication.succeeded",
        "control-plane.operator.session.issued",
    ]
    serialized = repr(tuple(dict(event.payload) for event in captured))
    assert _OPERATOR_TOKEN.value not in serialized
    assert _OPERATOR_TOKEN.digest not in serialized
    assert _SESSION_VALUE not in serialized
    assert stored.token_digest not in serialized


@pytest.mark.asyncio
async def test_session_authentication_uses_current_operator_permissions() -> None:
    registry = InMemoryControlPlaneOperatorRegistry()
    record = await _record(registry)
    service, _, _, _, _ = _service(registry)
    grant = await service.login(f"Bearer {_OPERATOR_TOKEN.value}")
    updated = replace(
        record,
        additional_permissions=frozenset({"audit.read"}),
        updated_at=_NOW,
        revision=2,
    )
    await registry.replace(updated, expected_revision=1)

    evidence = await service.authenticate(f"Bearer {grant.token.value}")

    assert evidence is not None
    assert evidence.session_id == grant.session_id
    assert evidence.operator_id == record.id
    assert evidence.principal.name == "alice"
    assert "audit.read" in evidence.principal.permissions


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "authorization",
    [None, "", "Basic x", "Bearer short", "Bearer " + "á" * 32, "Bearer " + "x" * 257],
)
async def test_login_uses_one_generic_failure_for_invalid_credentials(
    authorization: str | None,
) -> None:
    registry = InMemoryControlPlaneOperatorRegistry()
    await _record(registry)
    service, _, events, _, _ = _service(registry)
    captured: list[Event] = []
    await events.subscribe("*", captured.append)

    with pytest.raises(ControlPlaneOperatorAccessRejectedError) as captured_error:
        await service.login(authorization)

    assert str(captured_error.value) == "control-plane operator access was rejected"
    assert captured[-1].name == "control-plane.operator.authentication.failed"
    assert dict(captured[-1].payload) == {
        "action": "operator.authenticate",
        "actor": "anonymous",
        "outcome": "denied",
        "resource": "control-plane:local",
        "result_code": "operator.login-rejected",
    }


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status", "disabled_at", "revoked_at"),
    [
        (ControlPlaneOperatorStatus.DISABLED, _NOW, None),
        (ControlPlaneOperatorStatus.REVOKED, None, _NOW),
    ],
)
async def test_login_does_not_enumerate_inactive_operator_status(
    status: ControlPlaneOperatorStatus,
    disabled_at: datetime | None,
    revoked_at: datetime | None,
) -> None:
    registry = InMemoryControlPlaneOperatorRegistry()
    await _record(
        registry,
        status=status,
        disabled_at=disabled_at,
        revoked_at=revoked_at,
    )
    service, _, _, _, _ = _service(registry)
    with pytest.raises(ControlPlaneOperatorAccessRejectedError) as captured_error:
        await service.login(f"Bearer {_OPERATOR_TOKEN.value}")
    assert str(captured_error.value) == "control-plane operator access was rejected"


@pytest.mark.asyncio
async def test_rate_limiter_blocks_after_bounded_failures_and_resets_after_window() -> None:
    limiter = ControlPlaneOperatorLoginRateLimiter(
        max_attempts=2,
        window=timedelta(seconds=10),
    )
    assert await limiter.allow("a", now=_NOW)
    await limiter.record_failure("a", now=_NOW)
    assert await limiter.allow("a", now=_NOW)
    await limiter.record_failure("a", now=_NOW + timedelta(seconds=1))
    assert not await limiter.allow("a", now=_NOW + timedelta(seconds=2))
    assert await limiter.allow("a", now=_NOW + timedelta(seconds=11))


@pytest.mark.asyncio
async def test_rate_limiter_success_clears_only_matching_fingerprint() -> None:
    limiter = ControlPlaneOperatorLoginRateLimiter(max_attempts=1)
    await limiter.record_failure("a", now=_NOW)
    await limiter.record_failure("b", now=_NOW)
    await limiter.record_success("a")
    assert await limiter.allow("a", now=_NOW)
    assert not await limiter.allow("b", now=_NOW)


@pytest.mark.asyncio
async def test_rate_limiter_is_bounded_and_snapshot_is_safe() -> None:
    limiter = ControlPlaneOperatorLoginRateLimiter(max_attempts=2, capacity=1)
    await limiter.record_failure("a", now=_NOW)
    with pytest.raises(ControlPlaneOperatorRateLimitCapacityError):
        await limiter.record_failure("b", now=_NOW)
    assert await limiter.snapshot() == ControlPlaneOperatorRateLimitSnapshot(
        closed=False,
        tracked_keys=1,
        denied=0,
        capacity=1,
        max_attempts=2,
        window_seconds=60,
    )


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_attempts": 0},
        {"max_attempts": 101},
        {"window": timedelta(0)},
        {"window": timedelta(hours=2)},
        {"capacity": 0},
        {"capacity": 20_001},
    ],
)
def test_rate_limiter_rejects_invalid_bounds(kwargs: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        ControlPlaneOperatorLoginRateLimiter(**kwargs)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_service_rate_limit_failure_uses_same_generic_error_and_event() -> None:
    registry = InMemoryControlPlaneOperatorRegistry()
    await _record(registry)
    limiter = ControlPlaneOperatorLoginRateLimiter(max_attempts=1)
    service, _, events, _, _ = _service(registry, limiter=limiter)
    captured: list[Event] = []
    await events.subscribe("*", captured.append)
    invalid = "Bearer unknown-token-0123456789abcdef-operator"
    with pytest.raises(ControlPlaneOperatorAccessRejectedError):
        await service.login(invalid)
    with pytest.raises(ControlPlaneOperatorAccessRejectedError) as captured_error:
        await service.login(invalid)
    assert str(captured_error.value) == "control-plane operator access was rejected"
    assert captured[-1].payload["result_code"] == "operator.login-rejected"


@pytest.mark.asyncio
async def test_successful_login_clears_prior_failure_bucket() -> None:
    registry = InMemoryControlPlaneOperatorRegistry()
    await _record(registry)
    limiter = ControlPlaneOperatorLoginRateLimiter(max_attempts=2)
    service, _, _, _, _ = _service(registry, limiter=limiter)
    fingerprint_limiter = limiter
    invalid = "Bearer unknown-token-0123456789abcdef-operator"
    with pytest.raises(ControlPlaneOperatorAccessRejectedError):
        await service.login(invalid)
    await service.login(f"Bearer {_OPERATOR_TOKEN.value}")
    snapshot = await fingerprint_limiter.snapshot()
    assert snapshot.tracked_keys == 1


@pytest.mark.asyncio
async def test_expired_session_is_terminally_revoked() -> None:
    registry = InMemoryControlPlaneOperatorRegistry()
    await _record(registry)
    clock = _Clock()
    service, _, events, sessions, _ = _service(
        registry,
        clock=clock,
        ttl=timedelta(minutes=1),
    )
    captured: list[Event] = []
    await events.subscribe("*", captured.append)
    grant = await service.login(f"Bearer {_OPERATOR_TOKEN.value}")
    clock.value = _NOW + timedelta(minutes=1)

    assert await service.authenticate(f"Bearer {grant.token.value}") is None

    stored = await sessions.get(grant.session_id)
    assert stored is not None
    assert stored.status is ControlPlaneOperatorSessionStatus.REVOKED
    assert stored.revocation_reason is ControlPlaneOperatorSessionRevocationReason.EXPIRED
    assert captured[-1].name == "control-plane.operator.session.expired"
    assert (await service.snapshot()).sessions_expired == 1


@pytest.mark.asyncio
async def test_credential_rotation_invalidates_existing_session() -> None:
    registry = InMemoryControlPlaneOperatorRegistry()
    record = await _record(registry)
    service, clock, _, sessions, _ = _service(registry)
    grant = await service.login(f"Bearer {_OPERATOR_TOKEN.value}")
    clock.value += timedelta(seconds=1)
    await registry.replace(
        replace(
            record,
            token_digest=ControlPlaneOperatorToken(
                "replacement-token-0123456789abcdef-operator"
            ).digest,
            token_version=2,
            updated_at=clock.value,
            revision=2,
        ),
        expected_revision=1,
    )

    assert await service.authenticate(f"Bearer {grant.token.value}") is None
    stored = await sessions.get(grant.session_id)
    assert stored is not None
    assert (
        stored.revocation_reason is ControlPlaneOperatorSessionRevocationReason.CREDENTIAL_ROTATED
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status", "disabled_at", "revoked_at"),
    [
        (ControlPlaneOperatorStatus.DISABLED, _NOW + timedelta(seconds=1), None),
        (ControlPlaneOperatorStatus.REVOKED, None, _NOW + timedelta(seconds=1)),
    ],
)
async def test_inactive_operator_invalidates_existing_session(
    status: ControlPlaneOperatorStatus,
    disabled_at: datetime | None,
    revoked_at: datetime | None,
) -> None:
    registry = InMemoryControlPlaneOperatorRegistry()
    record = await _record(registry)
    service, clock, _, sessions, _ = _service(registry)
    grant = await service.login(f"Bearer {_OPERATOR_TOKEN.value}")
    clock.value += timedelta(seconds=1)
    await registry.replace(
        replace(
            record,
            status=status,
            disabled_at=disabled_at,
            revoked_at=revoked_at,
            updated_at=clock.value,
            revision=2,
        ),
        expected_revision=1,
    )
    assert await service.authenticate(f"Bearer {grant.token.value}") is None
    stored = await sessions.get(grant.session_id)
    assert stored is not None
    assert stored.revocation_reason is ControlPlaneOperatorSessionRevocationReason.OPERATOR_INACTIVE


@pytest.mark.asyncio
async def test_logout_revokes_known_session_and_unknown_is_generic() -> None:
    registry = InMemoryControlPlaneOperatorRegistry()
    await _record(registry)
    service, _, events, sessions, _ = _service(registry)
    captured: list[Event] = []
    await events.subscribe("*", captured.append)
    grant = await service.login(f"Bearer {_OPERATOR_TOKEN.value}")

    assert await service.logout(f"Bearer {grant.token.value}")
    assert not await service.logout(f"Bearer {grant.token.value}")
    stored = await sessions.get(grant.session_id)
    assert stored is not None
    assert stored.revocation_reason is ControlPlaneOperatorSessionRevocationReason.LOGOUT
    assert captured[-1].payload["actor"] == "anonymous"


@pytest.mark.asyncio
async def test_administrative_session_revoke_requires_exact_permission() -> None:
    registry = InMemoryControlPlaneOperatorRegistry()
    await _record(registry)
    service, _, _, sessions, _ = _service(registry)
    grant = await service.login(f"Bearer {_OPERATOR_TOKEN.value}")
    viewer = ControlPlanePrincipal("viewer")
    with pytest.raises(ControlPlaneOperatorPermissionDeniedError):
        await service.revoke_session(grant.session_id, actor=viewer)
    assert (await sessions.get(grant.session_id)).status is ControlPlaneOperatorSessionStatus.ACTIVE  # type: ignore[union-attr]


@pytest.mark.asyncio
async def test_administrative_session_revoke_emits_actor_without_credentials() -> None:
    registry = InMemoryControlPlaneOperatorRegistry()
    await _record(registry)
    service, _, events, sessions, _ = _service(registry)
    captured: list[Event] = []
    await events.subscribe("*", captured.append)
    grant = await service.login(f"Bearer {_OPERATOR_TOKEN.value}")
    maintainer = ControlPlanePrincipal(
        "maintainer",
        frozenset(
            {
                "control-plane.read",
                CONTROL_PLANE_OPERATOR_SESSIONS_REVOKE_PERMISSION,
            }
        ),
    )
    assert await service.revoke_session(grant.session_id, actor=maintainer)
    assert not await service.revoke_session(uuid4(), actor=maintainer)
    stored = await sessions.get(grant.session_id)
    assert stored is not None
    assert stored.revocation_reason is ControlPlaneOperatorSessionRevocationReason.ADMINISTRATIVE
    assert captured[-1].payload["actor"] == "maintainer"


@pytest.mark.asyncio
async def test_bulk_operator_session_revoke_is_bounded_and_counted() -> None:
    registry = InMemoryControlPlaneOperatorRegistry()
    record = await _record(registry)
    sessions = InMemoryControlPlaneOperatorSessionStore(max_sessions_per_operator=2)
    values = iter(
        (
            "first-temporary-session-token-0123456789abcdef",
            "second-temporary-session-token-0123456789abcdef",
        )
    )
    clock = _Clock()
    events = EventBus()
    limiter = ControlPlaneOperatorLoginRateLimiter()
    service = ControlPlaneOperatorAccessService(
        registry=registry,
        authenticator=ControlPlaneOperatorAuthenticator(registry, clock=clock),
        sessions=sessions,
        rate_limiter=limiter,
        events=events,
        clock=clock,
        token_factory=lambda: next(values),
    )
    await service.login(f"Bearer {_OPERATOR_TOKEN.value}")
    await service.login(f"Bearer {_OPERATOR_TOKEN.value}")
    actor = record.principal()
    assert await service.revoke_operator_sessions(record.id, actor=actor) == 2
    assert (await service.snapshot()).sessions_revoked == 2


@pytest.mark.asyncio
async def test_access_snapshot_counts_successes_and_rejections() -> None:
    registry = InMemoryControlPlaneOperatorRegistry()
    await _record(registry)
    service, _, _, _, _ = _service(registry)
    grant = await service.login(f"Bearer {_OPERATOR_TOKEN.value}")
    assert await service.authenticate(f"Bearer {grant.token.value}") is not None
    assert await service.authenticate("Bearer unknown-session-token-0123456789abcdef") is None
    assert await service.snapshot() == ControlPlaneOperatorAccessSnapshot(
        closed=False,
        logins_succeeded=1,
        logins_rejected=0,
        sessions_authenticated=1,
        sessions_rejected=1,
        sessions_expired=0,
        sessions_revoked=0,
    )


@pytest.mark.asyncio
async def test_service_close_is_idempotent_and_closes_owned_components() -> None:
    registry = InMemoryControlPlaneOperatorRegistry()
    await _record(registry)
    service, _, _, sessions, limiter = _service(registry)
    await service.close()
    await service.close()
    assert service.closed
    assert sessions.closed
    assert limiter.closed
    assert (await service.snapshot()).closed
    with pytest.raises(ControlPlaneOperatorSessionStoreClosedError):
        await service.login(f"Bearer {_OPERATOR_TOKEN.value}")


@pytest.mark.asyncio
async def test_closed_event_bus_does_not_break_login_or_logout() -> None:
    registry = InMemoryControlPlaneOperatorRegistry()
    await _record(registry)
    events = EventBus()
    await events.close()
    service, _, _, _, _ = _service(registry, events=events)
    grant = await service.login(f"Bearer {_OPERATOR_TOKEN.value}")
    assert await service.logout(f"Bearer {grant.token.value}")


def test_operator_access_events_map_to_authentication_audit_category() -> None:
    event = Event(
        name="control-plane.operator.session.revoked",
        source="phoenix.control-plane",
        payload={"outcome": "success"},
    )
    mapped = default_journal_event(event)
    assert mapped is not None
    assert mapped.category is AuditCategory.AUTHENTICATION


@pytest.mark.parametrize(
    "kwargs",
    [
        {"ttl": timedelta(0)},
        {"ttl": timedelta(hours=25)},
        {"clock": None},
        {"token_factory": None},
    ],
)
def test_service_rejects_invalid_configuration(kwargs: dict[str, object]) -> None:
    registry = InMemoryControlPlaneOperatorRegistry()
    base: dict[str, object] = {
        "registry": registry,
        "authenticator": ControlPlaneOperatorAuthenticator(registry),
        "sessions": InMemoryControlPlaneOperatorSessionStore(),
        "rate_limiter": ControlPlaneOperatorLoginRateLimiter(),
        "events": EventBus(),
    }
    base.update(kwargs)
    with pytest.raises((ValueError, TypeError)):
        ControlPlaneOperatorAccessService(**base)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_service_rejects_naive_clock_without_authenticating() -> None:
    registry = InMemoryControlPlaneOperatorRegistry()
    await _record(registry)
    clock = _Clock(datetime(2026, 7, 19, 19))
    service, _, _, _, _ = _service(registry, clock=clock)
    with pytest.raises(ValueError, match="timezone-aware"):
        await service.login(f"Bearer {_OPERATOR_TOKEN.value}")
