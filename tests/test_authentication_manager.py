from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

import pytest

from phoenix_os import (
    AuthenticationCredential,
    AuthenticationManager,
    AuthenticationManagerClosedError,
    AuthenticationProviderAlreadyRegisteredError,
    AuthenticationProviderError,
    AuthenticationProviderNotFoundError,
    AuthenticationRejectedError,
    CallableAuthenticationProvider,
    Event,
    EventBus,
    Identity,
    InMemorySink,
    ObservabilityHub,
    PrincipalType,
    SecretValue,
    SessionExpiredError,
    SessionLimitExceededError,
    SessionPolicy,
    SessionRevokedError,
    SessionStatus,
    SessionTokenInvalidError,
)


class Clock:
    def __init__(self) -> None:
        self.value = datetime(2026, 1, 1, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.value

    def advance(self, delta: timedelta) -> None:
        self.value += delta


def credential(secret: str = "correct-horse-battery-staple") -> AuthenticationCredential:
    return AuthenticationCredential("password", SecretValue(secret))


def identity(subject: str = "arthur") -> Identity:
    return Identity(
        subject,
        PrincipalType.USER,
        roles=frozenset({"admin"}),
        permissions=frozenset({"files.read"}),
        scopes=frozenset({"workspace"}),
        attributes={"tenant": "phoenix"},
    )


def token_factory() -> Callable[[], str]:
    counter = 0

    def make() -> str:
        nonlocal counter
        counter += 1
        return f"token-{counter:04d}-" + "x" * 40

    return make


@pytest.mark.asyncio
async def test_provider_registration_order_duplicates_and_removal() -> None:
    provider = CallableAuthenticationProvider(lambda request: identity())
    manager = AuthenticationManager((("first", provider),))
    registration = await manager.register_provider("second", provider)
    assert manager.provider_names() == ("first", "second")
    with pytest.raises(AuthenticationProviderAlreadyRegisteredError):
        await manager.register_provider("first", provider)
    assert await manager.unregister_provider(registration)
    assert not await manager.unregister_provider(registration)
    assert manager.provider_names() == ("first",)


@pytest.mark.asyncio
async def test_authenticate_with_sync_provider_and_resolve() -> None:
    clock = Clock()
    manager = AuthenticationManager(
        (("local", CallableAuthenticationProvider(lambda request: identity())),),
        clock=clock,
        token_factory=token_factory(),
    )
    grant = await manager.authenticate(
        "LOCAL",
        credential(),
        metadata={"device": "desktop"},
        correlation_id="trace-1",
    )
    assert grant.session.identity.provider == "local"
    assert grant.session.metadata == {"device": "desktop"}
    assert "token-" not in repr(grant)

    resolved = await manager.resolve(grant.token)
    assert resolved.id == grant.session.id
    context = await manager.security_context(grant.token, confirmed=True)
    assert context.principal == "arthur"
    assert context.authenticated
    assert context.confirmed
    assert context.attributes["session_id"] == str(grant.session.id)


@pytest.mark.asyncio
async def test_authenticate_with_async_provider() -> None:
    async def authenticate(request: object) -> Identity:
        await asyncio.sleep(0)
        return identity("nova")

    manager = AuthenticationManager(
        (("async", CallableAuthenticationProvider(authenticate)),),
        token_factory=token_factory(),
    )
    grant = await manager.authenticate("async", credential())
    assert grant.session.identity.subject == "nova"
    assert grant.session.identity.provider == "async"


@pytest.mark.asyncio
async def test_missing_provider_is_reported_and_counted() -> None:
    manager = AuthenticationManager()
    with pytest.raises(AuthenticationProviderNotFoundError):
        await manager.authenticate("missing", credential())
    snapshot = await manager.snapshot()
    assert snapshot.failures == 1
    assert snapshot.authentications == 0


@pytest.mark.asyncio
async def test_provider_rejection_is_preserved() -> None:
    def reject(request: object) -> Identity:
        raise AuthenticationRejectedError("invalid credentials")

    manager = AuthenticationManager((("local", CallableAuthenticationProvider(reject)),))
    with pytest.raises(AuthenticationRejectedError, match="invalid credentials"):
        await manager.authenticate("local", credential("wrong"))
    assert (await manager.snapshot()).failures == 1


@pytest.mark.asyncio
async def test_unexpected_provider_failure_is_safely_wrapped() -> None:
    def fail(request: object) -> Identity:
        raise RuntimeError("database password=secret")

    manager = AuthenticationManager((("local", CallableAuthenticationProvider(fail)),))
    with pytest.raises(AuthenticationProviderError) as captured:
        await manager.authenticate("local", credential())
    assert str(captured.value) == "authentication provider 'local' failed"
    assert isinstance(captured.value.exception, RuntimeError)


@pytest.mark.asyncio
async def test_provider_must_return_identity() -> None:
    def invalid_result(request: object) -> Identity:
        del request
        return "arthur"  # type: ignore[return-value]

    provider = CallableAuthenticationProvider(invalid_result)
    manager = AuthenticationManager((("local", provider),))
    with pytest.raises(AuthenticationProviderError) as captured:
        await manager.authenticate("local", credential())
    assert isinstance(captured.value.exception, TypeError)


@pytest.mark.asyncio
async def test_invalid_token_is_rejected() -> None:
    manager = AuthenticationManager()
    with pytest.raises(SessionTokenInvalidError):
        await manager.resolve("not-a-session-token")
    with pytest.raises(SessionTokenInvalidError, match="blank"):
        await manager.resolve(" ")


@pytest.mark.asyncio
async def test_absolute_expiration_is_persisted() -> None:
    clock = Clock()
    manager = AuthenticationManager(
        (("local", CallableAuthenticationProvider(lambda request: identity())),),
        policy=SessionPolicy(absolute_ttl=timedelta(minutes=5), idle_ttl=None),
        clock=clock,
        token_factory=token_factory(),
    )
    grant = await manager.authenticate("local", credential())
    clock.advance(timedelta(minutes=5))
    with pytest.raises(SessionExpiredError):
        await manager.resolve(grant.token)
    stored = await manager.session(grant.session.id)
    assert stored.status is SessionStatus.EXPIRED


@pytest.mark.asyncio
async def test_idle_expiration_and_touch() -> None:
    clock = Clock()
    manager = AuthenticationManager(
        (("local", CallableAuthenticationProvider(lambda request: identity())),),
        policy=SessionPolicy(
            absolute_ttl=timedelta(hours=1),
            idle_ttl=timedelta(minutes=5),
            touch_interval=timedelta(minutes=1),
        ),
        clock=clock,
        token_factory=token_factory(),
    )
    grant = await manager.authenticate("local", credential())
    original_idle = grant.session.idle_expires_at
    clock.advance(timedelta(minutes=2))
    touched = await manager.resolve(grant.token)
    assert touched.last_seen_at == clock.value
    assert touched.idle_expires_at is not None
    assert original_idle is not None and touched.idle_expires_at > original_idle
    clock.advance(timedelta(minutes=5))
    with pytest.raises(SessionExpiredError):
        await manager.resolve(grant.token)


@pytest.mark.asyncio
async def test_revoke_by_id_and_token() -> None:
    manager = AuthenticationManager(
        (("local", CallableAuthenticationProvider(lambda request: identity())),),
        token_factory=token_factory(),
    )
    first = await manager.authenticate("local", credential())
    second = await manager.authenticate("local", credential())
    assert await manager.revoke(first.session.id, reason="admin")
    assert not await manager.revoke(first.session.id)
    with pytest.raises(SessionRevokedError):
        await manager.resolve(first.token)
    assert await manager.revoke_token(second.token)
    with pytest.raises(SessionRevokedError):
        await manager.resolve(second.token)
    assert (await manager.snapshot()).revocations == 2


@pytest.mark.asyncio
async def test_revoke_all_sessions_for_identity() -> None:
    manager = AuthenticationManager(
        (("local", CallableAuthenticationProvider(lambda request: identity())),),
        token_factory=token_factory(),
    )
    first = await manager.authenticate("local", credential())
    second = await manager.authenticate("local", credential())
    assert await manager.revoke_identity("arthur") == 2
    with pytest.raises(SessionRevokedError):
        await manager.resolve(first.token)
    with pytest.raises(SessionRevokedError):
        await manager.resolve(second.token)


@pytest.mark.asyncio
async def test_session_limit_is_not_wrapped_as_provider_error() -> None:
    manager = AuthenticationManager(
        (("local", CallableAuthenticationProvider(lambda request: identity())),),
        policy=SessionPolicy(max_sessions_per_identity=1),
        token_factory=token_factory(),
    )
    await manager.authenticate("local", credential())
    with pytest.raises(SessionLimitExceededError):
        await manager.authenticate("local", credential())


@pytest.mark.asyncio
async def test_custom_expiration_cannot_exceed_policy() -> None:
    manager = AuthenticationManager(
        (("local", CallableAuthenticationProvider(lambda request: identity())),),
        policy=SessionPolicy(absolute_ttl=timedelta(hours=1)),
        token_factory=token_factory(),
    )
    with pytest.raises(ValueError, match="expires_in"):
        await manager.authenticate("local", credential(), expires_in=timedelta(hours=2))


@pytest.mark.asyncio
async def test_events_and_observability_never_receive_bearer_or_credential() -> None:
    events = EventBus()
    seen: list[Event] = []
    await events.subscribe("*", seen.append)
    sink = InMemorySink()
    observability = ObservabilityHub((sink,))
    secret = "credential-that-must-never-leak"
    manager = AuthenticationManager(
        (("local", CallableAuthenticationProvider(lambda request: identity())),),
        events=events,
        observability=observability,
        token_factory=lambda: "bearer-that-must-never-leak-" + "x" * 32,
    )
    grant = await manager.authenticate("local", credential(secret))
    await manager.resolve(grant.token)

    event_text = repr(seen)
    observations = repr((await sink.snapshot()).records)
    assert secret not in event_text
    assert secret not in observations
    assert "bearer-that-must-never-leak" not in event_text
    assert "bearer-that-must-never-leak" not in observations
    assert {event.name for event in seen} >= {
        "identity.authentication.succeeded",
        "identity.session.issued",
        "identity.session.resolved",
    }


@pytest.mark.asyncio
async def test_snapshot_and_purge_expired() -> None:
    clock = Clock()
    manager = AuthenticationManager(
        (("local", CallableAuthenticationProvider(lambda request: identity())),),
        policy=SessionPolicy(absolute_ttl=timedelta(minutes=1), idle_ttl=None),
        clock=clock,
        token_factory=token_factory(),
    )
    await manager.authenticate("local", credential())
    before = await manager.snapshot()
    assert before.sessions == 1
    assert before.active_sessions == 1
    assert before.authentications == 1
    clock.advance(timedelta(minutes=2))
    assert await manager.purge_expired() == 1
    assert (await manager.snapshot()).active_sessions == 0


@pytest.mark.asyncio
async def test_close_is_idempotent_and_rejects_use() -> None:
    manager = AuthenticationManager()
    await manager.close()
    await manager.close()
    assert manager.closed
    assert (await manager.snapshot()).closed
    with pytest.raises(AuthenticationManagerClosedError):
        manager.provider_names()
    with pytest.raises(AuthenticationManagerClosedError):
        await manager.authenticate("local", credential())
