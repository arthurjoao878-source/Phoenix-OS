from datetime import UTC, datetime, timedelta

import pytest

from phoenix_os import (
    EventBus,
    InMemorySecretStore,
    InMemorySink,
    KeyRef,
    ObservabilityHub,
    PolicyEffect,
    PolicyEngine,
    PolicyRule,
    PrincipalType,
    SecretAccessDeniedError,
    SecretAlreadyExistsError,
    SecretLeaseExpiredError,
    SecretLeasePolicy,
    SecretLeaseRevokedError,
    SecretNotFoundError,
    SecretRef,
    SecretRevokedError,
    SecretsManager,
    SecretsManagerClosedError,
    SecretValue,
    SecurityContext,
)


def context(*permissions: str, principal: str = "arthur") -> SecurityContext:
    return SecurityContext(
        principal=principal,
        principal_type=PrincipalType.USER,
        authenticated=True,
        permissions=frozenset(permissions),
        correlation_id="corr-1",
    )


@pytest.mark.asyncio
async def test_create_rotate_describe_and_lease() -> None:
    manager = SecretsManager()
    admin = context("secret.create", "secret.rotate", "secret.describe", "secret.read")
    ref = SecretRef("database-password", "production")

    first = await manager.create(ref, SecretValue("one"), admin, attributes={"owner": "db"})
    second = await manager.rotate(ref, SecretValue("two"), admin)
    described = await manager.describe(second.ref, admin)
    lease = await manager.lease(ref, admin)

    assert first.ref.version == 1
    assert second.ref.version == 2
    assert described == second
    assert lease.ref == second.ref
    assert lease.value.reveal(str) == "two"
    assert "two" not in repr(lease)


@pytest.mark.asyncio
async def test_manager_preserves_external_protection_key_reference() -> None:
    manager = SecretsManager()
    admin = context("secret.create", "secret.describe")
    key = KeyRef("primary", "kms", 7)
    metadata = await manager.create(
        SecretRef("api"),
        SecretValue("value"),
        admin,
        protection_key=key,
    )
    assert metadata.protection_key == key
    assert (await manager.describe(metadata.ref, admin)).protection_key == key


@pytest.mark.asyncio
async def test_create_rejects_name_with_revoked_history() -> None:
    manager = SecretsManager()
    admin = context("secret.create", "secret.revoke")
    ref = SecretRef("api")
    created = await manager.create(ref, SecretValue("one"), admin)
    assert await manager.revoke(created.ref, admin)
    with pytest.raises(SecretAlreadyExistsError):
        await manager.create(ref, SecretValue("two"), admin)


@pytest.mark.asyncio
async def test_create_existing_secret_is_rejected() -> None:
    manager = SecretsManager()
    admin = context("secret.create")
    ref = SecretRef("api")
    await manager.create(ref, SecretValue("one"), admin)
    with pytest.raises(SecretAlreadyExistsError):
        await manager.create(ref, SecretValue("two"), admin)


@pytest.mark.asyncio
async def test_rotate_missing_secret_is_rejected() -> None:
    manager = SecretsManager()
    with pytest.raises(SecretNotFoundError):
        await manager.rotate(SecretRef("missing"), SecretValue("value"), context("secret.rotate"))


@pytest.mark.asyncio
async def test_unauthenticated_and_missing_permission_are_denied() -> None:
    manager = SecretsManager()
    anonymous = SecurityContext()
    with pytest.raises(SecretAccessDeniedError):
        await manager.create(SecretRef("api"), SecretValue("value"), anonymous)
    with pytest.raises(SecretAccessDeniedError):
        await manager.create(SecretRef("api"), SecretValue("value"), context())
    snapshot = await manager.snapshot()
    assert snapshot.denied_operations == 2


@pytest.mark.asyncio
async def test_policy_engine_authorizes_without_local_permission() -> None:
    policy = PolicyEngine(
        (
            PolicyRule(
                "allow-secret-read",
                PolicyEffect.ALLOW,
                actions=frozenset({"secret.read", "secret.create"}),
                resources=frozenset({"secret:default/*"}),
                authenticated=True,
            ),
        )
    )
    manager = SecretsManager(policy=policy)
    user = context()
    await manager.create(SecretRef("api"), SecretValue("value"), user)
    lease = await manager.lease(SecretRef("api"), user)
    assert lease.value.reveal(str) == "value"


@pytest.mark.asyncio
async def test_policy_deny_is_translated_to_secret_access_error() -> None:
    policy = PolicyEngine((PolicyRule("deny", PolicyEffect.DENY, reason="blocked"),))
    manager = SecretsManager(policy=policy)
    with pytest.raises(SecretAccessDeniedError):
        await manager.lease(SecretRef("api"), context())


@pytest.mark.asyncio
async def test_lease_ttl_is_bounded() -> None:
    manager = SecretsManager(
        lease_policy=SecretLeasePolicy(timedelta(seconds=10), timedelta(seconds=30))
    )
    admin = context("secret.create", "secret.read")
    await manager.create(SecretRef("api"), SecretValue("value"), admin)
    with pytest.raises(ValueError):
        await manager.lease(SecretRef("api"), admin, ttl=timedelta(seconds=31))
    with pytest.raises(ValueError):
        await manager.lease(SecretRef("api"), admin, ttl=timedelta(0))


@pytest.mark.asyncio
async def test_resolve_lease_requires_owner_and_detects_expiration() -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    current = [now]
    manager = SecretsManager(clock=lambda: current[0])
    owner = context("secret.create", "secret.read", principal="arthur")
    await manager.create(SecretRef("api"), SecretValue("value"), owner)
    lease = await manager.lease(SecretRef("api"), owner, ttl=timedelta(seconds=10))
    assert await manager.resolve_lease(lease.id, owner) == lease
    with pytest.raises(SecretAccessDeniedError):
        await manager.resolve_lease(lease.id, context(principal="other"))
    current[0] = now + timedelta(seconds=11)
    with pytest.raises(SecretLeaseExpiredError):
        await manager.resolve_lease(lease.id, owner)
    assert await manager.purge_expired_leases() == 1


@pytest.mark.asyncio
async def test_revoke_secret_revokes_active_leases() -> None:
    manager = SecretsManager()
    admin = context("secret.create", "secret.read", "secret.revoke")
    ref = SecretRef("api")
    await manager.create(ref, SecretValue("value"), admin)
    lease = await manager.lease(ref, admin)
    assert await manager.revoke(ref, admin, reason="compromised")
    with pytest.raises(SecretLeaseRevokedError):
        await manager.resolve_lease(lease.id, admin)
    with pytest.raises(SecretNotFoundError):
        await manager.lease(ref, admin)


@pytest.mark.asyncio
async def test_exact_revoked_version_cannot_be_leased() -> None:
    manager = SecretsManager()
    admin = context("secret.create", "secret.rotate", "secret.read", "secret.revoke")
    ref = SecretRef("api")
    first = await manager.create(ref, SecretValue("one"), admin)
    await manager.rotate(ref, SecretValue("two"), admin)
    assert await manager.revoke(first.ref, admin)
    with pytest.raises(SecretRevokedError):
        await manager.lease(first.ref, admin)


@pytest.mark.asyncio
async def test_revoke_individual_lease() -> None:
    manager = SecretsManager()
    admin = context("secret.create", "secret.read", "secret.lease.revoke")
    await manager.create(SecretRef("api"), SecretValue("value"), admin)
    lease = await manager.lease(SecretRef("api"), admin)
    assert await manager.revoke_lease(lease.id, admin, reason="done")
    assert not await manager.revoke_lease(lease.id, admin, reason="again")
    with pytest.raises(SecretLeaseRevokedError):
        await manager.resolve_lease(lease.id, admin)


@pytest.mark.asyncio
async def test_events_and_observability_never_contain_material() -> None:
    events = EventBus()
    captured: list[object] = []
    await events.subscribe("*", lambda event: captured.append(event))
    sink = InMemorySink()
    hub = ObservabilityHub((sink,))
    manager = SecretsManager(events=events, observability=hub)
    admin = context("secret.create", "secret.read")

    await manager.create(SecretRef("api"), SecretValue("never-log-this"), admin)
    await manager.lease(SecretRef("api"), admin)

    assert "never-log-this" not in repr(captured)
    snapshot = await sink.snapshot()
    assert "never-log-this" not in repr(snapshot.records)
    assert {event.name for event in captured} >= {"secrets.created", "secrets.lease.issued"}  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_list_and_snapshot_are_non_sensitive() -> None:
    manager = SecretsManager(InMemorySecretStore())
    admin = context("secret.create", "secret.list", "secret.read")
    await manager.create(SecretRef("api", "prod"), SecretValue("hidden"), admin)
    await manager.lease(SecretRef("api", "prod"), admin)
    listed = await manager.list(admin, namespace="prod")
    snapshot = await manager.snapshot()
    assert [str(item.ref) for item in listed] == ["prod/api#1"]
    assert snapshot.issued_leases == 1
    assert "hidden" not in repr(listed)
    assert "hidden" not in repr(snapshot)


@pytest.mark.asyncio
async def test_close_clears_leases_and_closes_store() -> None:
    manager = SecretsManager()
    admin = context("secret.create", "secret.read")
    await manager.create(SecretRef("api"), SecretValue("value"), admin)
    await manager.lease(SecretRef("api"), admin)
    await manager.close()
    snapshot = await manager.snapshot()
    assert snapshot.closed
    assert snapshot.leases == 0
    with pytest.raises(SecretsManagerClosedError):
        await manager.describe(SecretRef("api"), admin)
