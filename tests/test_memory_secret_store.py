from datetime import UTC, datetime

import pytest

from phoenix_os import (
    InMemorySecretStore,
    KeyRef,
    SecretRef,
    SecretStatus,
    SecretStoreClosedError,
    SecretValue,
    SecretVersionError,
)


@pytest.mark.asyncio
async def test_store_records_provider_key_reference_without_material() -> None:
    store = InMemorySecretStore()
    key = KeyRef("primary", "kms", 2)
    stored = await store.put(
        SecretRef("api"),
        SecretValue("value"),
        created_by="system",
        protection_key=key,
    )
    assert stored.metadata.protection_key == key
    assert "value" not in repr(stored.metadata)


@pytest.mark.asyncio
async def test_store_assigns_versions_and_resolves_latest() -> None:
    store = InMemorySecretStore()
    first = await store.put(SecretRef("api"), SecretValue("one"), created_by="system")
    second = await store.put(SecretRef("api"), SecretValue("two"), created_by="system")

    assert first.metadata.ref.version == 1
    assert second.metadata.ref.version == 2
    assert second.metadata.rotated_from == 1
    latest = await store.get(SecretRef("api"))
    assert latest is not None
    assert latest.value.reveal(str) == "two"
    exact = await store.get(SecretRef("api", version=1))
    assert exact is not None
    assert exact.value.reveal(str) == "one"


@pytest.mark.asyncio
async def test_store_rejects_versioned_put_and_plain_values() -> None:
    store = InMemorySecretStore()
    with pytest.raises(SecretVersionError):
        await store.put(SecretRef("api", version=1), SecretValue("one"), created_by="system")
    with pytest.raises(TypeError):
        await store.put(SecretRef("api"), "unsafe", created_by="system")  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_list_is_deterministic_and_namespace_filtered() -> None:
    store = InMemorySecretStore()
    await store.put(SecretRef("zeta", "b"), SecretValue("z"), created_by="system")
    await store.put(SecretRef("alpha", "a"), SecretValue("a1"), created_by="system")
    await store.put(SecretRef("alpha", "a"), SecretValue("a2"), created_by="system")

    all_items = await store.list()
    assert [str(item.ref) for item in all_items] == ["a/alpha#1", "a/alpha#2", "b/zeta#1"]
    filtered = await store.list(namespace="A")
    assert [str(item.ref) for item in filtered] == ["a/alpha#1", "a/alpha#2"]


@pytest.mark.asyncio
async def test_revoke_exact_version_and_latest_active_fallback() -> None:
    store = InMemorySecretStore()
    await store.put(SecretRef("api"), SecretValue("one"), created_by="system")
    await store.put(SecretRef("api"), SecretValue("two"), created_by="system")

    metadata = await store.revoke(
        SecretRef("api", version=2),
        reason="compromised",
        revoked_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    assert metadata is not None
    assert metadata.status is SecretStatus.REVOKED
    assert metadata.revocation_reason == "compromised"
    latest = await store.get(SecretRef("api"))
    assert latest is not None
    assert latest.metadata.ref.version == 1


@pytest.mark.asyncio
async def test_revoke_missing_or_already_revoked_returns_none() -> None:
    store = InMemorySecretStore()
    assert (
        await store.revoke(
            SecretRef("missing"),
            reason="test",
            revoked_at=datetime.now(UTC),
        )
        is None
    )
    await store.put(SecretRef("api"), SecretValue("one"), created_by="system")
    assert await store.revoke(SecretRef("api"), reason="test", revoked_at=datetime.now(UTC))
    assert (
        await store.revoke(SecretRef("api"), reason="again", revoked_at=datetime.now(UTC)) is None
    )


@pytest.mark.asyncio
async def test_snapshot_contains_no_secret_values() -> None:
    store = InMemorySecretStore()
    await store.put(SecretRef("api"), SecretValue("never-show"), created_by="system")
    snapshot = await store.snapshot()
    assert snapshot.names == 1
    assert snapshot.versions == 1
    assert snapshot.active_versions == 1
    assert "never-show" not in repr(snapshot)


@pytest.mark.asyncio
async def test_close_clears_material_and_rejects_operations() -> None:
    store = InMemorySecretStore()
    await store.put(SecretRef("api"), SecretValue("one"), created_by="system")
    await store.close()
    snapshot = await store.snapshot()
    assert snapshot.closed
    assert snapshot.versions == 0
    with pytest.raises(SecretStoreClosedError):
        await store.get(SecretRef("api"))
