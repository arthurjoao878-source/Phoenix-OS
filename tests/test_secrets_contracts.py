from datetime import UTC, datetime, timedelta

import pytest

from phoenix_os import (
    KeyRef,
    SecretLease,
    SecretLeasePolicy,
    SecretLeaseStatus,
    SecretMetadata,
    SecretRef,
    SecretStatus,
    SecretValue,
    StoredSecret,
)


def test_key_ref_is_provider_neutral_and_versioned() -> None:
    key = KeyRef("Primary", "AWS-KMS", 4)
    assert key.name == "primary"
    assert key.provider == "aws-kms"
    assert key.canonical == "aws-kms/primary#4"
    with pytest.raises(ValueError):
        KeyRef("primary", version=0)


def test_secret_ref_normalizes_and_formats() -> None:
    ref = SecretRef("API-Key", "Production", 2)
    assert ref.name == "api-key"
    assert ref.namespace == "production"
    assert ref.canonical == "production/api-key"
    assert ref.resource == "secret:production/api-key"
    assert str(ref) == "production/api-key#2"
    assert ref.at(3) == SecretRef("api-key", "production", 3)


@pytest.mark.parametrize("name", ["", "  ", "1secret", "bad/name", "bad value"])
def test_secret_ref_rejects_invalid_names(name: str) -> None:
    with pytest.raises(ValueError):
        SecretRef(name)


@pytest.mark.parametrize("namespace", ["", "bad/name", "bad value"])
def test_secret_ref_rejects_invalid_namespaces(namespace: str) -> None:
    with pytest.raises(ValueError):
        SecretRef("token", namespace)


def test_secret_ref_rejects_non_positive_version() -> None:
    with pytest.raises(ValueError):
        SecretRef("token", version=0)


def test_secret_metadata_requires_exact_version_and_aware_times() -> None:
    with pytest.raises(ValueError):
        SecretMetadata(SecretRef("token"), "system")
    with pytest.raises(ValueError):
        SecretMetadata(
            SecretRef("token", version=1),
            "system",
            created_at=datetime.now(),
        )


def test_revoked_metadata_requires_revocation_time() -> None:
    with pytest.raises(ValueError):
        SecretMetadata(
            SecretRef("token", version=1),
            "system",
            status=SecretStatus.REVOKED,
        )


def test_metadata_freezes_attributes() -> None:
    attributes = {"Owner": " Security "}
    metadata = SecretMetadata(
        SecretRef("token", version=1),
        "system",
        attributes=attributes,
    )
    attributes["owner"] = "changed"
    assert metadata.attributes == {"owner": "Security"}
    with pytest.raises(TypeError):
        metadata.attributes["new"] = "value"  # type: ignore[index]


def test_stored_secret_and_lease_redact_value_from_repr() -> None:
    value = SecretValue("ultra-secret")
    metadata = SecretMetadata(SecretRef("token", version=1), "system")
    stored = StoredSecret(metadata, value)
    lease = SecretLease(
        ref=metadata.ref,
        principal="arthur",
        value=value,
        issued_at=datetime(2026, 1, 1, tzinfo=UTC),
        expires_at=datetime(2026, 1, 1, 0, 5, tzinfo=UTC),
    )
    assert "ultra-secret" not in repr(stored)
    assert "ultra-secret" not in repr(lease)
    assert lease.value.reveal(str) == "ultra-secret"


def test_secret_lease_validity_and_status() -> None:
    issued = datetime(2026, 1, 1, tzinfo=UTC)
    lease = SecretLease(
        ref=SecretRef("token", version=1),
        principal="arthur",
        value=SecretValue("value"),
        issued_at=issued,
        expires_at=issued + timedelta(minutes=5),
    )
    assert lease.valid_at(issued + timedelta(minutes=4))
    assert not lease.valid_at(issued + timedelta(minutes=5))
    revoked = SecretLease(
        ref=lease.ref,
        principal=lease.principal,
        value=lease.value,
        issued_at=lease.issued_at,
        expires_at=lease.expires_at,
        status=SecretLeaseStatus.REVOKED,
    )
    assert not revoked.valid_at(issued + timedelta(minutes=1))


def test_secret_lease_policy_validates_bounds() -> None:
    policy = SecretLeasePolicy(timedelta(minutes=1), timedelta(minutes=2))
    assert policy.default_ttl == timedelta(minutes=1)
    with pytest.raises(ValueError):
        SecretLeasePolicy(timedelta(minutes=3), timedelta(minutes=2))
    with pytest.raises(ValueError):
        SecretLeasePolicy(timedelta(0), timedelta(minutes=2))
