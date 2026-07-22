from __future__ import annotations

import hashlib
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest

from phoenix_os.control_plane.service_account_contracts import (
    MAX_CONTROL_PLANE_API_TOKEN_LIFETIME,
    ControlPlaneApiToken,
    ControlPlaneApiTokenMetadata,
    ControlPlaneApiTokenRestriction,
    ControlPlaneApiTokenStatus,
    ControlPlaneServiceAccountRecord,
    ControlPlaneServiceAccountRegistrySnapshot,
    ControlPlaneServiceAccountStatus,
)

_NOW = datetime(2026, 7, 20, 12, tzinfo=UTC)
_TOKEN_VALUE = "phx_sa_" + ("A" * 48)
_TOKEN_DIGEST = hashlib.sha256(_TOKEN_VALUE.encode("ascii")).hexdigest()


def _account(
    *,
    account_id: UUID | None = None,
    name: str = "release.bot",
    display_name: str = "Release Bot",
    status: ControlPlaneServiceAccountStatus = (ControlPlaneServiceAccountStatus.ACTIVE),
    disabled_at: datetime | None = None,
    revoked_at: datetime | None = None,
    created_at: datetime = _NOW,
    updated_at: datetime = _NOW,
    revision: int = 1,
    schema_version: int = 1,
) -> ControlPlaneServiceAccountRecord:
    return ControlPlaneServiceAccountRecord(
        id=account_id or uuid4(),
        name=name,
        display_name=display_name,
        created_at=created_at,
        updated_at=updated_at,
        status=status,
        disabled_at=disabled_at,
        revoked_at=revoked_at,
        revision=revision,
        schema_version=schema_version,
    )


def _metadata(
    *,
    token_id: UUID | None = None,
    account_id: UUID | None = None,
    label: str = "Deployment token",
    token_digest: str = _TOKEN_DIGEST,
    scopes: frozenset[str] = frozenset({"jobs.read", "jobs.create"}),
    issued_at: datetime = _NOW,
    expires_at: datetime = _NOW + timedelta(days=30),
    updated_at: datetime = _NOW,
    resources: frozenset[str] = frozenset({"job:*"}),
    restriction: ControlPlaneApiTokenRestriction | None = None,
    status: ControlPlaneApiTokenStatus = (ControlPlaneApiTokenStatus.ACTIVE),
    revoked_at: datetime | None = None,
    rotated_from: UUID | None = None,
    token_version: int = 1,
    revision: int = 1,
    schema_version: int = 1,
) -> ControlPlaneApiTokenMetadata:
    return ControlPlaneApiTokenMetadata(
        id=token_id or uuid4(),
        service_account_id=account_id or uuid4(),
        label=label,
        token_digest=token_digest,
        scopes=scopes,
        issued_at=issued_at,
        expires_at=expires_at,
        updated_at=updated_at,
        resources=resources,
        restriction=(restriction if restriction is not None else ControlPlaneApiTokenRestriction()),
        status=status,
        revoked_at=revoked_at,
        rotated_from=rotated_from,
        token_version=token_version,
        revision=revision,
        schema_version=schema_version,
    )


def test_api_token_is_redacted_and_has_stable_digest() -> None:
    token = ControlPlaneApiToken(_TOKEN_VALUE)

    assert token.digest == _TOKEN_DIGEST
    assert str(token) == "<redacted>"
    assert repr(token) == "ControlPlaneApiToken(<redacted>)"
    assert _TOKEN_VALUE not in repr(token)


@pytest.mark.parametrize(
    "value",
    [
        "short",
        " " + _TOKEN_VALUE,
        _TOKEN_VALUE + " ",
        "phx_sa_" + ("a" * 39),
        "phx_sa_" + ("a" * 153),
        "wrong_" + ("a" * 48),
        "phx_sa_" + ("a" * 47) + "/",
        "phx_sa_" + ("á" * 48),
    ],
)
def test_api_token_rejects_unsafe_values(
    value: str,
) -> None:
    with pytest.raises(ValueError):
        ControlPlaneApiToken(value)


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (
            ControlPlaneServiceAccountStatus.ACTIVE,
            True,
        ),
        (
            ControlPlaneServiceAccountStatus.DISABLED,
            False,
        ),
        (
            ControlPlaneServiceAccountStatus.REVOKED,
            False,
        ),
    ],
)
def test_service_account_status_authenticatable(
    status: ControlPlaneServiceAccountStatus,
    expected: bool,
) -> None:
    assert status.authenticatable is expected


def test_service_account_normalizes_safe_fields() -> None:
    account = _account(
        name=" Release.Bot ",
        display_name=" Release Bot ",
    )

    assert account.name == "release.bot"
    assert account.display_name == "Release Bot"


@pytest.mark.parametrize(
    "name",
    [
        "",
        "ab",
        "2service",
        "service account",
        "service/account",
        "áccount",
        "a" * 65,
    ],
)
def test_service_account_rejects_invalid_name(
    name: str,
) -> None:
    with pytest.raises(ValueError, match="name"):
        _account(name=name)


def test_disabled_account_requires_disabled_timestamp() -> None:
    account = _account(
        status=ControlPlaneServiceAccountStatus.DISABLED,
        disabled_at=_NOW,
    )

    assert account.status is ControlPlaneServiceAccountStatus.DISABLED

    with pytest.raises(ValueError, match="disabled"):
        _account(status=ControlPlaneServiceAccountStatus.DISABLED)


def test_revoked_account_requires_revoked_timestamp() -> None:
    account = _account(
        status=ControlPlaneServiceAccountStatus.REVOKED,
        revoked_at=_NOW,
    )

    assert account.status is ControlPlaneServiceAccountStatus.REVOKED

    with pytest.raises(ValueError, match="revoked"):
        _account(status=ControlPlaneServiceAccountStatus.REVOKED)


def test_account_rejects_naive_timestamps() -> None:
    with pytest.raises(ValueError, match="created_at"):
        _account(created_at=datetime(2026, 7, 20))


def test_token_restriction_normalizes_order() -> None:
    restriction = ControlPlaneApiTokenRestriction(
        allowed_client_networks=(
            "2001:db8::/32",
            "10.0.0.0/8",
            "192.168.0.0/16",
        ),
        mutual_tls_certificate_sha256=("A" * 64),
    )

    assert restriction.allowed_client_networks == (
        "10.0.0.0/8",
        "192.168.0.0/16",
        "2001:db8::/32",
    )
    assert restriction.mutual_tls_certificate_sha256 == "a" * 64
    assert restriction.restricted is True


@pytest.mark.parametrize(
    "network",
    [
        "10.1.0.0/8",
        "10.0.0.1/8",
        "not-a-network",
        "192.168.1.1",
    ],
)
def test_token_restriction_rejects_noncanonical_network(
    network: str,
) -> None:
    with pytest.raises(ValueError, match="CIDR"):
        ControlPlaneApiTokenRestriction(allowed_client_networks=(network,))


def test_token_restriction_rejects_duplicates() -> None:
    with pytest.raises(ValueError, match="unique"):
        ControlPlaneApiTokenRestriction(
            allowed_client_networks=(
                "10.0.0.0/8",
                "10.0.0.0/8",
            )
        )


def test_token_metadata_normalizes_fields() -> None:
    metadata = _metadata(
        label=" Deployment Token ",
        token_digest=_TOKEN_DIGEST.upper(),
        scopes=frozenset({" Jobs.Read ", "jobs.create"}),
        resources=frozenset({" job:* ", "workflow:release"}),
    )

    assert metadata.label == "Deployment Token"
    assert metadata.token_digest == _TOKEN_DIGEST
    assert metadata.scopes == frozenset({"jobs.read", "jobs.create"})
    assert metadata.resources == frozenset({"job:*", "workflow:release"})


def test_token_requires_at_least_one_scope() -> None:
    with pytest.raises(ValueError, match="scope"):
        _metadata(scopes=frozenset())


def test_token_rejects_invalid_scope() -> None:
    with pytest.raises(ValueError, match="scope"):
        _metadata(scopes=frozenset({"jobs/read"}))


def test_token_requires_expiration_after_issuance() -> None:
    with pytest.raises(ValueError, match="expires_at"):
        _metadata(expires_at=_NOW)


def test_token_rejects_excessive_lifetime() -> None:
    with pytest.raises(ValueError, match="lifetime"):
        _metadata(expires_at=(_NOW + MAX_CONTROL_PLANE_API_TOKEN_LIFETIME + timedelta(seconds=1)))


def test_active_token_is_authenticatable_before_expiry() -> None:
    metadata = _metadata()

    assert metadata.authenticatable_at(_NOW + timedelta(days=1))
    assert not metadata.authenticatable_at(metadata.expires_at)


def test_revoked_token_requires_revoked_at() -> None:
    revoked_at = _NOW + timedelta(hours=1)

    metadata = _metadata(
        status=ControlPlaneApiTokenStatus.REVOKED,
        revoked_at=revoked_at,
        updated_at=revoked_at,
    )

    assert not metadata.authenticatable_at(revoked_at)

    with pytest.raises(ValueError, match="revoked"):
        _metadata(status=ControlPlaneApiTokenStatus.REVOKED)


def test_expired_token_requires_expiration_transition() -> None:
    expires_at = _NOW + timedelta(days=1)

    metadata = _metadata(
        expires_at=expires_at,
        updated_at=expires_at,
        status=ControlPlaneApiTokenStatus.EXPIRED,
    )

    assert not metadata.authenticatable_at(expires_at)

    with pytest.raises(ValueError, match="expired"):
        _metadata(
            expires_at=expires_at,
            status=ControlPlaneApiTokenStatus.EXPIRED,
        )


def test_token_cannot_rotate_from_itself() -> None:
    token_id = uuid4()

    with pytest.raises(ValueError, match="itself"):
        _metadata(
            token_id=token_id,
            rotated_from=token_id,
        )


def test_metadata_replace_preserves_original() -> None:
    metadata = _metadata()

    replacement = replace(
        metadata,
        label="Rotated token",
        token_version=2,
        revision=2,
        updated_at=_NOW + timedelta(seconds=1),
    )

    assert metadata.label == "Deployment token"
    assert replacement.label == "Rotated token"
    assert replacement.revision == 2


def test_registry_snapshot_accepts_consistent_counts() -> None:
    snapshot = ControlPlaneServiceAccountRegistrySnapshot(
        closed=False,
        accounts=3,
        active_accounts=1,
        disabled_accounts=1,
        revoked_accounts=1,
        tokens=3,
        active_tokens=1,
        revoked_tokens=1,
        expired_tokens=1,
        account_capacity=10,
        max_tokens_per_account=4,
    )

    assert snapshot.accounts == 3
    assert snapshot.tokens == 3


@pytest.mark.parametrize(
    "snapshot",
    [
        {
            "accounts": 2,
            "active_accounts": 1,
            "disabled_accounts": 0,
            "revoked_accounts": 0,
            "tokens": 0,
            "active_tokens": 0,
            "revoked_tokens": 0,
            "expired_tokens": 0,
        },
        {
            "accounts": 1,
            "active_accounts": 1,
            "disabled_accounts": 0,
            "revoked_accounts": 0,
            "tokens": 3,
            "active_tokens": 3,
            "revoked_tokens": 0,
            "expired_tokens": 0,
        },
    ],
)
def test_registry_snapshot_rejects_inconsistent_counts(
    snapshot: dict[str, int],
) -> None:
    with pytest.raises(ValueError):
        ControlPlaneServiceAccountRegistrySnapshot(
            closed=False,
            account_capacity=10,
            max_tokens_per_account=2,
            **snapshot,
        )
