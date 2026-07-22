from __future__ import annotations

import hashlib
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import UUID

from phoenix_os.control_plane.service_account_contracts import (
    ControlPlaneApiTokenMetadata,
    ControlPlaneApiTokenRestriction,
    ControlPlaneApiTokenStatus,
    ControlPlaneServiceAccountRecord,
)
from phoenix_os.control_plane.service_account_state import (
    canonical_control_plane_api_token_record_bytes,
    canonical_control_plane_service_account_record_bytes,
    control_plane_api_token_record_digest,
    control_plane_service_account_record_digest,
)

_NOW = datetime(2026, 7, 20, 12, tzinfo=UTC)
_ACCOUNT_ID = UUID("00000000-0000-0000-0000-000000000001")
_TOKEN_ID = UUID("00000000-0000-0000-0000-000000000002")
_TOKEN_DIGEST = hashlib.sha256(b"credential-safe-test-token").hexdigest()


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
        label="Deployment Token",
        token_digest=_TOKEN_DIGEST,
        scopes=frozenset(
            {
                "workflows.read",
                "jobs.create",
                "jobs.read",
            }
        ),
        resources=frozenset(
            {
                "workflow:release",
                "job:*",
            }
        ),
        restriction=ControlPlaneApiTokenRestriction(
            allowed_client_networks=(
                "2001:db8::/32",
                "10.0.0.0/8",
            ),
            mutual_tls_certificate_sha256=("a" * 64),
        ),
        issued_at=_NOW,
        expires_at=_NOW + timedelta(days=30),
        updated_at=_NOW,
    )


def test_account_bytes_are_deterministic() -> None:
    record = _account()

    first = canonical_control_plane_service_account_record_bytes(record)
    second = canonical_control_plane_service_account_record_bytes(record)

    assert first == second
    assert first.startswith(b'{"created_at":')
    assert b": " not in first
    assert b", " not in first


def test_account_bytes_contain_no_credential_material() -> None:
    payload = canonical_control_plane_service_account_record_bytes(_account())

    assert b"bearer" not in payload
    assert b"password" not in payload
    assert b"plaintext" not in payload
    assert b"cookie" not in payload
    assert b"csrf" not in payload


def test_account_digest_matches_canonical_bytes() -> None:
    record = _account()

    expected = hashlib.sha256(
        canonical_control_plane_service_account_record_bytes(record)
    ).hexdigest()

    assert control_plane_service_account_record_digest(record) == expected


def test_account_digest_changes_with_revision() -> None:
    record = _account()
    updated = replace(
        record,
        updated_at=_NOW + timedelta(seconds=1),
        revision=2,
    )

    assert control_plane_service_account_record_digest(
        record
    ) != control_plane_service_account_record_digest(updated)


def test_token_bytes_are_deterministic() -> None:
    metadata = _token()

    first = canonical_control_plane_api_token_record_bytes(metadata)
    second = canonical_control_plane_api_token_record_bytes(metadata)

    assert first == second
    assert first.startswith(b'{"expires_at":')
    assert b": " not in first
    assert b", " not in first


def test_token_bytes_sort_scopes_and_resources() -> None:
    payload = canonical_control_plane_api_token_record_bytes(_token())

    assert (b'"scopes":["jobs.create","jobs.read","workflows.read"]') in payload

    assert (b'"resources":["job:*","workflow:release"]') in payload


def test_token_bytes_preserve_canonical_network_order() -> None:
    payload = canonical_control_plane_api_token_record_bytes(_token())

    assert (b'"allowed_client_networks":["10.0.0.0/8","2001:db8::/32"]') in payload


def test_token_bytes_contain_digest_not_plaintext() -> None:
    payload = canonical_control_plane_api_token_record_bytes(_token())

    assert _TOKEN_DIGEST.encode("ascii") in payload
    assert b"phx_sa_" not in payload
    assert b"credential-safe-test-token" not in payload
    assert b"Authorization" not in payload
    assert b"Bearer" not in payload


def test_token_digest_matches_canonical_bytes() -> None:
    metadata = _token()

    expected = hashlib.sha256(canonical_control_plane_api_token_record_bytes(metadata)).hexdigest()

    assert control_plane_api_token_record_digest(metadata) == expected


def test_token_digest_changes_with_revision() -> None:
    metadata = _token()

    updated = replace(
        metadata,
        updated_at=_NOW + timedelta(seconds=1),
        revision=2,
    )

    assert control_plane_api_token_record_digest(metadata) != control_plane_api_token_record_digest(
        updated
    )


def test_token_digest_changes_with_terminal_status() -> None:
    metadata = _token()
    revoked_at = _NOW + timedelta(seconds=1)

    revoked = replace(
        metadata,
        status=ControlPlaneApiTokenStatus.REVOKED,
        revoked_at=revoked_at,
        updated_at=revoked_at,
        revision=2,
    )

    assert control_plane_api_token_record_digest(metadata) != control_plane_api_token_record_digest(
        revoked
    )
