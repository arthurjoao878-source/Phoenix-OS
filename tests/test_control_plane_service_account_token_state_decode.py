from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from typing import cast
from uuid import UUID

import pytest

from phoenix_os.control_plane.errors import (
    ControlPlaneServiceAccountCorruptionError,
    ControlPlaneServiceAccountSchemaError,
)
from phoenix_os.control_plane.service_account_contracts import (
    ControlPlaneApiTokenMetadata,
    ControlPlaneApiTokenRestriction,
)
from phoenix_os.control_plane.service_account_state import (
    _api_token_digest_index_document,
    _api_token_record_envelope,
    _decode_api_token_digest_index_state,
    _decode_api_token_record_state,
    _verify_api_token_digest_index,
)
from phoenix_os.state import StateKey, StateRecord

_NOW = datetime(2026, 7, 20, 12, tzinfo=UTC)
_ACCOUNT_ID = UUID("00000000-0000-0000-0000-000000000001")
_TOKEN_ID = UUID("00000000-0000-0000-0000-000000000002")


def _digest(seed: str) -> str:
    return hashlib.sha256(seed.encode("ascii")).hexdigest()


def _token() -> ControlPlaneApiTokenMetadata:
    return ControlPlaneApiTokenMetadata(
        id=_TOKEN_ID,
        service_account_id=_ACCOUNT_ID,
        label="Deployment Token",
        token_digest=_digest("deployment"),
        scopes=frozenset(
            {
                "jobs.read",
                "jobs.create",
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
                "10.0.0.0/8",
                "2001:db8::/32",
            ),
            mutual_tls_certificate_sha256=("a" * 64),
        ),
        issued_at=_NOW,
        expires_at=_NOW + timedelta(days=30),
        updated_at=_NOW,
    )


def _token_record(
    value: object,
) -> StateRecord[object]:
    return StateRecord(
        key=StateKey(
            "control-plane-service-accounts",
            f"token_record_{_TOKEN_ID.hex}",
            object,
        ),
        value=value,
        version=1,
        created_at=_NOW,
        updated_at=_NOW,
    )


def _digest_index(
    value: object,
) -> StateRecord[object]:
    return StateRecord(
        key=StateKey(
            "control-plane-service-accounts",
            f"token_digest_{_digest('deployment')}",
            object,
        ),
        value=value,
        version=1,
        created_at=_NOW,
        updated_at=_NOW,
    )


def _document_digest(
    document: dict[str, object],
) -> str:
    payload = json.dumps(
        document,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    return hashlib.sha256(payload).hexdigest()


def test_token_envelope_contains_exact_fields() -> None:
    envelope = _api_token_record_envelope(_token())

    assert frozenset(envelope) == frozenset(
        {
            "schema_version",
            "kind",
            "record",
            "record_digest",
        }
    )


def test_token_envelope_contains_no_plaintext_token() -> None:
    envelope = _api_token_record_envelope(_token())
    serialized = json.dumps(
        envelope,
        sort_keys=True,
    )

    assert "phx_sa_" not in serialized
    assert "Bearer" not in serialized
    assert "deployment-token-plaintext" not in serialized


def test_token_record_round_trip() -> None:
    metadata = _token()

    decoded = _decode_api_token_record_state(_token_record(_api_token_record_envelope(metadata)))

    assert decoded == metadata


def test_token_record_rejects_digest_mismatch() -> None:
    envelope = _api_token_record_envelope(_token())
    envelope["record_digest"] = "0" * 64

    with pytest.raises(
        ControlPlaneServiceAccountCorruptionError,
        match="digest",
    ):
        _decode_api_token_record_state(_token_record(envelope))


def test_token_record_rejects_extra_fields() -> None:
    envelope = _api_token_record_envelope(_token())
    document = cast(
        dict[str, object],
        envelope["record"],
    )
    document["unexpected"] = True

    with pytest.raises(
        ControlPlaneServiceAccountCorruptionError,
        match="fields",
    ):
        _decode_api_token_record_state(_token_record(envelope))


def test_token_record_rejects_unknown_schema() -> None:
    envelope = _api_token_record_envelope(_token())
    envelope["schema_version"] = 2

    with pytest.raises(ControlPlaneServiceAccountSchemaError):
        _decode_api_token_record_state(_token_record(envelope))


def test_token_record_rejects_unsorted_scopes() -> None:
    envelope = _api_token_record_envelope(_token())
    document = cast(
        dict[str, object],
        envelope["record"],
    )
    document["scopes"] = [
        "jobs.read",
        "jobs.create",
    ]
    envelope["record_digest"] = _document_digest(document)

    with pytest.raises(
        ControlPlaneServiceAccountCorruptionError,
        match="record is invalid",
    ):
        _decode_api_token_record_state(_token_record(envelope))


def test_token_record_rejects_unsorted_resources() -> None:
    envelope = _api_token_record_envelope(_token())
    document = cast(
        dict[str, object],
        envelope["record"],
    )
    document["resources"] = [
        "workflow:release",
        "job:*",
    ]
    envelope["record_digest"] = _document_digest(document)

    with pytest.raises(
        ControlPlaneServiceAccountCorruptionError,
        match="record is invalid",
    ):
        _decode_api_token_record_state(_token_record(envelope))


def test_token_record_rejects_noncanonical_network() -> None:
    envelope = _api_token_record_envelope(_token())
    document = cast(
        dict[str, object],
        envelope["record"],
    )
    restriction = cast(
        dict[str, object],
        document["restriction"],
    )
    restriction["allowed_client_networks"] = [
        "10.0.0.1/8",
        "2001:db8::/32",
    ]
    envelope["record_digest"] = _document_digest(document)

    with pytest.raises(
        ControlPlaneServiceAccountCorruptionError,
        match="record is invalid",
    ):
        _decode_api_token_record_state(_token_record(envelope))


def test_token_digest_index_round_trip() -> None:
    metadata = _token()
    document = _api_token_digest_index_document(metadata)

    decoded = _decode_api_token_digest_index_state(_digest_index(document))

    assert decoded.token_id == metadata.id
    assert decoded.service_account_id == metadata.service_account_id
    assert decoded.token_digest == metadata.token_digest
    assert decoded.revision == metadata.revision

    _verify_api_token_digest_index(
        decoded,
        metadata,
    )


def test_token_digest_index_rejects_extra_fields() -> None:
    document = _api_token_digest_index_document(_token())
    document["unexpected"] = True

    with pytest.raises(
        ControlPlaneServiceAccountCorruptionError,
        match="fields",
    ):
        _decode_api_token_digest_index_state(_digest_index(document))


def test_token_digest_index_detects_mismatch() -> None:
    metadata = _token()
    document = _api_token_digest_index_document(metadata)
    document["revision"] = 2

    decoded = _decode_api_token_digest_index_state(_digest_index(document))

    with pytest.raises(
        ControlPlaneServiceAccountCorruptionError,
        match="do not match",
    ):
        _verify_api_token_digest_index(
            decoded,
            metadata,
        )
