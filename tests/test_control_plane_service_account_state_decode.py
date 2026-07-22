from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import cast
from uuid import UUID

import pytest

from phoenix_os.control_plane.errors import (
    ControlPlaneServiceAccountCorruptionError,
    ControlPlaneServiceAccountSchemaError,
)
from phoenix_os.control_plane.service_account_contracts import (
    ControlPlaneServiceAccountRecord,
)
from phoenix_os.control_plane.service_account_state import (
    _account_record_envelope,
    _decode_account_record_state,
)
from phoenix_os.state import StateKey, StateRecord

_NOW = datetime(2026, 7, 20, 12, tzinfo=UTC)
_ACCOUNT_ID = UUID("00000000-0000-0000-0000-000000000001")


def _account() -> ControlPlaneServiceAccountRecord:
    return ControlPlaneServiceAccountRecord(
        id=_ACCOUNT_ID,
        name="release.bot",
        display_name="Release Bot",
        created_at=_NOW,
        updated_at=_NOW,
    )


def _stored(
    value: object,
) -> StateRecord[object]:
    return StateRecord(
        key=StateKey(
            "control-plane-service-accounts",
            f"record_{_ACCOUNT_ID.hex}",
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


def test_account_envelope_contains_exact_safe_fields() -> None:
    envelope = _account_record_envelope(_account())

    assert frozenset(envelope) == frozenset(
        {
            "schema_version",
            "kind",
            "record",
            "record_digest",
        }
    )

    serialized = json.dumps(
        envelope,
        sort_keys=True,
    )

    assert "phx_sa_" not in serialized
    assert "Bearer" not in serialized
    assert "password" not in serialized


def test_account_record_round_trip() -> None:
    account = _account()
    envelope = _account_record_envelope(account)

    decoded = _decode_account_record_state(_stored(envelope))

    assert decoded == account


def test_decoder_rejects_digest_mismatch() -> None:
    envelope = _account_record_envelope(_account())
    envelope["record_digest"] = "0" * 64

    with pytest.raises(
        ControlPlaneServiceAccountCorruptionError,
        match="digest",
    ):
        _decode_account_record_state(_stored(envelope))


def test_decoder_rejects_unknown_envelope_fields() -> None:
    envelope = _account_record_envelope(_account())
    envelope["unexpected"] = True

    with pytest.raises(
        ControlPlaneServiceAccountCorruptionError,
        match="fields",
    ):
        _decode_account_record_state(_stored(envelope))


def test_decoder_rejects_unknown_record_fields() -> None:
    envelope = _account_record_envelope(_account())
    document = cast(
        dict[str, object],
        envelope["record"],
    )
    document["unexpected"] = True

    with pytest.raises(
        ControlPlaneServiceAccountCorruptionError,
        match="fields",
    ):
        _decode_account_record_state(_stored(envelope))


def test_decoder_rejects_unknown_envelope_schema() -> None:
    envelope = _account_record_envelope(_account())
    envelope["schema_version"] = 2

    with pytest.raises(ControlPlaneServiceAccountSchemaError):
        _decode_account_record_state(_stored(envelope))


def test_decoder_rejects_unknown_record_schema() -> None:
    envelope = _account_record_envelope(_account())
    document = cast(
        dict[str, object],
        envelope["record"],
    )
    document["schema_version"] = 2
    envelope["record_digest"] = _document_digest(document)

    with pytest.raises(ControlPlaneServiceAccountSchemaError):
        _decode_account_record_state(_stored(envelope))


def test_decoder_rejects_invalid_kind() -> None:
    envelope = _account_record_envelope(_account())
    envelope["kind"] = "invalid.kind"

    with pytest.raises(
        ControlPlaneServiceAccountCorruptionError,
        match="kind",
    ):
        _decode_account_record_state(_stored(envelope))


def test_decoder_rejects_invalid_uuid() -> None:
    envelope = _account_record_envelope(_account())
    document = cast(
        dict[str, object],
        envelope["record"],
    )
    document["id"] = "not-a-uuid"
    envelope["record_digest"] = _document_digest(document)

    with pytest.raises(
        ControlPlaneServiceAccountCorruptionError,
        match="record is invalid",
    ):
        _decode_account_record_state(_stored(envelope))


def test_decoder_rejects_boolean_revision() -> None:
    envelope = _account_record_envelope(_account())
    document = cast(
        dict[str, object],
        envelope["record"],
    )
    document["revision"] = True
    envelope["record_digest"] = _document_digest(document)

    with pytest.raises(
        ControlPlaneServiceAccountCorruptionError,
        match="record is invalid",
    ):
        _decode_account_record_state(_stored(envelope))


def test_decoder_rejects_non_mapping_envelope() -> None:
    with pytest.raises(
        ControlPlaneServiceAccountCorruptionError,
        match="envelope",
    ):
        _decode_account_record_state(_stored(["invalid"]))
