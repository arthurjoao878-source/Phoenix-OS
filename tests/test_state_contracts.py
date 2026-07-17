from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from phoenix_os import (
    ABSENT_VERSION,
    RestoreMode,
    StateKey,
    StateOperationContext,
    StateRecord,
    StateSnapshot,
    TransactionState,
)


def test_state_key_is_normalized_and_typed() -> None:
    key = StateKey(" Session ", " User.Profile ", dict)

    assert key.namespace == "session"
    assert key.name == "user.profile"
    assert key.canonical == "session:user.profile"
    assert key.expected_type is dict
    assert ABSENT_VERSION == 0


@pytest.mark.parametrize("value", ["", " ", "UP PER", "-invalid", "has/slash"])
def test_state_key_rejects_invalid_names(value: str) -> None:
    with pytest.raises(ValueError, match="invalid state"):
        StateKey(value, "valid")


@pytest.mark.parametrize("value", ["", " ", "UP PER", "-invalid", "has/slash"])
def test_state_key_rejects_invalid_key_parts(value: str) -> None:
    with pytest.raises(ValueError, match="invalid state"):
        StateKey("valid", value)


def test_operation_context_is_immutable_and_validated() -> None:
    metadata = {"tenant": "acme"}
    context = StateOperationContext(
        correlation_id=" corr ",
        causation_id=uuid4(),
        metadata=metadata,
    )
    metadata["tenant"] = "changed"

    assert context.correlation_id == "corr"
    assert context.metadata == {"tenant": "acme"}
    with pytest.raises(TypeError):
        context.metadata["new"] = "value"  # type: ignore[index]
    with pytest.raises(ValueError, match="correlation_id"):
        StateOperationContext(correlation_id=" ")


def test_state_record_validates_versions_and_timestamps() -> None:
    now = datetime.now(UTC)
    key = StateKey("session", "token", str)
    record = StateRecord(
        key=key,
        value="abc",
        version=1,
        created_at=now,
        updated_at=now,
        expires_at=now + timedelta(seconds=30),
    )

    assert record.ttl == timedelta(seconds=30)
    with pytest.raises(ValueError, match="positive"):
        StateRecord(key, "abc", 0, now, now)
    with pytest.raises(ValueError, match="earlier"):
        StateRecord(key, "abc", 1, now, now - timedelta(seconds=1))
    with pytest.raises(ValueError, match="later"):
        StateRecord(key, "abc", 1, now, now, now)


def test_snapshot_rejects_duplicate_keys() -> None:
    now = datetime.now(UTC)
    key = StateKey[object]("session", "token")
    record = StateRecord(key, "abc", 1, now, now)

    with pytest.raises(ValueError, match="unique"):
        StateSnapshot(1, (record, record))


def test_parameterized_state_contracts_construct_on_python_312() -> None:
    now = datetime.now(UTC)
    key = StateKey[object]("session", "token")
    record = StateRecord[object](key, "abc", 1, now, now)

    assert key.canonical == "session:token"
    assert record.key is key
    assert record.value == "abc"


def test_public_enums_are_stable() -> None:
    assert RestoreMode.REPLACE.value == "replace"
    assert RestoreMode.MERGE.value == "merge"
    assert TransactionState.NEW.value == "new"
    assert TransactionState.COMMITTED.value == "committed"
