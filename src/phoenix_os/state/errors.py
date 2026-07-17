"""Errors raised by Phoenix state stores."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from phoenix_os.state.contracts import StateKey


class PhoenixStateError(Exception):
    """Base class for state and persistence failures."""


class StateStoreClosedError(PhoenixStateError):
    """Raised when an operation targets a closed store or registry."""


class StateSerializationError(PhoenixStateError):
    """Raised when a value cannot be encoded or decoded safely."""


class StateTypeError(PhoenixStateError):
    """Raised when a decoded value violates a typed key contract."""


class StateConflictError(PhoenixStateError):
    """Raised when optimistic concurrency validation fails."""

    def __init__(
        self,
        key: StateKey[object],
        expected_version: int,
        actual_version: int | None,
    ) -> None:
        actual = "missing" if actual_version is None else str(actual_version)
        super().__init__(
            f"state version conflict for {key.canonical}: "
            f"expected {expected_version}, actual {actual}"
        )
        self.key = key
        self.expected_version = expected_version
        self.actual_version = actual_version


class StateTransactionError(PhoenixStateError):
    """Raised when a transaction is used in an invalid state."""


class StateSnapshotError(PhoenixStateError):
    """Raised when a snapshot is invalid or cannot be restored."""


class DuplicateStateStoreError(PhoenixStateError):
    """Raised when a registry receives a duplicate store name."""


class StateStoreNotFoundError(PhoenixStateError):
    """Raised when a named store cannot be resolved."""
