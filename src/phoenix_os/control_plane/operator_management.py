"""Safe lifecycle mutations for local control-plane operator access."""

from __future__ import annotations

import hmac
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID

from phoenix_os.control_plane.errors import (
    ControlPlaneOperatorConflictError,
    ControlPlaneOperatorNotFoundError,
    ControlPlaneOperatorStateError,
)
from phoenix_os.control_plane.operator_contracts import (
    ControlPlaneOperatorRecord,
    ControlPlaneOperatorRegistry,
    ControlPlaneOperatorStatus,
    ControlPlaneOperatorToken,
    _normalize_username,
)

type ControlPlaneOperatorManagementClock = Callable[[], datetime]


def _utc_now() -> datetime:
    return datetime.now(UTC)


class ControlPlaneOperatorMutationAction(StrEnum):
    """Allowlisted operator lifecycle actions exposed by safe receipts."""

    ROTATE_CREDENTIAL = "rotate-credential"
    DISABLE = "disable"
    REACTIVATE = "reactivate"
    REVOKE = "revoke"

    @property
    def result_code(self) -> str:
        return {
            self.ROTATE_CREDENTIAL: "operator.credential-rotated",
            self.DISABLE: "operator.disabled",
            self.REACTIVATE: "operator.reactivated",
            self.REVOKE: "operator.revoked",
        }[self]


@dataclass(frozen=True, slots=True)
class ControlPlaneOperatorMutationReceipt:
    """Credential-free receipt for one committed operator lifecycle mutation."""

    operator_id: UUID
    username: str
    action: ControlPlaneOperatorMutationAction
    status: ControlPlaneOperatorStatus
    token_version: int
    revision: int
    changed_at: datetime
    result_code: str
    schema_version: int = 1

    def __post_init__(self) -> None:
        username = _normalize_username(self.username)
        action = ControlPlaneOperatorMutationAction(self.action)
        status = ControlPlaneOperatorStatus(self.status)
        if self.token_version <= 0 or self.revision <= 0:
            raise ValueError("operator mutation versions must be positive")
        if self.changed_at.tzinfo is None:
            raise ValueError("operator mutation time must be timezone-aware")
        if self.result_code != action.result_code:
            raise ValueError("operator mutation result code does not match its action")
        expected_statuses = {
            ControlPlaneOperatorMutationAction.ROTATE_CREDENTIAL: frozenset(
                {ControlPlaneOperatorStatus.ACTIVE, ControlPlaneOperatorStatus.DISABLED}
            ),
            ControlPlaneOperatorMutationAction.DISABLE: frozenset(
                {ControlPlaneOperatorStatus.DISABLED}
            ),
            ControlPlaneOperatorMutationAction.REACTIVATE: frozenset(
                {ControlPlaneOperatorStatus.ACTIVE}
            ),
            ControlPlaneOperatorMutationAction.REVOKE: frozenset(
                {ControlPlaneOperatorStatus.REVOKED}
            ),
        }
        if status not in expected_statuses[action]:
            raise ValueError("operator mutation status does not match its action")
        if self.schema_version != 1:
            raise ValueError("unsupported control-plane operator mutation schema version")
        object.__setattr__(self, "username", username)
        object.__setattr__(self, "action", action)
        object.__setattr__(self, "status", status)


class ControlPlaneOperatorManager:
    """Rotate credentials and enforce explicit reversible and terminal status changes."""

    def __init__(
        self,
        registry: ControlPlaneOperatorRegistry,
        *,
        clock: ControlPlaneOperatorManagementClock = _utc_now,
    ) -> None:
        if not callable(clock):
            raise TypeError("operator management clock must be callable")
        self._registry = registry
        self._clock = clock

    async def rotate_credential(
        self,
        operator_id: UUID,
        token: ControlPlaneOperatorToken,
        *,
        expected_revision: int,
    ) -> ControlPlaneOperatorMutationReceipt:
        _require_expected_revision(expected_revision)
        current = await self._get_required(operator_id)
        if current.status is ControlPlaneOperatorStatus.REVOKED:
            raise ControlPlaneOperatorStateError("revoked operator credential cannot be rotated")
        if hmac.compare_digest(current.token_digest, token.digest):
            raise ControlPlaneOperatorStateError(
                "replacement operator credential must be different"
            )
        changed_at = self._change_time(current)
        updated = replace(
            current,
            token_digest=token.digest,
            token_version=current.token_version + 1,
            updated_at=changed_at,
            revision=current.revision + 1,
        )
        committed = await self._registry.replace(updated, expected_revision=expected_revision)
        return _receipt(committed, ControlPlaneOperatorMutationAction.ROTATE_CREDENTIAL)

    async def disable(
        self,
        operator_id: UUID,
        *,
        expected_revision: int,
    ) -> ControlPlaneOperatorMutationReceipt:
        _require_expected_revision(expected_revision)
        current = await self._get_required(operator_id)
        if current.status is not ControlPlaneOperatorStatus.ACTIVE:
            raise ControlPlaneOperatorStateError("only an active operator can be disabled")
        changed_at = self._change_time(current)
        updated = replace(
            current,
            status=ControlPlaneOperatorStatus.DISABLED,
            disabled_at=changed_at,
            updated_at=changed_at,
            revision=current.revision + 1,
        )
        committed = await self._registry.replace(updated, expected_revision=expected_revision)
        return _receipt(committed, ControlPlaneOperatorMutationAction.DISABLE)

    async def reactivate(
        self,
        operator_id: UUID,
        *,
        expected_revision: int,
    ) -> ControlPlaneOperatorMutationReceipt:
        _require_expected_revision(expected_revision)
        current = await self._get_required(operator_id)
        if current.status is not ControlPlaneOperatorStatus.DISABLED:
            raise ControlPlaneOperatorStateError("only a disabled operator can be reactivated")
        changed_at = self._change_time(current)
        updated = replace(
            current,
            status=ControlPlaneOperatorStatus.ACTIVE,
            disabled_at=None,
            updated_at=changed_at,
            revision=current.revision + 1,
        )
        committed = await self._registry.replace(updated, expected_revision=expected_revision)
        return _receipt(committed, ControlPlaneOperatorMutationAction.REACTIVATE)

    async def revoke(
        self,
        operator_id: UUID,
        *,
        expected_revision: int,
    ) -> ControlPlaneOperatorMutationReceipt:
        _require_expected_revision(expected_revision)
        current = await self._get_required(operator_id)
        if current.status is ControlPlaneOperatorStatus.REVOKED:
            raise ControlPlaneOperatorStateError("operator access is already revoked")
        changed_at = self._change_time(current)
        updated = replace(
            current,
            status=ControlPlaneOperatorStatus.REVOKED,
            revoked_at=changed_at,
            updated_at=changed_at,
            revision=current.revision + 1,
        )
        committed = await self._registry.replace(updated, expected_revision=expected_revision)
        return _receipt(committed, ControlPlaneOperatorMutationAction.REVOKE)

    async def _get_required(self, operator_id: UUID) -> ControlPlaneOperatorRecord:
        record = await self._registry.get(operator_id)
        if record is None:
            raise ControlPlaneOperatorNotFoundError("control-plane operator was not found")
        return record

    def _change_time(self, record: ControlPlaneOperatorRecord) -> datetime:
        changed_at = self._clock()
        if changed_at.tzinfo is None:
            raise ValueError("operator management clock must return a timezone-aware datetime")
        if changed_at < record.updated_at:
            raise ControlPlaneOperatorConflictError("operator management clock moved backwards")
        return changed_at


def _receipt(
    record: ControlPlaneOperatorRecord,
    action: ControlPlaneOperatorMutationAction,
) -> ControlPlaneOperatorMutationReceipt:
    return ControlPlaneOperatorMutationReceipt(
        operator_id=record.id,
        username=record.username,
        action=action,
        status=record.status,
        token_version=record.token_version,
        revision=record.revision,
        changed_at=record.updated_at,
        result_code=action.result_code,
    )


def _require_expected_revision(expected_revision: int) -> None:
    if expected_revision <= 0:
        raise ValueError("expected_revision must be positive")
