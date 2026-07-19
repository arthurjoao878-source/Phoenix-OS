"""Authenticated local operator administration and safe public views."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import Protocol
from uuid import UUID, uuid4

from phoenix_os.control_plane.auth import ControlPlanePrincipal
from phoenix_os.control_plane.errors import (
    ControlPlaneOperatorPermissionDeniedError,
    ControlPlaneOperatorStateError,
)
from phoenix_os.control_plane.operator_contracts import (
    CONTROL_PLANE_OPERATORS_CREATE_PERMISSION,
    CONTROL_PLANE_OPERATORS_DISABLE_PERMISSION,
    CONTROL_PLANE_OPERATORS_READ_PERMISSION,
    CONTROL_PLANE_OPERATORS_REVOKE_PERMISSION,
    CONTROL_PLANE_OPERATORS_ROTATE_PERMISSION,
    CONTROL_PLANE_OPERATORS_UPDATE_PERMISSION,
    DEFAULT_CONTROL_PLANE_OPERATOR_PAGE_REQUEST,
    ControlPlaneOperatorPageInfo,
    ControlPlaneOperatorPageRequest,
    ControlPlaneOperatorRecord,
    ControlPlaneOperatorRegistry,
    ControlPlaneOperatorRole,
    ControlPlaneOperatorStatus,
    ControlPlaneOperatorToken,
)
from phoenix_os.control_plane.operator_management import (
    ControlPlaneOperatorManager,
    ControlPlaneOperatorMutationReceipt,
)
from phoenix_os.control_plane.operator_sessions import (
    ControlPlaneOperatorSessionRevocationReason,
)
from phoenix_os.events import BusClosedError, EventBus

type ControlPlaneOperatorApiClock = Callable[[], datetime]


class ControlPlaneOperatorSessionAdministration(Protocol):
    def invalidate_operator_sessions(
        self,
        operator_id: UUID,
        *,
        actor: str,
        reason: ControlPlaneOperatorSessionRevocationReason,
    ) -> Awaitable[int]: ...

    def revoke_session(
        self,
        session_id: UUID,
        *,
        actor: ControlPlanePrincipal,
    ) -> Awaitable[bool]: ...

    def revoke_operator_sessions(
        self,
        operator_id: UUID,
        *,
        actor: ControlPlanePrincipal,
        reason: ControlPlaneOperatorSessionRevocationReason = (
            ControlPlaneOperatorSessionRevocationReason.ADMINISTRATIVE
        ),
    ) -> Awaitable[int]: ...


def _utc_now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class ControlPlaneOperatorView:
    """Allowlisted operator metadata without credential digests."""

    operator_id: UUID
    username: str
    display_name: str
    role: ControlPlaneOperatorRole
    status: ControlPlaneOperatorStatus
    additional_permissions: tuple[str, ...]
    effective_permissions: tuple[str, ...]
    created_at: datetime
    updated_at: datetime
    disabled_at: datetime | None
    revoked_at: datetime | None
    token_version: int
    revision: int
    schema_version: int = 1

    def __post_init__(self) -> None:
        if self.schema_version != 1:
            raise ValueError("unsupported operator view schema version")
        if self.token_version <= 0 or self.revision <= 0:
            raise ValueError("operator view versions must be positive")
        if tuple(sorted(self.additional_permissions)) != self.additional_permissions:
            raise ValueError("operator view additional permissions must be sorted")
        if tuple(sorted(self.effective_permissions)) != self.effective_permissions:
            raise ValueError("operator view effective permissions must be sorted")

    @classmethod
    def from_record(cls, record: ControlPlaneOperatorRecord) -> ControlPlaneOperatorView:
        return cls(
            operator_id=record.id,
            username=record.username,
            display_name=record.display_name,
            role=record.role,
            status=record.status,
            additional_permissions=tuple(sorted(record.additional_permissions)),
            effective_permissions=tuple(sorted(record.effective_permissions)),
            created_at=record.created_at,
            updated_at=record.updated_at,
            disabled_at=record.disabled_at,
            revoked_at=record.revoked_at,
            token_version=record.token_version,
            revision=record.revision,
        )


@dataclass(frozen=True, slots=True)
class ControlPlaneOperatorViewPage:
    """Bounded operator page safe for the local management API."""

    items: tuple[ControlPlaneOperatorView, ...]
    page: ControlPlaneOperatorPageInfo
    schema_version: int = 1

    def __post_init__(self) -> None:
        if self.schema_version != 1:
            raise ValueError("unsupported operator view page schema version")
        if len(self.items) != self.page.returned:
            raise ValueError("operator view page count must match items")


@dataclass(frozen=True, slots=True, repr=False)
class ControlPlaneOperatorCredentialGrant:
    """One-time plaintext credential returned only to the creating administrator."""

    operator: ControlPlaneOperatorView
    token: ControlPlaneOperatorToken
    result_code: str
    schema_version: int = 1

    def __post_init__(self) -> None:
        if self.result_code not in {
            "operator.created",
            "operator.credential-rotated",
        }:
            raise ValueError("unsupported operator credential grant result code")
        if self.schema_version != 1:
            raise ValueError("unsupported operator credential grant schema version")

    def __repr__(self) -> str:
        return (
            "ControlPlaneOperatorCredentialGrant("
            f"operator={self.operator!r}, token=<redacted>, result_code={self.result_code!r})"
        )


class ControlPlaneOperatorApi:
    """Apply exact RBAC checks around local operator registry mutations."""

    def __init__(
        self,
        *,
        registry: ControlPlaneOperatorRegistry,
        manager: ControlPlaneOperatorManager,
        access: ControlPlaneOperatorSessionAdministration,
        events: EventBus,
        clock: ControlPlaneOperatorApiClock = _utc_now,
    ) -> None:
        if not callable(clock):
            raise TypeError("operator API clock must be callable")
        self._registry = registry
        self._manager = manager
        self._access = access
        self._events = events
        self._clock = clock

    async def list_operators(
        self,
        actor: ControlPlanePrincipal,
        request: ControlPlaneOperatorPageRequest = DEFAULT_CONTROL_PLANE_OPERATOR_PAGE_REQUEST,
    ) -> ControlPlaneOperatorViewPage:
        self._require(actor, CONTROL_PLANE_OPERATORS_READ_PERMISSION)
        page = await self._registry.list_page(request)
        await self._emit(
            "control-plane.operator.management.listed",
            actor=actor,
            action="operator.list",
            resource="control-plane:operators",
            result_code="operator.listed",
        )
        return ControlPlaneOperatorViewPage(
            items=tuple(ControlPlaneOperatorView.from_record(item) for item in page.items),
            page=page.page,
        )

    async def create_operator(
        self,
        actor: ControlPlanePrincipal,
        *,
        username: str,
        display_name: str,
        role: ControlPlaneOperatorRole,
        token: ControlPlaneOperatorToken,
        additional_permissions: frozenset[str] = frozenset(),
    ) -> ControlPlaneOperatorCredentialGrant:
        self._require(actor, CONTROL_PLANE_OPERATORS_CREATE_PERMISSION)
        now = self._now()
        record = ControlPlaneOperatorRecord(
            id=uuid4(),
            username=username,
            display_name=display_name,
            role=role,
            token_digest=token.digest,
            additional_permissions=additional_permissions,
            created_at=now,
            updated_at=now,
        )
        await self._registry.add(record)
        await self._emit(
            "control-plane.operator.management.created",
            actor=actor,
            action="operator.create",
            resource=f"operator:{record.id}",
            result_code="operator.created",
            operator=record,
        )
        return ControlPlaneOperatorCredentialGrant(
            operator=ControlPlaneOperatorView.from_record(record),
            token=token,
            result_code="operator.created",
        )

    async def update_operator(
        self,
        actor: ControlPlanePrincipal,
        operator_id: UUID,
        *,
        expected_revision: int,
        display_name: str,
        role: ControlPlaneOperatorRole,
        additional_permissions: frozenset[str] = frozenset(),
    ) -> ControlPlaneOperatorView:
        self._require(actor, CONTROL_PLANE_OPERATORS_UPDATE_PERMISSION)
        current = await self._required(operator_id)
        if current.status is ControlPlaneOperatorStatus.REVOKED:
            raise ControlPlaneOperatorStateError("revoked operator cannot be updated")
        updated_at = self._now()
        if updated_at < current.updated_at:
            raise ValueError("operator API clock moved backwards")
        updated = replace(
            current,
            display_name=display_name,
            role=ControlPlaneOperatorRole(role),
            additional_permissions=additional_permissions,
            updated_at=updated_at,
            revision=current.revision + 1,
        )
        committed = await self._registry.replace(updated, expected_revision=expected_revision)
        await self._emit(
            "control-plane.operator.management.updated",
            actor=actor,
            action="operator.update",
            resource=f"operator:{committed.id}",
            result_code="operator.updated",
            operator=committed,
        )
        return ControlPlaneOperatorView.from_record(committed)

    async def rotate_credential(
        self,
        actor: ControlPlanePrincipal,
        operator_id: UUID,
        token: ControlPlaneOperatorToken,
        *,
        expected_revision: int,
    ) -> ControlPlaneOperatorCredentialGrant:
        self._require(actor, CONTROL_PLANE_OPERATORS_ROTATE_PERMISSION)
        receipt = await self._manager.rotate_credential(
            operator_id,
            token,
            expected_revision=expected_revision,
        )
        await self._access.invalidate_operator_sessions(
            operator_id,
            actor=actor.name,
            reason=ControlPlaneOperatorSessionRevocationReason.CREDENTIAL_ROTATED,
        )
        operator = await self._required(operator_id)
        await self._emit_receipt(actor, receipt)
        return ControlPlaneOperatorCredentialGrant(
            operator=ControlPlaneOperatorView.from_record(operator),
            token=token,
            result_code=receipt.result_code,
        )

    async def disable(
        self,
        actor: ControlPlanePrincipal,
        operator_id: UUID,
        *,
        expected_revision: int,
    ) -> ControlPlaneOperatorMutationReceipt:
        self._require(actor, CONTROL_PLANE_OPERATORS_DISABLE_PERMISSION)
        receipt = await self._manager.disable(operator_id, expected_revision=expected_revision)
        await self._access.invalidate_operator_sessions(
            operator_id,
            actor=actor.name,
            reason=ControlPlaneOperatorSessionRevocationReason.OPERATOR_INACTIVE,
        )
        await self._emit_receipt(actor, receipt)
        return receipt

    async def reactivate(
        self,
        actor: ControlPlanePrincipal,
        operator_id: UUID,
        *,
        expected_revision: int,
    ) -> ControlPlaneOperatorMutationReceipt:
        self._require(actor, CONTROL_PLANE_OPERATORS_DISABLE_PERMISSION)
        receipt = await self._manager.reactivate(operator_id, expected_revision=expected_revision)
        await self._emit_receipt(actor, receipt)
        return receipt

    async def revoke(
        self,
        actor: ControlPlanePrincipal,
        operator_id: UUID,
        *,
        expected_revision: int,
    ) -> ControlPlaneOperatorMutationReceipt:
        self._require(actor, CONTROL_PLANE_OPERATORS_REVOKE_PERMISSION)
        receipt = await self._manager.revoke(operator_id, expected_revision=expected_revision)
        await self._access.invalidate_operator_sessions(
            operator_id,
            actor=actor.name,
            reason=ControlPlaneOperatorSessionRevocationReason.OPERATOR_INACTIVE,
        )
        await self._emit_receipt(actor, receipt)
        return receipt

    async def revoke_session(
        self,
        actor: ControlPlanePrincipal,
        session_id: UUID,
    ) -> bool:
        return await self._access.revoke_session(session_id, actor=actor)

    async def revoke_operator_sessions(
        self,
        actor: ControlPlanePrincipal,
        operator_id: UUID,
    ) -> int:
        return await self._access.revoke_operator_sessions(operator_id, actor=actor)

    async def _required(self, operator_id: UUID) -> ControlPlaneOperatorRecord:
        record = await self._registry.get(operator_id)
        if record is None:
            from phoenix_os.control_plane.errors import ControlPlaneOperatorNotFoundError

            raise ControlPlaneOperatorNotFoundError("control-plane operator was not found")
        return record

    async def _emit_receipt(
        self,
        actor: ControlPlanePrincipal,
        receipt: ControlPlaneOperatorMutationReceipt,
    ) -> None:
        await self._emit(
            f"control-plane.operator.management.{receipt.action.value}",
            actor=actor,
            action=f"operator.{receipt.action.value}",
            resource=f"operator:{receipt.operator_id}",
            result_code=receipt.result_code,
            operator=await self._required(receipt.operator_id),
        )

    async def _emit(
        self,
        name: str,
        *,
        actor: ControlPlanePrincipal,
        action: str,
        resource: str,
        result_code: str,
        operator: ControlPlaneOperatorRecord | None = None,
    ) -> None:
        payload: dict[str, object] = {
            "action": action,
            "actor": actor.name,
            "outcome": "success",
            "resource": resource,
            "result_code": result_code,
        }
        if operator is not None:
            payload.update(
                {
                    "operator_id": str(operator.id),
                    "operator_role": operator.role.value,
                    "operator_status": operator.status.value,
                    "operator_username": operator.username,
                }
            )
        try:
            await self._events.emit(
                name,
                source="phoenix.control-plane",
                payload=payload,
            )
        except (BusClosedError, RuntimeError):
            pass

    def _now(self) -> datetime:
        now = self._clock()
        if now.tzinfo is None:
            raise ValueError("operator API clock must return a timezone-aware datetime")
        return now

    @staticmethod
    def _require(actor: ControlPlanePrincipal, permission: str) -> None:
        if permission not in actor.permissions:
            raise ControlPlaneOperatorPermissionDeniedError(
                f"operator management permission denied: {permission}"
            )
