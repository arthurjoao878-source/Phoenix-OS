"""Human durable reconciliation HTTP boundary for Maintainer sessions."""

from __future__ import annotations

import asyncio
import json
import secrets
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from http import HTTPStatus
from typing import Protocol, runtime_checkable
from uuid import UUID

from phoenix_os.agent.durable_contracts import (
    DurableAgentRunId,
    DurableRunVersion,
    ExecutionAttemptId,
    ReconciliationDecision,
)
from phoenix_os.agent.durable_reconciliation_administration import (
    DurableReconciliationAdministrationResult,
)
from phoenix_os.agent.errors import (
    AgentAdministrationAccessDeniedError,
    AgentError,
    AgentLimitExceededError,
    AgentServiceUnavailableError,
    AgentStateConflictError,
)
from phoenix_os.control_plane.csrf import ControlPlaneBrowserOrigin
from phoenix_os.control_plane.durable_administration_protection import (
    ControlPlaneDurableAdministrationConfirmationProof,
)
from phoenix_os.control_plane.durable_reconciliation_administration import (
    ControlPlaneDurableReconciliationConfirmation,
)
from phoenix_os.control_plane.durable_session_access import (
    ControlPlaneDurableSessionAuthentication,
)
from phoenix_os.control_plane.errors import (
    ControlPlaneCommandPermissionDeniedError,
    ControlPlaneConfirmationRejectedError,
    ControlPlaneDurableSessionCsrfRejectedError,
    ControlPlaneStepUpRejectedError,
    PhoenixControlPlaneError,
)

DURABLE_RECONCILIATION_CONTROL_PLANE_BASE_PATH = "/v1/control-plane/agent/durable-reconciliation"
_DURABLE_RECONCILIATION_PREPARE_PATH = f"{DURABLE_RECONCILIATION_CONTROL_PLANE_BASE_PATH}/prepare"
_DURABLE_RECONCILIATION_CONFIRMATION_PREFIX = (
    f"{DURABLE_RECONCILIATION_CONTROL_PLANE_BASE_PATH}/confirmations/"
)

DEFAULT_CONTROL_PLANE_DURABLE_RECONCILIATION_HTTP_CAPACITY = 256
MAX_CONTROL_PLANE_DURABLE_RECONCILIATION_HTTP_CAPACITY = 4096
_NO_STORE = {"Cache-Control": "no-store"}


class ControlPlaneDurableReconciliationCsrfVerifier(Protocol):
    """Durable-session CSRF verification boundary."""

    async def verify_csrf(
        self,
        token_value: str | None,
        authentication: ControlPlaneDurableSessionAuthentication,
        *,
        supplied_origin: ControlPlaneBrowserOrigin,
        expected_origin: ControlPlaneBrowserOrigin,
    ) -> object: ...


@runtime_checkable
class ControlPlaneDurableReconciliationHttpAdministration(Protocol):
    """Server-owned reconciliation orchestration required by the HTTP adapter."""

    async def prepare_confirmation(
        self,
        authentication: ControlPlaneDurableSessionAuthentication,
        run_id: DurableAgentRunId,
        attempt_id: ExecutionAttemptId,
        expected_version: DurableRunVersion,
        decision: ReconciliationDecision,
        *,
        step_up_token: str | None,
    ) -> ControlPlaneDurableReconciliationConfirmation: ...

    async def confirm_and_apply(
        self,
        authentication: ControlPlaneDurableSessionAuthentication,
        confirmation: ControlPlaneDurableReconciliationConfirmation,
        *,
        step_up_token: str | None,
    ) -> DurableReconciliationAdministrationResult: ...

    async def discard_confirmation(
        self,
        confirmation: ControlPlaneDurableReconciliationConfirmation,
    ) -> None: ...


type ControlPlaneDurableReconciliationHttpClock = Callable[[], datetime]


@dataclass(frozen=True, slots=True)
class _AuthenticationBinding:
    session_id: UUID
    operator_id: UUID
    generation: int
    principal: str


@dataclass(frozen=True, slots=True)
class _PendingConfirmation:
    confirmation: ControlPlaneDurableReconciliationConfirmation = field(repr=False)
    authentication: _AuthenticationBinding

    @property
    def id(self) -> UUID:
        return self.confirmation.intent.id

    @property
    def expires_at(self) -> datetime:
        return self.confirmation.expires_at


class _PendingConfirmationRejectedError(Exception):
    pass


class _PendingConfirmationCapacityError(Exception):
    pass


class _AdministrationContractError(Exception):
    pass


class ControlPlaneDurableReconciliationHttpAdapter:
    """Expose one bounded two-phase reconciliation flow to Maintainer sessions."""

    def __init__(
        self,
        *,
        administration: ControlPlaneDurableReconciliationHttpAdministration,
        boundary: ControlPlaneDurableReconciliationCsrfVerifier,
        capacity: int = DEFAULT_CONTROL_PLANE_DURABLE_RECONCILIATION_HTTP_CAPACITY,
        clock: ControlPlaneDurableReconciliationHttpClock | None = None,
    ) -> None:
        if not isinstance(
            administration,
            ControlPlaneDurableReconciliationHttpAdministration,
        ):
            raise TypeError("durable reconciliation HTTP requires reconciliation administration")
        if not callable(getattr(boundary, "verify_csrf", None)):
            raise TypeError("durable reconciliation HTTP requires a CSRF boundary")
        if isinstance(capacity, bool) or not isinstance(capacity, int):
            raise TypeError("durable reconciliation HTTP capacity must be an integer")
        if capacity <= 0 or capacity > MAX_CONTROL_PLANE_DURABLE_RECONCILIATION_HTTP_CAPACITY:
            raise ValueError("durable reconciliation HTTP capacity is outside supported bounds")
        selected_clock = (lambda: datetime.now(UTC)) if clock is None else clock
        if not callable(selected_clock):
            raise TypeError("durable reconciliation HTTP clock must be callable")

        self._administration = administration
        self._boundary = boundary
        self._capacity = capacity
        self._clock: ControlPlaneDurableReconciliationHttpClock = selected_clock
        self._pending: dict[UUID, _PendingConfirmation] = {}
        self._preparing = 0
        self._closed = False
        self._lock = asyncio.Lock()

    @property
    def administration(self) -> ControlPlaneDurableReconciliationHttpAdministration:
        return self._administration

    @property
    def closed(self) -> bool:
        """Return whether new human reconciliation admission is closed."""

        return self._closed

    async def close(self) -> None:
        """Close admission and discard every server-held pending confirmation."""

        await _await_drain(self._close_owned())

    async def _close_owned(self) -> None:
        async with self._lock:
            if self._closed:
                return
            self._closed = True
            pending = tuple(self._pending.values())
            self._pending.clear()
            for reservation in pending:
                await self._discard_without_masking(reservation.confirmation)

    @staticmethod
    def handles(path: str) -> bool:
        return path == _DURABLE_RECONCILIATION_PREPARE_PATH or (
            _confirmation_route(path) is not None
        )

    async def dispatch(
        self,
        *,
        authentication: ControlPlaneDurableSessionAuthentication,
        method: str,
        path: str,
        query: Mapping[str, tuple[str, ...]],
        headers: Mapping[str, tuple[str, ...]],
        body: bytes,
        server_origin: ControlPlaneBrowserOrigin,
    ) -> tuple[HTTPStatus, Mapping[str, object], dict[str, str]]:
        if not isinstance(authentication, ControlPlaneDurableSessionAuthentication):
            raise TypeError("authentication must be ControlPlaneDurableSessionAuthentication")
        if method != "POST":
            return (
                HTTPStatus.METHOD_NOT_ALLOWED,
                {"error": "method_not_allowed"},
                {"Allow": "POST", **_NO_STORE},
            )
        if query:
            return HTTPStatus.BAD_REQUEST, {"error": "invalid_request"}, dict(_NO_STORE)

        try:
            await self._require_open()
            await self._verify_csrf(authentication, headers, server_origin)
            await self._prune_expired()

            if path == _DURABLE_RECONCILIATION_PREPARE_PATH:
                return await self._prepare(
                    authentication=authentication,
                    headers=headers,
                    body=body,
                )

            confirmation_id = _confirmation_route(path)
            if confirmation_id is None:
                return HTTPStatus.NOT_FOUND, {"error": "not_found"}, dict(_NO_STORE)
            return await self._confirm(
                authentication=authentication,
                confirmation_id=confirmation_id,
                headers=headers,
                body=body,
            )
        except (
            ControlPlaneDurableSessionCsrfRejectedError,
            ControlPlaneStepUpRejectedError,
            ControlPlaneConfirmationRejectedError,
            _PendingConfirmationRejectedError,
        ):
            return HTTPStatus.FORBIDDEN, {"error": "request_rejected"}, dict(_NO_STORE)
        except (
            ControlPlaneCommandPermissionDeniedError,
            AgentAdministrationAccessDeniedError,
        ):
            return HTTPStatus.FORBIDDEN, {"error": "forbidden"}, dict(_NO_STORE)
        except AgentStateConflictError:
            return (
                HTTPStatus.CONFLICT,
                {"error": "reconciliation_conflict"},
                dict(_NO_STORE),
            )
        except (AgentLimitExceededError, _PendingConfirmationCapacityError):
            return (
                HTTPStatus.TOO_MANY_REQUESTS,
                {"error": "reconciliation_capacity_exhausted"},
                {"Retry-After": "1", **_NO_STORE},
            )
        except (AgentServiceUnavailableError, _AdministrationContractError):
            return (
                HTTPStatus.SERVICE_UNAVAILABLE,
                {"error": "reconciliation_unavailable"},
                dict(_NO_STORE),
            )
        except AgentError:
            return (
                HTTPStatus.SERVICE_UNAVAILABLE,
                {"error": "reconciliation_unavailable"},
                dict(_NO_STORE),
            )
        except PhoenixControlPlaneError:
            return (
                HTTPStatus.SERVICE_UNAVAILABLE,
                {"error": "reconciliation_unavailable"},
                dict(_NO_STORE),
            )
        except (
            KeyError,
            TypeError,
            ValueError,
            UnicodeDecodeError,
            json.JSONDecodeError,
        ):
            return (
                HTTPStatus.BAD_REQUEST,
                {"error": "invalid_reconciliation_request"},
                dict(_NO_STORE),
            )

    async def _prepare(
        self,
        *,
        authentication: ControlPlaneDurableSessionAuthentication,
        headers: Mapping[str, tuple[str, ...]],
        body: bytes,
    ) -> tuple[HTTPStatus, Mapping[str, object], dict[str, str]]:
        document = _json_object(body)
        _require_fields(
            document,
            required={"run_id", "attempt_id", "expected_version", "decision"},
        )

        await self._reserve_prepare_slot()
        slot_reserved = True
        confirmation: ControlPlaneDurableReconciliationConfirmation | None = None
        stored = False
        try:
            confirmation = await self._administration.prepare_confirmation(
                authentication,
                DurableAgentRunId(UUID(_string(document, "run_id"))),
                ExecutionAttemptId(UUID(_string(document, "attempt_id"))),
                DurableRunVersion(_integer(document, "expected_version")),
                ReconciliationDecision(_string(document, "decision")),
                step_up_token=_one_optional_header(headers, "x-phoenix-step-up"),
            )
            if not isinstance(
                confirmation,
                ControlPlaneDurableReconciliationConfirmation,
            ):
                raise _AdministrationContractError()

            now = self._now()
            if now >= confirmation.expires_at:
                raise ControlPlaneConfirmationRejectedError(
                    "durable administration confirmation failed"
                )
            response = _confirmation_to_dict(confirmation)
            pending = _PendingConfirmation(
                confirmation=confirmation,
                authentication=_authentication_binding(authentication),
            )
            async with self._lock:
                self._preparing -= 1
                slot_reserved = False
                if self._closed:
                    raise _AdministrationContractError()
                if pending.id in self._pending:
                    raise _AdministrationContractError()
                self._pending[pending.id] = pending
                stored = True
            return HTTPStatus.CREATED, response, dict(_NO_STORE)
        except (Exception, asyncio.CancelledError):
            if slot_reserved:
                async with self._lock:
                    self._preparing -= 1
            if confirmation is not None and not stored:
                await self._discard_without_masking(confirmation)
            raise

    async def _confirm(
        self,
        *,
        authentication: ControlPlaneDurableSessionAuthentication,
        confirmation_id: UUID,
        headers: Mapping[str, tuple[str, ...]],
        body: bytes,
    ) -> tuple[HTTPStatus, Mapping[str, object], dict[str, str]]:
        document = _json_object(body)
        _require_fields(document, required={"proof"})
        supplied_proof = ControlPlaneDurableAdministrationConfirmationProof(
            _string(document, "proof")
        )

        pending: _PendingConfirmation | None
        expired: _PendingConfirmation | None = None
        async with self._lock:
            if self._closed:
                raise _AdministrationContractError()
            pending = self._pending.get(confirmation_id)
            if pending is None:
                return (
                    HTTPStatus.NOT_FOUND,
                    {"error": "confirmation_not_found"},
                    dict(_NO_STORE),
                )
            now = self._now()
            if now >= pending.expires_at:
                expired = self._pending.pop(confirmation_id)
            else:
                if pending.authentication != _authentication_binding(authentication):
                    raise _PendingConfirmationRejectedError()
                if not secrets.compare_digest(
                    supplied_proof.digest,
                    pending.confirmation.challenge.proof.digest,
                ):
                    raise _PendingConfirmationRejectedError()
                del self._pending[confirmation_id]

        if expired is not None:
            await self._discard_without_masking(expired.confirmation)
            raise _PendingConfirmationRejectedError()

        assert pending is not None
        try:
            result = await self._administration.confirm_and_apply(
                authentication,
                pending.confirmation,
                step_up_token=_one_optional_header(headers, "x-phoenix-step-up"),
            )
        except (Exception, asyncio.CancelledError):
            await self._discard_without_masking(pending.confirmation)
            raise
        if not isinstance(result, DurableReconciliationAdministrationResult):
            raise _AdministrationContractError()
        return HTTPStatus.OK, _result_to_dict(result), dict(_NO_STORE)

    async def _require_open(self) -> None:
        async with self._lock:
            if self._closed:
                raise _AdministrationContractError()

    async def _reserve_prepare_slot(self) -> None:
        async with self._lock:
            if self._closed:
                raise _AdministrationContractError()
            if len(self._pending) + self._preparing >= self._capacity:
                raise _PendingConfirmationCapacityError()
            self._preparing += 1

    async def _prune_expired(self) -> None:
        now = self._now()
        async with self._lock:
            if self._closed:
                raise _AdministrationContractError()
            expired = tuple(
                pending for pending in self._pending.values() if now >= pending.expires_at
            )
            for pending in expired:
                self._pending.pop(pending.id, None)
        for pending in expired:
            await self._discard_without_masking(pending.confirmation)

    async def _discard_without_masking(
        self,
        confirmation: ControlPlaneDurableReconciliationConfirmation,
    ) -> None:
        try:
            await _await_drain(self._administration.discard_confirmation(confirmation))
        except BaseException:
            pass

    async def _verify_csrf(
        self,
        authentication: ControlPlaneDurableSessionAuthentication,
        headers: Mapping[str, tuple[str, ...]],
        server_origin: ControlPlaneBrowserOrigin,
    ) -> None:
        supplied_origin = _exact_origin(headers, server_origin)
        await self._boundary.verify_csrf(
            _one_optional_header(headers, "x-phoenix-csrf"),
            authentication,
            supplied_origin=supplied_origin,
            expected_origin=server_origin,
        )

    def _now(self) -> datetime:
        value = self._clock()
        if not isinstance(value, datetime):
            raise _AdministrationContractError()
        if value.tzinfo is None or value.utcoffset() is None:
            raise _AdministrationContractError()
        return value


def _authentication_binding(
    authentication: ControlPlaneDurableSessionAuthentication,
) -> _AuthenticationBinding:
    return _AuthenticationBinding(
        session_id=authentication.session_id,
        operator_id=authentication.operator_id,
        generation=authentication.generation,
        principal=authentication.principal.name,
    )


def _confirmation_route(path: str) -> UUID | None:
    if not path.startswith(_DURABLE_RECONCILIATION_CONFIRMATION_PREFIX):
        return None
    suffix = path[len(_DURABLE_RECONCILIATION_CONFIRMATION_PREFIX) :]
    parts = suffix.split("/")
    if len(parts) != 2 or parts[1] != "confirm":
        return None
    try:
        return UUID(parts[0])
    except ValueError:
        return None


def _confirmation_to_dict(
    confirmation: ControlPlaneDurableReconciliationConfirmation,
) -> dict[str, object]:
    preparation = confirmation.preparation
    evidence: dict[str, object] | None = None
    if preparation.evidence_type is not None:
        if preparation.evidence_digest is None or preparation.evidence_observed_at is None:
            raise _AdministrationContractError()
        evidence = {
            "type": preparation.evidence_type,
            "digest": str(preparation.evidence_digest),
            "observed_at": preparation.evidence_observed_at.isoformat(),
        }

    return {
        "schema_version": 1,
        "confirmation": {
            "id": str(confirmation.intent.id),
            "action": confirmation.intent.action,
            "resource": confirmation.intent.resource,
            "fingerprint": confirmation.intent.fingerprint,
            "proof": confirmation.challenge.proof.value,
            "issued_at": confirmation.challenge.issued_at.isoformat(),
            "expires_at": confirmation.expires_at.isoformat(),
        },
        "preparation": {
            "run_id": str(preparation.run_id),
            "attempt_id": str(preparation.attempt_id),
            "expected_version": preparation.expected_version.value,
            "checkpoint_id": str(preparation.checkpoint_id),
            "checkpoint_digest": str(preparation.checkpoint_digest),
            "decision": preparation.decision.value,
            "requested_at": preparation.requested_at.isoformat(),
            "prepared_at": preparation.prepared_at.isoformat(),
            "expires_at": preparation.expires_at.isoformat(),
            "evidence": evidence,
        },
    }


def _result_to_dict(
    result: DurableReconciliationAdministrationResult,
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "reconciliation": {
            "run_id": str(result.run_id),
            "attempt_id": str(result.attempt_id),
            "status": result.status.value,
            "run_version": result.run_version.value,
            "checkpoint_id": str(result.checkpoint_id),
            "checkpoint_sequence": result.checkpoint_sequence.value,
            "checkpoint_digest": str(result.checkpoint_digest),
            "decision": result.decision.value,
            "applied_at": result.applied_at.isoformat(),
        },
    }


def _json_object(body: bytes) -> dict[str, object]:
    if not body:
        raise ValueError("JSON body is required")
    document = json.loads(body.decode("utf-8"))
    if not isinstance(document, dict):
        raise TypeError("JSON body must be an object")
    if not all(isinstance(key, str) for key in document):
        raise TypeError("JSON object keys must be strings")
    return document


def _require_fields(
    document: Mapping[str, object],
    *,
    required: set[str],
) -> None:
    if set(document) != required:
        raise ValueError("JSON object fields do not match the exact contract")


def _string(document: Mapping[str, object], field_name: str) -> str:
    value = document[field_name]
    if not isinstance(value, str) or not value:
        raise TypeError(f"{field_name} must be a non-empty string")
    return value


def _integer(document: Mapping[str, object], field_name: str) -> int:
    value = document[field_name]
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{field_name} must be an integer")
    return value


def _one_optional_header(
    headers: Mapping[str, tuple[str, ...]],
    name: str,
) -> str | None:
    values = headers.get(name, ())
    if not values:
        return None
    if len(values) != 1 or not values[0]:
        raise ValueError(f"one {name} header is required")
    return values[0]


def _exact_origin(
    headers: Mapping[str, tuple[str, ...]],
    server_origin: ControlPlaneBrowserOrigin,
) -> ControlPlaneBrowserOrigin:
    try:
        origin = ControlPlaneBrowserOrigin(_one_optional_header(headers, "origin") or "")
    except ValueError:
        raise ControlPlaneDurableSessionCsrfRejectedError(
            "durable reconciliation request rejected"
        ) from None
    if origin != server_origin:
        raise ControlPlaneDurableSessionCsrfRejectedError("durable reconciliation request rejected")
    return origin


async def _await_drain(operation: Awaitable[None]) -> None:
    task = asyncio.ensure_future(operation)
    cancelled = False
    while True:
        try:
            await asyncio.shield(task)
            break
        except asyncio.CancelledError:
            cancelled = True
            if task.done():
                break
    task.result()
    if cancelled:
        raise asyncio.CancelledError()
