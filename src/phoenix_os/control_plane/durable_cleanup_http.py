"""Human durable cleanup HTTP boundary for Maintainer sessions."""

from __future__ import annotations

import asyncio
import json
import secrets
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from http import HTTPStatus
from typing import Protocol, runtime_checkable
from uuid import UUID

from phoenix_os.agent.durable_retention_worker import DurableRetentionWorkerReport
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
from phoenix_os.control_plane.durable_cleanup_administration import (
    ControlPlaneDurableCleanupConfirmation,
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

DURABLE_CLEANUP_CONTROL_PLANE_BASE_PATH = "/v1/control-plane/agent/durable-cleanup"
_DURABLE_CLEANUP_PREPARE_PATH = f"{DURABLE_CLEANUP_CONTROL_PLANE_BASE_PATH}/prepare"
_DURABLE_CLEANUP_CONFIRMATION_PREFIX = f"{DURABLE_CLEANUP_CONTROL_PLANE_BASE_PATH}/confirmations/"

DEFAULT_CONTROL_PLANE_DURABLE_CLEANUP_HTTP_CAPACITY = 256
MAX_CONTROL_PLANE_DURABLE_CLEANUP_HTTP_CAPACITY = 4096
_NO_STORE = {"Cache-Control": "no-store"}


class ControlPlaneDurableCleanupCsrfVerifier(Protocol):
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
class ControlPlaneDurableCleanupHttpAdministration(Protocol):
    """Server-owned cleanup orchestration required by the HTTP adapter."""

    async def prepare_confirmation(
        self,
        authentication: ControlPlaneDurableSessionAuthentication,
        *,
        step_up_token: str | None,
    ) -> ControlPlaneDurableCleanupConfirmation: ...

    async def confirm_and_run(
        self,
        authentication: ControlPlaneDurableSessionAuthentication,
        confirmation: ControlPlaneDurableCleanupConfirmation,
        *,
        step_up_token: str | None,
    ) -> DurableRetentionWorkerReport: ...


type ControlPlaneDurableCleanupHttpClock = Callable[[], datetime]


@dataclass(frozen=True, slots=True)
class _AuthenticationBinding:
    session_id: UUID
    operator_id: UUID
    generation: int
    principal: str


@dataclass(frozen=True, slots=True)
class _PendingConfirmation:
    confirmation: ControlPlaneDurableCleanupConfirmation = field(repr=False)
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


class ControlPlaneDurableCleanupHttpAdapter:
    """Expose one bounded two-phase cleanup flow to Maintainer sessions."""

    def __init__(
        self,
        *,
        administration: ControlPlaneDurableCleanupHttpAdministration,
        boundary: ControlPlaneDurableCleanupCsrfVerifier,
        capacity: int = DEFAULT_CONTROL_PLANE_DURABLE_CLEANUP_HTTP_CAPACITY,
        clock: ControlPlaneDurableCleanupHttpClock | None = None,
    ) -> None:
        if not isinstance(administration, ControlPlaneDurableCleanupHttpAdministration):
            raise TypeError("durable cleanup HTTP requires cleanup administration")
        if not callable(getattr(boundary, "verify_csrf", None)):
            raise TypeError("durable cleanup HTTP requires a CSRF boundary")
        if isinstance(capacity, bool) or not isinstance(capacity, int):
            raise TypeError("durable cleanup HTTP capacity must be an integer")
        if capacity <= 0 or capacity > MAX_CONTROL_PLANE_DURABLE_CLEANUP_HTTP_CAPACITY:
            raise ValueError("durable cleanup HTTP capacity is outside supported bounds")
        selected_clock = (lambda: datetime.now(UTC)) if clock is None else clock
        if not callable(selected_clock):
            raise TypeError("durable cleanup HTTP clock must be callable")

        self._administration = administration
        self._boundary = boundary
        self._capacity = capacity
        self._clock: ControlPlaneDurableCleanupHttpClock = selected_clock
        self._pending: dict[UUID, _PendingConfirmation] = {}
        self._preparing = 0
        self._closed = False
        self._lock = asyncio.Lock()

    @property
    def administration(self) -> ControlPlaneDurableCleanupHttpAdministration:
        return self._administration

    @property
    def closed(self) -> bool:
        """Return whether new human cleanup admission is closed."""

        return self._closed

    async def close(self) -> None:
        """Close HTTP admission and forget every server-held cleanup confirmation."""

        async with self._lock:
            self._closed = True
            self._pending.clear()

    @staticmethod
    def handles(path: str) -> bool:
        return path == _DURABLE_CLEANUP_PREPARE_PATH or _confirmation_route(path) is not None

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

            if path == _DURABLE_CLEANUP_PREPARE_PATH:
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
            return HTTPStatus.CONFLICT, {"error": "cleanup_conflict"}, dict(_NO_STORE)
        except (AgentLimitExceededError, _PendingConfirmationCapacityError):
            return (
                HTTPStatus.TOO_MANY_REQUESTS,
                {"error": "cleanup_capacity_exhausted"},
                {"Retry-After": "1", **_NO_STORE},
            )
        except (AgentServiceUnavailableError, _AdministrationContractError):
            return (
                HTTPStatus.SERVICE_UNAVAILABLE,
                {"error": "cleanup_unavailable"},
                dict(_NO_STORE),
            )
        except AgentError:
            return (
                HTTPStatus.SERVICE_UNAVAILABLE,
                {"error": "cleanup_unavailable"},
                dict(_NO_STORE),
            )
        except PhoenixControlPlaneError:
            return (
                HTTPStatus.SERVICE_UNAVAILABLE,
                {"error": "cleanup_unavailable"},
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
                {"error": "invalid_cleanup_request"},
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
        _require_fields(document, required=set())

        await self._reserve_prepare_slot()
        slot_reserved = True
        confirmation: ControlPlaneDurableCleanupConfirmation | None = None
        try:
            confirmation = await self._administration.prepare_confirmation(
                authentication,
                step_up_token=_one_optional_header(headers, "x-phoenix-step-up"),
            )
            if not isinstance(confirmation, ControlPlaneDurableCleanupConfirmation):
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
            return HTTPStatus.CREATED, response, dict(_NO_STORE)
        except (Exception, asyncio.CancelledError):
            if slot_reserved:
                async with self._lock:
                    self._preparing -= 1
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
            if pending.authentication != _authentication_binding(authentication):
                raise _PendingConfirmationRejectedError()
            if not secrets.compare_digest(
                supplied_proof.digest,
                pending.confirmation.challenge.proof.digest,
            ):
                raise _PendingConfirmationRejectedError()
            del self._pending[confirmation_id]

        result = await self._administration.confirm_and_run(
            authentication,
            pending.confirmation,
            step_up_token=_one_optional_header(headers, "x-phoenix-step-up"),
        )
        if not isinstance(result, DurableRetentionWorkerReport):
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
            expired_ids = tuple(
                pending.id for pending in self._pending.values() if now >= pending.expires_at
            )
            for confirmation_id in expired_ids:
                self._pending.pop(confirmation_id, None)

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
    if not path.startswith(_DURABLE_CLEANUP_CONFIRMATION_PREFIX):
        return None
    suffix = path[len(_DURABLE_CLEANUP_CONFIRMATION_PREFIX) :]
    parts = suffix.split("/")
    if len(parts) != 2 or parts[1] != "confirm":
        return None
    try:
        return UUID(parts[0])
    except ValueError:
        return None


def _confirmation_to_dict(
    confirmation: ControlPlaneDurableCleanupConfirmation,
) -> dict[str, object]:
    bounds = confirmation.intent.bounds
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
        "cleanup": {
            "requested_at": confirmation.intent.requested_at.isoformat(),
            "bounds": {
                "page_size": bounds.page_size,
                "max_candidates": bounds.max_candidates,
                "pass_timeout_microseconds": bounds.pass_timeout_microseconds,
                "payload_retention_microseconds": bounds.payload_retention_microseconds,
                "metadata_retention_microseconds": bounds.metadata_retention_microseconds,
                "tombstone_retention_microseconds": bounds.tombstone_retention_microseconds,
                "schema_version": bounds.schema_version,
            },
        },
    }


def _result_to_dict(result: DurableRetentionWorkerReport) -> dict[str, object]:
    return {
        "schema_version": 1,
        "cleanup": {
            "admitted": result.admitted,
            "payloads_deleted": result.payloads_deleted,
            "tombstoned": result.tombstoned,
            "purged": result.purged,
            "conflicts": result.conflicts,
            "failed": result.failed,
            "pages": result.pages,
            "exhausted": result.exhausted,
            "timed_out": result.timed_out,
            "stopped": result.stopped,
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
            "durable cleanup request rejected"
        ) from None
    if origin != server_origin:
        raise ControlPlaneDurableSessionCsrfRejectedError("durable cleanup request rejected")
    return origin
