"""HTTP translation layer for the bounded dashboard command API."""

from __future__ import annotations

import asyncio
import json
import math
from collections.abc import Mapping
from datetime import datetime, timedelta
from http import HTTPStatus
from uuid import UUID, uuid4

from phoenix_os.control_plane.auth import ControlPlanePrincipal
from phoenix_os.control_plane.command_api import ControlPlaneCommandApi
from phoenix_os.control_plane.commands import ControlPlaneCommandAction, IdempotencyKey
from phoenix_os.control_plane.confirmation import ControlPlaneConfirmationProof
from phoenix_os.control_plane.csrf import (
    ControlPlaneBrowserOrigin,
    ControlPlaneCsrfToken,
)
from phoenix_os.control_plane.errors import (
    ControlPlaneCommandBindingError,
    ControlPlaneCommandPermissionDeniedError,
    ControlPlaneCommandStateError,
    ControlPlaneConfirmationCapacityError,
    ControlPlaneConfirmationRejectedError,
    ControlPlaneCsrfRejectedError,
    ControlPlaneIdempotencyCapacityError,
    ControlPlaneIdempotencyConflictError,
)
from phoenix_os.control_plane.job_commands import (
    ControlPlaneCancelJobCommand,
    ControlPlaneCreateJobCommand,
    ControlPlaneRetryDeadLetterJobCommand,
)
from phoenix_os.control_plane.serialization import (
    confirmation_challenge_to_dict,
    csrf_token_to_dict,
    job_command_result_to_dict,
    workflow_command_result_to_dict,
)
from phoenix_os.control_plane.workflow_commands import ControlPlaneCancelWorkflowCommand

_COMMAND_PREFIX = "/v1/control-plane/commands/"


class ControlPlaneCommandHttpAdapter:
    """Translate fixed POST routes without exposing handler implementation details."""

    def __init__(
        self,
        api: ControlPlaneCommandApi,
        *,
        max_concurrency: int = 8,
    ) -> None:
        if max_concurrency <= 0 or max_concurrency > 1024:
            raise ValueError("command concurrency must be between 1 and 1024")
        self._api = api
        self._limit = asyncio.Semaphore(max_concurrency)

    @property
    def api(self) -> ControlPlaneCommandApi:
        return self._api

    @staticmethod
    def handles(path: str) -> bool:
        return path == "/v1/control-plane/csrf" or (
            path.startswith(_COMMAND_PREFIX) and path != "/v1/control-plane/commands/history"
        )

    async def dispatch(
        self,
        *,
        principal: ControlPlanePrincipal,
        method: str,
        path: str,
        headers: Mapping[str, tuple[str, ...]],
        body: bytes,
        server_origin: ControlPlaneBrowserOrigin,
    ) -> tuple[HTTPStatus, Mapping[str, object], dict[str, str]]:
        if method != "POST":
            return HTTPStatus.METHOD_NOT_ALLOWED, {"error": "method_not_allowed"}, {"Allow": "POST"}
        if self._limit.locked():
            return (
                HTTPStatus.TOO_MANY_REQUESTS,
                {"error": "command_api_busy"},
                {"Retry-After": "1"},
            )
        await self._limit.acquire()
        try:
            return await self._dispatch(
                principal=principal,
                path=path,
                headers=headers,
                body=body,
                server_origin=server_origin,
            )
        finally:
            self._limit.release()

    async def _dispatch(
        self,
        *,
        principal: ControlPlanePrincipal,
        path: str,
        headers: Mapping[str, tuple[str, ...]],
        body: bytes,
        server_origin: ControlPlaneBrowserOrigin,
    ) -> tuple[HTTPStatus, Mapping[str, object], dict[str, str]]:
        action = _action_for_path(path)
        target = "control-plane"
        command_id: UUID | None = None
        try:
            origin = _origin(headers, server_origin)
            if path == "/v1/control-plane/csrf":
                if body:
                    raise ValueError("CSRF issuance does not accept a request body")
                token = self._api.issue_csrf(principal, origin)
                return HTTPStatus.OK, csrf_token_to_dict(token), {}

            content_type = _single_required_header(headers, "content-type")
            if content_type.split(";", 1)[0].strip().lower() != "application/json":
                return HTTPStatus.UNSUPPORTED_MEDIA_TYPE, {"error": "json_required"}, {}
            document = _json_object(body)
            key = IdempotencyKey(_single_required_header(headers, "idempotency-key"))
            csrf = ControlPlaneCsrfToken(_single_required_header(headers, "x-phoenix-csrf"))

            if path == f"{_COMMAND_PREFIX}jobs/create":
                create_command = _create_job(document)
                target = create_command.target
                create_result = await self._api.create_job(
                    principal,
                    create_command,
                    key,
                    origin=origin,
                    csrf_token=csrf,
                )
                return _result_response(
                    job_command_result_to_dict(create_result),
                    create_result.receipt.status.value,
                )

            if path == f"{_COMMAND_PREFIX}jobs/retry-dead-letter":
                _require_fields(document, required={"job_id"})
                retry_command = ControlPlaneRetryDeadLetterJobCommand(_uuid(document, "job_id"))
                target = retry_command.target
                retry_result = await self._api.retry_dead_letter_job(
                    principal,
                    retry_command,
                    key,
                    origin=origin,
                    csrf_token=csrf,
                )
                return _result_response(
                    job_command_result_to_dict(retry_result),
                    retry_result.receipt.status.value,
                )

            if path == f"{_COMMAND_PREFIX}jobs/cancel/confirmation":
                _require_fields(document, required={"job_id"}, optional={"command_id"})
                cancel_job_command = ControlPlaneCancelJobCommand(_uuid(document, "job_id"))
                target = cancel_job_command.target
                command_id = _optional_uuid(document, "command_id") or uuid4()
                challenge = await self._api.issue_job_cancel_confirmation(
                    principal,
                    cancel_job_command,
                    key,
                    command_id=command_id,
                    origin=origin,
                    csrf_token=csrf,
                )
                return HTTPStatus.OK, confirmation_challenge_to_dict(challenge), {}

            if path == f"{_COMMAND_PREFIX}jobs/cancel":
                _require_fields(document, required={"job_id", "command_id"})
                cancel_job_command = ControlPlaneCancelJobCommand(_uuid(document, "job_id"))
                target = cancel_job_command.target
                command_id = _uuid(document, "command_id")
                proof = ControlPlaneConfirmationProof(
                    _single_required_header(headers, "x-phoenix-confirmation")
                )
                cancel_job_result = await self._api.cancel_job(
                    principal,
                    cancel_job_command,
                    key,
                    command_id=command_id,
                    origin=origin,
                    csrf_token=csrf,
                    confirmation=proof,
                )
                return _result_response(
                    job_command_result_to_dict(cancel_job_result),
                    cancel_job_result.receipt.status.value,
                )

            if path == f"{_COMMAND_PREFIX}workflows/cancel/confirmation":
                _require_fields(document, required={"workflow_id"}, optional={"command_id"})
                cancel_workflow_command = ControlPlaneCancelWorkflowCommand(
                    _uuid(document, "workflow_id")
                )
                target = cancel_workflow_command.target
                command_id = _optional_uuid(document, "command_id") or uuid4()
                challenge = await self._api.issue_workflow_cancel_confirmation(
                    principal,
                    cancel_workflow_command,
                    key,
                    command_id=command_id,
                    origin=origin,
                    csrf_token=csrf,
                )
                return HTTPStatus.OK, confirmation_challenge_to_dict(challenge), {}

            if path == f"{_COMMAND_PREFIX}workflows/cancel":
                _require_fields(document, required={"workflow_id", "command_id"})
                cancel_workflow_command = ControlPlaneCancelWorkflowCommand(
                    _uuid(document, "workflow_id")
                )
                target = cancel_workflow_command.target
                command_id = _uuid(document, "command_id")
                proof = ControlPlaneConfirmationProof(
                    _single_required_header(headers, "x-phoenix-confirmation")
                )
                cancel_workflow_result = await self._api.cancel_workflow(
                    principal,
                    cancel_workflow_command,
                    key,
                    command_id=command_id,
                    origin=origin,
                    csrf_token=csrf,
                    confirmation=proof,
                )
                return _result_response(
                    workflow_command_result_to_dict(cancel_workflow_result),
                    cancel_workflow_result.receipt.status.value,
                )

            return HTTPStatus.NOT_FOUND, {"error": "not_found"}, {}
        except ControlPlaneCommandPermissionDeniedError:
            await self._api.record_rejection(
                principal,
                action=action,
                target=target,
                result_code="permission.denied",
                command_id=command_id,
            )
            return HTTPStatus.FORBIDDEN, {"error": "forbidden"}, {}
        except ControlPlaneCsrfRejectedError:
            await self._api.record_rejection(
                principal,
                action=action,
                target=target,
                result_code="csrf.rejected",
                command_id=command_id,
            )
            return HTTPStatus.FORBIDDEN, {"error": "request_rejected"}, {}
        except ControlPlaneConfirmationRejectedError:
            await self._api.record_rejection(
                principal,
                action=action,
                target=target,
                result_code="confirmation.rejected",
                command_id=command_id,
            )
            return HTTPStatus.FORBIDDEN, {"error": "request_rejected"}, {}
        except ControlPlaneIdempotencyConflictError:
            return HTTPStatus.CONFLICT, {"error": "idempotency_conflict"}, {}
        except (ControlPlaneIdempotencyCapacityError, ControlPlaneConfirmationCapacityError):
            return (
                HTTPStatus.TOO_MANY_REQUESTS,
                {"error": "command_capacity_exhausted"},
                {"Retry-After": "1"},
            )
        except (ControlPlaneCommandBindingError, ControlPlaneCommandStateError):
            return HTTPStatus.CONFLICT, {"error": "command_conflict"}, {}
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            return HTTPStatus.BAD_REQUEST, {"error": "invalid_command"}, {}
        except RuntimeError:
            return HTTPStatus.SERVICE_UNAVAILABLE, {"error": "commands_unavailable"}, {}


def _result_response(
    payload: Mapping[str, object],
    status: str,
) -> tuple[HTTPStatus, Mapping[str, object], dict[str, str]]:
    return (
        HTTPStatus.OK if status == "succeeded" else HTTPStatus.UNPROCESSABLE_ENTITY,
        payload,
        {},
    )


def _create_job(document: Mapping[str, object]) -> ControlPlaneCreateJobCommand:
    allowed = {
        "arguments",
        "capability",
        "deadline",
        "initial_retry_delay_seconds",
        "interval_seconds",
        "max_attempts",
        "max_retry_delay_seconds",
        "retry_multiplier",
        "run_at",
        "schema_version",
    }
    if set(document) - allowed:
        raise ValueError("unsupported create-job field")
    capability = document["capability"]
    run_at = document["run_at"]
    if not isinstance(capability, str) or not isinstance(run_at, str):
        raise TypeError("capability and run_at must be strings")
    arguments = document.get("arguments", {})
    if not isinstance(arguments, Mapping):
        raise TypeError("arguments must be an object")
    return ControlPlaneCreateJobCommand(
        capability=capability,
        run_at=_datetime(run_at),
        arguments=arguments,
        interval=_optional_timedelta(document.get("interval_seconds")),
        max_attempts=_integer(document.get("max_attempts", 1), "max_attempts"),
        initial_retry_delay=_timedelta(
            document.get("initial_retry_delay_seconds", 0),
            "initial_retry_delay_seconds",
        ),
        retry_multiplier=_number(document.get("retry_multiplier", 2.0), "retry_multiplier"),
        max_retry_delay=_optional_timedelta(document.get("max_retry_delay_seconds")),
        deadline=_optional_number(document.get("deadline"), "deadline"),
        schema_version=_integer(document.get("schema_version", 1), "schema_version"),
    )


def _require_fields(
    document: Mapping[str, object],
    *,
    required: set[str],
    optional: set[str] | None = None,
) -> None:
    allowed = required | (set() if optional is None else optional)
    if set(document) != required and (not required.issubset(document) or set(document) - allowed):
        raise ValueError("command fields do not match the route schema")


def _json_object(body: bytes) -> Mapping[str, object]:
    if not body:
        raise ValueError("command body is required")
    document = json.loads(body.decode("utf-8"))
    if not isinstance(document, dict):
        raise TypeError("command body must be an object")
    return document


def _origin(
    headers: Mapping[str, tuple[str, ...]],
    server_origin: ControlPlaneBrowserOrigin,
) -> ControlPlaneBrowserOrigin:
    origin = ControlPlaneBrowserOrigin(_single_required_header(headers, "origin"))
    if origin != server_origin:
        raise ControlPlaneCsrfRejectedError("request origin does not match control plane")
    return origin


def _single_required_header(headers: Mapping[str, tuple[str, ...]], name: str) -> str:
    values = headers.get(name, ())
    if len(values) != 1 or not values[0]:
        raise ValueError(f"one {name} header is required")
    return values[0]


def _uuid(document: Mapping[str, object], name: str) -> UUID:
    value = document[name]
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a string")
    return UUID(value)


def _optional_uuid(document: Mapping[str, object], name: str) -> UUID | None:
    value = document.get(name)
    if value is None:
        return None
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a string")
    return UUID(value)


def _datetime(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("run_at must be timezone-aware")
    return parsed


def _integer(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an integer")
    return value


def _number(value: object, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{name} must be a number")
    result = float(value)
    if not math.isfinite(result):
        raise ValueError(f"{name} must be finite")
    return result


def _optional_number(value: object, name: str) -> float | None:
    return None if value is None else _number(value, name)


def _timedelta(value: object, name: str) -> timedelta:
    return timedelta(seconds=_number(value, name))


def _optional_timedelta(value: object) -> timedelta | None:
    return None if value is None else timedelta(seconds=_number(value, "duration"))


def _action_for_path(path: str) -> ControlPlaneCommandAction | None:
    if path == f"{_COMMAND_PREFIX}jobs/create":
        return ControlPlaneCommandAction.CREATE_JOB
    if path in {
        f"{_COMMAND_PREFIX}jobs/cancel",
        f"{_COMMAND_PREFIX}jobs/cancel/confirmation",
    }:
        return ControlPlaneCommandAction.CANCEL_JOB
    if path == f"{_COMMAND_PREFIX}jobs/retry-dead-letter":
        return ControlPlaneCommandAction.RETRY_DEAD_LETTER_JOB
    if path in {
        f"{_COMMAND_PREFIX}workflows/cancel",
        f"{_COMMAND_PREFIX}workflows/cancel/confirmation",
    }:
        return ControlPlaneCommandAction.CANCEL_WORKFLOW
    return None
