"""Safe job command contracts and handlers for the local control plane."""

from __future__ import annotations

import asyncio
import json
import math
from collections.abc import Awaitable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from types import MappingProxyType
from typing import Protocol
from uuid import UUID, uuid4

from phoenix_os.capabilities import (
    CapabilityContext,
    CapabilityDescriptor,
    CapabilityNotFoundError,
    RiskLevel,
)
from phoenix_os.control_plane.auth import (
    ControlPlaneCommandAuthorizer,
    ControlPlanePrincipal,
)
from phoenix_os.control_plane.commands import (
    ControlPlaneCommandAction,
    ControlPlaneCommandIntent,
    ControlPlaneCommandReceipt,
    ControlPlaneCommandStatus,
    ControlPlaneIdempotencyStore,
    IdempotencyKey,
    command_payload_digest,
)
from phoenix_os.control_plane.confirmation import (
    ControlPlaneConfirmationChallenge,
    ControlPlaneConfirmationProof,
)
from phoenix_os.control_plane.csrf import (
    ControlPlaneBrowserOrigin,
    ControlPlaneCsrfToken,
)
from phoenix_os.control_plane.errors import (
    ControlPlaneCommandBindingError,
    ControlPlaneCommandStateError,
)
from phoenix_os.control_plane.protection import ControlPlaneCommandProtector
from phoenix_os.jobs import JobRecord, JobSchedule, JobSpec, JobStatus, RetryPolicy

MAX_JOB_COMMAND_ARGUMENT_BYTES = 65_536
MAX_JOB_COMMAND_ARGUMENT_DEPTH = 8
MAX_JOB_COMMAND_ARGUMENT_ITEMS = 2_048
MAX_JOB_COMMAND_STRING_LENGTH = 4_096
MAX_JOB_COMMAND_MAPPING_ITEMS = 256
MAX_JOB_COMMAND_SEQUENCE_ITEMS = 256
MAX_JOB_COMMAND_ATTEMPTS = 100
MAX_JOB_COMMAND_INTERVAL = timedelta(days=365)
MAX_JOB_COMMAND_RETRY_DELAY = timedelta(days=30)
MAX_JOB_COMMAND_DEADLINE = 3_600.0


class ControlPlaneJobScheduler(Protocol):
    """Minimal scheduler surface required by command handlers."""

    def schedule(
        self,
        spec: JobSpec,
        *,
        job_id: UUID | None = None,
        now: datetime | None = None,
    ) -> Awaitable[JobRecord]: ...

    def get(self, job_id: UUID) -> Awaitable[JobRecord | None]: ...

    def cancel(self, job_id: UUID, *, now: datetime | None = None) -> Awaitable[bool]: ...


class ControlPlaneCapabilityCatalog(Protocol):
    """Read-only capability lookup used before a job is accepted."""

    def describe(self, name: str) -> Awaitable[CapabilityDescriptor]: ...


@dataclass(frozen=True, slots=True)
class ControlPlaneCreateJobCommand:
    """Allowlisted job creation request without caller-controlled security context."""

    capability: str
    run_at: datetime
    arguments: Mapping[str, object] = field(default_factory=dict)
    interval: timedelta | None = None
    max_attempts: int = 1
    initial_retry_delay: timedelta = timedelta(0)
    retry_multiplier: float = 2.0
    max_retry_delay: timedelta | None = None
    deadline: float | None = None
    schema_version: int = 1

    def __post_init__(self) -> None:
        capability = self.capability.strip()
        if self.schema_version != 1:
            raise ValueError("unsupported create-job command schema version")
        if not capability or len(capability) > 256:
            raise ValueError("job capability must contain between 1 and 256 characters")
        if any(ord(character) < 32 or ord(character) == 127 for character in capability):
            raise ValueError("job capability must not contain control characters")
        _require_aware(self.run_at, "run_at")
        if self.interval is not None and (
            self.interval <= timedelta(0) or self.interval > MAX_JOB_COMMAND_INTERVAL
        ):
            raise ValueError("job interval must be positive and at most 365 days")
        if self.max_attempts <= 0 or self.max_attempts > MAX_JOB_COMMAND_ATTEMPTS:
            raise ValueError("job max_attempts must be between 1 and 100")
        if self.initial_retry_delay < timedelta(0) or (
            self.initial_retry_delay > MAX_JOB_COMMAND_RETRY_DELAY
        ):
            raise ValueError("initial retry delay must be between zero and 30 days")
        if not math.isfinite(self.retry_multiplier) or self.retry_multiplier < 1:
            raise ValueError("retry multiplier must be finite and at least one")
        if self.max_retry_delay is not None:
            if (
                self.max_retry_delay < timedelta(0)
                or self.max_retry_delay > MAX_JOB_COMMAND_RETRY_DELAY
            ):
                raise ValueError("maximum retry delay must be between zero and 30 days")
            if self.max_retry_delay < self.initial_retry_delay:
                raise ValueError("maximum retry delay cannot precede initial retry delay")
        if self.deadline is not None and (
            not math.isfinite(self.deadline)
            or self.deadline <= 0
            or self.deadline > MAX_JOB_COMMAND_DEADLINE
        ):
            raise ValueError("job deadline must be positive and at most 3600 seconds")

        normalized = _normalize_arguments(self.arguments)
        encoded = _canonical_json_bytes(
            {
                "arguments": normalized,
                "capability": capability,
                "deadline": self.deadline,
                "interval_seconds": _seconds(self.interval),
                "max_attempts": self.max_attempts,
                "max_retry_delay_seconds": _seconds(self.max_retry_delay),
                "retry_delay_seconds": _seconds(self.initial_retry_delay),
                "retry_multiplier": self.retry_multiplier,
                "run_at": _canonical_datetime(self.run_at),
                "schema_version": self.schema_version,
            }
        )
        if len(encoded) > MAX_JOB_COMMAND_ARGUMENT_BYTES:
            raise ValueError("create-job command exceeds the maximum canonical payload size")

        object.__setattr__(self, "capability", capability)
        object.__setattr__(self, "arguments", _freeze_json_mapping(normalized))

    @property
    def target(self) -> str:
        return f"capability:{self.capability}"

    @property
    def canonical_payload(self) -> bytes:
        return _canonical_json_bytes(
            {
                "arguments": _thaw_json(self.arguments),
                "capability": self.capability,
                "deadline": self.deadline,
                "interval_seconds": _seconds(self.interval),
                "max_attempts": self.max_attempts,
                "max_retry_delay_seconds": _seconds(self.max_retry_delay),
                "retry_delay_seconds": _seconds(self.initial_retry_delay),
                "retry_multiplier": self.retry_multiplier,
                "run_at": _canonical_datetime(self.run_at),
                "schema_version": self.schema_version,
            }
        )

    @property
    def payload_digest(self) -> str:
        return command_payload_digest(self.canonical_payload)

    def intent(
        self,
        idempotency_key: IdempotencyKey,
        *,
        requested_at: datetime,
        command_id: UUID | None = None,
    ) -> ControlPlaneCommandIntent:
        return ControlPlaneCommandIntent(
            id=uuid4() if command_id is None else command_id,
            action=ControlPlaneCommandAction.CREATE_JOB,
            target=self.target,
            idempotency_key=idempotency_key,
            payload_digest=self.payload_digest,
            requested_at=requested_at,
        )

    def to_spec(
        self,
        principal: ControlPlanePrincipal,
        *,
        command_id: UUID,
    ) -> JobSpec:
        return JobSpec(
            capability=self.capability,
            schedule=JobSchedule(self.run_at, interval=self.interval),
            arguments=self.arguments,
            context=CapabilityContext(
                principal=principal.name,
                request_id=command_id,
                correlation_id=f"control-plane:{command_id.hex}",
                confirmed=False,
                permissions=principal.permissions,
            ),
            retry=RetryPolicy(
                max_attempts=self.max_attempts,
                initial_delay=self.initial_retry_delay,
                multiplier=self.retry_multiplier,
                max_delay=self.max_retry_delay,
            ),
            deadline=self.deadline,
        )


@dataclass(frozen=True, slots=True)
class ControlPlaneCancelJobCommand:
    """Exact job cancellation target used by the destructive command path."""

    job_id: UUID
    schema_version: int = 1

    def __post_init__(self) -> None:
        if self.schema_version != 1:
            raise ValueError("unsupported cancel-job command schema version")

    @property
    def target(self) -> str:
        return f"job:{self.job_id}"

    @property
    def canonical_payload(self) -> bytes:
        return _canonical_json_bytes(
            {
                "job_id": str(self.job_id),
                "schema_version": self.schema_version,
            }
        )

    @property
    def payload_digest(self) -> str:
        return command_payload_digest(self.canonical_payload)

    def intent(
        self,
        idempotency_key: IdempotencyKey,
        *,
        requested_at: datetime,
        command_id: UUID | None = None,
    ) -> ControlPlaneCommandIntent:
        return ControlPlaneCommandIntent(
            id=uuid4() if command_id is None else command_id,
            action=ControlPlaneCommandAction.CANCEL_JOB,
            target=self.target,
            idempotency_key=idempotency_key,
            payload_digest=self.payload_digest,
            requested_at=requested_at,
        )


@dataclass(frozen=True, slots=True)
class ControlPlaneRetryDeadLetterJobCommand:
    """Retry one dead-letter job as a new deterministic one-time job."""

    job_id: UUID
    schema_version: int = 1

    def __post_init__(self) -> None:
        if self.schema_version != 1:
            raise ValueError("unsupported retry-job command schema version")

    @property
    def target(self) -> str:
        return f"job:{self.job_id}"

    @property
    def canonical_payload(self) -> bytes:
        return _canonical_json_bytes(
            {
                "job_id": str(self.job_id),
                "schema_version": self.schema_version,
            }
        )

    @property
    def payload_digest(self) -> str:
        return command_payload_digest(self.canonical_payload)

    def intent(
        self,
        idempotency_key: IdempotencyKey,
        *,
        requested_at: datetime,
        command_id: UUID | None = None,
    ) -> ControlPlaneCommandIntent:
        return ControlPlaneCommandIntent(
            id=uuid4() if command_id is None else command_id,
            action=ControlPlaneCommandAction.RETRY_DEAD_LETTER_JOB,
            target=self.target,
            idempotency_key=idempotency_key,
            payload_digest=self.payload_digest,
            requested_at=requested_at,
        )


@dataclass(frozen=True, slots=True)
class ControlPlaneJobCommandResult:
    """Safe handler result with receipt and optional created job identifier."""

    receipt: ControlPlaneCommandReceipt
    job_id: UUID | None = None

    def __post_init__(self) -> None:
        creates_job = self.receipt.action in {
            ControlPlaneCommandAction.CREATE_JOB,
            ControlPlaneCommandAction.RETRY_DEAD_LETTER_JOB,
        }
        if creates_job:
            if self.receipt.status is ControlPlaneCommandStatus.SUCCEEDED and self.job_id is None:
                raise ValueError("successful job-producing result requires job_id")
            if (
                self.receipt.status is not ControlPlaneCommandStatus.SUCCEEDED
                and self.job_id is not None
            ):
                raise ValueError("failed job-producing result cannot expose job_id")
        elif self.job_id is not None:
            raise ValueError("only job-producing results may expose a job_id")


class ControlPlaneJobCommandHandler:
    """Authorize, protect, deduplicate, and execute bounded job mutations."""

    def __init__(
        self,
        scheduler: ControlPlaneJobScheduler,
        capabilities: ControlPlaneCapabilityCatalog,
        authorizer: ControlPlaneCommandAuthorizer,
        protector: ControlPlaneCommandProtector,
        idempotency: ControlPlaneIdempotencyStore,
    ) -> None:
        self._scheduler = scheduler
        self._capabilities = capabilities
        self._authorizer = authorizer
        self._protector = protector
        self._idempotency = idempotency

    async def issue_cancel_confirmation(
        self,
        principal: ControlPlanePrincipal,
        intent: ControlPlaneCommandIntent,
        command: ControlPlaneCancelJobCommand,
        *,
        origin: ControlPlaneBrowserOrigin,
        csrf_token: ControlPlaneCsrfToken,
    ) -> ControlPlaneConfirmationChallenge:
        _require_binding(
            intent,
            ControlPlaneCommandAction.CANCEL_JOB,
            command.target,
            command.payload_digest,
        )
        self._authorizer.require(principal, intent.action)
        return await self._protector.issue_confirmation(
            principal,
            intent,
            origin=origin,
            csrf_token=csrf_token,
        )

    async def create_job(
        self,
        principal: ControlPlanePrincipal,
        intent: ControlPlaneCommandIntent,
        command: ControlPlaneCreateJobCommand,
        *,
        origin: ControlPlaneBrowserOrigin,
        csrf_token: ControlPlaneCsrfToken,
    ) -> ControlPlaneJobCommandResult:
        _require_binding(
            intent,
            ControlPlaneCommandAction.CREATE_JOB,
            command.target,
            command.payload_digest,
        )
        self._authorizer.require(principal, intent.action)
        await self._protector.verify(
            principal,
            intent,
            origin=origin,
            csrf_token=csrf_token,
        )
        reservation = await self._idempotency.reserve(intent)
        receipt = reservation.receipt
        if receipt.status.terminal:
            return ControlPlaneJobCommandResult(
                receipt=receipt,
                job_id=receipt.command_id
                if receipt.status is ControlPlaneCommandStatus.SUCCEEDED
                else None,
            )

        command_id = receipt.command_id
        expected = command.to_spec(principal, command_id=command_id)
        try:
            descriptor = await self._capabilities.describe(command.capability)
        except asyncio.CancelledError:
            raise
        except CapabilityNotFoundError:
            return ControlPlaneJobCommandResult(
                receipt=await self._fail(intent, "capability.not-found")
            )
        except Exception:
            return ControlPlaneJobCommandResult(
                receipt=await self._fail(intent, "capability.unavailable")
            )

        if not _capability_allowed(principal, descriptor):
            return ControlPlaneJobCommandResult(
                receipt=await self._fail(intent, "capability.not-authorized")
            )
        if descriptor.risk is RiskLevel.DESTRUCTIVE or descriptor.confirmation_required:
            return ControlPlaneJobCommandResult(
                receipt=await self._fail(intent, "capability.unsupported-risk")
            )

        existing = await self._safe_get(command_id)
        if existing is not None:
            return await self._finish_existing_create(intent, existing, expected)

        try:
            created = await self._scheduler.schedule(
                expected,
                job_id=command_id,
                now=receipt.created_at,
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            existing = await self._safe_get(command_id)
            if existing is not None:
                return await self._finish_existing_create(intent, existing, expected)
            return ControlPlaneJobCommandResult(
                receipt=await self._fail(intent, "job.create-failed")
            )

        if created.id != command_id or created.spec != expected:
            return ControlPlaneJobCommandResult(receipt=await self._fail(intent, "job.conflict"))
        completed = await self._complete(intent, "job.created")
        return ControlPlaneJobCommandResult(receipt=completed, job_id=command_id)

    async def retry_dead_letter_job(
        self,
        principal: ControlPlanePrincipal,
        intent: ControlPlaneCommandIntent,
        command: ControlPlaneRetryDeadLetterJobCommand,
        *,
        origin: ControlPlaneBrowserOrigin,
        csrf_token: ControlPlaneCsrfToken,
    ) -> ControlPlaneJobCommandResult:
        """Create one new one-time job from an eligible dead-letter record."""

        _require_binding(
            intent,
            ControlPlaneCommandAction.RETRY_DEAD_LETTER_JOB,
            command.target,
            command.payload_digest,
        )
        self._authorizer.require(principal, intent.action)
        await self._protector.verify(
            principal,
            intent,
            origin=origin,
            csrf_token=csrf_token,
        )
        reservation = await self._idempotency.reserve(intent)
        receipt = reservation.receipt
        if receipt.status.terminal:
            return ControlPlaneJobCommandResult(
                receipt=receipt,
                job_id=(
                    receipt.command_id
                    if receipt.status is ControlPlaneCommandStatus.SUCCEEDED
                    else None
                ),
            )

        original = await self._safe_get(command.job_id)
        if original is None:
            return ControlPlaneJobCommandResult(receipt=await self._fail(intent, "job.not-found"))
        if original.status is not JobStatus.DEAD_LETTER:
            return ControlPlaneJobCommandResult(
                receipt=await self._fail(intent, "job.not-dead-letter")
            )
        if _workflow_owned(original):
            return ControlPlaneJobCommandResult(
                receipt=await self._fail(intent, "job.retry-unsupported-owner")
            )

        try:
            descriptor = await self._capabilities.describe(original.spec.capability)
        except asyncio.CancelledError:
            raise
        except CapabilityNotFoundError:
            return ControlPlaneJobCommandResult(
                receipt=await self._fail(intent, "capability.not-found")
            )
        except Exception:
            return ControlPlaneJobCommandResult(
                receipt=await self._fail(intent, "capability.unavailable")
            )

        if not _capability_allowed(principal, descriptor):
            return ControlPlaneJobCommandResult(
                receipt=await self._fail(intent, "capability.not-authorized")
            )
        if descriptor.risk is RiskLevel.DESTRUCTIVE or descriptor.confirmation_required:
            return ControlPlaneJobCommandResult(
                receipt=await self._fail(intent, "capability.unsupported-risk")
            )

        command_id = receipt.command_id
        expected = _dead_letter_retry_spec(
            original,
            principal,
            command_id=command_id,
            run_at=receipt.created_at,
        )
        existing = await self._safe_get(command_id)
        if existing is not None:
            return await self._finish_existing_retry(intent, existing, expected)

        try:
            created = await self._scheduler.schedule(
                expected,
                job_id=command_id,
                now=receipt.created_at,
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            existing = await self._safe_get(command_id)
            if existing is not None:
                return await self._finish_existing_retry(intent, existing, expected)
            return ControlPlaneJobCommandResult(
                receipt=await self._fail(intent, "job.retry-failed")
            )

        if created.id != command_id or created.spec != expected:
            return ControlPlaneJobCommandResult(receipt=await self._fail(intent, "job.conflict"))
        completed = await self._complete(intent, "job.retried")
        return ControlPlaneJobCommandResult(receipt=completed, job_id=command_id)

    async def cancel_job(
        self,
        principal: ControlPlanePrincipal,
        intent: ControlPlaneCommandIntent,
        command: ControlPlaneCancelJobCommand,
        *,
        origin: ControlPlaneBrowserOrigin,
        csrf_token: ControlPlaneCsrfToken,
        confirmation: ControlPlaneConfirmationProof,
    ) -> ControlPlaneJobCommandResult:
        _require_binding(
            intent,
            ControlPlaneCommandAction.CANCEL_JOB,
            command.target,
            command.payload_digest,
        )
        self._authorizer.require(principal, intent.action)
        await self._protector.verify(
            principal,
            intent,
            origin=origin,
            csrf_token=csrf_token,
            confirmation=confirmation,
        )
        reservation = await self._idempotency.reserve(intent)
        receipt = reservation.receipt
        if receipt.status.terminal:
            return ControlPlaneJobCommandResult(receipt=receipt)

        existing = await self._safe_get(command.job_id)
        if existing is None:
            return ControlPlaneJobCommandResult(receipt=await self._fail(intent, "job.not-found"))
        if existing.status is JobStatus.CANCELLED:
            return ControlPlaneJobCommandResult(
                receipt=await self._complete(intent, "job.cancelled")
            )
        if existing.status.terminal:
            return ControlPlaneJobCommandResult(
                receipt=await self._fail(intent, "job.not-cancellable")
            )

        try:
            cancelled = await self._scheduler.cancel(command.job_id, now=receipt.created_at)
        except asyncio.CancelledError:
            raise
        except Exception:
            current = await self._safe_get(command.job_id)
            if current is not None and current.status is JobStatus.CANCELLED:
                return ControlPlaneJobCommandResult(
                    receipt=await self._complete(intent, "job.cancelled")
                )
            if current is None:
                return ControlPlaneJobCommandResult(
                    receipt=await self._fail(intent, "job.not-found")
                )
            return ControlPlaneJobCommandResult(
                receipt=await self._fail(intent, "job.cancel-failed")
            )

        if not cancelled:
            current = await self._safe_get(command.job_id)
            if current is not None and current.status is JobStatus.CANCELLED:
                return ControlPlaneJobCommandResult(
                    receipt=await self._complete(intent, "job.cancelled")
                )
            return ControlPlaneJobCommandResult(
                receipt=await self._fail(intent, "job.not-cancellable")
            )
        return ControlPlaneJobCommandResult(receipt=await self._complete(intent, "job.cancelled"))

    async def _finish_existing_create(
        self,
        intent: ControlPlaneCommandIntent,
        existing: JobRecord,
        expected: JobSpec,
    ) -> ControlPlaneJobCommandResult:
        if existing.spec != expected:
            return ControlPlaneJobCommandResult(receipt=await self._fail(intent, "job.conflict"))
        receipt = await self._complete(intent, "job.created")
        return ControlPlaneJobCommandResult(receipt=receipt, job_id=existing.id)

    async def _finish_existing_retry(
        self,
        intent: ControlPlaneCommandIntent,
        existing: JobRecord,
        expected: JobSpec,
    ) -> ControlPlaneJobCommandResult:
        if existing.spec != expected:
            return ControlPlaneJobCommandResult(receipt=await self._fail(intent, "job.conflict"))
        receipt = await self._complete(intent, "job.retried")
        return ControlPlaneJobCommandResult(receipt=receipt, job_id=existing.id)

    async def _safe_get(self, job_id: UUID) -> JobRecord | None:
        try:
            return await self._scheduler.get(job_id)
        except asyncio.CancelledError:
            raise
        except Exception:
            return None

    async def _complete(
        self,
        intent: ControlPlaneCommandIntent,
        result_code: str,
    ) -> ControlPlaneCommandReceipt:
        try:
            return await self._idempotency.complete(intent, result_code=result_code)
        except ControlPlaneCommandStateError:
            current = await self._idempotency.get(intent.idempotency_key)
            if current is not None and current.status.terminal:
                return current
            raise

    async def _fail(
        self,
        intent: ControlPlaneCommandIntent,
        result_code: str,
    ) -> ControlPlaneCommandReceipt:
        try:
            return await self._idempotency.fail(intent, result_code=result_code)
        except ControlPlaneCommandStateError:
            current = await self._idempotency.get(intent.idempotency_key)
            if current is not None and current.status.terminal:
                return current
            raise


def _workflow_owned(record: JobRecord) -> bool:
    return any(
        key in record.spec.metadata for key in ("phoenix.workflow_id", "phoenix.workflow_step")
    )


def _dead_letter_retry_spec(
    original: JobRecord,
    principal: ControlPlanePrincipal,
    *,
    command_id: UUID,
    run_at: datetime,
) -> JobSpec:
    return replace(
        original.spec,
        schedule=JobSchedule(run_at),
        context=CapabilityContext(
            principal=principal.name,
            request_id=command_id,
            correlation_id=f"control-plane:{command_id.hex}",
            confirmed=False,
            permissions=principal.permissions,
        ),
        metadata={},
    )


def _require_binding(
    intent: ControlPlaneCommandIntent,
    action: ControlPlaneCommandAction,
    target: str,
    payload_digest: str,
) -> None:
    if (
        intent.action is not action
        or intent.target != target
        or intent.payload_digest != payload_digest
    ):
        raise ControlPlaneCommandBindingError("command intent does not match submitted command")


def _capability_allowed(
    principal: ControlPlanePrincipal,
    descriptor: CapabilityDescriptor,
) -> bool:
    return descriptor.required_permissions.issubset(principal.permissions)


def _normalize_arguments(arguments: Mapping[str, object]) -> dict[str, object]:
    if not isinstance(arguments, Mapping):
        raise TypeError("job arguments must be a mapping")
    budget = [MAX_JOB_COMMAND_ARGUMENT_ITEMS]
    normalized = _normalize_json(arguments, path="$.arguments", depth=0, budget=budget)
    if not isinstance(normalized, dict):
        raise TypeError("job arguments must be a mapping")
    return normalized


def _normalize_json(
    value: object,
    *,
    path: str,
    depth: int,
    budget: list[int],
) -> object:
    if depth > MAX_JOB_COMMAND_ARGUMENT_DEPTH:
        raise ValueError(f"job arguments exceed maximum nesting depth at {path}")
    budget[0] -= 1
    if budget[0] < 0:
        raise ValueError("job arguments exceed maximum item count")
    value_type = type(value)
    if (
        value_type.__name__ == "SecretValue"
        and value_type.__module__ == "phoenix_os.configuration.contracts"
    ):
        raise ValueError(f"secret values are not accepted in job arguments at {path}")
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(f"non-finite number is not accepted at {path}")
        return value
    if isinstance(value, str):
        if len(value) > MAX_JOB_COMMAND_STRING_LENGTH:
            raise ValueError(f"job argument string is too long at {path}")
        if any(ord(character) == 0 for character in value):
            raise ValueError(f"job argument strings must not contain NUL at {path}")
        return value
    if isinstance(value, Mapping):
        if len(value) > MAX_JOB_COMMAND_MAPPING_ITEMS:
            raise ValueError(f"job argument mapping has too many entries at {path}")
        result: dict[str, object] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError(f"job argument mapping keys must be strings at {path}")
            if not key or len(key) > 256:
                raise ValueError(f"job argument mapping key has invalid length at {path}")
            if any(ord(character) < 32 or ord(character) == 127 for character in key):
                raise ValueError(f"job argument mapping key contains control characters at {path}")
            result[key] = _normalize_json(
                item,
                path=f"{path}.{key}",
                depth=depth + 1,
                budget=budget,
            )
        return result
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray, memoryview)):
        if len(value) > MAX_JOB_COMMAND_SEQUENCE_ITEMS:
            raise ValueError(f"job argument sequence has too many entries at {path}")
        return [
            _normalize_json(
                item,
                path=f"{path}[{index}]",
                depth=depth + 1,
                budget=budget,
            )
            for index, item in enumerate(value)
        ]
    raise ValueError(f"unsupported job argument type {type(value).__name__} at {path}")


def _freeze_json_mapping(value: Mapping[str, object]) -> Mapping[str, object]:
    return MappingProxyType({key: _freeze_json(item) for key, item in value.items()})


def _freeze_json(value: object) -> object:
    if isinstance(value, dict):
        return _freeze_json_mapping(value)
    if isinstance(value, list):
        return tuple(_freeze_json(item) for item in value)
    return value


def _thaw_json(value: object) -> object:
    if isinstance(value, Mapping):
        return {str(key): _thaw_json(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw_json(item) for item in value]
    return value


def _canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _canonical_datetime(value: datetime) -> str:
    _require_aware(value, "datetime")
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _seconds(value: timedelta | None) -> float | None:
    return None if value is None else value.total_seconds()


def _require_aware(value: datetime, label: str) -> None:
    if value.tzinfo is None:
        raise ValueError(f"{label} must be timezone-aware")
