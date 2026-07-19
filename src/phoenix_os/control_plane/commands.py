"""Immutable contracts for authenticated Phoenix control-plane commands."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Awaitable
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Protocol
from uuid import UUID, uuid4

_IDEMPOTENCY_KEY_PATTERN = re.compile(r"[A-Za-z0-9._:-]{16,128}\Z")
_SHA256_PATTERN = re.compile(r"[0-9a-fA-F]{64}\Z")
_RESULT_CODE_PATTERN = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}\Z")


class ControlPlaneCommandAction(StrEnum):
    """Fixed mutation actions available to future command transports."""

    CREATE_JOB = "job.create"
    CANCEL_JOB = "job.cancel"
    RETRY_DEAD_LETTER_JOB = "job.retry-dead-letter"
    CANCEL_WORKFLOW = "workflow.cancel"

    @property
    def permission(self) -> str:
        return {
            self.CREATE_JOB: "control-plane.jobs.create",
            self.CANCEL_JOB: "control-plane.jobs.cancel",
            self.RETRY_DEAD_LETTER_JOB: "control-plane.jobs.retry",
            self.CANCEL_WORKFLOW: "control-plane.workflows.cancel",
        }[self]

    @property
    def destructive(self) -> bool:
        return self in {self.CANCEL_JOB, self.CANCEL_WORKFLOW}


class ControlPlaneCommandStatus(StrEnum):
    """Safe lifecycle states retained for one idempotent command."""

    PENDING = "pending"
    SUCCEEDED = "succeeded"
    FAILED = "failed"

    @property
    def terminal(self) -> bool:
        return self in {self.SUCCEEDED, self.FAILED}


@dataclass(frozen=True, slots=True, repr=False)
class IdempotencyKey:
    """Validated opaque client key whose plaintext must never be persisted or logged."""

    value: str = field(repr=False)

    def __post_init__(self) -> None:
        if self.value != self.value.strip():
            raise ValueError("idempotency key must not contain surrounding whitespace")
        try:
            self.value.encode("ascii")
        except UnicodeEncodeError as exception:
            raise ValueError("idempotency key must contain ASCII characters only") from exception
        if _IDEMPOTENCY_KEY_PATTERN.fullmatch(self.value) is None:
            raise ValueError(
                "idempotency key must contain 16 to 128 URL-safe identifier characters"
            )

    @property
    def digest(self) -> bytes:
        """Return the stable storage key without exposing the original value."""

        return hashlib.sha256(self.value.encode("ascii")).digest()

    def __repr__(self) -> str:
        return "IdempotencyKey(<redacted>)"

    def __str__(self) -> str:
        return "<redacted>"


@dataclass(frozen=True, slots=True)
class ControlPlaneCommandIntent:
    """Payload-free command identity used for authorization and deduplication."""

    action: ControlPlaneCommandAction
    target: str
    idempotency_key: IdempotencyKey
    payload_digest: str
    requested_at: datetime
    id: UUID = field(default_factory=uuid4)
    schema_version: int = 1

    def __post_init__(self) -> None:
        action = ControlPlaneCommandAction(self.action)
        target = self.target.strip()
        if self.schema_version != 1:
            raise ValueError("unsupported command intent schema version")
        if not target or len(target) > 256:
            raise ValueError("command target must contain between 1 and 256 characters")
        if any(ord(character) < 32 or ord(character) == 127 for character in target):
            raise ValueError("command target must not contain control characters")
        digest = self.payload_digest.lower()
        if _SHA256_PATTERN.fullmatch(digest) is None:
            raise ValueError("command payload digest must be a SHA-256 hexadecimal digest")
        if self.requested_at.tzinfo is None:
            raise ValueError("requested_at must be timezone-aware")
        object.__setattr__(self, "action", action)
        object.__setattr__(self, "target", target)
        object.__setattr__(self, "payload_digest", digest)

    @property
    def fingerprint(self) -> str:
        """Bind action, target, and payload digest without retaining command payloads."""

        material = (
            f"phoenix-control-command:{self.schema_version}:"
            f"{self.action.value}:{self.target}:{self.payload_digest}"
        )
        return hashlib.sha256(material.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class ControlPlaneCommandAuthorization:
    """Explicit per-action authorization decision."""

    action: ControlPlaneCommandAction
    permission: str
    allowed: bool

    def __post_init__(self) -> None:
        action = ControlPlaneCommandAction(self.action)
        permission = self.permission.strip()
        if permission != action.permission:
            raise ValueError("command authorization permission does not match action")
        object.__setattr__(self, "action", action)
        object.__setattr__(self, "permission", permission)


@dataclass(frozen=True, slots=True)
class ControlPlaneCommandReceipt:
    """Safe idempotency result without command payloads or internal exception details."""

    command_id: UUID
    action: ControlPlaneCommandAction
    target: str
    status: ControlPlaneCommandStatus
    created_at: datetime
    completed_at: datetime | None = None
    result_code: str | None = None
    schema_version: int = 1

    def __post_init__(self) -> None:
        action = ControlPlaneCommandAction(self.action)
        status = ControlPlaneCommandStatus(self.status)
        target = self.target.strip()
        if self.schema_version != 1:
            raise ValueError("unsupported command receipt schema version")
        if not target:
            raise ValueError("command receipt target must not be blank")
        if self.created_at.tzinfo is None:
            raise ValueError("created_at must be timezone-aware")
        if self.completed_at is not None:
            if self.completed_at.tzinfo is None:
                raise ValueError("completed_at must be timezone-aware")
            if self.completed_at < self.created_at:
                raise ValueError("completed_at cannot precede created_at")
        result_code = None if self.result_code is None else self.result_code.strip().lower()
        if result_code is not None and _RESULT_CODE_PATTERN.fullmatch(result_code) is None:
            raise ValueError("command result code contains unsupported characters")
        if status is ControlPlaneCommandStatus.PENDING:
            if self.completed_at is not None or result_code is not None:
                raise ValueError("pending command cannot contain terminal result state")
        elif self.completed_at is None or result_code is None:
            raise ValueError("terminal command requires completed_at and result_code")
        object.__setattr__(self, "action", action)
        object.__setattr__(self, "target", target)
        object.__setattr__(self, "status", status)
        object.__setattr__(self, "result_code", result_code)


@dataclass(frozen=True, slots=True)
class ControlPlaneIdempotencyReservation:
    """Reservation result distinguishing a new command from a safe replay."""

    receipt: ControlPlaneCommandReceipt
    replayed: bool


@dataclass(frozen=True, slots=True)
class ControlPlaneIdempotencySnapshot:
    """Non-sensitive bounded-store counters for operational diagnostics."""

    closed: bool
    entries: int
    pending: int
    succeeded: int
    failed: int
    capacity: int

    def __post_init__(self) -> None:
        counters = (
            self.entries,
            self.pending,
            self.succeeded,
            self.failed,
            self.capacity,
        )
        if any(value < 0 for value in counters) or self.capacity <= 0:
            raise ValueError("idempotency counters and capacity must be positive")
        if self.entries > self.capacity:
            raise ValueError("idempotency entries cannot exceed capacity")
        if self.pending + self.succeeded + self.failed != self.entries:
            raise ValueError("idempotency status counts must equal entries")


class ControlPlaneIdempotencyStore(Protocol):
    """Asynchronous command-deduplication boundary."""

    @property
    def closed(self) -> bool: ...

    def reserve(
        self, intent: ControlPlaneCommandIntent
    ) -> Awaitable[ControlPlaneIdempotencyReservation]: ...

    def complete(
        self,
        intent: ControlPlaneCommandIntent,
        *,
        result_code: str,
        completed_at: datetime | None = None,
    ) -> Awaitable[ControlPlaneCommandReceipt]: ...

    def fail(
        self,
        intent: ControlPlaneCommandIntent,
        *,
        result_code: str,
        completed_at: datetime | None = None,
    ) -> Awaitable[ControlPlaneCommandReceipt]: ...

    def get(self, key: IdempotencyKey) -> Awaitable[ControlPlaneCommandReceipt | None]: ...

    def snapshot(self) -> Awaitable[ControlPlaneIdempotencySnapshot]: ...

    def close(self) -> Awaitable[None]: ...


def command_payload_digest(payload: bytes | bytearray | memoryview) -> str:
    """Hash canonical command bytes so idempotency storage never retains payloads."""

    return hashlib.sha256(bytes(payload)).hexdigest()
