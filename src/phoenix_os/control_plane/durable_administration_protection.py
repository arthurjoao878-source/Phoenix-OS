"""Recent-authentication and one-time confirmation for durable reconciliation."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import re
import secrets
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Protocol
from uuid import UUID, uuid4

from phoenix_os.agent.durable_authorization import (
    AGENT_RECONCILE_ACTION,
    durable_reconciliation_resource,
)
from phoenix_os.agent.durable_contracts import (
    CheckpointDigest,
    DurableAgentRunId,
    DurableRunVersion,
    ExecutionAttemptId,
    ReconciliationDecision,
)
from phoenix_os.control_plane.durable_session_access import (
    ControlPlaneDurableSessionAuthentication,
)
from phoenix_os.control_plane.errors import (
    ControlPlaneCommandPermissionDeniedError,
    ControlPlaneConfirmationCapacityError,
    ControlPlaneConfirmationRejectedError,
    ControlPlaneConfirmationStoreClosedError,
    ControlPlaneStepUpRejectedError,
)
from phoenix_os.control_plane.operator_contracts import (
    CONTROL_PLANE_DURABLE_RECONCILE_PERMISSION,
)
from phoenix_os.control_plane.step_up import ControlPlaneStepUpAction

DEFAULT_CONTROL_PLANE_DURABLE_CONFIRMATION_CAPACITY = 1024
MAX_CONTROL_PLANE_DURABLE_CONFIRMATION_CAPACITY = 100_000
DEFAULT_CONTROL_PLANE_DURABLE_CONFIRMATION_TTL = timedelta(minutes=2)
MAX_CONTROL_PLANE_DURABLE_CONFIRMATION_TTL = timedelta(minutes=10)

_PROOF_PATTERN = re.compile(r"[A-Za-z0-9_-]{43}\Z")
_IDENTIFIER_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,127})$")
_CONFIRM_DECISIONS = frozenset(
    {
        ReconciliationDecision.CONFIRM_SUCCEEDED,
        ReconciliationDecision.CONFIRM_FAILED,
        ReconciliationDecision.CONFIRM_NOT_STARTED,
    }
)

type ControlPlaneDurableAdministrationClock = Callable[[], datetime]
type ControlPlaneDurableAdministrationNonceSource = Callable[[int], bytes]


class _ControlPlaneDurableStepUpVerifier(Protocol):
    async def verify(
        self,
        token_value: str | None,
        session: ControlPlaneDurableSessionAuthentication,
        action: ControlPlaneStepUpAction,
    ) -> object: ...


@dataclass(frozen=True, slots=True)
class ControlPlaneDurableReconciliationEvidenceBinding:
    """Content-free confirmation binding for trusted reconciliation evidence."""

    evidence_type: str
    evidence_digest: CheckpointDigest
    evidence_observed_at: datetime
    schema_version: int = 1

    def __post_init__(self) -> None:
        if (
            not isinstance(self.evidence_type, str)
            or _IDENTIFIER_PATTERN.fullmatch(self.evidence_type) is None
        ):
            raise ValueError("durable reconciliation evidence type is invalid")
        if not isinstance(self.evidence_digest, CheckpointDigest):
            raise TypeError("evidence_digest must be CheckpointDigest")
        _require_aware(self.evidence_observed_at, "evidence_observed_at")
        if self.schema_version != 1:
            raise ValueError("unsupported durable reconciliation evidence binding version")


@dataclass(frozen=True, slots=True)
class ControlPlaneDurableReconciliationIntent:
    """Content-free exact operator intent for one durable reconciliation."""

    run_id: DurableAgentRunId
    attempt_id: ExecutionAttemptId
    expected_version: DurableRunVersion
    decision: ReconciliationDecision
    requested_at: datetime
    evidence_binding: ControlPlaneDurableReconciliationEvidenceBinding | None = None
    id: UUID = field(default_factory=uuid4)
    schema_version: int = 1

    def __post_init__(self) -> None:
        if not isinstance(self.run_id, DurableAgentRunId):
            raise TypeError("run_id must be DurableAgentRunId")
        if not isinstance(self.attempt_id, ExecutionAttemptId):
            raise TypeError("attempt_id must be ExecutionAttemptId")
        if not isinstance(self.expected_version, DurableRunVersion):
            raise TypeError("expected_version must be DurableRunVersion")
        if not isinstance(self.decision, ReconciliationDecision):
            raise TypeError("decision must be ReconciliationDecision")
        if not isinstance(self.id, UUID):
            raise TypeError("durable reconciliation intent id must be UUID")
        _require_aware(self.requested_at, "requested_at")
        binding = self.evidence_binding
        if binding is not None and not isinstance(
            binding,
            ControlPlaneDurableReconciliationEvidenceBinding,
        ):
            raise TypeError(
                "evidence_binding must be ControlPlaneDurableReconciliationEvidenceBinding or None"
            )
        if self.decision in _CONFIRM_DECISIONS and binding is None:
            raise ValueError("confirmed reconciliation requires evidence binding")
        if self.decision not in _CONFIRM_DECISIONS and binding is not None:
            raise ValueError("selected reconciliation decision cannot carry evidence binding")
        if binding is not None and binding.evidence_observed_at > self.requested_at:
            raise ValueError("reconciliation evidence cannot follow the request")
        if self.schema_version != 1:
            raise ValueError("unsupported durable reconciliation intent version")

    @property
    def action(self) -> str:
        return AGENT_RECONCILE_ACTION

    @property
    def resource(self) -> str:
        return durable_reconciliation_resource(self.run_id, self.attempt_id)

    @property
    def fingerprint(self) -> str:
        binding = self.evidence_binding
        document = {
            "action": self.action,
            "attempt_id": str(self.attempt_id),
            "decision": self.decision.value,
            "evidence_binding_schema_version": (
                None if binding is None else binding.schema_version
            ),
            "evidence_digest": (None if binding is None else str(binding.evidence_digest)),
            "evidence_observed_at": (
                None if binding is None else binding.evidence_observed_at.isoformat()
            ),
            "evidence_type": None if binding is None else binding.evidence_type,
            "expected_version": self.expected_version.value,
            "requested_at": self.requested_at.isoformat(),
            "resource": self.resource,
            "run_id": str(self.run_id),
            "schema_version": self.schema_version,
        }
        encoded = json.dumps(
            document,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True, slots=True, repr=False)
class ControlPlaneDurableAdministrationConfirmationProof:
    """Opaque one-time confirmation secret that is always redacted."""

    value: str = field(repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.value, str):
            raise TypeError("durable administration confirmation proof must be str")
        if _PROOF_PATTERN.fullmatch(self.value) is None:
            raise ValueError("durable administration confirmation proof has invalid format")

    @property
    def digest(self) -> bytes:
        return hashlib.sha256(self.value.encode("ascii")).digest()

    def __repr__(self) -> str:
        return "ControlPlaneDurableAdministrationConfirmationProof(<redacted>)"

    def __str__(self) -> str:
        return "<redacted>"


@dataclass(frozen=True, slots=True)
class ControlPlaneDurableAdministrationConfirmationChallenge:
    """Safe metadata plus one redacted one-time proof for an exact mutation."""

    intent_id: UUID
    action: str
    resource: str
    fingerprint: str
    issued_at: datetime
    expires_at: datetime
    proof: ControlPlaneDurableAdministrationConfirmationProof = field(repr=False)
    schema_version: int = 1

    def __post_init__(self) -> None:
        if not isinstance(self.intent_id, UUID):
            raise TypeError("intent_id must be UUID")
        if self.action != AGENT_RECONCILE_ACTION:
            raise ValueError("unsupported durable administration action")
        if not isinstance(self.resource, str) or not self.resource:
            raise ValueError("durable administration resource must not be blank")
        if (
            not isinstance(self.fingerprint, str)
            or re.fullmatch(
                r"[0-9a-f]{64}",
                self.fingerprint,
            )
            is None
        ):
            raise ValueError("durable administration fingerprint must be SHA-256")
        _require_aware(self.issued_at, "issued_at")
        _require_aware(self.expires_at, "expires_at")
        if self.expires_at <= self.issued_at:
            raise ValueError("confirmation expiry must follow issuance")
        if self.schema_version != 1:
            raise ValueError("unsupported durable confirmation challenge version")


@dataclass(frozen=True, slots=True)
class ControlPlaneDurableAdministrationConfirmationVerification:
    """Safe evidence that one exact confirmation was consumed."""

    intent_id: UUID
    action: str
    resource: str
    fingerprint: str
    confirmed_at: datetime
    schema_version: int = 1

    def __post_init__(self) -> None:
        if not isinstance(self.intent_id, UUID):
            raise TypeError("intent_id must be UUID")
        if self.action != AGENT_RECONCILE_ACTION:
            raise ValueError("unsupported durable administration action")
        if not isinstance(self.resource, str) or not self.resource:
            raise ValueError("durable administration resource must not be blank")
        if (
            not isinstance(self.fingerprint, str)
            or re.fullmatch(
                r"[0-9a-f]{64}",
                self.fingerprint,
            )
            is None
        ):
            raise ValueError("durable administration fingerprint must be SHA-256")
        _require_aware(self.confirmed_at, "confirmed_at")
        if self.schema_version != 1:
            raise ValueError("unsupported durable confirmation verification version")


@dataclass(frozen=True, slots=True)
class ControlPlaneDurableAdministrationProtectionSnapshot:
    """Content-free bounded counters for durable destructive protection."""

    closed: bool
    entries: int
    active: int
    consumed: int
    capacity: int
    issued: int
    verified: int
    rejected: int
    schema_version: int = 1

    def __post_init__(self) -> None:
        if type(self.closed) is not bool:
            raise TypeError("closed must be bool")
        for label, value in (
            ("entries", self.entries),
            ("active", self.active),
            ("consumed", self.consumed),
            ("capacity", self.capacity),
            ("issued", self.issued),
            ("verified", self.verified),
            ("rejected", self.rejected),
        ):
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"{label} must be an integer")
            if value < 0:
                raise ValueError(f"{label} must not be negative")
        if self.capacity <= 0:
            raise ValueError("capacity must be positive")
        if self.entries > self.capacity or self.active + self.consumed != self.entries:
            raise ValueError("durable protection counters are inconsistent")
        if self.schema_version != 1:
            raise ValueError("unsupported durable protection snapshot version")


@dataclass(slots=True)
class _ConfirmationEntry:
    binding_digest: bytes
    issued_at: datetime
    expires_at: datetime
    consumed: bool = False


class ControlPlaneDurableAdministrationProtection:
    """Require exact permission, recent step-up, and one-time confirmation."""

    def __init__(
        self,
        *,
        step_up: _ControlPlaneDurableStepUpVerifier,
        capacity: int = DEFAULT_CONTROL_PLANE_DURABLE_CONFIRMATION_CAPACITY,
        ttl: timedelta = DEFAULT_CONTROL_PLANE_DURABLE_CONFIRMATION_TTL,
        clock: ControlPlaneDurableAdministrationClock | None = None,
        nonce_source: ControlPlaneDurableAdministrationNonceSource = secrets.token_bytes,
    ) -> None:
        if not callable(getattr(step_up, "verify", None)):
            raise TypeError("durable administration protection requires step-up verification")
        if isinstance(capacity, bool) or not isinstance(capacity, int):
            raise TypeError("durable confirmation capacity must be an integer")
        if capacity <= 0 or capacity > MAX_CONTROL_PLANE_DURABLE_CONFIRMATION_CAPACITY:
            raise ValueError("durable confirmation capacity is outside supported bounds")
        if not isinstance(ttl, timedelta):
            raise TypeError("durable confirmation TTL must be timedelta")
        if ttl <= timedelta(0) or ttl > MAX_CONTROL_PLANE_DURABLE_CONFIRMATION_TTL:
            raise ValueError("durable confirmation TTL is outside supported bounds")
        selected_clock = (lambda: datetime.now(UTC)) if clock is None else clock
        if not callable(selected_clock):
            raise TypeError("durable administration clock must be callable")
        if not callable(nonce_source):
            raise TypeError("durable administration nonce source must be callable")

        self._step_up = step_up
        self._capacity = capacity
        self._ttl = ttl
        self._clock: ControlPlaneDurableAdministrationClock = selected_clock
        self._nonce_source = nonce_source
        self._entries: dict[bytes, _ConfirmationEntry] = {}
        self._closed = False
        self._issued = 0
        self._verified = 0
        self._rejected = 0
        self._lock = asyncio.Lock()

    @property
    def closed(self) -> bool:
        return self._closed

    async def issue_confirmation(
        self,
        authentication: ControlPlaneDurableSessionAuthentication,
        intent: ControlPlaneDurableReconciliationIntent,
        *,
        step_up_token: str | None,
    ) -> ControlPlaneDurableAdministrationConfirmationChallenge:
        """Issue one exact confirmation only after recent operator reauthentication."""

        self._require_authentication(authentication)
        self._require_intent(intent)
        self._require_permission(authentication)

        try:
            await self._step_up.verify(
                step_up_token,
                authentication,
                ControlPlaneStepUpAction.RECONCILE_DURABLE_RUN,
            )
            now = self._now()
            raw = self._nonce_source(32)
            if not isinstance(raw, bytes) or len(raw) != 32:
                raise ValueError("durable confirmation nonce source must return exactly 32 bytes")
            proof = ControlPlaneDurableAdministrationConfirmationProof(_encode(raw))
            entry = _ConfirmationEntry(
                binding_digest=_binding_digest(authentication, intent),
                issued_at=now,
                expires_at=now + self._ttl,
            )
            proof_digest = proof.digest
            async with self._lock:
                self._require_open()
                self._ensure_capacity(now)
                if proof_digest in self._entries:
                    raise ControlPlaneConfirmationRejectedError(
                        "durable administration confirmation failed"
                    )
                self._entries[proof_digest] = entry
                self._issued += 1
            return ControlPlaneDurableAdministrationConfirmationChallenge(
                intent_id=intent.id,
                action=intent.action,
                resource=intent.resource,
                fingerprint=intent.fingerprint,
                issued_at=now,
                expires_at=entry.expires_at,
                proof=proof,
            )
        except (
            ControlPlaneStepUpRejectedError,
            ControlPlaneConfirmationRejectedError,
        ):
            async with self._lock:
                self._rejected += 1
            raise

    async def verify_and_consume(
        self,
        authentication: ControlPlaneDurableSessionAuthentication,
        intent: ControlPlaneDurableReconciliationIntent,
        *,
        step_up_token: str | None,
        confirmation: ControlPlaneDurableAdministrationConfirmationProof,
    ) -> ControlPlaneDurableAdministrationConfirmationVerification:
        """Verify recent authentication and atomically consume one exact confirmation."""

        self._require_authentication(authentication)
        self._require_intent(intent)
        self._require_permission(authentication)
        if not isinstance(
            confirmation,
            ControlPlaneDurableAdministrationConfirmationProof,
        ):
            raise TypeError(
                "confirmation must be ControlPlaneDurableAdministrationConfirmationProof"
            )

        try:
            await self._step_up.verify(
                step_up_token,
                authentication,
                ControlPlaneStepUpAction.RECONCILE_DURABLE_RUN,
            )
            now = self._now()
            expected_binding = _binding_digest(authentication, intent)
            async with self._lock:
                self._require_open()
                entry = self._entries.get(confirmation.digest)
                if (
                    entry is None
                    or entry.consumed
                    or now >= entry.expires_at
                    or not secrets.compare_digest(
                        entry.binding_digest,
                        expected_binding,
                    )
                ):
                    raise ControlPlaneConfirmationRejectedError(
                        "durable administration confirmation failed"
                    )
                entry.consumed = True
                self._verified += 1
            return ControlPlaneDurableAdministrationConfirmationVerification(
                intent_id=intent.id,
                action=intent.action,
                resource=intent.resource,
                fingerprint=intent.fingerprint,
                confirmed_at=now,
            )
        except ControlPlaneStepUpRejectedError:
            async with self._lock:
                self._rejected += 1
            raise
        except ControlPlaneConfirmationStoreClosedError:
            raise
        except ControlPlaneConfirmationRejectedError:
            async with self._lock:
                self._rejected += 1
            raise
        except Exception:
            async with self._lock:
                self._rejected += 1
            raise ControlPlaneConfirmationRejectedError(
                "durable administration confirmation failed"
            ) from None

    async def snapshot(self) -> ControlPlaneDurableAdministrationProtectionSnapshot:
        async with self._lock:
            active = sum(not entry.consumed for entry in self._entries.values())
            return ControlPlaneDurableAdministrationProtectionSnapshot(
                closed=self._closed,
                entries=len(self._entries),
                active=active,
                consumed=len(self._entries) - active,
                capacity=self._capacity,
                issued=self._issued,
                verified=self._verified,
                rejected=self._rejected,
            )

    async def close(self) -> None:
        async with self._lock:
            self._closed = True
            self._entries.clear()

    @staticmethod
    def _require_authentication(
        authentication: ControlPlaneDurableSessionAuthentication,
    ) -> None:
        if not isinstance(authentication, ControlPlaneDurableSessionAuthentication):
            raise TypeError(
                "durable administration protection requires durable session authentication"
            )

    @staticmethod
    def _require_intent(intent: ControlPlaneDurableReconciliationIntent) -> None:
        if not isinstance(intent, ControlPlaneDurableReconciliationIntent):
            raise TypeError("durable administration protection requires reconciliation intent")

    @staticmethod
    def _require_permission(
        authentication: ControlPlaneDurableSessionAuthentication,
    ) -> None:
        if CONTROL_PLANE_DURABLE_RECONCILE_PERMISSION not in authentication.principal.permissions:
            raise ControlPlaneCommandPermissionDeniedError(
                "durable administration permission denied"
            )

    def _now(self) -> datetime:
        value = self._clock()
        _require_aware(value, "durable administration clock result")
        return datetime.fromtimestamp(int(value.timestamp()), UTC)

    def _ensure_capacity(self, now: datetime) -> None:
        if len(self._entries) < self._capacity:
            return
        removable = [
            (digest, entry)
            for digest, entry in self._entries.items()
            if entry.consumed or now >= entry.expires_at
        ]
        if not removable:
            raise ControlPlaneConfirmationCapacityError(
                "durable confirmation capacity is occupied by active challenges"
            )
        digest, _ = min(removable, key=lambda item: (item[1].issued_at, item[0]))
        del self._entries[digest]

    def _require_open(self) -> None:
        if self._closed:
            raise ControlPlaneConfirmationStoreClosedError(
                "durable administration confirmation service is closed"
            )


def _binding_digest(
    authentication: ControlPlaneDurableSessionAuthentication,
    intent: ControlPlaneDurableReconciliationIntent,
) -> bytes:
    document = {
        "action": intent.action,
        "fingerprint": intent.fingerprint,
        "generation": authentication.generation,
        "intent_id": intent.id.hex,
        "operator_id": authentication.operator_id.hex,
        "principal": authentication.principal.name,
        "resource": intent.resource,
        "session_id": authentication.session_id.hex,
        "version": 1,
    }
    encoded = json.dumps(
        document,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return hashlib.sha256(encoded).digest()


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _require_aware(value: datetime, label: str) -> None:
    if not isinstance(value, datetime):
        raise TypeError(f"{label} must be datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")
