"""Immutable contracts for RFC-0033 authority inspection and explanation."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID, uuid4

from phoenix_os.policy import PrincipalType

_ACTION_PATTERN = re.compile(r"^[a-z][a-z0-9_.:/-]*$")
_RESOURCE_PATTERN = re.compile(r"^[a-z][a-z0-9_.:/-]*$")
_DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
MAX_AUTHORITY_ACTION_LENGTH = 128
MAX_AUTHORITY_REFERENCE_LENGTH = 1_024
MAX_AUTHORITY_RESOURCE_LENGTH = 2_048
MAX_AUTHORITY_FRESHNESS_BINDINGS = 16
MAX_AUTHORITY_PATH_BOUNDARIES = 16
MAX_AUTHORITY_BLOCKED_ALTERNATIVES = 32
MAX_AUTHORITY_OBSERVATIONS = 256


def _normalize_action(value: str, *, label: str = "authority action") -> str:
    if not isinstance(value, str):
        raise TypeError(f"{label} must be a string")
    normalized = value.strip().lower()
    if len(normalized) > MAX_AUTHORITY_ACTION_LENGTH:
        raise ValueError(f"{label} exceeds the maximum length")
    if _ACTION_PATTERN.fullmatch(normalized) is None:
        raise ValueError(f"invalid {label}: {value!r}")
    return normalized


def _normalize_resource(value: str) -> str:
    if not isinstance(value, str):
        raise TypeError("canonical_resource must be a string")
    normalized = value.strip().lower()
    if len(normalized) > MAX_AUTHORITY_RESOURCE_LENGTH:
        raise ValueError("canonical_resource exceeds the maximum length")
    if _RESOURCE_PATTERN.fullmatch(normalized) is None:
        raise ValueError(f"invalid canonical authority resource: {value!r}")
    return normalized


def _normalize_digest(value: str, *, label: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{label} must be a string")
    normalized = value.strip().lower()
    if _DIGEST_PATTERN.fullmatch(normalized) is None:
        raise ValueError(f"{label} must be a sha256 digest")
    return normalized


def _bounded_text(
    value: str,
    *,
    label: str,
    maximum: int = MAX_AUTHORITY_REFERENCE_LENGTH,
) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{label} must be a string")
    normalized = value.strip()
    if not normalized:
        raise ValueError(f"{label} must not be blank")
    if len(normalized) > maximum:
        raise ValueError(f"{label} exceeds the maximum length")
    return normalized


def _optional_bounded_text(value: str | None, *, label: str) -> str | None:
    if value is None:
        return None
    return _bounded_text(value, label=label)


def _aware(value: datetime, *, label: str) -> datetime:
    if not isinstance(value, datetime):
        raise TypeError(f"{label} must be datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")
    return value


def _fingerprint(parts: tuple[str | None, ...]) -> str:
    digest = hashlib.sha256()
    for part in parts:
        if part is None:
            digest.update(b"\x00")
            continue
        encoded = part.encode("utf-8")
        digest.update(b"\x01")
        digest.update(len(encoded).to_bytes(4, "big"))
        digest.update(encoded)
    return "sha256:" + digest.hexdigest()


class AuthorityEffect(StrEnum):
    """Effective point-in-time authority outcome."""

    ALLOWED = "allowed"
    DENIED = "denied"


class AuthorityConstraint(StrEnum):
    """Safe operator-facing categories that may constrain effective authority."""

    POLICY = "policy"
    SUBJECT_BINDING = "subject_binding"
    SESSION_FRESHNESS = "session_freshness"
    AGENT_BINDING = "agent_binding"
    RUN_BINDING = "run_binding"
    APPROVAL = "approval"
    RESOURCE_FRESHNESS = "resource_freshness"
    CANCELLATION = "cancellation"
    DELEGATION = "delegation"
    CANONICAL_BOUNDARY = "canonical_boundary"


class AuthorityDenialReason(StrEnum):
    """Content-free denial categories safe to expose to an authorized operator."""

    POLICY_DENIED = "policy_denied"
    APPROVAL_REQUIRED = "approval_required"
    SUBJECT_STALE = "subject_stale"
    RESOURCE_STALE = "resource_stale"
    CANCELLED = "cancelled"
    BOUNDARY_DENIED = "boundary_denied"
    UNKNOWN_OPERATION = "unknown_operation"
    SOURCE_UNAVAILABLE = "source_unavailable"


@dataclass(frozen=True, slots=True)
class AuthoritySubject:
    """Trusted structural authority subject resolved from Phoenix-owned state."""

    principal_type: PrincipalType
    principal: str
    session_id: UUID | None = None
    agent_id: str | None = None
    run_id: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.principal_type, PrincipalType):
            raise TypeError("principal_type must be PrincipalType")
        object.__setattr__(self, "principal", _bounded_text(self.principal, label="principal"))
        if self.session_id is not None and not isinstance(self.session_id, UUID):
            raise TypeError("session_id must be UUID or None")
        object.__setattr__(
            self,
            "agent_id",
            _optional_bounded_text(self.agent_id, label="agent_id"),
        )
        object.__setattr__(self, "run_id", _optional_bounded_text(self.run_id, label="run_id"))


@dataclass(frozen=True, slots=True, order=True)
class AuthorityFreshnessBinding:
    """One finite server-derived freshness identity bound into an exact intent."""

    kind: str
    identity: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "kind",
            _normalize_action(self.kind, label="freshness binding kind"),
        )
        object.__setattr__(
            self,
            "identity",
            _bounded_text(self.identity, label="freshness binding identity"),
        )


@dataclass(frozen=True, slots=True)
class AuthorityIntent:
    """Exact protected-operation intent resolved from trusted current state."""

    action: str
    canonical_resource: str
    parameter_digest: str
    freshness_bindings: tuple[AuthorityFreshnessBinding, ...] = ()

    def __post_init__(self) -> None:
        action = _normalize_action(self.action)
        resource = _normalize_resource(self.canonical_resource)
        parameter_digest = _normalize_digest(self.parameter_digest, label="parameter_digest")
        raw_bindings = tuple(self.freshness_bindings)
        if any(not isinstance(item, AuthorityFreshnessBinding) for item in raw_bindings):
            raise TypeError("freshness_bindings must contain AuthorityFreshnessBinding values")
        bindings = tuple(sorted(raw_bindings))
        if len(bindings) > MAX_AUTHORITY_FRESHNESS_BINDINGS:
            raise ValueError("too many authority freshness bindings")
        if len(bindings) != len(set(bindings)):
            raise ValueError("duplicate authority freshness bindings")
        object.__setattr__(self, "action", action)
        object.__setattr__(self, "canonical_resource", resource)
        object.__setattr__(self, "parameter_digest", parameter_digest)
        object.__setattr__(self, "freshness_bindings", bindings)


@dataclass(frozen=True, slots=True)
class AuthorityPathObservation:
    """Internal point-in-time observation for one exact protected intent."""

    intent: AuthorityIntent
    boundaries: tuple[str, ...]
    effect: AuthorityEffect
    constraints: tuple[AuthorityConstraint, ...] = ()
    denial_reason: AuthorityDenialReason | None = None
    blocked_downstream: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.intent, AuthorityIntent):
            raise TypeError("intent must be AuthorityIntent")
        boundaries = tuple(
            _normalize_action(item, label="authority boundary") for item in self.boundaries
        )
        if not boundaries:
            raise ValueError("authority path must contain at least one boundary")
        if len(boundaries) > MAX_AUTHORITY_PATH_BOUNDARIES:
            raise ValueError("authority path exceeds the maximum boundary count")
        if not isinstance(self.effect, AuthorityEffect):
            raise TypeError("effect must be AuthorityEffect")
        if any(not isinstance(item, AuthorityConstraint) for item in self.constraints):
            raise TypeError("constraints must contain AuthorityConstraint values")
        constraints = tuple(sorted(set(self.constraints), key=lambda item: item.value))
        blocked = tuple(
            _normalize_action(item, label="blocked downstream action")
            for item in self.blocked_downstream
        )
        if len(blocked) > MAX_AUTHORITY_BLOCKED_ALTERNATIVES:
            raise ValueError("blocked_downstream exceeds the maximum action count")
        if len(blocked) != len(set(blocked)):
            raise ValueError("blocked_downstream must not contain duplicates")
        if self.effect is AuthorityEffect.ALLOWED and self.denial_reason is not None:
            raise ValueError("allowed authority observation cannot have a denial reason")
        if self.effect is AuthorityEffect.DENIED and not isinstance(
            self.denial_reason, AuthorityDenialReason
        ):
            raise ValueError("denied authority observation requires a denial reason")
        object.__setattr__(self, "boundaries", boundaries)
        object.__setattr__(self, "constraints", constraints)
        object.__setattr__(self, "blocked_downstream", blocked)


@dataclass(frozen=True, slots=True)
class AuthorityInspectionState:
    """Trusted internal state collected for one exact resolved subject."""

    subject: AuthoritySubject
    observations: tuple[AuthorityPathObservation, ...]
    observed_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        if not isinstance(self.subject, AuthoritySubject):
            raise TypeError("subject must be AuthoritySubject")
        _aware(self.observed_at, label="observed_at")
        observations = tuple(self.observations)
        if any(not isinstance(item, AuthorityPathObservation) for item in observations):
            raise TypeError("observations must contain AuthorityPathObservation values")
        if len(observations) > MAX_AUTHORITY_OBSERVATIONS:
            raise ValueError("inspection observations exceed the maximum item count")
        fingerprints = tuple(authority_intent_fingerprint(item.intent) for item in observations)
        if len(fingerprints) != len(set(fingerprints)):
            raise ValueError("inspection observations must not contain duplicate intents")
        object.__setattr__(self, "observations", observations)


@dataclass(frozen=True, slots=True)
class AuthorityInspectRequest:
    """Untrusted selector for a server-resolved authority subject."""

    target_ref: str
    request_id: UUID = field(default_factory=uuid4)
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "target_ref",
            _bounded_text(self.target_ref, label="authority target reference"),
        )
        if not isinstance(self.request_id, UUID):
            raise TypeError("request_id must be UUID")
        _aware(self.created_at, label="created_at")


@dataclass(frozen=True, slots=True)
class AuthorityExplainRequest:
    """Untrusted selector for a server-resolved subject and exact intent."""

    target_ref: str
    action: str
    resource_ref: str | None = None
    request_id: UUID = field(default_factory=uuid4)
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "target_ref",
            _bounded_text(self.target_ref, label="authority target reference"),
        )
        object.__setattr__(self, "action", _normalize_action(self.action))
        object.__setattr__(
            self,
            "resource_ref",
            _optional_bounded_text(self.resource_ref, label="authority resource reference"),
        )
        if not isinstance(self.request_id, UUID):
            raise TypeError("request_id must be UUID")
        _aware(self.created_at, label="created_at")


@dataclass(frozen=True, slots=True)
class AuthoritySubjectProjection:
    """Safe diagnostic subject projection; never bearer authority."""

    principal_type: PrincipalType
    principal: str
    session_identity: str | None
    agent_id: str | None
    run_id: str | None

    def __post_init__(self) -> None:
        if not isinstance(self.principal_type, PrincipalType):
            raise TypeError("principal_type must be PrincipalType")
        object.__setattr__(self, "principal", _bounded_text(self.principal, label="principal"))
        if self.session_identity is not None:
            object.__setattr__(
                self,
                "session_identity",
                _normalize_digest(self.session_identity, label="session_identity"),
            )
        object.__setattr__(
            self,
            "agent_id",
            _optional_bounded_text(self.agent_id, label="agent_id"),
        )
        object.__setattr__(self, "run_id", _optional_bounded_text(self.run_id, label="run_id"))


@dataclass(frozen=True, slots=True)
class AuthorityObservationProjection:
    """Safe diagnostic projection for one exact authority observation."""

    effect: AuthorityEffect
    requested_action: str
    canonical_resource: str
    authority_path: tuple[str, ...]
    applicable_constraints: tuple[AuthorityConstraint, ...]
    denial_reason: AuthorityDenialReason | None
    blocked_downstream_alternatives: tuple[str, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.effect, AuthorityEffect):
            raise TypeError("effect must be AuthorityEffect")
        requested_action = _normalize_action(self.requested_action)
        canonical_resource = _normalize_resource(self.canonical_resource)
        authority_path = tuple(
            _normalize_action(item, label="authority boundary") for item in self.authority_path
        )
        if not authority_path:
            raise ValueError("authority_path must not be empty")
        if len(authority_path) > MAX_AUTHORITY_PATH_BOUNDARIES:
            raise ValueError("authority_path exceeds the maximum boundary count")
        if any(not isinstance(item, AuthorityConstraint) for item in self.applicable_constraints):
            raise TypeError("applicable_constraints must contain AuthorityConstraint values")
        constraints = tuple(sorted(set(self.applicable_constraints), key=lambda item: item.value))
        blocked = tuple(
            _normalize_action(item, label="blocked downstream action")
            for item in self.blocked_downstream_alternatives
        )
        if len(blocked) > MAX_AUTHORITY_BLOCKED_ALTERNATIVES:
            raise ValueError("blocked_downstream_alternatives exceeds the maximum action count")
        if len(blocked) != len(set(blocked)):
            raise ValueError("blocked_downstream_alternatives must not contain duplicates")
        if self.effect is AuthorityEffect.ALLOWED and self.denial_reason is not None:
            raise ValueError("allowed projection cannot have a denial reason")
        if self.effect is AuthorityEffect.DENIED and not isinstance(
            self.denial_reason, AuthorityDenialReason
        ):
            raise ValueError("denied projection requires a denial reason")
        object.__setattr__(self, "requested_action", requested_action)
        object.__setattr__(self, "canonical_resource", canonical_resource)
        object.__setattr__(self, "authority_path", authority_path)
        object.__setattr__(self, "applicable_constraints", constraints)
        object.__setattr__(self, "blocked_downstream_alternatives", blocked)


@dataclass(frozen=True, slots=True)
class AuthorityInspectionResult:
    """Authorized redacted point-in-time authority inspection."""

    subject: AuthoritySubjectProjection
    observations: tuple[AuthorityObservationProjection, ...]
    observed_at: datetime

    def __post_init__(self) -> None:
        if not isinstance(self.subject, AuthoritySubjectProjection):
            raise TypeError("subject must be AuthoritySubjectProjection")
        if any(not isinstance(item, AuthorityObservationProjection) for item in self.observations):
            raise TypeError("observations must contain AuthorityObservationProjection values")
        if len(self.observations) > MAX_AUTHORITY_OBSERVATIONS:
            raise ValueError("observations exceed the maximum item count")
        _aware(self.observed_at, label="observed_at")
        object.__setattr__(self, "observations", tuple(self.observations))


@dataclass(frozen=True, slots=True)
class AuthorityExplanationResult:
    """Authorized redacted point-in-time explanation for one exact intent."""

    subject: AuthoritySubjectProjection
    observation: AuthorityObservationProjection
    observed_at: datetime

    def __post_init__(self) -> None:
        if not isinstance(self.subject, AuthoritySubjectProjection):
            raise TypeError("subject must be AuthoritySubjectProjection")
        if not isinstance(self.observation, AuthorityObservationProjection):
            raise TypeError("observation must be AuthorityObservationProjection")
        _aware(self.observed_at, label="observed_at")


def authority_subject_fingerprint(subject: AuthoritySubject) -> str:
    """Return a content-free digest over one exact structural subject."""

    if not isinstance(subject, AuthoritySubject):
        raise TypeError("subject must be AuthoritySubject")
    return _fingerprint(
        (
            subject.principal_type.value,
            subject.principal,
            str(subject.session_id) if subject.session_id is not None else None,
            subject.agent_id,
            subject.run_id,
        )
    )


def authority_intent_fingerprint(intent: AuthorityIntent) -> str:
    """Return a content-free digest over one exact server-resolved intent."""

    if not isinstance(intent, AuthorityIntent):
        raise TypeError("intent must be AuthorityIntent")
    binding_parts: list[str | None] = [
        intent.action,
        intent.canonical_resource,
        intent.parameter_digest,
    ]
    for binding in intent.freshness_bindings:
        binding_parts.extend((binding.kind, binding.identity))
    return _fingerprint(tuple(binding_parts))
