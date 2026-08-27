"""Immutable bounded contracts for RFC-0036 integrated agent execution."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import timedelta
from enum import StrEnum
from uuid import UUID, uuid4

MAX_INTEGRATED_IDENTIFIER_LENGTH = 128
MAX_INTEGRATED_BINDING_LENGTH = 1_024
MAX_INTEGRATED_FRESHNESS_BINDINGS = 32
MAX_INTEGRATED_TASK_OBJECTIVE_CHARS = 65_536
MAX_INTEGRATED_PRINCIPAL_CHARS = 512
MAX_INTEGRATED_PRINCIPAL_BYTES = 2_048
MAX_INTEGRATED_TASK_OBJECTIVE_BYTES = 262_144
MAX_INTEGRATED_TASK_INPUT_REFERENCES = 128
MAX_INTEGRATED_PLAN_STATEMENTS = 64
MAX_INTEGRATED_PLAN_STATEMENT_CHARS = 4_096
MAX_INTEGRATED_PLAN_STATEMENT_BYTES = 16_384
MAX_INTEGRATED_PROVENANCE_ATOMS = 256
MAX_INTEGRATED_PROVENANCE_BYTES = 131_072
MAX_INTEGRATED_DATA_FLOW_ROUTES = 256
MAX_INTEGRATED_PROFILE_GENERATION = 2_147_483_647
MAX_INTEGRATED_PLAN_REVISION = 2_147_483_647
MAX_INTEGRATED_BUDGET_COUNT = 1_000_000
MAX_INTEGRATED_WORKSPACE_MUTATION_BYTES = 1_073_741_824
MAX_INTEGRATED_TOTAL_DURATION = timedelta(hours=2)

_IDENTIFIER_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,127})$")
_BINDING_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9._:/-]{0,1023})$")
_SHA256_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")


def _normalize_identifier(value: str, *, label: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{label} must be a string")
    normalized = value.strip().lower()
    if len(normalized) > MAX_INTEGRATED_IDENTIFIER_LENGTH:
        raise ValueError(f"{label} exceeds the maximum length")
    if _IDENTIFIER_PATTERN.fullmatch(normalized) is None:
        raise ValueError(
            f"{label} must use lowercase ASCII letters, digits, dot, underscore, or hyphen"
        )
    return normalized


def _normalize_binding(value: str, *, label: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{label} must be a string")
    normalized = value.strip()
    if len(normalized) > MAX_INTEGRATED_BINDING_LENGTH:
        raise ValueError(f"{label} exceeds the maximum length")
    if "://" in normalized or "\\" in normalized or normalized.startswith("/"):
        raise ValueError(f"{label} is not a canonical Phoenix binding")
    if _BINDING_PATTERN.fullmatch(normalized) is None:
        raise ValueError(f"{label} is not a canonical Phoenix binding")
    return normalized


def _bounded_text(
    value: str,
    *,
    label: str,
    maximum_chars: int,
    maximum_bytes: int,
) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{label} must be a string")
    if not value.strip():
        raise ValueError(f"{label} must not be blank")
    if len(value) > maximum_chars:
        raise ValueError(f"{label} exceeds the maximum character count")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exception:
        raise ValueError(f"{label} is not valid Unicode") from exception
    if len(encoded) > maximum_bytes:
        raise ValueError(f"{label} exceeds the maximum byte count")
    return value


def _positive_int(value: int, *, label: str, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{label} must be an integer")
    if value <= 0 or value > maximum:
        raise ValueError(f"{label} is outside supported bounds")
    return value


def _non_negative_int(value: int, *, label: str, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{label} must be an integer")
    if value < 0 or value > maximum:
        raise ValueError(f"{label} is outside supported bounds")
    return value


def _canonical_json_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, OverflowError) as exception:
        raise ValueError("integrated contract is not canonically encodable") from exception


def _sha256_digest(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


@dataclass(frozen=True, slots=True, order=True)
class IntegratedTaskId:
    """Opaque Phoenix-owned identity for one integrated task."""

    value: UUID = field(default_factory=uuid4)

    def __post_init__(self) -> None:
        if not isinstance(self.value, UUID):
            raise TypeError("integrated task id must be UUID")

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True, order=True)
class IntegratedTaskDigest:
    """Exact canonical SHA-256 digest for one integrated task request."""

    value: str

    def __post_init__(self) -> None:
        if not isinstance(self.value, str):
            raise TypeError("integrated task digest must be a string")
        if _SHA256_PATTERN.fullmatch(self.value) is None:
            raise ValueError("integrated task digest must be an exact lowercase SHA-256 digest")

    @classmethod
    def from_bytes(cls, value: bytes) -> IntegratedTaskDigest:
        if not isinstance(value, bytes):
            raise TypeError("integrated task digest input must be bytes")
        return cls(_sha256_digest(value))

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True, order=True)
class IntegratedExecutionProfileId:
    """Stable server-owned identity for one integrated execution profile."""

    value: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "value",
            _normalize_identifier(self.value, label="integrated execution profile id"),
        )

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True, order=True)
class IntegratedExecutionProfileGeneration:
    """Positive material-generation identity for one integrated profile."""

    value: int

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "value",
            _positive_int(
                self.value,
                label="integrated execution profile generation",
                maximum=MAX_INTEGRATED_PROFILE_GENERATION,
            ),
        )

    def __str__(self) -> str:
        return str(self.value)


class IntegratedDataSourceKind(StrEnum):
    """Finite Phoenix-owned provenance source classes."""

    USER_TASK = "user_task"
    MEMORY = "memory"
    WORKSPACE = "workspace"
    BROWSER = "browser"
    NETWORK = "network"
    HOST_CLIPBOARD = "host_clipboard"
    TOOL_RESULT = "tool_result"
    MODEL_OUTPUT = "model_output"


class IntegratedDataSink(StrEnum):
    """Finite Phoenix-owned content sinks."""

    MODEL = "model"
    ORCHESTRATION_STATE = "orchestration_state"
    WORKSPACE = "workspace"
    NETWORK = "network"
    BROWSER_EFFECT = "browser_effect"
    USER_RESULT = "user_result"


@dataclass(frozen=True, slots=True, order=True)
class IntegratedDataProvenanceAtom:
    """One exact Phoenix-owned source identity plus descriptive freshness."""

    source_kind: IntegratedDataSourceKind
    source_binding: str
    freshness_bindings: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.source_kind, IntegratedDataSourceKind):
            raise TypeError("source_kind must be IntegratedDataSourceKind")
        source_binding = _normalize_binding(
            self.source_binding,
            label="integrated provenance source binding",
        )
        supplied = tuple(self.freshness_bindings)
        if len(supplied) > MAX_INTEGRATED_FRESHNESS_BINDINGS:
            raise ValueError("integrated provenance contains too many freshness bindings")
        normalized: list[str] = []
        for item in supplied:
            normalized.append(
                _normalize_binding(
                    item,
                    label="integrated provenance freshness binding",
                )
            )
        normalized_tuple = tuple(sorted(set(normalized)))
        object.__setattr__(self, "source_binding", source_binding)
        object.__setattr__(self, "freshness_bindings", normalized_tuple)


@dataclass(frozen=True, slots=True)
class IntegratedDataProvenance:
    """Bounded exact set of provenance atoms; empty provenance is not valid content metadata."""

    atoms: tuple[IntegratedDataProvenanceAtom, ...]

    def __post_init__(self) -> None:
        supplied = tuple(self.atoms)
        if not supplied:
            raise ValueError("integrated provenance requires at least one source atom")
        if any(not isinstance(item, IntegratedDataProvenanceAtom) for item in supplied):
            raise TypeError("atoms must contain IntegratedDataProvenanceAtom values")
        normalized = tuple(sorted(set(supplied)))
        if len(normalized) > MAX_INTEGRATED_PROVENANCE_ATOMS:
            raise ValueError("PROVENANCE_OVERFLOW: too many provenance atoms")
        encoded = _canonical_json_bytes(
            [
                {
                    "source_kind": item.source_kind.value,
                    "source_binding": item.source_binding,
                    "freshness_bindings": list(item.freshness_bindings),
                }
                for item in normalized
            ]
        )
        if len(encoded) > MAX_INTEGRATED_PROVENANCE_BYTES:
            raise ValueError("PROVENANCE_OVERFLOW: provenance encoding exceeds supported bounds")
        object.__setattr__(self, "atoms", normalized)


@dataclass(frozen=True, slots=True, order=True)
class IntegratedTaskInputReference:
    """One exact reviewed task input reference; content is resolved separately."""

    source_kind: IntegratedDataSourceKind
    source_binding: str
    freshness_bindings: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        atom = IntegratedDataProvenanceAtom(
            source_kind=self.source_kind,
            source_binding=self.source_binding,
            freshness_bindings=self.freshness_bindings,
        )
        object.__setattr__(self, "source_kind", atom.source_kind)
        object.__setattr__(self, "source_binding", atom.source_binding)
        object.__setattr__(self, "freshness_bindings", atom.freshness_bindings)


@dataclass(frozen=True, slots=True)
class IntegratedTaskRequest:
    """Complete bounded task request whose canonical bytes are digest-bound."""

    task_id: IntegratedTaskId
    objective: str = field(repr=False)
    input_references: tuple[IntegratedTaskInputReference, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.task_id, IntegratedTaskId):
            raise TypeError("task_id must be IntegratedTaskId")
        objective = _bounded_text(
            self.objective,
            label="integrated task objective",
            maximum_chars=MAX_INTEGRATED_TASK_OBJECTIVE_CHARS,
            maximum_bytes=MAX_INTEGRATED_TASK_OBJECTIVE_BYTES,
        )
        references = tuple(self.input_references)
        if len(references) > MAX_INTEGRATED_TASK_INPUT_REFERENCES:
            raise ValueError("integrated task contains too many input references")
        if any(not isinstance(item, IntegratedTaskInputReference) for item in references):
            raise TypeError("input_references must contain IntegratedTaskInputReference values")
        if len(references) != len(set(references)):
            raise ValueError("integrated task contains duplicate input references")
        object.__setattr__(self, "objective", objective)
        object.__setattr__(self, "input_references", references)

    @property
    def canonical_bytes(self) -> bytes:
        return _canonical_json_bytes(
            {
                "input_references": [
                    {
                        "freshness_bindings": list(item.freshness_bindings),
                        "source_binding": item.source_binding,
                        "source_kind": item.source_kind.value,
                    }
                    for item in self.input_references
                ],
                "objective": self.objective,
                "task_id": str(self.task_id),
            }
        )

    @property
    def digest(self) -> IntegratedTaskDigest:
        return IntegratedTaskDigest.from_bytes(self.canonical_bytes)


@dataclass(frozen=True, slots=True, order=True)
class PlanRevision:
    """Positive Phoenix-owned advisory plan revision."""

    value: int

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "value",
            _positive_int(
                self.value,
                label="integrated plan revision",
                maximum=MAX_INTEGRATED_PLAN_REVISION,
            ),
        )

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True, order=True)
class PlanDigest:
    """Deterministic SHA-256 digest for normalized advisory plan data."""

    value: str

    def __post_init__(self) -> None:
        if not isinstance(self.value, str):
            raise TypeError("plan digest must be a string")
        if _SHA256_PATTERN.fullmatch(self.value) is None:
            raise ValueError("plan digest must be an exact lowercase SHA-256 digest")

    @classmethod
    def from_bytes(cls, value: bytes) -> PlanDigest:
        if not isinstance(value, bytes):
            raise TypeError("plan digest input must be bytes")
        return cls(_sha256_digest(value))

    def __str__(self) -> str:
        return self.value


def _normalize_plan_statements(values: tuple[str, ...], *, label: str) -> tuple[str, ...]:
    supplied = tuple(values)
    if not supplied:
        raise ValueError(f"{label} requires at least one statement")
    if len(supplied) > MAX_INTEGRATED_PLAN_STATEMENTS:
        raise ValueError(f"{label} contains too many statements")
    normalized: list[str] = []
    for statement in supplied:
        normalized.append(
            _bounded_text(
                statement,
                label="integrated plan statement",
                maximum_chars=MAX_INTEGRATED_PLAN_STATEMENT_CHARS,
                maximum_bytes=MAX_INTEGRATED_PLAN_STATEMENT_BYTES,
            )
        )
    return tuple(normalized)


@dataclass(frozen=True, slots=True)
class PlanProposal:
    """Bounded untrusted advisory planning data carried inside one tool proposal."""

    statements: tuple[str, ...]

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "statements",
            _normalize_plan_statements(self.statements, label="plan proposal"),
        )


@dataclass(frozen=True, slots=True)
class NormalizedPlan:
    """Phoenix-normalized advisory plan with exact revision, digest, and provenance."""

    task_id: IntegratedTaskId
    revision: PlanRevision
    digest: PlanDigest
    statements: tuple[str, ...]
    provenance: IntegratedDataProvenance

    def __post_init__(self) -> None:
        if not isinstance(self.task_id, IntegratedTaskId):
            raise TypeError("task_id must be IntegratedTaskId")
        if not isinstance(self.revision, PlanRevision):
            raise TypeError("revision must be PlanRevision")
        if not isinstance(self.digest, PlanDigest):
            raise TypeError("digest must be PlanDigest")
        statements = _normalize_plan_statements(self.statements, label="normalized plan")
        if not isinstance(self.provenance, IntegratedDataProvenance):
            raise TypeError("provenance must be IntegratedDataProvenance")
        expected = PlanDigest.from_bytes(
            _canonical_json_bytes(
                {
                    "revision": self.revision.value,
                    "statements": list(statements),
                    "task_id": str(self.task_id),
                }
            )
        )
        if self.digest != expected:
            raise ValueError("normalized plan digest does not match canonical plan data")
        object.__setattr__(self, "statements", statements)

    @classmethod
    def create(
        cls,
        *,
        task_id: IntegratedTaskId,
        revision: PlanRevision,
        statements: tuple[str, ...],
        provenance: IntegratedDataProvenance,
    ) -> NormalizedPlan:
        normalized = _normalize_plan_statements(statements, label="normalized plan")
        digest = PlanDigest.from_bytes(
            _canonical_json_bytes(
                {
                    "revision": revision.value,
                    "statements": list(normalized),
                    "task_id": str(task_id),
                }
            )
        )
        return cls(
            task_id=task_id,
            revision=revision,
            digest=digest,
            statements=normalized,
            provenance=provenance,
        )


@dataclass(frozen=True, slots=True)
class IntegratedResultAudience:
    """Authenticated Phoenix-owned audience identity for USER_RESULT disclosure."""

    principal: str = field(repr=False)
    session_id: UUID | None = None

    def __post_init__(self) -> None:
        principal = _bounded_text(
            self.principal,
            label="integrated result principal",
            maximum_chars=MAX_INTEGRATED_PRINCIPAL_CHARS,
            maximum_bytes=MAX_INTEGRATED_PRINCIPAL_BYTES,
        )
        if self.session_id is not None and not isinstance(self.session_id, UUID):
            raise TypeError("integrated result session id must be UUID or None")
        object.__setattr__(self, "principal", principal)


class IntegratedDataFlowDisposition(StrEnum):
    """Server-owned route result; absence of a route is also deny."""

    ALLOW = "allow"
    DENY = "deny"


@dataclass(frozen=True, slots=True)
class IntegratedDataFlowRoute:
    """Finite server-owned route selector evaluated later against exact provenance atoms."""

    route_id: str
    source_kind: IntegratedDataSourceKind
    sink: IntegratedDataSink
    disposition: IntegratedDataFlowDisposition
    source_scope: str | None = None
    required_freshness_bindings: tuple[str, ...] = ()
    requires_audience_match: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "route_id",
            _normalize_identifier(self.route_id, label="integrated data-flow route id"),
        )
        if not isinstance(self.source_kind, IntegratedDataSourceKind):
            raise TypeError("source_kind must be IntegratedDataSourceKind")
        if not isinstance(self.sink, IntegratedDataSink):
            raise TypeError("sink must be IntegratedDataSink")
        if not isinstance(self.disposition, IntegratedDataFlowDisposition):
            raise TypeError("disposition must be IntegratedDataFlowDisposition")
        if self.source_scope is not None:
            object.__setattr__(
                self,
                "source_scope",
                _normalize_binding(self.source_scope, label="integrated data-flow source scope"),
            )
        freshness = tuple(self.required_freshness_bindings)
        if len(freshness) > MAX_INTEGRATED_FRESHNESS_BINDINGS:
            raise ValueError("integrated data-flow route has too many freshness constraints")
        normalized_freshness = tuple(
            sorted(
                {
                    _normalize_binding(
                        item,
                        label="integrated data-flow required freshness binding",
                    )
                    for item in freshness
                }
            )
        )
        object.__setattr__(self, "required_freshness_bindings", normalized_freshness)
        if type(self.requires_audience_match) is not bool:
            raise TypeError("requires_audience_match must be a boolean")
        if (
            self.sink is IntegratedDataSink.USER_RESULT
            and self.disposition is IntegratedDataFlowDisposition.ALLOW
            and not self.requires_audience_match
        ):
            raise ValueError("USER_RESULT allow routes require authenticated audience matching")
        if self.sink is not IntegratedDataSink.USER_RESULT and self.requires_audience_match:
            raise ValueError("audience matching is valid only for USER_RESULT routes")


@dataclass(frozen=True, slots=True)
class IntegratedDataFlowDecision:
    """Content-free result of one future exact data-flow admission."""

    source_kind: IntegratedDataSourceKind
    sink: IntegratedDataSink
    disposition: IntegratedDataFlowDisposition
    route_id: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.source_kind, IntegratedDataSourceKind):
            raise TypeError("source_kind must be IntegratedDataSourceKind")
        if not isinstance(self.sink, IntegratedDataSink):
            raise TypeError("sink must be IntegratedDataSink")
        if not isinstance(self.disposition, IntegratedDataFlowDisposition):
            raise TypeError("disposition must be IntegratedDataFlowDisposition")
        if self.disposition is IntegratedDataFlowDisposition.ALLOW and self.route_id is None:
            raise ValueError("allowed data-flow decision requires an exact route_id")
        if self.route_id is not None:
            object.__setattr__(
                self,
                "route_id",
                _normalize_identifier(self.route_id, label="integrated data-flow route id"),
            )


@dataclass(frozen=True, slots=True)
class IntegratedDataFlowPolicy:
    """Finite immutable route-class policy with fail-closed default deny."""

    routes: tuple[IntegratedDataFlowRoute, ...] = ()

    def __post_init__(self) -> None:
        supplied = tuple(self.routes)
        if len(supplied) > MAX_INTEGRATED_DATA_FLOW_ROUTES:
            raise ValueError("integrated data-flow policy contains too many routes")
        if any(not isinstance(route, IntegratedDataFlowRoute) for route in supplied):
            raise TypeError("routes must contain IntegratedDataFlowRoute values")
        route_ids = tuple(route.route_id for route in supplied)
        if len(route_ids) != len(set(route_ids)):
            raise ValueError("integrated data-flow policy contains duplicate route ids")
        selectors = tuple(
            (
                route.source_kind,
                route.sink,
                route.source_scope,
                route.required_freshness_bindings,
                route.requires_audience_match,
            )
            for route in supplied
        )
        if len(selectors) != len(set(selectors)):
            raise ValueError("integrated data-flow policy contains duplicate route selectors")
        object.__setattr__(
            self,
            "routes",
            tuple(
                sorted(
                    supplied,
                    key=lambda route: (
                        route.source_kind.value,
                        route.sink.value,
                        route.source_scope or "",
                        route.required_freshness_bindings,
                        route.route_id,
                    ),
                )
            ),
        )

    @property
    def default_disposition(self) -> IntegratedDataFlowDisposition:
        """Missing exact route admission is always fail-closed deny."""

        return IntegratedDataFlowDisposition.DENY


@dataclass(frozen=True, slots=True)
class IntegratedBudgetExtension:
    """Task-level/cross-subsystem bounds not substituting RFC-0027 limits."""

    total_duration: timedelta = timedelta(minutes=20)
    max_plan_revisions: int = 16
    max_integrated_steps: int = 64
    max_browser_operations: int = 32
    max_network_operations: int = 32
    max_memory_operations: int = 32
    max_workspace_operations: int = 32
    max_workspace_mutation_bytes: int = 16_777_216
    max_host_operations: int = 16

    def __post_init__(self) -> None:
        if not isinstance(self.total_duration, timedelta):
            raise TypeError("total_duration must be a timedelta")
        if (
            self.total_duration <= timedelta(0)
            or self.total_duration > MAX_INTEGRATED_TOTAL_DURATION
        ):
            raise ValueError("total_duration is outside supported bounds")
        for label, value in (
            ("max_plan_revisions", self.max_plan_revisions),
            ("max_integrated_steps", self.max_integrated_steps),
            ("max_browser_operations", self.max_browser_operations),
            ("max_network_operations", self.max_network_operations),
            ("max_memory_operations", self.max_memory_operations),
            ("max_workspace_operations", self.max_workspace_operations),
            ("max_host_operations", self.max_host_operations),
        ):
            _positive_int(value, label=label, maximum=MAX_INTEGRATED_BUDGET_COUNT)
        _positive_int(
            self.max_workspace_mutation_bytes,
            label="max_workspace_mutation_bytes",
            maximum=MAX_INTEGRATED_WORKSPACE_MUTATION_BYTES,
        )


@dataclass(frozen=True, slots=True)
class IntegratedBudgetUsage:
    """Content-free consumed cross-subsystem budget counters."""

    plan_revisions: int = 0
    integrated_steps: int = 0
    browser_operations: int = 0
    network_operations: int = 0
    memory_operations: int = 0
    workspace_operations: int = 0
    workspace_mutation_bytes: int = 0
    host_operations: int = 0

    def __post_init__(self) -> None:
        for label, value, maximum in (
            ("plan_revisions", self.plan_revisions, MAX_INTEGRATED_BUDGET_COUNT),
            ("integrated_steps", self.integrated_steps, MAX_INTEGRATED_BUDGET_COUNT),
            ("browser_operations", self.browser_operations, MAX_INTEGRATED_BUDGET_COUNT),
            ("network_operations", self.network_operations, MAX_INTEGRATED_BUDGET_COUNT),
            ("memory_operations", self.memory_operations, MAX_INTEGRATED_BUDGET_COUNT),
            ("workspace_operations", self.workspace_operations, MAX_INTEGRATED_BUDGET_COUNT),
            (
                "workspace_mutation_bytes",
                self.workspace_mutation_bytes,
                MAX_INTEGRATED_WORKSPACE_MUTATION_BYTES,
            ),
            ("host_operations", self.host_operations, MAX_INTEGRATED_BUDGET_COUNT),
        ):
            _non_negative_int(value, label=label, maximum=maximum)


class IntegratedEffectDisposition(StrEnum):
    """Protected-effect certainty without inventing downstream knowledge."""

    NO_EFFECT = "no_effect"
    CONFIRMED_EFFECT = "confirmed_effect"
    INDETERMINATE = "indeterminate"


class IntegratedFailureClass(StrEnum):
    """Bounded sanitized orchestration failure classes."""

    VALIDATION_FAILED = "validation_failed"
    AUTHORITY_DENIED = "authority_denied"
    DATA_FLOW_DENIED = "data_flow_denied"
    PROVENANCE_OVERFLOW = "provenance_overflow"
    APPROVAL_REQUIRED = "approval_required"
    STALE_STATE = "stale_state"
    BUDGET_EXHAUSTED = "budget_exhausted"
    DEADLINE_EXCEEDED = "deadline_exceeded"
    CANCELLED = "cancelled"
    DEPENDENCY_UNAVAILABLE = "dependency_unavailable"
    DEFINITIVE_OPERATION_FAILURE = "definitive_operation_failure"
    INDETERMINATE_EFFECT = "indeterminate_effect"
    INTERNAL_FAILURE = "internal_failure"


class IntegratedOrchestrationPhase(StrEnum):
    """Derived non-authoritative task-level phase."""

    CREATED = "created"
    PLANNING = "planning"
    EXECUTING = "executing"
    WAITING = "waiting"
    TERMINAL = "terminal"


class IntegratedWaitingReason(StrEnum):
    """Finite content-free reasons for a derived WAITING phase."""

    APPROVAL = "approval"
    CONTEXT_RESUPPLY = "context_resupply"
    RECONCILIATION = "reconciliation"
    DEPENDENCY = "dependency"
