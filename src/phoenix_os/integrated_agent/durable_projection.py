"""Metadata-only RFC-0036 projection into RFC-0028 durable checkpoints."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from uuid import UUID

from phoenix_os.agent.contracts import (
    AgentJsonInput,
    AgentStepId,
    canonical_agent_json_bytes,
    freeze_agent_json_object,
)
from phoenix_os.agent.durable_contracts import (
    CheckpointEnvelope,
    CheckpointId,
    CheckpointNextOperation,
    DurableRunStatus,
    ExecutionAttemptId,
)
from phoenix_os.integrated_agent.contracts import (
    IntegratedBudgetUsage,
    IntegratedDataProvenance,
    IntegratedExecutionProfileGeneration,
    IntegratedExecutionProfileId,
    IntegratedOrchestrationPhase,
    IntegratedTaskDigest,
    IntegratedTaskId,
    IntegratedWaitingReason,
    PlanDigest,
    PlanRevision,
)
from phoenix_os.integrated_agent.errors import IntegratedAgentCodecError

RFC0036_DURABLE_METADATA_PREFIX = "rfc0036."
CURRENT_RFC0036_PROJECTION_SCHEMA_VERSION = 1

_SCHEMA_VERSION = f"{RFC0036_DURABLE_METADATA_PREFIX}schema_version"
_TASK_ID = f"{RFC0036_DURABLE_METADATA_PREFIX}task_id"
_TASK_DIGEST = f"{RFC0036_DURABLE_METADATA_PREFIX}task_digest"
_PROFILE_ID = f"{RFC0036_DURABLE_METADATA_PREFIX}execution_profile_id"
_PROFILE_GENERATION = f"{RFC0036_DURABLE_METADATA_PREFIX}execution_profile_generation"
_PLAN_REVISION = f"{RFC0036_DURABLE_METADATA_PREFIX}plan_revision"
_PLAN_DIGEST = f"{RFC0036_DURABLE_METADATA_PREFIX}plan_digest"
_DATA_FLOW_DIGEST = f"{RFC0036_DURABLE_METADATA_PREFIX}data_flow_context_digest"
_PHASE = f"{RFC0036_DURABLE_METADATA_PREFIX}orchestration_phase"
_STEP_ID = f"{RFC0036_DURABLE_METADATA_PREFIX}current_agent_step_id"
_ATTEMPT_ID = f"{RFC0036_DURABLE_METADATA_PREFIX}current_attempt_id"
_LAST_SAFE_BOUNDARY = f"{RFC0036_DURABLE_METADATA_PREFIX}last_safe_boundary"
_WAITING_REASON = f"{RFC0036_DURABLE_METADATA_PREFIX}waiting_reason"

_BUDGET_KEYS = {
    "plan_revisions": f"{RFC0036_DURABLE_METADATA_PREFIX}budget.plan_revisions",
    "integrated_steps": f"{RFC0036_DURABLE_METADATA_PREFIX}budget.integrated_steps",
    "browser_operations": f"{RFC0036_DURABLE_METADATA_PREFIX}budget.browser_operations",
    "network_operations": f"{RFC0036_DURABLE_METADATA_PREFIX}budget.network_operations",
    "memory_operations": f"{RFC0036_DURABLE_METADATA_PREFIX}budget.memory_operations",
    "workspace_operations": f"{RFC0036_DURABLE_METADATA_PREFIX}budget.workspace_operations",
    "workspace_mutation_bytes": (
        f"{RFC0036_DURABLE_METADATA_PREFIX}budget.workspace_mutation_bytes"
    ),
    "host_operations": f"{RFC0036_DURABLE_METADATA_PREFIX}budget.host_operations",
}

_REQUIRED_KEYS = frozenset(
    {
        _SCHEMA_VERSION,
        _TASK_ID,
        _TASK_DIGEST,
        _PROFILE_ID,
        _PROFILE_GENERATION,
        _PHASE,
        _LAST_SAFE_BOUNDARY,
        *_BUDGET_KEYS.values(),
    }
)
_OPTIONAL_KEYS = frozenset(
    {
        _PLAN_REVISION,
        _PLAN_DIGEST,
        _DATA_FLOW_DIGEST,
        _STEP_ID,
        _ATTEMPT_ID,
        _WAITING_REASON,
    }
)
_KNOWN_KEYS = _REQUIRED_KEYS | _OPTIONAL_KEYS
_CANONICAL_INTEGER = re.compile(r"^(?:0|[1-9][0-9]*)$")
_INTEGRATED_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")

_ACTIVE_NEXT_OPERATIONS = frozenset(
    {
        CheckpointNextOperation.MODEL_TURN,
        CheckpointNextOperation.VALIDATE_PROPOSAL,
        CheckpointNextOperation.AUTHORIZE_TOOL,
        CheckpointNextOperation.TOOL_INVOCATION,
        CheckpointNextOperation.VALIDATE_RESULT,
        CheckpointNextOperation.COMPLETE,
    }
)


@dataclass(frozen=True, slots=True)
class IntegratedOrchestrationCheckpointProjection:
    """Bounded server-owned RFC-0036 state stored only as checkpoint metadata."""

    task_id: IntegratedTaskId
    task_digest: IntegratedTaskDigest
    execution_profile_id: IntegratedExecutionProfileId
    execution_profile_generation: IntegratedExecutionProfileGeneration
    budget_extension_usage: IntegratedBudgetUsage
    orchestration_phase: IntegratedOrchestrationPhase
    last_safe_boundary: CheckpointId
    plan_revision: PlanRevision | None = None
    plan_digest: PlanDigest | None = None
    data_flow_context_digest: str | None = None
    current_agent_step_id: AgentStepId | None = None
    current_attempt_id: ExecutionAttemptId | None = None
    waiting_reason: IntegratedWaitingReason | None = None
    schema_version: int = CURRENT_RFC0036_PROJECTION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if not isinstance(self.task_id, IntegratedTaskId):
            raise TypeError("task_id must be IntegratedTaskId")
        if not isinstance(self.task_digest, IntegratedTaskDigest):
            raise TypeError("task_digest must be IntegratedTaskDigest")
        if not isinstance(self.execution_profile_id, IntegratedExecutionProfileId):
            raise TypeError("execution_profile_id must be IntegratedExecutionProfileId")
        if not isinstance(
            self.execution_profile_generation,
            IntegratedExecutionProfileGeneration,
        ):
            raise TypeError(
                "execution_profile_generation must be IntegratedExecutionProfileGeneration"
            )
        if not isinstance(self.budget_extension_usage, IntegratedBudgetUsage):
            raise TypeError("budget_extension_usage must be IntegratedBudgetUsage")
        if not isinstance(self.orchestration_phase, IntegratedOrchestrationPhase):
            raise TypeError("orchestration_phase must be IntegratedOrchestrationPhase")
        if not isinstance(self.last_safe_boundary, CheckpointId):
            raise TypeError("last_safe_boundary must be CheckpointId")
        if self.plan_revision is not None and not isinstance(self.plan_revision, PlanRevision):
            raise TypeError("plan_revision must be PlanRevision or None")
        if self.plan_digest is not None and not isinstance(self.plan_digest, PlanDigest):
            raise TypeError("plan_digest must be PlanDigest or None")
        if (self.plan_revision is None) != (self.plan_digest is None):
            raise ValueError("plan revision and digest must be present together")
        if self.data_flow_context_digest is not None:
            if (
                not isinstance(self.data_flow_context_digest, str)
                or _INTEGRATED_SHA256.fullmatch(self.data_flow_context_digest) is None
            ):
                raise ValueError("data-flow context digest must be canonical SHA-256")
        if self.current_agent_step_id is not None and not isinstance(
            self.current_agent_step_id,
            AgentStepId,
        ):
            raise TypeError("current_agent_step_id must be AgentStepId or None")
        if self.current_attempt_id is not None and not isinstance(
            self.current_attempt_id,
            ExecutionAttemptId,
        ):
            raise TypeError("current_attempt_id must be ExecutionAttemptId or None")
        if self.waiting_reason is not None and not isinstance(
            self.waiting_reason,
            IntegratedWaitingReason,
        ):
            raise TypeError("waiting_reason must be IntegratedWaitingReason or None")
        if (
            isinstance(self.schema_version, bool)
            or not isinstance(self.schema_version, int)
            or self.schema_version != CURRENT_RFC0036_PROJECTION_SCHEMA_VERSION
        ):
            raise ValueError("unsupported RFC-0036 projection schema version")
        if (
            self.orchestration_phase is not IntegratedOrchestrationPhase.WAITING
            and self.waiting_reason is not None
        ):
            raise ValueError("waiting_reason is valid only for WAITING projection")


def integrated_data_flow_context_digest(provenance: IntegratedDataProvenance) -> str:
    """Return a canonical content-free digest for exact integrated provenance."""

    if not isinstance(provenance, IntegratedDataProvenance):
        raise TypeError("provenance must be IntegratedDataProvenance")
    atoms: list[AgentJsonInput] = [
        {
            "freshness_bindings": list(atom.freshness_bindings),
            "source_binding": atom.source_binding,
            "source_kind": atom.source_kind.value,
        }
        for atom in provenance.atoms
    ]
    payload_input: dict[str, AgentJsonInput] = {
        "schema_version": CURRENT_RFC0036_PROJECTION_SCHEMA_VERSION,
        "provenance": atoms,
    }
    payload = freeze_agent_json_object(payload_input)
    return f"sha256:{hashlib.sha256(canonical_agent_json_bytes(payload)).hexdigest()}"


def encode_integrated_durable_projection(
    projection: IntegratedOrchestrationCheckpointProjection,
) -> Mapping[str, str]:
    """Encode only bounded server-owned RFC-0036 metadata values."""

    if not isinstance(projection, IntegratedOrchestrationCheckpointProjection):
        raise TypeError("projection must be IntegratedOrchestrationCheckpointProjection")

    usage = projection.budget_extension_usage
    encoded = {
        _SCHEMA_VERSION: str(projection.schema_version),
        _TASK_ID: str(projection.task_id),
        _TASK_DIGEST: str(projection.task_digest),
        _PROFILE_ID: str(projection.execution_profile_id),
        _PROFILE_GENERATION: str(projection.execution_profile_generation),
        _BUDGET_KEYS["plan_revisions"]: str(usage.plan_revisions),
        _BUDGET_KEYS["integrated_steps"]: str(usage.integrated_steps),
        _BUDGET_KEYS["browser_operations"]: str(usage.browser_operations),
        _BUDGET_KEYS["network_operations"]: str(usage.network_operations),
        _BUDGET_KEYS["memory_operations"]: str(usage.memory_operations),
        _BUDGET_KEYS["workspace_operations"]: str(usage.workspace_operations),
        _BUDGET_KEYS["workspace_mutation_bytes"]: str(usage.workspace_mutation_bytes),
        _BUDGET_KEYS["host_operations"]: str(usage.host_operations),
        _PHASE: projection.orchestration_phase.value,
        _LAST_SAFE_BOUNDARY: str(projection.last_safe_boundary),
    }
    if projection.plan_revision is not None:
        encoded[_PLAN_REVISION] = str(projection.plan_revision)
        assert projection.plan_digest is not None
        encoded[_PLAN_DIGEST] = str(projection.plan_digest)
    if projection.data_flow_context_digest is not None:
        encoded[_DATA_FLOW_DIGEST] = projection.data_flow_context_digest
    if projection.current_agent_step_id is not None:
        encoded[_STEP_ID] = str(projection.current_agent_step_id)
    if projection.current_attempt_id is not None:
        encoded[_ATTEMPT_ID] = str(projection.current_attempt_id)
    if projection.waiting_reason is not None:
        encoded[_WAITING_REASON] = projection.waiting_reason.value
    return MappingProxyType(encoded)


def merge_integrated_durable_projection(
    metadata: Mapping[str, str],
    projection: IntegratedOrchestrationCheckpointProjection,
) -> Mapping[str, str]:
    """Add a server-owned projection while rejecting reserved-key injection."""

    if not isinstance(metadata, Mapping):
        raise TypeError("metadata must be a mapping")
    if any(
        not isinstance(key, str) or not isinstance(value, str) for key, value in metadata.items()
    ):
        raise IntegratedAgentCodecError("checkpoint metadata is invalid")
    if any(key.startswith(RFC0036_DURABLE_METADATA_PREFIX) for key in metadata):
        raise IntegratedAgentCodecError("reserved RFC-0036 metadata is server-owned")
    merged = dict(metadata)
    merged.update(encode_integrated_durable_projection(projection))
    return MappingProxyType(merged)


def decode_integrated_durable_projection(
    checkpoint: CheckpointEnvelope,
) -> IntegratedOrchestrationCheckpointProjection | None:
    """Strictly decode and validate RFC-0036 metadata against its RFC-0028 checkpoint."""

    if not isinstance(checkpoint, CheckpointEnvelope):
        raise TypeError("checkpoint must be CheckpointEnvelope")
    projected = {
        key: value
        for key, value in checkpoint.metadata.metadata.items()
        if key.startswith(RFC0036_DURABLE_METADATA_PREFIX)
    }
    if not projected:
        return None
    try:
        _require_exact_key_set(projected)
        projection = _decode_projection(projected)
        validate_integrated_durable_projection(checkpoint, projection)
        return projection
    except IntegratedAgentCodecError:
        raise
    except (TypeError, ValueError) as exception:
        raise IntegratedAgentCodecError("integrated durable projection is invalid") from exception


def require_integrated_durable_projection(
    checkpoint: CheckpointEnvelope,
) -> IntegratedOrchestrationCheckpointProjection:
    """Require RFC-0036 projection presence for an integrated durable checkpoint."""

    projection = decode_integrated_durable_projection(checkpoint)
    if projection is None:
        raise IntegratedAgentCodecError("integrated durable projection is missing")
    return projection


def validate_integrated_durable_projection(
    checkpoint: CheckpointEnvelope,
    projection: IntegratedOrchestrationCheckpointProjection,
) -> None:
    """Fail closed when projected state contradicts authoritative RFC-0028 state."""

    if not isinstance(checkpoint, CheckpointEnvelope):
        raise TypeError("checkpoint must be CheckpointEnvelope")
    if not isinstance(projection, IntegratedOrchestrationCheckpointProjection):
        raise TypeError("projection must be IntegratedOrchestrationCheckpointProjection")

    if (checkpoint.step_id is None) != (projection.current_agent_step_id is None):
        raise IntegratedAgentCodecError("projected agent step does not match checkpoint")
    if checkpoint.step_id is not None and projection.current_agent_step_id != checkpoint.step_id:
        raise IntegratedAgentCodecError("projected agent step does not match checkpoint")

    attempt = checkpoint.metadata.active_attempt
    if (attempt is None) != (projection.current_attempt_id is None):
        raise IntegratedAgentCodecError("projected attempt does not match checkpoint")
    if attempt is not None and projection.current_attempt_id != attempt.attempt_id:
        raise IntegratedAgentCodecError("projected attempt does not match checkpoint")

    phase = projection.orchestration_phase
    next_operation = checkpoint.metadata.next_operation

    if checkpoint.status.terminal:
        if phase is not IntegratedOrchestrationPhase.TERMINAL:
            raise IntegratedAgentCodecError("projected phase contradicts terminal checkpoint")
    elif phase is IntegratedOrchestrationPhase.TERMINAL:
        raise IntegratedAgentCodecError("projected terminal phase contradicts checkpoint")

    if phase is IntegratedOrchestrationPhase.WAITING:
        reason = projection.waiting_reason
        if reason is IntegratedWaitingReason.APPROVAL:
            if next_operation is not CheckpointNextOperation.WAIT_APPROVAL:
                raise IntegratedAgentCodecError("approval wait contradicts next operation")
        elif next_operation is not CheckpointNextOperation.OPERATOR_REVIEW and not (
            checkpoint.status is DurableRunStatus.PAUSED_OPERATOR
            and next_operation in _ACTIVE_NEXT_OPERATIONS
        ):
            raise IntegratedAgentCodecError("operator wait contradicts next operation")
    elif next_operation in {
        CheckpointNextOperation.WAIT_APPROVAL,
        CheckpointNextOperation.OPERATOR_REVIEW,
    }:
        raise IntegratedAgentCodecError("waiting next operation requires WAITING phase")

    if phase is IntegratedOrchestrationPhase.TERMINAL:
        if next_operation is not CheckpointNextOperation.NONE:
            raise IntegratedAgentCodecError("terminal projection requires no next operation")
    elif next_operation is CheckpointNextOperation.NONE:
        raise IntegratedAgentCodecError("non-terminal projection cannot use no next operation")
    elif (
        phase is not IntegratedOrchestrationPhase.WAITING
        and next_operation not in _ACTIVE_NEXT_OPERATIONS
    ):
        raise IntegratedAgentCodecError("projected phase contradicts next operation")

    if (
        checkpoint.status is DurableRunStatus.PAUSED_OPERATOR
        and phase is not IntegratedOrchestrationPhase.WAITING
    ):
        raise IntegratedAgentCodecError("operator pause requires WAITING projection")
    if (
        checkpoint.status.indeterminate
        and projection.waiting_reason is not IntegratedWaitingReason.RECONCILIATION
    ):
        raise IntegratedAgentCodecError(
            "indeterminate checkpoint requires reconciliation waiting projection"
        )
    if (
        checkpoint.status is DurableRunStatus.PAUSED_APPROVAL
        and projection.waiting_reason is not IntegratedWaitingReason.APPROVAL
    ):
        raise IntegratedAgentCodecError("approval pause requires approval waiting projection")


def _require_exact_key_set(projected: Mapping[str, str]) -> None:
    keys = frozenset(projected)
    unknown = keys - _KNOWN_KEYS
    if unknown:
        raise IntegratedAgentCodecError("checkpoint contains unknown RFC-0036 metadata")
    if not _REQUIRED_KEYS <= keys:
        raise IntegratedAgentCodecError("checkpoint contains incomplete RFC-0036 metadata")
    if (_PLAN_REVISION in keys) != (_PLAN_DIGEST in keys):
        raise IntegratedAgentCodecError("checkpoint contains incomplete plan projection")


def _decode_projection(
    projected: Mapping[str, str],
) -> IntegratedOrchestrationCheckpointProjection:
    if projected[_SCHEMA_VERSION] != str(CURRENT_RFC0036_PROJECTION_SCHEMA_VERSION):
        raise IntegratedAgentCodecError("unsupported RFC-0036 projection schema version")

    task_id = IntegratedTaskId(_canonical_uuid(projected[_TASK_ID]))
    task_digest = IntegratedTaskDigest(projected[_TASK_DIGEST])

    profile_id = IntegratedExecutionProfileId(projected[_PROFILE_ID])
    if str(profile_id) != projected[_PROFILE_ID]:
        raise IntegratedAgentCodecError("integrated profile id is not canonical")
    profile_generation = IntegratedExecutionProfileGeneration(
        _canonical_int(projected[_PROFILE_GENERATION])
    )

    plan_revision: PlanRevision | None = None
    plan_digest: PlanDigest | None = None
    if _PLAN_REVISION in projected:
        plan_revision = PlanRevision(_canonical_int(projected[_PLAN_REVISION]))
        plan_digest = PlanDigest(projected[_PLAN_DIGEST])

    data_flow_digest = projected.get(_DATA_FLOW_DIGEST)
    if data_flow_digest is not None and _INTEGRATED_SHA256.fullmatch(data_flow_digest) is None:
        raise IntegratedAgentCodecError("data-flow context digest is not canonical")

    step_id = AgentStepId(_canonical_uuid(projected[_STEP_ID])) if _STEP_ID in projected else None
    attempt_id = (
        ExecutionAttemptId(_canonical_uuid(projected[_ATTEMPT_ID]))
        if _ATTEMPT_ID in projected
        else None
    )
    waiting_reason = (
        IntegratedWaitingReason(projected[_WAITING_REASON])
        if _WAITING_REASON in projected
        else None
    )
    return IntegratedOrchestrationCheckpointProjection(
        task_id=task_id,
        task_digest=task_digest,
        execution_profile_id=profile_id,
        execution_profile_generation=profile_generation,
        plan_revision=plan_revision,
        plan_digest=plan_digest,
        budget_extension_usage=IntegratedBudgetUsage(
            plan_revisions=_canonical_int(projected[_BUDGET_KEYS["plan_revisions"]]),
            integrated_steps=_canonical_int(projected[_BUDGET_KEYS["integrated_steps"]]),
            browser_operations=_canonical_int(projected[_BUDGET_KEYS["browser_operations"]]),
            network_operations=_canonical_int(projected[_BUDGET_KEYS["network_operations"]]),
            memory_operations=_canonical_int(projected[_BUDGET_KEYS["memory_operations"]]),
            workspace_operations=_canonical_int(projected[_BUDGET_KEYS["workspace_operations"]]),
            workspace_mutation_bytes=_canonical_int(
                projected[_BUDGET_KEYS["workspace_mutation_bytes"]]
            ),
            host_operations=_canonical_int(projected[_BUDGET_KEYS["host_operations"]]),
        ),
        data_flow_context_digest=data_flow_digest,
        orchestration_phase=IntegratedOrchestrationPhase(projected[_PHASE]),
        current_agent_step_id=step_id,
        current_attempt_id=attempt_id,
        last_safe_boundary=CheckpointId(_canonical_uuid(projected[_LAST_SAFE_BOUNDARY])),
        waiting_reason=waiting_reason,
    )


def _canonical_int(value: str) -> int:
    if _CANONICAL_INTEGER.fullmatch(value) is None:
        raise IntegratedAgentCodecError("RFC-0036 integer metadata is not canonical")
    return int(value)


def _canonical_uuid(value: str) -> UUID:
    try:
        parsed = UUID(value)
    except (ValueError, AttributeError) as exception:
        raise IntegratedAgentCodecError("RFC-0036 UUID metadata is invalid") from exception
    if str(parsed) != value:
        raise IntegratedAgentCodecError("RFC-0036 UUID metadata is not canonical")
    return parsed
