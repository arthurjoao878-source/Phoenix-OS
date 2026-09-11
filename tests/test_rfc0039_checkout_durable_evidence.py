from __future__ import annotations

import base64
import hashlib
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from phoenix_os.agent.checkout_agent_tools import (
    CHECKOUT_READ_TOOL_ID,
    checkout_tool_descriptors,
)
from phoenix_os.agent.checkout_durable_evidence import (
    CheckoutReadDurableResultMetadataProjectorFactory,
)
from phoenix_os.agent.contracts import (
    AgentId,
    AgentRunId,
    AgentStepId,
    ToolCallId,
    ToolEffect,
    ToolInvocationRequest,
    ToolInvocationResult,
    ToolResultStatus,
)
from phoenix_os.agent.durable_codec import seal_checkpoint_envelope
from phoenix_os.agent.durable_contracts import (
    CheckpointDigest,
    CheckpointEnvelope,
    CheckpointId,
    CheckpointMetadata,
    CheckpointNextOperation,
    CheckpointPayloadProfile,
    CheckpointSchemaVersion,
    CheckpointSequence,
    CompatibilityDigests,
    DurableAgentRunId,
    DurableRunStatus,
    DurableRunVersion,
    ExecutionAttempt,
    ExecutionAttemptId,
    ExecutionAttemptKind,
    ExecutionAttemptStatus,
)
from phoenix_os.agent.durable_memory import InMemoryDurableRunStore
from phoenix_os.agent.durable_metadata import DurableCheckpointMetadataProjector
from phoenix_os.agent.durable_tool import DurableToolAttemptBinding
from phoenix_os.agent.errors import AgentStateConflictError
from phoenix_os.agent.state import AgentBudgetSnapshot
from phoenix_os.agent.tools import ToolDescriptor

NOW = datetime(2026, 9, 7, 2, tzinfo=UTC)
DURABLE_RUN_ID = DurableAgentRunId(UUID("15000000-0000-0000-0000-000000000039"))
RUN_ID = AgentRunId(UUID("25000000-0000-0000-0000-000000000039"))
STEP_ID = AgentStepId(UUID("35000000-0000-0000-0000-000000000039"))
CALL_ID = ToolCallId(UUID("45000000-0000-0000-0000-000000000039"))
ATTEMPT_ID = ExecutionAttemptId(UUID("55000000-0000-0000-0000-000000000039"))
WORKSPACE_ID = UUID("65000000-0000-0000-0000-000000000039")


def _digest(seed: bytes) -> str:
    return "sha256:" + hashlib.sha256(seed).hexdigest()


def _checkpoint_digest(character: str) -> CheckpointDigest:
    return CheckpointDigest(character * 64)


def _compatibility() -> CompatibilityDigests:
    return CompatibilityDigests(
        configuration=_checkpoint_digest("a"),
        tool_registry=_checkpoint_digest("b"),
        model_provider=_checkpoint_digest("c"),
        checkpoint_codec=_checkpoint_digest("d"),
    )


def _budget() -> AgentBudgetSnapshot:
    return AgentBudgetSnapshot(
        steps=1,
        model_turns=1,
        tool_calls=1,
        model_output_bytes=64,
        tool_result_bytes=0,
        input_tokens=8,
        output_tokens=8,
        started_at=NOW - timedelta(minutes=1),
        deadline=NOW + timedelta(minutes=10),
    )


def _started_attempt() -> ExecutionAttempt:
    return ExecutionAttempt(
        attempt_id=ATTEMPT_ID,
        kind=ExecutionAttemptKind.TOOL_INVOCATION,
        status=ExecutionAttemptStatus.STARTED,
        agent_run_id=RUN_ID,
        step_id=STEP_ID,
        prepared_at=NOW - timedelta(seconds=2),
        started_at=NOW - timedelta(seconds=1),
        tool_call_id=CALL_ID,
        tool_effect=ToolEffect.READ_ONLY,
        external_request_digest=_checkpoint_digest("e"),
    )


def _succeeded_attempt() -> ExecutionAttempt:
    return ExecutionAttempt(
        attempt_id=ATTEMPT_ID,
        kind=ExecutionAttemptKind.TOOL_INVOCATION,
        status=ExecutionAttemptStatus.SUCCEEDED,
        agent_run_id=RUN_ID,
        step_id=STEP_ID,
        prepared_at=NOW - timedelta(seconds=2),
        started_at=NOW - timedelta(seconds=1),
        completed_at=NOW,
        tool_call_id=CALL_ID,
        tool_effect=ToolEffect.READ_ONLY,
        external_request_digest=_checkpoint_digest("e"),
    )


def _checkpoint() -> CheckpointEnvelope:
    return seal_checkpoint_envelope(
        CheckpointEnvelope(
            schema_version=CheckpointSchemaVersion(),
            durable_run_id=DURABLE_RUN_ID,
            checkpoint_id=CheckpointId(UUID("75000000-0000-0000-0000-000000000039")),
            sequence=CheckpointSequence(1),
            previous_digest=None,
            run_version=DurableRunVersion(1),
            status=DurableRunStatus.ACTIVE,
            agent_run_id=RUN_ID,
            step_id=STEP_ID,
            metadata=CheckpointMetadata(
                agent_id=AgentId("assistant"),
                actor_id="rfc0039-checkout-durable-evidence-test",
                next_operation=CheckpointNextOperation.TOOL_INVOCATION,
                budget=_budget(),
                compatibility=_compatibility(),
                payload_profile=CheckpointPayloadProfile.METADATA_ONLY,
                retention_deadline=NOW + timedelta(days=1),
                active_attempt=None,
                metadata={"fixture": "base"},
            ),
            created_at=NOW,
            digest=_checkpoint_digest("0"),
        )
    )


async def _binding(
    descriptor: ToolDescriptor | None = None,
) -> tuple[InMemoryDurableRunStore, DurableToolAttemptBinding]:
    store = InMemoryDurableRunStore()
    checkpoint = _checkpoint()
    await store.create(checkpoint)
    lease = await store.lease_manager.acquire(
        DURABLE_RUN_ID,
        owner_id="rfc0039-checkout-durable-evidence-test",
        now=NOW,
    )
    invocation = ToolInvocationRequest(
        agent_id=AgentId("assistant"),
        run_id=RUN_ID,
        step_id=STEP_ID,
        call_id=CALL_ID,
        tool_id=CHECKOUT_READ_TOOL_ID,
        arguments={"logical_path": "src/readme.txt"},
        resolved_resource=f"development-checkout:{WORKSPACE_ID}/generation:7",
        created_at=NOW,
        deadline=NOW + timedelta(minutes=1),
    )
    return store, DurableToolAttemptBinding(
        checkpoint=checkpoint,
        lease=lease,
        invocation=invocation,
        descriptor=descriptor or checkout_tool_descriptors()[1],
    )


def _result(payload: bytes = b"hello\n") -> ToolInvocationResult:
    encoded = base64.b64encode(payload).decode("ascii")
    return ToolInvocationResult(
        run_id=RUN_ID,
        step_id=STEP_ID,
        call_id=CALL_ID,
        tool_id=CHECKOUT_READ_TOOL_ID,
        status=ToolResultStatus.SUCCEEDED,
        output={
            "snapshot": {
                "run_id": str(RUN_ID),
                "workspace_id": str(WORKSPACE_ID),
                "registration_generation": 7,
                "logical_path": "src/readme.txt",
                "root_identity": _digest(b"root"),
                "file_identity": _digest(b"file"),
                "content_digest": _digest(payload),
                "byte_length": len(payload),
            },
            "content_encoding": "base64-utf8",
            "content_base64_chunks": (encoded,),
        },
        started_at=NOW,
        completed_at=NOW,
    )


@pytest.mark.asyncio
async def test_factory_projects_only_content_free_checkout_read_evidence() -> None:
    store, binding = await _binding()
    try:
        factory = CheckoutReadDurableResultMetadataProjectorFactory()
        projector = factory.create_projector(binding, _result())
        assert isinstance(projector, DurableCheckpointMetadataProjector)

        projected = projector.project_metadata(
            binding.checkpoint,
            checkpoint_id=CheckpointId(),
            status=DurableRunStatus.ACTIVE,
            step_id=STEP_ID,
            next_operation=CheckpointNextOperation.VALIDATE_RESULT,
            active_attempt=_succeeded_attempt(),
            metadata={"fixture": "base"},
        )

        assert projected["rfc0039.checkout.read.count"] == "1"
        assert projected["rfc0039.checkout.read.bytes"] == "6"
        assert projected["rfc0039.checkout.read.last.workspace_id"] == str(WORKSPACE_ID)
        assert projected["rfc0039.checkout.read.last.registration_generation"] == "7"
        assert projected["rfc0039.checkout.read.last.root_identity"] == _digest(b"root")
        assert projected["rfc0039.checkout.read.last.file_identity"] == _digest(b"file")
        assert projected["rfc0039.checkout.read.last.content_digest"] == _digest(b"hello\n")
        assert projected["rfc0039.checkout.read.last.byte_length"] == "6"
        serialized = repr(projected)
        assert "src/readme.txt" not in serialized
        assert "aGVsbG8K" not in serialized
        assert "hello" not in serialized
    finally:
        await store.close()


@pytest.mark.asyncio
async def test_projector_accumulates_read_count_and_bytes() -> None:
    store, binding = await _binding()
    try:
        factory = CheckoutReadDurableResultMetadataProjectorFactory()
        first = factory.create_projector(binding, _result(b"abc"))
        assert first is not None
        metadata = first.project_metadata(
            binding.checkpoint,
            checkpoint_id=CheckpointId(),
            status=DurableRunStatus.ACTIVE,
            step_id=STEP_ID,
            next_operation=CheckpointNextOperation.VALIDATE_RESULT,
            active_attempt=_succeeded_attempt(),
            metadata={"fixture": "base"},
        )
        second = factory.create_projector(binding, _result(b"hello"))
        assert second is not None
        metadata = second.project_metadata(
            binding.checkpoint,
            checkpoint_id=CheckpointId(),
            status=DurableRunStatus.ACTIVE,
            step_id=STEP_ID,
            next_operation=CheckpointNextOperation.VALIDATE_RESULT,
            active_attempt=_succeeded_attempt(),
            metadata=metadata,
        )

        assert metadata["rfc0039.checkout.read.count"] == "2"
        assert metadata["rfc0039.checkout.read.bytes"] == "8"
        assert metadata["rfc0039.checkout.read.last.byte_length"] == "5"
        assert metadata["rfc0039.checkout.read.last.content_digest"] == _digest(b"hello")
    finally:
        await store.close()


@pytest.mark.asyncio
async def test_factory_rejects_tampered_snapshot_digest_before_projection() -> None:
    store, binding = await _binding()
    try:
        result = _result(b"hello")
        assert result.output is not None
        output = dict(result.output)
        snapshot_value = output["snapshot"]
        assert isinstance(snapshot_value, Mapping)
        snapshot = dict(snapshot_value)
        snapshot["content_digest"] = _digest(b"different")
        output["snapshot"] = snapshot
        tampered = ToolInvocationResult(
            run_id=result.run_id,
            step_id=result.step_id,
            call_id=result.call_id,
            tool_id=result.tool_id,
            status=result.status,
            output=output,
            started_at=result.started_at,
            completed_at=result.completed_at,
        )

        with pytest.raises(AgentStateConflictError):
            CheckoutReadDurableResultMetadataProjectorFactory().create_projector(
                binding,
                tampered,
            )
    finally:
        await store.close()


@pytest.mark.asyncio
async def test_factory_rejects_path_or_resource_identity_mismatch() -> None:
    store, binding = await _binding()
    try:
        result = _result()
        assert result.output is not None
        output = dict(result.output)
        snapshot_value = output["snapshot"]
        assert isinstance(snapshot_value, Mapping)
        snapshot = dict(snapshot_value)
        snapshot["logical_path"] = "src/other.txt"
        output["snapshot"] = snapshot
        tampered = ToolInvocationResult(
            run_id=result.run_id,
            step_id=result.step_id,
            call_id=result.call_id,
            tool_id=result.tool_id,
            status=result.status,
            output=output,
            started_at=result.started_at,
            completed_at=result.completed_at,
        )
        with pytest.raises(AgentStateConflictError):
            CheckoutReadDurableResultMetadataProjectorFactory().create_projector(
                binding,
                tampered,
            )
    finally:
        await store.close()


@pytest.mark.asyncio
async def test_factory_ignores_non_checkout_workspace_read_descriptor() -> None:
    descriptor = checkout_tool_descriptors()[1]
    other = ToolDescriptor(
        tool_id=descriptor.tool_id,
        name=descriptor.name,
        description=descriptor.description,
        input_schema=descriptor.input_schema,
        output_schema=descriptor.output_schema,
        effect=descriptor.effect,
        approval_may_be_required=descriptor.approval_may_be_required,
        max_input_bytes=descriptor.max_input_bytes,
        max_output_bytes=descriptor.max_output_bytes,
        timeout=descriptor.timeout,
        resolver_id="other-workspace-resource",
        adapter_id="other-workspace-read",
        metadata=descriptor.metadata,
    )
    store, binding = await _binding(other)
    try:
        projector = CheckoutReadDurableResultMetadataProjectorFactory().create_projector(
            binding,
            _result(),
        )
        assert projector is None
    finally:
        await store.close()


@pytest.mark.asyncio
async def test_projector_rejects_partial_or_invalid_prior_evidence() -> None:
    store, binding = await _binding()
    try:
        projector = CheckoutReadDurableResultMetadataProjectorFactory().create_projector(
            binding,
            _result(),
        )
        assert projector is not None

        with pytest.raises(AgentStateConflictError):
            projector.project_metadata(
                binding.checkpoint,
                checkpoint_id=CheckpointId(),
                status=DurableRunStatus.ACTIVE,
                step_id=STEP_ID,
                next_operation=CheckpointNextOperation.VALIDATE_RESULT,
                active_attempt=_succeeded_attempt(),
                metadata={"rfc0039.checkout.read.count": "1"},
            )
    finally:
        await store.close()
