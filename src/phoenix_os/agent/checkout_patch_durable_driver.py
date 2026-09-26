"""Specialized durable dispatch for RFC-0039 workspace.patch."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Protocol, runtime_checkable

from phoenix_os.agent.approval import (
    ToolApprovalChallenge,
    ToolApprovalEvidence,
    ToolApprovalService,
    ToolApprovalVerification,
)
from phoenix_os.agent.authorization import canonical_tool_argument_digest
from phoenix_os.agent.checkout_patch_agent_tool import (
    CHECKOUT_PATCH_TOOL_ID,
    CheckoutPatchToolAdapter,
    checkout_patch_tool_descriptor,
)
from phoenix_os.agent.checkout_patch_commit import revalidate_checkout_patch_commit
from phoenix_os.agent.checkout_patch_durable import commit_checkout_patch_durable
from phoenix_os.agent.checkout_patch_physical import CheckoutPatchCommitIndeterminateError
from phoenix_os.agent.checkout_patch_preparation import (
    CheckoutPatchPreparation,
    prepare_checkout_patch,
)
from phoenix_os.agent.checkout_patch_security import observe_checkout_patch_security_metadata
from phoenix_os.agent.contracts import (
    AgentJsonInput,
    ToolInvocationRequest,
    ToolInvocationResult,
    ToolResultStatus,
)
from phoenix_os.agent.durable_attempts import DurableExecutionAttemptRecorder
from phoenix_os.agent.durable_contracts import CheckpointEnvelope
from phoenix_os.agent.durable_lease_keepalive import (
    StoreBackedDurableLeaseKeepaliveFactory,
)
from phoenix_os.agent.durable_live_tool import DurableToolBindingProvider
from phoenix_os.agent.errors import (
    AgentApprovalRejectedError,
    AgentStateConflictError,
    AgentTimeoutError,
    ToolExecutionError,
)
from phoenix_os.agent.execution import BoundedAgentExecutor, validate_tool_invocation_result
from phoenix_os.agent.loop import AgentToolExecutionDriver, ToolApprovalResolver
from phoenix_os.agent.state import AgentCancellationToken
from phoenix_os.agent.tools import (
    ToolAdapter,
    ToolDescriptor,
    ToolFinalAdmissionValidator,
)
from phoenix_os.policy import SecurityContext


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _require_timezone_aware(value: datetime, *, label: str) -> None:
    if not isinstance(value, datetime):
        raise TypeError(f"{label} must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")


def _is_exact_patch_descriptor(descriptor: ToolDescriptor) -> bool:
    return descriptor == checkout_patch_tool_descriptor()


@runtime_checkable
class CheckoutPatchApprovalResolver(ToolApprovalResolver, Protocol):
    "Resolve one exact prepared patch only after presenting trusted review material."

    async def resolve_prepared_patch(
        self,
        challenge: ToolApprovalChallenge,
        *,
        logical_path: str,
        preparation_digest: str,
        unified_diff: str,
    ) -> ToolApprovalEvidence: ...


def _prepared_patch_approval_arguments(
    preparation: CheckoutPatchPreparation,
) -> dict[str, AgentJsonInput]:
    if not isinstance(preparation, CheckoutPatchPreparation):
        raise TypeError("preparation must be CheckoutPatchPreparation")
    review_diff_digest = (
        "sha256:" + hashlib.sha256(preparation.unified_diff.encode("utf-8")).hexdigest()
    )
    return {
        "approval_binding_schema": "rfc0039.workspace.patch.prepared-approval.v1",
        "workspace_id": str(preparation.workspace_id),
        "registration_generation": preparation.registration_generation,
        "logical_path": preparation.logical_path,
        "root_identity": preparation.root_identity,
        "file_identity": preparation.file_identity,
        "before_content_digest": preparation.before_content_digest,
        "after_content_digest": preparation.after_content_digest,
        "preparation_digest": preparation.preparation_digest,
        "security_metadata_fingerprint": preparation.security_metadata_fingerprint,
        "changed_line_count": preparation.changed_line_count,
        "review_diff_digest": review_diff_digest,
    }


def _prepared_patch_approval_request(
    invocation: ToolInvocationRequest,
    preparation: CheckoutPatchPreparation,
    *,
    deadline: datetime,
) -> ToolInvocationRequest:
    _require_timezone_aware(deadline, label="prepared patch approval deadline")
    return ToolInvocationRequest(
        agent_id=invocation.agent_id,
        run_id=invocation.run_id,
        step_id=invocation.step_id,
        call_id=invocation.call_id,
        tool_id=invocation.tool_id,
        arguments=_prepared_patch_approval_arguments(preparation),
        resolved_resource=invocation.resolved_resource,
        created_at=invocation.created_at,
        deadline=deadline,
    )


def _validate_consumed_prepared_patch_approval(
    *,
    invocation: ToolInvocationRequest,
    descriptor: ToolDescriptor,
    preparation: CheckoutPatchPreparation,
    approval_request: ToolInvocationRequest,
    evidence: ToolApprovalEvidence,
    verification: ToolApprovalVerification,
    now: datetime,
) -> None:
    _require_timezone_aware(now, label="approval validation time")
    expected_arguments = _prepared_patch_approval_arguments(preparation)
    if approval_request.arguments != expected_arguments:
        raise AgentApprovalRejectedError()
    if approval_request.deadline > invocation.deadline:
        raise AgentApprovalRejectedError()
    if evidence.expires_at <= now or verification.consumed_at >= evidence.expires_at:
        raise AgentApprovalRejectedError()
    if (
        evidence.run_id != invocation.run_id
        or evidence.step_id != invocation.step_id
        or evidence.call_id != invocation.call_id
        or evidence.tool_id != invocation.tool_id
        or evidence.effect != descriptor.effect
        or evidence.resolved_resource != invocation.resolved_resource
        or evidence.argument_digest != canonical_tool_argument_digest(expected_arguments)
        or verification.run_id != invocation.run_id
        or verification.step_id != invocation.step_id
        or verification.call_id != invocation.call_id
        or verification.tool_id != invocation.tool_id
        or verification.approval_id != evidence.approval_id
    ):
        raise AgentApprovalRejectedError()


class CheckoutPatchDurableToolExecutionDriver:
    """Route only workspace.patch through the specialized durable boundary owner."""

    def __init__(
        self,
        *,
        fallback: AgentToolExecutionDriver,
        binding_provider: DurableToolBindingProvider,
        recorder: DurableExecutionAttemptRecorder,
        approval_service: ToolApprovalService | None = None,
        approval_resolver: ToolApprovalResolver | None = None,
        lease_keepalive_factory: StoreBackedDurableLeaseKeepaliveFactory | None = None,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        if not isinstance(fallback, AgentToolExecutionDriver):
            raise TypeError("fallback must implement AgentToolExecutionDriver")
        if not isinstance(binding_provider, DurableToolBindingProvider):
            raise TypeError("binding_provider must implement DurableToolBindingProvider")
        if not isinstance(recorder, DurableExecutionAttemptRecorder):
            raise TypeError("recorder must implement DurableExecutionAttemptRecorder")
        if approval_service is not None and not isinstance(approval_service, ToolApprovalService):
            raise TypeError("approval_service must implement ToolApprovalService")
        if approval_resolver is not None and not isinstance(
            approval_resolver, ToolApprovalResolver
        ):
            raise TypeError("approval_resolver must implement ToolApprovalResolver")
        if lease_keepalive_factory is not None and not isinstance(
            lease_keepalive_factory,
            StoreBackedDurableLeaseKeepaliveFactory,
        ):
            raise TypeError(
                "lease_keepalive_factory must be StoreBackedDurableLeaseKeepaliveFactory or None"
            )
        if not callable(clock):
            raise TypeError("clock must be callable")
        self._fallback = fallback
        self._binding_provider = binding_provider
        self._recorder = recorder
        self._approval_service = approval_service
        self._approval_resolver = approval_resolver
        self._lease_keepalive_factory = lease_keepalive_factory
        self._clock = clock
        self._last_checkpoint: CheckpointEnvelope | None = None

    @property
    def last_checkpoint(self) -> CheckpointEnvelope | None:
        return self._last_checkpoint

    async def execute(
        self,
        executor: BoundedAgentExecutor,
        adapter: ToolAdapter,
        invocation: ToolInvocationRequest,
        descriptor: ToolDescriptor,
        context: SecurityContext,
        *,
        final_admission: ToolFinalAdmissionValidator | None,
        timeout_seconds: float,
        cancellation_grace: float,
        cancellation: AgentCancellationToken,
        prepare_time: datetime,
    ) -> ToolInvocationResult:
        if not isinstance(executor, BoundedAgentExecutor):
            raise TypeError("executor must be BoundedAgentExecutor")
        if not isinstance(adapter, ToolAdapter):
            raise TypeError("adapter must implement ToolAdapter")
        if not isinstance(invocation, ToolInvocationRequest):
            raise TypeError("invocation must be ToolInvocationRequest")
        if not isinstance(descriptor, ToolDescriptor):
            raise TypeError("descriptor must be ToolDescriptor")
        if not isinstance(context, SecurityContext):
            raise TypeError("context must be SecurityContext")
        if not isinstance(cancellation, AgentCancellationToken):
            raise TypeError("cancellation must be AgentCancellationToken")
        _require_timezone_aware(prepare_time, label="prepare_time")

        patch_invocation = invocation.tool_id == CHECKOUT_PATCH_TOOL_ID
        patch_descriptor = descriptor.tool_id == CHECKOUT_PATCH_TOOL_ID
        if not patch_invocation and not patch_descriptor:
            return await self._fallback.execute(
                executor,
                adapter,
                invocation,
                descriptor,
                context,
                final_admission=final_admission,
                timeout_seconds=timeout_seconds,
                cancellation_grace=cancellation_grace,
                cancellation=cancellation,
                prepare_time=prepare_time,
            )

        if (
            not patch_invocation
            or not patch_descriptor
            or not _is_exact_patch_descriptor(descriptor)
            or not isinstance(adapter, CheckoutPatchToolAdapter)
            or final_admission is None
            or not callable(final_admission)
        ):
            raise ToolExecutionError()

        if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float)):
            raise TypeError("timeout_seconds must be numeric")
        if timeout_seconds <= 0:
            raise AgentTimeoutError()

        cancellation.raise_if_cancelled()
        started_at = max(prepare_time, self._now())
        effective_deadline = min(
            invocation.deadline,
            prepare_time + descriptor.timeout,
            prepare_time + timedelta(seconds=float(timeout_seconds)),
        )
        if started_at >= effective_deadline:
            raise AgentTimeoutError()

        preparation_request = await adapter.prepare_request_with_context(
            invocation,
            context,
        )
        cancellation.raise_if_cancelled()

        current_read_result = await adapter.checkout.read(
            preparation_request.snapshot.logical_path,
            run_id=invocation.run_id,
        )
        if current_read_result.snapshot != preparation_request.snapshot:
            raise AgentStateConflictError()

        target = adapter.checkout._patch_target_for_commit(
            preparation_request.snapshot.logical_path
        )
        security_metadata = observe_checkout_patch_security_metadata(target)
        preparation = prepare_checkout_patch(
            adapter.registration,
            current_read_result,
            preparation_request,
            security_metadata,
        )
        approval_service = self._approval_service
        approval_resolver = self._approval_resolver
        if (
            approval_service is None
            or approval_resolver is None
            or not isinstance(approval_resolver, CheckoutPatchApprovalResolver)
        ):
            raise AgentApprovalRejectedError()
        cancellation.raise_if_cancelled()
        approval_request = _prepared_patch_approval_request(
            invocation,
            preparation,
            deadline=effective_deadline,
        )
        approval_challenge = await approval_service.request(
            approval_request,
            descriptor,
            context,
        )
        approval_evidence = await approval_resolver.resolve_prepared_patch(
            approval_challenge,
            logical_path=preparation.logical_path,
            preparation_digest=preparation.preparation_digest,
            unified_diff=preparation.unified_diff,
        )
        cancellation.raise_if_cancelled()

        current_read_result = await adapter.checkout.read(
            preparation.logical_path,
            run_id=invocation.run_id,
        )
        current_security = observe_checkout_patch_security_metadata(
            adapter.checkout._patch_target_for_commit(preparation.logical_path)
        )
        ticket = revalidate_checkout_patch_commit(
            adapter.registration,
            current_read_result,
            preparation,
            security_metadata=current_security,
            run_id=invocation.run_id,
            step_id=invocation.step_id,
            call_id=invocation.call_id,
        )

        binding = await self._binding_provider.bind(
            invocation,
            descriptor,
            now=prepare_time,
        )
        if binding.invocation is not invocation or binding.descriptor is not descriptor:
            raise AgentStateConflictError()

        lease_keepalive = (
            None
            if self._lease_keepalive_factory is None
            else self._lease_keepalive_factory.create(binding.lease)
        )
        approval_verification = await approval_service.verify_and_consume(
            approval_evidence,
            approval_request,
            descriptor,
            context,
        )
        _validate_consumed_prepared_patch_approval(
            invocation=invocation,
            descriptor=descriptor,
            preparation=preparation,
            approval_request=approval_request,
            evidence=approval_evidence,
            verification=approval_verification,
            now=self._now(),
        )

        def physical_pre_effect_validator() -> None:
            cancellation.raise_if_cancelled()
            now = self._now()
            if now >= effective_deadline:
                raise AgentTimeoutError()
            _validate_consumed_prepared_patch_approval(
                invocation=invocation,
                descriptor=descriptor,
                preparation=preparation,
                approval_request=approval_request,
                evidence=approval_evidence,
                verification=approval_verification,
                now=now,
            )

        try:
            physical_result, terminal = await commit_checkout_patch_durable(
                binding,
                self._recorder,
                adapter.checkout,
                current_read_result,
                preparation,
                ticket,
                run_id=invocation.run_id,
                step_id=invocation.step_id,
                call_id=invocation.call_id,
                prepare_time=prepare_time,
                physical_pre_effect_validator=physical_pre_effect_validator,
                final_admission=final_admission,
                mutation_bytes=len(preparation.candidate_bytes),
                cancellation=cancellation,
                lease_keepalive=lease_keepalive,
                clock=self._clock,
            )
        except CheckoutPatchCommitIndeterminateError:
            completed_at = self._completed_at(started_at)
            result = ToolInvocationResult(
                run_id=invocation.run_id,
                step_id=invocation.step_id,
                call_id=invocation.call_id,
                tool_id=invocation.tool_id,
                status=ToolResultStatus.INDETERMINATE,
                error_code="workspace_patch_commit_indeterminate",
                started_at=started_at,
                completed_at=completed_at,
            )
            return validate_tool_invocation_result(
                invocation,
                descriptor,
                result,
                started_at=started_at,
                completed_at=completed_at,
            )

        self._last_checkpoint = terminal
        completed_at = self._completed_at(started_at)
        result = ToolInvocationResult(
            run_id=invocation.run_id,
            step_id=invocation.step_id,
            call_id=invocation.call_id,
            tool_id=invocation.tool_id,
            status=ToolResultStatus.SUCCEEDED,
            output={
                "workspace_id": str(physical_result.workspace_id),
                "logical_path": physical_result.logical_path,
                "before_content_digest": physical_result.before_content_digest,
                "after_content_digest": physical_result.after_content_digest,
                "preparation_digest": physical_result.preparation_digest,
                "changed_line_count": physical_result.changed_line_count,
                "files_changed": 1,
                "review_status": "approved",
                "status": physical_result.status,
            },
            started_at=started_at,
            completed_at=completed_at,
        )
        return validate_tool_invocation_result(
            invocation,
            descriptor,
            result,
            started_at=started_at,
            completed_at=completed_at,
        )

    def _now(self) -> datetime:
        value = self._clock()
        _require_timezone_aware(value, label="clock result")
        return value

    def _completed_at(self, started_at: datetime) -> datetime:
        return max(started_at, self._now())
