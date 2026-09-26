from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import cast
from uuid import UUID

import pytest

import phoenix_os.agent.checkout_patch_durable as durable_module
import phoenix_os.agent.checkout_patch_durable_driver as driver_module
import phoenix_os.agent.checkout_patch_physical as physical_module
import phoenix_os.agent.checkout_patch_security as security_module
from phoenix_os.agent.approval import (
    InMemoryToolApprovalService,
    ToolApprovalChallenge,
    ToolApprovalEvidence,
)
from phoenix_os.agent.authorization import canonical_tool_argument_digest
from phoenix_os.agent.checkout_authorization import (
    CheckoutListAuthorizationRequest,
    CheckoutPatchAuthorizationRequest,
    CheckoutReadAuthorizationRequest,
)
from phoenix_os.agent.checkout_patch_agent_tool import CHECKOUT_PATCH_TOOL_ID
from phoenix_os.agent.checkout_patch_commit import CheckoutPatchCommitTicket
from phoenix_os.agent.checkout_patch_durable_driver import (
    CheckoutPatchDurableToolExecutionDriver,
)
from phoenix_os.agent.checkout_patch_physical import CheckoutPatchPhysicalCommitResult
from phoenix_os.agent.checkout_patch_preparation import (
    CheckoutPatchPreparation,
    CheckoutPatchPreparationRequest,
    prepare_checkout_patch,
)
from phoenix_os.agent.checkout_patch_security import CheckoutPatchSecurityMetadata
from phoenix_os.agent.checkout_workspace import (
    CheckoutReadResult,
    RegisteredDevelopmentCheckout,
    RegisteredDevelopmentCheckoutAdapter,
)
from phoenix_os.agent.contracts import (
    AgentId,
    AgentJsonInput,
    AgentRunId,
    AgentStepId,
    ToolCallId,
    ToolInvocationRequest,
    ToolResultStatus,
)
from phoenix_os.agent.durable_attempts import DurableExecutionAttemptRecorder
from phoenix_os.agent.durable_contracts import (
    CheckpointNextOperation,
    ExecutionAttemptStatus,
)
from phoenix_os.agent.durable_live_tool import DurableToolBindingProvider
from phoenix_os.agent.execution import BoundedAgentExecutor
from phoenix_os.agent.loop import AgentToolExecutionDriver
from phoenix_os.agent.state import AgentCancellationToken
from phoenix_os.agent.tools import (
    ToolDescriptor,
    ToolFinalAdmissionContext,
    ToolFinalAdmissionGrant,
)
from phoenix_os.integrated_agent.composition import (
    integrated_checkout_patch_tool_registration,
    integrated_development_checkout_dogfood_profile,
)
from phoenix_os.integrated_agent.contracts import (
    IntegratedDataFlowPolicy,
    IntegratedExecutionProfileGeneration,
    IntegratedExecutionProfileId,
)
from phoenix_os.integrated_agent.profiles import (
    IntegratedDownstreamBridgeBinding,
    IntegratedExecutionProfile,
)
from phoenix_os.policy import PrincipalType, SecurityContext

_WORKSPACE_ID = UUID("10000000-0000-4000-8000-000000000001")
_RUN_ID = AgentRunId(UUID("20000000-0000-4000-8000-000000000002"))
_STEP_ID = AgentStepId(UUID("30000000-0000-4000-8000-000000000003"))
_CALL_ID = ToolCallId(UUID("40000000-0000-4000-8000-000000000004"))
_AGENT_ID = AgentId("rfc0039-e2e-patch")
_PROFILE_ID = IntegratedExecutionProfileId("rfc0039-e2e-patch")
_PROFILE_GENERATION = IntegratedExecutionProfileGeneration(1)
_NOW = datetime(2026, 9, 12, 18, 0, tzinfo=UTC)


class _RecordingAuthorizer:
    def __init__(self) -> None:
        self.patch_calls: list[tuple[CheckoutPatchAuthorizationRequest, SecurityContext]] = []

    async def authorize_list(
        self,
        request: CheckoutListAuthorizationRequest,
        context: SecurityContext,
    ) -> None:
        del request, context
        raise AssertionError("list authorization is not expected")

    async def authorize_read(
        self,
        request: CheckoutReadAuthorizationRequest,
        context: SecurityContext,
    ) -> None:
        del request, context
        raise AssertionError("read authorization is not expected")

    async def authorize_patch(
        self,
        request: CheckoutPatchAuthorizationRequest,
        context: SecurityContext,
    ) -> None:
        self.patch_calls.append((request, context))


class _ApprovingPatchResolver:
    def __init__(
        self,
        service: InMemoryToolApprovalService,
        approver: SecurityContext,
    ) -> None:
        self._service = service
        self._approver = approver
        self.challenges: list[ToolApprovalChallenge] = []
        self.review_logical_paths: list[str] = []
        self.review_preparation_digests: list[str] = []
        self.review_diffs: list[str] = []

    async def resolve(self, challenge: ToolApprovalChallenge) -> ToolApprovalEvidence:
        return await self._service.approve(challenge.approval_id, self._approver)

    async def resolve_prepared_patch(
        self,
        challenge: ToolApprovalChallenge,
        *,
        logical_path: str,
        preparation_digest: str,
        unified_diff: str,
    ) -> ToolApprovalEvidence:
        self.challenges.append(challenge)
        self.review_logical_paths.append(logical_path)
        self.review_preparation_digests.append(preparation_digest)
        self.review_diffs.append(unified_diff)
        return await self._service.approve(challenge.approval_id, self._approver)


class _FailingFallback:
    def __init__(self) -> None:
        self.calls = 0

    async def execute(self, *args: object, **kwargs: object) -> object:
        del args, kwargs
        self.calls += 1
        raise AssertionError("workspace.patch must not reach generic durable fallback")


class _FakeBinding:
    def __init__(self, invocation: ToolInvocationRequest, descriptor: ToolDescriptor) -> None:
        self.invocation = invocation
        self.descriptor = descriptor
        self.lease = object()
        self.external_request_digest = object()
        self.ready_calls = 0

    def require_ready(self, *, now: datetime) -> None:
        assert now == _NOW
        self.ready_calls += 1


class _BindingProvider:
    def __init__(self) -> None:
        self.binding: _FakeBinding | None = None
        self.calls = 0

    async def bind(
        self,
        invocation: ToolInvocationRequest,
        descriptor: ToolDescriptor,
        *,
        now: datetime,
    ) -> _FakeBinding:
        assert now == _NOW
        self.calls += 1
        self.binding = _FakeBinding(invocation, descriptor)
        return self.binding


class _Recorder:
    def __init__(self) -> None:
        self.terminal_calls: list[dict[str, object]] = []
        self.indeterminate_calls: list[dict[str, object]] = []
        self.terminal_checkpoint = SimpleNamespace(kind="terminal-checkpoint")

    async def prepare_model_attempt(self, *args: object, **kwargs: object) -> object:
        del args, kwargs
        raise AssertionError("generic model durable path is not expected")

    async def prepare_tool_attempt(self, *args: object, **kwargs: object) -> object:
        del args, kwargs
        raise AssertionError("generic tool durable owner is not expected")

    async def mark_started(self, *args: object, **kwargs: object) -> object:
        del args, kwargs
        raise AssertionError("generic STARTED owner is not expected")

    async def mark_indeterminate(self, *args: object, **kwargs: object) -> object:
        self.indeterminate_calls.append({"args": args, **kwargs})
        return SimpleNamespace(kind="indeterminate-checkpoint")

    async def mark_terminal(self, *args: object, **kwargs: object) -> object:
        self.terminal_calls.append({"args": args, **kwargs})
        return self.terminal_checkpoint


class _FakeGate:
    def __init__(self, binding: _FakeBinding) -> None:
        self.binding = binding
        self.attempt_id = object()
        self.started_checkpoint: object | None = None
        self.calls = 0

    async def before_submit(self) -> None:
        self.calls += 1
        assert self.calls == 1
        attempt = SimpleNamespace(
            attempt_id=self.attempt_id,
            status=ExecutionAttemptStatus.STARTED,
            tool_call_id=self.binding.invocation.call_id,
            tool_effect=self.binding.descriptor.effect,
            external_request_digest=self.binding.external_request_digest,
        )
        self.started_checkpoint = SimpleNamespace(
            agent_run_id=self.binding.invocation.run_id,
            step_id=self.binding.invocation.step_id,
            durable_run_id="durable-run",
            run_version="version-2",
            metadata=SimpleNamespace(active_attempt=attempt),
        )


@dataclass
class _FakeSecurityBackend:
    file_attributes_value: int = 32
    descriptor: bytes = b"rfc0039-e2e-security"
    named_stream_count_value: int = 0

    def file_attributes(self, path: str) -> int:
        assert path
        return self.file_attributes_value

    def security_descriptor(self, path: str) -> bytes:
        assert path
        return self.descriptor

    def named_stream_count(self, path: str) -> int:
        assert path
        return self.named_stream_count_value


@dataclass
class _FakePhysicalBackend:
    replace_count: int = 0
    flush_count: int = 0
    replacement_parent: Path | None = None

    def replace_file(self, target: Path, replacement: Path) -> None:
        self.replace_count += 1
        self.replacement_parent = replacement.parent
        replacement.replace(target)

    def flush_file(self, path: Path) -> None:
        assert path.exists()
        self.flush_count += 1


def _checkout(tmp_path: Path) -> tuple[RegisteredDevelopmentCheckoutAdapter, Path]:
    root = tmp_path / "checkout"
    (root / "src").mkdir(parents=True)
    target = root / "src" / "example.py"
    target.write_bytes(b"alpha\nbeta\n")
    checkout = RegisteredDevelopmentCheckoutAdapter(
        workspace_id=_WORKSPACE_ID,
        workspace_name="rfc0039-e2e",
        generation=17,
        root=root,
        read_prefixes=("src",),
        patch_prefixes=("src",),
    )
    return checkout, target


def _profile(checkout: RegisteredDevelopmentCheckoutAdapter) -> IntegratedExecutionProfile:
    return integrated_development_checkout_dogfood_profile(
        profile_id=_PROFILE_ID,
        generation=_PROFILE_GENERATION,
        agent_id=_AGENT_ID,
        data_flow_policy=IntegratedDataFlowPolicy(),
        registration=checkout.registration,
        durability_profile="rfc0039-e2e",
        allow_workspace_patch=True,
    ).execution_profile


def _context() -> SecurityContext:
    return SecurityContext(
        principal="operator-rfc0039-e2e",
        principal_type=PrincipalType.USER,
        authenticated=True,
        permissions=frozenset({"tool.invoke", "workspace.patch"}),
    )


async def _request(
    checkout: RegisteredDevelopmentCheckoutAdapter,
    resolved_resource: str,
) -> ToolInvocationRequest:
    read_result = await checkout.read("src/example.py", run_id=_RUN_ID)
    snapshot = read_result.snapshot
    arguments: dict[str, AgentJsonInput] = {
        "logical_path": snapshot.logical_path,
        "snapshot": {
            "run_id": str(snapshot.run_id),
            "workspace_id": str(snapshot.workspace_id),
            "registration_generation": snapshot.registration_generation,
            "logical_path": snapshot.logical_path,
            "root_identity": snapshot.root_identity,
            "file_identity": snapshot.file_identity,
            "content_digest": snapshot.content_digest,
            "byte_length": snapshot.byte_length,
        },
        "base_content_digest": snapshot.content_digest,
        "edits": [
            {
                "start_byte": 6,
                "end_byte": 10,
                "expected_text": "beta",
                "replacement_text": "gamma",
            }
        ],
    }
    return ToolInvocationRequest(
        agent_id=_AGENT_ID,
        run_id=_RUN_ID,
        step_id=_STEP_ID,
        call_id=_CALL_ID,
        tool_id=CHECKOUT_PATCH_TOOL_ID,
        arguments=arguments,
        resolved_resource=resolved_resource,
        created_at=_NOW,
        deadline=_NOW + timedelta(minutes=1),
    )


@pytest.mark.asyncio
async def test_patch_runtime_specialized_driver_applies_real_effect(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkout, target = _checkout(tmp_path)
    authorizer = _RecordingAuthorizer()
    profile = _profile(checkout)
    patch_binding = profile.require_tool_binding(CHECKOUT_PATCH_TOOL_ID)
    assert isinstance(patch_binding, IntegratedDownstreamBridgeBinding)

    registration = integrated_checkout_patch_tool_registration(
        patch_binding,
        checkout,
        authorizer,
    )
    adapter = registration.adapter
    descriptor = registration.descriptor
    resolver = registration.resolver
    assert descriptor.metadata["durable_dispatch"] == "specialized"

    request = await _request(checkout, resolver.resolve_resource({}))
    fallback = _FailingFallback()
    binding_provider = _BindingProvider()
    recorder = _Recorder()
    approval_service = InMemoryToolApprovalService(clock=lambda: _NOW)
    approval_resolver = _ApprovingPatchResolver(approval_service, _context())
    execution_driver = CheckoutPatchDurableToolExecutionDriver(
        fallback=cast(AgentToolExecutionDriver, fallback),
        binding_provider=cast(DurableToolBindingProvider, binding_provider),
        recorder=cast(DurableExecutionAttemptRecorder, recorder),
        approval_service=approval_service,
        approval_resolver=approval_resolver,
        lease_keepalive_factory=None,
        clock=lambda: _NOW,
    )

    security_backend = _FakeSecurityBackend()
    physical_backend = _FakePhysicalBackend()

    def observe_security(path: Path) -> CheckoutPatchSecurityMetadata:
        return security_module.observe_checkout_patch_security_metadata(
            path,
            _backend=security_backend,
        )

    real_physical_commit = physical_module.commit_checkout_patch_physical
    real_prepare = prepare_checkout_patch
    prepared_patches: list[CheckoutPatchPreparation] = []

    def capture_prepare(
        registration: RegisteredDevelopmentCheckout,
        read_result: CheckoutReadResult,
        request: CheckoutPatchPreparationRequest,
        security_metadata: CheckoutPatchSecurityMetadata,
    ) -> CheckoutPatchPreparation:
        prepared = real_prepare(registration, read_result, request, security_metadata)
        prepared_patches.append(prepared)
        return prepared

    monkeypatch.setattr(driver_module, "prepare_checkout_patch", capture_prepare)

    def physical_commit(
        adapter: RegisteredDevelopmentCheckoutAdapter,
        current_read_result: CheckoutReadResult,
        preparation: CheckoutPatchPreparation,
        ticket: CheckoutPatchCommitTicket,
        *,
        run_id: AgentRunId,
        step_id: AgentStepId,
        call_id: ToolCallId,
        pre_effect_validator: Callable[[], None],
    ) -> CheckoutPatchPhysicalCommitResult:
        return real_physical_commit(
            adapter,
            current_read_result,
            preparation,
            ticket,
            run_id=run_id,
            step_id=step_id,
            call_id=call_id,
            pre_effect_validator=pre_effect_validator,
            _physical_backend=physical_backend,
            _security_backend=security_backend,
        )

    async def prepare_submission(
        binding: _FakeBinding,
        actual_recorder: object,
        **kwargs: object,
    ) -> _FakeGate:
        assert actual_recorder is recorder
        assert kwargs["now"] == _NOW
        return _FakeGate(binding)

    monkeypatch.setattr(
        driver_module,
        "observe_checkout_patch_security_metadata",
        observe_security,
    )
    monkeypatch.setattr(
        durable_module,
        "commit_checkout_patch_physical",
        physical_commit,
    )
    monkeypatch.setattr(
        durable_module,
        "prepare_durable_tool_submission",
        prepare_submission,
    )

    final_admission_calls: list[ToolFinalAdmissionContext] = []

    async def final_admission(
        details: ToolFinalAdmissionContext,
    ) -> ToolFinalAdmissionGrant:
        final_admission_calls.append(details)
        return ToolFinalAdmissionGrant()

    result = await execution_driver.execute(
        BoundedAgentExecutor(clock=lambda: _NOW),
        adapter,
        request,
        descriptor,
        _context(),
        final_admission=final_admission,
        timeout_seconds=60,
        cancellation_grace=0.1,
        cancellation=AgentCancellationToken(),
        prepare_time=_NOW,
    )

    assert result.status is ToolResultStatus.SUCCEEDED
    assert result.output is not None
    assert result.output["status"] == "applied"
    assert len(prepared_patches) == 1
    prepared = prepared_patches[0]
    assert len(approval_resolver.challenges) == 1
    challenge = approval_resolver.challenges[0]
    expected_approval_arguments = driver_module._prepared_patch_approval_arguments(prepared)
    assert challenge.argument_digest == canonical_tool_argument_digest(expected_approval_arguments)
    assert expected_approval_arguments["preparation_digest"] == result.output["preparation_digest"]
    assert approval_resolver.review_logical_paths == [result.output["logical_path"]]
    assert approval_resolver.review_preparation_digests == [result.output["preparation_digest"]]
    assert approval_resolver.review_diffs == [prepared.unified_diff]
    approval_snapshot = await approval_service.snapshot()
    assert approval_snapshot.entries == 1
    assert approval_snapshot.pending == 0
    assert approval_snapshot.approved == 0
    assert approval_snapshot.consumed == 1
    assert result.output["logical_path"] == "src/example.py"
    assert result.output["workspace_id"] == str(_WORKSPACE_ID)
    assert target.read_bytes() == b"alpha\ngamma\n"

    assert fallback.calls == 0
    assert binding_provider.calls == 1
    assert binding_provider.binding is not None
    assert binding_provider.binding.ready_calls == 1
    assert len(authorizer.patch_calls) == 1
    assert authorizer.patch_calls[0][0].logical_path == "src/example.py"

    assert len(final_admission_calls) == 1
    assert final_admission_calls[0].mutation_bytes == len(b"alpha\ngamma\n")

    assert physical_backend.replace_count == 1
    assert physical_backend.flush_count == 1
    assert physical_backend.replacement_parent == target.parent
    assert not tuple(target.parent.glob(".phoenix-patch-*.tmp"))

    assert len(recorder.terminal_calls) == 1
    assert recorder.terminal_calls[0]["status"] is ExecutionAttemptStatus.SUCCEEDED
    assert recorder.terminal_calls[0]["next_operation"] is CheckpointNextOperation.VALIDATE_RESULT
    assert recorder.indeterminate_calls == []
    assert cast(object, execution_driver.last_checkpoint) is recorder.terminal_checkpoint
