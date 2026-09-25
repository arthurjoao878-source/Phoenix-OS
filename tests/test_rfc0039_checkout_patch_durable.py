from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import cast
from uuid import UUID

import pytest

import phoenix_os.agent.checkout_patch_durable as durable
from phoenix_os.agent.checkout_patch_commit import CheckoutPatchCommitTicket
from phoenix_os.agent.checkout_patch_physical import (
    CheckoutPatchCommitIndeterminateError,
    CheckoutPatchPhysicalCommitResult,
)
from phoenix_os.agent.checkout_patch_preparation import CheckoutPatchPreparation
from phoenix_os.agent.checkout_workspace import (
    CheckoutReadResult,
    RegisteredDevelopmentCheckoutAdapter,
)
from phoenix_os.agent.contracts import AgentRunId, AgentStepId, ToolCallId
from phoenix_os.agent.durable_attempts import DurableExecutionAttemptRecorder
from phoenix_os.agent.durable_contracts import (
    CheckpointNextOperation,
    ExecutionAttemptStatus,
    IndeterminateReason,
)
from phoenix_os.agent.durable_tool import DurableToolAttemptBinding
from phoenix_os.agent.errors import AgentStateConflictError
from phoenix_os.agent.tools import ToolFinalAdmissionContext

_NOW = datetime(2026, 9, 12, 17, 0, tzinfo=UTC)
_RUN_ID = AgentRunId(UUID("20000000-0000-4000-8000-000000000002"))
_STEP_ID = AgentStepId(UUID("30000000-0000-4000-8000-000000000003"))
_CALL_ID = ToolCallId(UUID("40000000-0000-4000-8000-000000000004"))
_DIGEST_A = "sha256:" + ("a" * 64)
_DIGEST_B = "sha256:" + ("b" * 64)
_DIGEST_C = "sha256:" + ("c" * 64)
_DIGEST_D = "sha256:" + ("d" * 64)


class _FakeBinding:
    def __init__(self, events: list[str]) -> None:
        self.invocation = SimpleNamespace(
            run_id=_RUN_ID,
            step_id=_STEP_ID,
            call_id=_CALL_ID,
        )
        self.descriptor = SimpleNamespace(effect=object())
        self.external_request_digest = object()
        self.lease = object()
        self.events = events

    def require_ready(self, *, now: datetime) -> None:
        assert now == _NOW
        self.events.append("binding-ready")


class _FakeGate:
    def __init__(self, binding: _FakeBinding, events: list[str], *, expose_started: bool = True):
        self.binding = binding
        self.events = events
        self.attempt_id = "attempt"
        self.expose_started = expose_started
        self.started_checkpoint: SimpleNamespace | None = None

    async def before_submit(self) -> None:
        await asyncio.sleep(0)
        self.events.append("started")
        if not self.expose_started:
            return
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


class _FakeRecorder:
    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.terminal_calls: list[dict[str, object]] = []
        self.indeterminate_calls: list[dict[str, object]] = []

    async def mark_terminal(self, *args: object, **kwargs: object) -> object:
        await asyncio.sleep(0)
        self.events.append("terminal")
        self.terminal_calls.append({"args": args, **kwargs})
        return SimpleNamespace(kind="terminal-checkpoint")

    async def mark_indeterminate(self, *args: object, **kwargs: object) -> object:
        await asyncio.sleep(0)
        self.events.append("indeterminate")
        self.indeterminate_calls.append({"args": args, **kwargs})
        return SimpleNamespace(kind="indeterminate-checkpoint")


def _physical_result() -> CheckoutPatchPhysicalCommitResult:
    return CheckoutPatchPhysicalCommitResult(
        workspace_id=UUID("10000000-0000-4000-8000-000000000001"),
        logical_path="src/example.py",
        before_content_digest=_DIGEST_A,
        after_content_digest=_DIGEST_B,
        preparation_digest=_DIGEST_C,
        security_metadata_fingerprint=_DIGEST_D,
        changed_line_count=1,
        status="applied",
    )


def _install_fake_prepare(
    monkeypatch: pytest.MonkeyPatch,
    binding: _FakeBinding,
    recorder: _FakeRecorder,
    events: list[str],
    *,
    expose_started: bool = True,
) -> None:
    async def fake_prepare(
        actual_binding: object,
        actual_recorder: object,
        **kwargs: object,
    ) -> _FakeGate:
        await asyncio.sleep(0)
        assert actual_binding is binding
        assert actual_recorder is recorder
        assert kwargs["now"] == _NOW
        events.append("prepared")
        return _FakeGate(binding, events, expose_started=expose_started)

    monkeypatch.setattr(durable, "prepare_durable_tool_submission", fake_prepare)


def _typed_commit_dependencies(
    binding: _FakeBinding,
    recorder: _FakeRecorder,
) -> tuple[
    DurableToolAttemptBinding,
    DurableExecutionAttemptRecorder,
    RegisteredDevelopmentCheckoutAdapter,
    CheckoutReadResult,
    CheckoutPatchPreparation,
    CheckoutPatchCommitTicket,
]:
    return (
        cast(DurableToolAttemptBinding, binding),
        cast(DurableExecutionAttemptRecorder, recorder),
        cast(RegisteredDevelopmentCheckoutAdapter, object()),
        cast(CheckoutReadResult, object()),
        cast(CheckoutPatchPreparation, object()),
        cast(CheckoutPatchCommitTicket, object()),
    )


@pytest.mark.asyncio
async def test_durable_patch_persists_prepared_and_started_before_physical_effect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    binding = _FakeBinding(events)
    recorder = _FakeRecorder(events)
    _install_fake_prepare(monkeypatch, binding, recorder, events)

    def fake_physical(*args: object, **kwargs: object) -> CheckoutPatchPhysicalCommitResult:
        events.append("physical-enter")
        validator = kwargs["pre_effect_validator"]
        assert callable(validator)
        validator()
        events.append("physical-effect")
        return _physical_result()

    monkeypatch.setattr(durable, "commit_checkout_patch_physical", fake_physical)

    result, checkpoint = await durable.commit_checkout_patch_durable(
        *_typed_commit_dependencies(binding, recorder),
        run_id=_RUN_ID,
        step_id=_STEP_ID,
        call_id=_CALL_ID,
        prepare_time=_NOW,
        physical_pre_effect_validator=lambda: events.append("final-admission"),
        clock=lambda: _NOW,
    )

    assert result == _physical_result()
    assert cast(SimpleNamespace, checkpoint).kind == "terminal-checkpoint"
    assert events == [
        "prepared",
        "started",
        "physical-enter",
        "binding-ready",
        "final-admission",
        "physical-effect",
        "terminal",
    ]
    assert recorder.terminal_calls[0]["status"] is ExecutionAttemptStatus.SUCCEEDED
    assert recorder.terminal_calls[0]["next_operation"] is CheckpointNextOperation.VALIDATE_RESULT
    assert recorder.indeterminate_calls == []


@pytest.mark.asyncio
async def test_durable_patch_marks_indeterminate_without_retry_after_possible_effect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    binding = _FakeBinding(events)
    recorder = _FakeRecorder(events)
    _install_fake_prepare(monkeypatch, binding, recorder, events)
    physical_calls = 0

    def fake_physical(*args: object, **kwargs: object) -> CheckoutPatchPhysicalCommitResult:
        nonlocal physical_calls
        physical_calls += 1
        raise CheckoutPatchCommitIndeterminateError(
            logical_path="src/example.py",
            before_content_digest=_DIGEST_A,
            after_content_digest=_DIGEST_B,
            preparation_digest=_DIGEST_C,
        )

    monkeypatch.setattr(durable, "commit_checkout_patch_physical", fake_physical)

    with pytest.raises(CheckoutPatchCommitIndeterminateError):
        await durable.commit_checkout_patch_durable(
            *_typed_commit_dependencies(binding, recorder),
            run_id=_RUN_ID,
            step_id=_STEP_ID,
            call_id=_CALL_ID,
            prepare_time=_NOW,
            physical_pre_effect_validator=lambda: None,
            clock=lambda: _NOW,
        )

    assert physical_calls == 1
    assert recorder.terminal_calls == []
    assert len(recorder.indeterminate_calls) == 1
    assert recorder.indeterminate_calls[0]["reason"] is IndeterminateReason.TOOL_STATUS_UNKNOWN
    assert events == ["prepared", "started", "indeterminate"]


@pytest.mark.asyncio
async def test_durable_patch_records_known_pre_effect_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    binding = _FakeBinding(events)
    recorder = _FakeRecorder(events)
    _install_fake_prepare(monkeypatch, binding, recorder, events)

    def fake_physical(*args: object, **kwargs: object) -> CheckoutPatchPhysicalCommitResult:
        raise AgentStateConflictError()

    monkeypatch.setattr(durable, "commit_checkout_patch_physical", fake_physical)

    with pytest.raises(AgentStateConflictError):
        await durable.commit_checkout_patch_durable(
            *_typed_commit_dependencies(binding, recorder),
            run_id=_RUN_ID,
            step_id=_STEP_ID,
            call_id=_CALL_ID,
            prepare_time=_NOW,
            physical_pre_effect_validator=lambda: None,
            clock=lambda: _NOW,
        )

    assert len(recorder.terminal_calls) == 1
    assert recorder.terminal_calls[0]["status"] is ExecutionAttemptStatus.FAILED
    assert recorder.terminal_calls[0]["error_code"] == "workspace_patch_pre_effect_failed"
    assert recorder.indeterminate_calls == []
    assert events == ["prepared", "started", "terminal"]


@pytest.mark.asyncio
async def test_durable_patch_requires_started_checkpoint_before_physical_effect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    binding = _FakeBinding(events)
    recorder = _FakeRecorder(events)
    _install_fake_prepare(
        monkeypatch,
        binding,
        recorder,
        events,
        expose_started=False,
    )
    physical_calls = 0

    def fake_physical(*args: object, **kwargs: object) -> CheckoutPatchPhysicalCommitResult:
        nonlocal physical_calls
        physical_calls += 1
        return _physical_result()

    monkeypatch.setattr(durable, "commit_checkout_patch_physical", fake_physical)

    with pytest.raises(AgentStateConflictError):
        await durable.commit_checkout_patch_durable(
            *_typed_commit_dependencies(binding, recorder),
            run_id=_RUN_ID,
            step_id=_STEP_ID,
            call_id=_CALL_ID,
            prepare_time=_NOW,
            physical_pre_effect_validator=lambda: None,
            clock=lambda: _NOW,
        )

    assert physical_calls == 0
    assert recorder.terminal_calls == []
    assert recorder.indeterminate_calls == []
    assert events == ["prepared", "started"]


@pytest.mark.asyncio
async def test_durable_patch_runs_async_final_admission_after_started_before_physical(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    binding = _FakeBinding(events)
    recorder = _FakeRecorder(events)
    _install_fake_prepare(monkeypatch, binding, recorder, events)

    async def final_admission(details: ToolFinalAdmissionContext) -> None:
        assert details.mutation_bytes == 11
        events.append("async-final-admission")

    def fake_physical(*args: object, **kwargs: object) -> CheckoutPatchPhysicalCommitResult:
        events.append("physical-enter")
        validator = kwargs["pre_effect_validator"]
        assert callable(validator)
        validator()
        events.append("physical-effect")
        return _physical_result()

    monkeypatch.setattr(durable, "commit_checkout_patch_physical", fake_physical)

    result, checkpoint = await durable.commit_checkout_patch_durable(
        *_typed_commit_dependencies(binding, recorder),
        run_id=_RUN_ID,
        step_id=_STEP_ID,
        call_id=_CALL_ID,
        prepare_time=_NOW,
        physical_pre_effect_validator=lambda: events.append("physical-pre-effect"),
        final_admission=final_admission,
        mutation_bytes=11,
        clock=lambda: _NOW,
    )

    assert result == _physical_result()
    assert cast(SimpleNamespace, checkpoint).kind == "terminal-checkpoint"
    assert events == [
        "prepared",
        "started",
        "async-final-admission",
        "physical-enter",
        "binding-ready",
        "physical-pre-effect",
        "physical-effect",
        "terminal",
    ]
