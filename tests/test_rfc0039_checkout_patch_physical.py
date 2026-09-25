from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from uuid import UUID

import pytest

from phoenix_os.agent.checkout_patch_commit import (
    CheckoutPatchCommitTicket,
    revalidate_checkout_patch_commit,
)
from phoenix_os.agent.checkout_patch_physical import (
    CheckoutPatchCommitIndeterminateError,
    commit_checkout_patch_physical,
)
from phoenix_os.agent.checkout_patch_preparation import (
    CheckoutPatchEdit,
    CheckoutPatchPreparation,
    CheckoutPatchPreparationRequest,
    prepare_checkout_patch,
)
from phoenix_os.agent.checkout_patch_security import (
    observe_checkout_patch_security_metadata,
)
from phoenix_os.agent.checkout_workspace import (
    CheckoutReadResult,
    RegisteredDevelopmentCheckoutAdapter,
)
from phoenix_os.agent.contracts import AgentRunId, AgentStepId, ToolCallId
from phoenix_os.agent.errors import AgentStateConflictError

_WORKSPACE_ID = UUID("10000000-0000-4000-8000-000000000001")
_RUN_ID = AgentRunId(UUID("20000000-0000-4000-8000-000000000002"))
_STEP_ID = AgentStepId(UUID("30000000-0000-4000-8000-000000000003"))
_CALL_ID = ToolCallId(UUID("40000000-0000-4000-8000-000000000004"))


@dataclass
class _FakeSecurityBackend:
    file_attributes_value: int = 32
    descriptor: bytes = b"descriptor-bytes"
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
    corrupt_after_replace: bool = False
    replacement_parent: Path | None = None
    replace_count: int = 0
    flush_count: int = 0

    def replace_file(self, target: Path, replacement: Path) -> None:
        self.replace_count += 1
        self.replacement_parent = replacement.parent
        replacement.replace(target)
        if self.corrupt_after_replace:
            target.write_bytes(b"corrupted\n")

    def flush_file(self, path: Path) -> None:
        assert path.exists()
        self.flush_count += 1


def _adapter(root: Path) -> RegisteredDevelopmentCheckoutAdapter:
    return RegisteredDevelopmentCheckoutAdapter(
        workspace_id=_WORKSPACE_ID,
        workspace_name="project",
        generation=7,
        root=root,
        read_prefixes=("src",),
        patch_prefixes=("src",),
    )


async def _prepared(
    tmp_path: Path,
    *,
    security_backend: _FakeSecurityBackend,
) -> tuple[
    RegisteredDevelopmentCheckoutAdapter,
    Path,
    CheckoutReadResult,
    CheckoutPatchPreparation,
    CheckoutPatchCommitTicket,
]:
    root = tmp_path / "checkout"
    (root / "src").mkdir(parents=True)
    target = root / "src" / "example.py"
    target.write_text("alpha\nbeta\n", encoding="utf-8")

    adapter = _adapter(root)
    current = await adapter.read("src/example.py", run_id=_RUN_ID)
    security = observe_checkout_patch_security_metadata(
        target,
        _backend=security_backend,
    )
    start = current.text.encode("utf-8").index(b"beta")
    request = CheckoutPatchPreparationRequest(
        run_id=_RUN_ID,
        step_id=_STEP_ID,
        call_id=_CALL_ID,
        snapshot=current.snapshot,
        base_content_digest=current.snapshot.content_digest,
        edits=(
            CheckoutPatchEdit(
                start_byte=start,
                end_byte=start + len(b"beta"),
                expected_text="beta",
                replacement_text="delta",
            ),
        ),
    )
    preparation = prepare_checkout_patch(
        adapter.registration,
        current,
        request,
        security,
    )
    ticket = revalidate_checkout_patch_commit(
        adapter.registration,
        current,
        preparation,
        security_metadata=security,
        run_id=_RUN_ID,
        step_id=_STEP_ID,
        call_id=_CALL_ID,
    )
    return adapter, target, current, preparation, ticket


@pytest.mark.asyncio
async def test_physical_commit_applies_exact_candidate_and_is_content_free(
    tmp_path: Path,
) -> None:
    security_backend = _FakeSecurityBackend()
    physical_backend = _FakePhysicalBackend()
    adapter, target, current, preparation, ticket = await _prepared(
        tmp_path,
        security_backend=security_backend,
    )
    validator_calls = 0

    def validate() -> None:
        nonlocal validator_calls
        validator_calls += 1

    result = commit_checkout_patch_physical(
        adapter,
        current,
        preparation,
        ticket,
        run_id=_RUN_ID,
        step_id=_STEP_ID,
        call_id=_CALL_ID,
        pre_effect_validator=validate,
        _physical_backend=physical_backend,
        _security_backend=security_backend,
    )

    assert target.read_text(encoding="utf-8") == "alpha\ndelta\n"
    assert result.status == "applied"
    assert result.before_content_digest == ticket.before_content_digest
    assert result.after_content_digest == ticket.after_content_digest
    assert result.preparation_digest == ticket.preparation_digest
    assert "alpha" not in repr(result)
    assert "delta" not in repr(result)
    assert validator_calls == 1
    assert physical_backend.replace_count == 1
    assert physical_backend.flush_count == 1
    assert physical_backend.replacement_parent == target.parent
    assert not tuple(target.parent.glob(".phoenix-patch-*.tmp"))


@pytest.mark.asyncio
async def test_physical_commit_rejects_stale_disk_before_effect(tmp_path: Path) -> None:
    security_backend = _FakeSecurityBackend()
    physical_backend = _FakePhysicalBackend()
    adapter, target, current, preparation, ticket = await _prepared(
        tmp_path,
        security_backend=security_backend,
    )
    target.write_text("alpha\nchanged\n", encoding="utf-8")

    with pytest.raises(AgentStateConflictError):
        commit_checkout_patch_physical(
            adapter,
            current,
            preparation,
            ticket,
            run_id=_RUN_ID,
            step_id=_STEP_ID,
            call_id=_CALL_ID,
            pre_effect_validator=lambda: None,
            _physical_backend=physical_backend,
            _security_backend=security_backend,
        )

    assert physical_backend.replace_count == 0
    assert target.read_text(encoding="utf-8") == "alpha\nchanged\n"
    assert not tuple(target.parent.glob(".phoenix-patch-*.tmp"))


@pytest.mark.asyncio
async def test_physical_commit_revalidates_security_metadata_before_effect(
    tmp_path: Path,
) -> None:
    security_backend = _FakeSecurityBackend()
    physical_backend = _FakePhysicalBackend()
    adapter, target, current, preparation, ticket = await _prepared(
        tmp_path,
        security_backend=security_backend,
    )
    security_backend.file_attributes_value = 33

    with pytest.raises(ValueError, match="security metadata changed"):
        commit_checkout_patch_physical(
            adapter,
            current,
            preparation,
            ticket,
            run_id=_RUN_ID,
            step_id=_STEP_ID,
            call_id=_CALL_ID,
            pre_effect_validator=lambda: None,
            _physical_backend=physical_backend,
            _security_backend=security_backend,
        )

    assert physical_backend.replace_count == 0
    assert target.read_text(encoding="utf-8") == "alpha\nbeta\n"


@pytest.mark.asyncio
async def test_physical_commit_validator_failure_is_pre_effect_and_cleans_temp(
    tmp_path: Path,
) -> None:
    security_backend = _FakeSecurityBackend()
    physical_backend = _FakePhysicalBackend()
    adapter, target, current, preparation, ticket = await _prepared(
        tmp_path,
        security_backend=security_backend,
    )

    def reject() -> None:
        raise RuntimeError("deadline-or-approval-stale")

    with pytest.raises(RuntimeError, match="deadline-or-approval-stale"):
        commit_checkout_patch_physical(
            adapter,
            current,
            preparation,
            ticket,
            run_id=_RUN_ID,
            step_id=_STEP_ID,
            call_id=_CALL_ID,
            pre_effect_validator=reject,
            _physical_backend=physical_backend,
            _security_backend=security_backend,
        )

    assert physical_backend.replace_count == 0
    assert target.read_text(encoding="utf-8") == "alpha\nbeta\n"
    assert not tuple(target.parent.glob(".phoenix-patch-*.tmp"))


@pytest.mark.asyncio
async def test_physical_commit_post_replace_failure_is_indeterminate(
    tmp_path: Path,
) -> None:
    security_backend = _FakeSecurityBackend()
    physical_backend = _FakePhysicalBackend(corrupt_after_replace=True)
    adapter, _target, current, preparation, ticket = await _prepared(
        tmp_path,
        security_backend=security_backend,
    )

    with pytest.raises(CheckoutPatchCommitIndeterminateError) as captured:
        commit_checkout_patch_physical(
            adapter,
            current,
            preparation,
            ticket,
            run_id=_RUN_ID,
            step_id=_STEP_ID,
            call_id=_CALL_ID,
            pre_effect_validator=lambda: None,
            _physical_backend=physical_backend,
            _security_backend=security_backend,
        )

    assert physical_backend.replace_count == 1
    assert captured.value.before_content_digest == ticket.before_content_digest
    assert captured.value.after_content_digest == ticket.after_content_digest
    assert captured.value.preparation_digest == ticket.preparation_digest
    assert "alpha" not in str(captured.value)
    assert "delta" not in str(captured.value)


@pytest.mark.asyncio
@pytest.mark.skipif(os.name != "nt", reason="Windows ReplaceFileW physical commit")
async def test_windows_physical_commit_replaces_real_temp_file(tmp_path: Path) -> None:
    root = tmp_path / "checkout"
    (root / "src").mkdir(parents=True)
    target = root / "src" / "example.py"
    target.write_text("alpha\nbeta\n", encoding="utf-8")

    adapter = _adapter(root)
    current = await adapter.read("src/example.py", run_id=_RUN_ID)
    security = observe_checkout_patch_security_metadata(target)
    start = current.text.encode("utf-8").index(b"beta")
    request = CheckoutPatchPreparationRequest(
        run_id=_RUN_ID,
        step_id=_STEP_ID,
        call_id=_CALL_ID,
        snapshot=current.snapshot,
        base_content_digest=current.snapshot.content_digest,
        edits=(
            CheckoutPatchEdit(
                start_byte=start,
                end_byte=start + len(b"beta"),
                expected_text="beta",
                replacement_text="delta",
            ),
        ),
    )
    preparation = prepare_checkout_patch(
        adapter.registration,
        current,
        request,
        security,
    )
    ticket = revalidate_checkout_patch_commit(
        adapter.registration,
        current,
        preparation,
        security_metadata=security,
        run_id=_RUN_ID,
        step_id=_STEP_ID,
        call_id=_CALL_ID,
    )

    result = commit_checkout_patch_physical(
        adapter,
        current,
        preparation,
        ticket,
        run_id=_RUN_ID,
        step_id=_STEP_ID,
        call_id=_CALL_ID,
        pre_effect_validator=lambda: None,
    )

    assert result.status == "applied"
    assert target.read_text(encoding="utf-8") == "alpha\ndelta\n"
    after_security = observe_checkout_patch_security_metadata(target)
    assert after_security.fingerprint == ticket.security_metadata_fingerprint
    assert not tuple(target.parent.glob(".phoenix-patch-*.tmp"))
