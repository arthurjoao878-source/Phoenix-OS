from __future__ import annotations

import hashlib
from dataclasses import replace
from uuid import UUID

import pytest

from phoenix_os.agent.checkout_patch_commit import (
    CheckoutPatchCommitTicket,
    revalidate_checkout_patch_commit,
)
from phoenix_os.agent.checkout_patch_preparation import (
    CheckoutPatchEdit,
    CheckoutPatchPreparation,
    CheckoutPatchPreparationRequest,
    prepare_checkout_patch,
)
from phoenix_os.agent.checkout_patch_security import (
    CheckoutPatchSecurityMetadata,
    bind_checkout_patch_security_metadata,
)
from phoenix_os.agent.checkout_workspace import (
    CheckoutFileSnapshot,
    CheckoutReadResult,
    RegisteredDevelopmentCheckout,
)
from phoenix_os.agent.contracts import AgentRunId, AgentStepId, ToolCallId

_WORKSPACE_ID = UUID("10000000-0000-4000-8000-000000000001")
_RUN_ID = AgentRunId(UUID("20000000-0000-4000-8000-000000000002"))
_STEP_ID = AgentStepId(UUID("30000000-0000-4000-8000-000000000003"))
_CALL_ID = ToolCallId(UUID("40000000-0000-4000-8000-000000000004"))
_OTHER_CALL_ID = ToolCallId(UUID("40000000-0000-4000-8000-000000000005"))
_ROOT_DIGEST = "sha256:" + ("1" * 64)
_FILE_DIGEST = "sha256:" + ("2" * 64)
_OTHER_FILE_DIGEST = "sha256:" + ("3" * 64)


def _digest(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _security_metadata(*, file_attributes: int = 32) -> CheckoutPatchSecurityMetadata:
    return bind_checkout_patch_security_metadata(
        file_attributes=file_attributes,
        security_descriptor_digest="sha256:" + ("a" * 64),
        named_stream_count=0,
        link_count=1,
    )


def _registration(
    *,
    generation: int = 7,
    patch_prefixes: tuple[str, ...] = ("src",),
) -> RegisteredDevelopmentCheckout:
    return RegisteredDevelopmentCheckout(
        workspace_id=_WORKSPACE_ID,
        workspace_name="project",
        generation=generation,
        root_identity=_ROOT_DIGEST,
        read_prefixes=("src", "tests"),
        patch_prefixes=patch_prefixes,
    )


def _read_result(
    text: str,
    *,
    logical_path: str = "src/example.py",
    run_id: AgentRunId = _RUN_ID,
    generation: int = 7,
    root_identity: str = _ROOT_DIGEST,
    file_identity: str = _FILE_DIGEST,
) -> CheckoutReadResult:
    payload = text.encode("utf-8")
    return CheckoutReadResult(
        snapshot=CheckoutFileSnapshot(
            run_id=run_id,
            workspace_id=_WORKSPACE_ID,
            registration_generation=generation,
            logical_path=logical_path,
            root_identity=root_identity,
            file_identity=file_identity,
            content_digest=_digest(payload),
            byte_length=len(payload),
        ),
        text=text,
    )


def _prepared(
    text: str = "alpha\nbeta\n",
) -> tuple[CheckoutReadResult, CheckoutPatchPreparation]:
    read_result = _read_result(text)
    start = len(b"alpha\n")
    request = CheckoutPatchPreparationRequest(
        run_id=_RUN_ID,
        step_id=_STEP_ID,
        call_id=_CALL_ID,
        snapshot=read_result.snapshot,
        base_content_digest=read_result.snapshot.content_digest,
        edits=(
            CheckoutPatchEdit(
                start_byte=start,
                end_byte=start + len(b"beta"),
                expected_text="beta",
                replacement_text="delta",
            ),
        ),
    )
    return read_result, prepare_checkout_patch(
        _registration(),
        read_result,
        request,
        _security_metadata(),
    )


def _revalidate(
    current: CheckoutReadResult,
    preparation: CheckoutPatchPreparation,
) -> CheckoutPatchCommitTicket:
    return revalidate_checkout_patch_commit(
        _registration(),
        current,
        preparation,
        security_metadata=_security_metadata(),
        run_id=_RUN_ID,
        step_id=_STEP_ID,
        call_id=_CALL_ID,
    )


def test_commit_preflight_is_deterministic_content_free_and_zero_effect() -> None:
    current, preparation = _prepared()

    first = _revalidate(current, preparation)
    second = _revalidate(current, preparation)

    assert first == second
    assert first.logical_path == "src/example.py"
    assert first.before_content_digest == current.snapshot.content_digest
    assert first.after_content_digest == preparation.after_content_digest
    assert first.preparation_digest == preparation.preparation_digest
    assert first.security_metadata_fingerprint == preparation.security_metadata_fingerprint
    assert first.current_byte_length == len(current.text.encode("utf-8"))
    assert first.freshness_digest.startswith("sha256:")
    assert "alpha" not in repr(first)
    assert "beta" not in repr(first)
    assert "delta" not in repr(first)


def test_commit_preflight_rejects_stale_content_file_identity_and_registration() -> None:
    current, preparation = _prepared()

    changed = _read_result("alpha\nchanged\n")
    with pytest.raises(ValueError, match="base content changed"):
        _revalidate(changed, preparation)

    replaced_file = _read_result(current.text, file_identity=_OTHER_FILE_DIGEST)
    with pytest.raises(ValueError, match="file identity changed"):
        _revalidate(replaced_file, preparation)

    with pytest.raises(ValueError, match="checkout registration changed"):
        revalidate_checkout_patch_commit(
            _registration(generation=8),
            current,
            preparation,
            security_metadata=_security_metadata(),
            run_id=_RUN_ID,
            step_id=_STEP_ID,
            call_id=_CALL_ID,
        )


def test_commit_preflight_rejects_snapshot_and_invocation_substitution() -> None:
    current, preparation = _prepared()

    substituted_path = _read_result(current.text, logical_path="src/other.py")
    with pytest.raises(ValueError, match="snapshot identity changed"):
        _revalidate(substituted_path, preparation)

    with pytest.raises(ValueError, match="invocation binding is stale"):
        revalidate_checkout_patch_commit(
            _registration(),
            current,
            preparation,
            security_metadata=_security_metadata(),
            run_id=_RUN_ID,
            step_id=_STEP_ID,
            call_id=_OTHER_CALL_ID,
        )


def test_commit_preflight_requires_current_patch_prefix_authority() -> None:
    current, preparation = _prepared()

    with pytest.raises(ValueError, match="outside patch_prefixes"):
        revalidate_checkout_patch_commit(
            _registration(patch_prefixes=("tests",)),
            current,
            preparation,
            security_metadata=_security_metadata(),
            run_id=_RUN_ID,
            step_id=_STEP_ID,
            call_id=_CALL_ID,
        )


def test_commit_preflight_rejects_security_metadata_change() -> None:
    current, preparation = _prepared()

    with pytest.raises(ValueError, match="security metadata changed"):
        revalidate_checkout_patch_commit(
            _registration(),
            current,
            preparation,
            security_metadata=_security_metadata(file_attributes=33),
            run_id=_RUN_ID,
            step_id=_STEP_ID,
            call_id=_CALL_ID,
        )


def test_commit_preflight_rejects_tampered_candidate() -> None:
    current, preparation = _prepared()
    tampered = replace(preparation, _candidate_bytes=b"alpha\nforged\n")

    with pytest.raises(ValueError, match="candidate digest changed"):
        _revalidate(current, tampered)


def test_commit_ticket_binds_preparation_and_current_snapshot_without_raw_content() -> None:
    current, preparation = _prepared("alpha\nbeta\n")
    ticket = _revalidate(current, preparation)

    assert ticket.run_id == _RUN_ID
    assert ticket.step_id == _STEP_ID
    assert ticket.call_id == _CALL_ID
    assert ticket.workspace_id == _WORKSPACE_ID
    assert ticket.registration_generation == 7
    assert ticket.root_identity == _ROOT_DIGEST
    assert ticket.file_identity == _FILE_DIGEST
    assert ticket.changed_line_count == 1
    assert ticket.freshness_digest not in {
        ticket.before_content_digest,
        ticket.after_content_digest,
        ticket.preparation_digest,
    }
