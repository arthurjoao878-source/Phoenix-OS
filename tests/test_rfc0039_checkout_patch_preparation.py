from __future__ import annotations

import hashlib
from uuid import UUID

import pytest

import phoenix_os.agent.checkout_patch_preparation as patch_preparation
from phoenix_os.agent.checkout_patch_preparation import (
    MAX_CHECKOUT_PATCH_AFFECTED_LINES,
    MAX_CHECKOUT_PATCH_DIFF_BYTES,
    MAX_CHECKOUT_PATCH_REPLACEMENT_BYTES,
    MAX_CHECKOUT_PATCH_REQUEST_BYTES,
    MAX_CHECKOUT_PATCH_TARGET_BYTES,
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
_ROOT_DIGEST = "sha256:" + ("1" * 64)
_FILE_DIGEST = "sha256:" + ("2" * 64)


def _digest(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _security_metadata() -> CheckoutPatchSecurityMetadata:
    return bind_checkout_patch_security_metadata(
        file_attributes=32,
        security_descriptor_digest="sha256:" + ("a" * 64),
        named_stream_count=0,
        link_count=1,
    )


def _registration(
    *,
    patch_prefixes: tuple[str, ...] = ("src",),
) -> RegisteredDevelopmentCheckout:
    return RegisteredDevelopmentCheckout(
        workspace_id=_WORKSPACE_ID,
        workspace_name="project",
        generation=7,
        root_identity=_ROOT_DIGEST,
        read_prefixes=("src", "tests"),
        patch_prefixes=patch_prefixes,
    )


def _read_result(
    text: str,
    *,
    logical_path: str = "src/example.py",
) -> CheckoutReadResult:
    payload = text.encode("utf-8")
    return CheckoutReadResult(
        snapshot=CheckoutFileSnapshot(
            run_id=_RUN_ID,
            workspace_id=_WORKSPACE_ID,
            registration_generation=7,
            logical_path=logical_path,
            root_identity=_ROOT_DIGEST,
            file_identity=_FILE_DIGEST,
            content_digest=_digest(payload),
            byte_length=len(payload),
        ),
        text=text,
    )


def _request(
    read_result: CheckoutReadResult,
    edits: tuple[CheckoutPatchEdit, ...],
    *,
    base_content_digest: str | None = None,
) -> CheckoutPatchPreparationRequest:
    return CheckoutPatchPreparationRequest(
        run_id=_RUN_ID,
        step_id=_STEP_ID,
        call_id=_CALL_ID,
        snapshot=read_result.snapshot,
        base_content_digest=(
            read_result.snapshot.content_digest
            if base_content_digest is None
            else base_content_digest
        ),
        edits=edits,
    )


def _prepare(
    registration: RegisteredDevelopmentCheckout,
    read_result: CheckoutReadResult,
    request: CheckoutPatchPreparationRequest,
) -> CheckoutPatchPreparation:
    return prepare_checkout_patch(
        registration,
        read_result,
        request,
        _security_metadata(),
    )


def test_prepare_patch_is_deterministic_content_bound_and_zero_effect() -> None:
    read_result = _read_result("alpha\nbeta\ngamma\n")
    start = len(b"alpha\n")
    edit = CheckoutPatchEdit(
        start_byte=start,
        end_byte=start + len(b"beta"),
        expected_text="beta",
        replacement_text="delta",
    )
    request = _request(read_result, (edit,))

    first = _prepare(_registration(), read_result, request)
    second = _prepare(_registration(), read_result, request)

    assert first == second
    assert first.candidate_bytes == b"alpha\ndelta\ngamma\n"
    assert first.before_content_digest == read_result.snapshot.content_digest
    assert first.after_content_digest == _digest(first.candidate_bytes)
    assert first.preparation_digest == second.preparation_digest
    assert first.security_metadata_fingerprint == _security_metadata().fingerprint
    assert first.changed_line_count == 1
    assert "--- a/src/example.py" in first.unified_diff
    assert "+++ b/src/example.py" in first.unified_diff
    assert "-beta" in first.unified_diff
    assert "+delta" in first.unified_diff


def test_trusted_diff_over_display_bound_is_rejected_not_truncated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    read_result = _read_result("old\n")
    edit = CheckoutPatchEdit(0, 3, "old", "new")
    oversized_diff = "x" * (MAX_CHECKOUT_PATCH_DIFF_BYTES + 1)
    monkeypatch.setattr(
        patch_preparation,
        "_trusted_unified_diff",
        lambda **_: oversized_diff,
    )

    with pytest.raises(ValueError, match="patch trusted diff exceeds supported bound"):
        _prepare(
            _registration(),
            read_result,
            _request(read_result, (edit,)),
        )


def test_prepare_patch_requires_exact_snapshot_base_and_patch_prefix() -> None:
    read_result = _read_result("old\n")
    edit = CheckoutPatchEdit(0, 3, "old", "new")

    with pytest.raises(ValueError, match="base content digest is stale"):
        _prepare(
            _registration(),
            read_result,
            _request(read_result, (edit,), base_content_digest="sha256:" + ("0" * 64)),
        )

    substituted = _read_result("old\n", logical_path="tests/example.py")
    with pytest.raises(ValueError, match="outside patch_prefixes"):
        _prepare(
            _registration(),
            substituted,
            _request(substituted, (edit,)),
        )

    other = _read_result("different\n")
    with pytest.raises(ValueError, match="snapshot is stale or substituted"):
        _prepare(
            _registration(),
            read_result,
            CheckoutPatchPreparationRequest(
                run_id=_RUN_ID,
                step_id=_STEP_ID,
                call_id=_CALL_ID,
                snapshot=other.snapshot,
                base_content_digest=other.snapshot.content_digest,
                edits=(edit,),
            ),
        )


def test_edit_order_overlap_and_utf8_boundaries_fail_closed() -> None:
    with pytest.raises(ValueError, match="strictly ordered"):
        CheckoutPatchPreparationRequest(
            run_id=_RUN_ID,
            step_id=_STEP_ID,
            call_id=_CALL_ID,
            snapshot=_read_result("abcdef").snapshot,
            base_content_digest=_read_result("abcdef").snapshot.content_digest,
            edits=(
                CheckoutPatchEdit(3, 4, "d", "x"),
                CheckoutPatchEdit(1, 2, "b", "y"),
            ),
        )

    with pytest.raises(ValueError, match="must not overlap"):
        CheckoutPatchPreparationRequest(
            run_id=_RUN_ID,
            step_id=_STEP_ID,
            call_id=_CALL_ID,
            snapshot=_read_result("abcdef").snapshot,
            base_content_digest=_read_result("abcdef").snapshot.content_digest,
            edits=(
                CheckoutPatchEdit(1, 4, "bcd", "x"),
                CheckoutPatchEdit(3, 5, "de", "y"),
            ),
        )

    read_result = _read_result("a\u03b2c")
    with pytest.raises(ValueError, match="codepoint aligned"):
        _prepare(
            _registration(),
            read_result,
            _request(
                read_result,
                (CheckoutPatchEdit(2, 3, "", "x"),),
            ),
        )


def test_expected_old_text_bom_and_nul_are_rejected() -> None:
    read_result = _read_result("alpha")
    with pytest.raises(ValueError, match="expected old text"):
        _prepare(
            _registration(),
            read_result,
            _request(read_result, (CheckoutPatchEdit(0, 5, "other", "new"),)),
        )

    bom_result = _read_result("\ufeffalpha")
    with pytest.raises(ValueError, match="without BOM"):
        _prepare(
            _registration(),
            bom_result,
            _request(
                bom_result,
                (CheckoutPatchEdit(3, 8, "alpha", "new"),),
            ),
        )

    with pytest.raises(ValueError, match="cannot contain NUL"):
        CheckoutPatchEdit(0, 1, "a", "b\x00c")


def test_request_replacement_candidate_and_affected_line_limits_fail_closed() -> None:
    read_result = _read_result("x")
    with pytest.raises(ValueError, match="replacement_text exceeds"):
        CheckoutPatchEdit(
            0,
            1,
            "x",
            "y" * (MAX_CHECKOUT_PATCH_REPLACEMENT_BYTES + 1),
        )

    with pytest.raises(ValueError, match="request exceeds"):
        _request(
            _read_result("x" * MAX_CHECKOUT_PATCH_REQUEST_BYTES),
            (
                CheckoutPatchEdit(
                    0,
                    MAX_CHECKOUT_PATCH_REQUEST_BYTES,
                    "x" * MAX_CHECKOUT_PATCH_REQUEST_BYTES,
                    "y",
                ),
            ),
        )

    many_lines = "\n" * MAX_CHECKOUT_PATCH_AFFECTED_LINES
    with pytest.raises(ValueError, match="affected-line count"):
        _prepare(
            _registration(),
            read_result,
            _request(
                read_result,
                (CheckoutPatchEdit(0, 1, "x", many_lines),),
            ),
        )

    near_limit = "x" * MAX_CHECKOUT_PATCH_TARGET_BYTES
    near_limit_result = _read_result(near_limit)
    with pytest.raises(ValueError, match="candidate exceeds"):
        _prepare(
            _registration(),
            near_limit_result,
            _request(
                near_limit_result,
                (CheckoutPatchEdit(0, 0, "", "y"),),
            ),
        )


def test_preparation_digest_binds_edit_without_persisting_raw_source() -> None:
    read_result = _read_result("secret-old-value\n")
    edit = CheckoutPatchEdit(
        0,
        len(b"secret-old-value"),
        "secret-old-value",
        "secret-new-value",
    )
    prepared = _prepare(
        _registration(),
        read_result,
        _request(read_result, (edit,)),
    )

    assert prepared.preparation_digest.startswith("sha256:")
    assert "secret-old-value" not in prepared.preparation_digest
    assert "secret-new-value" not in prepared.preparation_digest
    assert "secret-old-value" in prepared.unified_diff
    assert "secret-new-value" in prepared.unified_diff
