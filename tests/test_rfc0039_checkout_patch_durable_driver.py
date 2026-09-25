from __future__ import annotations

import inspect
from dataclasses import replace

import phoenix_os.agent.checkout_patch_durable as durable
import phoenix_os.agent.checkout_patch_durable_driver as driver
import phoenix_os.integrated_agent.durable_run as integrated_durable_run
from phoenix_os.agent.checkout_patch_agent_tool import checkout_patch_tool_descriptor


def test_patch_driver_never_delegates_patch_to_generic_durable_owner() -> None:
    source = inspect.getsource(driver)

    assert "execute_durable_tool(" not in source
    assert "prepare_durable_tool_submission(" not in source
    assert source.count("commit_checkout_patch_durable(") == 1
    assert "return await self._fallback.execute(" in source
    assert "mutation_bytes=len(preparation.candidate_bytes)" in source


def test_patch_durable_module_is_single_prepared_started_owner() -> None:
    source = inspect.getsource(durable)

    assert source.count("prepare_durable_tool_submission(") == 1
    assert source.count("await gate.before_submit()") == 1
    assert source.count("commit_checkout_patch_physical(") == 1
    assert "ToolFinalAdmissionContext(mutation_bytes=mutation_bytes)" in source


def test_patch_driver_requires_exact_specialized_descriptor() -> None:
    descriptor = checkout_patch_tool_descriptor()

    assert driver._is_exact_patch_descriptor(descriptor)
    tampered = replace(
        descriptor,
        metadata={
            **dict(descriptor.metadata),
            "durable_dispatch": "generic",
        },
    )
    assert not driver._is_exact_patch_descriptor(tampered)


def test_integrated_durable_run_wires_specialized_patch_driver_around_legacy_fallback() -> None:
    source = inspect.getsource(integrated_durable_run)

    assert "CheckoutPatchDurableToolExecutionDriver(" in source
    assert "StoreBackedDurableToolInvocationBindingProvider(" in source
    assert "StoreBackedDurableLeaseKeepaliveFactory(" in source
    assert "_CheckoutReadBudgetBoundToolExecutionDriver(" in source
    assert "_patch_approval_dependencies(" in source
    assert "approval_service=approval_service" in source
    assert "approval_resolver=approval_resolver" in source


def test_patch_driver_binds_and_consumes_exact_prepared_approval_before_effect() -> None:
    source = inspect.getsource(driver)

    assert "CheckoutPatchApprovalResolver" in source
    assert "_prepared_patch_approval_arguments(" in source
    assert "review_diff_digest" in source
    assert "resolve_prepared_patch(" in source
    assert "verify_and_consume(" in source
    assert source.count("_validate_consumed_prepared_patch_approval(") == 3


def test_success_result_exposes_terminal_operator_review_metadata() -> None:
    import ast
    from pathlib import Path

    source_path = (
        Path(__file__).resolve().parents[1]
        / "src"
        / "phoenix_os"
        / "agent"
        / "checkout_patch_durable_driver.py"
    )
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    candidates: list[dict[str, ast.expr]] = []
    identifying_fields = {
        "workspace_id",
        "logical_path",
        "before_content_digest",
        "after_content_digest",
        "preparation_digest",
        "changed_line_count",
        "status",
    }

    for node in ast.walk(tree):
        if not isinstance(node, ast.Dict):
            continue
        fields: dict[str, ast.expr] = {}
        for key, value in zip(node.keys, node.values, strict=True):
            if isinstance(key, ast.Constant) and isinstance(key.value, str):
                fields[key.value] = value
        if identifying_fields <= set(fields):
            candidates.append(fields)

    assert len(candidates) == 1
    fields = candidates[0]
    assert ast.literal_eval(fields["files_changed"]) == 1
    assert ast.literal_eval(fields["review_status"]) == "approved"
    assert "unified_diff" not in fields
    assert "content" not in fields
    assert "replacement_text" not in fields
