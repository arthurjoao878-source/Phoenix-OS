from __future__ import annotations

import runpy
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_GATE = _ROOT / "scripts/check_integrated_agent_release.py"
_GATE_COMMAND = "python scripts/check_integrated_agent_release.py"

_EXPECTED_REQUIREMENTS = frozenset(
    {
        "immutable_task_digest_binding",
        "agent_run_intent_profile_freshness_binding",
        "reuse_rfc0027_run_and_step_ids",
        "no_task_run_substitution",
        "no_second_capability_registry",
        "model_turn_exactly_final_or_tool_proposal",
        "plan_updates_only_reserved_tool_and_tool_invoke",
        "planner_cannot_create_authority",
        "every_exposed_tool_exact_binding",
        "dogfood_profiles_narrow_existing_authority",
        "dogfood_research_network_read_only_and_exact_browser_target",
        "dogfood_profiles_preserve_provider_neutral_semantics",
        "bridge_substitution_rejected",
        "data_flow_denied_before_approval_or_effect",
        "independent_tool_and_downstream_authority",
        "malicious_planning_fails_closed",
        "prompt_injection_cannot_manufacture_resources",
        "cross_subsystem_exfiltration_denied_before_effect",
        "final_user_result_audience_and_source_scope",
        "exact_provenance_atoms",
        "conservative_provenance_transformations",
        "no_provenance_laundering_or_declassification",
        "provenance_overflow_fails_closed",
        "budget_deadline_cancellation_races",
        "stale_integrated_and_downstream_profiles",
        "workspace_browser_network_composition",
        "no_automatic_retry_possible_effect",
        "indeterminate_effect_enters_rfc0028_reconciliation",
        "recovery_exact_task_profile_and_fresh_auth",
        "metadata_only_recovery_cannot_resume_without_context",
        "missing_context_waits_for_resupply_or_fails_safely",
        "consumed_approvals_invalid_after_recovery",
        "stale_browser_ids_invalid_after_recovery",
        "routine_observability_content_free",
        "separate_redacted_inspection_authority",
        "wheel_and_sdist_package_boundary",
        "isolated_install_and_smoke",
        "deterministic_network_free_end_to_end",
        "observer_best_effort_outside_execution_path",
    }
)


def _namespace() -> dict[str, object]:
    return runpy.run_path(str(_GATE))


def test_integrated_release_gate_manifest_covers_frozen_security_requirements() -> None:
    namespace = _namespace()
    manifest = namespace["_SECURITY_REQUIREMENT_FILES"]
    assert isinstance(manifest, dict)
    assert frozenset(manifest) == _EXPECTED_REQUIREMENTS
    assert all(paths for paths in manifest.values())


def test_integrated_release_gate_covers_v036_release_metadata() -> None:
    namespace = _namespace()
    companion = namespace["_COMPANION_TESTS"]
    hardening = namespace["_REQUIRED_HARDENING_FILES"]
    assert isinstance(companion, tuple)
    assert isinstance(hardening, tuple)
    assert companion == ("tests/test_v036_release.py",)
    assert "docs/releases/v0.36.0.md" in hardening
    assert (_ROOT / "tests/test_v036_release.py").is_file()
    assert (_ROOT / "docs/releases/v0.36.0.md").is_file()


def test_integrated_release_gate_freezes_exact_package_surface() -> None:
    namespace = _namespace()
    required = namespace["_REQUIRED_INTEGRATED_MODULES"]
    assert isinstance(required, frozenset)

    source = _ROOT / "src/phoenix_os/integrated_agent"
    actual = frozenset(
        f"phoenix_os/integrated_agent/{path.relative_to(source).as_posix()}"
        for path in source.rglob("*.py")
    )
    assert actual == required
    assert "phoenix_os/integrated_agent/observer.py" in required
    assert "phoenix_os/integrated_agent/administration.py" in required


def test_integrated_release_gate_is_release_blocking_everywhere() -> None:
    browser = "python scripts/check_browser_automation_release.py"
    for relative in (
        "scripts/check.ps1",
        "scripts/check.sh",
        ".github/workflows/ci.yml",
    ):
        text = (_ROOT / relative).read_text(encoding="utf-8")
        assert text.count(_GATE_COMMAND) == 1
        assert browser in text
        assert text.index(browser) < text.index(_GATE_COMMAND)
