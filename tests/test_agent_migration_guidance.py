from __future__ import annotations

from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_GUIDE = _ROOT / "docs" / "migrations" / "v0.26.0-to-v0.27.0-agent.md"
_README = _ROOT / "README.md"


def _guide() -> str:
    return _GUIDE.read_text(encoding="utf-8")


def _normalized() -> str:
    return " ".join(_guide().split())


def test_agent_migration_guide_is_linked_from_readme() -> None:
    readme = _README.read_text(encoding="utf-8")
    assert _GUIDE.is_file()
    assert "docs/migrations/v0.26.0-to-v0.27.0-agent.md" in readme
    assert "Migrate v0.26.0 deployments to v0.27.0 agent execution" in readme


def test_migration_preserves_disabled_v0260_compatibility() -> None:
    guide = _normalized()
    for phrase in (
        "without adding agent arguments",
        "no `agent` service or component exists",
        "no agent State Store key is created",
        "no agent audit fact, metric, log, or Event Bus event is emitted",
        "independently configured RFC-0026 inference remains available",
    ):
        assert phrase in guide


def test_migration_forbids_automatic_authority() -> None:
    guide = _normalized()
    for phrase in (
        "no default assistant, tool, permission, approval",
        "Existing service accounts receive no agent or tool scopes",
        "no human or machine principal receives `agent.run`, `model.infer`, "
        "or `tool.invoke` automatically",
        "Do not enable an agent merely because the package imports successfully",
    ):
        assert phrase in guide


def test_migration_stages_deterministic_execution_first() -> None:
    guide = _normalized()
    for phrase in (
        "`DeterministicModelTurnAdapter`",
        "perform no network request",
        "no paid provider usage or credential",
        "one final-only run",
        "one read-only tool cycle",
        "does not prove that a third-party model transport or tool adapter is safe",
    ):
        assert phrase in guide


def test_migration_documents_closed_world_tools_and_strict_schemas() -> None:
    guide = _normalized()
    for phrase in (
        "The registry is the allowlisting boundary",
        "unknown object properties",
        "duplicate JSON keys",
        "model-provided string must never be copied directly into the policy resource",
        "Do not register a generic shell",
    ):
        assert phrase in guide


def test_migration_documents_independent_policy_and_exact_approval() -> None:
    guide = _normalized()
    for phrase in (
        "`agent.run`",
        "RFC-0026 `model.infer`",
        "`tool.invoke`",
        "Authorizing `agent.run` does not authorize nested model or tool work",
        "one consumption",
        "changing any tool, argument, resource, actor, run, step, or call identifier "
        "invalidates the approval",
    ):
        assert phrase in guide


def test_migration_documents_finite_canary_without_transparent_retry() -> None:
    guide = _normalized().lower()
    for phrase in (
        "the most restrictive applicable limit wins",
        "run a conservative canary",
        "serial tool execution within one run",
        "no transparent retry of model or tool execution",
        "any caller retry must be explicit and domain-aware",
    ):
        assert phrase in guide


def test_migration_rollback_disables_agent_without_disabling_inference() -> None:
    guide = _normalized()
    for phrase in (
        "Rollback should first remove agent authority",
        "Disable every active tool",
        "Remove agent configuration and restart Phoenix",
        "Keep RFC-0026 inference configured",
        "Preserve exact `SecretRef` versions",
        "unrelated Phoenix state survives enablement and rollback",
    ):
        assert phrase in guide


def test_migration_contains_full_quality_and_offline_package_gate() -> None:
    guide = _normalized()
    for phrase in (
        "python -m ruff check .",
        "python -m ruff format --check .",
        "python -m mypy",
        "python -m pytest -q",
        "python scripts/check_agent_release.py",
        "wheel and sdist artifacts",
        "isolated offline environments",
        "without source-tree imports",
    ):
        assert phrase in guide


def test_migration_contains_no_plaintext_secret_or_unrestricted_tool_example() -> None:
    guide = _normalized()
    for phrase in (
        'api_key = "',
        'password = "',
        'secret = "',
        "Authorization: Bearer",
        "enable every tool automatically",
    ):
        assert phrase not in guide
