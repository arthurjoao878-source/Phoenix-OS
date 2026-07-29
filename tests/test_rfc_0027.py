from __future__ import annotations

import tomllib
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_RFC = _ROOT / "docs" / "rfcs" / "RFC-0027-secure-agent-loop-and-tool-calling.md"
_README = _ROOT / "README.md"
_PYPROJECT = _ROOT / "pyproject.toml"


def _normalized(text: str) -> str:
    return " ".join(text.split())


def test_rfc_0027_metadata_is_accepted_for_v0270() -> None:
    rfc = _normalized(_RFC.read_text(encoding="utf-8"))
    assert rfc.startswith("# RFC-0027: Secure Agent Loop and Tool Calling Runtime")
    assert "- Status: Accepted" in rfc
    assert "- Target release: Phoenix OS v0.27.0" in rfc


def test_readme_lists_rfc_0027_as_accepted() -> None:
    readme = _README.read_text(encoding="utf-8")
    assert "Version `0.27.0` implements twenty-seven accepted specifications:" in readme
    assert "**RFC-0027 — Secure Agent Loop and Tool Calling Runtime:**" in readme
    assert "## Draft specifications" not in readme
    assert "[Phoenix OS 0.27.0](docs/releases/v0.27.0.md)" in readme


def test_rfc_0027_has_required_design_sections() -> None:
    rfc = _normalized(_RFC.read_text(encoding="utf-8"))
    required = (
        "## Summary",
        "## Motivation",
        "## Goals",
        "## Non-goals",
        "## Threat model",
        "## Security invariants",
        "## Proposed contracts",
        "## Tool descriptors and registry",
        "## Strict schema subset",
        "## Model turn contract",
        "## Argument validation and canonicalization",
        "## Authorization and authority separation",
        "## Human approval",
        "## Tool effect classification",
        "## Tool execution",
        "## Agent state machine",
        "## Limits, budgets, and admission",
        "## Loop termination",
        "## Retry and duplicate execution semantics",
        "## Cancellation and shutdown",
        "## Tool-result isolation",
        "## Secrets and sensitive data",
        "## Audit, observability, and events",
        "## Configuration and RuntimeAssembler integration",
        "## Administration",
        "## Compatibility and migration",
        "## Slice plan",
        "## Acceptance",
    )
    for heading in required:
        assert heading in rfc


def test_rfc_0027_preserves_authority_separation() -> None:
    rfc = _normalized(_RFC.read_text(encoding="utf-8"))
    for phrase in (
        "model output is data, not authority",
        "Authorization for `agent.run` does not authorize",
        "Every model turn still requires the RFC-0026 `model.infer` authorization",
        "Every tool call requires a new exact `tool.invoke` authorization",
        "policy resource is resolved by trusted server-side code",
    ):
        assert phrase in rfc


def test_rfc_0027_defines_strict_tools_approvals_and_results() -> None:
    rfc = _normalized(_RFC.read_text(encoding="utf-8"))
    for phrase in (
        "Duplicate JSON keys",
        "Unknown object properties are rejected by default",
        "Approval tokens are single-use, short-lived, actor-bound",
        "Tool output is untrusted data when returned to the model",
        "Generic shell, unrestricted HTTP, and unrestricted filesystem tools are not included",
    ):
        assert phrase in rfc


def test_rfc_0027_defines_finite_no_retry_shutdown_semantics() -> None:
    rfc = _normalized(_RFC.read_text(encoding="utf-8"))
    for phrase in (
        "most restrictive applicable limit wins",
        "performs no transparent retry of model turns or tool calls",
        "Cancellation is cooperative and bounded",
        "closes tool adapters in reverse composition order",
        "leaves RFC-0026 inference shutdown ordering intact",
    ):
        assert phrase in rfc


def test_rfc_0027_releases_version_0270_after_implementation() -> None:
    rfc = _normalized(_RFC.read_text(encoding="utf-8"))
    project = tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))
    assert project["project"]["version"] == "0.27.0"
    assert "Agent configuration begins absent and disabled" in rfc
    assert "remains `0.26.0` during implementation slices" in rfc
    assert "changes to `0.27.0` only in the final release slice" in rfc


def test_rfc_0027_implementation_progress_is_complete() -> None:
    rfc = _RFC.read_text(encoding="utf-8")
    plan = rfc.split("## Slice plan", maxsplit=1)[1].split("## Acceptance", maxsplit=1)[0]
    slices = []
    for number in range(1, 6):
        section = plan.split(f"### Slice {number}", maxsplit=1)[1]
        if number < 5:
            section = section.split(f"### Slice {number + 1}", maxsplit=1)[0]
        slices.append(section)

    assert plan.count("### Slice ") == 5
    assert plan.count("- [x]") == 36
    assert plan.count("- [ ]") == 0
    assert [section.count("- [x]") for section in slices] == [7, 7, 8, 7, 7]


def test_rfc_0027_records_release_evidence_and_acceptance() -> None:
    rfc = _RFC.read_text(encoding="utf-8")
    for phrase in (
        "v0.26.0-to-v0.27.0-agent.md",
        "RFC-0027-agent-threat-model-review.md",
        "scripts/check_agent_release.py",
        "docs/releases/v0.27.0.md",
        "tag `v0.27.0`",
        "SHA256SUMS",
        "RFC-0027 is accepted for Phoenix OS 0.27.0.",
    ):
        assert phrase in rfc
