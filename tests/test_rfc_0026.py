from __future__ import annotations

import tomllib
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_RFC = _ROOT / "docs" / "rfcs" / "RFC-0026-secure-model-providers-and-inference-runtime.md"
_README = _ROOT / "README.md"
_PYPROJECT = _ROOT / "pyproject.toml"


def _normalized(text: str) -> str:
    return " ".join(text.split())


def test_rfc_0026_metadata_is_draft_for_v0260() -> None:
    rfc = _normalized(_RFC.read_text(encoding="utf-8"))
    assert rfc.startswith("# RFC-0026: Secure Model Providers and Inference Runtime")
    assert "- Status: Draft" in rfc
    assert "- Target release: Phoenix OS v0.26.0" in rfc


def test_readme_lists_rfc_0026_as_draft() -> None:
    readme = _README.read_text(encoding="utf-8")
    assert "Version `0.25.0` implements twenty-five accepted specifications:" in readme
    assert "## Draft specifications" in readme
    assert (
        "[RFC-0026 — Secure Model Providers and Inference Runtime]"
        "(docs/rfcs/RFC-0026-secure-model-providers-and-inference-runtime.md)" in readme
    )


def test_rfc_0026_has_required_design_sections() -> None:
    rfc = _normalized(_RFC.read_text(encoding="utf-8"))
    required = (
        "## Summary",
        "## Motivation",
        "## Goals",
        "## Non-goals",
        "## Threat model",
        "## Security invariants",
        "## Proposed contracts",
        "## Request and response model",
        "## Provider and model registry",
        "## Authorization and authority separation",
        "## Credentials and endpoint security",
        "## Limits, budgets, and admission",
        "## Complete and streaming execution",
        "## Retry, failure, and cancellation semantics",
        "## Audit, observability, and events",
        "## Configuration and RuntimeAssembler integration",
        "## Compatibility and migration",
        "## Slice plan",
        "## Acceptance",
    )
    for heading in required:
        assert heading in rfc


def test_rfc_0026_preserves_authority_boundaries() -> None:
    rfc = _normalized(_RFC.read_text(encoding="utf-8"))
    for phrase in (
        "Model output is untrusted data and never executes directly",
        "exact `model.infer` action",
        "never grants capability, command, job, workflow, plugin",
        "model output receives no implicit authority",
    ):
        assert phrase in rfc


def test_rfc_0026_defines_secret_and_endpoint_safety() -> None:
    rfc = _normalized(_RFC.read_text(encoding="utf-8"))
    for phrase in (
        "exact versioned `SecretRef`",
        "Hosted endpoints require verified HTTPS",
        "Plain HTTP is permitted only",
        "Redirects are disabled by default",
        "Requests cannot supply proxy, DNS, TLS",
    ):
        assert phrase in rfc


def test_rfc_0026_defines_bounded_streaming_and_cancellation() -> None:
    rfc = _normalized(_RFC.read_text(encoding="utf-8"))
    for phrase in (
        "Streaming chunks are ordered, bounded",
        "exactly one terminal record",
        "Cancellation and deadlines stop local consumption",
        "no transparent retry after provider execution begins",
    ):
        assert phrase in rfc


def test_rfc_0026_keeps_version_0250_during_planning() -> None:
    rfc = _normalized(_RFC.read_text(encoding="utf-8"))
    project = tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))
    assert project["project"]["version"] == "0.25.0"
    assert "Inference providers are optional and begin empty." in rfc
    assert "No provider, model, endpoint, secret reference" in rfc
    assert "remains `0.25.0` during implementation slices" in rfc
    assert "changes to `0.26.0` only in the final release slice" in rfc


def test_rfc_0026_slice_1_is_implemented() -> None:
    rfc = _RFC.read_text(encoding="utf-8")
    plan = rfc.split("## Slice plan", maxsplit=1)[1].split("## Acceptance", maxsplit=1)[0]
    slice_1 = plan.split("### Slice 2", maxsplit=1)[0]

    assert plan.count("### Slice ") == 5
    assert plan.count("- [x]") == 7
    assert plan.count("- [ ]") == 28
    assert slice_1.count("- [x]") == 7
    assert slice_1.count("- [ ]") == 0
    for phrase in (
        "Immutable inference request, response, chunk, usage, and error contracts",
        "Strict provider, model, role, finish-reason, and limit validation",
        "Provider and model registry with duplicate rejection",
        "Deterministic fake provider with complete and streaming modes",
        "Bounded request and response codecs",
        "Provider capability compatibility checks",
        "Contract, registry, and fake-provider tests",
    ):
        assert f"- [x] {phrase}" in slice_1


def test_rfc_0026_records_slice_1_implementation_boundary() -> None:
    rfc = _normalized(_RFC.read_text(encoding="utf-8"))
    for phrase in (
        "`phoenix_os.inference`",
        "deterministic network-free provider",
        "No hosted-provider SDK",
        "model output remains untrusted",
    ):
        assert phrase in rfc
