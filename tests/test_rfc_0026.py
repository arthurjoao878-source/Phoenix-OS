from __future__ import annotations

import tomllib
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_RFC = _ROOT / "docs" / "rfcs" / "RFC-0026-secure-model-providers-and-inference-runtime.md"
_README = _ROOT / "README.md"
_PYPROJECT = _ROOT / "pyproject.toml"


def _normalized(text: str) -> str:
    return " ".join(text.split())


def test_rfc_0026_metadata_is_accepted_for_v0260() -> None:
    rfc = _normalized(_RFC.read_text(encoding="utf-8"))
    assert rfc.startswith("# RFC-0026: Secure Model Providers and Inference Runtime")
    assert "- Status: Accepted" in rfc
    assert "- Target release: Phoenix OS v0.26.0" in rfc


def test_readme_preserves_rfc_0026_as_accepted() -> None:
    readme = _README.read_text(encoding="utf-8")
    assert "**RFC-0026 — Secure Model Providers and Inference Runtime:**" in readme
    assert "[Phoenix OS 0.26.0](docs/releases/v0.26.0.md)" in readme


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


def test_rfc_0026_records_completed_v0260_release_boundary() -> None:
    rfc = _normalized(_RFC.read_text(encoding="utf-8"))
    project = tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))
    assert project["project"]["version"] >= "0.26.0"
    assert "Inference providers are optional and begin empty." in rfc
    assert "No provider, model, endpoint, secret reference" in rfc
    assert "remains `0.25.0` during implementation slices" in rfc
    assert "changes to `0.26.0` only in the final release slice" in rfc
    assert "RFC-0026 is accepted for Phoenix OS 0.26.0." in rfc


def test_rfc_0026_implementation_progress_is_current() -> None:
    rfc = _RFC.read_text(encoding="utf-8")
    plan = rfc.split("## Slice plan", maxsplit=1)[1].split(
        "## Acceptance",
        maxsplit=1,
    )[0]
    slice_1 = plan.split("### Slice 2", maxsplit=1)[0]
    slice_2 = plan.split("### Slice 2", maxsplit=1)[1].split(
        "### Slice 3",
        maxsplit=1,
    )[0]
    slice_3 = plan.split("### Slice 3", maxsplit=1)[1].split(
        "### Slice 4",
        maxsplit=1,
    )[0]
    slice_4 = plan.split("### Slice 4", maxsplit=1)[1].split(
        "### Slice 5",
        maxsplit=1,
    )[0]
    slice_5 = plan.split("### Slice 5", maxsplit=1)[1]

    assert plan.count("### Slice ") == 5
    assert plan.count("- [x]") == 35
    assert plan.count("- [ ]") == 0
    assert slice_1.count("- [x]") == 7
    assert slice_2.count("- [x]") == 7
    assert slice_3.count("- [x]") == 7
    assert slice_4.count("- [x]") == 7

    for phrase in (
        "Complete inference execution",
        "Ordered bounded streaming with one terminal record",
        "Cooperative cancellation and finite cleanup",
        "Deadline, first-byte, duration, byte, token, and chunk limits",
        "Global, provider, and model admission controls",
        "No-transparent-retry execution semantics",
        "Timeout, malformed-stream, saturation, and race tests",
    ):
        assert f"- [x] {phrase}" in slice_3

    for phrase in (
        "Typed provider, model, endpoint, credential, and limit configuration",
        "RuntimeAssembler optional composition and deterministic rollback",
        "Safe Runtime service exposure and health snapshots",
        "Content-free audit facts and redacted observability",
        "Phoenix-owned content-free Event Bus lifecycle events",
        "Bounded shutdown, cancellation, and adapter cleanup",
        "Compatibility tests with inference omitted",
    ):
        assert f"- [x] {phrase}" in slice_4

    for phrase in (
        "Maintainer-only provider and model administration",
        "Dashboard provider lifecycle and content-free invocation health",
        "Optional scoped service-account administration",
        "Migration guidance and rollback procedure",
        "Architecture Decision Records",
    ):
        assert f"- [x] {phrase}" in slice_5

    assert "- [x] Security, limits, streaming, and packaging release gate" in slice_5
    assert "- [x] Release notes, version 0.26.0, tag, artifacts, and checksums" in slice_5


def test_rfc_0026_records_slice_1_implementation_boundary() -> None:
    rfc = _normalized(_RFC.read_text(encoding="utf-8"))
    for phrase in (
        "`phoenix_os.inference`",
        "deterministic network-free provider",
        "No hosted-provider SDK",
        "model output remains untrusted",
    ):
        assert phrase in rfc


def test_rfc_0026_records_slice_2_security_boundary() -> None:
    rfc = _normalized(_RFC.read_text(encoding="utf-8"))
    for phrase in (
        "`model.infer` authorization",
        "exact versioned `SecretRef` leases",
        "pinned literal destination addresses",
        "No provider HTTP request",
        "redirects and ambient proxies remain disabled",
    ):
        assert phrase in rfc


def test_rfc_0026_records_slice_3_execution_boundary() -> None:
    rfc = _normalized(_RFC.read_text(encoding="utf-8"))
    for phrase in (
        "`InferenceRuntime`",
        "fail-fast global, provider, and model admission",
        "exactly one validated terminal record",
        "No execution path performs a transparent retry",
        "No hosted-provider transport",
    ):
        assert phrase in rfc


def test_rfc_0026_records_slice_4_runtime_boundary() -> None:
    rfc = _normalized(_RFC.read_text(encoding="utf-8"))
    for phrase in (
        "`RuntimeAssembler` composition",
        "`inference.runtime`",
        "empty payloads",
        "exclude prompt text, response text, credentials",
        "Shutdown first drains active invocations",
        "No hosted-provider SDK",
    ):
        assert phrase in rfc
