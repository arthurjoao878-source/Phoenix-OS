from __future__ import annotations

from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_ADRS = _ROOT / "docs" / "adrs"
_INDEX = _ADRS / "README.md"
_RFC = _ROOT / "docs" / "rfcs" / "RFC-0026-secure-model-providers-and-inference-runtime.md"
_README = _ROOT / "README.md"

_ADR_FILES = (
    "ADR-0011-provider-neutral-contracts-and-reviewed-inference-registry.md",
    "ADR-0012-exact-inference-authorization-and-untrusted-model-output.md",
    "ADR-0013-exact-credential-leases-and-fail-closed-provider-endpoints.md",
    "ADR-0014-bounded-streaming-cancellation-and-no-transparent-retry.md",
    "ADR-0015-opt-in-inference-runtime-and-separated-administration.md",
)


def _read(name: str) -> str:
    return (_ADRS / name).read_text(encoding="utf-8")


def _normalized(name: str) -> str:
    return " ".join(_read(name).split())


def test_inference_adr_index_links_every_record() -> None:
    index = _INDEX.read_text(encoding="utf-8")
    for name in _ADR_FILES:
        assert name in index


def test_inference_adrs_use_complete_accepted_structure() -> None:
    for name in _ADR_FILES:
        document = _read(name)
        assert "- **Status:** Accepted" in document
        assert "- **Date:** 2026-07-27" in document
        assert "RFC-0026" in document
        assert "## Context" in document
        assert "## Decision" in document
        assert "## Consequences" in document
        assert "## Alternatives considered" in document
        assert "## Supersession criteria" in document


def test_registry_adr_records_provider_neutral_allowlisting() -> None:
    document = _read(_ADR_FILES[0])
    normalized = _normalized(_ADR_FILES[0])
    assert "`InferenceRequest`" in document
    assert "`ModelProviderRegistry`" in document
    assert "`ModelProviderRegistry` is the allowlisting boundary" in normalized
    assert "Callers cannot supply endpoint" in normalized
    assert "deterministic network-free provider" in normalized


def test_authority_adr_records_exact_model_decision() -> None:
    document = _read(_ADR_FILES[1])
    normalized = _normalized(_ADR_FILES[1])
    assert "`model.infer`" in document
    assert "`model-provider:<provider-id>/model:<model-id>`" in document
    assert "Model output is untrusted data" in document
    assert "new independent policy decision" in normalized
    assert "never grants capability" in normalized


def test_endpoint_adr_records_exact_secret_and_fail_closed_network() -> None:
    document = _read(_ADR_FILES[2])
    normalized = _normalized(_ADR_FILES[2])
    assert "exact versioned `SecretRef`" in document
    assert "revokes leases after completion" in normalized
    assert "resolve, admit, and pin" in normalized
    assert "Redirects and ambient proxies remain disabled" in document
    assert "Plain HTTP remains limited to explicit loopback-local" in normalized


def test_execution_adr_records_bounded_terminal_semantics() -> None:
    normalized = _normalized(_ADR_FILES[3])
    for phrase in (
        "exactly one terminal record",
        "no transparent retry after provider execution begins",
        "Cancellation is cooperative and bounded",
        "Admission occurs before credential leasing",
        "Partial output is not reported as complete",
    ):
        assert phrase in normalized


def test_runtime_adr_records_opt_in_separated_administration() -> None:
    document = _read(_ADR_FILES[4])
    normalized = _normalized(_ADR_FILES[4])
    assert "disabled by default" in document
    assert "`RuntimeAssembler`" in document
    assert "Human administration" in document
    assert "Machine administration" in document
    assert "content-free" in document
    assert "no second Phoenix listener" in normalized
    assert "Provider and model lifecycle state is runtime-local" in document


def test_inference_adrs_do_not_contain_unsafe_advice() -> None:
    joined = "\n".join(_read(name) for name in _ADR_FILES)
    forbidden = (
        'api_key = "',
        'password = "',
        'secret = "',
        "grant `*`",
        "execute model output directly",
        "follow redirects automatically",
        "use ambient proxy",
    )
    for phrase in forbidden:
        assert phrase not in joined

    normalized = " ".join(joined.split())
    assert "Plaintext credentials never enter inference requests" in normalized
    assert "There is no transparent retry" in normalized
    assert "prompts and responses are not persisted by default" in normalized.lower()


def test_readme_and_rfc_link_the_inference_adr_collection() -> None:
    readme = _README.read_text(encoding="utf-8")
    rfc = _RFC.read_text(encoding="utf-8")
    assert "docs/adrs/README.md" in readme
    assert "RFC-0026 inference records cover" in readme
    assert "- [x] Architecture Decision Records" in rfc
    for name in _ADR_FILES:
        assert name in rfc
