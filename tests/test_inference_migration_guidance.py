from __future__ import annotations

from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_GUIDE = _ROOT / "docs" / "migrations" / "v0.25.0-to-v0.26.0-inference.md"
_README = _ROOT / "README.md"


def _guide() -> str:
    return _GUIDE.read_text(encoding="utf-8")


def _normalized_guide() -> str:
    return " ".join(_guide().split())


def test_inference_migration_guide_is_linked_from_readme() -> None:
    readme = _README.read_text(encoding="utf-8")
    assert _GUIDE.is_file()
    assert "docs/migrations/v0.25.0-to-v0.26.0-inference.md" in readme
    assert "Migrate v0.25.0 deployments to v0.26.0 inference" in readme


def test_migration_preserves_disabled_v0250_compatibility() -> None:
    guide = _normalized_guide()
    for phrase in (
        "without adding inference arguments",
        "inference_enabled=True",
        "no `inference` service or component exists",
        "no inference State Store key is created",
        "no prompt or response is persisted",
    ):
        assert phrase in guide


def test_migration_forbids_automatic_authority() -> None:
    guide = _normalized_guide()
    for phrase in (
        "No provider, model, endpoint, secret reference",
        "Existing service accounts receive no inference scope",
        "no credential lease is acquired",
        "no provider or model is registered",
        "no Control Plane inference route is available",
    ):
        assert phrase in guide


def test_migration_stages_deterministic_provider_first() -> None:
    guide = _normalized_guide()
    for phrase in (
        "DeterministicModelProvider",
        "performs no network request",
        "no paid provider usage or credential",
        "exactly one terminal record",
        "does not prove that a third-party transport adapter is safe",
    ):
        assert phrase in guide


def test_migration_documents_reviewed_registry_and_authority() -> None:
    guide = _normalized_guide()
    for phrase in (
        "The registry is the allowlisting boundary",
        "Callers select only registered identifiers",
        "model.infer",
        "model-provider:<provider-id>/model:<model-id>",
        "Model output is untrusted data",
        "new independent policy decision",
    ):
        assert phrase in guide


def test_migration_documents_exact_secret_and_endpoint_safety() -> None:
    guide = _normalized_guide()
    for phrase in (
        "exact immutable `SecretRef` version",
        "revokes the lease after completion",
        "Hosted endpoints require reviewed HTTPS",
        "Every DNS answer",
        "disabled ambient proxies",
        "Plain HTTP is permitted only",
    ):
        assert phrase in guide


def test_migration_documents_separated_administration() -> None:
    guide = _normalized_guide()
    for phrase in (
        "Enable operations require action-bound recent step-up",
        "Disable remains CSRF-protected without step-up",
        "inference_service_account_administration_enabled=True",
        "inference-machine",
        "intentionally provide no aggregate provider inventory",
        "Service-account administration does not grant `model.infer`",
    ):
        assert phrase in guide


def test_migration_documents_canary_without_transparent_retry() -> None:
    guide = _normalized_guide()
    for phrase in (
        "run a conservative canary",
        "global, provider, and model saturation",
        "credential lease revocation after every outcome",
        "no transparent retry after provider execution begins",
        "any caller retry must be explicit",
    ):
        assert phrase.lower() in guide.lower()


def test_migration_rollback_preserves_unrelated_state_and_secrets() -> None:
    guide = _normalized_guide()
    for phrase in (
        "Rollback should first remove inference authority",
        "Disable every active model",
        "Disable every active provider",
        "Preserve exact `SecretRef` versions",
        "no inference State Store records",
        "unrelated Phoenix state survives enablement and rollback",
    ):
        assert phrase in guide


def test_migration_contains_complete_quality_and_package_gate() -> None:
    guide = _normalized_guide()
    for phrase in (
        "python -m ruff check .",
        "python -m ruff format --check .",
        "python -m mypy",
        "python -m pytest -q",
        "wheel and sdist",
        "isolated offline environments",
    ):
        assert phrase in guide


def test_migration_contains_no_plaintext_credential_example() -> None:
    guide = _normalized_guide()
    forbidden = (
        'api_key = "',
        'password = "',
        'secret = "',
        "Authorization: Bearer",
        "enable every provider automatically",
    )
    for phrase in forbidden:
        assert phrase not in guide
