from __future__ import annotations

from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_GUIDE = _ROOT / "docs" / "migrations" / "v0.24.0-to-v0.25.0-inbound-events.md"
_README = _ROOT / "README.md"


def _guide() -> str:
    return _GUIDE.read_text(encoding="utf-8")


def test_inbound_migration_guide_is_linked_from_readme() -> None:
    readme = _README.read_text(encoding="utf-8")
    assert _GUIDE.is_file()
    assert "docs/migrations/v0.24.0-to-v0.25.0-inbound-events.md" in readme
    assert "Migrate v0.24.0 deployments to v0.25.0 inbound events" in readme


def test_migration_preserves_disabled_v0240_compatibility() -> None:
    guide = _guide()
    for phrase in (
        "inbound_events_enabled=True",
        "without adding inbound arguments",
        "preserve its previous",
        "no `/v1/control-plane/inbound/<source-name>` route exists",
        "no inbound State Store keys or in-memory repositories are created",
    ):
        assert phrase in guide


def test_migration_forbids_automatic_conversion_or_grants() -> None:
    guide = _guide()
    for phrase in (
        "Existing webhook subscriptions are not converted",
        "no source, route, schema, HMAC key, service-account grant",
        "receive no inbound scope or resource automatically",
        "no network permission is added automatically",
    ):
        assert phrase in guide


def test_migration_requires_reviewed_schema_normalization() -> None:
    guide = _guide()
    for phrase in (
        "InboundEventSchema",
        "ReleaseCompletedNormalizer",
        "reject_unknown_fields=True",
        "reviewed normalizer is the allowlisting boundary",
        "arbitrary caller-selected internal Event Bus event names",
    ):
        assert phrase in guide


def test_migration_documents_shared_listener_and_exact_routes() -> None:
    guide = _guide()
    for phrase in (
        "do not create a second socket",
        "/v1/control-plane/inbound/<source-name>",
        "Disabled and revoked sources have no active ingress route",
        "fixed nonzero port",
        "native TLS",
        "explicit allowed client networks",
    ):
        assert phrase in guide


def test_migration_documents_coordinated_durability() -> None:
    guide = _guide()
    for phrase in (
        "coordinated repository trio",
        "State Store-backed source, event, and replay repositories",
        "must include all three repositories",
        "256 sources",
        "4096 accepted events",
        "16,384 replay reservations",
    ):
        assert phrase in guide


def test_migration_documents_exact_hmac_and_request_evidence() -> None:
    guide = _guide()
    for phrase in (
        "exact immutable `SecretRef`",
        "X-Phoenix-Inbound-Request-Id",
        "X-Phoenix-Inbound-Event-Id",
        "X-Phoenix-Inbound-Timestamp",
        "X-Phoenix-Inbound-Nonce",
        "X-Phoenix-Inbound-Signature",
        "X-Phoenix-Inbound-Key-Version",
        "must not contain `Authorization`",
    ):
        assert phrase in guide


def test_migration_stages_disabled_source_before_enablement() -> None:
    guide = _guide()
    for phrase in (
        "New sources are created disabled",
        'assert source.status.value == "disabled"',
        "expected_revision=source.revision",
        "Send one controlled canary event",
        "same stable receipt",
    ):
        assert phrase in guide


def test_migration_separates_submission_and_machine_administration() -> None:
    guide = _guide()
    for phrase in (
        "Source authentication and machine administration are different decisions",
        "inbound_event.submit",
        "inbound_service_account_administration_enabled=True",
        "inbound-machine",
        "inbound-source:<uuid>",
        "External event submission and administrative authority are separate permissions",
    ):
        assert phrase in guide


def test_migration_rollback_preserves_state_and_secret_versions() -> None:
    guide = _guide()
    for phrase in (
        "Rollback should first remove ingress authority",
        "Disable every active source",
        "Preserve State Store records",
        "Do not revoke or delete HMAC material",
        "cannot interpret v0.25.0 inbound records",
    ):
        assert phrase in guide


def test_migration_contains_complete_quality_and_package_gate() -> None:
    guide = _guide()
    for phrase in (
        "python -m ruff check .",
        "python -m ruff format --check .",
        "python -m mypy",
        "python -m pytest -q",
        "wheel and sdist artifacts",
        "isolated offline environments",
    ):
        assert phrase in guide
