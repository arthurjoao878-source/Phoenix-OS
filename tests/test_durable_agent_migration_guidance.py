from __future__ import annotations

from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_GUIDE = _ROOT / "docs" / "migrations" / "v0.27.0-to-v0.28.0-durable-agent.md"
_RFC = _ROOT / "docs" / "rfcs" / "RFC-0028-durable-agent-runs-and-controlled-resumption.md"
_README = _ROOT / "README.md"


def _guide() -> str:
    return _GUIDE.read_text(encoding="utf-8")


def _normalized() -> str:
    return " ".join(_guide().split())


def test_durable_migration_guide_is_linked_from_readme_and_rfc() -> None:
    readme = _README.read_text(encoding="utf-8")
    rfc = _RFC.read_text(encoding="utf-8")
    assert _GUIDE.is_file()
    assert "docs/migrations/v0.27.0-to-v0.28.0-durable-agent.md" in readme
    assert "Migrate v0.27.0 deployments to v0.28.0 durable agent runs" in readme
    assert "v0.27.0-to-v0.28.0-durable-agent.md" in rfc
    assert "- [x] Migration guidance and rollback procedure" in rfc


def test_durable_migration_preserves_disabled_v0270_compatibility() -> None:
    guide = _normalized()
    for phrase in (
        "keeping durable-agent configuration absent",
        "no durable run, checkpoint, protected payload, lease, recovery worker",
        "ordinary in-memory RFC-0027 agent execution remains available",
        "RFC-0026 inference remains independently configurable",
        "fastest disable-first rollback point",
    ):
        assert phrase in guide


def test_durable_migration_forbids_automatic_authority() -> None:
    guide = _normalized()
    for phrase in (
        "Durability is not authority",
        "A checkpoint is data, not authority",
        "No principal receives `agent.resume`, `agent.reconcile`, "
        "`agent.durable.cleanup`, or durable read authority automatically",
        "Machine administration remains disabled by default",
        "wildcard permission does not satisfy exact destructive authority",
    ):
        assert phrase in guide


def test_durable_migration_stages_storage_codec_and_fencing_first() -> None:
    guide = _normalized()
    for phrase in (
        "fresh empty namespace for the first deterministic storage and codec validation",
        "monotonic checkpoint sequence enforcement",
        "cross-run checkpoint substitution rejection",
        "digest-chain validation",
        "lease expiry and reacquisition with a higher fencing generation",
        "rejection of a stale fencing generation",
        "Checkpoint corruption, rollback, substitution, and unsupported versions fail closed",
    ):
        assert phrase in guide


def test_durable_migration_starts_with_metadata_only_restart_canary() -> None:
    guide = _normalized()
    for phrase in (
        "Begin with `METADATA_ONLY`",
        "Do not enable protected content during the first canary",
        "current configuration, registry, schemas, limits, and policy override persisted metadata",
        "`agent.resume` receives a fresh exact authorization decision",
        "restart does not reset budgets or deadlines",
        "There is no transparent retry of model turns or tool invocations",
    ):
        assert phrase in guide


def test_durable_migration_covers_indeterminate_reconciliation_and_approval() -> None:
    guide = _normalized()
    for phrase in (
        "Checkpointed approval correlation metadata is not approval authority",
        "do not retry first",
        "exact `agent.reconcile` action",
        "cannot rewrite tool, resource, argument, actor, or attempt identity",
        "When evidence is insufficient, keep the run indeterminate or terminate safely",
    ):
        assert phrase in guide


def test_durable_migration_keeps_protected_content_explicit_and_secret_safe() -> None:
    guide = _normalized()
    for phrase in (
        "Enable `PROTECTED_CONTENT` only after the metadata-only canary passes",
        "authenticated encryption",
        "versioned secret references",
        "decryption only after authorization, lease acquisition, and checkpoint validation",
        "Never log plaintext or ciphertext",
        "Encryption does not replace authorization",
    ):
        assert phrase in guide


def test_durable_migration_documents_bounded_cleanup_and_tombstones() -> None:
    guide = _normalized()
    for phrase in (
        "skips actively leased runs",
        "preserves terminal tombstones and anti-resurrection metadata",
        "derives bounds from trusted Runtime-owned retention configuration",
        "step-up protected, confirmed, and audited",
        "Do not send client-selected candidate identifiers",
    ):
        assert phrase in guide


def test_durable_migration_rollback_preserves_records_without_old_writer() -> None:
    guide = _normalized()
    for phrase in (
        "Disable new durable admission and automatic recovery first",
        "does not delete existing durable records automatically",
        "Preserve durable records for later compatible recovery",
        "Export only safe content-free diagnostics",
        "A package downgrade is not a checkpoint migrator",
        "Do not let a downgraded v0.27.0 process write to a v0.28.0 durable namespace",
    ):
        assert phrase in guide


def test_durable_migration_contains_full_quality_and_offline_package_gate() -> None:
    guide = _normalized()
    for phrase in (
        "python -m ruff check .",
        "python -m ruff format --check .",
        "python -m mypy",
        "python -m pytest -q",
        "python scripts/check_agent_release.py",
        "Wheel and sdist artifacts",
        "isolated offline environments",
        "without source-tree imports",
    ):
        assert phrase in guide


def test_durable_migration_contains_no_plaintext_secret_or_unsafe_retry_advice() -> None:
    guide = _normalized()
    forbidden = (
        'api_key = "',
        'password = "',
        'secret = "',
        "Authorization: Bearer",
        "retry indeterminate attempts automatically",
        "grant `*`",
    )
    for phrase in forbidden:
        assert phrase not in guide
