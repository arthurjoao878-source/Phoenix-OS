from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_MIGRATION = _ROOT / "docs" / "migrations" / "v0.28.0-to-v0.29.0-multi-agent.md"


def test_multi_agent_migration_is_disabled_first_and_authority_safe() -> None:
    text = _MIGRATION.read_text(encoding="utf-8")
    for phrase in (
        "Delegation creates work, never authority.",
        "When coordination configuration is omitted",
        "no principal receives `agent.delegate` automatically",
        "action: agent.delegate",
        "Completing a child may free concurrency but must not restore lifetime root budget",
        "one `DelegationId` maps to one child run",
        "a running child becomes `INDETERMINATE`",
        "disable-first rollback",
    ):
        assert phrase in text


def test_multi_agent_migration_names_release_gate_and_offline_validation() -> None:
    raw = _MIGRATION.read_text(encoding="utf-8")
    text = " ".join(raw.split())
    assert "python scripts/check_multi_agent_release.py" in text
    assert "--no-deps --no-index" in text
    assert "without source-tree imports" in text
    assert "## Final rollout checklist" in raw
