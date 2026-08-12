from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_MIGRATION = _ROOT / "docs" / "migrations" / "v0.29.0-to-v0.30.0-agent-memory.md"


def test_agent_memory_migration_is_disabled_first_and_authority_safe() -> None:
    text = " ".join(_MIGRATION.read_text(encoding="utf-8").split())
    for phrase in (
        "Memory informs work, never authority.",
        "When memory configuration is omitted",
        "no principal receives any memory action automatically",
        "Parent and child agents do not share memory by default",
        "current memory policy immediately wins",
        "explicit server-admitted operation",
        "derived index may contain only candidate identity/version/digest",
        "disable-first rollback",
    ):
        assert phrase in text


def test_agent_memory_migration_names_release_gate_and_offline_validation() -> None:
    raw = _MIGRATION.read_text(encoding="utf-8")
    text = " ".join(raw.split())
    assert "python scripts/check_agent_memory_release.py" in text
    assert "--no-deps --no-index" in text
    assert "without source-tree imports" in text
    assert "## Final rollout checklist" in raw
