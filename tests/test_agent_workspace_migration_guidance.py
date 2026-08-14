from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_MIGRATION = _ROOT / "docs" / "migrations" / "v0.30.0-to-v0.31.0-agent-workspaces.md"


def test_agent_workspace_migration_is_disabled_first_and_authority_safe() -> None:
    text = " ".join(_MIGRATION.read_text(encoding="utf-8").split())
    for phrase in (
        "Files carry data, never authority.",
        "When workspace configuration is omitted",
        "no principal receives any workspace action automatically",
        "migration-free-by-omission upgrade",
        "current workspace policy immediately wins",
        "portable relative identifiers, not native host filesystem paths",
        "Import and export remain independent operations",
        "disable-first rollback",
        "package downgrade is not a workspace-artifact migrator",
    ):
        assert phrase in text


def test_agent_workspace_migration_rejects_automatic_state_reinterpretation() -> None:
    text = " ".join(_MIGRATION.read_text(encoding="utf-8").split())
    for phrase in (
        "does not import, mount, scan, reinterpret, or copy existing host files",
        "Existing memory records, prompts, responses, tool results, checkpoints",
        "must not be converted into artifacts",
        "Do not reuse a user's project tree or personal directory",
        "workspace read does not perform an implicit remote network fetch",
        (
            "final RFC acceptance, release commit, tag, artifacts, and "
            "checksums remain later Slice 5 work"
        ),
    ):
        assert phrase in text


def test_agent_workspace_migration_names_release_gate_and_offline_validation() -> None:
    raw = _MIGRATION.read_text(encoding="utf-8")
    text = " ".join(raw.split())
    assert "python scripts/check_agent_workspace_release.py" in text
    assert "--no-deps --no-index" in text
    assert "without source-tree imports" in text
    assert "derives the current package version from pyproject.toml" in text
