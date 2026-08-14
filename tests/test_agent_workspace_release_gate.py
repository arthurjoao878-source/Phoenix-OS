from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_GATE = _ROOT / "scripts" / "check_agent_workspace_release.py"
_CI = _ROOT / ".github" / "workflows" / "ci.yml"
_CHECK_PS1 = _ROOT / "scripts" / "check.ps1"
_CHECK_SH = _ROOT / "scripts" / "check.sh"
_README = _ROOT / "README.md"
_RFC = _ROOT / "docs" / "rfcs" / "RFC-0031-secure-agent-workspaces-and-artifact-handling.md"


def test_agent_workspace_release_gate_has_packaging_and_isolated_smoke_boundaries() -> None:
    text = _GATE.read_text(encoding="utf-8")
    for phrase in (
        'glob("test_agent_workspace*.py")',
        'glob("workspace_*.py")',
        '"docs/rfcs/RFC-0031-secure-agent-workspaces-and-artifact-handling.md"',
        '"docs/migrations/v0.30.0-to-v0.31.0-agent-workspaces.md"',
        '"docs/security/RFC-0031-agent-workspace-threat-model-review.md"',
        '"docs/adrs/ADR-0056-files-carry-data-never-authority.md"',
        '"docs/adrs/ADR-0059-explicit-workspace-import-export-boundaries.md"',
        '"--no-deps"',
        '"--no-index"',
        '"-I"',
        "workspace_scope_resource",
        "workspace_artifact_resource",
        "ArtifactLogicalPath",
        "InMemoryWorkspaceStore",
        "artifact_content_digest",
        "distribution_version",
    ):
        assert phrase in text


def test_agent_workspace_release_gate_rejects_unsafe_archive_content() -> None:
    text = _GATE.read_text(encoding="utf-8")
    assert "_FORBIDDEN_ARCHIVE_COMPONENTS" in text
    assert "_FORBIDDEN_ARCHIVE_SUFFIXES" in text
    assert "member.issym() or member.islnk()" in text
    assert 'archive.extractall(destination, filter="data")' in text


def test_agent_workspace_release_gate_is_named_in_ci_local_checks_and_docs() -> None:
    command = "python scripts/check_agent_workspace_release.py"
    for path in (_CI, _CHECK_PS1, _CHECK_SH, _README, _RFC):
        assert command in path.read_text(encoding="utf-8")

    shell = _CHECK_SH.read_text(encoding="utf-8")
    assert shell.index("python scripts/check_agent_memory_release.py") < shell.index(command)

    rfc = _RFC.read_text(encoding="utf-8")
    assert "- [x] Named agent-workspace release gate" in rfc
    assert "- [x] Offline wheel/sdist validation" in rfc
