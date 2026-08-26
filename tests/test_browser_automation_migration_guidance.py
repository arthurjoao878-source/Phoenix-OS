from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_GUIDE = _ROOT / "docs" / "migrations" / "v0.34.0-to-v0.35.0-secure-browser-automation.md"


def test_browser_migration_preserves_omission_and_independent_authority() -> None:
    text = _GUIDE.read_text(encoding="utf-8")
    for phrase in (
        "No migration action is required to preserve Phoenix OS v0.34.0 behavior.",
        "browser-automation configuration is omitted",
        "grants no browser action automatically",
        "`tool.invoke`",
        "`network.http.request`",
        "remain independent",
    ):
        assert phrase in text


def test_browser_migration_documents_frozen_v035_scope_and_lifecycle() -> None:
    text = _GUIDE.read_text(encoding="utf-8")
    for phrase in (
        "does not bundle a production browser engine",
        "JavaScript",
        "downloads",
        "persistent browser storage",
        "Runtime state controls availability and shutdown only",
        "Security quarantine remains distinct",
        "`browser.health.read`",
        "INDETERMINATE",
    ):
        assert phrase in text


def test_browser_migration_keeps_release_metadata_for_s8() -> None:
    text = _GUIDE.read_text(encoding="utf-8")
    assert "python scripts/check_browser_automation_release.py" in text
    assert "S7 intentionally does not change `pyproject.toml`" in text
    assert "RFC-0035 S8 performs v0.35.0 release finalization" in text
