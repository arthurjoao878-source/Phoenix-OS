from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_ADRS = _ROOT / "docs" / "adrs"

_FILES = (
    "ADR-0056-files-carry-data-never-authority.md",
    "ADR-0057-phoenix-owned-logical-paths-and-host-confinement.md",
    "ADR-0058-authoritative-workspace-store-and-backing-boundary.md",
    "ADR-0059-explicit-workspace-import-export-boundaries.md",
)


def test_rfc0031_adrs_are_accepted_and_indexed() -> None:
    index = (_ADRS / "README.md").read_text(encoding="utf-8")
    for name in _FILES:
        path = _ADRS / name
        assert path.is_file()
        text = path.read_text(encoding="utf-8")
        assert "- **Status:** Accepted" in text
        assert "- **Related:** RFC-0031" in text
        assert "## Decision" in text
        assert "## Consequences" in text
        assert name in index


def test_rfc0031_adrs_preserve_core_workspace_security_choices() -> None:
    joined = " ".join(
        "\n".join((_ADRS / name).read_text(encoding="utf-8") for name in _FILES).split()
    )
    for phrase in (
        "Files carry data, never authority.",
        "portable relative identifiers, not native host filesystem paths",
        "The workspace store is authoritative",
        "opaque Phoenix-owned key",
        "Import and export are explicit server-mediated transfers",
        "independent exact authorization",
    ):
        assert phrase in joined
