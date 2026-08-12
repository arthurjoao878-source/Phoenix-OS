from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_ADRS = _ROOT / "docs" / "adrs"

_FILES = (
    "ADR-0052-memory-informs-work-never-authority.md",
    "ADR-0053-phoenix-owned-exact-memory-scopes.md",
    "ADR-0054-authoritative-memory-records-derived-indexes.md",
    "ADR-0055-finite-retention-runtime-owned-memory-lifecycle.md",
)


def test_rfc0030_adrs_are_accepted_and_indexed() -> None:
    index = (_ADRS / "README.md").read_text(encoding="utf-8")
    for name in _FILES:
        path = _ADRS / name
        assert path.is_file()
        text = path.read_text(encoding="utf-8")
        assert "- **Status:** Accepted" in text
        assert "- **Related:** RFC-0030" in text
        assert "## Decision" in text
        assert "## Consequences" in text
        assert name in index


def test_rfc0030_adrs_preserve_core_memory_security_choices() -> None:
    joined = " ".join(
        "\n".join((_ADRS / name).read_text(encoding="utf-8") for name in _FILES).split()
    )
    for phrase in (
        "Memory informs work, never authority.",
        "There is no global shared memory in v1.",
        "The memory source store is authoritative",
        "candidate identity/version/digest",
        "Every configured memory domain has finite",
        "startup recovery fails or is cancelled, the owner self-cleans",
    ):
        assert phrase in joined
