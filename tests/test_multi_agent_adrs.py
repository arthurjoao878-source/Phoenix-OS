from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_ADRS = _ROOT / "docs" / "adrs"

_FILES = (
    "ADR-0048-delegation-creates-work-never-authority.md",
    "ADR-0049-monotonic-root-budget-reservation.md",
    "ADR-0050-phoenix-owned-delegation-lineage.md",
    "ADR-0051-runtime-owned-child-lifecycle-and-recovery.md",
)


def test_rfc0029_adrs_are_accepted_and_indexed() -> None:
    index = (_ADRS / "README.md").read_text(encoding="utf-8")
    for name in _FILES:
        path = _ADRS / name
        assert path.is_file()
        text = path.read_text(encoding="utf-8")
        assert "- **Status:** Accepted" in text
        assert "- **Related:** RFC-0029" in text
        assert "## Decision" in text
        assert "## Consequences" in text
        assert name in index


def test_rfc0029_adrs_preserve_core_security_choices() -> None:
    joined = "\n".join((_ADRS / name).read_text(encoding="utf-8") for name in _FILES)
    for phrase in (
        "Delegation creates work, never authority.",
        "monotonic lifetime accounting",
        "Phoenix-owned typed data",
        "`RUNNING` child becomes `INDETERMINATE`",
        "never replayed automatically",
    ):
        assert phrase in joined
