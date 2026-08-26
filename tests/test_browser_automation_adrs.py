from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_ADR_DIR = _ROOT / "docs" / "adrs"
_INDEX = _ADR_DIR / "README.md"

_ADRS = {
    "ADR-0064-web-content-and-browser-state-are-data.md": (
        "Web content and browser state are data",
        "never authority",
    ),
    "ADR-0065-server-owned-browser-profiles-and-navigation-targets.md": (
        "Server-owned browser profiles and navigation targets",
        "arbitrary URLs",
    ),
    "ADR-0066-opaque-stale-safe-browser-identities.md": (
        "Opaque stale-safe browser identities",
        "stale",
    ),
    "ADR-0067-zero-effect-preparation-and-final-browser-admission.md": (
        "Zero-effect preparation and final browser admission",
        "INDETERMINATE",
    ),
}


def test_browser_adrs_are_accepted_and_indexed() -> None:
    index = _INDEX.read_text(encoding="utf-8")
    for filename, (title, phrase) in _ADRS.items():
        path = _ADR_DIR / filename
        text = path.read_text(encoding="utf-8")
        number = filename.split("-", 2)[1]
        assert "- **Status:** Accepted" in text
        assert "- **Related:** RFC-0035" in text
        assert title in text
        assert phrase in text
        assert f"ADR-{number}" in index
        assert filename in index


def test_browser_adrs_preserve_frozen_non_amplification_boundaries() -> None:
    text = "\n".join((_ADR_DIR / filename).read_text(encoding="utf-8") for filename in _ADRS)
    for phrase in (
        "never grant",
        "server-owned",
        "opaque",
        "zero-effect",
        "final",
        "no",
    ):
        assert phrase.lower() in text.lower()
    assert "wildcard origins" in text.lower()
    assert "transparent" in text.lower()
