from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_ADRS = _ROOT / "docs" / "adrs"

_FILES = (
    "ADR-0060-host-state-is-data-effects-require-fresh-authority.md",
    "ADR-0061-server-owned-configured-application-profiles.md",
    "ADR-0062-opaque-phoenix-host-identities.md",
    "ADR-0063-immediate-ui-toctou-revalidation.md",
)


def _read(name: str) -> str:
    return (_ADRS / name).read_text(encoding="utf-8")


def _normalized(name: str) -> str:
    return " ".join(_read(name).split())


def test_rfc0032_adrs_are_accepted_and_indexed() -> None:
    index = (_ADRS / "README.md").read_text(encoding="utf-8")
    for name in _FILES:
        path = _ADRS / name
        assert path.is_file()
        text = path.read_text(encoding="utf-8")
        assert "- **Status:** Accepted" in text
        assert "- **Date:** 2026-08-18" in text
        assert "- **Related:** RFC-0032" in text
        assert "## Context" in text
        assert "## Decision" in text
        assert "## Consequences" in text
        assert "## Alternatives considered" in text
        assert "## Supersession criteria" in text
        assert name in index


def test_host_authority_adr_preserves_fresh_independent_authority() -> None:
    normalized = _normalized(_FILES[0])
    for phrase in (
        "Desktop state is data; host effects require fresh authority.",
        "fresh exact current-policy authorization",
        "normal RFC-0027 `tool.invoke` authorization",
        "Neither decision implies the other.",
        "Host effects are not transparently retried.",
    ):
        assert phrase in normalized


def test_application_profile_adr_preserves_server_owned_launch_boundary() -> None:
    normalized = _normalized(_FILES[1])
    for phrase in (
        "server-owned `HostApplicationId` profiles",
        "The model cannot create, replace, or mutate the configured profile.",
        "never accepts model-selected executable paths",
        "generic command-line escape hatch",
        "uncertainty after effect admission becomes an indeterminate outcome",
    ):
        assert phrase in normalized


def test_native_identity_adr_preserves_public_opacity() -> None:
    normalized = _normalized(_FILES[2])
    for phrase in (
        "opaque Phoenix-owned process and window identities",
        "Native PID/HWND values remain adapter-private implementation details.",
        "do not become public policy resource names",
        "bound to one configured host and finite host epoch",
        "fail closed rather than being treated as the previously observed Phoenix object",
    ):
        assert phrase in normalized


def test_ui_toctou_adr_preserves_immediate_fail_closed_revalidation() -> None:
    normalized = _normalized(_FILES[3])
    for phrase in (
        "immediately before the effect",
        "fails closed rather than retargeting another window",
        "grants no keyboard or mouse authority",
        "never widens into force-kill or arbitrary process termination",
        "indeterminate and are not transparently retried",
    ):
        assert phrase in normalized
