from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_MIGRATION = _ROOT / "docs" / "migrations" / "v0.31.0-to-v0.32.0-secure-host-automation.md"


def _normalized() -> str:
    return " ".join(_MIGRATION.read_text(encoding="utf-8").split())


def test_host_automation_migration_is_disabled_first_and_authority_safe() -> None:
    text = _normalized()
    for phrase in (
        "Desktop state is data; host effects require fresh authority.",
        "When no host-automation adapter is supplied to Runtime composition",
        "no principal receives any `host.*` action automatically",
        "migration-free-by-omission upgrade",
        "current host policy immediately wins",
        "`tool.invoke` and `host.*` authorization remain independent",
        "disable-first rollback",
    ):
        assert phrase in text


def test_host_automation_migration_preserves_the_narrow_windows_boundary() -> None:
    text = _normalized()
    for phrase in (
        "Windows is the only concrete v0.32.0 adapter.",
        "server-owned `HostApplicationId`",
        "does not accept a model-selected executable path",
        "`clipboard_read_enabled=False`",
        "`host.app.close` is graceful close only in v0.32.0",
        "grants no keyboard or mouse authority",
        "A package downgrade is not a host-effect rollback mechanism.",
    ):
        assert phrase in text


def test_host_automation_migration_keeps_release_hardening_separate() -> None:
    raw = _MIGRATION.read_text(encoding="utf-8")
    text = " ".join(raw.split())
    assert r".\scripts\check.ps1" in text
    assert "Gate 3 adds migration guidance and its regression test only." in text
    assert "The named host-automation release gate remains the next formal Slice 7 gate" in text
    assert "Windows dogfood" in text
    assert "offline wheel/sdist validation" in text
    assert "package version 0.32.0" in text
    assert "tag, artifacts, and checksums" in text
