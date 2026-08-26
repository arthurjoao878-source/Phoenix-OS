from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_RFC = (
    _ROOT / "docs" / "rfcs" / "RFC-0035-secure-browser-automation-and-controlled-web-interaction.md"
)


def test_rfc0035_is_draft_for_v035_with_frozen_browser_boundaries() -> None:
    text = _RFC.read_text(encoding="utf-8")

    assert "- Status: Draft" in text
    assert "- Target release: Phoenix OS v0.35.0" in text
    assert "- Architecture freeze: 2026-08-25" in text
    assert "Web content is data. Browser state is data." in text
    assert "There is no generic `browser.execute`." in text
    assert "JavaScript is disabled unconditionally" in text


def test_rfc0035_keeps_browser_network_tool_and_workspace_authority_independent() -> None:
    text = _RFC.read_text(encoding="utf-8")

    assert "Browser authority is independent of `tool.invoke`, `network.http.request`" in text
    assert "browser transfer authority remains intersected with the exact RFC-0031" in text
    assert "Browser results remain untrusted tool data" in text


def test_rfc0035_slice1_is_contract_only_without_authority_or_remote_effect() -> None:
    text = _RFC.read_text(encoding="utf-8")

    assert "### S1 — Browser contracts and immutable profiles" in text
    assert "No browser action enters the" in text
    assert "authority catalog yet and no remote effect occurs." in text


def test_rfc0035_freeze_forbids_scope_expansion_without_re_review() -> None:
    text = _RFC.read_text(encoding="utf-8")

    assert "one page per session, no downloads/uploads" in text
    assert "exact stale-safe session/page/revision/element identity remains mandatory" in text
    assert "requires architecture" in text
    assert "re-review before code proceeds" in text


def test_rfc0035_slice7_requires_runtime_observability_administration_hardening() -> None:
    text = _RFC.read_text(encoding="utf-8")

    assert (
        "### S7 — Runtime lifecycle, observability, administration, and release hardening" in text
    )
    assert "Add optional Runtime ownership, bounded shutdown, content-free observations" in text
    assert "separately authorized" in text
    assert (
        "Runtime lifecycle state controls availability only and does not grant browser authority."
        in text
    )


def test_rfc0035_s7_release_hardening_is_wired_without_s8_metadata() -> None:
    text = _RFC.read_text(encoding="utf-8")

    assert "ADR-0064 through ADR-0067" in text
    assert "python scripts/check_browser_automation_release.py" in text
    assert "`browser.health.read`" in text
    assert "isolated offline installed smoke behavior" in text
    assert "S7 does not update package version" in text
    assert "Those remain S8-only finalization work" in text
