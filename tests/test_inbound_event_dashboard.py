from __future__ import annotations

from pathlib import Path

from phoenix_os.control_plane import DashboardAssets

_ROOT = Path(__file__).resolve().parents[1]
_RFC = (
    _ROOT / "docs" / "rfcs" / "RFC-0025-secure-inbound-event-gateway-and-external-event-sources.md"
)


def _asset(path: str) -> str:
    asset = DashboardAssets().get(path)
    assert asset is not None
    return asset.body.decode("utf-8")


def test_dashboard_contains_inbound_health_card() -> None:
    html = _asset("/dashboard/")
    assert 'id="inbound-card"' in html
    assert 'id="inbound-sources-total"' in html
    assert 'id="inbound-summary"' in html


def test_dashboard_contains_disabled_source_creation_form() -> None:
    html = _asset("/dashboard/")
    assert 'id="create-inbound-source-form"' in html
    for field in (
        "inbound-name",
        "inbound-display-name",
        "inbound-event-types",
        "inbound-secret-name",
        "inbound-secret-namespace",
        "inbound-secret-version",
        "inbound-max-body-bytes",
        "inbound-max-concurrency",
        "inbound-requests-per-minute",
        "inbound-max-attempts",
    ):
        assert f'id="{field}"' in html
    assert "Create disabled source" in html


def test_dashboard_contains_safe_source_event_and_receipt_views() -> None:
    html = _asset("/dashboard/")
    assert 'id="inbound-sources-table"' in html
    assert 'id="inbound-events-table"' in html
    assert 'id="inbound-receipt-status"' in html
    assert "Normalized payloads, protected digests" in html


def test_dashboard_gates_inbound_operations_by_exact_permissions() -> None:
    javascript = _asset("/dashboard/app.js")
    permissions = {
        "inbound_event.source.read",
        "inbound_event.source.create",
        "inbound_event.source.update",
        "inbound_event.source.disable",
        "inbound_event.source.enable",
        "inbound_event.source.revoke",
        "inbound_event.source.rotate",
        "inbound_event.event.read",
        "inbound_event.receipt.read",
        "inbound_event.dead_letter.redrive",
        "inbound_event.health.read",
    }
    for permission in permissions:
        assert permission in javascript


def test_dashboard_uses_only_control_plane_inbound_routes() -> None:
    javascript = _asset("/dashboard/app.js")
    assert "/v1/control-plane/inbound/health" in javascript
    assert "/v1/control-plane/inbound/sources" in javascript
    assert "/v1/control-plane/inbound/events" in javascript
    assert "/v1/control-plane/inbound/receipts" in javascript
    assert '"/v1/inbound/' not in javascript


def test_dashboard_uses_reviewed_inbound_step_up_actions() -> None:
    javascript = _asset("/dashboard/app.js")
    for action in {
        "create-inbound-source",
        "update-inbound-source",
        "enable-inbound-source",
        "revoke-inbound-source",
        "rotate-inbound-hmac-key",
        "redrive-inbound-event",
    }:
        assert action in javascript


def test_dashboard_never_reads_protected_event_or_secret_fields() -> None:
    javascript = _asset("/dashboard/app.js")
    for expression in (
        "item.normalized_payload",
        "item.normalized_payload_sha256",
        "item.authentication.secret_ref",
        "item.authentication.secret_name",
        "item.authentication.secret_namespace",
        "item.signature",
        "item.authorization",
        "item.internal_exception",
    ):
        assert expression not in javascript


def test_dashboard_inbound_refresh_degrades_independently() -> None:
    javascript = _asset("/dashboard/app.js")
    assert "async function refreshInbound()" in javascript
    assert "Inbound health unavailable" in javascript
    assert "Inbound sources unavailable" in javascript
    assert "Inbound events unavailable" in javascript
    assert "await refreshInbound();" in javascript


def test_dashboard_disconnect_clears_inbound_views() -> None:
    javascript = _asset("/dashboard/app.js")
    assert 'byId("inbound-card").classList.add("hidden")' in javascript
    assert 'byId("inbound-sources-table").replaceChildren()' in javascript
    assert 'byId("inbound-events-table").replaceChildren()' in javascript
    assert "state.inboundSources = new Map()" in javascript


def test_dashboard_inbound_form_is_responsive() -> None:
    css = _asset("/dashboard/app.css")
    assert ".inbound-form {" in css
    assert "grid-template-columns: repeat(3" in css
    assert "grid-template-columns: 1fr" in css


def test_rfc_marks_dashboard_inbound_administration_complete() -> None:
    rfc = _RFC.read_text(encoding="utf-8")
    assert "- [x] Dashboard source, receipt, history, and dead-letter administration" in rfc
    assert "The dependency-free Dashboard now exposes inbound" in rfc
