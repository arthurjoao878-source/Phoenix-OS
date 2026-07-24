from __future__ import annotations

from pathlib import Path

from phoenix_os.control_plane import DashboardAssets

_ROOT = Path(__file__).resolve().parents[1]
_RFC = _ROOT / "docs" / "rfcs" / "RFC-0024-durable-signed-webhooks-and-event-subscriptions.md"


def _asset(path: str) -> str:
    asset = DashboardAssets().get(path)
    assert asset is not None
    return asset.body.decode("utf-8")


def test_dashboard_packages_webhook_administration_assets() -> None:
    assets = DashboardAssets()
    assert {
        "/dashboard/",
        "/dashboard/app.css",
        "/dashboard/app.js",
    } <= set(assets.paths())


def test_dashboard_contains_webhook_health_card() -> None:
    html = _asset("/dashboard/")
    assert 'id="webhooks-card"' in html
    assert 'id="webhooks-subscriptions-total"' in html
    assert 'id="webhooks-summary"' in html


def test_dashboard_contains_subscription_administration_form() -> None:
    html = _asset("/dashboard/")
    assert 'id="create-webhook-subscription-form"' in html
    for field in (
        "webhook-name",
        "webhook-display-name",
        "webhook-event-types",
        "webhook-endpoint-url",
        "webhook-egress-policy",
        "webhook-secret-name",
        "webhook-secret-namespace",
        "webhook-secret-version",
    ):
        assert f'id="{field}"' in html


def test_dashboard_contains_safe_subscription_and_delivery_tables() -> None:
    html = _asset("/dashboard/")
    assert 'id="webhook-subscriptions-table"' in html
    assert 'id="webhook-deliveries-table"' in html
    assert "Canonical bodies, signatures, raw responses" in html


def test_dashboard_gates_webhooks_by_exact_permissions() -> None:
    javascript = _asset("/dashboard/app.js")
    permissions = {
        "webhook.subscription.read",
        "webhook.subscription.create",
        "webhook.subscription.update",
        "webhook.subscription.disable",
        "webhook.subscription.enable",
        "webhook.subscription.revoke",
        "webhook.subscription.rotate",
        "webhook.delivery.read",
        "webhook.delivery.redrive",
        "webhook.health.read",
    }
    for permission in permissions:
        assert permission in javascript


def test_dashboard_uses_only_control_plane_webhook_routes() -> None:
    javascript = _asset("/dashboard/app.js")
    assert "/v1/control-plane/webhooks/health" in javascript
    assert "/v1/control-plane/webhooks/subscriptions" in javascript
    assert "/v1/control-plane/webhooks/deliveries" in javascript
    assert "http://127.0.0.1" not in javascript
    assert "https://api." not in javascript


def test_dashboard_uses_reviewed_step_up_actions() -> None:
    javascript = _asset("/dashboard/app.js")
    actions = {
        "create-webhook-subscription",
        "update-webhook-subscription",
        "enable-webhook-subscription",
        "revoke-webhook-subscription",
        "rotate-webhook-signing-key",
        "redrive-webhook-delivery",
    }
    for action in actions:
        assert action in javascript


def test_dashboard_mutations_reuse_csrf_protected_operator_command() -> None:
    javascript = _asset("/dashboard/app.js")
    assert "async function operatorCommand(" in javascript
    assert '"X-Phoenix-CSRF": state.csrf' in javascript
    assert "createWebhookSubscription" in javascript
    assert "redriveWebhookDelivery" in javascript
    assert "operatorCommand(" in javascript


def test_dashboard_displays_endpoint_digest_not_protected_path() -> None:
    javascript = _asset("/dashboard/app.js")
    assert "item.endpoint.path_sha256" in javascript
    assert "item.endpoint.url" not in javascript
    assert "item.endpoint.path)" not in javascript


def test_dashboard_never_renders_signing_reference_or_delivery_body() -> None:
    javascript = _asset("/dashboard/app.js")
    forbidden = (
        "item.signing.secret_name",
        "item.signing.secret_namespace",
        "item.canonical_body",
        "item.signature",
        "item.response_body",
        "item.internal_exception",
    )
    for expression in forbidden:
        assert expression not in javascript


def test_dashboard_webhook_refresh_degrades_independently() -> None:
    javascript = _asset("/dashboard/app.js")
    assert "async function refreshWebhooks()" in javascript
    assert "Webhook health unavailable" in javascript
    assert "Webhook subscriptions unavailable" in javascript
    assert "Webhook deliveries unavailable" in javascript
    assert "await refreshWebhooks();" in javascript


def test_dashboard_disconnect_clears_webhook_views() -> None:
    javascript = _asset("/dashboard/app.js")
    assert 'byId("webhooks-card").classList.add("hidden")' in javascript
    assert 'byId("webhook-subscriptions-table").replaceChildren()' in javascript
    assert 'byId("webhook-deliveries-table").replaceChildren()' in javascript
    assert "state.webhookSubscriptions = new Map()" in javascript


def test_dashboard_webhook_form_is_responsive() -> None:
    css = _asset("/dashboard/app.css")
    assert ".webhook-form {" in css
    assert ".webhook-form .checkbox-field input" in css
    assert "grid-template-columns: repeat(3" in css
    assert "grid-template-columns: 1fr" in css


def test_dashboard_keeps_same_origin_packaged_assets() -> None:
    html = _asset("/dashboard/")
    assert 'src="/dashboard/app.js"' in html
    assert 'href="/dashboard/app.css"' in html
    assert 'src="https://' not in html
    assert 'href="https://' not in html
    assert 'src="http://' not in html
    assert 'href="http://' not in html


def test_rfc_marks_dashboard_administration_complete() -> None:
    rfc = _RFC.read_text(encoding="utf-8")
    assert "- [x] Dashboard subscription and delivery administration" in rfc
    assert "The dependency-free Dashboard now exposes" in rfc
