from __future__ import annotations

from phoenix_os.control_plane import DashboardAssets


def _asset_text(path: str) -> str:
    asset = DashboardAssets().get(path)
    assert asset is not None
    return asset.body.decode("utf-8")


def test_dashboard_exposes_content_free_inference_administration_shell() -> None:
    html = _asset_text("/dashboard/")

    expected_ids = (
        "inference-card",
        "inference-providers-total",
        "inference-summary",
        "inference-providers-panel",
        "inference-providers-page",
        "inference-status",
        "inference-providers-table",
        "inference-models-panel",
        "inference-models-page",
        "inference-model-status",
        "inference-models-table",
    )

    for element_id in expected_ids:
        assert f'id="{element_id}"' in html

    inference_html = html.split(
        'id="inference-providers-panel"',
        1,
    )[1].split(
        '<article class="panel wide">',
        1,
    )[0]

    assert "Prompts, responses, credentials, endpoint URLs" in inference_html
    assert "provider_model_name" not in inference_html
    assert "credential_ref" not in inference_html
    assert "secret_name" not in inference_html
    assert "<script>" not in html
    assert " style=" not in html


def test_dashboard_reads_content_free_inference_health_and_inventory() -> None:
    javascript = _asset_text("/dashboard/app.js")

    expected = (
        "function renderInferenceHealth(snapshot)",
        "function renderInferenceProviders(page)",
        "function renderInferenceModels(page)",
        "async function refreshInference()",
        "/v1/control-plane/inference/health",
        "/v1/control-plane/inference/providers?limit=200",
        "/v1/control-plane/inference/models?limit=200",
        "inference.health.read",
        "inference.provider.read",
        "inference.model.read",
    )

    for fragment in expected:
        assert fragment in javascript

    inference_javascript = javascript.split(
        "// RFC-0026 Slice 5C",
        1,
    )[1].split(
        "// End RFC-0026 Slice 5C",
        1,
    )[0]

    forbidden = (
        "provider_model_name",
        "credential_ref",
        "secret_name",
        "secret_namespace",
        "prompt_text",
        "response_text",
        "raw_exception",
        "endpoint_url",
    )

    for fragment in forbidden:
        assert fragment not in inference_javascript

    assert "innerHTML" not in javascript
    assert "eval(" not in javascript
    assert "localStorage" not in javascript
    assert "sessionStorage" not in javascript


def test_dashboard_manages_inference_lifecycle_with_exact_protection() -> None:
    javascript = _asset_text("/dashboard/app.js")

    expected = (
        "async function inferenceLifecycle(kind, item, action)",
        "inference.provider.disable",
        "inference.provider.enable",
        "inference.model.disable",
        "inference.model.enable",
        "enable-inference-provider",
        "enable-inference-model",
        "expected_revision: item.revision",
        "await operatorCommand(",
        "await refreshInference();",
    )

    for fragment in expected:
        assert fragment in javascript

    inference_javascript = javascript.split(
        "// RFC-0026 Slice 5C",
        1,
    )[1].split(
        "// End RFC-0026 Slice 5C",
        1,
    )[0]

    assert "X-Phoenix-CSRF" not in inference_javascript
    assert "X-Phoenix-Step-Up" not in inference_javascript
    assert "operatorCommand(" in inference_javascript
    assert javascript.count("async function refreshInference()") == 1
    assert javascript.count("async function inferenceLifecycle(") == 1


def test_dashboard_hides_optional_inference_when_unavailable() -> None:
    javascript = _asset_text("/dashboard/app.js")

    expected = (
        "function hideInferenceDashboard()",
        'if (error.message === "not_found")',
        "hideInferenceDashboard();",
        'byId("inference-card").classList.add("hidden")',
        'byId("inference-providers-table").replaceChildren()',
        'byId("inference-models-table").replaceChildren()',
    )

    for fragment in expected:
        assert fragment in javascript
