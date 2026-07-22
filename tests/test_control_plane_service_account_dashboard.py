from __future__ import annotations

from phoenix_os.control_plane import DashboardAssets


def test_dashboard_exposes_service_account_management_shell() -> None:
    asset = DashboardAssets().get("/dashboard/")

    assert asset is not None

    html = asset.body.decode("utf-8")

    expected_ids = (
        "service-accounts-panel",
        "create-service-account-form",
        "service-account-name",
        "service-account-display-name",
        "create-service-account-submit",
        "service-accounts-table",
        "service-account-tokens-panel",
        "service-account-tokens-title",
        "close-service-account-tokens",
        "issue-api-token-form",
        "api-token-label",
        "api-token-expires-at",
        "api-token-scopes",
        "api-token-resources",
        "api-token-networks",
        "api-token-mtls-sha256",
        "issue-api-token-submit",
        "api-token-output",
        "api-tokens-table",
    )

    for element_id in expected_ids:
        assert f'id="{element_id}"' in html

    assert "A newly issued or rotated token appears here once." in html
    assert "token_digest" not in html
    assert "<script>" not in html
    assert " style=" not in html


def test_dashboard_packages_service_account_styles() -> None:
    asset = DashboardAssets().get("/dashboard/app.css")

    assert asset is not None

    css = asset.body.decode("utf-8")

    assert ".service-account-form {" in css
    assert ".api-token-form {" in css
    assert ".service-account-form label" in css


def test_dashboard_reads_service_accounts_without_browser_secrets() -> None:
    asset = DashboardAssets().get("/dashboard/app.js")

    assert asset is not None

    javascript = asset.body.decode("utf-8")

    expected = (
        "selectedServiceAccount: null",
        "function renderServiceAccounts(page)",
        "function renderApiTokens(page)",
        "function refreshServiceAccounts()",
        "function refreshSelectedServiceAccountTokens()",
        "/v1/control-plane/service-accounts?limit=200",
        "control-plane.service-accounts.read",
        'credentials: "same-origin"',
    )

    for fragment in expected:
        assert fragment in javascript

    assert "serviceAccountToken" not in javascript
    assert "apiTokenSecret" not in javascript
    assert "localStorage" not in javascript
    assert "sessionStorage" not in javascript
    assert "innerHTML" not in javascript
    assert "eval(" not in javascript


def test_dashboard_service_account_labels_preserve_utf8_symbols() -> None:
    asset = DashboardAssets().get("/dashboard/app.js")

    assert asset is not None

    javascript = asset.body.decode("utf-8")
    dash = chr(0x2014)
    middle_dot = chr(0x00B7)

    renderer = javascript.split(
        "function renderApiTokens(page) {",
        1,
    )[1].split(
        "\nfunction localDateTimeValue",
        1,
    )[0]

    assert f'item.scopes.join(", ") || "{dash}"' in renderer
    assert f'item.resources.join(", ") || "{dash}"' in renderer
    assert f'actions.textContent = "{dash}";' in renderer

    open_function = javascript.split(
        "async function openServiceAccountTokens(account) {",
        1,
    )[1].split(
        "\nasync function refreshServiceAccounts",
        1,
    )[0]

    assert f"`API tokens {middle_dot} ${{account.display_name}}`" in open_function

    assert 'item.scopes.join(", ") || "?"' not in renderer
    assert 'item.resources.join(", ") || "?"' not in renderer
    assert 'actions.textContent = "?";' not in renderer
    assert "`API tokens ? ${account.display_name}`" not in open_function

    assert chr(0xFFFD) not in javascript
    assert "\u00e2\u20ac\u201d" not in javascript
    assert "\u00c2\u00b7" not in javascript


def test_dashboard_manages_service_account_lifecycle_with_exact_permissions() -> None:
    asset = DashboardAssets().get("/dashboard/app.js")

    assert asset is not None

    javascript = asset.body.decode("utf-8")

    expected = (
        "async function createServiceAccount(event)",
        "async function updateServiceAccount(item)",
        "async function serviceAccountLifecycle(",
        "control-plane.service-accounts.create",
        "control-plane.service-accounts.update",
        "control-plane.service-accounts.disable",
        "control-plane.service-accounts.revoke",
        "enable-service-account",
        "revoke-service-account",
        "/v1/control-plane/service-accounts",
        "/update",
        "${item.service_account_id}/${action}",
        '"submit",\n  createServiceAccount,',
    )

    for fragment in expected:
        assert fragment in javascript

    assert javascript.count("async function createServiceAccount(event)") == 1

    assert javascript.count("async function updateServiceAccount(item)") == 1

    assert javascript.count("async function serviceAccountLifecycle(") == 1

    assert "innerHTML" not in javascript
    assert "eval(" not in javascript
    assert "localStorage" not in javascript
    assert "sessionStorage" not in javascript


def test_dashboard_issues_api_tokens_without_persisting_plaintext() -> None:
    asset = DashboardAssets().get("/dashboard/app.js")

    assert asset is not None

    javascript = asset.body.decode("utf-8")

    expected = (
        "function multilineFieldValues(elementId)",
        "function apiTokenRestrictionFromForm()",
        "function updateApiTokenIssueAvailability()",
        "async function issueApiToken(event)",
        "control-plane.api-tokens.issue",
        "/issue-token",
        '"issue-api-token"',
        "allowed_client_networks",
        "mutual_tls_certificate_sha256",
        "grant.metadata.label",
        "grant.token",
        '"submit",\n  issueApiToken,',
    )

    for fragment in expected:
        assert fragment in javascript

    assert javascript.count("async function issueApiToken(event)") == 1

    forbidden = (
        "state.apiToken",
        "state.serviceAccountToken",
        "state.tokenSecret",
        "localStorage",
        "sessionStorage",
        "innerHTML",
        "eval(",
    )

    for fragment in forbidden:
        assert fragment not in javascript


def test_dashboard_rotates_api_tokens_with_exact_step_up() -> None:
    asset = DashboardAssets().get("/dashboard/app.js")

    assert asset is not None

    javascript = asset.body.decode("utf-8")

    expected = (
        "async function rotateApiToken(item)",
        "control-plane.api-tokens.rotate",
        "${item.token_id}/rotate",
        "expected_revision: item.revision",
        "expires_at: expiresAt.toISOString()",
        "overlap_seconds: overlapSeconds",
        '"rotate-api-token"',
        "grant.metadata.label",
        "grant.token",
        "() => rotateApiToken(item)",
    )

    for fragment in expected:
        assert fragment in javascript

    assert javascript.count("async function rotateApiToken(item)") == 1

    assert javascript.count("() => rotateApiToken(item)") == 1

    rotation = javascript.split(
        "async function rotateApiToken(item) {",
        1,
    )[1].split(
        "\nasync function issueApiToken(event) {",
        1,
    )[0]

    assert 'item.status !== "active"' in rotation
    assert "expected_revision: item.revision" in rotation
    assert "overlap_seconds: overlapSeconds" in rotation
    assert '"rotate-api-token"' in rotation

    forbidden = (
        "state.apiToken",
        "state.serviceAccountToken",
        "state.tokenSecret",
        "localStorage",
        "sessionStorage",
        "innerHTML",
        "eval(",
    )

    for fragment in forbidden:
        assert fragment not in javascript


def test_dashboard_revokes_active_api_tokens_with_exact_step_up() -> None:
    asset = DashboardAssets().get("/dashboard/app.js")

    assert asset is not None

    javascript = asset.body.decode("utf-8")

    expected = (
        "async function revokeApiToken(item)",
        "control-plane.api-tokens.revoke",
        "${item.token_id}/revoke",
        "expected_revision: item.revision",
        '"revoke-api-token"',
        "revoked.label",
        "revoked.status",
        "() => revokeApiToken(item)",
    )

    for fragment in expected:
        assert fragment in javascript

    assert javascript.count("async function revokeApiToken(item)") == 1

    assert javascript.count("() => revokeApiToken(item)") == 1

    revocation = javascript.split(
        "async function revokeApiToken(item) {",
        1,
    )[1].split(
        "\nasync function rotateApiToken(item) {",
        1,
    )[0]

    assert 'item.status !== "active"' in revocation
    assert "expected_revision: item.revision" in revocation
    assert '"revoke-api-token"' in revocation
    assert "grant.token" not in revocation

    renderer = javascript.split(
        "function renderApiTokens(page) {",
        1,
    )[1].split(
        "\nfunction localDateTimeValue(value) {",
        1,
    )[0]

    assert 'item.status === "active"' in renderer
    assert "control-plane.api-tokens.revoke" in renderer
    assert "() => revokeApiToken(item)" in renderer

    forbidden = (
        "state.apiToken",
        "state.serviceAccountToken",
        "state.tokenSecret",
        "localStorage",
        "sessionStorage",
        "innerHTML",
        "eval(",
    )

    for fragment in forbidden:
        assert fragment not in javascript
