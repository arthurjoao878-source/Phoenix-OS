from __future__ import annotations

from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_GUIDE = _ROOT / "docs" / "migrations" / "v0.23.0-to-v0.24.0-webhooks.md"
_RFC = _ROOT / "docs" / "rfcs" / "RFC-0024-durable-signed-webhooks-and-event-subscriptions.md"
_README = _ROOT / "README.md"


def _guide() -> str:
    return _GUIDE.read_text(encoding="utf-8")


def test_webhook_migration_guide_is_present_and_linked() -> None:
    assert _GUIDE.is_file()
    readme = _README.read_text(encoding="utf-8")
    assert "docs/migrations/v0.23.0-to-v0.24.0-webhooks.md" in readme


def test_webhook_migration_guide_covers_compatibility() -> None:
    guide = _guide()
    assert "`webhooks_enabled=True`" in guide
    assert "Existing Event Bus subscribers are not converted" in guide
    assert "webhook options require webhooks_enabled" in guide
    assert "conditional keyword arguments" in guide


def test_webhook_migration_guide_covers_security_boundaries() -> None:
    guide = _guide()
    required = (
        "reviewed event serializer",
        "exact versioned signing secret",
        "WebhookEgressPolicy",
        "DNS and destination addresses",
        "constant time",
        "deduplicate by `X-Phoenix-Webhook-Id`",
        "Do not grant `*`",
    )
    for phrase in required:
        assert phrase in guide


def test_webhook_migration_guide_covers_persistence() -> None:
    guide = _guide()
    assert "with a default `StateStore`" in guide
    assert "without a State Store" in guide
    assert "In-memory repositories lose subscriptions" in guide
    assert "Do not delete webhook repository namespaces" in guide


def test_webhook_migration_guide_covers_administration_modes() -> None:
    guide = _guide()
    assert "## Step 8: enable human administration" in guide
    assert "## Step 9: optionally enable service-account administration" in guide
    assert "webhook_service_account_administration_enabled=True" in guide
    assert "Browser cookies, CSRF proofs" in guide


def test_webhook_migration_guide_has_safe_rollout_and_rollback() -> None:
    guide = _guide()
    assert "## Recommended rollout" in guide
    assert "## Rollback" in guide
    assert "Disable every active subscription" in guide
    assert "Preserve the State Store records" in guide
    assert "Do not revoke or delete a signing-key version" in guide


def test_webhook_migration_guide_contains_no_placeholder_secret() -> None:
    guide = _guide()
    forbidden = (
        'secret = "',
        'password = "',
        'api_key = "',
        "allow_insecure_loopback=True",
    )
    for phrase in forbidden:
        assert phrase not in guide


def test_rfc_marks_migration_guidance_complete() -> None:
    rfc = _RFC.read_text(encoding="utf-8")
    assert "- [x] Migration guidance" in rfc
    assert "v0.23.0-to-v0.24.0-webhooks.md" in rfc
