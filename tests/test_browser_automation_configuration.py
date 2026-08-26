import json

import pytest

from phoenix_os.browser_automation import (
    BrowserAutomationConfiguration,
    BrowserDestinationMode,
    BrowserProfileId,
    browser_automation_configuration_json,
    decode_browser_automation_configuration,
    encode_browser_automation_configuration,
)


def _mapping() -> dict[str, object]:
    return {
        "enabled": True,
        "profiles": [
            {
                "profile_id": "docs",
                "generation": 1,
                "adapter_id": "deterministic.fake",
                "allowed_origins": [
                    {"mode": "hosted_https", "host": "docs.example.com", "port": 443}
                ],
                "network_policy": {
                    "allow_public_networks": True,
                    "allowed_networks": [],
                },
                "initial_targets": [
                    {
                        "target_id": "home",
                        "origin": {
                            "mode": "hosted_https",
                            "host": "docs.example.com",
                            "port": 443,
                        },
                        "request_target": "/",
                    }
                ],
                "limits": {"max_redirects": 3, "session_ttl_seconds": 120.0},
            }
        ],
    }


def test_omitted_browser_configuration_is_disabled_and_creates_no_profile() -> None:
    configuration = decode_browser_automation_configuration(None)

    assert configuration == BrowserAutomationConfiguration()
    assert configuration.enabled is False
    assert configuration.profiles == ()
    assert configuration.catalog is None


def test_strict_configuration_decodes_server_owned_profile_without_url_or_script_fields() -> None:
    configuration = decode_browser_automation_configuration(_mapping())

    assert configuration.enabled is True
    assert configuration.catalog is not None
    profile = configuration.catalog.require_profile(BrowserProfileId("docs"))
    assert profile.allowed_origins[0].mode is BrowserDestinationMode.HOSTED_HTTPS
    assert profile.javascript_enabled is False
    assert profile.max_pages_per_session == 1


def test_configuration_rejects_unknown_escape_hatch_fields_instead_of_ignoring_them() -> None:
    for key, value in (
        ("javascript_enabled", True),
        ("proxy", "http://127.0.0.1:8080"),
        ("browser_executable", "C:/browser.exe"),
        ("url", "https://evil.example/"),
    ):
        mapping = _mapping()
        profile = mapping["profiles"][0]  # type: ignore[index]
        profile[key] = value
        with pytest.raises(ValueError, match="unknown keys"):
            decode_browser_automation_configuration(mapping)


def test_configuration_rejects_enabled_without_profiles() -> None:
    with pytest.raises(ValueError, match="requires at least one profile"):
        decode_browser_automation_configuration({"enabled": True, "profiles": []})


def test_configuration_round_trip_and_json_serialization_are_deterministic() -> None:
    configuration = decode_browser_automation_configuration(_mapping())
    encoded = encode_browser_automation_configuration(configuration)
    rebuilt = decode_browser_automation_configuration(encoded)

    assert rebuilt == configuration
    first = browser_automation_configuration_json(configuration)
    second = browser_automation_configuration_json(rebuilt)
    assert first == second
    assert json.loads(first) == encoded
    assert "javascript_enabled" not in first
    assert "browser_executable" not in first
