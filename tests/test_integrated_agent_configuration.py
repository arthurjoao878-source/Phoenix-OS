from typing import cast

import pytest

from phoenix_os.integrated_agent import (
    IntegratedAgentConfiguration,
    IntegratedDownstreamBoundary,
    decode_integrated_agent_configuration,
    encode_integrated_agent_configuration,
)


def _configuration_mapping() -> dict[str, object]:
    return {
        "enabled": True,
        "profiles": [
            {
                "profile_id": "supplier-research",
                "generation": 3,
                "agent_id": "research-agent",
                "tool_bindings": [
                    {
                        "kind": "local_transform",
                        "tool_id": "integrated.plan.update",
                        "transform_id": "integrated.plan.update",
                        "advisory_state_keys": ["plan"],
                    },
                    {
                        "kind": "downstream_bridge",
                        "tool_id": "research.supplier",
                        "boundary": "browser",
                        "binding_id": "browser:profile/supplier-research",
                        "generation": 4,
                        "action_family": "browser.research",
                    },
                ],
                "browser_profile_binding": {
                    "boundary": "browser",
                    "binding_id": "browser:profile/supplier-research",
                    "generation": 4,
                },
                "data_flow_routes": [
                    {
                        "route_id": "browser-model",
                        "source_kind": "browser",
                        "sink": "model",
                        "disposition": "allow",
                        "requires_audience_match": False,
                    },
                    {
                        "route_id": "browser-result",
                        "source_kind": "browser",
                        "sink": "user_result",
                        "disposition": "allow",
                        "requires_audience_match": True,
                    },
                ],
                "durability_profile": None,
                "enabled": True,
            }
        ],
    }


def _first_profile(value: dict[str, object]) -> dict[str, object]:
    raw_profiles = value["profiles"]
    if not isinstance(raw_profiles, list) or not raw_profiles:
        raise AssertionError("expected one profile mapping")
    raw_profile = raw_profiles[0]
    if not isinstance(raw_profile, dict):
        raise AssertionError("expected profile mapping")
    return cast(dict[str, object], raw_profile)


def _second_tool(profile: dict[str, object]) -> dict[str, object]:
    raw_tools = profile["tool_bindings"]
    if not isinstance(raw_tools, list) or len(raw_tools) < 2:
        raise AssertionError("expected two tool binding mappings")
    raw_tool = raw_tools[1]
    if not isinstance(raw_tool, dict):
        raise AssertionError("expected tool binding mapping")
    return cast(dict[str, object], raw_tool)


def test_integrated_execution_is_disabled_by_default_and_creates_no_profile_catalog() -> None:
    configuration = IntegratedAgentConfiguration()
    assert configuration.enabled is False
    assert configuration.profiles == ()
    assert configuration.catalog is None

    decoded = decode_integrated_agent_configuration({})
    assert decoded == configuration
    assert decode_integrated_agent_configuration(None) == configuration


def test_strict_configuration_round_trip_binds_tool_and_capability_profiles() -> None:
    configuration = decode_integrated_agent_configuration(_configuration_mapping())
    assert configuration.enabled is True
    assert len(configuration.profiles) == 1

    profile = configuration.profiles[0]
    browser = profile.require_capability_binding(IntegratedDownstreamBoundary.BROWSER)
    assert browser.binding_id == "browser:profile/supplier-research"
    assert browser.generation == 4

    encoded = encode_integrated_agent_configuration(configuration)
    decoded_again = decode_integrated_agent_configuration(encoded)
    assert decoded_again == configuration


def test_configuration_rejects_unknown_keys_and_enabled_without_profiles() -> None:
    with pytest.raises(ValueError, match="unknown keys"):
        decode_integrated_agent_configuration({"enabled": False, "unexpected": True})

    with pytest.raises(ValueError, match="at least one profile"):
        decode_integrated_agent_configuration({"enabled": True, "profiles": []})


def test_configuration_rejects_bridge_substitution_and_missing_generation() -> None:
    substituted = _configuration_mapping()
    profile = _first_profile(substituted)
    bridge = _second_tool(profile)
    bridge["binding_id"] = "browser:profile/other"

    with pytest.raises(ValueError, match="does not match"):
        decode_integrated_agent_configuration(substituted)

    missing_generation = _configuration_mapping()
    profile = _first_profile(missing_generation)
    bridge = _second_tool(profile)
    bridge.pop("generation")

    with pytest.raises(ValueError, match="exact profile generation"):
        decode_integrated_agent_configuration(missing_generation)


def test_disabled_configuration_may_hold_reviewed_profiles_without_enabling_execution() -> None:
    value = _configuration_mapping()
    value["enabled"] = False

    configuration = decode_integrated_agent_configuration(value)
    assert configuration.enabled is False
    assert len(configuration.profiles) == 1
    assert configuration.catalog is not None
