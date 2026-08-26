"""Strict deterministic mapping codec for server-owned RFC-0035 browser configuration."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import cast

from phoenix_os.browser_automation.contracts import (
    BrowserAdapterId,
    BrowserNavigationTargetId,
    BrowserProfileId,
)
from phoenix_os.browser_automation.profiles import (
    BrowserDestinationMode,
    BrowserNavigationTarget,
    BrowserNetworkPolicy,
    BrowserOrigin,
    BrowserProfile,
    BrowserProfileCatalog,
    BrowserProfileLimits,
)

_CONFIG_KEYS = frozenset({"enabled", "profiles"})
_PROFILE_KEYS = frozenset(
    {
        "profile_id",
        "generation",
        "adapter_id",
        "allowed_origins",
        "initial_targets",
        "network_policy",
        "limits",
    }
)
_ORIGIN_KEYS = frozenset({"mode", "host", "port"})
_TARGET_KEYS = frozenset({"target_id", "origin", "request_target"})
_NETWORK_POLICY_KEYS = frozenset({"allow_public_networks", "allowed_networks"})
_LIMIT_KEYS = frozenset(
    {
        "max_snapshot_title_chars",
        "max_snapshot_text_chars",
        "max_snapshot_text_bytes",
        "max_snapshot_elements",
        "max_element_name_chars",
        "max_element_value_chars",
        "max_fill_text_chars",
        "max_fill_text_bytes",
        "max_cookies",
        "max_cookie_bytes",
        "max_resolved_addresses",
        "max_redirects",
        "session_ttl_seconds",
        "operation_timeout_seconds",
        "max_concurrent_sessions",
    }
)


def _mapping(value: object, *, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise TypeError(f"{label} must be a mapping")
    if any(not isinstance(key, str) for key in value):
        raise TypeError(f"{label} keys must be strings")
    return cast(Mapping[str, object], value)


def _sequence(value: object, *, label: str) -> Sequence[object]:
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(value, Sequence):
        raise TypeError(f"{label} must be a sequence")
    return cast(Sequence[object], value)


def _require_exact_keys(
    value: Mapping[str, object],
    *,
    allowed: frozenset[str],
    required: frozenset[str],
    label: str,
) -> None:
    unknown = set(value) - allowed
    missing = required - set(value)
    if unknown:
        raise ValueError(f"{label} contains unknown keys: {', '.join(sorted(unknown))}")
    if missing:
        raise ValueError(f"{label} is missing required keys: {', '.join(sorted(missing))}")


def _bool(value: object, *, label: str) -> bool:
    if not isinstance(value, bool):
        raise TypeError(f"{label} must be a boolean")
    return value


def _int(value: object, *, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{label} must be an integer")
    return value


def _number(value: object, *, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{label} must be numeric")
    return float(value)


def _string(value: object, *, label: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{label} must be a string")
    return value


def _optional_int(value: object, *, label: str) -> int | None:
    if value is None:
        return None
    return _int(value, label=label)


def _decode_origin(value: object) -> BrowserOrigin:
    mapping = _mapping(value, label="browser origin")
    _require_exact_keys(
        mapping,
        allowed=_ORIGIN_KEYS,
        required=frozenset({"mode", "host"}),
        label="browser origin",
    )
    return BrowserOrigin(
        mode=BrowserDestinationMode(_string(mapping["mode"], label="browser origin mode")),
        host=_string(mapping["host"], label="browser origin host"),
        port=_optional_int(mapping.get("port"), label="browser origin port"),
    )


def _decode_network_policy(value: object | None) -> BrowserNetworkPolicy:
    if value is None:
        return BrowserNetworkPolicy()
    mapping = _mapping(value, label="browser network policy")
    _require_exact_keys(
        mapping,
        allowed=_NETWORK_POLICY_KEYS,
        required=frozenset(),
        label="browser network policy",
    )
    allow_public = _bool(
        mapping.get("allow_public_networks", True),
        label="allow_public_networks",
    )
    raw_networks = _sequence(mapping.get("allowed_networks", ()), label="allowed_networks")
    networks = tuple(_string(item, label="allowed network") for item in raw_networks)
    return BrowserNetworkPolicy(
        allow_public_networks=allow_public,
        allowed_networks=networks,
    )


def _decode_limits(value: object | None) -> BrowserProfileLimits:
    if value is None:
        return BrowserProfileLimits()
    mapping = _mapping(value, label="browser profile limits")
    _require_exact_keys(
        mapping,
        allowed=_LIMIT_KEYS,
        required=frozenset(),
        label="browser profile limits",
    )
    defaults = BrowserProfileLimits()
    return BrowserProfileLimits(
        max_snapshot_title_chars=_int(
            mapping.get("max_snapshot_title_chars", defaults.max_snapshot_title_chars),
            label="max_snapshot_title_chars",
        ),
        max_snapshot_text_chars=_int(
            mapping.get("max_snapshot_text_chars", defaults.max_snapshot_text_chars),
            label="max_snapshot_text_chars",
        ),
        max_snapshot_text_bytes=_int(
            mapping.get("max_snapshot_text_bytes", defaults.max_snapshot_text_bytes),
            label="max_snapshot_text_bytes",
        ),
        max_snapshot_elements=_int(
            mapping.get("max_snapshot_elements", defaults.max_snapshot_elements),
            label="max_snapshot_elements",
        ),
        max_element_name_chars=_int(
            mapping.get("max_element_name_chars", defaults.max_element_name_chars),
            label="max_element_name_chars",
        ),
        max_element_value_chars=_int(
            mapping.get("max_element_value_chars", defaults.max_element_value_chars),
            label="max_element_value_chars",
        ),
        max_fill_text_chars=_int(
            mapping.get("max_fill_text_chars", defaults.max_fill_text_chars),
            label="max_fill_text_chars",
        ),
        max_fill_text_bytes=_int(
            mapping.get("max_fill_text_bytes", defaults.max_fill_text_bytes),
            label="max_fill_text_bytes",
        ),
        max_cookies=_int(mapping.get("max_cookies", defaults.max_cookies), label="max_cookies"),
        max_cookie_bytes=_int(
            mapping.get("max_cookie_bytes", defaults.max_cookie_bytes),
            label="max_cookie_bytes",
        ),
        max_resolved_addresses=_int(
            mapping.get("max_resolved_addresses", defaults.max_resolved_addresses),
            label="max_resolved_addresses",
        ),
        max_redirects=_int(
            mapping.get("max_redirects", defaults.max_redirects),
            label="max_redirects",
        ),
        session_ttl_seconds=_number(
            mapping.get("session_ttl_seconds", defaults.session_ttl_seconds),
            label="session_ttl_seconds",
        ),
        operation_timeout_seconds=_number(
            mapping.get("operation_timeout_seconds", defaults.operation_timeout_seconds),
            label="operation_timeout_seconds",
        ),
        max_concurrent_sessions=_int(
            mapping.get("max_concurrent_sessions", defaults.max_concurrent_sessions),
            label="max_concurrent_sessions",
        ),
    )


def _decode_profile(value: object) -> BrowserProfile:
    mapping = _mapping(value, label="browser profile")
    _require_exact_keys(
        mapping,
        allowed=_PROFILE_KEYS,
        required=frozenset(
            {"profile_id", "generation", "adapter_id", "allowed_origins", "initial_targets"}
        ),
        label="browser profile",
    )

    origins = tuple(
        _decode_origin(item)
        for item in _sequence(mapping["allowed_origins"], label="allowed_origins")
    )
    targets: list[BrowserNavigationTarget] = []
    for item in _sequence(mapping["initial_targets"], label="initial_targets"):
        target_mapping = _mapping(item, label="browser navigation target")
        _require_exact_keys(
            target_mapping,
            allowed=_TARGET_KEYS,
            required=_TARGET_KEYS,
            label="browser navigation target",
        )
        targets.append(
            BrowserNavigationTarget(
                target_id=BrowserNavigationTargetId(
                    _string(target_mapping["target_id"], label="browser navigation target id")
                ),
                origin=_decode_origin(target_mapping["origin"]),
                request_target=_string(
                    target_mapping["request_target"],
                    label="browser navigation request target",
                ),
            )
        )

    return BrowserProfile(
        profile_id=BrowserProfileId(_string(mapping["profile_id"], label="browser profile id")),
        generation=_int(mapping["generation"], label="browser profile generation"),
        adapter_id=BrowserAdapterId(_string(mapping["adapter_id"], label="browser adapter id")),
        allowed_origins=origins,
        initial_targets=tuple(targets),
        network_policy=_decode_network_policy(mapping.get("network_policy")),
        limits=_decode_limits(mapping.get("limits")),
    )


@dataclass(frozen=True, slots=True)
class BrowserAutomationConfiguration:
    """Top-level opt-in configuration; omission is disabled and creates no profiles."""

    enabled: bool = False
    profiles: tuple[BrowserProfile, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.enabled, bool):
            raise TypeError("enabled must be a boolean")
        profiles = tuple(self.profiles)
        if any(not isinstance(profile, BrowserProfile) for profile in profiles):
            raise TypeError("profiles must contain BrowserProfile values")
        if self.enabled and not profiles:
            raise ValueError("enabled browser automation requires at least one profile")
        if profiles:
            BrowserProfileCatalog(profiles)
        object.__setattr__(self, "profiles", profiles)

    @property
    def catalog(self) -> BrowserProfileCatalog | None:
        if not self.profiles:
            return None
        return BrowserProfileCatalog(self.profiles)


def decode_browser_automation_configuration(
    value: Mapping[str, object] | None,
) -> BrowserAutomationConfiguration:
    """Decode strict server-owned configuration; `None` means disabled by omission."""

    if value is None:
        return BrowserAutomationConfiguration()
    mapping = _mapping(value, label="browser automation configuration")
    _require_exact_keys(
        mapping,
        allowed=_CONFIG_KEYS,
        required=frozenset(),
        label="browser automation configuration",
    )
    enabled = _bool(mapping.get("enabled", False), label="browser automation enabled")
    raw_profiles = mapping.get("profiles", ())
    profiles = tuple(
        _decode_profile(item)
        for item in _sequence(raw_profiles, label="browser automation profiles")
    )
    return BrowserAutomationConfiguration(enabled=enabled, profiles=profiles)


def _origin_mapping(origin: BrowserOrigin) -> dict[str, object]:
    return {
        "host": origin.host,
        "mode": origin.mode.value,
        "port": origin.port,
    }


def _network_policy_mapping(policy: BrowserNetworkPolicy) -> dict[str, object]:
    return {
        "allow_public_networks": policy.allow_public_networks,
        "allowed_networks": list(policy.allowed_networks),
    }


def _limits_mapping(limits: BrowserProfileLimits) -> dict[str, object]:
    return {
        "max_concurrent_sessions": limits.max_concurrent_sessions,
        "max_cookie_bytes": limits.max_cookie_bytes,
        "max_cookies": limits.max_cookies,
        "max_element_name_chars": limits.max_element_name_chars,
        "max_element_value_chars": limits.max_element_value_chars,
        "max_fill_text_bytes": limits.max_fill_text_bytes,
        "max_fill_text_chars": limits.max_fill_text_chars,
        "max_redirects": limits.max_redirects,
        "max_resolved_addresses": limits.max_resolved_addresses,
        "max_snapshot_elements": limits.max_snapshot_elements,
        "max_snapshot_text_bytes": limits.max_snapshot_text_bytes,
        "max_snapshot_text_chars": limits.max_snapshot_text_chars,
        "max_snapshot_title_chars": limits.max_snapshot_title_chars,
        "operation_timeout_seconds": limits.operation_timeout_seconds,
        "session_ttl_seconds": limits.session_ttl_seconds,
    }


def _profile_mapping(profile: BrowserProfile) -> dict[str, object]:
    return {
        "adapter_id": str(profile.adapter_id),
        "allowed_origins": [_origin_mapping(origin) for origin in profile.allowed_origins],
        "generation": profile.generation,
        "initial_targets": [
            {
                "origin": _origin_mapping(target.origin),
                "request_target": target.request_target,
                "target_id": str(target.target_id),
            }
            for target in profile.initial_targets
        ],
        "limits": _limits_mapping(profile.limits),
        "network_policy": _network_policy_mapping(profile.network_policy),
        "profile_id": str(profile.profile_id),
    }


def encode_browser_automation_configuration(
    configuration: BrowserAutomationConfiguration,
) -> dict[str, object]:
    """Return a JSON-safe deterministic primitive mapping with no ambient configuration."""

    if not isinstance(configuration, BrowserAutomationConfiguration):
        raise TypeError("configuration must be BrowserAutomationConfiguration")
    return {
        "enabled": configuration.enabled,
        "profiles": [_profile_mapping(profile) for profile in configuration.profiles],
    }


def browser_automation_configuration_json(
    configuration: BrowserAutomationConfiguration,
) -> str:
    """Canonical UTF-8/ASCII JSON representation used by S1 deterministic tests."""

    return json.dumps(
        encode_browser_automation_configuration(configuration),
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )
