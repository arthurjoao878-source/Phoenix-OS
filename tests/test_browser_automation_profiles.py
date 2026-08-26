from dataclasses import fields

import pytest

from phoenix_os.browser_automation import (
    BrowserAdapterId,
    BrowserDestinationMode,
    BrowserNavigationTarget,
    BrowserNavigationTargetId,
    BrowserNetworkPolicy,
    BrowserOrigin,
    BrowserProfile,
    BrowserProfileCatalog,
    BrowserProfileId,
    BrowserProfileLimits,
)


def _origin() -> BrowserOrigin:
    return BrowserOrigin(BrowserDestinationMode.HOSTED_HTTPS, "DOCS.EXAMPLE.COM")


def _target(origin: BrowserOrigin | None = None) -> BrowserNavigationTarget:
    resolved = origin or _origin()
    return BrowserNavigationTarget(
        target_id=BrowserNavigationTargetId("home"),
        origin=resolved,
        request_target="/docs/start?lang=en",
    )


def _profile() -> BrowserProfile:
    origin = _origin()
    return BrowserProfile(
        profile_id=BrowserProfileId("docs"),
        generation=2,
        adapter_id=BrowserAdapterId("deterministic.fake"),
        allowed_origins=(origin,),
        initial_targets=(_target(origin),),
    )


def test_origin_is_exact_canonical_scheme_host_port_and_loopback_http_is_explicit() -> None:
    hosted = _origin()
    loopback = BrowserOrigin(BrowserDestinationMode.LOOPBACK_HTTP, "127.0.0.1")

    assert hosted.host == "docs.example.com"
    assert hosted.port == 443
    assert hosted.scheme == "https"
    assert hosted.canonical == "https://docs.example.com"
    assert loopback.port == 80
    assert loopback.canonical == "http://127.0.0.1"

    with pytest.raises(ValueError, match="loopback host"):
        BrowserOrigin(BrowserDestinationMode.LOOPBACK_HTTP, "example.com")


def test_navigation_target_rejects_arbitrary_urls_fragments_and_path_ambiguity() -> None:
    for request_target in (
        "https://example.com/path",
        "//example.com/path",
        "/safe/../admin",
        "/safe%2Fadmin",
        "/safe%5cadmin",
        "/safe%2e%2e/admin",
        "/safe#fragment",
        "/safe\\windows",
        "/bad%zz",
        "/space here",
        "/café",
        " /safe",
    ):
        with pytest.raises(ValueError):
            BrowserNavigationTarget(
                target_id=BrowserNavigationTargetId("bad"),
                origin=_origin(),
                request_target=request_target,
            )

    assert _target().request_target == "/docs/start?lang=en"


def test_network_policy_is_server_owned_finite_and_normalizes_explicit_cidrs() -> None:
    policy = BrowserNetworkPolicy(
        allow_public_networks=False,
        allowed_networks=("10.20.0.0/16", "2001:db8::/32"),
    )
    assert policy.allowed_networks == ("10.20.0.0/16", "2001:db8::/32")

    with pytest.raises(ValueError, match="invalid explicit network"):
        BrowserNetworkPolicy(allowed_networks=("10.20.0.1/16",))


def test_loopback_only_profile_requires_public_network_admission_to_be_disabled() -> None:
    origin = BrowserOrigin(BrowserDestinationMode.LOOPBACK_HTTP, "localhost")
    target = BrowserNavigationTarget(
        target_id=BrowserNavigationTargetId("local"),
        origin=origin,
        request_target="/",
    )

    with pytest.raises(ValueError, match="cannot allow public networks"):
        BrowserProfile(
            profile_id=BrowserProfileId("local"),
            generation=1,
            adapter_id=BrowserAdapterId("deterministic.fake"),
            allowed_origins=(origin,),
            initial_targets=(target,),
        )

    profile = BrowserProfile(
        profile_id=BrowserProfileId("local"),
        generation=1,
        adapter_id=BrowserAdapterId("deterministic.fake"),
        allowed_origins=(origin,),
        initial_targets=(target,),
        network_policy=BrowserNetworkPolicy(allow_public_networks=False),
    )
    assert profile.network_policy.allow_public_networks is False


def test_profile_has_no_generic_browser_escape_hatches_and_fixed_v035_scope() -> None:
    profile = _profile()
    names = {item.name for item in fields(BrowserProfile)}

    for forbidden in (
        "url",
        "proxy",
        "dns_server",
        "browser_executable",
        "command_line",
        "user_data_directory",
        "extensions",
        "javascript_enabled",
        "subresources_enabled",
        "downloads_enabled",
        "uploads_enabled",
        "selector",
    ):
        assert forbidden not in names

    assert profile.javascript_enabled is False
    assert profile.subresources_enabled is False
    assert profile.downloads_enabled is False
    assert profile.uploads_enabled is False
    assert profile.persistent_storage_enabled is False
    assert profile.max_pages_per_session == 1


def test_profile_target_must_be_inside_exact_allowed_origin_set() -> None:
    allowed = _origin()
    other = BrowserOrigin(BrowserDestinationMode.HOSTED_HTTPS, "other.example.com")

    with pytest.raises(ValueError, match="origin is not in the profile allowlist"):
        BrowserProfile(
            profile_id=BrowserProfileId("bad"),
            generation=1,
            adapter_id=BrowserAdapterId("deterministic.fake"),
            allowed_origins=(allowed,),
            initial_targets=(_target(other),),
        )


def test_profile_rejects_duplicate_origins_and_target_ids() -> None:
    origin = _origin()
    target = _target(origin)

    with pytest.raises(ValueError, match="duplicate allowed origins"):
        BrowserProfile(
            profile_id=BrowserProfileId("duplicate-origin"),
            generation=1,
            adapter_id=BrowserAdapterId("deterministic.fake"),
            allowed_origins=(origin, origin),
            initial_targets=(target,),
        )
    with pytest.raises(ValueError, match="duplicate navigation target"):
        BrowserProfile(
            profile_id=BrowserProfileId("duplicate-target"),
            generation=1,
            adapter_id=BrowserAdapterId("deterministic.fake"),
            allowed_origins=(origin,),
            initial_targets=(target, target),
        )


def test_profile_limits_are_finite_and_operation_timeout_cannot_outlive_session() -> None:
    limits = BrowserProfileLimits(
        max_redirects=0, operation_timeout_seconds=10, session_ttl_seconds=20
    )
    assert limits.max_redirects == 0

    with pytest.raises(ValueError, match="cannot exceed browser session TTL"):
        BrowserProfileLimits(operation_timeout_seconds=31, session_ttl_seconds=30)
    with pytest.raises(ValueError, match="cannot be less"):
        BrowserProfileLimits(max_snapshot_text_chars=10, max_snapshot_text_bytes=9)


def test_profile_catalog_is_finite_immutable_and_requires_exact_profile_id() -> None:
    profile = _profile()
    catalog = BrowserProfileCatalog((profile,))

    assert catalog.profile_ids == (BrowserProfileId("docs"),)
    assert catalog.require_profile(BrowserProfileId("docs")) == profile
    assert profile.require_target(BrowserNavigationTargetId("home")) == _target(_origin())

    with pytest.raises(ValueError, match="duplicate profile"):
        BrowserProfileCatalog((profile, profile))
    with pytest.raises(KeyError, match="unknown browser profile"):
        catalog.require_profile(BrowserProfileId("missing"))
