from dataclasses import fields

import pytest

from phoenix_os.network_egress import (
    NetworkCredentialBinding,
    NetworkDestinationMode,
    NetworkEgressOperation,
    NetworkEgressOperationId,
    NetworkEgressProfile,
    NetworkEgressProfileCatalog,
    NetworkEgressProfileId,
    NetworkHttpMethod,
    NetworkOperationEffect,
    NetworkOperationLimits,
)
from phoenix_os.secrets import SecretRef


def _read_operation() -> NetworkEgressOperation:
    return NetworkEgressOperation(
        operation_id=NetworkEgressOperationId("read-repository"),
        method=NetworkHttpMethod.GET,
        request_target="/repos/arthurjoao878-source/Phoenix-OS",
        effect=NetworkOperationEffect.READ_ONLY,
        limits=NetworkOperationLimits(max_response_body_bytes=262_144),
        accept="application/json",
        exposed_response_headers=("content-type", "etag"),
    )


def test_operation_fixes_method_target_effect_and_response_exposure() -> None:
    operation = _read_operation()

    assert operation.method is NetworkHttpMethod.GET
    assert operation.request_target == "/repos/arthurjoao878-source/Phoenix-OS"
    assert operation.effect is NetworkOperationEffect.READ_ONLY
    assert operation.exposed_response_headers == ("content-type", "etag")


def test_operation_rejects_arbitrary_or_ambiguous_request_targets() -> None:
    for target in (
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
        "/safe ",
        " /safe",
        "/safe\t",
        "\t/safe",
    ):
        with pytest.raises(ValueError):
            NetworkEgressOperation(
                operation_id=NetworkEgressOperationId("bad"),
                method=NetworkHttpMethod.GET,
                request_target=target,
                effect=NetworkOperationEffect.READ_ONLY,
            )


def test_request_target_accepts_explicit_percent_encoded_space_and_utf8() -> None:
    for target in ("/hello%20world", "/caf%C3%A9"):
        operation = NetworkEgressOperation(
            operation_id=NetworkEgressOperationId("encoded"),
            method=NetworkHttpMethod.GET,
            request_target=target,
            effect=NetworkOperationEffect.READ_ONLY,
        )
        assert operation.request_target == target


def test_get_and_head_cannot_enable_request_body() -> None:
    with pytest.raises(ValueError, match="cannot permit request bodies"):
        NetworkEgressOperation(
            operation_id=NetworkEgressOperationId("bad-get"),
            method=NetworkHttpMethod.GET,
            request_target="/",
            effect=NetworkOperationEffect.READ_ONLY,
            limits=NetworkOperationLimits(max_request_body_bytes=1),
        )


def test_read_only_effect_rejects_potentially_mutating_http_methods() -> None:
    for method in (
        NetworkHttpMethod.POST,
        NetworkHttpMethod.PUT,
        NetworkHttpMethod.PATCH,
        NetworkHttpMethod.DELETE,
    ):
        with pytest.raises(ValueError, match=r"read-only.*GET or HEAD"):
            NetworkEgressOperation(
                operation_id=NetworkEgressOperationId(f"unsafe-{method.value.lower()}"),
                method=method,
                request_target="/resource",
                effect=NetworkOperationEffect.READ_ONLY,
            )


def test_remote_effect_is_conservatively_valid_for_every_reviewed_http_method() -> None:
    for method in NetworkHttpMethod:
        operation = NetworkEgressOperation(
            operation_id=NetworkEgressOperationId(f"effect-{method.value.lower()}"),
            method=method,
            request_target="/resource",
            effect=NetworkOperationEffect.REMOTE_EFFECT,
        )
        assert operation.effect is NetworkOperationEffect.REMOTE_EFFECT


def test_sensitive_cookie_response_headers_cannot_be_exposed() -> None:
    with pytest.raises(ValueError, match="sensitive response header"):
        NetworkEgressOperation(
            operation_id=NetworkEgressOperationId("cookie"),
            method=NetworkHttpMethod.GET,
            request_target="/",
            effect=NetworkOperationEffect.READ_ONLY,
            exposed_response_headers=("set-cookie",),
        )


def test_profile_owns_destination_generation_and_operation_allowlist() -> None:
    profile = NetworkEgressProfile(
        profile_id=NetworkEgressProfileId("github-api"),
        generation=3,
        mode=NetworkDestinationMode.HOSTED_HTTPS,
        host="API.GITHUB.COM",
        operations=(_read_operation(),),
    )

    assert profile.host == "api.github.com"
    assert profile.port == 443
    assert profile.allow_public_networks is True
    assert profile.generation == 3
    assert profile.require_operation(NetworkEgressOperationId("read-repository")) == (
        _read_operation()
    )


def test_loopback_profile_is_explicit_and_cannot_widen_to_public_or_network_allowlists() -> None:
    operation = _read_operation()
    profile = NetworkEgressProfile(
        profile_id=NetworkEgressProfileId("local-api"),
        generation=1,
        mode=NetworkDestinationMode.LOOPBACK_HTTP,
        host="localhost",
        operations=(operation,),
    )

    assert profile.port == 80
    assert profile.allow_public_networks is False

    with pytest.raises(ValueError, match="cannot allow public"):
        NetworkEgressProfile(
            profile_id=NetworkEgressProfileId("bad-loopback"),
            generation=1,
            mode=NetworkDestinationMode.LOOPBACK_HTTP,
            host="localhost",
            operations=(operation,),
            allow_public_networks=True,
        )
    with pytest.raises(ValueError, match="cannot define explicit networks"):
        NetworkEgressProfile(
            profile_id=NetworkEgressProfileId("bad-loopback-network"),
            generation=1,
            mode=NetworkDestinationMode.LOOPBACK_HTTP,
            host="localhost",
            operations=(operation,),
            allowed_networks=("127.0.0.0/8",),
        )


def test_hosted_profile_can_explicitly_name_private_networks_without_caller_control() -> None:
    profile = NetworkEgressProfile(
        profile_id=NetworkEgressProfileId("internal-api"),
        generation=1,
        mode=NetworkDestinationMode.HOSTED_HTTPS,
        host="internal.example",
        operations=(_read_operation(),),
        allow_public_networks=False,
        allowed_networks=("10.20.0.0/16", "2001:db8::/32"),
    )

    assert profile.allowed_networks == ("10.20.0.0/16", "2001:db8::/32")
    public_fields = {item.name for item in fields(NetworkEgressProfile)}
    assert "url" not in public_fields
    assert "proxy" not in public_fields
    assert "dns_server" not in public_fields


def test_media_type_header_material_is_printable_ascii_token_grammar() -> None:
    valid = (
        ("application/json", "application/json"),
        ("application/vnd.github+json", "application/vnd.github+json"),
        ("text/plain; charset=UTF-8", "text/plain; charset=UTF-8"),
        ("TEXT/PLAIN; Charset=UTF-8", "text/plain; charset=UTF-8"),
    )
    for supplied, expected in valid:
        operation = NetworkEgressOperation(
            operation_id=NetworkEgressOperationId("media"),
            method=NetworkHttpMethod.POST,
            request_target="/resource",
            effect=NetworkOperationEffect.REMOTE_EFFECT,
            limits=NetworkOperationLimits(max_request_body_bytes=1024),
            content_type=supplied,
        )
        assert operation.content_type == expected

    for supplied in (
        "text/plain\r\n; charset=utf-8",
        "text/plain;\r\ncharset=utf-8",
        "text/plain;charset=utf-8\x1b",
        "text/plain;\tcharset=utf-8",
        "text/évil",
        'text/plain; charset="utf-8"',
    ):
        with pytest.raises(ValueError):
            NetworkEgressOperation(
                operation_id=NetworkEgressOperationId("bad-media"),
                method=NetworkHttpMethod.POST,
                request_target="/resource",
                effect=NetworkOperationEffect.REMOTE_EFFECT,
                limits=NetworkOperationLimits(max_request_body_bytes=1024),
                content_type=supplied,
            )


def test_credential_prefix_rejects_non_printable_or_non_ascii_material() -> None:
    exact = SecretRef(name="token", namespace="network", version=1)

    assert (
        NetworkCredentialBinding(
            header_name="authorization",
            secret_ref=exact,
            value_prefix="Bearer ",
        ).value_prefix
        == "Bearer "
    )

    for prefix in ("\t", "\x00", "\x1b", "\x7f", "Béarer "):
        with pytest.raises(ValueError, match="printable ASCII"):
            NetworkCredentialBinding(
                header_name="authorization",
                secret_ref=exact,
                value_prefix=prefix,
            )


def test_credential_binding_requires_exact_secret_version_and_rejects_transport_headers() -> None:
    binding = NetworkCredentialBinding(
        header_name="Authorization",
        secret_ref=SecretRef(name="github-token", namespace="network", version=7),
        value_prefix="Bearer ",
    )
    assert binding.header_name == "authorization"
    assert str(binding.secret_ref) == "network/github-token#7"

    with pytest.raises(ValueError, match="exact secret version"):
        NetworkCredentialBinding(
            header_name="authorization",
            secret_ref=SecretRef(name="github-token", namespace="network"),
            value_prefix="Bearer ",
        )

    for header in ("host", "content-length", "proxy-authorization", "transfer-encoding"):
        with pytest.raises(ValueError, match="reserved"):
            NetworkCredentialBinding(
                header_name=header,
                secret_ref=SecretRef(name="token", namespace="network", version=1),
            )


def test_profile_catalog_is_finite_and_rejects_duplicate_profiles_and_operations() -> None:
    profile = NetworkEgressProfile(
        profile_id=NetworkEgressProfileId("github-api"),
        generation=1,
        mode=NetworkDestinationMode.HOSTED_HTTPS,
        host="api.github.com",
        operations=(_read_operation(),),
    )
    catalog = NetworkEgressProfileCatalog((profile,))

    assert catalog.profile_ids == (NetworkEgressProfileId("github-api"),)
    assert catalog.require_profile(NetworkEgressProfileId("github-api")) == profile
    assert (
        catalog.require_operation(
            NetworkEgressProfileId("github-api"),
            NetworkEgressOperationId("read-repository"),
        )
        == _read_operation()
    )

    with pytest.raises(ValueError, match="duplicate profile"):
        NetworkEgressProfileCatalog((profile, profile))

    duplicate_operation = _read_operation()
    with pytest.raises(ValueError, match="duplicate operation"):
        NetworkEgressProfile(
            profile_id=NetworkEgressProfileId("duplicate"),
            generation=1,
            mode=NetworkDestinationMode.HOSTED_HTTPS,
            host="example.com",
            operations=(duplicate_operation, duplicate_operation),
        )
