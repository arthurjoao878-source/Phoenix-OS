import pytest

from phoenix_os.inference import (
    InferenceEndpointRejectedError,
    InferenceEndpointRejectionCode,
    ModelEndpointMode,
    ModelEndpointPolicy,
    admit_model_endpoint,
)


def test_hosted_endpoint_is_canonical_https_without_proxy_or_redirects() -> None:
    policy = ModelEndpointPolicy(" HTTPS://API.EXAMPLE.COM:443/v1/infer ")

    assert policy.url == "https://api.example.com/v1/infer"
    assert policy.host == "api.example.com"
    assert policy.port == 443
    assert policy.request_target == "/v1/infer"
    assert policy.follow_redirects is False
    assert policy.use_proxy is False


@pytest.mark.parametrize(
    "url",
    (
        "http://api.example.com/v1",
        "https://user:pass@api.example.com/v1",
        "https://api.example.com/v1?token=secret",
        "https://api.example.com/v1#fragment",
    ),
)
def test_hosted_endpoint_rejects_insecure_or_credential_bearing_urls(url: str) -> None:
    with pytest.raises(ValueError):
        ModelEndpointPolicy(url)


def test_loopback_http_requires_explicit_mode_and_resolves_only_to_loopback() -> None:
    policy = ModelEndpointPolicy(
        "http://localhost:8080/v1",
        mode=ModelEndpointMode.LOOPBACK_HTTP,
        allowed_ports=frozenset({8080}),
    )
    admitted = admit_model_endpoint(policy, ("127.0.0.1", "::1"))

    assert admitted.tls is False
    assert admitted.server_hostname is None
    assert admitted.follow_redirects is False
    assert admitted.use_proxy is False

    with pytest.raises(InferenceEndpointRejectedError) as captured:
        admit_model_endpoint(policy, ("127.0.0.1", "10.0.0.5"))
    assert captured.value.category is InferenceEndpointRejectionCode.LOOPBACK_RESOLUTION_MISMATCH


def test_hosted_endpoint_allows_public_or_explicit_networks_only() -> None:
    public = ModelEndpointPolicy("https://api.example.com/v1")
    assert admit_model_endpoint(public, ("8.8.8.8",)).addresses == ("8.8.8.8",)

    private = ModelEndpointPolicy(
        "https://internal.example.com/v1",
        allowed_networks=("10.20.0.0/16",),
        allow_public_networks=False,
    )
    assert admit_model_endpoint(private, ("10.20.1.5",)).addresses == ("10.20.1.5",)

    with pytest.raises(InferenceEndpointRejectedError) as captured:
        admit_model_endpoint(public, ("10.20.1.5",))
    assert captured.value.category is InferenceEndpointRejectionCode.DESTINATION_NOT_ALLOWED


def test_mixed_dns_answers_fail_closed_to_prevent_rebinding() -> None:
    policy = ModelEndpointPolicy("https://api.example.com/v1")

    with pytest.raises(InferenceEndpointRejectedError):
        admit_model_endpoint(policy, ("8.8.8.8", "127.0.0.1"))


def test_ipv4_mapped_ipv6_is_evaluated_as_the_effective_ipv4_address() -> None:
    loopback = ModelEndpointPolicy(
        "http://localhost/v1",
        mode=ModelEndpointMode.LOOPBACK_HTTP,
    )
    admitted = admit_model_endpoint(loopback, ("::ffff:127.0.0.1",))

    assert admitted.addresses == ("::ffff:7f00:1",)


def test_endpoint_admission_deduplicates_sorts_and_pins_literal_addresses() -> None:
    policy = ModelEndpointPolicy("https://api.example.com/v1")
    admitted = admit_model_endpoint(
        policy,
        ("8.8.4.4", "8.8.8.8", "8.8.4.4"),
    )

    assert admitted.addresses == ("8.8.4.4", "8.8.8.8")
    assert admitted.policy.host == "api.example.com"


def test_endpoint_policy_enforces_port_and_resolution_bounds() -> None:
    with pytest.raises(ValueError, match="allowlisted"):
        ModelEndpointPolicy(
            "https://api.example.com:8443/v1",
            allowed_ports=frozenset({443}),
        )

    policy = ModelEndpointPolicy(
        "https://api.example.com/v1",
        max_resolved_addresses=1,
    )
    with pytest.raises(InferenceEndpointRejectedError) as captured:
        admit_model_endpoint(policy, ("8.8.8.8", "8.8.4.4"))
    assert captured.value.category is InferenceEndpointRejectionCode.TOO_MANY_ADDRESSES


def test_endpoint_rejection_message_does_not_disclose_destination() -> None:
    policy = ModelEndpointPolicy("https://private.example.com/v1")

    with pytest.raises(InferenceEndpointRejectedError) as captured:
        admit_model_endpoint(policy, ("10.0.0.8",))

    assert str(captured.value) == "inference endpoint rejected"
    assert "private.example.com" not in str(captured.value)
    assert "10.0.0.8" not in str(captured.value)
