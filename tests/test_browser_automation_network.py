from __future__ import annotations

import asyncio

import pytest

from phoenix_os.browser_automation.contracts import (
    BrowserAdapterId,
    BrowserNavigationTargetId,
    BrowserProfileId,
)
from phoenix_os.browser_automation.errors import (
    BrowserAutomationAdapterError,
    BrowserAutomationLimitExceededError,
    BrowserAutomationRejectedError,
)
from phoenix_os.browser_automation.network import (
    BrowserDestinationAdmission,
    admit_browser_destination,
    resolve_and_admit_browser_destination,
)
from phoenix_os.browser_automation.profiles import (
    BrowserDestinationMode,
    BrowserNavigationTarget,
    BrowserNetworkPolicy,
    BrowserOrigin,
    BrowserProfile,
    BrowserProfileLimits,
)


def _profile(
    *,
    origin: BrowserOrigin | None = None,
    allow_public_networks: bool = True,
    allowed_networks: tuple[str, ...] = (),
    max_resolved_addresses: int = 16,
) -> BrowserProfile:
    selected_origin = origin or BrowserOrigin(
        BrowserDestinationMode.HOSTED_HTTPS,
        "example.com",
    )
    target = BrowserNavigationTarget(
        target_id=BrowserNavigationTargetId("start"),
        origin=selected_origin,
        request_target="/start",
    )
    return BrowserProfile(
        profile_id=BrowserProfileId("browser-network-test"),
        generation=7,
        adapter_id=BrowserAdapterId("deterministic"),
        allowed_origins=(selected_origin,),
        initial_targets=(target,),
        network_policy=BrowserNetworkPolicy(
            allow_public_networks=allow_public_networks,
            allowed_networks=allowed_networks,
        ),
        limits=BrowserProfileLimits(
            max_resolved_addresses=max_resolved_addresses,
        ),
    )


def test_exact_allowed_origin_is_required() -> None:
    profile = _profile()
    other = BrowserOrigin(
        BrowserDestinationMode.HOSTED_HTTPS,
        "other.example.com",
    )

    with pytest.raises(BrowserAutomationRejectedError):
        admit_browser_destination(profile, other, ("8.8.8.8",))


def test_public_ipv4_is_admitted_by_default() -> None:
    profile = _profile()
    origin = profile.allowed_origins[0]

    admission = admit_browser_destination(profile, origin, ("8.8.8.8",))

    assert admission.profile_id == profile.profile_id
    assert admission.profile_generation == profile.generation
    assert admission.origin == origin
    assert admission.addresses == ("8.8.8.8",)
    assert admission.tls_server_name == "example.com"


def test_public_ipv6_is_admitted_by_default() -> None:
    profile = _profile()
    origin = profile.allowed_origins[0]

    admission = admit_browser_destination(
        profile,
        origin,
        ("2606:4700:4700::1111",),
    )

    assert admission.addresses == ("2606:4700:4700::1111",)


def test_private_address_is_rejected_by_default() -> None:
    profile = _profile()
    origin = profile.allowed_origins[0]

    with pytest.raises(BrowserAutomationRejectedError):
        admit_browser_destination(profile, origin, ("10.20.30.40",))


def test_explicit_private_cidr_is_admitted() -> None:
    profile = _profile(
        allow_public_networks=False,
        allowed_networks=("10.20.0.0/16",),
    )
    origin = profile.allowed_origins[0]

    admission = admit_browser_destination(profile, origin, ("10.20.30.40",))

    assert admission.addresses == ("10.20.30.40",)


def test_loopback_http_accepts_only_loopback_addresses() -> None:
    origin = BrowserOrigin(
        BrowserDestinationMode.LOOPBACK_HTTP,
        "localhost",
    )
    profile = _profile(
        origin=origin,
        allow_public_networks=False,
    )

    admission = admit_browser_destination(
        profile,
        origin,
        ("127.0.0.1", "::1"),
    )

    assert admission.addresses == ("127.0.0.1", "::1")
    assert admission.tls_server_name is None

    with pytest.raises(BrowserAutomationRejectedError):
        admit_browser_destination(
            profile,
            origin,
            ("127.0.0.1", "10.0.0.1"),
        )


def test_mixed_public_and_unsafe_answer_set_fails_closed() -> None:
    profile = _profile()
    origin = profile.allowed_origins[0]

    with pytest.raises(BrowserAutomationRejectedError):
        admit_browser_destination(
            profile,
            origin,
            ("8.8.8.8", "10.0.0.1"),
        )


@pytest.mark.parametrize(
    "value",
    (
        "not-an-ip",
        "127.0.0.1%zone",
        "::%",
        "",
    ),
)
def test_invalid_resolved_literals_are_rejected(value: str) -> None:
    profile = _profile()
    origin = profile.allowed_origins[0]

    with pytest.raises(BrowserAutomationRejectedError):
        admit_browser_destination(profile, origin, (value,))


def test_empty_answer_set_is_rejected() -> None:
    profile = _profile()
    origin = profile.allowed_origins[0]

    with pytest.raises(BrowserAutomationRejectedError):
        admit_browser_destination(profile, origin, ())


def test_too_many_dns_answers_are_rejected_before_admission() -> None:
    profile = _profile(max_resolved_addresses=1)
    origin = profile.allowed_origins[0]

    with pytest.raises(BrowserAutomationLimitExceededError):
        admit_browser_destination(
            profile,
            origin,
            ("8.8.8.8", "1.1.1.1"),
        )


def test_duplicate_and_ipv4_mapped_answers_are_canonicalized() -> None:
    profile = _profile()
    origin = profile.allowed_origins[0]

    admission = admit_browser_destination(
        profile,
        origin,
        (
            "8.8.8.8",
            "8.8.8.8",
            "::ffff:8.8.8.8",
        ),
    )

    assert admission.addresses == ("8.8.8.8",)


def test_public_exception_does_not_disclose_dns_or_ip_details() -> None:
    profile = _profile()
    origin = profile.allowed_origins[0]

    with pytest.raises(BrowserAutomationRejectedError) as captured:
        admit_browser_destination(
            profile,
            origin,
            ("10.123.45.67",),
        )

    rendered = str(captured.value).lower()
    assert "10.123.45.67" not in rendered
    assert "dns" not in rendered
    assert "ip" not in rendered


def test_admission_repr_does_not_disclose_literal_destination_pins() -> None:
    profile = _profile()
    origin = profile.allowed_origins[0]

    admission = admit_browser_destination(profile, origin, ("8.8.8.8",))

    assert isinstance(admission, BrowserDestinationAdmission)
    assert "8.8.8.8" not in repr(admission)


class _RecordingResolver:
    def __init__(self, addresses: tuple[str, ...]) -> None:
        self.addresses = addresses
        self.calls: list[tuple[str, int, int]] = []

    async def resolve(
        self,
        host: str,
        port: int,
        *,
        max_addresses: int,
    ) -> tuple[str, ...]:
        self.calls.append((host, port, max_addresses))
        return self.addresses


def test_reviewed_resolver_receives_exact_origin_and_bound() -> None:
    profile = _profile(max_resolved_addresses=4)
    origin = profile.allowed_origins[0]
    resolver = _RecordingResolver(("8.8.8.8",))

    admission = asyncio.run(
        resolve_and_admit_browser_destination(
            profile,
            origin,
            resolver=resolver,
        )
    )

    assert resolver.calls == [("example.com", 443, 4)]
    assert admission.addresses == ("8.8.8.8",)


class _FailingResolver:
    async def resolve(
        self,
        host: str,
        port: int,
        *,
        max_addresses: int,
    ) -> tuple[str, ...]:
        del host, port, max_addresses
        raise OSError("sensitive resolver detail")


def test_raw_resolver_failure_is_content_minimized() -> None:
    profile = _profile()
    origin = profile.allowed_origins[0]

    with pytest.raises(BrowserAutomationAdapterError) as captured:
        asyncio.run(
            resolve_and_admit_browser_destination(
                profile,
                origin,
                resolver=_FailingResolver(),
            )
        )

    assert "sensitive resolver detail" not in str(captured.value)
