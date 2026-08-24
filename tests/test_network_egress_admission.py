from __future__ import annotations

import asyncio
from typing import Any, cast

import pytest

from phoenix_os.network_egress._admission import (
    NetworkDestinationAdmission,
    NetworkResolver,
    admit_network_destination,
    resolve_and_admit_network_destination,
)
from phoenix_os.network_egress._errors import (
    NetworkDestinationRejectedError,
    NetworkTransportError,
)
from phoenix_os.network_egress.contracts import (
    NetworkEgressOperationId,
    NetworkEgressProfileId,
)
from phoenix_os.network_egress.profiles import (
    NetworkDestinationMode,
    NetworkEgressOperation,
    NetworkEgressProfile,
    NetworkHttpMethod,
    NetworkOperationEffect,
    NetworkOperationLimits,
)


class _FakeResolver:
    def __init__(self, result: tuple[str, ...]) -> None:
        self.result = result
        self.calls: list[tuple[str, int, int]] = []

    async def resolve(
        self,
        host: str,
        port: int,
        *,
        max_addresses: int,
    ) -> tuple[str, ...]:
        self.calls.append((host, port, max_addresses))
        await asyncio.sleep(0)
        return self.result


def _operation(**changes: object) -> NetworkEgressOperation:
    values: dict[str, object] = {
        "operation_id": NetworkEgressOperationId("read"),
        "method": NetworkHttpMethod.GET,
        "request_target": "/v1/data",
        "effect": NetworkOperationEffect.READ_ONLY,
        "limits": NetworkOperationLimits(max_resolved_addresses=4),
    }
    values.update(changes)
    return NetworkEgressOperation(**cast(Any, values))


def _profile(
    operation: NetworkEgressOperation | None = None,
    **changes: object,
) -> NetworkEgressProfile:
    values: dict[str, object] = {
        "profile_id": NetworkEgressProfileId("example"),
        "generation": 1,
        "mode": NetworkDestinationMode.HOSTED_HTTPS,
        "host": "api.example.com",
        "operations": (operation or _operation(),),
    }
    values.update(changes)
    return NetworkEgressProfile(**cast(Any, values))


def test_admission_accepts_public_https_and_pins_sorted_literals() -> None:
    operation = _operation()
    profile = _profile(operation)
    admission = admit_network_destination(
        profile,
        operation,
        ("8.8.8.8", "1.1.1.1", "8.8.8.8"),
    )

    assert admission == NetworkDestinationAdmission(
        profile_id=profile.profile_id,
        generation=1,
        operation_id=operation.operation_id,
        mode=NetworkDestinationMode.HOSTED_HTTPS,
        host="api.example.com",
        port=443,
        addresses=("1.1.1.1", "8.8.8.8"),
    )


def test_admission_rejects_entire_mixed_safe_and_unsafe_dns_set() -> None:
    operation = _operation()
    profile = _profile(operation)

    with pytest.raises(NetworkDestinationRejectedError) as raised:
        admit_network_destination(
            profile,
            operation,
            ("8.8.8.8", "127.0.0.1"),
        )

    assert raised.value.category == "destination_not_allowed"


def test_admission_allows_only_trusted_explicit_private_https_network() -> None:
    operation = _operation()
    profile = _profile(
        operation,
        allow_public_networks=False,
        allowed_networks=("10.0.0.0/8",),
    )

    admission = admit_network_destination(
        profile,
        operation,
        ("10.20.30.40",),
    )
    assert admission.addresses == ("10.20.30.40",)

    with pytest.raises(NetworkDestinationRejectedError):
        admit_network_destination(profile, operation, ("10.20.30.40", "8.8.8.8"))


@pytest.mark.parametrize(
    "address",
    [
        "0.0.0.0",
        "::",
        "224.0.0.1",
        "ff02::1",
        "fe80::1%eth0",
        "not-an-ip",
    ],
)
def test_admission_rejects_hard_forbidden_or_invalid_literals(address: str) -> None:
    operation = _operation()
    profile = _profile(operation, allowed_networks=("0.0.0.0/0", "::/0"))

    with pytest.raises(NetworkDestinationRejectedError):
        admit_network_destination(profile, operation, (address,))


@pytest.mark.parametrize(
    "address",
    [
        "64:ff9b::7f00:1",
        "64:ff9b:1::7f00:1",
        "::7f00:1",
        "2002:7f00:1::",
    ],
)
def test_public_admission_rejects_known_ipv4_transition_destinations(address: str) -> None:
    operation = _operation()
    profile = _profile(operation)

    with pytest.raises(NetworkDestinationRejectedError) as raised:
        admit_network_destination(profile, operation, (address,))

    assert raised.value.category == "destination_not_allowed"


def test_explicit_trusted_network_can_admit_transition_destination() -> None:
    operation = _operation()
    profile = _profile(
        operation,
        allowed_networks=("64:ff9b::/96",),
    )

    admission = admit_network_destination(
        profile,
        operation,
        ("64:ff9b::808:808",),
    )

    assert admission.addresses == ("64:ff9b::808:808",)


@pytest.mark.parametrize(
    "address",
    [
        "192.0.0.8",
        "192.0.0.170",
        "192.0.0.171",
        "fec0::1",
        "5f00::1",
    ],
)
def test_auto_public_rejects_special_use_addresses_independent_of_stdlib_version(
    address: str,
) -> None:
    operation = _operation()
    profile = _profile(operation)

    with pytest.raises(NetworkDestinationRejectedError) as raised:
        admit_network_destination(profile, operation, (address,))

    assert raised.value.category == "destination_not_allowed"


def test_explicit_trusted_network_can_admit_special_use_address() -> None:
    operation = _operation()
    profile = _profile(
        operation,
        allowed_networks=("192.0.0.8/32",),
    )

    admission = admit_network_destination(
        profile,
        operation,
        ("192.0.0.8",),
    )

    assert admission.addresses == ("192.0.0.8",)


def test_loopback_http_requires_every_answer_to_be_loopback() -> None:
    operation = _operation()
    profile = _profile(
        operation,
        mode=NetworkDestinationMode.LOOPBACK_HTTP,
        host="localhost",
        allow_public_networks=False,
    )

    admission = admit_network_destination(
        profile,
        operation,
        ("127.0.0.1", "::1", "::ffff:127.0.0.1"),
    )
    assert admission.addresses == ("127.0.0.1", "::1")

    with pytest.raises(NetworkDestinationRejectedError) as raised:
        admit_network_destination(profile, operation, ("127.0.0.1", "8.8.8.8"))
    assert raised.value.category == "loopback_resolution_mismatch"


def test_admission_enforces_raw_answer_bound_before_deduplication() -> None:
    operation = _operation(
        limits=NetworkOperationLimits(max_resolved_addresses=2),
    )
    profile = _profile(operation)

    with pytest.raises(NetworkDestinationRejectedError) as raised:
        admit_network_destination(profile, operation, ("8.8.8.8", "8.8.8.8", "8.8.8.8"))
    assert raised.value.category == "too_many_addresses"


@pytest.mark.asyncio
async def test_resolve_and_admit_uses_server_owned_host_and_limits() -> None:
    operation = _operation()
    profile = _profile(operation)
    resolver = _FakeResolver(("8.8.8.8",))

    admission = await resolve_and_admit_network_destination(
        profile,
        operation,
        resolver=resolver,
    )

    assert admission.addresses == ("8.8.8.8",)
    assert resolver.calls == [("api.example.com", 443, operation.limits.max_resolved_addresses)]


@pytest.mark.asyncio
async def test_literal_profile_host_never_calls_resolver() -> None:
    operation = _operation()
    profile = _profile(operation, host="127.0.0.1", allowed_networks=("127.0.0.1/32",))
    resolver = _FakeResolver(("8.8.8.8",))

    admission = await resolve_and_admit_network_destination(
        profile,
        operation,
        resolver=resolver,
    )

    assert admission.addresses == ("127.0.0.1",)
    assert resolver.calls == []


@pytest.mark.asyncio
async def test_resolution_failure_is_sanitized() -> None:
    class _ExplodingResolver:
        async def resolve(
            self,
            host: str,
            port: int,
            *,
            max_addresses: int,
        ) -> tuple[str, ...]:
            del host, port, max_addresses
            await asyncio.sleep(0)
            raise RuntimeError("10.0.0.9 token=must-not-leak")

    operation = _operation()
    profile = _profile(operation)

    with pytest.raises(NetworkTransportError) as raised:
        await resolve_and_admit_network_destination(
            profile,
            operation,
            resolver=cast(NetworkResolver, _ExplodingResolver()),
        )

    assert raised.value.category == "dns_failed"
    assert "10.0.0.9" not in str(raised.value)
    assert "token" not in str(raised.value)


def test_admission_rejects_operation_object_not_owned_by_profile() -> None:
    configured = _operation()
    profile = _profile(configured)
    altered = _operation(request_target="/different")

    with pytest.raises(NetworkDestinationRejectedError) as raised:
        admit_network_destination(profile, altered, ("8.8.8.8",))

    assert raised.value.category == "operation_mismatch"


def test_admission_requires_non_empty_dns_set() -> None:
    operation = _operation()
    profile = _profile(operation)

    with pytest.raises(NetworkTransportError) as raised:
        admit_network_destination(profile, operation, ())
    assert raised.value.category == "dns_no_addresses"
    assert raised.value.request_started is False
