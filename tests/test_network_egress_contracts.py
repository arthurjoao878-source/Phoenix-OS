from dataclasses import FrozenInstanceError, fields
from datetime import UTC, datetime
from uuid import UUID

import pytest

from phoenix_os.network_egress import (
    MAX_NETWORK_REQUEST_BODY_BYTES,
    MAX_NETWORK_RESPONSE_BODY_BYTES,
    NetworkEgressOperationId,
    NetworkEgressProfileId,
    NetworkHttpRequest,
    NetworkHttpResponse,
)

_NOW = datetime(2026, 8, 23, 20, tzinfo=UTC)


def test_server_owned_network_identifiers_normalize_and_reject_unsafe_values() -> None:
    assert str(NetworkEgressProfileId(" GitHub.API ")) == "github.api"
    assert str(NetworkEgressOperationId(" Read_Repo ")) == "read_repo"

    for value in ("", "has space", "/absolute", "https://example.com", "shell&escape"):
        with pytest.raises(ValueError):
            NetworkEgressProfileId(value)


def test_public_request_exposes_no_destination_or_transport_authority() -> None:
    names = {item.name for item in fields(NetworkHttpRequest)}

    assert names == {"profile_id", "operation_id", "body", "request_id", "created_at"}
    for forbidden in (
        "url",
        "scheme",
        "host",
        "port",
        "method",
        "headers",
        "proxy",
        "dns",
        "tls",
        "credential",
        "address",
    ):
        assert forbidden not in names


def test_request_body_is_bounded_immutable_data_with_exact_digest() -> None:
    request = NetworkHttpRequest(
        profile_id=NetworkEgressProfileId("github"),
        operation_id=NetworkEgressOperationId("read"),
        body=b'{"repo":"phoenix"}',
        request_id=UUID(int=1),
        created_at=_NOW,
    )

    assert request.body_digest == (
        "sha256:65f82b6845e131e124126833fe01119b83a338fcd908a27fc8c7b2f51063e947"
    )
    with pytest.raises(FrozenInstanceError):
        request.body = b"changed"  # type: ignore[misc]
    with pytest.raises(TypeError):
        NetworkHttpRequest(
            profile_id=NetworkEgressProfileId("github"),
            operation_id=NetworkEgressOperationId("read"),
            body=bytearray(b"mutable"),  # type: ignore[arg-type]
        )
    with pytest.raises(ValueError, match="global maximum"):
        NetworkHttpRequest(
            profile_id=NetworkEgressProfileId("github"),
            operation_id=NetworkEgressOperationId("read"),
            body=b"x" * (MAX_NETWORK_REQUEST_BODY_BYTES + 1),
        )


def test_request_requires_aware_timestamp() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        NetworkHttpRequest(
            profile_id=NetworkEgressProfileId("github"),
            operation_id=NetworkEgressOperationId("read"),
            created_at=datetime(2026, 8, 23, 20),
        )


def test_response_freezes_bounded_untrusted_filtered_headers() -> None:
    headers = {"Content-Type": "application/json", "X-Request-Id": "abc"}
    response = NetworkHttpResponse(
        request_id=UUID(int=2),
        profile_id=NetworkEgressProfileId("github"),
        operation_id=NetworkEgressOperationId("read"),
        status_code=200,
        body=b"{}",
        headers=headers,
        created_at=_NOW,
    )
    headers.clear()

    assert dict(response.headers) == {
        "content-type": "application/json",
        "x-request-id": "abc",
    }
    with pytest.raises(TypeError):
        response.headers["x-new"] = "value"  # type: ignore[index]
    with pytest.raises(ValueError, match="global maximum"):
        NetworkHttpResponse(
            request_id=UUID(int=3),
            profile_id=NetworkEgressProfileId("github"),
            operation_id=NetworkEgressOperationId("read"),
            status_code=200,
            body=b"x" * (MAX_NETWORK_RESPONSE_BODY_BYTES + 1),
        )


def test_response_rejects_interim_status_and_header_injection() -> None:
    with pytest.raises(ValueError, match="final HTTP status"):
        NetworkHttpResponse(
            request_id=UUID(int=4),
            profile_id=NetworkEgressProfileId("github"),
            operation_id=NetworkEgressOperationId("read"),
            status_code=101,
        )

    with pytest.raises(ValueError, match="forbidden control"):
        NetworkHttpResponse(
            request_id=UUID(int=5),
            profile_id=NetworkEgressProfileId("github"),
            operation_id=NetworkEgressOperationId("read"),
            status_code=200,
            headers={"x-test": "safe\r\ninjected: value"},
        )
