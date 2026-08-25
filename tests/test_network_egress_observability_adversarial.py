from __future__ import annotations

import inspect
from dataclasses import fields
from uuid import uuid4

import pytest

from phoenix_os.network_egress import (
    NetworkEgressAdministrationSnapshot,
    NetworkEgressOperationObservation,
    NetworkEgressOperationOutcome,
    NetworkEgressService,
    NetworkEgressServiceSnapshot,
)
from phoenix_os.network_egress.observer import ContentFreeNetworkEgressObserver


def test_observation_and_health_shapes_have_closed_content_free_fields() -> None:
    assert {item.name for item in fields(NetworkEgressOperationObservation)} == {
        "request_id",
        "outcome",
        "request_started",
        "duration_ms",
    }
    assert {item.name for item in fields(NetworkEgressServiceSnapshot)} == {
        "limits",
        "closed",
        "closing",
        "available",
        "runtime_managed",
        "active_requests",
        "schema_version",
    }
    assert {item.name for item in fields(NetworkEgressAdministrationSnapshot)} == {
        "runtime",
        "schema_version",
    }

    observation = NetworkEgressOperationObservation(
        request_id=uuid4(),
        outcome=NetworkEgressOperationOutcome.REJECTED,
        request_started=False,
        duration_ms=3,
    )
    assert set(observation.metadata()) == {
        "request_id",
        "action",
        "outcome",
        "request_started",
        "duration_ms",
    }


def test_builtin_observer_never_reads_network_content_or_authority_objects() -> None:
    source = inspect.getsource(ContentFreeNetworkEgressObserver.record)
    compact = "".join(source.split())
    assert "payload={}" in compact
    for forbidden in (
        ".profile_id",
        ".operation_id",
        ".body",
        ".headers",
        ".host",
        ".port",
        ".credential",
        "NetworkDestinationAdmission",
        "AuthorityIntent",
        "SecretRef",
    ):
        assert forbidden not in source


def test_service_has_no_observer_wait_inside_final_network_pipeline() -> None:
    critical = inspect.getsource(NetworkEgressService._request_admitted)
    record = inspect.getsource(NetworkEgressService._record)

    assert "_record(" not in critical
    assert "observer" not in critical.lower()
    assert inspect.iscoroutinefunction(NetworkEgressService._record) is False
    assert "create_task" in record


@pytest.mark.parametrize(
    "field_name",
    (
        "profile_id",
        "generation",
        "operation_id",
        "host",
        "port",
        "request_target",
        "body",
        "headers",
        "addresses",
        "credential",
        "secret_ref",
        "status_code",
    ),
)
def test_observation_contract_has_no_network_sensitive_field(field_name: str) -> None:
    assert field_name not in {item.name for item in fields(NetworkEgressOperationObservation)}
