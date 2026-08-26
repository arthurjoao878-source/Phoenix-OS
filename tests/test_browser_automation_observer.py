from __future__ import annotations

import inspect
from dataclasses import fields
from uuid import uuid4

from phoenix_os.browser_automation import (
    BrowserAutomationObservabilityConfiguration,
    BrowserAutomationObservationOutcome,
    BrowserAutomationObservedOperation,
    BrowserAutomationOperationObservation,
    ContentFreeBrowserAutomationObserver,
)


def test_browser_observation_shape_is_closed_and_content_free() -> None:
    assert {item.name for item in fields(BrowserAutomationOperationObservation)} == {
        "operation_id",
        "operation",
        "outcome",
        "effect_started",
        "duration_ms",
    }

    observation = BrowserAutomationOperationObservation(
        operation_id=uuid4(),
        operation=BrowserAutomationObservedOperation.ELEMENT_CLICK,
        outcome=BrowserAutomationObservationOutcome.REJECTED,
        effect_started=False,
        duration_ms=3,
    )
    assert set(observation.metadata()) == {
        "operation_id",
        "operation",
        "outcome",
        "effect_started",
        "duration_ms",
    }
    serialized = repr(observation).lower()
    for forbidden in (
        "profile_id",
        "session_id",
        "page_id",
        "element_id",
        "url",
        "origin",
        "host",
        "cookie",
        "body",
        "header",
        "dns",
        "certificate",
        "authorityintent",
    ):
        assert forbidden not in serialized


def test_browser_observability_configuration_is_explicit_and_bounded() -> None:
    configuration = BrowserAutomationObservabilityConfiguration()
    assert configuration.audit_enabled is True
    assert configuration.metrics_enabled is True
    assert configuration.logs_enabled is True
    assert configuration.events_enabled is True
    assert configuration.source == "phoenix.browser_automation"
    assert configuration.any_enabled is True


def test_content_free_browser_observer_uses_empty_event_payload_and_fixed_metadata() -> None:
    source = inspect.getsource(ContentFreeBrowserAutomationObserver.record)
    compact = "".join(source.split())

    assert "payload={}" in compact
    for forbidden in (
        ".profile_id",
        ".session_id",
        ".page_id",
        ".element_id",
        ".origin",
        ".request_target",
        ".body",
        ".headers",
        ".cookie",
        "BrowserDestinationAdmission",
        "AuthorityIntent",
    ):
        assert forbidden not in source
