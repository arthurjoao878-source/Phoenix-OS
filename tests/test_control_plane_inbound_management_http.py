from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from http import HTTPStatus
from typing import ClassVar, cast
from uuid import UUID

import pytest

from phoenix_os.control_plane import (
    AdminTokenAuthenticator,
    ControlPlaneBrowserOrigin,
    ControlPlaneDurableSessionAuthentication,
    ControlPlaneDurableSessionCsrfRejectedError,
    ControlPlaneHttpServer,
    ControlPlaneInboundManagementHttpAdapter,
    ControlPlanePrincipal,
    ControlPlaneReader,
    ControlPlaneStepUpRejectedError,
)
from phoenix_os.control_plane.operator_contracts import (
    ControlPlaneOperatorRole,
)
from phoenix_os.control_plane.step_up import ControlPlaneStepUpAction
from phoenix_os.events import Event, EventBus
from phoenix_os.inbound_events import (
    InboundAcceptance,
    InboundAcceptedEvent,
    InboundEventPublisher,
    InboundEventReceipt,
    InboundEventSchema,
    InboundEventSource,
    InboundHmacPolicy,
    InboundManager,
    InboundPublicationDisposition,
    InboundPublicationRecovery,
    InboundPublicationRetryPolicy,
    InboundReplayKind,
    InboundReplayReservation,
    InboundSchemaRegistry,
    canonical_inbound_json_bytes,
    create_in_memory_inbound_repositories,
    inbound_evidence_digest,
)
from phoenix_os.secrets import SecretRef

_NOW = datetime(2026, 7, 25, 12, 0, tzinfo=UTC)
_LATER = _NOW + timedelta(minutes=3)
_ORIGIN = ControlPlaneBrowserOrigin("http://127.0.0.1:9443")
_SOURCE_ID = UUID("00000000-0000-4000-8000-000000001501")
_EVENT_ID = UUID("00000000-0000-4000-8000-000000002501")
_RECEIPT_ID = UUID("00000000-0000-4000-8000-000000003501")
_SESSION_ID = UUID("00000000-0000-4000-8000-000000004501")
_OPERATOR_ID = UUID("00000000-0000-4000-8000-000000005501")


class _Normalizer:
    schema = InboundEventSchema(
        event_type="release.completed",
        event_schema_version=1,
        internal_event_type="external.release.completed",
        required_fields=frozenset({"release", "status"}),
        optional_fields=frozenset({"private"}),
    )

    def normalize(
        self,
        payload: Mapping[str, object],
    ) -> Mapping[str, object]:
        return dict(payload)


class _Boundary:
    def __init__(self, *, reject: bool = False) -> None:
        self.reject = reject
        self.calls = 0

    async def verify_csrf(
        self,
        token_value: str | None,
        authentication: ControlPlaneDurableSessionAuthentication,
        *,
        supplied_origin: ControlPlaneBrowserOrigin,
        expected_origin: ControlPlaneBrowserOrigin,
    ) -> object:
        self.calls += 1
        if self.reject:
            raise ControlPlaneDurableSessionCsrfRejectedError("CSRF rejected")
        assert token_value == "csrf-value"
        assert authentication.session_id == _SESSION_ID
        assert supplied_origin == _ORIGIN
        assert expected_origin == _ORIGIN
        return object()


class _StepUp:
    calls: ClassVar[
        list[
            tuple[
                str | None,
                ControlPlaneDurableSessionAuthentication,
                ControlPlaneStepUpAction,
            ]
        ]
    ] = []

    def __init__(self, *, reject: bool = False) -> None:
        type(self).calls = []
        self.reject = reject

    async def verify(
        self,
        token_value: str | None,
        session: ControlPlaneDurableSessionAuthentication,
        action: ControlPlaneStepUpAction,
    ) -> object:
        type(self).calls.append((token_value, session, action))
        if self.reject:
            raise ControlPlaneStepUpRejectedError("step-up rejected")
        assert token_value == "step-up-value"
        return object()


def _last_step_up_action() -> ControlPlaneStepUpAction:
    return _StepUp.calls[-1][2]


def _principal(
    *,
    maintainer: bool = True,
) -> ControlPlanePrincipal:
    role = ControlPlaneOperatorRole.MAINTAINER if maintainer else ControlPlaneOperatorRole.OPERATOR
    return ControlPlanePrincipal(
        "maintainer" if maintainer else "operator",
        role.permissions,
    )


def _authentication(
    *,
    maintainer: bool = True,
) -> ControlPlaneDurableSessionAuthentication:
    return ControlPlaneDurableSessionAuthentication(
        session_id=_SESSION_ID,
        operator_id=_OPERATOR_ID,
        principal=_principal(maintainer=maintainer),
        generation=1,
        authenticated_at=_NOW,
        absolute_expires_at=_NOW + timedelta(hours=2),
        idle_expires_at=_NOW + timedelta(minutes=30),
    )


def _source(
    *,
    retry: InboundPublicationRetryPolicy | None = None,
) -> InboundEventSource:
    return InboundEventSource(
        id=_SOURCE_ID,
        name="release.events",
        display_name="Release Events",
        authentication=InboundHmacPolicy(SecretRef("must-not-leak", "integrations", 1)),
        event_types=frozenset({"release.completed"}),
        created_at=_NOW,
        updated_at=_NOW,
        created_by="maintainer:test",
        retry=retry or InboundPublicationRetryPolicy(),
    )


def _acceptance(source: InboundEventSource) -> InboundAcceptance:
    payload = {
        "release": "0.25.0",
        "status": "completed",
        "private": "must-not-leak",
    }
    digest = hashlib.sha256(canonical_inbound_json_bytes(payload)).hexdigest()
    event = InboundAcceptedEvent(
        id=_EVENT_ID,
        receipt_id=_RECEIPT_ID,
        source_id=source.id,
        source_event_id="source-event-must-not-leak",
        external_event_type="release.completed",
        external_schema_version=1,
        internal_event_type="external.release.completed",
        occurred_at=_NOW,
        accepted_at=_NOW,
        updated_at=_NOW,
        normalized_payload=payload,
        normalized_payload_sha256=digest,
        correlation_id="inbound-correlation",
        next_attempt_at=_NOW,
    )
    receipt = InboundEventReceipt(
        id=_RECEIPT_ID,
        accepted_event_id=event.id,
        source_id=source.id,
        source_event_id=event.source_event_id,
        external_event_type=event.external_event_type,
        external_schema_version=event.external_schema_version,
        accepted_at=event.accepted_at,
        correlation_id=event.correlation_id,
    )
    reservations = tuple(
        InboundReplayReservation(
            source_id=source.id,
            kind=kind,
            evidence_digest=inbound_evidence_digest(
                source.id,
                kind,
                value,
            ),
            accepted_event_id=event.id,
            created_at=_NOW,
            expires_at=_NOW + timedelta(days=1),
            normalized_payload_sha256=(
                digest if kind is InboundReplayKind.SOURCE_EVENT_ID else None
            ),
        )
        for kind, value in (
            (InboundReplayKind.REQUEST_ID, "request-000001"),
            (InboundReplayKind.NONCE, "nonce-000001"),
            (
                InboundReplayKind.SOURCE_EVENT_ID,
                event.source_event_id,
            ),
        )
    )
    return InboundAcceptance(event, receipt, reservations)


async def _system(
    *,
    with_source: bool = False,
    with_event: bool = False,
    dead_letter: bool = False,
    maintainer: bool = True,
    reject_csrf: bool = False,
    reject_step_up: bool = False,
) -> tuple[
    ControlPlaneInboundManagementHttpAdapter,
    _Boundary,
    _StepUp,
    ControlPlaneDurableSessionAuthentication,
]:
    repositories = create_in_memory_inbound_repositories()
    schemas = InboundSchemaRegistry()
    schemas.register(_Normalizer())
    source = _source(retry=(InboundPublicationRetryPolicy(max_attempts=1) if dead_letter else None))
    if with_source or with_event or dead_letter:
        await repositories.sources.add(source)
    if with_event or dead_letter:
        await repositories.events.accept(_acceptance(source))
    if dead_letter:
        bus = EventBus()

        async def fail(event: Event) -> None:
            del event
            raise RuntimeError("private-handler-failure")

        await bus.subscribe("external.release.completed", fail)
        publisher = InboundEventPublisher(
            sources=repositories.sources,
            events=repositories.events,
            event_bus=bus,
            clock=lambda: _NOW,
        )
        result = await publisher.publish(_EVENT_ID)
        assert result.disposition is InboundPublicationDisposition.DEAD_LETTER

    recovery = InboundPublicationRecovery(
        sources=repositories.sources,
        events=repositories.events,
        replay=repositories.replay,
        clock=lambda: _LATER,
    )
    manager = InboundManager(
        sources=repositories.sources,
        events=repositories.events,
        replay=repositories.replay,
        recovery=recovery,
        schemas=schemas,
        clock=lambda: _LATER,
        source_id_factory=lambda: _SOURCE_ID,
    )
    boundary = _Boundary(reject=reject_csrf)
    step_up = _StepUp(reject=reject_step_up)
    adapter = ControlPlaneInboundManagementHttpAdapter(
        manager=manager,
        boundary=boundary,
        step_up=step_up,
    )
    return (
        adapter,
        boundary,
        step_up,
        _authentication(maintainer=maintainer),
    )


def _headers(
    *,
    origin: str = "http://127.0.0.1:9443",
    step_up: bool = True,
) -> dict[str, tuple[str, ...]]:
    result: dict[str, tuple[str, ...]] = {
        "origin": (origin,),
        "x-phoenix-csrf": ("csrf-value",),
    }
    if step_up:
        result["x-phoenix-step-up"] = ("step-up-value",)
    return result


def _body(value: Mapping[str, object]) -> bytes:
    return json.dumps(dict(value)).encode("utf-8")


def _create_document() -> dict[str, object]:
    return {
        "name": "release.events",
        "display_name": "Release Events",
        "authentication": {
            "mode": "hmac_sha256",
            "secret_name": "must-not-leak",
            "secret_namespace": "private-namespace",
            "secret_version": 3,
        },
        "event_types": ["release.completed"],
        "retry": {
            "max_attempts": 3,
            "initial_delay_seconds": 2,
            "max_delay_seconds": 30,
        },
    }


def test_adapter_handles_only_inbound_management_routes() -> None:
    assert ControlPlaneInboundManagementHttpAdapter.handles("/v1/control-plane/inbound/sources")
    assert ControlPlaneInboundManagementHttpAdapter.handles(
        f"/v1/control-plane/inbound/events/{_EVENT_ID}"
    )
    assert not ControlPlaneInboundManagementHttpAdapter.handles("/v1/inbound/release.events")


@pytest.mark.asyncio
async def test_server_requires_durable_session_for_adapter() -> None:
    adapter, _, _, _ = await _system()
    with pytest.raises(
        ValueError,
        match="inbound management HTTP requires durable session",
    ):
        ControlPlaneHttpServer(
            cast(ControlPlaneReader, object()),
            AdminTokenAuthenticator("a" * 32),
            inbound_management_http=adapter,
        )


@pytest.mark.asyncio
async def test_create_source_is_disabled_and_hides_secret_reference() -> None:
    adapter, boundary, _, authentication = await _system()

    status, payload, headers = await adapter.dispatch(
        authentication=authentication,
        method="POST",
        path="/v1/control-plane/inbound/sources",
        query={},
        headers=_headers(),
        body=_body(_create_document()),
        server_origin=_ORIGIN,
    )

    assert status is HTTPStatus.CREATED
    assert headers["Cache-Control"] == "no-store"
    assert boundary.calls == 1
    assert _last_step_up_action() is ControlPlaneStepUpAction.CREATE_INBOUND_SOURCE
    rendered = json.dumps(dict(payload), sort_keys=True)
    assert '"status": "disabled"' in rendered
    assert '"key_version": 3' in rendered
    assert "must-not-leak" not in rendered
    assert "private-namespace" not in rendered


@pytest.mark.asyncio
async def test_operator_cannot_read_or_mutate_sources() -> None:
    adapter, _, _, authentication = await _system(
        with_source=True,
        maintainer=False,
    )

    read_status, _, read_headers = await adapter.dispatch(
        authentication=authentication,
        method="GET",
        path=f"/v1/control-plane/inbound/sources/{_SOURCE_ID}",
        query={},
        headers={},
        body=b"",
        server_origin=_ORIGIN,
    )
    create_status, _, create_headers = await adapter.dispatch(
        authentication=authentication,
        method="POST",
        path="/v1/control-plane/inbound/sources",
        query={},
        headers=_headers(),
        body=_body(_create_document()),
        server_origin=_ORIGIN,
    )

    assert read_status is HTTPStatus.FORBIDDEN
    assert create_status is HTTPStatus.FORBIDDEN
    assert read_headers["Cache-Control"] == "no-store"
    assert create_headers["Cache-Control"] == "no-store"


@pytest.mark.asyncio
async def test_source_list_and_health_are_bounded_safe_views() -> None:
    adapter, _, _, authentication = await _system(with_source=True)

    source_status, source_payload, _ = await adapter.dispatch(
        authentication=authentication,
        method="GET",
        path="/v1/control-plane/inbound/sources",
        query={"offset": ("0",), "limit": ("10",)},
        headers={},
        body=b"",
        server_origin=_ORIGIN,
    )
    health_status, health_payload, _ = await adapter.dispatch(
        authentication=authentication,
        method="GET",
        path="/v1/control-plane/inbound/health",
        query={},
        headers={},
        body=b"",
        server_origin=_ORIGIN,
    )

    assert source_status is HTTPStatus.OK
    assert health_status is HTTPStatus.OK
    rendered = json.dumps(dict(source_payload), sort_keys=True)
    assert "must-not-leak" not in rendered
    assert health_payload["sources"] == {
        "closed": False,
        "sources": 1,
        "active": 1,
        "disabled": 0,
        "revoked": 0,
        "capacity": 256,
    }


@pytest.mark.asyncio
async def test_event_view_excludes_payload_digest_and_source_event_id() -> None:
    adapter, _, _, authentication = await _system(with_event=True)

    event_status, event_payload, _ = await adapter.dispatch(
        authentication=authentication,
        method="GET",
        path=f"/v1/control-plane/inbound/events/{_EVENT_ID}",
        query={},
        headers={},
        body=b"",
        server_origin=_ORIGIN,
    )
    receipt_status, receipt_payload, _ = await adapter.dispatch(
        authentication=authentication,
        method="GET",
        path=f"/v1/control-plane/inbound/receipts/{_RECEIPT_ID}",
        query={},
        headers={},
        body=b"",
        server_origin=_ORIGIN,
    )

    assert event_status is HTTPStatus.OK
    assert receipt_status is HTTPStatus.OK
    event_rendered = json.dumps(dict(event_payload), sort_keys=True)
    assert "must-not-leak" not in event_rendered
    assert "normalized_payload" not in event_rendered
    assert "normalized_payload_sha256" not in event_rendered
    assert "source-event-must-not-leak" not in event_rendered
    assert receipt_payload["source_event_id"] == "source-event-must-not-leak"


@pytest.mark.asyncio
async def test_source_lifecycle_uses_csrf_and_reviewed_step_up_actions() -> None:
    adapter, boundary, _, authentication = await _system(with_source=True)

    disable_status, disable_payload, _ = await adapter.dispatch(
        authentication=authentication,
        method="POST",
        path=f"/v1/control-plane/inbound/sources/{_SOURCE_ID}/disable",
        query={},
        headers=_headers(step_up=False),
        body=_body({"expected_revision": 1}),
        server_origin=_ORIGIN,
    )
    assert disable_status is HTTPStatus.OK
    assert disable_payload["status"] == "disabled"
    assert boundary.calls == 1
    assert not _StepUp.calls

    enable_status, enable_payload, _ = await adapter.dispatch(
        authentication=authentication,
        method="POST",
        path=f"/v1/control-plane/inbound/sources/{_SOURCE_ID}/enable",
        query={},
        headers=_headers(),
        body=_body({"expected_revision": 2}),
        server_origin=_ORIGIN,
    )
    assert enable_status is HTTPStatus.OK
    assert enable_payload["status"] == "active"
    assert _last_step_up_action() is ControlPlaneStepUpAction.ENABLE_INBOUND_SOURCE


@pytest.mark.asyncio
async def test_sensitive_mutation_rejects_missing_step_up() -> None:
    adapter, _, _, authentication = await _system(reject_step_up=True)

    status, payload, headers = await adapter.dispatch(
        authentication=authentication,
        method="POST",
        path="/v1/control-plane/inbound/sources",
        query={},
        headers=_headers(),
        body=_body(_create_document()),
        server_origin=_ORIGIN,
    )

    assert status is HTTPStatus.FORBIDDEN
    assert payload == {"error": "request_rejected"}
    assert headers["Cache-Control"] == "no-store"


@pytest.mark.asyncio
async def test_mutation_rejects_invalid_origin_before_manager() -> None:
    adapter, boundary, _, authentication = await _system()

    status, payload, _ = await adapter.dispatch(
        authentication=authentication,
        method="POST",
        path="/v1/control-plane/inbound/sources",
        query={},
        headers=_headers(origin="http://127.0.0.1:9999"),
        body=_body(_create_document()),
        server_origin=_ORIGIN,
    )

    assert status is HTTPStatus.FORBIDDEN
    assert payload == {"error": "request_rejected"}
    assert boundary.calls == 0


@pytest.mark.asyncio
async def test_dead_letter_redrive_preserves_event_identity() -> None:
    adapter, _, _, authentication = await _system(dead_letter=True)

    status, payload, headers = await adapter.dispatch(
        authentication=authentication,
        method="POST",
        path=f"/v1/control-plane/inbound/events/{_EVENT_ID}/redrive",
        query={},
        headers=_headers(),
        body=_body({}),
        server_origin=_ORIGIN,
    )

    assert status is HTTPStatus.ACCEPTED
    assert payload["accepted_event_id"] == str(_EVENT_ID)
    assert payload["status"] == "retrying"
    assert headers["Cache-Control"] == "no-store"
    assert _last_step_up_action() is ControlPlaneStepUpAction.REDRIVE_INBOUND_EVENT


@pytest.mark.asyncio
async def test_duplicate_json_keys_fail_closed() -> None:
    adapter, _, _, authentication = await _system()

    status, payload, _ = await adapter.dispatch(
        authentication=authentication,
        method="POST",
        path="/v1/control-plane/inbound/sources",
        query={},
        headers=_headers(),
        body=b'{"name":"one","name":"two"}',
        server_origin=_ORIGIN,
    )

    assert status is HTTPStatus.BAD_REQUEST
    assert payload == {"error": "invalid_inbound_request"}
