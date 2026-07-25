from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from http import HTTPStatus
from pathlib import Path
from uuid import UUID

import pytest

from phoenix_os.control_plane import (
    CONTROL_PLANE_INBOUND_MACHINE_BASE_PATH,
    CONTROL_PLANE_INBOUND_MACHINE_RESOURCE,
    ControlPlaneInboundMachineAdministration,
    control_plane_inbound_machine_routes,
)
from phoenix_os.control_plane import (
    service_account_authentication as service_account_authentication_module,
)
from phoenix_os.control_plane.network_contracts import (
    ControlPlaneClientIdentitySource,
)
from phoenix_os.control_plane.service_account_audit import (
    ControlPlaneServiceAccountAudit,
    ControlPlaneServiceAccountAuditProtector,
)
from phoenix_os.control_plane.service_account_authentication import (
    ControlPlaneServiceAccountAuthentication,
    ControlPlaneServiceAccountAuthenticationContext,
)
from phoenix_os.control_plane.service_account_authorization import (
    ControlPlaneServiceAccountPermissionDeniedError,
)
from phoenix_os.control_plane.service_account_machine_http import (
    ControlPlaneServiceAccountMachineHttpAdapter,
)
from phoenix_os.control_plane.service_account_policy import (
    ControlPlaneServiceAccountApiContext,
)
from phoenix_os.control_plane.service_account_replay import (
    ControlPlaneServiceAccountReplayRequest,
)
from phoenix_os.events import Event, EventBus
from phoenix_os.inbound_events import (
    INBOUND_EVENTS_READ_PERMISSION,
    INBOUND_RECEIPTS_READ_PERMISSION,
    INBOUND_REDRIVE_PERMISSION,
    INBOUND_SOURCES_AUTHENTICATION_PERMISSION,
    INBOUND_SOURCES_DISABLE_PERMISSION,
    INBOUND_SOURCES_ENABLE_PERMISSION,
    INBOUND_SOURCES_READ_PERMISSION,
    INBOUND_SOURCES_REVOKE_PERMISSION,
    INBOUND_SOURCES_ROTATE_PERMISSION,
    INBOUND_SOURCES_UPDATE_PERMISSION,
    InboundAcceptance,
    InboundAcceptedEvent,
    InboundEventPublisher,
    InboundEventReceipt,
    InboundEventSchema,
    InboundEventSource,
    InboundHmacPolicy,
    InboundManager,
    InboundManagerConfig,
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

_NOW = datetime(2026, 7, 26, 12, 0, tzinfo=UTC)
_LATER = _NOW + timedelta(minutes=3)
_ACCOUNT_ID = UUID("10000000-0000-4000-8000-000000000025")
_TOKEN_ID = UUID("20000000-0000-4000-8000-000000000025")
_SOURCE_ID = UUID("30000000-0000-4000-8000-000000000025")
_EVENT_ID = UUID("40000000-0000-4000-8000-000000000025")
_RECEIPT_ID = UUID("50000000-0000-4000-8000-000000000025")
_RFC = (
    Path(__file__).resolve().parents[1]
    / "docs"
    / "rfcs"
    / "RFC-0025-secure-inbound-event-gateway-and-external-event-sources.md"
)
_CSS = (
    Path(__file__).resolve().parents[1]
    / "src"
    / "phoenix_os"
    / "control_plane"
    / "dashboard"
    / "app.css"
)

_ALL_SCOPES = frozenset(
    {
        INBOUND_SOURCES_READ_PERMISSION,
        INBOUND_SOURCES_UPDATE_PERMISSION,
        INBOUND_SOURCES_AUTHENTICATION_PERMISSION,
        INBOUND_SOURCES_DISABLE_PERMISSION,
        INBOUND_SOURCES_ENABLE_PERMISSION,
        INBOUND_SOURCES_REVOKE_PERMISSION,
        INBOUND_SOURCES_ROTATE_PERMISSION,
        INBOUND_EVENTS_READ_PERMISSION,
        INBOUND_RECEIPTS_READ_PERMISSION,
        INBOUND_REDRIVE_PERMISSION,
    }
)


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


class _Authentication:
    def __init__(
        self,
        evidence: ControlPlaneServiceAccountAuthentication | None,
    ) -> None:
        self.evidence = evidence
        self.calls = 0

    async def authenticate(
        self,
        authorization: str | None,
        *,
        context: ControlPlaneServiceAccountAuthenticationContext,
        request: ControlPlaneServiceAccountReplayRequest,
    ) -> ControlPlaneServiceAccountAuthentication | None:
        del authorization, context, request
        self.calls += 1
        return self.evidence


class _Policy:
    def __init__(
        self,
        *,
        denied: bool = False,
    ) -> None:
        self.denied = denied
        self.calls: list[tuple[str, str]] = []

    async def enforce(
        self,
        context: ControlPlaneServiceAccountApiContext,
        *,
        action: str,
        resource: str,
    ) -> object:
        del context
        self.calls.append((action, resource))
        if self.denied:
            raise ControlPlaneServiceAccountPermissionDeniedError(
                "service-account authorization denied"
            )
        return object()


def _source_resource() -> str:
    return f"inbound-source:{_SOURCE_ID}"


def _event_resource() -> str:
    return f"inbound-event:{_EVENT_ID}"


def _receipt_resource() -> str:
    return f"inbound-receipt:{_RECEIPT_ID}"


def _evidence(
    *,
    scopes: frozenset[str] = _ALL_SCOPES,
    resources: frozenset[str] | None = None,
) -> ControlPlaneServiceAccountAuthentication:
    resolved_resources = (
        frozenset(
            {
                CONTROL_PLANE_INBOUND_MACHINE_RESOURCE,
                _source_resource(),
                _event_resource(),
                _receipt_resource(),
            }
        )
        if resources is None
        else resources
    )
    return ControlPlaneServiceAccountAuthentication(
        service_account_id=_ACCOUNT_ID,
        token_id=_TOKEN_ID,
        account_name="inbound.bot",
        scopes=scopes,
        resources=resolved_resources,
        token_version=1,
        account_revision=1,
        token_revision=1,
        authenticated_at=_NOW,
        expires_at=_NOW + timedelta(hours=1),
    )


def _transport_context() -> ControlPlaneServiceAccountAuthenticationContext:
    return ControlPlaneServiceAccountAuthenticationContext(
        client_address="127.0.0.1",
        peer_address="127.0.0.1",
        identity_source=ControlPlaneClientIdentitySource.DIRECT,
        _authority=(service_account_authentication_module._CONTEXT_AUTHORITY),
    )


def _source(
    *,
    retry: InboundPublicationRetryPolicy | None = None,
) -> InboundEventSource:
    return InboundEventSource(
        id=_SOURCE_ID,
        name="release.events",
        display_name="Release Events",
        authentication=InboundHmacPolicy(
            SecretRef(
                "release-inbound",
                "integrations",
                1,
            )
        ),
        event_types=frozenset({"release.completed"}),
        created_at=_NOW,
        updated_at=_NOW,
        created_by="maintainer:test",
        retry=retry or InboundPublicationRetryPolicy(),
    )


def _acceptance(
    source: InboundEventSource,
) -> InboundAcceptance:
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
            (
                InboundReplayKind.REQUEST_ID,
                "request-000001",
            ),
            (
                InboundReplayKind.NONCE,
                "nonce-000001",
            ),
            (
                InboundReplayKind.SOURCE_EVENT_ID,
                event.source_event_id,
            ),
        )
    )
    return InboundAcceptance(
        event,
        receipt,
        reservations,
    )


async def _manager(
    *,
    machine: bool,
    with_event: bool = False,
    dead_letter: bool = False,
) -> InboundManager:
    repositories = create_in_memory_inbound_repositories()
    schemas = InboundSchemaRegistry()
    schemas.register(_Normalizer())
    source = _source(retry=(InboundPublicationRetryPolicy(max_attempts=1) if dead_letter else None))
    await repositories.sources.add(source)
    if with_event or dead_letter:
        await repositories.events.accept(_acceptance(source))
    if dead_letter:
        bus = EventBus()

        async def fail(event: Event) -> None:
            del event
            raise RuntimeError("private-handler-failure")

        await bus.subscribe(
            "external.release.completed",
            fail,
        )
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
    return InboundManager(
        sources=repositories.sources,
        events=repositories.events,
        replay=repositories.replay,
        recovery=recovery,
        schemas=schemas,
        config=InboundManagerConfig(machine_administration_enabled=machine),
        clock=lambda: _LATER,
    )


async def _system(
    *,
    machine: bool = True,
    evidence: ControlPlaneServiceAccountAuthentication | None = None,
    policy_denied: bool = False,
    with_event: bool = False,
    dead_letter: bool = False,
) -> tuple[
    InboundManager,
    ControlPlaneServiceAccountMachineHttpAdapter,
    _Authentication,
    _Policy,
]:
    manager = await _manager(
        machine=machine,
        with_event=with_event,
        dead_letter=dead_letter,
    )
    authentication = _Authentication(_evidence() if evidence is None else evidence)
    policy = _Policy(denied=policy_denied)
    audit = ControlPlaneServiceAccountAudit(
        None,
        ControlPlaneServiceAccountAuditProtector(b"a" * 32),
    )
    adapter = ControlPlaneServiceAccountMachineHttpAdapter(
        authentication=authentication,
        policy=policy,
        audit=audit,
        routes=control_plane_inbound_machine_routes(manager),
    )
    return manager, adapter, authentication, policy


def _headers() -> dict[str, tuple[str, ...]]:
    return {
        "authorization": ("Bearer phx_sa_" + "A" * 48,),
        "x-phoenix-request-nonce": ("N" * 32,),
        "x-phoenix-request-timestamp": (_NOW.isoformat(),),
        "content-type": ("application/json",),
    }


async def _dispatch(
    adapter: ControlPlaneServiceAccountMachineHttpAdapter,
    *,
    method: str,
    path: str,
    document: Mapping[str, object] | None = None,
    query: dict[str, tuple[str, ...]] | None = None,
    headers: dict[str, tuple[str, ...]] | None = None,
) -> tuple[
    HTTPStatus,
    dict[str, object],
    dict[str, str],
]:
    body = (
        b""
        if document is None
        else json.dumps(
            dict(document),
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    )
    status, payload, response_headers = await adapter.dispatch(
        context=_transport_context(),
        method=method,
        path=path,
        query={} if query is None else query,
        headers=_headers() if headers is None else headers,
        body=body,
    )
    return status, dict(payload), response_headers


def test_machine_constants_are_canonical() -> None:
    assert CONTROL_PLANE_INBOUND_MACHINE_BASE_PATH == "/v1/control-plane/machine/inbound"
    assert CONTROL_PLANE_INBOUND_MACHINE_RESOURCE == "inbound-machine"


@pytest.mark.asyncio
async def test_route_set_is_concrete_and_has_no_aggregate_routes() -> None:
    manager = await _manager(machine=True)
    administration = ControlPlaneInboundMachineAdministration(manager)
    routes = administration.routes

    assert len(routes) == 10
    assert (
        len(
            {
                (
                    route.method,
                    route.path,
                )
                for route in routes
            }
        )
        == 10
    )
    assert {route.action for route in routes} == _ALL_SCOPES
    assert {route.resource for route in routes} == {CONTROL_PLANE_INBOUND_MACHINE_RESOURCE}
    paths = {route.path for route in routes}
    assert f"{CONTROL_PLANE_INBOUND_MACHINE_BASE_PATH}/sources" not in paths
    assert f"{CONTROL_PLANE_INBOUND_MACHINE_BASE_PATH}/events" not in paths
    assert f"{CONTROL_PLANE_INBOUND_MACHINE_BASE_PATH}/health" not in paths
    assert all(
        route.path.startswith(f"{CONTROL_PLANE_INBOUND_MACHINE_BASE_PATH}/") for route in routes
    )


@pytest.mark.asyncio
async def test_machine_administration_remains_disabled_by_default() -> None:
    _, adapter, _, _ = await _system(machine=False)

    status, payload, headers = await _dispatch(
        adapter,
        method="GET",
        path=f"{CONTROL_PLANE_INBOUND_MACHINE_BASE_PATH}/source",
        query={"source_id": (str(_SOURCE_ID),)},
    )

    assert status is HTTPStatus.FORBIDDEN
    assert payload == {"error": "forbidden"}
    assert headers == {"Cache-Control": "no-store"}


@pytest.mark.asyncio
async def test_source_read_requires_gateway_and_concrete_resource() -> None:
    _, adapter, _, policy = await _system()

    status, payload, headers = await _dispatch(
        adapter,
        method="GET",
        path=f"{CONTROL_PLANE_INBOUND_MACHINE_BASE_PATH}/source",
        query={"source_id": (str(_SOURCE_ID),)},
    )

    assert status is HTTPStatus.OK
    assert headers == {"Cache-Control": "no-store"}
    assert payload["id"] == str(_SOURCE_ID)
    rendered = json.dumps(payload, sort_keys=True)
    assert "release-inbound" not in rendered
    assert "integrations" not in rendered
    assert policy.calls == [
        (
            INBOUND_SOURCES_READ_PERMISSION,
            CONTROL_PLANE_INBOUND_MACHINE_RESOURCE,
        )
    ]

    wrong = _evidence(
        resources=frozenset(
            {
                CONTROL_PLANE_INBOUND_MACHINE_RESOURCE,
                "inbound-source:00000000-0000-4000-8000-000000000999",
            }
        )
    )
    _, denied_adapter, _, _ = await _system(evidence=wrong)
    denied_status, denied_payload, _ = await _dispatch(
        denied_adapter,
        method="GET",
        path=f"{CONTROL_PLANE_INBOUND_MACHINE_BASE_PATH}/source",
        query={"source_id": (str(_SOURCE_ID),)},
    )
    assert denied_status is HTTPStatus.FORBIDDEN
    assert denied_payload == {"error": "forbidden"}


@pytest.mark.asyncio
async def test_source_update_and_lifecycle_are_resource_bound() -> None:
    _, adapter, _, _ = await _system()

    update_status, updated, _ = await _dispatch(
        adapter,
        method="POST",
        path=(f"{CONTROL_PLANE_INBOUND_MACHINE_BASE_PATH}/source/update"),
        document={
            "source_id": str(_SOURCE_ID),
            "expected_revision": 1,
            "display_name": "Release Events Updated",
        },
    )
    assert update_status is HTTPStatus.OK
    assert updated["display_name"] == "Release Events Updated"
    assert updated["revision"] == 2

    disable_status, disabled, _ = await _dispatch(
        adapter,
        method="POST",
        path=(f"{CONTROL_PLANE_INBOUND_MACHINE_BASE_PATH}/source/disable"),
        document={
            "source_id": str(_SOURCE_ID),
            "expected_revision": 2,
        },
    )
    assert disable_status is HTTPStatus.OK
    assert disabled["status"] == "disabled"

    enable_status, enabled, _ = await _dispatch(
        adapter,
        method="POST",
        path=(f"{CONTROL_PLANE_INBOUND_MACHINE_BASE_PATH}/source/enable"),
        document={
            "source_id": str(_SOURCE_ID),
            "expected_revision": 3,
        },
    )
    assert enable_status is HTTPStatus.OK
    assert enabled["status"] == "active"
    assert enabled["revision"] == 4


@pytest.mark.asyncio
async def test_hmac_rotation_keeps_secret_reference_private() -> None:
    _, adapter, _, _ = await _system()

    status, payload, _ = await _dispatch(
        adapter,
        method="POST",
        path=(f"{CONTROL_PLANE_INBOUND_MACHINE_BASE_PATH}/source/rotate-hmac-key"),
        document={
            "source_id": str(_SOURCE_ID),
            "expected_revision": 1,
            "secret_name": "release-inbound",
            "secret_namespace": "integrations",
            "secret_version": 2,
            "predecessor_valid_until": (_LATER + timedelta(minutes=10)).isoformat(),
        },
    )

    assert status is HTTPStatus.OK
    authentication = payload["authentication"]
    assert isinstance(authentication, dict)
    assert authentication["key_version"] == 2
    assert authentication["predecessor_key_version"] == 1
    rendered = json.dumps(payload, sort_keys=True)
    assert "release-inbound" not in rendered
    assert "integrations" not in rendered


@pytest.mark.asyncio
async def test_event_and_receipt_reads_are_payload_free_and_exact() -> None:
    _, adapter, _, _ = await _system(with_event=True)

    event_status, event, event_headers = await _dispatch(
        adapter,
        method="GET",
        path=f"{CONTROL_PLANE_INBOUND_MACHINE_BASE_PATH}/event",
        query={"event_id": (str(_EVENT_ID),)},
    )
    receipt_status, receipt, receipt_headers = await _dispatch(
        adapter,
        method="GET",
        path=(f"{CONTROL_PLANE_INBOUND_MACHINE_BASE_PATH}/receipt"),
        query={"receipt_id": (str(_RECEIPT_ID),)},
    )

    assert event_status is HTTPStatus.OK
    assert receipt_status is HTTPStatus.OK
    assert event_headers == {"Cache-Control": "no-store"}
    assert receipt_headers == {"Cache-Control": "no-store"}
    rendered = json.dumps(event, sort_keys=True)
    assert "normalized_payload" not in rendered
    assert "normalized_payload_sha256" not in rendered
    assert "source-event-must-not-leak" not in rendered
    assert receipt["source_event_id"] == "source-event-must-not-leak"


@pytest.mark.asyncio
async def test_dead_letter_redrive_preserves_stable_identity() -> None:
    _, adapter, _, _ = await _system(dead_letter=True)

    status, payload, headers = await _dispatch(
        adapter,
        method="POST",
        path=(f"{CONTROL_PLANE_INBOUND_MACHINE_BASE_PATH}/event/redrive"),
        document={"event_id": str(_EVENT_ID)},
    )

    assert status is HTTPStatus.ACCEPTED
    assert payload["accepted_event_id"] == str(_EVENT_ID)
    assert payload["status"] == "retrying"
    assert headers == {"Cache-Control": "no-store"}


@pytest.mark.asyncio
async def test_missing_scope_or_central_policy_denial_fails_closed() -> None:
    missing_scope = _evidence(scopes=frozenset(_ALL_SCOPES - {INBOUND_SOURCES_READ_PERMISSION}))
    _, scoped_adapter, _, _ = await _system(evidence=missing_scope)
    scoped_status, scoped_payload, _ = await _dispatch(
        scoped_adapter,
        method="GET",
        path=f"{CONTROL_PLANE_INBOUND_MACHINE_BASE_PATH}/source",
        query={"source_id": (str(_SOURCE_ID),)},
    )
    assert scoped_status is HTTPStatus.FORBIDDEN
    assert scoped_payload == {"error": "forbidden"}

    _, policy_adapter, _, policy = await _system(policy_denied=True)
    policy_status, policy_payload, _ = await _dispatch(
        policy_adapter,
        method="GET",
        path=f"{CONTROL_PLANE_INBOUND_MACHINE_BASE_PATH}/source",
        query={"source_id": (str(_SOURCE_ID),)},
    )
    assert policy_status is HTTPStatus.FORBIDDEN
    assert policy_payload == {"error": "forbidden"}
    assert policy.calls == [
        (
            INBOUND_SOURCES_READ_PERMISSION,
            CONTROL_PLANE_INBOUND_MACHINE_RESOURCE,
        )
    ]


@pytest.mark.asyncio
async def test_mutations_reject_duplicate_json_keys() -> None:
    _, adapter, _, _ = await _system()
    body = (
        b'{"source_id":"'
        + str(_SOURCE_ID).encode("ascii")
        + b'","expected_revision":1,"expected_revision":2}'
    )
    status, payload, _ = await adapter.dispatch(
        context=_transport_context(),
        method="POST",
        path=(f"{CONTROL_PLANE_INBOUND_MACHINE_BASE_PATH}/source/disable"),
        query={},
        headers=_headers(),
        body=body,
    )

    assert status is HTTPStatus.BAD_REQUEST
    assert payload == {"error": "invalid_inbound_request"}


def test_dashboard_css_has_one_terminal_newline() -> None:
    css = _CSS.read_text(encoding="utf-8")
    assert css.endswith("\n")
    assert not css.endswith("\n\n")


def test_rfc_marks_optional_machine_administration_complete() -> None:
    rfc = _RFC.read_text(encoding="utf-8")
    assert "- [x] Optional scoped service-account administration" in rfc
    assert "Machine administration remains disabled by default" in rfc
