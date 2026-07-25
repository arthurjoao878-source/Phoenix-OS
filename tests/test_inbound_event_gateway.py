from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from http import HTTPStatus
from typing import Any
from uuid import UUID

import pytest

from phoenix_os.configuration import SecretValue
from phoenix_os.inbound_events import (
    INBOUND_CONTENT_TYPE,
    INBOUND_CORRELATION_ID_HEADER,
    INBOUND_KEY_VERSION_HEADER,
    INBOUND_NONCE_HEADER,
    INBOUND_REQUEST_ID_HEADER,
    INBOUND_SIGNATURE_HEADER,
    INBOUND_SOURCE_EVENT_ID_HEADER,
    INBOUND_TIMESTAMP_HEADER,
    InboundAdmissionLimiter,
    InboundAdmissionLimitPolicy,
    InboundAuthenticationResult,
    InboundAuthenticationVerifier,
    InboundEventGateway,
    InboundEventSchema,
    InboundEventSource,
    InboundEventSourceStatus,
    InboundHmacPolicy,
    InboundHttpAdapter,
    InboundHttpResponse,
    InboundHttpRoute,
    InboundNormalizedEnvelope,
    InboundPolicyDeniedError,
    InboundReplayIdempotencyService,
    InboundSchemaRegistry,
    PolicyEngineInboundAdmissionPolicy,
    compute_inbound_hmac_signature,
    create_in_memory_inbound_repositories,
    inbound_http_path,
)
from phoenix_os.policy import (
    PolicyEffect,
    PolicyEngine,
    PolicyRule,
    PrincipalType,
    SecurityContext,
)
from phoenix_os.secrets import SecretRef, SecretsManager

_NOW = datetime(2026, 7, 25, 12, 0, tzinfo=UTC)
_SOURCE_ID = UUID("00000000-0000-4000-8000-000000000025")
_SECRET = "gateway-secret-never-expose"


class _Normalizer:
    def __init__(self) -> None:
        self.calls = 0
        self.schema = InboundEventSchema(
            event_type="release.completed",
            event_schema_version=1,
            internal_event_type="external.release.completed",
            required_fields=frozenset({"release", "status"}),
            max_raw_body_bytes=4_096,
            max_normalized_payload_bytes=2_048,
        )

    def normalize(
        self,
        payload: Mapping[str, object],
    ) -> Mapping[str, object]:
        self.calls += 1
        return {
            "release": payload["release"],
            "status": payload["status"],
        }


class _Policy:
    def __init__(self, *, reject: bool = False) -> None:
        self.reject = reject
        self.calls: list[
            tuple[
                InboundAuthenticationResult,
                InboundEventSource,
                InboundNormalizedEnvelope,
            ]
        ] = []

    async def enforce(
        self,
        authentication: InboundAuthenticationResult,
        source: InboundEventSource,
        envelope: InboundNormalizedEnvelope,
    ) -> object:
        self.calls.append((authentication, source, envelope))
        if self.reject:
            raise InboundPolicyDeniedError
        return object()


@dataclass
class _Fixture:
    source: InboundEventSource
    repositories: Any
    normalizer: _Normalizer
    policy: _Policy
    limiter: InboundAdmissionLimiter
    adapter: InboundHttpAdapter


def _admin_context(permission: str) -> SecurityContext:
    return SecurityContext(
        principal="maintainer:test",
        principal_type=PrincipalType.USER,
        authenticated=True,
        permissions=frozenset({permission}),
    )


def _lease_context() -> SecurityContext:
    return SecurityContext(
        principal="phoenix.inbound-events",
        principal_type=PrincipalType.SYSTEM,
        authenticated=True,
        permissions=frozenset({"secret.read", "secret.lease.revoke"}),
    )


def _body(release: str = "0.25.0") -> bytes:
    return json.dumps(
        {
            "schema_version": 1,
            "event_type": "release.completed",
            "event_schema_version": 1,
            "occurred_at": "2026-07-25T11:59:59Z",
            "payload": {"release": release, "status": "completed"},
        },
        separators=(",", ":"),
    ).encode()


async def _fixture(
    *,
    policy_reject: bool = False,
    event_capacity: int = 100,
    max_concurrency: int = 8,
) -> _Fixture:
    manager = SecretsManager(clock=lambda: _NOW)
    metadata = await manager.create(
        SecretRef("release-inbound", "integrations"),
        SecretValue(_SECRET),
        _admin_context("secret.create"),
    )
    source = InboundEventSource(
        id=_SOURCE_ID,
        name="release.events",
        display_name="Release Events",
        authentication=InboundHmacPolicy(metadata.ref),
        event_types=frozenset({"release.completed"}),
        created_at=_NOW,
        updated_at=_NOW,
        created_by="maintainer:test",
        max_concurrency=max_concurrency,
    )
    repositories = create_in_memory_inbound_repositories(event_capacity=event_capacity)
    await repositories.sources.add(source)
    normalizer = _Normalizer()
    schemas = InboundSchemaRegistry()
    schemas.register(normalizer)
    policy = _Policy(reject=policy_reject)
    limiter = InboundAdmissionLimiter(
        InboundAdmissionLimitPolicy(global_max_concurrency=16),
        clock=lambda: _NOW,
    )
    gateway = InboundEventGateway(
        sources=repositories.sources,
        authentication=InboundAuthenticationVerifier(
            secrets=manager,
            security_context=_lease_context(),
            clock=lambda: _NOW,
        ),
        schemas=schemas,
        admission=InboundReplayIdempotencyService(
            repositories.events,
            repositories.replay,
            clock=lambda: _NOW,
        ),
        policy=policy,
        limits=limiter,
    )
    adapter = InboundHttpAdapter((InboundHttpRoute(source, gateway),))
    return _Fixture(
        source=source,
        repositories=repositories,
        normalizer=normalizer,
        policy=policy,
        limiter=limiter,
        adapter=adapter,
    )


def _headers(
    fixture: _Fixture,
    body: bytes,
    *,
    request_id: str = "request-000000000001",
    source_event_id: str = "release-000000000001",
    nonce: str = "nonce-000000000001",
) -> dict[str, tuple[str, ...]]:
    signature = compute_inbound_hmac_signature(
        _SECRET,
        source_id=fixture.source.id,
        request_id=request_id,
        source_event_id=source_event_id,
        timestamp=_NOW,
        nonce=nonce,
        body=body,
    )
    authentication = fixture.source.authentication
    assert isinstance(authentication, InboundHmacPolicy)
    key_version = authentication.key_version
    headers: dict[str, tuple[str, ...]] = {
        "host": ("127.0.0.1",),
        "content-type": (INBOUND_CONTENT_TYPE,),
        INBOUND_REQUEST_ID_HEADER.lower(): (request_id,),
        INBOUND_SOURCE_EVENT_ID_HEADER.lower(): (source_event_id,),
        INBOUND_TIMESTAMP_HEADER.lower(): ("2026-07-25T12:00:00Z",),
        INBOUND_NONCE_HEADER.lower(): (nonce,),
        INBOUND_SIGNATURE_HEADER.lower(): (signature,),
        INBOUND_KEY_VERSION_HEADER.lower(): (str(key_version),),
        INBOUND_CORRELATION_ID_HEADER.lower(): ("inbound-correlation",),
    }
    return headers


async def _dispatch(
    fixture: _Fixture,
    body: bytes,
    *,
    request_id: str = "request-000000000001",
    source_event_id: str = "release-000000000001",
    nonce: str = "nonce-000000000001",
) -> InboundHttpResponse:
    return await fixture.adapter.dispatch(
        method="POST",
        path=inbound_http_path(fixture.source),
        query={},
        headers=_headers(
            fixture,
            body,
            request_id=request_id,
            source_event_id=source_event_id,
            nonce=nonce,
        ),
        body=body,
        transport_context=None,
    )


@pytest.mark.asyncio
async def test_gateway_authenticates_normalizes_authorizes_and_commits_before_202() -> None:
    fixture = await _fixture()
    body = _body()

    status, payload, headers = await _dispatch(fixture, body)

    assert status is HTTPStatus.ACCEPTED
    assert payload["status"] == "accepted"
    assert headers == {"Cache-Control": "no-store"}
    assert fixture.normalizer.calls == 1
    assert len(fixture.policy.calls) == 1

    snapshot = await fixture.repositories.events.snapshot()
    assert snapshot.events == 1
    event = (await fixture.repositories.events.list()).items[0]
    assert dict(event.normalized_payload) == {
        "release": "0.25.0",
        "status": "completed",
    }
    assert event.internal_event_type == "external.release.completed"

    rendered = json.dumps(payload, sort_keys=True)
    assert _SECRET not in rendered
    assert body.decode() not in rendered
    assert event.normalized_payload_sha256 not in rendered
    assert event.internal_event_type not in rendered


@pytest.mark.asyncio
async def test_gateway_idempotent_repeat_returns_same_stable_receipt() -> None:
    fixture = await _fixture()
    body = _body()

    first_status, first, _ = await _dispatch(fixture, body)
    second_status, second, _ = await _dispatch(
        fixture,
        body,
        request_id="request-000000000002",
        nonce="nonce-000000000002",
    )

    assert first_status is HTTPStatus.ACCEPTED
    assert second_status is HTTPStatus.ACCEPTED
    assert first["status"] == "accepted"
    assert second["status"] == "idempotent"
    assert second["receipt_id"] == first["receipt_id"]
    assert second["accepted_event_id"] == first["accepted_event_id"]
    assert (await fixture.repositories.events.snapshot()).events == 1


@pytest.mark.asyncio
async def test_authentication_failure_happens_before_schema_processing() -> None:
    fixture = await _fixture()
    body = _body()
    headers = _headers(fixture, body)
    headers[INBOUND_SIGNATURE_HEADER.lower()] = ("hmac-sha256-v1=" + "0" * 64,)

    status, payload, _ = await fixture.adapter.dispatch(
        method="POST",
        path=inbound_http_path(fixture.source),
        query={},
        headers=headers,
        body=body,
        transport_context=None,
    )

    assert status is HTTPStatus.UNAUTHORIZED
    assert payload == {"error": "unauthorized"}
    assert fixture.normalizer.calls == 0
    assert not fixture.policy.calls
    assert (await fixture.repositories.events.snapshot()).events == 0


@pytest.mark.asyncio
async def test_policy_denial_prevents_durable_acceptance() -> None:
    fixture = await _fixture(policy_reject=True)

    status, payload, _ = await _dispatch(fixture, _body())

    assert status is HTTPStatus.FORBIDDEN
    assert payload == {"error": "forbidden"}
    assert fixture.normalizer.calls == 1
    assert (await fixture.repositories.events.snapshot()).events == 0


@pytest.mark.asyncio
async def test_invalid_registered_schema_maps_to_422_after_authentication() -> None:
    fixture = await _fixture()
    body = json.dumps(
        {
            "schema_version": 1,
            "event_type": "release.completed",
            "event_schema_version": 1,
            "occurred_at": "2026-07-25T11:59:59Z",
            "payload": {"release": "0.25.0"},
        },
        separators=(",", ":"),
    ).encode()

    status, payload, _ = await _dispatch(fixture, body)

    assert status is HTTPStatus.UNPROCESSABLE_ENTITY
    assert payload == {"error": "invalid_event"}
    assert not fixture.policy.calls


@pytest.mark.asyncio
async def test_replay_and_digest_conflict_have_safe_distinct_mappings() -> None:
    fixture = await _fixture()
    await _dispatch(fixture, _body())

    replay_status, replay, _ = await _dispatch(
        fixture,
        _body(),
        nonce="nonce-000000000002",
    )
    conflict_status, conflict, _ = await _dispatch(
        fixture,
        _body("0.25.1"),
        request_id="request-000000000002",
        nonce="nonce-000000000003",
    )

    assert replay_status is HTTPStatus.UNAUTHORIZED
    assert replay == {"error": "unauthorized"}
    assert conflict_status is HTTPStatus.CONFLICT
    assert conflict == {"error": "conflict"}


@pytest.mark.asyncio
async def test_source_and_global_limits_map_to_429_without_waiting() -> None:
    fixture = await _fixture(max_concurrency=1)
    held = await fixture.limiter.acquire(fixture.source)

    status, payload, headers = await _dispatch(fixture, _body())

    assert status is HTTPStatus.TOO_MANY_REQUESTS
    assert payload == {"error": "rate_limited"}
    assert headers["Retry-After"] == "1"
    assert fixture.normalizer.calls == 0
    await held.close()


@pytest.mark.asyncio
async def test_source_disablement_after_route_registration_fails_closed() -> None:
    fixture = await _fixture()
    disabled_at = _NOW + timedelta(seconds=1)
    disabled = replace(
        fixture.source,
        status=InboundEventSourceStatus.DISABLED,
        updated_at=disabled_at,
        disabled_at=disabled_at,
        revision=2,
    )
    await fixture.repositories.sources.replace(
        disabled,
        expected_revision=1,
    )

    status, payload, _ = await _dispatch(fixture, _body())

    assert status is HTTPStatus.UNAUTHORIZED
    assert payload == {"error": "unauthorized"}
    assert fixture.normalizer.calls == 0


@pytest.mark.asyncio
async def test_capacity_failure_maps_to_safe_503() -> None:
    fixture = await _fixture(event_capacity=1)
    first_status, _, _ = await _dispatch(fixture, _body())
    second_status, payload, _ = await _dispatch(
        fixture,
        _body(),
        request_id="request-000000000002",
        source_event_id="release-000000000002",
        nonce="nonce-000000000002",
    )

    assert first_status is HTTPStatus.ACCEPTED
    assert second_status is HTTPStatus.SERVICE_UNAVAILABLE
    assert payload == {"error": "service_unavailable"}


@pytest.mark.asyncio
async def test_policy_engine_adapter_is_deny_by_default_and_explicitly_allowable() -> None:
    fixture = await _fixture()
    source_authentication = fixture.source.authentication
    assert isinstance(source_authentication, InboundHmacPolicy)
    authentication = InboundAuthenticationResult(
        source_id=fixture.source.id,
        mode=source_authentication.mode,
        principal=f"inbound-source:{fixture.source.id}",
        authenticated_at=_NOW,
        key_version=source_authentication.key_version,
    )
    envelope = InboundNormalizedEnvelope(
        event_type="release.completed",
        event_schema_version=1,
        internal_event_type="external.release.completed",
        occurred_at=_NOW,
        normalized_payload={"release": "0.25.0", "status": "completed"},
    )

    denied = PolicyEngineInboundAdmissionPolicy(PolicyEngine())
    with pytest.raises(InboundPolicyDeniedError):
        await denied.enforce(authentication, fixture.source, envelope)

    allowed = PolicyEngineInboundAdmissionPolicy(
        PolicyEngine(
            (
                PolicyRule(
                    rule_id="allow.release.inbound",
                    effect=PolicyEffect.ALLOW,
                    actions=frozenset({"inbound_event.submit"}),
                    resources=frozenset({"inbound-source:release.events"}),
                    principals=frozenset({f"inbound-source:{fixture.source.id}"}),
                    principal_types=frozenset({PrincipalType.SERVICE}),
                    authenticated=True,
                ),
            )
        )
    )
    decision = await allowed.enforce(authentication, fixture.source, envelope)
    assert decision.effect is PolicyEffect.ALLOW
