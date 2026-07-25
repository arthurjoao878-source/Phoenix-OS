from __future__ import annotations

import asyncio
import hashlib
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any, cast
from uuid import UUID

import pytest

from phoenix_os.configuration import SecretValue
from phoenix_os.control_plane.service_account_authentication import (
    ControlPlaneServiceAccountAuthentication,
    ControlPlaneServiceAccountAuthenticationContext,
)
from phoenix_os.control_plane.service_account_policy import (
    ControlPlaneServiceAccountApiContext,
)
from phoenix_os.control_plane.service_account_replay import (
    ControlPlaneServiceAccountReplayRequest,
)
from phoenix_os.inbound_events import (
    InboundAuthenticationMode,
    InboundAuthenticationRejectedError,
    InboundAuthenticationResult,
    InboundAuthenticationVerifier,
    InboundEventSource,
    InboundEventSourceStatus,
    InboundHmacPolicy,
    InboundRequestEvidence,
    InboundServiceAccountPolicy,
    canonical_inbound_signature_input,
    compute_inbound_hmac_signature,
    format_inbound_timestamp,
    parse_inbound_timestamp,
    verify_inbound_hmac_signature,
)
from phoenix_os.policy import PrincipalType, SecurityContext
from phoenix_os.secrets import SecretRef, SecretsManager

_NOW = datetime(2026, 7, 25, 12, 0, 1, 987654, tzinfo=UTC)
_SOURCE_ID = UUID("00000000-0000-4000-8000-000000000025")
_SERVICE_ACCOUNT_ID = UUID("00000000-0000-4000-8000-000000000125")
_TOKEN_ID = UUID("00000000-0000-4000-8000-000000000225")
_BODY = b'{"event_type":"release.created","payload":{"release":"0.25.0"}}'


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
        correlation_id="runtime-correlation",
    )


def _source(
    authentication: InboundHmacPolicy | InboundServiceAccountPolicy,
    *,
    status: InboundEventSourceStatus = InboundEventSourceStatus.ACTIVE,
    timestamp_skew: timedelta = timedelta(minutes=5),
    updated_at: datetime = _NOW,
    disabled_at: datetime | None = None,
) -> InboundEventSource:
    return InboundEventSource(
        id=_SOURCE_ID,
        name="release.events",
        display_name="Release Events",
        authentication=authentication,
        event_types=frozenset({"release.created"}),
        created_at=_NOW,
        updated_at=updated_at,
        created_by="maintainer:test",
        timestamp_skew=timestamp_skew,
        status=status,
        disabled_at=disabled_at,
    )


def _evidence(
    body: bytes = _BODY,
    *,
    timestamp: datetime = _NOW,
    source_id: UUID = _SOURCE_ID,
    request_id: str = "request-000000000001",
    source_event_id: str = "release-000000000001",
    nonce: str = "nonce-000000000001",
) -> InboundRequestEvidence:
    return InboundRequestEvidence(
        source_id=source_id,
        request_id=request_id,
        source_event_id=source_event_id,
        nonce=nonce,
        timestamp=timestamp,
        body_sha256=hashlib.sha256(body).hexdigest(),
        correlation_id="inbound-correlation",
    )


async def _hmac_services(
    secret: object = "current-secret",
) -> tuple[SecretsManager, SecretRef, InboundEventSource, InboundAuthenticationVerifier]:
    manager = SecretsManager(clock=lambda: _NOW)
    metadata = await manager.create(
        SecretRef("release-inbound", "integrations"),
        SecretValue(secret),
        _admin_context("secret.create"),
    )
    source = _source(
        InboundHmacPolicy(
            metadata.ref,
            lease_ttl=timedelta(seconds=10),
        )
    )
    verifier = InboundAuthenticationVerifier(
        secrets=manager,
        security_context=_lease_context(),
        clock=lambda: _NOW,
    )
    return manager, metadata.ref, source, verifier


def _signature(
    secret: object,
    evidence: InboundRequestEvidence,
    body: bytes = _BODY,
    *,
    source_id: UUID = _SOURCE_ID,
) -> str:
    return compute_inbound_hmac_signature(
        secret,
        source_id=source_id,
        request_id=evidence.request_id,
        source_event_id=evidence.source_event_id,
        timestamp=evidence.timestamp,
        nonce=evidence.nonce,
        body=body,
    )


def _service_authentication() -> ControlPlaneServiceAccountAuthentication:
    return ControlPlaneServiceAccountAuthentication(
        service_account_id=_SERVICE_ACCOUNT_ID,
        token_id=_TOKEN_ID,
        account_name="release-bot",
        scopes=frozenset({"inbound_event.submit"}),
        resources=frozenset({"inbound-source:release.events"}),
        token_version=3,
        account_revision=4,
        token_revision=5,
        authenticated_at=_NOW - timedelta(seconds=1),
        expires_at=_NOW + timedelta(hours=1),
    )


class _FakeServiceAuthenticator:
    def __init__(
        self,
        result: ControlPlaneServiceAccountAuthentication | None,
        *,
        cancel: bool = False,
    ) -> None:
        self.result = result
        self.cancel = cancel
        self.calls: list[
            tuple[str | None, ControlPlaneServiceAccountAuthenticationContext | None]
        ] = []

    async def authenticate(
        self,
        authorization: str | None,
        *,
        context: ControlPlaneServiceAccountAuthenticationContext | None = None,
    ) -> ControlPlaneServiceAccountAuthentication | None:
        self.calls.append((authorization, context))
        if self.cancel:
            raise asyncio.CancelledError
        return self.result


class _FakeServiceReplay:
    def __init__(self) -> None:
        self.calls: list[
            tuple[ControlPlaneServiceAccountAuthentication, ControlPlaneServiceAccountReplayRequest]
        ] = []

    async def admit(
        self,
        authentication: ControlPlaneServiceAccountAuthentication,
        request: ControlPlaneServiceAccountReplayRequest,
    ) -> None:
        self.calls.append((authentication, request))


class _FakeServicePolicy:
    def __init__(self, *, reject: bool = False) -> None:
        self.reject = reject
        self.calls: list[tuple[ControlPlaneServiceAccountApiContext, str, str]] = []

    async def enforce(
        self,
        context: ControlPlaneServiceAccountApiContext,
        *,
        action: str,
        resource: str,
    ) -> object:
        self.calls.append((context, action, resource))
        if self.reject:
            raise PermissionError("denied")
        return object()


def test_canonical_signature_input_is_exact() -> None:
    evidence = _evidence()
    canonical = canonical_inbound_signature_input(
        source_id=_SOURCE_ID,
        request_id=evidence.request_id,
        source_event_id=evidence.source_event_id,
        timestamp=evidence.timestamp,
        nonce=evidence.nonce,
        body=_BODY,
    )

    assert canonical == b"\n".join(
        (
            b"phoenix-inbound-signature-v1",
            str(_SOURCE_ID).encode("ascii"),
            b"request-000000000001",
            b"release-000000000001",
            b"2026-07-25T12:00:01Z",
            b"nonce-000000000001",
            hashlib.sha256(_BODY).hexdigest().encode("ascii"),
        )
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("request_id", "request-000000000002"),
        ("source_event_id", "release-000000000002"),
        ("nonce", "nonce-000000000002"),
        ("timestamp", _NOW + timedelta(seconds=1)),
        ("body", _BODY + b" "),
    ],
)
def test_signature_binds_every_request_fact(field: str, value: object) -> None:
    evidence = _evidence()
    signature = _signature("current-secret", evidence)
    arguments: dict[str, object] = {
        "signature": signature,
        "source_id": _SOURCE_ID,
        "request_id": evidence.request_id,
        "source_event_id": evidence.source_event_id,
        "timestamp": evidence.timestamp,
        "nonce": evidence.nonce,
        "body": _BODY,
    }
    arguments[field] = value

    assert not verify_inbound_hmac_signature(
        "current-secret",
        **cast(Any, arguments),
    )


def test_timestamp_wire_format_is_exact() -> None:
    assert format_inbound_timestamp(_NOW) == "2026-07-25T12:00:01Z"
    assert parse_inbound_timestamp("2026-07-25T12:00:01Z") == _NOW.replace(microsecond=0)

    for invalid in (
        "2026-07-25T12:00:01.000Z",
        "2026-07-25 12:00:01Z",
        "2026-07-25T12:00:01+00:00",
    ):
        with pytest.raises(ValueError, match="invalid inbound timestamp"):
            parse_inbound_timestamp(invalid)


@pytest.mark.asyncio
async def test_hmac_verifier_resolves_exact_secret_and_revokes_lease() -> None:
    manager, ref, source, verifier = await _hmac_services()
    evidence = _evidence()
    result = await verifier.verify(
        source,
        evidence,
        _BODY,
        signature=_signature("current-secret", evidence),
        key_version=str(ref.version),
    )

    assert result == InboundAuthenticationResult(
        source_id=_SOURCE_ID,
        mode=InboundAuthenticationMode.HMAC_SHA256,
        principal=f"inbound-source:{_SOURCE_ID}",
        authenticated_at=_NOW,
        key_version=1,
    )
    snapshot = await manager.snapshot()
    assert snapshot.leases == 1
    assert snapshot.active_leases == 0
    assert snapshot.revoked_leases == 1


@pytest.mark.asyncio
async def test_hmac_verifier_accepts_bounded_predecessor_overlap() -> None:
    manager, first_ref, _, _ = await _hmac_services("first-secret")
    second = await manager.rotate(
        SecretRef("release-inbound", "integrations"),
        SecretValue("second-secret"),
        _admin_context("secret.rotate"),
    )
    source = _source(
        InboundHmacPolicy(
            second.ref,
            predecessor_secret_ref=first_ref,
            predecessor_valid_until=_NOW + timedelta(minutes=1),
        )
    )
    verifier = InboundAuthenticationVerifier(
        secrets=manager,
        security_context=_lease_context(),
        clock=lambda: _NOW,
    )
    evidence = _evidence()

    predecessor = await verifier.verify(
        source,
        evidence,
        _BODY,
        signature=_signature("first-secret", evidence),
        key_version="1",
    )
    current = await verifier.verify(
        source,
        evidence,
        _BODY,
        signature=_signature("second-secret", evidence),
        key_version="2",
    )

    assert predecessor.key_version == 1
    assert current.key_version == 2


@pytest.mark.asyncio
async def test_expired_hmac_predecessor_fails_generically() -> None:
    manager, first_ref, _, _ = await _hmac_services("first-secret")
    second = await manager.rotate(
        SecretRef("release-inbound", "integrations"),
        SecretValue("second-secret"),
        _admin_context("secret.rotate"),
    )
    verification_time = _NOW + timedelta(minutes=2)
    source = _source(
        InboundHmacPolicy(
            second.ref,
            predecessor_secret_ref=first_ref,
            predecessor_valid_until=_NOW + timedelta(minutes=1),
        ),
        timestamp_skew=timedelta(minutes=5),
    )
    verifier = InboundAuthenticationVerifier(
        secrets=manager,
        security_context=_lease_context(),
        clock=lambda: verification_time,
    )
    evidence = _evidence(timestamp=verification_time)

    with pytest.raises(
        InboundAuthenticationRejectedError,
        match="inbound request authentication failed",
    ):
        await verifier.verify(
            source,
            evidence,
            _BODY,
            signature=_signature("first-secret", evidence),
            key_version="1",
        )


@pytest.mark.asyncio
async def test_hmac_failures_share_one_generic_external_error() -> None:
    _, ref, source, verifier = await _hmac_services()
    evidence = _evidence()
    valid_signature = _signature("current-secret", evidence)
    disabled_at = _NOW + timedelta(seconds=1)
    disabled = replace(
        source,
        status=InboundEventSourceStatus.DISABLED,
        updated_at=disabled_at,
        disabled_at=disabled_at,
        revision=2,
    )
    stale = _evidence(timestamp=_NOW - timedelta(minutes=6))
    wrong_digest = replace(evidence, body_sha256="0" * 64)

    scenarios = (
        (source, evidence, _BODY, "hmac-sha256-v1=" + "0" * 64, str(ref.version)),
        (source, evidence, _BODY, valid_signature, "9"),
        (source, wrong_digest, _BODY, valid_signature, str(ref.version)),
        (source, stale, _BODY, _signature("current-secret", stale), str(ref.version)),
        (disabled, evidence, _BODY, valid_signature, str(ref.version)),
    )

    messages: set[str] = set()
    for candidate, request, body, signature, version in scenarios:
        with pytest.raises(InboundAuthenticationRejectedError) as raised:
            await verifier.verify(
                candidate,
                request,
                body,
                signature=signature,
                key_version=version,
            )
        messages.add(str(raised.value))

    assert messages == {"inbound request authentication failed"}


@pytest.mark.asyncio
async def test_unknown_source_and_mode_confusion_fail_generically() -> None:
    _, ref, source, verifier = await _hmac_services()
    evidence = _evidence()
    signature = _signature("current-secret", evidence)

    for candidate, authorization in (
        (None, None),
        (source, "Bearer phx_invalid"),
    ):
        with pytest.raises(
            InboundAuthenticationRejectedError,
            match="inbound request authentication failed",
        ):
            await verifier.verify(
                candidate,
                evidence,
                _BODY,
                signature=signature,
                key_version=str(ref.version),
                authorization=authorization,
            )


@pytest.mark.asyncio
async def test_service_account_mode_reuses_rfc0023_boundaries() -> None:
    authentication = _service_authentication()
    authenticator = _FakeServiceAuthenticator(authentication)
    replay = _FakeServiceReplay()
    policy = _FakeServicePolicy()
    verifier = InboundAuthenticationVerifier(
        service_account_authenticator=authenticator,
        service_account_replay=replay,
        service_account_policy=policy,
        clock=lambda: _NOW,
    )
    source = _source(InboundServiceAccountPolicy("inbound-source:release.events"))
    evidence = _evidence()

    result = await verifier.verify(
        source,
        evidence,
        _BODY,
        authorization="Bearer phx_example",
        request_target="/v1/control-plane/inbound/release.events",
    )

    assert result.mode is InboundAuthenticationMode.SERVICE_ACCOUNT
    assert result.principal == "service-account:release-bot"
    assert result.service_account_id == _SERVICE_ACCOUNT_ID
    assert result.token_id == _TOKEN_ID
    assert result.key_version is None
    assert authenticator.calls == [("Bearer phx_example", None)]
    assert len(replay.calls) == 1
    assert replay.calls[0][0] == authentication
    assert replay.calls[0][1].nonce.value == "nonce-000000000001"
    assert replay.calls[0][1].body_digest == hashlib.sha256(_BODY).hexdigest()
    assert len(policy.calls) == 1
    assert policy.calls[0][1:] == (
        "inbound_event.submit",
        "inbound-source:release.events",
    )
    assert policy.calls[0][0].security_context.roles == frozenset()
    assert policy.calls[0][0].security_context.permissions == frozenset()


@pytest.mark.asyncio
async def test_service_account_denials_are_generic() -> None:
    source = _source(InboundServiceAccountPolicy("inbound-source:release.events"))
    evidence = _evidence()
    replay = _FakeServiceReplay()

    verifiers = (
        InboundAuthenticationVerifier(
            service_account_authenticator=_FakeServiceAuthenticator(None),
            service_account_replay=replay,
            service_account_policy=_FakeServicePolicy(),
            clock=lambda: _NOW,
        ),
        InboundAuthenticationVerifier(
            service_account_authenticator=_FakeServiceAuthenticator(_service_authentication()),
            service_account_replay=replay,
            service_account_policy=_FakeServicePolicy(reject=True),
            clock=lambda: _NOW,
        ),
        InboundAuthenticationVerifier(clock=lambda: _NOW),
    )

    messages: set[str] = set()
    for verifier in verifiers:
        with pytest.raises(InboundAuthenticationRejectedError) as raised:
            await verifier.verify(
                source,
                evidence,
                _BODY,
                authorization="Bearer phx_example",
                request_target="/v1/control-plane/inbound/release.events",
            )
        messages.add(str(raised.value))

    assert messages == {"inbound request authentication failed"}


@pytest.mark.asyncio
async def test_service_account_mode_rejects_hmac_headers() -> None:
    verifier = InboundAuthenticationVerifier(
        service_account_authenticator=_FakeServiceAuthenticator(_service_authentication()),
        service_account_replay=_FakeServiceReplay(),
        service_account_policy=_FakeServicePolicy(),
        clock=lambda: _NOW,
    )
    source = _source(InboundServiceAccountPolicy("inbound-source:release.events"))

    with pytest.raises(InboundAuthenticationRejectedError):
        await verifier.verify(
            source,
            _evidence(),
            _BODY,
            signature="hmac-sha256-v1=" + "0" * 64,
            key_version="1",
            authorization="Bearer phx_example",
            request_target="/v1/control-plane/inbound/release.events",
        )


@pytest.mark.asyncio
async def test_service_account_cancellation_propagates() -> None:
    verifier = InboundAuthenticationVerifier(
        service_account_authenticator=_FakeServiceAuthenticator(None, cancel=True),
        service_account_replay=_FakeServiceReplay(),
        service_account_policy=_FakeServicePolicy(),
        clock=lambda: _NOW,
    )
    source = _source(InboundServiceAccountPolicy("inbound-source:release.events"))

    with pytest.raises(asyncio.CancelledError):
        await verifier.verify(
            source,
            _evidence(),
            _BODY,
            authorization="Bearer phx_example",
            request_target="/v1/control-plane/inbound/release.events",
        )


def test_authentication_result_rejects_cross_mode_identity() -> None:
    with pytest.raises(ValueError, match="principal"):
        InboundAuthenticationResult(
            source_id=_SOURCE_ID,
            mode=InboundAuthenticationMode.HMAC_SHA256,
            principal="service-account:release-bot",
            authenticated_at=_NOW,
            key_version=1,
        )

    with pytest.raises(ValueError, match="stable ids"):
        InboundAuthenticationResult(
            source_id=_SOURCE_ID,
            mode=InboundAuthenticationMode.SERVICE_ACCOUNT,
            principal="service-account:release-bot",
            authenticated_at=_NOW,
        )


@pytest.mark.asyncio
async def test_authentication_errors_and_results_do_not_expose_secrets() -> None:
    _, ref, source, verifier = await _hmac_services("never-leak-this")
    evidence = _evidence()
    signature = _signature("never-leak-this", evidence)

    result = await verifier.verify(
        source,
        evidence,
        _BODY,
        signature=signature,
        key_version=str(ref.version),
    )
    assert "never-leak-this" not in repr(result)
    assert signature not in repr(result)

    with pytest.raises(InboundAuthenticationRejectedError) as raised:
        await verifier.verify(
            source,
            evidence,
            _BODY,
            signature="hmac-sha256-v1=" + "0" * 64,
            key_version=str(ref.version),
        )
    assert "never-leak-this" not in str(raised.value)
    assert signature not in str(raised.value)
