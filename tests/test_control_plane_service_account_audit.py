from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import cast
from uuid import UUID

import pytest

from phoenix_os.control_plane import (
    ControlPlaneClientIdentity,
    ControlPlaneNetworkRequestContext,
    ControlPlaneServiceAccountAudit,
    ControlPlaneServiceAccountAuditEvent,
    ControlPlaneServiceAccountAuditProtector,
    ControlPlaneServiceAccountAuthorization,
    ControlPlaneServiceAccountReplayRejectionReason,
    ControlPlaneServiceAccountThrottleBlockReason,
    ControlPlaneTlsPolicy,
    control_plane_service_account_api_context,
    control_plane_service_account_authentication_context,
)
from phoenix_os.control_plane.service_account_authentication import (
    ControlPlaneServiceAccountAuthentication,
    ControlPlaneServiceAccountAuthenticationContext,
)
from phoenix_os.control_plane.service_account_contracts import (
    ControlPlaneApiTokenMetadata,
    ControlPlaneApiTokenRotation,
    ControlPlaneApiTokenStatus,
    ControlPlaneServiceAccountRecord,
    ControlPlaneServiceAccountStatus,
)
from phoenix_os.events import EventBus

_NOW = datetime(
    2026,
    7,
    20,
    12,
    tzinfo=UTC,
)
_ACCOUNT_ID = UUID("10000000-0000-0000-0000-000000000001")
_TOKEN_ID = UUID("20000000-0000-0000-0000-000000000001")
_SUCCESSOR_ID = UUID("20000000-0000-0000-0000-000000000002")
_REQUEST_ID = UUID("30000000-0000-0000-0000-000000000001")
_RESOURCE = "job:40000000-0000-0000-0000-000000000001"


class _Writer:
    def get_extra_info(
        self,
        name: str,
        default: object = None,
    ) -> object:
        if name == "peername":
            return (
                "8.8.8.8",
                443,
            )

        return default


class _Events:
    def __init__(
        self,
        *,
        fail: bool = False,
    ) -> None:
        self.fail = fail
        self.records: list[dict[str, object]] = []

    async def emit(
        self,
        name: str,
        *,
        source: str,
        payload: Mapping[str, object],
        correlation_id: str | None = None,
        causation_id: object = None,
    ) -> object:
        if self.fail:
            raise RuntimeError("closed")

        self.records.append(
            {
                "name": name,
                "source": source,
                "payload": dict(payload),
                "correlation_id": correlation_id,
                "causation_id": causation_id,
            }
        )

        return object()


def _transport() -> ControlPlaneServiceAccountAuthenticationContext:
    network = ControlPlaneNetworkRequestContext(
        identity=ControlPlaneClientIdentity(
            address="8.8.8.8",
            peer_address="8.8.8.8",
        ),
        host="api.example.test",
        origin=None,
    )

    return control_plane_service_account_authentication_context(
        network,
        _Writer(),
        tls_policy=ControlPlaneTlsPolicy(),
    )


def _authentication() -> ControlPlaneServiceAccountAuthentication:
    return ControlPlaneServiceAccountAuthentication(
        service_account_id=_ACCOUNT_ID,
        token_id=_TOKEN_ID,
        account_name="release.bot",
        scopes=frozenset(
            {
                "job.cancel",
            }
        ),
        resources=frozenset(
            {
                _RESOURCE,
            }
        ),
        token_version=1,
        account_revision=2,
        token_revision=3,
        authenticated_at=_NOW,
        expires_at=_NOW + timedelta(hours=1),
        restriction_applied=True,
    )


def _events_and_audit(
    *,
    fail: bool = False,
) -> tuple[_Events, ControlPlaneServiceAccountAudit]:
    events = _Events(fail=fail)

    audit = ControlPlaneServiceAccountAudit(
        cast(EventBus, events),
        ControlPlaneServiceAccountAuditProtector(b"A" * 32),
    )

    return events, audit


def _active_token(
    token_id: UUID = _TOKEN_ID,
    *,
    version: int = 1,
    rotated_from: UUID | None = None,
) -> ControlPlaneApiTokenMetadata:
    return ControlPlaneApiTokenMetadata(
        id=token_id,
        service_account_id=_ACCOUNT_ID,
        label="automation",
        token_digest=("a" * 64 if token_id == _TOKEN_ID else "b" * 64),
        scopes=frozenset(
            {
                "job.cancel",
            }
        ),
        resources=frozenset(
            {
                _RESOURCE,
            }
        ),
        issued_at=_NOW,
        expires_at=_NOW + timedelta(hours=2),
        updated_at=_NOW,
        rotated_from=rotated_from,
        token_version=version,
    )


def _revoked_predecessor() -> ControlPlaneApiTokenMetadata:
    return ControlPlaneApiTokenMetadata(
        id=_TOKEN_ID,
        service_account_id=_ACCOUNT_ID,
        label="automation",
        token_digest="a" * 64,
        scopes=frozenset(
            {
                "job.cancel",
            }
        ),
        resources=frozenset(
            {
                _RESOURCE,
            }
        ),
        issued_at=_NOW - timedelta(hours=1),
        expires_at=_NOW + timedelta(hours=1),
        updated_at=_NOW,
        status=ControlPlaneApiTokenStatus.REVOKED,
        revoked_at=_NOW,
        token_version=1,
        revision=2,
    )


def test_protector_is_deterministic_and_domain_separated() -> None:
    protector = ControlPlaneServiceAccountAuditProtector(b"A" * 32)

    account = protector.account(_ACCOUNT_ID)
    token = protector.token(_ACCOUNT_ID)

    assert account == protector.account(_ACCOUNT_ID)
    assert account != token
    assert len(account) == 64
    assert str(_ACCOUNT_ID) not in account
    assert "A" * 32 not in repr(protector)


@pytest.mark.asyncio
async def test_authentication_success_uses_only_protected_facts() -> None:
    events, audit = _events_and_audit()

    await audit.authentication_succeeded(
        _authentication(),
        _transport(),
    )

    record = events.records[0]
    payload = cast(
        dict[str, object],
        record["payload"],
    )
    rendered = repr(record)

    assert record["name"] == (ControlPlaneServiceAccountAuditEvent.AUTHENTICATION_SUCCEEDED.value)
    assert record["source"] == ("phoenix.control-plane.service-account")
    assert payload["outcome"] == "succeeded"
    assert payload["mutual_tls"] is False
    assert payload["restriction_applied"] is True
    assert len(cast(str, payload["client_fingerprint"])) == 64

    assert str(_ACCOUNT_ID) not in rendered
    assert str(_TOKEN_ID) not in rendered
    assert "8.8.8.8" not in rendered
    assert "release.bot" not in rendered
    assert "phx_sa_" not in rendered
    assert "digest" not in rendered.lower()


@pytest.mark.asyncio
async def test_authentication_rejection_has_no_identity_guess() -> None:
    events, audit = _events_and_audit()

    await audit.authentication_rejected(_transport())

    payload = cast(
        dict[str, object],
        events.records[0]["payload"],
    )

    assert payload["outcome"] == "denied"
    assert "account_fingerprint" not in payload
    assert "token_fingerprint" not in payload
    assert "client_fingerprint" in payload


@pytest.mark.asyncio
async def test_authorization_protects_resource_and_tracing() -> None:
    events, audit = _events_and_audit()
    authentication = _authentication()
    context = control_plane_service_account_api_context(
        authentication,
        request_id=_REQUEST_ID,
        correlation_id="request-123",
    )

    await audit.authorization_decided(
        context,
        ControlPlaneServiceAccountAuthorization(
            action="job.cancel",
            resource=_RESOURCE,
            allowed=False,
        ),
    )

    record = events.records[0]
    payload = cast(
        dict[str, object],
        record["payload"],
    )

    assert record["name"] == (ControlPlaneServiceAccountAuditEvent.AUTHORIZATION_DENIED.value)
    assert record["correlation_id"] == "request-123"
    assert record["causation_id"] == _REQUEST_ID
    assert payload["action"] == "job.cancel"
    assert payload["outcome"] == "denied"
    assert _RESOURCE not in repr(record)
    assert (
        len(
            cast(
                str,
                payload["resource_fingerprint"],
            )
        )
        == 64
    )


@pytest.mark.asyncio
async def test_throttle_and_replay_reasons_are_allowlisted() -> None:
    events, audit = _events_and_audit()
    authentication = _authentication()

    await audit.throttle_blocked(
        ControlPlaneServiceAccountThrottleBlockReason.CLIENT,
        transport=_transport(),
    )

    await audit.replay_rejected(
        authentication,
        ControlPlaneServiceAccountReplayRejectionReason.REPLAY,
    )

    throttle_payload = cast(
        dict[str, object],
        events.records[0]["payload"],
    )
    replay_payload = cast(
        dict[str, object],
        events.records[1]["payload"],
    )

    assert throttle_payload["result"] == "client"
    assert replay_payload["result"] == "replay"
    assert "nonce" not in repr(events.records)
    assert "Bearer" not in repr(events.records)


@pytest.mark.asyncio
async def test_token_lifecycle_contains_only_protected_ids() -> None:
    events, audit = _events_and_audit()
    issued = _active_token()
    predecessor = _revoked_predecessor()
    successor = _active_token(
        _SUCCESSOR_ID,
        version=2,
        rotated_from=_TOKEN_ID,
    )

    await audit.token_issued(issued)
    await audit.token_rotated(
        ControlPlaneApiTokenRotation(
            predecessor=predecessor,
            successor=successor,
        )
    )
    await audit.token_revoked(predecessor)

    rendered = repr(events.records)

    assert str(_ACCOUNT_ID) not in rendered
    assert str(_TOKEN_ID) not in rendered
    assert str(_SUCCESSOR_ID) not in rendered
    assert "a" * 64 not in rendered
    assert "b" * 64 not in rendered

    rotation_payload = cast(
        dict[str, object],
        events.records[1]["payload"],
    )

    assert rotation_payload["result"] == "immediate"
    assert rotation_payload["successor_token_version"] == 2


@pytest.mark.asyncio
async def test_account_state_events_omit_names_and_ids() -> None:
    events, audit = _events_and_audit()

    disabled = ControlPlaneServiceAccountRecord(
        id=_ACCOUNT_ID,
        name="release.bot",
        display_name="Release Bot",
        created_at=_NOW - timedelta(days=1),
        updated_at=_NOW,
        status=ControlPlaneServiceAccountStatus.DISABLED,
        disabled_at=_NOW,
        revision=2,
    )

    await audit.account_disabled(disabled)

    rendered = repr(events.records)
    payload = cast(
        dict[str, object],
        events.records[0]["payload"],
    )

    assert payload["account_status"] == "disabled"
    assert payload["account_revision"] == 2
    assert str(_ACCOUNT_ID) not in rendered
    assert "release.bot" not in rendered
    assert "Release Bot" not in rendered


@pytest.mark.asyncio
async def test_event_failure_is_counted_without_escaping() -> None:
    _, audit = _events_and_audit(fail=True)

    await audit.authentication_rejected(_transport())

    snapshot = await audit.snapshot()

    assert snapshot.emitted == 0
    assert snapshot.dropped == 1
    assert snapshot.last_event is (ControlPlaneServiceAccountAuditEvent.AUTHENTICATION_REJECTED)


@pytest.mark.asyncio
async def test_snapshot_contains_only_delivery_counters() -> None:
    events, audit = _events_and_audit()

    await audit.authentication_succeeded(
        _authentication(),
        _transport(),
    )

    snapshot = await audit.snapshot()
    rendered = repr(snapshot)

    assert snapshot.emitted == 1
    assert snapshot.dropped == 0
    assert len(events.records) == 1
    assert str(_ACCOUNT_ID) not in rendered
    assert str(_TOKEN_ID) not in rendered
    assert "8.8.8.8" not in rendered


def test_audit_exports_are_public() -> None:
    import phoenix_os.control_plane as control_plane

    assert control_plane.ControlPlaneServiceAccountAudit is ControlPlaneServiceAccountAudit
    assert (
        control_plane.ControlPlaneServiceAccountAuditProtector
        is ControlPlaneServiceAccountAuditProtector
    )
    assert (
        control_plane.ControlPlaneServiceAccountAuditEvent is ControlPlaneServiceAccountAuditEvent
    )
