from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import MappingProxyType
from uuid import uuid4

import pytest

from phoenix_os import (
    AuthenticationCredential,
    AuthenticationRequest,
    AuthenticationSnapshot,
    Identity,
    PrincipalType,
    SecretValue,
    Session,
    SessionGrant,
    SessionPolicy,
    SessionRecord,
    SessionStatus,
)


def test_credential_is_normalized_frozen_and_redacted() -> None:
    credential = AuthenticationCredential(
        " Password ",
        SecretValue("super-secret"),
        {" Tenant ": " phoenix "},
    )
    assert credential.scheme == "password"
    assert credential.attributes == {"tenant": "phoenix"}
    assert isinstance(credential.attributes, MappingProxyType)
    assert "super-secret" not in repr(credential)
    assert str(credential.secret) == "***"


def test_credential_requires_secret_value_and_valid_scheme() -> None:
    with pytest.raises(TypeError, match="SecretValue"):
        AuthenticationCredential("password", "secret")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="credential scheme"):
        AuthenticationCredential("bad scheme", SecretValue("secret"))


def test_authentication_request_normalizes_and_freezes_metadata() -> None:
    request = AuthenticationRequest(
        " Local ",
        AuthenticationCredential("token", SecretValue("credential-secret")),
        {" Device ": " desktop "},
        correlation_id=" trace-1 ",
    )
    assert request.provider == "local"
    assert request.metadata == {"device": "desktop"}
    assert request.correlation_id == "trace-1"
    assert "credential-secret" not in repr(request)


def test_authentication_request_rejects_naive_time_and_blank_correlation() -> None:
    credential = AuthenticationCredential("token", SecretValue("x"))
    with pytest.raises(ValueError, match="timezone"):
        AuthenticationRequest("local", credential, created_at=datetime.now())
    with pytest.raises(ValueError, match="correlation"):
        AuthenticationRequest("local", credential, correlation_id=" ")


def test_identity_normalizes_authorization_data() -> None:
    identity = Identity(
        " Arthur ",
        PrincipalType.USER,
        " Local ",
        display_name=" João Arthur ",
        roles=frozenset({" Admin "}),
        permissions=frozenset({" Files.Read "}),
        scopes=frozenset({" Workspace "}),
        attributes={" Tenant ": " phoenix "},
    )
    assert identity.subject == "Arthur"
    assert identity.provider == "local"
    assert identity.display_name == "João Arthur"
    assert identity.roles == frozenset({"admin"})
    assert identity.permissions == frozenset({"files.read"})
    assert identity.scopes == frozenset({"workspace"})
    assert identity.attributes == {"tenant": "phoenix"}


def test_identity_rejects_anonymous_and_invalid_values() -> None:
    with pytest.raises(ValueError, match="anonymous"):
        Identity("guest", PrincipalType.ANONYMOUS)
    with pytest.raises(ValueError, match="subject"):
        Identity(" ")
    with pytest.raises(ValueError, match="display_name"):
        Identity("arthur", display_name=" ")
    with pytest.raises(ValueError, match="timezone"):
        Identity("arthur", authenticated_at=datetime.now())


def test_identity_builds_security_context() -> None:
    session_id = uuid4()
    identity = Identity(
        "arthur",
        roles=frozenset({"admin"}),
        permissions=frozenset({"state.read"}),
        scopes=frozenset({"profile"}),
        attributes={"tenant": "phoenix"},
    )
    context = identity.security_context(
        correlation_id="trace",
        confirmed=True,
        session_id=session_id,
    )
    assert context.principal == "arthur"
    assert context.authenticated
    assert context.roles == frozenset({"admin"})
    assert context.attributes["session_id"] == str(session_id)
    assert context.attributes["identity_provider"] == "local"
    assert context.confirmed


def test_session_policy_validates_limits() -> None:
    with pytest.raises(ValueError, match="absolute_ttl"):
        SessionPolicy(absolute_ttl=timedelta(0))
    with pytest.raises(ValueError, match="idle_ttl"):
        SessionPolicy(idle_ttl=timedelta(0))
    with pytest.raises(ValueError, match="max_sessions"):
        SessionPolicy(max_sessions_per_identity=0)
    with pytest.raises(ValueError, match="touch_interval"):
        SessionPolicy(touch_interval=timedelta(seconds=-1))


def make_session(*, status: SessionStatus = SessionStatus.ACTIVE) -> Session:
    now = datetime.now(UTC)
    revoked = now if status is SessionStatus.REVOKED else None
    return Session(
        id=uuid4(),
        identity=Identity("arthur"),
        issued_at=now,
        expires_at=now + timedelta(hours=1),
        last_seen_at=now,
        idle_expires_at=now + timedelta(minutes=10),
        idle_ttl=timedelta(minutes=10),
        status=status,
        revoked_at=revoked,
        revocation_reason="logout" if revoked else None,
        metadata={"device": "desktop"},
    )


def test_session_validity_and_security_context() -> None:
    session = make_session()
    assert session.valid_at(session.issued_at + timedelta(minutes=1))
    assert not session.valid_at(session.expires_at)
    assert session.security_context().attributes["session_id"] == str(session.id)


def test_session_rejects_inconsistent_lifecycle_fields() -> None:
    now = datetime.now(UTC)
    identity = Identity("arthur")
    with pytest.raises(ValueError, match="revoked_at"):
        Session(
            uuid4(),
            identity,
            now,
            now + timedelta(hours=1),
            now,
            status=SessionStatus.REVOKED,
        )
    with pytest.raises(ValueError, match="idle_ttl"):
        Session(
            uuid4(),
            identity,
            now,
            now + timedelta(hours=1),
            now,
            idle_expires_at=now + timedelta(minutes=1),
        )


def test_session_record_and_grant_hide_token_material() -> None:
    session = make_session()
    digest = "a" * 64
    record = SessionRecord(session, digest)
    grant = SessionGrant(session, SecretValue("bearer-token"))
    assert record.token_digest == digest
    assert digest not in repr(record)
    assert "bearer-token" not in repr(grant)
    with pytest.raises(ValueError, match="digest"):
        SessionRecord(session, "bad")


def test_authentication_snapshot_is_value_contract() -> None:
    snapshot = AuthenticationSnapshot(False, ("local",), 2, 1, 3, 1, 1)
    assert snapshot.providers == ("local",)
    assert snapshot.active_sessions == 1
