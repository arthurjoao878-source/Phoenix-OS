from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from phoenix_os.control_plane.durable_session_access import (
    ControlPlaneDurableSessionAccessService,
    ControlPlaneDurableSessionAuthentication,
)
from phoenix_os.control_plane.durable_session_contracts import (
    ControlPlaneDurableSessionPolicy,
    ControlPlaneDurableSessionStatus,
    ControlPlaneDurableSessionTerminationReason,
)
from phoenix_os.control_plane.durable_session_memory import (
    InMemoryControlPlaneDurableSessionRepository,
)
from phoenix_os.control_plane.errors import ControlPlaneStepUpRejectedError
from phoenix_os.control_plane.operator_authentication import ControlPlaneOperatorAuthenticator
from phoenix_os.control_plane.operator_contracts import (
    ControlPlaneOperatorRecord,
    ControlPlaneOperatorRole,
    ControlPlaneOperatorStatus,
    ControlPlaneOperatorToken,
)
from phoenix_os.control_plane.operator_memory import InMemoryControlPlaneOperatorRegistry
from phoenix_os.control_plane.step_up import (
    MAX_CONTROL_PLANE_STEP_UP_WINDOW,
    ControlPlaneOperatorStepUpService,
    ControlPlaneStepUpAction,
    ControlPlaneStepUpPolicy,
    ControlPlaneStepUpToken,
)

NOW = datetime(2026, 7, 19, 20, 0, tzinfo=UTC)
OPERATOR_ID = UUID(int=900)
SECOND_OPERATOR_ID = UUID(int=901)
TOKEN = ControlPlaneOperatorToken("step-up-operator-token-0123456789abcdef")
SECOND_TOKEN = ControlPlaneOperatorToken("step-up-second-token-0123456789abcdef")
SESSION_POLICY = ControlPlaneDurableSessionPolicy(
    absolute_ttl=timedelta(hours=2),
    idle_ttl=timedelta(minutes=30),
    rotation_interval=timedelta(minutes=20),
)


class _Clock:
    def __init__(self) -> None:
        self.now = NOW

    def __call__(self) -> datetime:
        return self.now


class _Secrets:
    def __init__(self, prefix: str) -> None:
        self.prefix = prefix
        self.counter = 0

    def __call__(self) -> str:
        self.counter += 1
        return f"{self.prefix}-{self.counter:048d}"


async def _service() -> tuple[
    ControlPlaneOperatorStepUpService,
    ControlPlaneDurableSessionAccessService,
    InMemoryControlPlaneDurableSessionRepository,
    InMemoryControlPlaneOperatorRegistry,
    _Clock,
]:
    clock = _Clock()
    registry = InMemoryControlPlaneOperatorRegistry()
    await registry.add(
        ControlPlaneOperatorRecord(
            id=OPERATOR_ID,
            username="alice",
            display_name="Alice",
            role=ControlPlaneOperatorRole.MAINTAINER,
            token_digest=TOKEN.digest,
            created_at=NOW,
            updated_at=NOW,
        )
    )
    await registry.add(
        ControlPlaneOperatorRecord(
            id=SECOND_OPERATOR_ID,
            username="bob",
            display_name="Bob",
            role=ControlPlaneOperatorRole.MAINTAINER,
            token_digest=SECOND_TOKEN.digest,
            created_at=NOW,
            updated_at=NOW,
        )
    )
    repository = InMemoryControlPlaneDurableSessionRepository()
    authenticator = ControlPlaneOperatorAuthenticator(registry, clock=clock)
    access = ControlPlaneDurableSessionAccessService(
        registry=registry,
        repository=repository,
        policy=SESSION_POLICY,
        clock=clock,
        token_factory=_Secrets("session"),
        csrf_factory=_Secrets("csrf"),
    )
    step_up = ControlPlaneOperatorStepUpService(
        authenticator=authenticator,
        registry=registry,
        repository=repository,
        secret=b"s" * 32,
        policy=ControlPlaneStepUpPolicy(window=timedelta(minutes=5)),
        clock=clock,
        nonce_source=lambda size: b"n" * size,
    )
    return step_up, access, repository, registry, clock


async def _session(
    access: ControlPlaneDurableSessionAccessService,
    registry: InMemoryControlPlaneOperatorRegistry,
) -> ControlPlaneDurableSessionAuthentication:
    operator = await registry.get(OPERATOR_ID)
    assert operator is not None
    authenticator = ControlPlaneOperatorAuthenticator(registry, clock=lambda: NOW)
    evidence = await authenticator.authenticate(f"Bearer {TOKEN.value}")
    assert evidence is not None
    grant = await access.issue(evidence)
    authentication = await access.authenticate(grant.token.value)
    assert authentication is not None
    return authentication


@pytest.mark.parametrize(
    "window",
    [timedelta(0), timedelta(seconds=-1), MAX_CONTROL_PLANE_STEP_UP_WINDOW + timedelta(seconds=1)],
)
def test_step_up_policy_rejects_unbounded_windows(window: timedelta) -> None:
    with pytest.raises(ValueError):
        ControlPlaneStepUpPolicy(window=window)


def test_step_up_token_is_redacted() -> None:
    token = ControlPlaneStepUpToken("x" * 32)
    assert str(token) == "<redacted>"
    assert token.value not in repr(token)


@pytest.mark.asyncio
async def test_confirm_reauthenticates_same_operator_and_binds_high_risk_action() -> None:
    step_up, access, _, registry, _ = await _service()
    session = await _session(access, registry)

    grant = await step_up.confirm(
        session,
        f"Bearer {TOKEN.value}",
        ControlPlaneStepUpAction.ROTATE_CREDENTIAL,
    )

    assert grant.evidence.session_id == session.session_id
    assert grant.evidence.operator_id == OPERATOR_ID
    assert grant.evidence.action is ControlPlaneStepUpAction.ROTATE_CREDENTIAL
    assert grant.evidence.expires_at - grant.evidence.authenticated_at == timedelta(minutes=5)
    assert TOKEN.value not in repr(grant)
    assert grant.token.value not in repr(grant)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "authorization",
    [None, "", "Basic token", "Bearer unknown-credential-0123456789abcdef"],
)
async def test_confirm_rejects_invalid_credentials_generically(authorization: str | None) -> None:
    step_up, access, _, registry, _ = await _service()
    session = await _session(access, registry)

    with pytest.raises(ControlPlaneStepUpRejectedError) as captured:
        await step_up.confirm(
            session,
            authorization,
            ControlPlaneStepUpAction.REVOKE_OPERATOR,
        )

    assert str(captured.value) == "step-up authentication rejected"


@pytest.mark.asyncio
async def test_confirm_rejects_another_maintainer_credential() -> None:
    step_up, access, _, registry, _ = await _service()
    session = await _session(access, registry)

    with pytest.raises(ControlPlaneStepUpRejectedError):
        await step_up.confirm(
            session,
            f"Bearer {SECOND_TOKEN.value}",
            ControlPlaneStepUpAction.REVOKE_OPERATOR,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("action", list(ControlPlaneStepUpAction))
async def test_signed_proof_verifies_for_each_reviewed_action(
    action: ControlPlaneStepUpAction,
) -> None:
    step_up, access, _, registry, _ = await _service()
    session = await _session(access, registry)
    grant = await step_up.confirm(session, f"Bearer {TOKEN.value}", action)

    evidence = await step_up.verify(grant.token.value, session, action)

    assert evidence == grant.evidence


@pytest.mark.asyncio
async def test_proof_is_action_specific() -> None:
    step_up, access, _, registry, _ = await _service()
    session = await _session(access, registry)
    grant = await step_up.confirm(
        session,
        f"Bearer {TOKEN.value}",
        ControlPlaneStepUpAction.UPDATE_ACCESS,
    )

    with pytest.raises(ControlPlaneStepUpRejectedError):
        await step_up.verify(
            grant.token.value,
            session,
            ControlPlaneStepUpAction.REVOKE_OPERATOR,
        )


@pytest.mark.asyncio
async def test_proof_is_session_specific() -> None:
    step_up, access, _, registry, _ = await _service()
    first = await _session(access, registry)
    second = await _session(access, registry)
    grant = await step_up.confirm(
        first,
        f"Bearer {TOKEN.value}",
        ControlPlaneStepUpAction.CREATE_MAINTAINER,
    )

    with pytest.raises(ControlPlaneStepUpRejectedError):
        await step_up.verify(
            grant.token.value,
            second,
            ControlPlaneStepUpAction.CREATE_MAINTAINER,
        )


@pytest.mark.asyncio
async def test_proof_expires_at_end_of_recent_authentication_window() -> None:
    step_up, access, _, registry, clock = await _service()
    session = await _session(access, registry)
    grant = await step_up.confirm(
        session,
        f"Bearer {TOKEN.value}",
        ControlPlaneStepUpAction.ROTATE_CREDENTIAL,
    )
    clock.now += timedelta(minutes=5)

    with pytest.raises(ControlPlaneStepUpRejectedError):
        await step_up.verify(
            grant.token.value,
            session,
            ControlPlaneStepUpAction.ROTATE_CREDENTIAL,
        )


@pytest.mark.asyncio
async def test_tampered_proof_fails_closed() -> None:
    step_up, access, _, registry, _ = await _service()
    session = await _session(access, registry)
    grant = await step_up.confirm(
        session,
        f"Bearer {TOKEN.value}",
        ControlPlaneStepUpAction.REVOKE_OPERATOR,
    )
    token = grant.token.value
    tampered = token[:-1] + ("A" if token[-1] != "A" else "B")

    with pytest.raises(ControlPlaneStepUpRejectedError):
        await step_up.verify(
            tampered,
            session,
            ControlPlaneStepUpAction.REVOKE_OPERATOR,
        )


@pytest.mark.asyncio
async def test_operator_role_change_invalidates_existing_proof() -> None:
    step_up, access, _, registry, clock = await _service()
    session = await _session(access, registry)
    grant = await step_up.confirm(
        session,
        f"Bearer {TOKEN.value}",
        ControlPlaneStepUpAction.UPDATE_ACCESS,
    )
    operator = await registry.get(OPERATOR_ID)
    assert operator is not None
    clock.now += timedelta(seconds=1)
    await registry.replace(
        replace(
            operator,
            role=ControlPlaneOperatorRole.VIEWER,
            updated_at=clock.now,
            revision=operator.revision + 1,
        ),
        expected_revision=operator.revision,
    )

    with pytest.raises(ControlPlaneStepUpRejectedError):
        await step_up.verify(
            grant.token.value,
            session,
            ControlPlaneStepUpAction.UPDATE_ACCESS,
        )


@pytest.mark.asyncio
async def test_durable_credential_rotation_invalidates_existing_proof() -> None:
    step_up, access, _, registry, clock = await _service()
    session = await _session(access, registry)
    grant = await step_up.confirm(
        session,
        f"Bearer {TOKEN.value}",
        ControlPlaneStepUpAction.ROTATE_CREDENTIAL,
    )
    operator = await registry.get(OPERATOR_ID)
    assert operator is not None
    clock.now += timedelta(seconds=1)
    await registry.replace(
        replace(
            operator,
            token_digest=ControlPlaneOperatorToken(
                "replacement-step-up-token-0123456789abcdef"
            ).digest,
            token_version=operator.token_version + 1,
            updated_at=clock.now,
            revision=operator.revision + 1,
        ),
        expected_revision=operator.revision,
    )

    with pytest.raises(ControlPlaneStepUpRejectedError):
        await step_up.verify(
            grant.token.value,
            session,
            ControlPlaneStepUpAction.ROTATE_CREDENTIAL,
        )


@pytest.mark.asyncio
async def test_terminal_session_invalidates_existing_proof() -> None:
    step_up, access, repository, registry, clock = await _service()
    session = await _session(access, registry)
    grant = await step_up.confirm(
        session,
        f"Bearer {TOKEN.value}",
        ControlPlaneStepUpAction.REVOKE_OPERATOR_SESSIONS,
    )
    record = await repository.get(session.session_id)
    assert record is not None
    clock.now += timedelta(seconds=1)
    await repository.terminate(
        record.id,
        expected_revision=record.revision,
        status=ControlPlaneDurableSessionStatus.REVOKED,
        reason=ControlPlaneDurableSessionTerminationReason.ADMINISTRATIVE,
        terminated_at=clock.now,
    )

    with pytest.raises(ControlPlaneStepUpRejectedError):
        await step_up.verify(
            grant.token.value,
            session,
            ControlPlaneStepUpAction.REVOKE_OPERATOR_SESSIONS,
        )


@pytest.mark.asyncio
async def test_disabled_operator_cannot_confirm_step_up() -> None:
    step_up, access, _, registry, clock = await _service()
    session = await _session(access, registry)
    operator = await registry.get(OPERATOR_ID)
    assert operator is not None
    clock.now += timedelta(seconds=1)
    await registry.replace(
        replace(
            operator,
            status=ControlPlaneOperatorStatus.DISABLED,
            disabled_at=clock.now,
            updated_at=clock.now,
            revision=operator.revision + 1,
        ),
        expected_revision=operator.revision,
    )

    with pytest.raises(ControlPlaneStepUpRejectedError):
        await step_up.confirm(
            session,
            f"Bearer {TOKEN.value}",
            ControlPlaneStepUpAction.REVOKE_OPERATOR,
        )


@pytest.mark.asyncio
async def test_snapshot_counts_confirmed_verified_and_rejected_without_credentials() -> None:
    step_up, access, _, registry, _ = await _service()
    session = await _session(access, registry)
    grant = await step_up.confirm(
        session,
        f"Bearer {TOKEN.value}",
        ControlPlaneStepUpAction.REVOKE_OPERATOR,
    )
    await step_up.verify(
        grant.token.value,
        session,
        ControlPlaneStepUpAction.REVOKE_OPERATOR,
    )
    with pytest.raises(ControlPlaneStepUpRejectedError):
        await step_up.verify(
            "invalid",
            session,
            ControlPlaneStepUpAction.REVOKE_OPERATOR,
        )

    snapshot = step_up.snapshot()
    assert snapshot.confirmed == 1
    assert snapshot.verified == 1
    assert snapshot.rejected == 1
    assert TOKEN.value not in repr(snapshot)
