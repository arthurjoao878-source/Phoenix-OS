from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from phoenix_os.control_plane.auth import (
    CONTROL_PLANE_READ_PERMISSION,
    ControlPlanePrincipal,
)
from phoenix_os.control_plane.durable_session_access import (
    ControlPlaneDurableSessionAuthentication,
)
from phoenix_os.control_plane.task_authority_composition import (
    compose_durable_session_task_execution_authority,
)
from phoenix_os.control_plane.task_runtime_bridge import (
    TaskRuntimeBridgeValidationError,
)
from phoenix_os.policy import PolicyEngine, PrincipalType

_NOW = datetime(2026, 9, 9, 19, 0, tzinfo=UTC)
_SESSION_ID = UUID("73000000-0000-4000-8000-000000000001")
_OPERATOR_ID = UUID("74000000-0000-4000-8000-000000000001")
_PERMISSIONS = frozenset(
    {
        CONTROL_PLANE_READ_PERMISSION,
        "agent.run",
        "agent.resume",
        "model.infer",
        "tool.invoke",
        "workspace.list",
        "workspace.read",
    }
)


def _authentication() -> ControlPlaneDurableSessionAuthentication:
    return ControlPlaneDurableSessionAuthentication(
        session_id=_SESSION_ID,
        operator_id=_OPERATOR_ID,
        principal=ControlPlanePrincipal("operator-1", _PERMISSIONS),
        generation=3,
        authenticated_at=_NOW,
        absolute_expires_at=_NOW + timedelta(hours=1),
        idle_expires_at=_NOW + timedelta(minutes=30),
    )


@pytest.mark.asyncio
async def test_task_authority_reuses_exact_policy_without_creating_rules() -> None:
    policy = PolicyEngine()
    try:
        before = await policy.list_rules()

        authority = compose_durable_session_task_execution_authority(
            policy=policy,
            authentication=_authentication(),
        )

        after = await policy.list_rules()
        assert authority.policy is policy
        assert before == after == ()
    finally:
        await policy.close()


@pytest.mark.asyncio
async def test_task_authority_uses_canonical_durable_session_identity() -> None:
    policy = PolicyEngine()
    authentication = _authentication()
    try:
        authority = compose_durable_session_task_execution_authority(
            policy=policy,
            authentication=authentication,
        )

        assert authority.context.principal == authentication.principal.name
        assert authority.context.principal_type is PrincipalType.USER
        assert authority.context.authenticated
        assert authority.context.permissions == authentication.principal.permissions
        assert authority.context.session_id == authentication.session_id
    finally:
        await policy.close()


@pytest.mark.asyncio
async def test_task_authority_fails_closed_after_policy_is_closed() -> None:
    policy = PolicyEngine()
    await policy.close()

    with pytest.raises(TaskRuntimeBridgeValidationError):
        compose_durable_session_task_execution_authority(
            policy=policy,
            authentication=_authentication(),
        )


@pytest.mark.asyncio
async def test_task_authority_rejects_non_durable_authentication() -> None:
    policy = PolicyEngine()
    try:
        with pytest.raises(TypeError, match="authentication"):
            compose_durable_session_task_execution_authority(
                policy=policy,
                authentication=object(),  # type: ignore[arg-type]
            )
    finally:
        await policy.close()
