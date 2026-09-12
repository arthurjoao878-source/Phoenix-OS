"""Compose RFC-0039 task execution authority from trusted durable operator auth."""

from __future__ import annotations

from phoenix_os.control_plane.authority_integration import (
    control_plane_authority_security_context,
)
from phoenix_os.control_plane.durable_session_access import (
    ControlPlaneDurableSessionAuthentication,
)
from phoenix_os.control_plane.task_runtime_bridge import TaskExecutionAuthority
from phoenix_os.policy import PolicyEngine


def compose_durable_session_task_execution_authority(
    *,
    policy: PolicyEngine,
    authentication: ControlPlaneDurableSessionAuthentication,
) -> TaskExecutionAuthority:
    """Reuse the caller-owned policy and canonical durable-session identity."""

    if not isinstance(policy, PolicyEngine):
        raise TypeError("policy must be PolicyEngine")
    if not isinstance(authentication, ControlPlaneDurableSessionAuthentication):
        raise TypeError("authentication must be ControlPlaneDurableSessionAuthentication")
    return TaskExecutionAuthority(
        policy=policy,
        context=control_plane_authority_security_context(authentication),
    )
