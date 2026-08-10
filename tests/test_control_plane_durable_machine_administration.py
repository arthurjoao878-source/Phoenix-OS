"""Tests for the trusted RFC-0028 durable machine-administration guard."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from phoenix_os.agent import (
    AGENT_DURABLE_HEALTH_READ_ACTION,
    DURABLE_ADMINISTRATION_HEALTH_RESOURCE,
    DurableAdministrationConfiguration,
    DurableMachineAdministrationGuard,
    InMemoryDurableRunStore,
    StaticDurableCompatibilityValidator,
    create_durable_agent_runtime_stack,
)
from phoenix_os.control_plane import (
    ControlPlaneDurableMachineAdministrationGuard,
    ControlPlaneServiceAccountPermissionDeniedError,
    control_plane_service_account_api_context,
    control_plane_service_account_api_scope,
)
from phoenix_os.control_plane.service_account_authentication import (
    ControlPlaneServiceAccountAuthentication,
)
from phoenix_os.control_plane.service_account_policy import (
    ControlPlaneServiceAccountApiContext,
)

_NOW = datetime(2026, 8, 8, 12, tzinfo=UTC)
_ACCOUNT_ID = UUID("10000000-0000-4000-8000-000000000028")
_TOKEN_ID = UUID("20000000-0000-4000-8000-000000000028")
_REQUEST_ID = UUID("30000000-0000-4000-8000-000000000028")
_ACTION = "agent.durable.read"
_RESOURCE = "durable-agent-run:40000000-0000-4000-8000-000000000028"
_DENIED_MESSAGE = "service-account authorization denied"


def _authentication(
    *,
    scopes: frozenset[str] = frozenset({_ACTION}),
    resources: frozenset[str] = frozenset({_RESOURCE}),
) -> ControlPlaneServiceAccountAuthentication:
    return ControlPlaneServiceAccountAuthentication(
        service_account_id=_ACCOUNT_ID,
        token_id=_TOKEN_ID,
        account_name="durable.bot",
        scopes=scopes,
        resources=resources,
        token_version=1,
        account_revision=1,
        token_revision=1,
        authenticated_at=_NOW,
        expires_at=_NOW + timedelta(hours=1),
    )


def _context(
    *,
    scopes: frozenset[str] = frozenset({_ACTION}),
    resources: frozenset[str] = frozenset({_RESOURCE}),
) -> ControlPlaneServiceAccountApiContext:
    return control_plane_service_account_api_context(
        _authentication(scopes=scopes, resources=resources),
        request_id=_REQUEST_ID,
        correlation_id="durable-machine-administration-test",
    )


def _assert_generic_denial(
    captured: pytest.ExceptionInfo[ControlPlaneServiceAccountPermissionDeniedError],
) -> None:
    assert str(captured.value) == _DENIED_MESSAGE
    assert captured.value.__cause__ is None


def test_guard_structurally_implements_agent_machine_guard_protocol() -> None:
    guard = ControlPlaneDurableMachineAdministrationGuard()
    assert isinstance(guard, DurableMachineAdministrationGuard)


@pytest.mark.asyncio
async def test_guard_authorizes_real_durable_administration_health_boundary() -> None:
    store = InMemoryDurableRunStore()
    guard = ControlPlaneDurableMachineAdministrationGuard()
    stack = create_durable_agent_runtime_stack(
        store=store,
        lease_manager=store.lease_manager,
        compatibility_validator=StaticDurableCompatibilityValidator(()),
        administration_configuration=DurableAdministrationConfiguration(
            machine_administration_enabled=True
        ),
        machine_guard=guard,
    )
    context = _context(
        scopes=frozenset({AGENT_DURABLE_HEALTH_READ_ACTION}),
        resources=frozenset({DURABLE_ADMINISTRATION_HEALTH_RESOURCE}),
    )

    try:
        with control_plane_service_account_api_scope(context):
            snapshot = await stack.administration.snapshot(context.security_context)

        assert snapshot.store_open
        assert snapshot.lease_manager_open
    finally:
        await stack.close()


@pytest.mark.asyncio
async def test_guard_allows_exact_scope_and_exact_resource_from_active_api_context() -> None:
    guard = ControlPlaneDurableMachineAdministrationGuard()
    context = _context()

    with control_plane_service_account_api_scope(context):
        await guard.authorize(
            context.security_context,
            action=_ACTION,
            resource=_RESOURCE,
        )


@pytest.mark.asyncio
async def test_guard_requires_active_trusted_api_context() -> None:
    guard = ControlPlaneDurableMachineAdministrationGuard()
    context = _context()

    with pytest.raises(ControlPlaneServiceAccountPermissionDeniedError) as captured:
        await guard.authorize(
            context.security_context,
            action=_ACTION,
            resource=_RESOURCE,
        )

    _assert_generic_denial(captured)


@pytest.mark.asyncio
async def test_guard_rejects_forged_security_context_even_when_fields_match() -> None:
    guard = ControlPlaneDurableMachineAdministrationGuard()
    context = _context()
    forged = replace(context.security_context)

    assert forged == context.security_context
    assert forged is not context.security_context

    with control_plane_service_account_api_scope(context):
        with pytest.raises(ControlPlaneServiceAccountPermissionDeniedError) as captured:
            await guard.authorize(
                forged,
                action=_ACTION,
                resource=_RESOURCE,
            )

    _assert_generic_denial(captured)


@pytest.mark.asyncio
async def test_guard_rejects_missing_exact_action_scope() -> None:
    guard = ControlPlaneDurableMachineAdministrationGuard()
    context = _context(scopes=frozenset({"agent.durable.health.read"}))

    with control_plane_service_account_api_scope(context):
        with pytest.raises(ControlPlaneServiceAccountPermissionDeniedError) as captured:
            await guard.authorize(
                context.security_context,
                action=_ACTION,
                resource=_RESOURCE,
            )

    _assert_generic_denial(captured)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "resources",
    [
        frozenset({"*"}),
        frozenset({"durable-agent-run:*"}),
    ],
)
async def test_guard_rejects_wildcard_resource_grants(
    resources: frozenset[str],
) -> None:
    guard = ControlPlaneDurableMachineAdministrationGuard()
    context = _context(resources=resources)

    with control_plane_service_account_api_scope(context):
        with pytest.raises(ControlPlaneServiceAccountPermissionDeniedError) as captured:
            await guard.authorize(
                context.security_context,
                action=_ACTION,
                resource=_RESOURCE,
            )

    _assert_generic_denial(captured)


@pytest.mark.asyncio
async def test_guard_rejects_neighboring_exact_resource() -> None:
    guard = ControlPlaneDurableMachineAdministrationGuard()
    context = _context(
        resources=frozenset({"durable-agent-run:40000000-0000-4000-8000-000000000029"})
    )

    with control_plane_service_account_api_scope(context):
        with pytest.raises(ControlPlaneServiceAccountPermissionDeniedError) as captured:
            await guard.authorize(
                context.security_context,
                action=_ACTION,
                resource=_RESOURCE,
            )

    _assert_generic_denial(captured)
