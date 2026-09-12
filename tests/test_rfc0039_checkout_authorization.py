from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from uuid import UUID

import pytest

from phoenix_os.agent.checkout_authorization import (
    CheckoutListAuthorizationRequest,
    CheckoutReadAuthorizationRequest,
    PolicyEngineCheckoutWorkspaceAuthorizer,
)
from phoenix_os.agent.checkout_workspace import (
    RegisteredDevelopmentCheckout,
    checkout_path_resource,
    checkout_prefix_resource,
)
from phoenix_os.agent.contracts import AgentRunId
from phoenix_os.agent.errors import AgentAuthorizationRejectedError
from phoenix_os.agent.workspace_authorization import (
    WORKSPACE_LIST_ACTION,
    WORKSPACE_READ_ACTION,
)
from phoenix_os.policy import (
    PolicyEffect,
    PolicyEngine,
    PolicyRule,
    PrincipalType,
    SecurityContext,
)

_WORKSPACE_ID = UUID("10000000-0000-4000-8000-000000000001")
_RUN_ID = AgentRunId(UUID("20000000-0000-4000-8000-000000000002"))
_NOW = datetime(2026, 9, 6, 12, 0, tzinfo=UTC)


def _registration(*, generation: int = 7) -> RegisteredDevelopmentCheckout:
    return RegisteredDevelopmentCheckout(
        workspace_id=_WORKSPACE_ID,
        workspace_name="project",
        generation=generation,
        root_identity="sha256:" + ("0" * 64),
        read_prefixes=("src", "tests"),
    )


def _context(*, authenticated: bool = True) -> SecurityContext:
    return SecurityContext(
        principal="operator-1",
        principal_type=PrincipalType.USER,
        authenticated=authenticated,
        permissions=frozenset({WORKSPACE_LIST_ACTION, WORKSPACE_READ_ACTION}),
    )


def _digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _list_request(
    *,
    run_id: AgentRunId = _RUN_ID,
    generation: int = 7,
    prefix: str = "src",
) -> CheckoutListAuthorizationRequest:
    return CheckoutListAuthorizationRequest(
        run_id=run_id,
        registration=_registration(generation=generation),
        prefix=prefix,
        max_entries=32,
        created_at=_NOW,
    )


def _read_request(
    *,
    run_id: AgentRunId = _RUN_ID,
    generation: int = 7,
    logical_path: str = "src/example.py",
) -> CheckoutReadAuthorizationRequest:
    return CheckoutReadAuthorizationRequest(
        run_id=run_id,
        registration=_registration(generation=generation),
        logical_path=logical_path,
        created_at=_NOW,
    )


@pytest.mark.asyncio
async def test_checkout_authorizer_is_default_deny() -> None:
    policy = PolicyEngine()
    authorizer = PolicyEngineCheckoutWorkspaceAuthorizer(policy)
    try:
        with pytest.raises(AgentAuthorizationRejectedError):
            await authorizer.authorize_list(_list_request(), _context())
        with pytest.raises(AgentAuthorizationRejectedError):
            await authorizer.authorize_read(_read_request(), _context())
    finally:
        await policy.close()


@pytest.mark.asyncio
async def test_exact_list_and_read_policy_are_enforced() -> None:
    registration = _registration()
    context = _context()
    policy = PolicyEngine(
        (
            PolicyRule(
                rule_id="checkout-list",
                effect=PolicyEffect.ALLOW,
                actions=frozenset({WORKSPACE_LIST_ACTION}),
                resources=frozenset({checkout_prefix_resource(registration, "src")}),
                principals=frozenset({context.principal}),
                principal_types=frozenset({PrincipalType.USER}),
                required_permissions=frozenset({WORKSPACE_LIST_ACTION}),
                authenticated=True,
                attribute_equals={
                    "checkout_workspace_id": str(_WORKSPACE_ID),
                    "checkout_registration_generation": "7",
                    "run_id": str(_RUN_ID),
                    "prefix_digest": _digest("src"),
                    "max_entries": "32",
                },
            ),
            PolicyRule(
                rule_id="checkout-read",
                effect=PolicyEffect.ALLOW,
                actions=frozenset({WORKSPACE_READ_ACTION}),
                resources=frozenset({checkout_path_resource(registration, "src/example.py")}),
                principals=frozenset({context.principal}),
                principal_types=frozenset({PrincipalType.USER}),
                required_permissions=frozenset({WORKSPACE_READ_ACTION}),
                authenticated=True,
                attribute_equals={
                    "checkout_workspace_id": str(_WORKSPACE_ID),
                    "checkout_registration_generation": "7",
                    "run_id": str(_RUN_ID),
                    "logical_path_digest": _digest("src/example.py"),
                },
            ),
        )
    )
    authorizer = PolicyEngineCheckoutWorkspaceAuthorizer(policy)

    try:
        await authorizer.authorize_list(_list_request(), context)
        await authorizer.authorize_read(_read_request(), context)
    finally:
        await policy.close()


@pytest.mark.asyncio
async def test_run_generation_and_logical_resource_substitution_fail_closed() -> None:
    registration = _registration()
    context = _context()
    policy = PolicyEngine(
        (
            PolicyRule(
                rule_id="checkout-list",
                effect=PolicyEffect.ALLOW,
                actions=frozenset({WORKSPACE_LIST_ACTION}),
                resources=frozenset({checkout_prefix_resource(registration, "src")}),
                principals=frozenset({context.principal}),
                principal_types=frozenset({PrincipalType.USER}),
                required_permissions=frozenset({WORKSPACE_LIST_ACTION}),
                authenticated=True,
                attribute_equals={
                    "checkout_workspace_id": str(_WORKSPACE_ID),
                    "checkout_registration_generation": "7",
                    "run_id": str(_RUN_ID),
                    "prefix_digest": _digest("src"),
                    "max_entries": "32",
                },
            ),
            PolicyRule(
                rule_id="checkout-read",
                effect=PolicyEffect.ALLOW,
                actions=frozenset({WORKSPACE_READ_ACTION}),
                resources=frozenset({checkout_path_resource(registration, "src/example.py")}),
                principals=frozenset({context.principal}),
                principal_types=frozenset({PrincipalType.USER}),
                required_permissions=frozenset({WORKSPACE_READ_ACTION}),
                authenticated=True,
                attribute_equals={
                    "checkout_workspace_id": str(_WORKSPACE_ID),
                    "checkout_registration_generation": "7",
                    "run_id": str(_RUN_ID),
                    "logical_path_digest": _digest("src/example.py"),
                },
            ),
        )
    )
    authorizer = PolicyEngineCheckoutWorkspaceAuthorizer(policy)

    try:
        wrong_run = AgentRunId(UUID("30000000-0000-4000-8000-000000000003"))
        for request in (
            _list_request(run_id=wrong_run),
            _list_request(generation=8),
            _list_request(prefix="tests"),
        ):
            with pytest.raises(AgentAuthorizationRejectedError):
                await authorizer.authorize_list(request, context)

        for read_request in (
            _read_request(run_id=wrong_run),
            _read_request(generation=8),
            _read_request(logical_path="src/other.py"),
        ):
            with pytest.raises(AgentAuthorizationRejectedError):
                await authorizer.authorize_read(read_request, context)
    finally:
        await policy.close()


@pytest.mark.asyncio
async def test_unauthenticated_context_rejected_before_policy() -> None:
    policy = PolicyEngine()
    authorizer = PolicyEngineCheckoutWorkspaceAuthorizer(policy)
    try:
        with pytest.raises(AgentAuthorizationRejectedError):
            await authorizer.authorize_list(
                _list_request(),
                _context(authenticated=False),
            )
        with pytest.raises(AgentAuthorizationRejectedError):
            await authorizer.authorize_read(
                _read_request(),
                _context(authenticated=False),
            )
    finally:
        await policy.close()


def test_authorization_requests_validate_bounds_and_timezone() -> None:
    with pytest.raises(ValueError):
        CheckoutListAuthorizationRequest(
            run_id=_RUN_ID,
            registration=_registration(),
            prefix="src",
            max_entries=0,
            created_at=_NOW,
        )
    with pytest.raises(ValueError):
        CheckoutListAuthorizationRequest(
            run_id=_RUN_ID,
            registration=_registration(),
            prefix="src",
            max_entries=1,
            created_at=datetime(2026, 9, 6, 12, 0),
        )
    with pytest.raises(ValueError):
        CheckoutReadAuthorizationRequest(
            run_id=_RUN_ID,
            registration=_registration(),
            logical_path="src/example.py",
            created_at=datetime(2026, 9, 6, 12, 0),
        )
