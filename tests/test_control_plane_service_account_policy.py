from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from phoenix_os.control_plane import (
    ControlPlaneServiceAccountApiContext,
    ControlPlaneServiceAccountApiContextUnavailableError,
    ControlPlaneServiceAccountPermissionDeniedError,
    ControlPlaneServiceAccountPolicyAuthorizer,
    control_plane_service_account_api_context,
    control_plane_service_account_api_scope,
    current_control_plane_service_account_api_context,
)
from phoenix_os.control_plane.service_account_authentication import (
    ControlPlaneServiceAccountAuthentication,
)
from phoenix_os.policy import (
    PolicyEffect,
    PolicyEngine,
    PolicyRule,
    PrincipalType,
)

_NOW = datetime(
    2026,
    7,
    20,
    12,
    tzinfo=UTC,
)
_ACCOUNT_ID = UUID("10000000-0000-0000-0000-000000000001")
_TOKEN_ID = UUID("20000000-0000-0000-0000-000000000001")
_REQUEST_ID = UUID("30000000-0000-0000-0000-000000000001")
_JOB_ID = UUID("40000000-0000-0000-0000-000000000001")


def _authentication(
    *,
    scopes: frozenset[str] = frozenset(
        {
            "job.cancel",
        }
    ),
    resources: frozenset[str] = frozenset(
        {
            f"job:{_JOB_ID}",
        }
    ),
) -> ControlPlaneServiceAccountAuthentication:
    return ControlPlaneServiceAccountAuthentication(
        service_account_id=_ACCOUNT_ID,
        token_id=_TOKEN_ID,
        account_name="release.bot",
        scopes=scopes,
        resources=resources,
        token_version=2,
        account_revision=3,
        token_revision=4,
        authenticated_at=_NOW,
        expires_at=_NOW + timedelta(hours=1),
        restriction_applied=True,
    )


def _context(
    *,
    scopes: frozenset[str] = frozenset(
        {
            "job.cancel",
        }
    ),
    resources: frozenset[str] = frozenset(
        {
            f"job:{_JOB_ID}",
        }
    ),
) -> ControlPlaneServiceAccountApiContext:
    return control_plane_service_account_api_context(
        _authentication(
            scopes=scopes,
            resources=resources,
        ),
        request_id=_REQUEST_ID,
        correlation_id="request-123",
    )


def _allow_policy() -> PolicyEngine:
    return PolicyEngine(
        (
            PolicyRule(
                "allow-release-bot-cancel",
                PolicyEffect.ALLOW,
                actions=frozenset(
                    {
                        "job.cancel",
                    }
                ),
                resources=frozenset(
                    {
                        f"job:{_JOB_ID}",
                    }
                ),
                principals=frozenset(
                    {
                        "service-account:release.bot",
                    }
                ),
                principal_types=frozenset(
                    {
                        PrincipalType.SERVICE,
                    }
                ),
                required_scopes=frozenset(
                    {
                        "job.cancel",
                    }
                ),
                authenticated=True,
            ),
        )
    )


def test_api_context_uses_explicit_service_identity() -> None:
    context = _context()
    security = context.security_context

    assert context.principal_name == ("service-account:release.bot")
    assert security.principal == context.principal_name
    assert security.principal_type is PrincipalType.SERVICE
    assert security.authenticated
    assert security.roles == frozenset()
    assert security.permissions == frozenset()
    assert security.scopes == frozenset(
        {
            "job.cancel",
        }
    )
    assert not security.confirmed
    assert security.causation_id == _REQUEST_ID
    assert security.correlation_id == "request-123"


def test_api_context_contains_only_safe_machine_metadata() -> None:
    context = _context()
    attributes = dict(context.security_context.attributes)

    assert attributes == {
        "service_account_id": str(_ACCOUNT_ID),
        "token_id": str(_TOKEN_ID),
        "token_version": "2",
        "account_revision": "3",
        "token_revision": "4",
        "restriction_applied": "true",
        "authentication_schema_version": "1",
    }

    rendered = repr(context)

    assert "phx_sa_" not in rendered
    assert "digest" not in rendered.lower()
    assert "authorization" not in rendered.lower()


def test_api_context_cannot_be_forged_directly() -> None:
    trusted = _context()

    with pytest.raises(
        TypeError,
        match="trusted context factory",
    ):
        ControlPlaneServiceAccountApiContext(
            authentication=trusted.authentication,
            security_context=trusted.security_context,
            request_id=trusted.request_id,
            correlation_id=trusted.correlation_id,
        )


def test_api_scope_propagates_and_restores_context() -> None:
    context = _context()

    assert current_control_plane_service_account_api_context() is None

    with control_plane_service_account_api_scope(context):
        assert current_control_plane_service_account_api_context() is context

    assert current_control_plane_service_account_api_context() is None


def test_api_scope_restores_context_after_exception() -> None:
    context = _context()

    with pytest.raises(
        RuntimeError,
        match="boom",
    ):
        with control_plane_service_account_api_scope(context):
            raise RuntimeError("boom")

    assert current_control_plane_service_account_api_context() is None


def test_nested_api_scopes_restore_previous_context() -> None:
    outer = _context()
    inner = control_plane_service_account_api_context(
        _authentication(),
        request_id=UUID(int=99),
        correlation_id="request-inner",
    )

    with control_plane_service_account_api_scope(outer):
        assert current_control_plane_service_account_api_context() is outer

        with control_plane_service_account_api_scope(inner):
            assert current_control_plane_service_account_api_context() is inner

        assert current_control_plane_service_account_api_context() is outer


@pytest.mark.asyncio
async def test_exact_grants_and_policy_must_both_allow() -> None:
    context = _context()
    authorizer = ControlPlaneServiceAccountPolicyAuthorizer(_allow_policy())

    decision = await authorizer.enforce(
        context,
        action="job.cancel",
        resource=f"job:{_JOB_ID}",
    )

    assert decision.effect is PolicyEffect.ALLOW
    assert decision.rule_id == ("allow-release-bot-cancel")


@pytest.mark.asyncio
async def test_missing_scope_denies_before_policy_evaluation() -> None:
    engine = _allow_policy()
    authorizer = ControlPlaneServiceAccountPolicyAuthorizer(engine)
    context = _context(
        scopes=frozenset(
            {
                "jobs.read",
            }
        )
    )

    with pytest.raises(
        ControlPlaneServiceAccountPermissionDeniedError,
        match="authorization denied",
    ):
        await authorizer.enforce(
            context,
            action="job.cancel",
            resource=f"job:{_JOB_ID}",
        )

    snapshot = await engine.snapshot()

    assert snapshot.evaluations == 0


@pytest.mark.asyncio
async def test_missing_resource_denies_before_policy_evaluation() -> None:
    engine = _allow_policy()
    authorizer = ControlPlaneServiceAccountPolicyAuthorizer(engine)
    context = _context(
        resources=frozenset(
            {
                "job:00000000-0000-0000-0000-000000000099",
            }
        )
    )

    with pytest.raises(
        ControlPlaneServiceAccountPermissionDeniedError,
        match="authorization denied",
    ):
        await authorizer.enforce(
            context,
            action="job.cancel",
            resource=f"job:{_JOB_ID}",
        )

    snapshot = await engine.snapshot()

    assert snapshot.evaluations == 0


@pytest.mark.asyncio
async def test_policy_default_deny_is_generic() -> None:
    engine = PolicyEngine()
    authorizer = ControlPlaneServiceAccountPolicyAuthorizer(engine)

    with pytest.raises(
        ControlPlaneServiceAccountPermissionDeniedError,
    ) as captured:
        await authorizer.enforce(
            _context(),
            action="job.cancel",
            resource=f"job:{_JOB_ID}",
        )

    assert str(captured.value) == ("service-account authorization denied")
    assert captured.value.__cause__ is None

    snapshot = await engine.snapshot()

    assert snapshot.evaluations == 1
    assert snapshot.denied == 1


@pytest.mark.asyncio
async def test_human_policy_rule_does_not_authorize_service() -> None:
    engine = PolicyEngine(
        (
            PolicyRule(
                "human-only",
                PolicyEffect.ALLOW,
                actions=frozenset(
                    {
                        "job.cancel",
                    }
                ),
                resources=frozenset(
                    {
                        f"job:{_JOB_ID}",
                    }
                ),
                principal_types=frozenset(
                    {
                        PrincipalType.USER,
                    }
                ),
                authenticated=True,
            ),
        )
    )

    with pytest.raises(
        ControlPlaneServiceAccountPermissionDeniedError,
    ):
        await ControlPlaneServiceAccountPolicyAuthorizer(engine).enforce(
            _context(),
            action="job.cancel",
            resource=f"job:{_JOB_ID}",
        )


@pytest.mark.asyncio
async def test_confirmation_policy_is_denied_for_machine() -> None:
    engine = PolicyEngine(
        (
            PolicyRule(
                "confirmation-required",
                PolicyEffect.REQUIRE_CONFIRMATION,
                actions=frozenset(
                    {
                        "job.cancel",
                    }
                ),
                resources=frozenset(
                    {
                        f"job:{_JOB_ID}",
                    }
                ),
                principal_types=frozenset(
                    {
                        PrincipalType.SERVICE,
                    }
                ),
            ),
        )
    )

    with pytest.raises(
        ControlPlaneServiceAccountPermissionDeniedError,
        match="authorization denied",
    ):
        await ControlPlaneServiceAccountPolicyAuthorizer(engine).enforce(
            _context(),
            action="job.cancel",
            resource=f"job:{_JOB_ID}",
        )


@pytest.mark.asyncio
async def test_enforce_current_uses_propagated_context() -> None:
    context = _context()
    authorizer = ControlPlaneServiceAccountPolicyAuthorizer(_allow_policy())

    with control_plane_service_account_api_scope(context):
        decision = await authorizer.enforce_current(
            action="job.cancel",
            resource=f"job:{_JOB_ID}",
        )

    assert decision.effect is PolicyEffect.ALLOW


@pytest.mark.asyncio
async def test_enforce_current_fails_without_context() -> None:
    authorizer = ControlPlaneServiceAccountPolicyAuthorizer(_allow_policy())

    with pytest.raises(
        ControlPlaneServiceAccountApiContextUnavailableError,
        match="context is unavailable",
    ):
        await authorizer.enforce_current(
            action="job.cancel",
            resource=f"job:{_JOB_ID}",
        )


def test_policy_exports_are_public() -> None:
    import phoenix_os.control_plane as control_plane

    assert (
        control_plane.ControlPlaneServiceAccountApiContext is ControlPlaneServiceAccountApiContext
    )
    assert (
        control_plane.ControlPlaneServiceAccountPolicyAuthorizer
        is ControlPlaneServiceAccountPolicyAuthorizer
    )
    assert (
        control_plane.control_plane_service_account_api_context
        is control_plane_service_account_api_context
    )
    assert (
        control_plane.control_plane_service_account_api_scope
        is control_plane_service_account_api_scope
    )
    assert (
        control_plane.current_control_plane_service_account_api_context
        is current_control_plane_service_account_api_context
    )
