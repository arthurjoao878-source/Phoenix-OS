"""Durable control-plane caller binding for RFC-0033 authority diagnostics."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime

from phoenix_os.authority import (
    AuthorityFreshnessRejectedError,
    AuthorityInspectionSource,
    AuthorityService,
)
from phoenix_os.control_plane.durable_session_access import (
    ControlPlaneDurableSessionAuthentication,
)
from phoenix_os.control_plane.durable_session_contracts import (
    ControlPlaneDurableSessionRecord,
    ControlPlaneDurableSessionRepository,
    ControlPlaneDurableSessionStatus,
)
from phoenix_os.control_plane.operator_contracts import (
    ControlPlaneOperatorRecord,
    ControlPlaneOperatorRegistry,
    ControlPlaneOperatorStatus,
)
from phoenix_os.policy import PolicyEngine, PrincipalType, SecurityContext

type ControlPlaneAuthorityClock = Callable[[], datetime]


def _utc_now() -> datetime:
    return datetime.now(UTC)


def control_plane_authority_security_context(
    authentication: ControlPlaneDurableSessionAuthentication,
) -> SecurityContext:
    """Project trusted durable operator authentication into RFC-0033 caller identity."""

    if not isinstance(authentication, ControlPlaneDurableSessionAuthentication):
        raise TypeError("authentication must be ControlPlaneDurableSessionAuthentication")
    return SecurityContext(
        principal=authentication.principal.name,
        principal_type=PrincipalType.USER,
        authenticated=True,
        permissions=authentication.principal.permissions,
        session_id=authentication.session_id,
    )


class ControlPlaneDurableAuthorityFreshnessValidator:
    """Revalidate durable operator authority without touching or rotating session state."""

    def __init__(
        self,
        *,
        repository: ControlPlaneDurableSessionRepository,
        registry: ControlPlaneOperatorRegistry,
        clock: ControlPlaneAuthorityClock = _utc_now,
    ) -> None:
        if not callable(getattr(repository, "get", None)):
            raise TypeError("authority freshness repository must support get")
        if not callable(getattr(registry, "get", None)):
            raise TypeError("authority freshness registry must support get")
        if not callable(clock):
            raise TypeError("authority freshness clock must be callable")
        self._repository = repository
        self._registry = registry
        self._clock = clock

    async def validate(self, context: SecurityContext) -> None:
        """Fail closed unless one exact current durable operator session backs the caller."""

        if not isinstance(context, SecurityContext):
            raise TypeError("context must be SecurityContext")
        session_id = context.session_id
        if session_id is None:
            raise AuthorityFreshnessRejectedError("current operator authority rejected")

        try:
            record = await self._repository.get(session_id)
            if not isinstance(record, ControlPlaneDurableSessionRecord):
                raise AuthorityFreshnessRejectedError("current operator authority rejected")
            now = self._now()
            if (
                record.status is not ControlPlaneDurableSessionStatus.ACTIVE
                or now < record.last_seen_at
                or not record.active_at(now)
            ):
                raise AuthorityFreshnessRejectedError("current operator authority rejected")

            operator = await self._registry.get(record.operator_id)
            if not isinstance(operator, ControlPlaneOperatorRecord):
                raise AuthorityFreshnessRejectedError("current operator authority rejected")
            if (
                operator.status is not ControlPlaneOperatorStatus.ACTIVE
                or operator.token_version != record.operator_token_version
                or operator.revision != record.operator_revision
                or operator.username != record.username
            ):
                raise AuthorityFreshnessRejectedError("current operator authority rejected")

            expected = SecurityContext(
                principal=operator.username,
                principal_type=PrincipalType.USER,
                authenticated=True,
                permissions=operator.effective_permissions,
                session_id=record.id,
            )
            if not _same_authority_identity(context, expected):
                raise AuthorityFreshnessRejectedError("current operator authority rejected")
        except AuthorityFreshnessRejectedError:
            raise
        except Exception:
            raise AuthorityFreshnessRejectedError("current operator authority rejected") from None

    def _now(self) -> datetime:
        value = self._clock()
        if not isinstance(value, datetime):
            raise TypeError("authority freshness clock must return datetime")
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("authority freshness clock must return a timezone-aware datetime")
        return value


def create_control_plane_authority_service(
    *,
    policy: PolicyEngine,
    source: AuthorityInspectionSource,
    repository: ControlPlaneDurableSessionRepository,
    registry: ControlPlaneOperatorRegistry,
    clock: ControlPlaneAuthorityClock = _utc_now,
) -> AuthorityService:
    """Compose the read-only authority service for durable control-plane operators."""

    return AuthorityService(
        policy,
        source,
        ControlPlaneDurableAuthorityFreshnessValidator(
            repository=repository,
            registry=registry,
            clock=clock,
        ),
    )


def _same_authority_identity(actual: SecurityContext, expected: SecurityContext) -> bool:
    return (
        actual.principal == expected.principal
        and actual.principal_type is expected.principal_type
        and actual.authenticated is expected.authenticated
        and actual.roles == expected.roles
        and actual.permissions == expected.permissions
        and actual.scopes == expected.scopes
        and actual.attributes == expected.attributes
        and actual.session_id == expected.session_id
    )
