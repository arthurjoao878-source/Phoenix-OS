from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import InitVar, dataclass, field
from uuid import UUID, uuid4

from phoenix_os.control_plane.service_account_authentication import (
    ControlPlaneServiceAccountAuthentication,
)
from phoenix_os.control_plane.service_account_authorization import (
    ControlPlaneServiceAccountAuthorization,
    ControlPlaneServiceAccountAuthorizer,
    ControlPlaneServiceAccountPermissionDeniedError,
)
from phoenix_os.policy import (
    PolicyConfirmationRequiredError,
    PolicyDecision,
    PolicyDeniedError,
    PolicyEngine,
    PolicyRequest,
    PrincipalType,
    SecurityContext,
)

_API_CONTEXT_AUTHORITY = object()
_MAX_CORRELATION_ID_LENGTH = 256

_CURRENT_SERVICE_ACCOUNT_API_CONTEXT: ContextVar[ControlPlaneServiceAccountApiContext | None] = (
    ContextVar(
        "phoenix_control_plane_service_account_api_context",
        default=None,
    )
)


class ControlPlaneServiceAccountApiContextUnavailableError(RuntimeError):
    """No trusted service-account context is active."""


@dataclass(frozen=True, slots=True)
class ControlPlaneServiceAccountApiContext:
    """Credential-free machine identity propagated inside one API request."""

    authentication: ControlPlaneServiceAccountAuthentication = field(repr=False)
    security_context: SecurityContext = field(repr=False)
    request_id: UUID
    correlation_id: str | None = None
    schema_version: int = 1
    _authority: InitVar[object] = None

    def __post_init__(
        self,
        _authority: object,
    ) -> None:
        if _authority is not _API_CONTEXT_AUTHORITY:
            raise TypeError(
                "service-account API context must come from the trusted context factory"
            )

        if not isinstance(
            self.authentication,
            ControlPlaneServiceAccountAuthentication,
        ):
            raise TypeError("service-account API context requires authentication evidence")

        if not isinstance(
            self.security_context,
            SecurityContext,
        ):
            raise TypeError("service-account API context requires a security context")

        if not isinstance(self.request_id, UUID):
            raise TypeError("service-account API request id must be UUID")

        correlation_id = _normalize_correlation_id(self.correlation_id)
        security = self.security_context
        authentication = self.authentication

        if security.principal != authentication.principal_name:
            raise ValueError(
                "service-account security principal does not match authentication evidence"
            )

        if security.principal_type is not PrincipalType.SERVICE or not security.authenticated:
            raise ValueError(
                "service-account security context must represent an authenticated service"
            )

        if security.roles or security.permissions:
            raise ValueError(
                "service-account security context must not contain human roles or permissions"
            )

        expected_scopes = frozenset(scope.lower() for scope in authentication.scopes)

        if security.scopes != expected_scopes:
            raise ValueError("service-account security scopes do not match authentication evidence")

        if security.confirmed:
            raise ValueError("service-account API context cannot carry human confirmation")

        if security.correlation_id != correlation_id or security.causation_id != self.request_id:
            raise ValueError("service-account tracing context is inconsistent")

        if dict(security.attributes) != _security_attributes(authentication):
            raise ValueError("service-account security attributes are not canonical")

        if self.schema_version != 1:
            raise ValueError("unsupported service-account API context schema version")

        object.__setattr__(
            self,
            "correlation_id",
            correlation_id,
        )

    @property
    def principal_name(self) -> str:
        return self.authentication.principal_name

    @property
    def service_account_id(self) -> UUID:
        return self.authentication.service_account_id

    @property
    def token_id(self) -> UUID:
        return self.authentication.token_id

    @property
    def scopes(self) -> frozenset[str]:
        return self.authentication.scopes

    @property
    def resources(self) -> frozenset[str]:
        return self.authentication.resources


def control_plane_service_account_api_context(
    authentication: ControlPlaneServiceAccountAuthentication,
    *,
    request_id: UUID | None = None,
    correlation_id: str | None = None,
) -> ControlPlaneServiceAccountApiContext:
    """Create trusted policy context from accepted machine evidence."""

    if not isinstance(
        authentication,
        ControlPlaneServiceAccountAuthentication,
    ):
        raise TypeError("service-account API context requires authentication evidence")

    normalized_request_id = uuid4() if request_id is None else request_id

    if not isinstance(normalized_request_id, UUID):
        raise TypeError("service-account API request id must be UUID")

    normalized_correlation_id = _normalize_correlation_id(correlation_id)

    security_context = SecurityContext(
        principal=authentication.principal_name,
        principal_type=PrincipalType.SERVICE,
        authenticated=True,
        roles=frozenset(),
        permissions=frozenset(),
        scopes=authentication.scopes,
        attributes=_security_attributes(authentication),
        correlation_id=normalized_correlation_id,
        causation_id=normalized_request_id,
        confirmed=False,
    )

    return ControlPlaneServiceAccountApiContext(
        authentication=authentication,
        security_context=security_context,
        request_id=normalized_request_id,
        correlation_id=normalized_correlation_id,
        _authority=_API_CONTEXT_AUTHORITY,
    )


def current_control_plane_service_account_api_context() -> (
    ControlPlaneServiceAccountApiContext | None
):
    """Return the machine API context active in this async context."""

    return _CURRENT_SERVICE_ACCOUNT_API_CONTEXT.get()


@contextmanager
def control_plane_service_account_api_scope(
    context: ControlPlaneServiceAccountApiContext,
) -> Iterator[ControlPlaneServiceAccountApiContext]:
    """Bind and reliably restore one trusted machine API context."""

    if not isinstance(
        context,
        ControlPlaneServiceAccountApiContext,
    ):
        raise TypeError("service-account API scope requires a trusted API context")

    token = _CURRENT_SERVICE_ACCOUNT_API_CONTEXT.set(context)

    try:
        yield context
    finally:
        _CURRENT_SERVICE_ACCOUNT_API_CONTEXT.reset(token)


class ControlPlaneServiceAccountPolicyAuthorizer:
    """Apply token grants before the central deny-by-default policy."""

    def __init__(
        self,
        engine: PolicyEngine,
        *,
        exact_authorizer: (ControlPlaneServiceAccountAuthorizer | None) = None,
    ) -> None:
        if not isinstance(engine, PolicyEngine):
            raise TypeError("service-account policy authorizer requires a PolicyEngine")

        if exact_authorizer is not None and not isinstance(
            exact_authorizer,
            ControlPlaneServiceAccountAuthorizer,
        ):
            raise TypeError("exact service-account authorizer has an invalid type")

        self._engine = engine
        self._exact_authorizer = exact_authorizer or ControlPlaneServiceAccountAuthorizer()

    async def enforce(
        self,
        context: ControlPlaneServiceAccountApiContext,
        *,
        action: str,
        resource: str,
    ) -> PolicyDecision:
        """Require both token grants and central policy approval."""

        if not isinstance(
            context,
            ControlPlaneServiceAccountApiContext,
        ):
            raise TypeError("service-account policy authorization requires a trusted API context")

        exact = self._exact_authorizer.require(
            context.authentication,
            action=action,
            resource=resource,
        )

        return await self._enforce_policy(
            context,
            exact,
        )

    async def enforce_current(
        self,
        *,
        action: str,
        resource: str,
    ) -> PolicyDecision:
        """Authorize using the safely propagated request context."""

        context = current_control_plane_service_account_api_context()

        if context is None:
            raise (
                ControlPlaneServiceAccountApiContextUnavailableError(
                    "service-account API context is unavailable"
                )
            )

        return await self.enforce(
            context,
            action=action,
            resource=resource,
        )

    async def _enforce_policy(
        self,
        context: ControlPlaneServiceAccountApiContext,
        exact: ControlPlaneServiceAccountAuthorization,
    ) -> PolicyDecision:
        request = PolicyRequest(
            action=exact.action,
            resource=exact.resource,
            context=context.security_context,
        )

        try:
            return await self._engine.enforce(request)
        except (
            PolicyDeniedError,
            PolicyConfirmationRequiredError,
        ):
            raise (
                ControlPlaneServiceAccountPermissionDeniedError(
                    "service-account authorization denied"
                )
            ) from None


def _security_attributes(
    authentication: ControlPlaneServiceAccountAuthentication,
) -> dict[str, str]:
    return {
        "service_account_id": str(authentication.service_account_id),
        "token_id": str(authentication.token_id),
        "token_version": str(authentication.token_version),
        "account_revision": str(authentication.account_revision),
        "token_revision": str(authentication.token_revision),
        "restriction_applied": ("true" if authentication.restriction_applied else "false"),
        "authentication_schema_version": str(authentication.schema_version),
    }


def _normalize_correlation_id(
    value: str | None,
) -> str | None:
    if value is None:
        return None

    if not isinstance(value, str):
        raise TypeError("service-account correlation id must be str")

    normalized = value.strip()

    if (
        not normalized
        or normalized != value
        or len(normalized) > _MAX_CORRELATION_ID_LENGTH
        or any(ord(character) < 32 or ord(character) == 127 for character in normalized)
    ):
        raise ValueError("service-account correlation id is invalid")

    return normalized
