"""Adapters that propagate authenticated sessions across Phoenix boundaries."""

from __future__ import annotations

from dataclasses import replace

from phoenix_os.capabilities import CapabilityContext
from phoenix_os.configuration.contracts import SecretValue
from phoenix_os.identity.context import session_scope
from phoenix_os.identity.contracts import Session
from phoenix_os.identity.manager import AuthenticationManager
from phoenix_os.kernel import Kernel, Request, Response
from phoenix_os.state import StateOperationContext


def capability_context_from_session(
    session: Session,
    *,
    request: Request | None = None,
) -> CapabilityContext:
    """Create a trusted CapabilityContext from an authenticated session."""

    correlation_id = None if request is None else request.correlation_id
    request_id = None if request is None else request.id
    confirmed = False if request is None else request.confirmed
    identity = session.identity
    metadata = dict(identity.attributes)
    metadata.update(
        {
            "authenticated": "true",
            "principal_type": identity.principal_type.value,
            "provider": identity.provider,
            "roles": ",".join(sorted(identity.roles)),
            "scopes": ",".join(sorted(identity.scopes)),
            "session_id": str(session.id),
        }
    )
    return CapabilityContext(
        principal=identity.subject,
        request_id=request_id,
        correlation_id=correlation_id,
        confirmed=confirmed,
        permissions=identity.permissions,
        metadata=metadata,
    )


def state_context_from_session(
    session: Session,
    *,
    request: Request | None = None,
) -> StateOperationContext:
    """Create StateOperationContext metadata understood by PolicyStateStore."""

    identity = session.identity
    metadata = dict(identity.attributes)
    metadata.update(
        {
            "principal": identity.subject,
            "principal_type": identity.principal_type.value,
            "authenticated": "true",
            "roles": ",".join(sorted(identity.roles)),
            "permissions": ",".join(sorted(identity.permissions)),
            "scopes": ",".join(sorted(identity.scopes)),
            "session_id": str(session.id),
            "confirmed": str(False if request is None else request.confirmed).lower(),
        }
    )
    return StateOperationContext(
        correlation_id=None if request is None else request.correlation_id,
        causation_id=None if request is None else request.id,
        metadata=metadata,
    )


class AuthenticatedKernel:
    """Resolve a session before forwarding a request to the headless Kernel."""

    def __init__(self, kernel: Kernel, identity: AuthenticationManager) -> None:
        self._kernel = kernel
        self._identity = identity

    async def handle(
        self,
        request: Request,
        *,
        token: SecretValue | str,
        deadline: float | None = None,
    ) -> Response:
        session = await self._identity.resolve(
            token,
            correlation_id=request.correlation_id,
            causation_id=request.id,
        )
        authenticated = replace(request, principal=session.identity.subject)
        with session_scope(
            session,
            correlation_id=request.correlation_id,
            causation_id=request.id,
            confirmed=request.confirmed,
        ):
            return await self._kernel.handle(authenticated, deadline=deadline)
