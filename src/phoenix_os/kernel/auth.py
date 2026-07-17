"""Reference authorizers."""

from phoenix_os.kernel.contracts import (
    AuthorizationDecision,
    AuthorizationStatus,
    Request,
    Route,
)


class AllowAllAuthorizer:
    async def authorize(self, request: Request, route: Route) -> AuthorizationDecision:
        del request, route
        return AuthorizationDecision(AuthorizationStatus.ALLOW)
