"""Authenticate a user, issue a session, and propagate identity through the Kernel."""

from __future__ import annotations

import asyncio
import hmac

from phoenix_os import (
    AllowAllAuthorizer,
    AuthenticatedKernel,
    AuthenticationCredential,
    AuthenticationManager,
    AuthenticationRejectedError,
    CallableAuthenticationProvider,
    Identity,
    Request,
    Response,
    Router,
    SecretValue,
    current_security_context,
)
from phoenix_os.kernel import Kernel


async def verify_local_user(request: object) -> Identity:
    from phoenix_os import AuthenticationRequest

    authentication = request
    if not isinstance(authentication, AuthenticationRequest):
        raise TypeError("expected AuthenticationRequest")
    supplied = authentication.credential.secret.reveal(str)
    if not hmac.compare_digest(supplied, "phoenix-demo-password"):
        raise AuthenticationRejectedError("invalid credentials")
    return Identity(
        "arthur",
        display_name="João Arthur",
        roles=frozenset({"operator"}),
        permissions=frozenset({"profile.read"}),
        scopes=frozenset({"workspace"}),
    )


async def profile(request: Request) -> Response:
    security = current_security_context()
    return Response(
        200,
        {
            "principal": request.principal,
            "authenticated": security is not None and security.authenticated,
            "roles": [] if security is None else sorted(security.roles),
        },
    )


async def main() -> None:
    identity = AuthenticationManager(
        (("local", CallableAuthenticationProvider(verify_local_user)),)
    )
    grant = await identity.authenticate(
        "local",
        AuthenticationCredential(
            "password",
            SecretValue("phoenix-demo-password"),
            {"device": "desktop"},
        ),
        correlation_id="identity-example",
    )

    router = Router()
    router.add("profile.read", profile)
    kernel = AuthenticatedKernel(
        Kernel(router=router, authorizer=AllowAllAuthorizer()),
        identity,
    )
    response = await kernel.handle(
        Request("profile.read", correlation_id="identity-example"),
        token=grant.token,
    )
    print(dict(response.body))

    await identity.revoke_token(grant.token, reason="logout")
    await identity.close()


if __name__ == "__main__":
    asyncio.run(main())
