from __future__ import annotations

import pytest

from phoenix_os import (
    AllowAllAuthorizer,
    AuthenticatedKernel,
    AuthenticationCredential,
    AuthenticationManager,
    CallableAuthenticationProvider,
    Identity,
    Kernel,
    Request,
    Response,
    Router,
    SecretValue,
    SessionTokenInvalidError,
    capability_context_from_session,
    current_security_context,
    current_session,
    session_scope,
    state_context_from_session,
)


def identity() -> Identity:
    return Identity(
        "arthur",
        roles=frozenset({"admin"}),
        permissions=frozenset({"files.read", "state.read"}),
        scopes=frozenset({"workspace"}),
        attributes={"tenant": "phoenix"},
    )


@pytest.mark.asyncio
async def test_capability_context_from_session() -> None:
    manager = AuthenticationManager(
        (("local", CallableAuthenticationProvider(lambda request: identity())),),
        token_factory=lambda: "a" * 48,
    )
    grant = await manager.authenticate(
        "local", AuthenticationCredential("password", SecretValue("secret"))
    )
    request = Request("files.read", correlation_id="trace", confirmed=True)
    context = capability_context_from_session(grant.session, request=request)
    assert context.principal == "arthur"
    assert context.request_id == request.id
    assert context.correlation_id == "trace"
    assert context.confirmed
    assert context.permissions == frozenset({"files.read", "state.read"})
    assert context.metadata["roles"] == "admin"
    assert context.metadata["session_id"] == str(grant.session.id)


@pytest.mark.asyncio
async def test_state_context_from_session() -> None:
    manager = AuthenticationManager(
        (("local", CallableAuthenticationProvider(lambda request: identity())),),
        token_factory=lambda: "b" * 48,
    )
    grant = await manager.authenticate(
        "local", AuthenticationCredential("password", SecretValue("secret"))
    )
    request = Request("state.read", correlation_id="trace")
    context = state_context_from_session(grant.session, request=request)
    assert context.correlation_id == "trace"
    assert context.causation_id == request.id
    assert context.metadata["principal"] == "arthur"
    assert context.metadata["authenticated"] == "true"
    assert context.metadata["permissions"] == "files.read,state.read"


def test_session_scope_is_nested_and_restored() -> None:
    from datetime import UTC, datetime, timedelta
    from uuid import uuid4

    from phoenix_os import Session

    now = datetime.now(UTC)
    first = Session(uuid4(), identity(), now, now + timedelta(hours=1), now)
    second = Session(uuid4(), Identity("nova"), now, now + timedelta(hours=1), now)
    assert current_session() is None
    assert current_security_context() is None
    with session_scope(first) as first_context:
        assert current_session() is first
        assert current_security_context() is first_context
        with session_scope(second):
            assert current_session() is second
            security = current_security_context()
            assert security is not None
            assert security.principal == "nova"
        assert current_session() is first
    assert current_session() is None
    assert current_security_context() is None


@pytest.mark.asyncio
async def test_authenticated_kernel_propagates_identity_and_context() -> None:
    manager = AuthenticationManager(
        (("local", CallableAuthenticationProvider(lambda request: identity())),),
        token_factory=lambda: "c" * 48,
    )
    grant = await manager.authenticate(
        "local", AuthenticationCredential("password", SecretValue("secret"))
    )
    router = Router()

    async def handler(request: Request) -> Response:
        security = current_security_context()
        session = current_session()
        return Response(
            200,
            {
                "principal": request.principal,
                "security_principal": None if security is None else security.principal,
                "session_id": None if session is None else str(session.id),
            },
        )

    router.add("profile.read", handler)
    kernel = AuthenticatedKernel(
        Kernel(router=router, authorizer=AllowAllAuthorizer()),
        manager,
    )
    response = await kernel.handle(Request("profile.read"), token=grant.token)
    assert response.status == 200
    assert response.body["principal"] == "arthur"
    assert response.body["security_principal"] == "arthur"
    assert response.body["session_id"] == str(grant.session.id)
    assert current_session() is None


@pytest.mark.asyncio
async def test_authenticated_kernel_rejects_invalid_session_before_handler() -> None:
    called = False
    router = Router()

    async def handler(request: Request) -> Response:
        nonlocal called
        called = True
        return Response(200)

    router.add("profile.read", handler)
    wrapped = AuthenticatedKernel(
        Kernel(router=router, authorizer=AllowAllAuthorizer()),
        AuthenticationManager(),
    )
    with pytest.raises(SessionTokenInvalidError):
        await wrapped.handle(Request("profile.read"), token="invalid")
    assert not called
