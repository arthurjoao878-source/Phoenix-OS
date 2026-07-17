import asyncio

import pytest

from phoenix_os.events import Event, EventBus
from phoenix_os.kernel import (
    AllowAllAuthorizer,
    AuthorizationDecision,
    AuthorizationStatus,
    Kernel,
    Request,
    Response,
    Route,
    Router,
)


class DenyAuthorizer:
    async def authorize(self, request: Request, route: Route) -> AuthorizationDecision:
        del request, route
        return AuthorizationDecision(AuthorizationStatus.DENY, "not permitted")


class ConfirmAuthorizer:
    async def authorize(self, request: Request, route: Route) -> AuthorizationDecision:
        del request, route
        return AuthorizationDecision(AuthorizationStatus.CONFIRM, "confirm operation")


@pytest.mark.asyncio
async def test_kernel_handles_registered_route() -> None:
    router = Router()

    async def handler(request: Request) -> Response:
        return Response(status=200, body={"echo": request.payload["value"]})

    router.add("echo", handler)
    kernel = Kernel(router=router, authorizer=AllowAllAuthorizer())
    request = Request(action="echo", payload={"value": "ok"})

    response = await kernel.handle(request)

    assert response.status == 200
    assert response.body == {"echo": "ok"}
    assert response.request_id == request.id


@pytest.mark.asyncio
async def test_missing_route_becomes_safe_404() -> None:
    kernel = Kernel(router=Router(), authorizer=AllowAllAuthorizer())

    response = await kernel.handle(Request(action="missing"))

    assert response.status == 404
    assert response.body["error"] == "route_not_found"


@pytest.mark.asyncio
async def test_denied_request_becomes_safe_403() -> None:
    router = Router()

    async def handler(request: Request) -> Response:
        del request
        return Response(status=200)

    router.add("secret", handler)
    kernel = Kernel(router=router, authorizer=DenyAuthorizer())

    response = await kernel.handle(Request(action="secret"))

    assert response.status == 403
    assert response.body["error"] == "authorization_denied"


@pytest.mark.asyncio
async def test_confirmation_decision_requires_explicit_flag() -> None:
    router = Router()

    async def handler(request: Request) -> Response:
        del request
        return Response(status=204)

    router.add("change", handler)
    kernel = Kernel(router=router, authorizer=ConfirmAuthorizer())

    unconfirmed = await kernel.handle(Request(action="change"))
    confirmed = await kernel.handle(Request(action="change", confirmed=True))

    assert unconfirmed.status == 409
    assert unconfirmed.body["error"] == "confirmation_required"
    assert confirmed.status == 204


@pytest.mark.asyncio
async def test_sensitive_route_requires_confirmation_even_when_authorized() -> None:
    router = Router()

    async def handler(request: Request) -> Response:
        del request
        return Response(status=204)

    router.add("dangerous", handler, sensitive=True)
    kernel = Kernel(router=router, authorizer=AllowAllAuthorizer())

    response = await kernel.handle(Request(action="dangerous"))

    assert response.status == 409


@pytest.mark.asyncio
async def test_unexpected_exception_is_not_leaked() -> None:
    router = Router()

    async def handler(request: Request) -> Response:
        del request
        raise RuntimeError("secret path / credential")

    router.add("explode", handler)
    kernel = Kernel(router=router, authorizer=AllowAllAuthorizer())

    response = await kernel.handle(Request(action="explode"))

    assert response.status == 500
    assert response.body == {
        "error": "internal_error",
        "message": "internal request failure",
    }


@pytest.mark.asyncio
async def test_timeout_becomes_504() -> None:
    router = Router()

    async def handler(request: Request) -> Response:
        del request
        await asyncio.sleep(1)
        return Response(status=200)

    router.add("slow", handler)
    kernel = Kernel(router=router, authorizer=AllowAllAuthorizer())

    response = await kernel.handle(Request(action="slow"), deadline=0.001)

    assert response.status == 504
    assert response.body["error"] == "deadline_exceeded"


@pytest.mark.asyncio
async def test_caller_cancellation_propagates() -> None:
    router = Router()
    started = asyncio.Event()

    async def handler(request: Request) -> Response:
        del request
        started.set()
        await asyncio.sleep(10)
        return Response(status=200)

    router.add("wait", handler)
    kernel = Kernel(router=router, authorizer=AllowAllAuthorizer())
    task = asyncio.create_task(kernel.handle(Request(action="wait")))
    await started.wait()
    task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await task


@pytest.mark.asyncio
async def test_kernel_emits_lifecycle_events_with_correlation() -> None:
    events = EventBus()
    router = Router()
    observed: list[Event] = []

    async def observer(event: Event) -> None:
        observed.append(event)

    async def handler(request: Request) -> Response:
        del request
        return Response(status=201)

    await events.subscribe("*", observer)
    router.add("create", handler)
    kernel = Kernel(router=router, authorizer=AllowAllAuthorizer(), events=events)
    request = Request(action="create", principal="joao", correlation_id="corr-1")

    await kernel.handle(request)

    assert [event.name for event in observed] == [
        "kernel.request.received",
        "kernel.route.resolved",
        "kernel.handler.started",
        "kernel.request.completed",
    ]
    assert all(event.correlation_id == "corr-1" for event in observed)
    assert all(event.causation_id == request.id for event in observed)
    assert observed[-1].payload["status"] == 201


@pytest.mark.asyncio
async def test_kernel_event_handler_failure_does_not_break_request() -> None:
    events = EventBus()
    router = Router()

    async def broken_observer(event: Event) -> None:
        del event
        raise RuntimeError("observer failed")

    async def handler(request: Request) -> Response:
        del request
        return Response(status=200)

    await events.subscribe("*", broken_observer)
    router.add("ok", handler)
    kernel = Kernel(router=router, authorizer=AllowAllAuthorizer(), events=events)

    response = await kernel.handle(Request(action="ok"))

    assert response.status == 200
