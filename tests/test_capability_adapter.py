from collections.abc import Mapping

import pytest

from phoenix_os.capabilities import (
    CapabilityContext,
    CapabilityDescriptor,
    CapabilityHandler,
    CapabilityInvocation,
    CapabilityRegistry,
    request_context,
)
from phoenix_os.events import Event, EventBus
from phoenix_os.kernel import AllowAllAuthorizer, Kernel, Request, Router


def test_request_context_is_conservative_and_preserves_tracing() -> None:
    request = Request(
        action="files.read",
        principal="joao",
        correlation_id="corr-1",
        confirmed=True,
    )

    context = request_context(request)

    assert context.principal == "joao"
    assert context.request_id == request.id
    assert context.correlation_id == "corr-1"
    assert context.confirmed is True
    assert context.permissions == frozenset()


@pytest.mark.asyncio
async def test_handler_translates_success_to_kernel_response() -> None:
    registry = CapabilityRegistry()

    async def provider(invocation: CapabilityInvocation) -> Mapping[str, object]:
        return {"echo": invocation.arguments["value"]}

    await registry.register(CapabilityDescriptor("system.echo"), provider)
    handler = CapabilityHandler(registry, "system.echo", success_status=201)
    request = Request(action="echo", payload={"value": "ok"})

    response = await handler(request)

    assert response.status == 201
    assert response.body == {"echo": "ok"}
    assert response.request_id == request.id


@pytest.mark.asyncio
async def test_handler_translates_capability_error_to_safe_response() -> None:
    registry = CapabilityRegistry()
    handler = CapabilityHandler(registry, "missing")

    response = await handler(Request(action="missing"))

    assert response.status == 404
    assert response.body == {
        "error": "capability_not_found",
        "message": "capability not found: missing",
    }


@pytest.mark.asyncio
async def test_async_context_factory_can_supply_trusted_permissions() -> None:
    registry = CapabilityRegistry()

    async def provider(invocation: CapabilityInvocation) -> Mapping[str, object]:
        del invocation
        return {"content": "safe"}

    await registry.register(
        CapabilityDescriptor(
            "files.read",
            required_permissions=frozenset({"files.read"}),
        ),
        provider,
    )

    async def context_factory(request: Request) -> CapabilityContext:
        return CapabilityContext(
            principal=request.principal,
            request_id=request.id,
            permissions=frozenset({"files.read"}),
        )

    handler = CapabilityHandler(
        registry,
        "files.read",
        context_factory=context_factory,
    )

    response = await handler(Request(action="files.read", principal="joao"))

    assert response.status == 200
    assert response.body == {"content": "safe"}


@pytest.mark.asyncio
async def test_kernel_and_registry_integrate_without_kernel_dependency_on_provider() -> None:
    events = EventBus()
    observed: list[Event] = []

    async def observer(event: Event) -> None:
        observed.append(event)

    await events.subscribe("*", observer)
    registry = CapabilityRegistry(events=events)

    async def provider(invocation: CapabilityInvocation) -> Mapping[str, object]:
        return {"reply": invocation.arguments["message"]}

    await registry.register(CapabilityDescriptor("system.echo"), provider)
    router = Router()
    router.add("system.echo", CapabilityHandler(registry, "system.echo"))
    kernel = Kernel(router=router, authorizer=AllowAllAuthorizer(), events=events)
    request = Request(
        action="system.echo",
        payload={"message": "Phoenix"},
        correlation_id="corr-kernel",
    )

    response = await kernel.handle(request)

    assert response.status == 200
    assert response.body == {"reply": "Phoenix"}
    assert [event.name for event in observed] == [
        "kernel.request.received",
        "kernel.route.resolved",
        "kernel.handler.started",
        "capability.invocation.received",
        "capability.permission.allowed",
        "capability.invocation.started",
        "capability.invocation.completed",
        "kernel.request.completed",
    ]
    capability_events = [event for event in observed if event.name.startswith("capability.")]
    assert all(event.correlation_id == "corr-kernel" for event in capability_events)
    assert all(event.causation_id == request.id for event in capability_events)
