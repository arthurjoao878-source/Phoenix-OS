"""Run with: python examples/runtime.py"""

import asyncio

from phoenix_os import (
    AllowAllAuthorizer,
    CapabilityRegistry,
    ComponentSpec,
    Event,
    EventBus,
    HookComponent,
    Kernel,
    PhoenixRuntime,
    Request,
    Response,
    Router,
    RuntimeContext,
)


async def main() -> None:
    events = EventBus()
    router = Router()
    capabilities = CapabilityRegistry(events=events)

    async def observe(event: Event) -> None:
        if event.name.startswith("runtime."):
            print(event.name, dict(event.payload))

    async def ping(request: Request) -> Response:
        return Response(status=200, body={"reply": "pong", "principal": request.principal})

    async def start_adapter(context: RuntimeContext) -> None:
        print("adapter started with services:", tuple(context.services))

    async def stop_adapter(context: RuntimeContext) -> None:
        del context
        print("adapter stopped")

    await events.subscribe("*", observe)
    router.add("system.ping", ping)
    kernel = Kernel(router=router, authorizer=AllowAllAuthorizer(), events=events)
    runtime = PhoenixRuntime(
        kernel=kernel,
        events=events,
        capabilities=capabilities,
        components=(
            ComponentSpec(
                "example.adapter",
                HookComponent(start=start_adapter, stop=stop_adapter),
            ),
        ),
        services={"configuration": {"environment": "example"}},
    )

    async with runtime:
        response = await runtime.handle(
            Request(action="system.ping", principal="example", correlation_id="runtime-demo")
        )
        print(response.status, dict(response.body))


if __name__ == "__main__":
    asyncio.run(main())
