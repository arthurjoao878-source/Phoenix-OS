"""Run with: python examples/kernel.py"""

import asyncio

from phoenix_os import AllowAllAuthorizer, Event, EventBus, Kernel, Request, Response, Router


async def main() -> None:
    events = EventBus()
    router = Router()

    async def observe(event: Event) -> None:
        print(event.name, dict(event.payload))

    async def ping(request: Request) -> Response:
        return Response(status=200, body={"reply": "pong", "principal": request.principal})

    await events.subscribe("*", observe)
    router.add("system.ping", ping)
    kernel = Kernel(router=router, authorizer=AllowAllAuthorizer(), events=events)

    response = await kernel.handle(
        Request(action="system.ping", principal="example", correlation_id="demo-1")
    )
    print(response.status, dict(response.body))


if __name__ == "__main__":
    asyncio.run(main())
