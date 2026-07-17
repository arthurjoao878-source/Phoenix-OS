import asyncio
from collections.abc import Mapping

from phoenix_os import (
    AllowAllAuthorizer,
    CapabilityContext,
    CapabilityDescriptor,
    CapabilityHandler,
    CapabilityInvocation,
    CapabilityRegistry,
    Kernel,
    Request,
    Router,
)


async def main() -> None:
    registry = CapabilityRegistry()

    async def echo(invocation: CapabilityInvocation) -> Mapping[str, object]:
        return {"reply": invocation.arguments.get("message", "")}

    await registry.register(
        CapabilityDescriptor(
            name="system.echo",
            description="Return the supplied message.",
        ),
        echo,
    )

    async def trusted_context(request: Request) -> CapabilityContext:
        return CapabilityContext(
            principal=request.principal,
            request_id=request.id,
            correlation_id=request.correlation_id,
            confirmed=request.confirmed,
        )

    router = Router()
    router.add(
        "system.echo",
        CapabilityHandler(
            registry,
            "system.echo",
            context_factory=trusted_context,
        ),
    )
    kernel = Kernel(router=router, authorizer=AllowAllAuthorizer())
    response = await kernel.handle(
        Request(
            action="system.echo",
            payload={"message": "Phoenix online"},
            principal="joao",
        )
    )
    print(response.status, dict(response.body))


if __name__ == "__main__":
    asyncio.run(main())
