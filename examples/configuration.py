"""Run with: python examples/configuration.py"""

import asyncio

from phoenix_os import (
    AllowAllAuthorizer,
    CapabilityRegistry,
    ConfigField,
    ConfigLoader,
    ConfigSchema,
    EnvironmentConfigSource,
    EventBus,
    Kernel,
    MappingConfigSource,
    Request,
    Response,
    Router,
    RuntimeAssembler,
    ServiceDefinition,
    as_boolean,
    as_integer,
    as_string,
    positive,
)
from phoenix_os.configuration import Configuration
from phoenix_os.runtime import RuntimeContext


class DemoWorker:
    def __init__(self, port: int) -> None:
        self._port = port

    async def start(self, context: RuntimeContext) -> None:
        environment = context.services["configuration"]
        assert isinstance(environment, Configuration)
        print("worker started", self._port, environment.value("runtime.debug", bool))

    async def stop(self, context: RuntimeContext) -> None:
        del context
        print("worker stopped")


async def main() -> None:
    schema = ConfigSchema(
        (
            ConfigField("runtime.port", as_integer, default=8080, validator=positive),
            ConfigField("runtime.debug", as_boolean, default=False),
            ConfigField("auth.token", as_string, secret=True),
        )
    )
    configuration = await ConfigLoader(
        schema,
        (
            MappingConfigSource({"auth.token": "example-secret"}, name="defaults"),
            EnvironmentConfigSource(environ={"PHOENIX_RUNTIME__PORT": "9000"}),
        ),
    ).load()

    events = EventBus()
    router = Router()

    async def status(request: Request) -> Response:
        del request
        return Response(status=200, body=configuration.as_dict())

    router.add("system.status", status)
    kernel = Kernel(router=router, authorizer=AllowAllAuthorizer(), events=events)
    capabilities = CapabilityRegistry(events=events)

    def worker_factory(resolver: object, config: Configuration) -> object:
        del resolver
        return DemoWorker(config.value("runtime.port", int))

    runtime = await RuntimeAssembler(
        kernel=kernel,
        events=events,
        capabilities=capabilities,
        configuration=configuration,
        definitions=(ServiceDefinition("demo.worker", worker_factory, lifecycle=True),),
    ).assemble()

    print("redacted configuration:", dict(configuration.as_dict()))
    async with runtime:
        response = await runtime.handle(Request("system.status"))
        print(response.status, dict(response.body))


if __name__ == "__main__":
    asyncio.run(main())
