import pytest

from phoenix_os import (
    AllowAllAuthorizer,
    CapabilityRegistry,
    ConfigField,
    ConfigLoader,
    ConfigSchema,
    EventBus,
    Kernel,
    MappingConfigSource,
    Request,
    Response,
    Router,
    RuntimeAssembler,
    RuntimeState,
    ServiceDefinition,
    as_integer,
)
from phoenix_os.configuration import Configuration
from phoenix_os.runtime import RuntimeContext


async def echo(request: Request) -> Response:
    return Response(status=200, body={"action": request.action})


class Worker:
    def __init__(self, port: int, calls: list[str]) -> None:
        self.port = port
        self.calls = calls

    async def start(self, context: RuntimeContext) -> None:
        assert context.services["configuration"]
        self.calls.append(f"start:{self.port}")

    async def stop(self, context: RuntimeContext) -> None:
        del context
        self.calls.append(f"stop:{self.port}")


@pytest.mark.asyncio
async def test_runtime_assembler_exposes_configuration_and_composed_services() -> None:
    configuration = await ConfigLoader(
        ConfigSchema((ConfigField("worker.port", as_integer),)),
        (MappingConfigSource({"worker.port": 9000}),),
    ).load()
    calls: list[str] = []
    events = EventBus()
    router = Router()
    router.add("system.echo", echo)
    kernel = Kernel(router=router, authorizer=AllowAllAuthorizer(), events=events)
    capabilities = CapabilityRegistry(events=events)

    def worker_factory(resolver: object, config: Configuration) -> object:
        assert resolver.service("events") is events  # type: ignore[attr-defined]
        return Worker(config.value("worker.port", int), calls)

    runtime = await RuntimeAssembler(
        kernel=kernel,
        events=events,
        capabilities=capabilities,
        configuration=configuration,
        definitions=(ServiceDefinition("worker", worker_factory, lifecycle=True),),
        metadata={"environment": "test"},
    ).assemble()

    assert runtime.service("configuration") is configuration
    worker = runtime.service("worker")
    assert isinstance(worker, Worker)
    assert runtime.context.metadata == {"environment": "test"}

    await runtime.start()
    response = await runtime.handle(Request("system.echo"))
    await runtime.stop()

    assert response.status == 200
    assert calls == ["start:9000", "stop:9000"]
    assert runtime.state is RuntimeState.STOPPED


@pytest.mark.asyncio
async def test_runtime_assembler_exposes_policy_engine_as_lifecycle_service() -> None:
    from phoenix_os import PolicyEffect, PolicyEngine, PolicyRequest, PolicyRule

    configuration = await ConfigLoader(ConfigSchema(()), (MappingConfigSource({}),)).load()
    events = EventBus()
    router = Router()
    router.add("system.echo", echo)
    kernel = Kernel(router=router, authorizer=AllowAllAuthorizer(), events=events)
    capabilities = CapabilityRegistry(events=events)
    policy = PolicyEngine((PolicyRule("allow", PolicyEffect.ALLOW),), events=events)

    runtime = await RuntimeAssembler(
        kernel=kernel,
        events=events,
        capabilities=capabilities,
        configuration=configuration,
        policy=policy,
    ).assemble()

    assert runtime.service("policy") is policy
    await runtime.start()
    decision = await policy.evaluate(PolicyRequest("runtime.read", "runtime:self"))
    assert decision.effect is PolicyEffect.ALLOW
    await runtime.stop()
    assert policy.closed
