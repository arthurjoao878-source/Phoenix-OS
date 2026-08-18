import asyncio

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
from phoenix_os.configuration.dependencies import _HostAutomationLifecycle
from phoenix_os.host_automation import (
    DeterministicHostAutomationAdapter,
    HostAutomationAdministration,
    HostAutomationObservabilityConfiguration,
    HostAutomationService,
    HostAutomationServiceUnavailableError,
    HostProcessListRequest,
    HostProcessListResult,
)
from phoenix_os.policy import PrincipalType, SecurityContext
from phoenix_os.runtime import ComponentSpec, PhoenixRuntime, RuntimeContext


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


@pytest.mark.asyncio
async def test_runtime_assembler_exposes_identity_manager_as_lifecycle_service() -> None:
    from phoenix_os import AuthenticationManager

    configuration = await ConfigLoader(ConfigSchema(()), (MappingConfigSource({}),)).load()
    events = EventBus()
    router = Router()
    router.add("system.echo", echo)
    kernel = Kernel(router=router, authorizer=AllowAllAuthorizer(), events=events)
    capabilities = CapabilityRegistry(events=events)
    identity = AuthenticationManager(events=events)

    runtime = await RuntimeAssembler(
        kernel=kernel,
        events=events,
        capabilities=capabilities,
        configuration=configuration,
        identity=identity,
    ).assemble()

    assert runtime.service("identity") is identity
    await runtime.start()
    assert not identity.closed
    await runtime.stop()
    assert identity.closed


@pytest.mark.asyncio
async def test_runtime_assembler_leaves_host_namespace_untouched_when_host_is_omitted() -> None:
    configuration = await ConfigLoader(ConfigSchema(()), (MappingConfigSource({}),)).load()
    events = EventBus()
    router = Router()
    router.add("system.echo", echo)
    kernel = Kernel(router=router, authorizer=AllowAllAuthorizer(), events=events)
    capabilities = CapabilityRegistry(events=events)
    marker = object()

    runtime = await RuntimeAssembler(
        kernel=kernel,
        events=events,
        capabilities=capabilities,
        configuration=configuration,
        definitions=(ServiceDefinition("host", lambda _resolver, _config: marker),),
    ).assemble()

    assert runtime.service("host") is marker
    await runtime.start()
    await runtime.stop()
    assert runtime.state is RuntimeState.STOPPED


@pytest.mark.asyncio
async def test_runtime_assembler_owns_configured_host_service_and_adapter_shutdown() -> None:
    from phoenix_os import PolicyEffect, PolicyEngine, PolicyRule

    configuration = await ConfigLoader(ConfigSchema(()), (MappingConfigSource({}),)).load()
    events = EventBus()
    router = Router()
    router.add("system.echo", echo)
    kernel = Kernel(router=router, authorizer=AllowAllAuthorizer(), events=events)
    capabilities = CapabilityRegistry(events=events)
    policy = PolicyEngine((PolicyRule("allow", PolicyEffect.ALLOW),), events=events)
    adapter = DeterministicHostAutomationAdapter(host_id="desktop")

    runtime = await RuntimeAssembler(
        kernel=kernel,
        events=events,
        capabilities=capabilities,
        configuration=configuration,
        policy=policy,
        host_automation_adapter=adapter,
    ).assemble()

    service = runtime.service("host")
    administration = runtime.service("host.administration")
    assert isinstance(service, HostAutomationService)
    assert isinstance(administration, HostAutomationAdministration)
    assert runtime.service("host.health") is administration
    assert not service.closed
    assert not adapter.closed
    before_start = await service.snapshot()
    assert not before_start.closed
    assert not before_start.available
    with pytest.raises(HostAutomationServiceUnavailableError):
        await service.list_processes(
            HostProcessListRequest(host_id=adapter.host_id),
            SecurityContext(
                principal="service:runtime-test",
                principal_type=PrincipalType.SERVICE,
                authenticated=True,
            ),
        )

    await runtime.start()
    assert (await service.snapshot()).available

    await runtime.stop()

    assert service.closed
    assert adapter.closed
    assert not (await service.snapshot()).available
    assert runtime.state is RuntimeState.STOPPED


def _assert_runtime_state(
    runtime: PhoenixRuntime,
    expected: RuntimeState,
) -> None:
    assert runtime.state is expected


class _BlockingHostAutomationAdapter(DeterministicHostAutomationAdapter):
    def __init__(self) -> None:
        super().__init__(host_id="desktop")
        self.operation_started = asyncio.Event()
        self.release_operation = asyncio.Event()

    async def list_processes(
        self,
        request: HostProcessListRequest,
    ) -> HostProcessListResult:
        self.operation_started.set()
        await self.release_operation.wait()
        return await super().list_processes(request)


class _BlockingRuntimeComponent:
    def __init__(self) -> None:
        self.starting = asyncio.Event()
        self.release_start = asyncio.Event()
        self.stopping = asyncio.Event()
        self.release_stop = asyncio.Event()

    async def start(self, context: RuntimeContext) -> None:
        del context
        self.starting.set()
        await self.release_start.wait()

    async def stop(self, context: RuntimeContext) -> None:
        del context
        self.stopping.set()
        await self.release_stop.wait()


@pytest.mark.asyncio
async def test_host_lifecycle_availability_tracks_runtime_running_state() -> None:
    from phoenix_os import PolicyEngine
    from phoenix_os.host_automation import PolicyEngineHostAutomationAuthorizer

    events = EventBus()
    kernel = Kernel(router=Router(), authorizer=AllowAllAuthorizer(), events=events)
    capabilities = CapabilityRegistry(events=events)
    adapter = DeterministicHostAutomationAdapter(host_id="desktop")
    service = HostAutomationService(
        adapter=adapter,
        authorizer=PolicyEngineHostAutomationAuthorizer(PolicyEngine()),
    )
    blocker = _BlockingRuntimeComponent()
    runtime = PhoenixRuntime(
        kernel=kernel,
        events=events,
        capabilities=capabilities,
        components=(
            ComponentSpec("host", _HostAutomationLifecycle(service)),
            ComponentSpec("blocker", blocker),
        ),
        services={"host": service},
    )

    start_task = asyncio.create_task(runtime.start())
    await blocker.starting.wait()

    _assert_runtime_state(runtime, RuntimeState.STARTING)
    assert not (await service.snapshot()).available
    with pytest.raises(HostAutomationServiceUnavailableError):
        await service.list_processes(
            HostProcessListRequest(host_id=adapter.host_id),
            SecurityContext(
                principal="service:runtime-test",
                principal_type=PrincipalType.SERVICE,
                authenticated=True,
            ),
        )

    blocker.release_start.set()
    await start_task

    _assert_runtime_state(runtime, RuntimeState.RUNNING)
    assert (await service.snapshot()).available

    stop_task = asyncio.create_task(runtime.stop())
    await blocker.stopping.wait()

    _assert_runtime_state(runtime, RuntimeState.STOPPING)
    assert not service.closed
    assert not adapter.closed
    assert not (await service.snapshot()).available
    with pytest.raises(HostAutomationServiceUnavailableError):
        await service.list_processes(
            HostProcessListRequest(host_id=adapter.host_id),
            SecurityContext(
                principal="service:runtime-test",
                principal_type=PrincipalType.SERVICE,
                authenticated=True,
            ),
        )

    blocker.release_stop.set()
    await stop_task

    _assert_runtime_state(runtime, RuntimeState.STOPPED)
    assert service.closed
    assert adapter.closed
    assert not (await service.snapshot()).available


@pytest.mark.asyncio
async def test_host_lifecycle_drains_in_flight_operation_before_adapter_shutdown() -> None:
    from phoenix_os import PolicyEffect, PolicyEngine, PolicyRule
    from phoenix_os.host_automation import PolicyEngineHostAutomationAuthorizer

    events = EventBus()
    kernel = Kernel(router=Router(), authorizer=AllowAllAuthorizer(), events=events)
    capabilities = CapabilityRegistry(events=events)
    adapter = _BlockingHostAutomationAdapter()
    policy = PolicyEngine((PolicyRule("allow", PolicyEffect.ALLOW),), events=events)
    service = HostAutomationService(
        adapter=adapter,
        authorizer=PolicyEngineHostAutomationAuthorizer(policy),
    )
    runtime = PhoenixRuntime(
        kernel=kernel,
        events=events,
        capabilities=capabilities,
        components=(ComponentSpec("host", _HostAutomationLifecycle(service)),),
        services={"host": service},
    )

    await runtime.start()

    operation_task = asyncio.create_task(
        service.list_processes(
            HostProcessListRequest(host_id=adapter.host_id),
            SecurityContext(
                principal="service:runtime-test",
                principal_type=PrincipalType.SERVICE,
                authenticated=True,
            ),
        )
    )
    await adapter.operation_started.wait()

    stop_task = asyncio.create_task(runtime.stop())
    for _ in range(100):
        if runtime.state is RuntimeState.STOPPING:
            break
        await asyncio.sleep(0)

    _assert_runtime_state(runtime, RuntimeState.STOPPING)
    assert not stop_task.done()
    assert not adapter.closed
    assert not (await service.snapshot()).available

    adapter.release_operation.set()
    result = await operation_task
    assert result.host_id == adapter.host_id
    await stop_task

    _assert_runtime_state(runtime, RuntimeState.STOPPED)
    assert service.closed
    assert adapter.closed


@pytest.mark.asyncio
async def test_host_lifecycle_shutdown_is_retryable_after_cancellation() -> None:
    from phoenix_os import PolicyEffect, PolicyEngine, PolicyRule
    from phoenix_os.host_automation import PolicyEngineHostAutomationAuthorizer

    events = EventBus()
    kernel = Kernel(router=Router(), authorizer=AllowAllAuthorizer(), events=events)
    capabilities = CapabilityRegistry(events=events)
    adapter = _BlockingHostAutomationAdapter()
    policy = PolicyEngine((PolicyRule("allow", PolicyEffect.ALLOW),), events=events)
    service = HostAutomationService(
        adapter=adapter,
        authorizer=PolicyEngineHostAutomationAuthorizer(policy),
    )
    runtime = PhoenixRuntime(
        kernel=kernel,
        events=events,
        capabilities=capabilities,
        components=(ComponentSpec("host", _HostAutomationLifecycle(service)),),
        services={"host": service},
    )

    await runtime.start()

    operation_task = asyncio.create_task(
        service.list_processes(
            HostProcessListRequest(host_id=adapter.host_id),
            SecurityContext(
                principal="service:runtime-test",
                principal_type=PrincipalType.SERVICE,
                authenticated=True,
            ),
        )
    )
    await adapter.operation_started.wait()

    stop_task = asyncio.create_task(runtime.stop())
    for _ in range(100):
        if service._closing:
            break
        await asyncio.sleep(0)

    assert service._closing
    _assert_runtime_state(runtime, RuntimeState.STOPPING)
    assert not service.closed
    assert not adapter.closed

    stop_task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await stop_task

    _assert_runtime_state(runtime, RuntimeState.FAILED)
    assert not service.closed
    assert not adapter.closed
    assert not (await service.snapshot()).available

    adapter.release_operation.set()
    result = await operation_task
    assert result.host_id == adapter.host_id

    await runtime.stop()

    _assert_runtime_state(runtime, RuntimeState.STOPPED)
    assert service.closed
    assert adapter.closed
    assert not (await service.snapshot()).available


@pytest.mark.asyncio
async def test_runtime_assembler_host_options_require_an_explicit_adapter() -> None:
    configuration = await ConfigLoader(ConfigSchema(()), (MappingConfigSource({}),)).load()
    events = EventBus()
    kernel = Kernel(router=Router(), authorizer=AllowAllAuthorizer(), events=events)
    capabilities = CapabilityRegistry(events=events)

    with pytest.raises(ValueError, match="host automation options require an adapter"):
        RuntimeAssembler(
            kernel=kernel,
            events=events,
            capabilities=capabilities,
            configuration=configuration,
            host_automation_observability_configuration=(
                HostAutomationObservabilityConfiguration()
            ),
        )


@pytest.mark.asyncio
async def test_runtime_assembler_configured_host_requires_policy_and_owns_namespace() -> None:
    from phoenix_os import PolicyEffect, PolicyEngine, PolicyRule

    configuration = await ConfigLoader(ConfigSchema(()), (MappingConfigSource({}),)).load()
    events = EventBus()
    kernel = Kernel(router=Router(), authorizer=AllowAllAuthorizer(), events=events)
    capabilities = CapabilityRegistry(events=events)
    adapter = DeterministicHostAutomationAdapter(host_id="desktop")

    with pytest.raises(
        ValueError,
        match="configured host automation requires a PolicyEngine",
    ):
        RuntimeAssembler(
            kernel=kernel,
            events=events,
            capabilities=capabilities,
            configuration=configuration,
            host_automation_adapter=adapter,
        )

    policy = PolicyEngine((PolicyRule("allow", PolicyEffect.ALLOW),), events=events)
    with pytest.raises(
        ValueError,
        match="host automation services conflict with definitions: host",
    ):
        RuntimeAssembler(
            kernel=kernel,
            events=events,
            capabilities=capabilities,
            configuration=configuration,
            policy=policy,
            host_automation_adapter=adapter,
            definitions=(ServiceDefinition("host", lambda _resolver, _config: object()),),
        )
