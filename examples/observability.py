"""Run with: python examples/observability.py"""

import asyncio

from phoenix_os import (
    AllowAllAuthorizer,
    CapabilityRegistry,
    Configuration,
    EventBus,
    InMemorySink,
    Kernel,
    MetricKind,
    ObservabilityHub,
    Router,
    RuntimeAssembler,
    Severity,
    SpanRecord,
)


async def main() -> None:
    events = EventBus()
    sink = InMemorySink(capacity=100)
    observability = ObservabilityHub((sink,))
    router = Router()
    kernel = Kernel(router=router, authorizer=AllowAllAuthorizer(), events=events)
    capabilities = CapabilityRegistry(events=events)
    configuration = Configuration(values={}, origins={})

    runtime = await RuntimeAssembler(
        kernel=kernel,
        events=events,
        capabilities=capabilities,
        configuration=configuration,
        observability=observability,
    ).assemble()

    async with runtime:
        async with observability.span(
            "demo.operation",
            source="examples.observability",
            attributes={"password": "redacted", "mode": "demo"},
        ):
            await observability.log(
                "demo.ready",
                source="examples.observability",
                message="demo operation is running",
                severity=Severity.INFO,
            )
            await observability.metric(
                "demo.operations",
                1,
                source="examples.observability",
                kind=MetricKind.COUNTER,
                unit="operation",
            )
            await events.emit(
                "demo.event.completed",
                source="examples.observability",
                payload={"api_key": "redacted", "result": "ok"},
            )

    snapshot = await sink.snapshot()
    print("records:", len(snapshot.records), "dropped:", snapshot.dropped)
    for record in snapshot.records:
        if isinstance(record, SpanRecord):
            print(record.name, record.status, f"{record.duration_seconds:.6f}s")
        else:
            print(record.name, dict(record.attributes))


if __name__ == "__main__":
    asyncio.run(main())
