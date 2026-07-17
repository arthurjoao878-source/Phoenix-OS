"""Run with: python examples/event_bus.py"""

import asyncio

from phoenix_os.events import Event, EventBus


async def main() -> None:
    bus = EventBus()

    async def audit(event: Event) -> None:
        print(f"audit: {event.name} from {event.source}: {dict(event.payload)}")

    await bus.subscribe("*", audit, priority=100)
    report = await bus.emit(
        "demo.started",
        source="examples.event_bus",
        payload={"version": "0.5.0"},
    )
    print(f"delivered={report.delivered} succeeded={report.succeeded}")
    await bus.close()


if __name__ == "__main__":
    asyncio.run(main())
