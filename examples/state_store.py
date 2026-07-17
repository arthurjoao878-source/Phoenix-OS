"""Run with: python examples/state_store.py"""

import asyncio
from datetime import timedelta

from phoenix_os import (
    ABSENT_VERSION,
    EventBus,
    InMemorySink,
    MemoryStateStore,
    ObservabilityHub,
    RestoreMode,
    StateKey,
    StateOperationContext,
)


async def main() -> None:
    events = EventBus()
    diagnostics = InMemorySink(capacity=200)
    observability = ObservabilityHub((diagnostics,))
    store = MemoryStateStore(events=events, observability=observability)
    profile = StateKey("profile", "arthur", dict)
    context = StateOperationContext(
        correlation_id="example-state",
        metadata={"environment": "demo"},
    )

    created = await store.put(
        profile,
        {"level": 1, "roles": ["operator"]},
        expected_version=ABSENT_VERSION,
        ttl=timedelta(minutes=30),
        context=context,
    )

    async with store.transaction(context=context) as transaction:
        await transaction.put(
            profile,
            {"level": 2, "roles": ["operator", "maintainer"]},
            expected_version=created.version,
            ttl=timedelta(minutes=30),
        )
        await transaction.put(StateKey("session", "active", bool), True)

    snapshot = await store.snapshot(context=context)
    restored = MemoryStateStore(events=events, observability=observability)
    await restored.restore(snapshot, mode=RestoreMode.REPLACE, context=context)

    record = await restored.get(profile, context=context)
    print("profile:", record.value if record is not None else None)
    print("version:", record.version if record is not None else None)
    print("snapshot records:", len(snapshot.records))
    print("diagnostic records:", len((await diagnostics.snapshot()).records))

    await store.close()
    await restored.close()
    await observability.close()
    await events.close()


if __name__ == "__main__":
    asyncio.run(main())
