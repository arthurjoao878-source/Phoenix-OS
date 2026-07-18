"""Schedule and recover one durable capability-backed Phoenix job."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

from phoenix_os import (
    CapabilityDescriptor,
    CapabilityInvocation,
    CapabilityRegistry,
    JobSchedule,
    JobScheduler,
    JobSpec,
    MemoryStateStore,
    StateJobRepository,
)


async def main() -> None:
    capabilities = CapabilityRegistry()

    def generate_report(invocation: CapabilityInvocation) -> dict[str, object]:
        return {"generated": invocation.arguments["report_id"]}

    await capabilities.register(
        CapabilityDescriptor("report.generate"),
        generate_report,
    )
    store = MemoryStateStore()
    repository = StateJobRepository(store)
    scheduler = JobScheduler(repository, capabilities)
    now = datetime.now(UTC)
    job = await scheduler.schedule(
        JobSpec(
            capability="report.generate",
            schedule=JobSchedule(now),
            arguments={"report_id": "daily"},
        ),
        now=now,
    )
    runs = await scheduler.run_due(now=now)
    loaded = await scheduler.get(job.id)

    print("runs:", len(runs))
    print("status:", None if loaded is None else loaded.status.value)
    print("output:", None if loaded is None else dict(loaded.output))


if __name__ == "__main__":
    asyncio.run(main())
