"""Execute and recover one durable capability-backed Phoenix workflow graph."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

from phoenix_os import (
    CapabilityDescriptor,
    CapabilityInvocation,
    CapabilityRegistry,
    JobScheduler,
    MemoryStateStore,
    StateJobRepository,
    StateWorkflowRepository,
    WorkflowDefinition,
    WorkflowOrchestrator,
    WorkflowStep,
)


async def main() -> None:
    capabilities = CapabilityRegistry()

    def execute(invocation: CapabilityInvocation) -> dict[str, object]:
        return {"completed": invocation.capability}

    for name in ("release.prepare", "release.test", "release.package", "release.publish"):
        await capabilities.register(CapabilityDescriptor(name), execute)

    store = MemoryStateStore()
    jobs = JobScheduler(StateJobRepository(store, namespace="workflow-jobs"), capabilities)
    workflows = WorkflowOrchestrator(
        StateWorkflowRepository(store),
        jobs,
    )
    definition = WorkflowDefinition(
        "release",
        (
            WorkflowStep("prepare", "release.prepare"),
            WorkflowStep(
                "test",
                "release.test",
                dependencies=frozenset({"prepare"}),
            ),
            WorkflowStep(
                "package",
                "release.package",
                dependencies=frozenset({"prepare"}),
            ),
            WorkflowStep(
                "publish",
                "release.publish",
                dependencies=frozenset({"test", "package"}),
            ),
        ),
    )
    now = datetime.now(UTC)
    workflow = await workflows.start(definition, now=now)

    for offset in range(4):
        tick = now + timedelta(seconds=offset)
        await jobs.run_due(now=tick)
        workflow = await workflows.advance(workflow.id, now=tick)

    print("status:", workflow.status.value)
    print("revision:", workflow.revision)
    print("steps:", {name: step.status.value for name, step in workflow.steps.items()})


if __name__ == "__main__":
    asyncio.run(main())
