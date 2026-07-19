"""Launch the local Phoenix dashboard with safe command permissions."""

from __future__ import annotations

import asyncio
import secrets
from datetime import UTC, datetime, timedelta

from phoenix_os import (
    AllowAllAuthorizer,
    CapabilityDescriptor,
    CapabilityInvocation,
    CapabilityRegistry,
    ConfigLoader,
    ConfigSchema,
    ControlPlaneHttpConfig,
    ControlPlaneOperatorToken,
    EventBus,
    InMemoryJobRepository,
    InMemoryWorkflowRepository,
    JobSchedule,
    JobScheduler,
    JobSpec,
    Kernel,
    MappingConfigSource,
    Router,
    RuntimeAssembler,
    WorkflowOrchestrator,
)


async def _preview(invocation: CapabilityInvocation) -> dict[str, object]:
    del invocation
    return {"previewed": True}


async def main() -> None:
    events = EventBus()
    capabilities = CapabilityRegistry(events=events)
    await capabilities.register(
        CapabilityDescriptor("dashboard.preview", "Dashboard preview task"),
        _preview,
    )
    jobs_repository = InMemoryJobRepository()
    jobs = JobScheduler(jobs_repository, capabilities, events=events)
    workflows = WorkflowOrchestrator(
        InMemoryWorkflowRepository(),
        jobs,
        events=events,
    )
    configuration = await ConfigLoader(
        ConfigSchema(()),
        (MappingConfigSource({}),),
    ).load()
    token = ControlPlaneOperatorToken(secrets.token_urlsafe(32))
    runtime = await RuntimeAssembler(
        kernel=Kernel(
            router=Router(),
            authorizer=AllowAllAuthorizer(),
            events=events,
        ),
        events=events,
        capabilities=capabilities,
        configuration=configuration,
        jobs=jobs,
        workflows=workflows,
        control_plane_operator_token=token,
        control_plane_operator_username="phoenix-maintainer",
        control_plane_operator_display_name="Phoenix Maintainer",
        control_plane_http_config=ControlPlaneHttpConfig(port=8765),
        control_plane_job_records=jobs_repository,
    ).assemble()

    await runtime.start()
    await jobs.schedule(
        JobSpec(
            capability="dashboard.preview",
            schedule=JobSchedule(datetime.now(UTC) + timedelta(minutes=10)),
        )
    )
    print("Phoenix OS dashboard: http://127.0.0.1:8765/dashboard/")
    print(f"Bootstrap Maintainer credential: {token.value}")
    try:
        await asyncio.to_thread(input, "Press Enter to stop Phoenix OS... ")
    finally:
        await runtime.stop()


if __name__ == "__main__":
    asyncio.run(main())
