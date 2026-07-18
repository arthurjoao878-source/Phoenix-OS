"""Durable job-backed orchestration for validated Phoenix workflow graphs."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from dataclasses import replace
from datetime import UTC, datetime
from uuid import UUID, uuid5

from phoenix_os.events import EventBus
from phoenix_os.jobs import (
    JobAlreadyExistsError,
    JobSchedule,
    JobScheduler,
    JobSpec,
    JobStatus,
)
from phoenix_os.workflows.contracts import (
    WorkflowDefinition,
    WorkflowId,
    WorkflowRecord,
    WorkflowRepository,
    WorkflowStatus,
    WorkflowStep,
    WorkflowStepRecord,
    WorkflowStepStatus,
)
from phoenix_os.workflows.errors import (
    WorkflowNotFoundError,
    WorkflowOrchestratorClosedError,
)
from phoenix_os.workflows.planner import WorkflowPlanner


class WorkflowOrchestrator:
    """Persist workflow state while delegating every runnable step to durable jobs."""

    def __init__(
        self,
        repository: WorkflowRepository,
        jobs: JobScheduler,
        *,
        planner: WorkflowPlanner | None = None,
        events: EventBus | None = None,
        source: str = "phoenix.workflows",
    ) -> None:
        normalized_source = source.strip()
        if not normalized_source:
            raise ValueError("source must not be blank")
        self._repository = repository
        self._jobs = jobs
        self._planner = planner or WorkflowPlanner()
        self._events = events
        self._source = normalized_source
        self._closed = False
        self._lock = asyncio.Lock()

    @property
    def closed(self) -> bool:
        return self._closed

    async def start(
        self,
        definition: WorkflowDefinition,
        *,
        workflow_id: WorkflowId | None = None,
        now: datetime | None = None,
    ) -> WorkflowRecord:
        """Persist a workflow instance and schedule its root fan-out deterministically."""

        self._ensure_open()
        started_at = _now(now)
        record = self._planner.instantiate(
            definition,
            workflow_id=workflow_id,
            now=started_at,
        )
        await self._repository.add(record)
        await self._emit("workflow.started", record)
        return await self.advance(record.id, now=started_at)

    async def get(self, workflow_id: WorkflowId) -> WorkflowRecord | None:
        self._ensure_open()
        return await self._repository.get(workflow_id)

    async def list_all(self) -> tuple[WorkflowRecord, ...]:
        self._ensure_open()
        return await self._repository.list_all()

    async def advance(
        self,
        workflow_id: WorkflowId,
        *,
        now: datetime | None = None,
    ) -> WorkflowRecord:
        """Reconcile durable jobs and release every newly satisfied dependency level."""

        self._ensure_open()
        advanced_at = _now(now)
        async with self._lock:
            self._ensure_open()
            current = await self._require(workflow_id)
            if current.status.terminal:
                return current

            steps = dict(current.steps)
            changed = current.status is WorkflowStatus.PENDING
            if changed:
                status = WorkflowStatus.RUNNING
            else:
                status = current.status

            reconciled, reconciled_changed = await self._reconcile_running(steps, advanced_at)
            steps = reconciled
            changed = changed or reconciled_changed

            terminal = await self._terminal_transition(current, steps, advanced_at)
            if terminal is not None:
                return await self._save(current, terminal)

            while True:
                released = self._release_dependencies(current, steps)
                if released:
                    changed = True

                scheduled, schedule_changed = await self._schedule_ready(
                    current,
                    steps,
                    advanced_at,
                )
                steps = scheduled
                changed = changed or schedule_changed

                terminal = await self._terminal_transition(current, steps, advanced_at)
                if terminal is not None:
                    return await self._save(current, terminal)

                # A recovered deterministic job may already be terminal. Loop once more so its
                # dependants are released without requiring a second recovery tick.
                if not released and not self._has_ready(steps):
                    break
                if not schedule_changed:
                    break
                if not any(item.status is WorkflowStepStatus.SUCCEEDED for item in steps.values()):
                    break

            if not changed:
                return current
            updated = replace(
                current,
                status=status,
                steps=steps,
                revision=current.revision + 1,
                updated_at=advanced_at,
            )
            return await self._save(current, updated)

    async def recover(self, *, now: datetime | None = None) -> tuple[WorkflowRecord, ...]:
        """Advance every non-terminal persisted workflow after process restart."""

        self._ensure_open()
        recovered_at = _now(now)
        records = await self._repository.list_all()
        recovered: list[WorkflowRecord] = []
        for record in records:
            if record.status.terminal:
                recovered.append(record)
            else:
                recovered.append(await self.advance(record.id, now=recovered_at))
        return tuple(recovered)

    async def cancel(
        self,
        workflow_id: WorkflowId,
        *,
        now: datetime | None = None,
    ) -> WorkflowRecord:
        """Cancel every outstanding step job and terminate the workflow."""

        self._ensure_open()
        cancelled_at = _now(now)
        async with self._lock:
            self._ensure_open()
            current = await self._require(workflow_id)
            if current.status.terminal:
                return current
            steps = dict(current.steps)
            await self._cancel_jobs(steps, cancelled_at)
            cancelled_steps = self._cancel_open_steps(steps, cancelled_at)
            cancelled = replace(
                current,
                status=WorkflowStatus.CANCELLED,
                steps=cancelled_steps,
                revision=current.revision + 1,
                updated_at=cancelled_at,
                finished_at=cancelled_at,
                error=None,
            )
            return await self._save(current, cancelled)

    async def close(self) -> None:
        """Close only this coordinator; repositories and schedulers remain externally owned."""

        async with self._lock:
            self._closed = True

    async def _reconcile_running(
        self,
        steps: dict[str, WorkflowStepRecord],
        now: datetime,
    ) -> tuple[dict[str, WorkflowStepRecord], bool]:
        changed = False
        for step_id, record in tuple(steps.items()):
            if record.status is not WorkflowStepStatus.RUNNING:
                continue
            if record.job_id is None:
                steps[step_id] = replace(
                    record,
                    status=WorkflowStepStatus.FAILED,
                    finished_at=now,
                    error="WorkflowJobMissing",
                )
                changed = True
                continue
            job = await self._jobs.get(record.job_id)
            if job is None:
                steps[step_id] = replace(
                    record,
                    status=WorkflowStepStatus.FAILED,
                    finished_at=now,
                    error="WorkflowJobMissing",
                )
                changed = True
                continue
            updated = _step_from_job(record, job.status, job.updated_at, job.output, job.error)
            if updated != record:
                steps[step_id] = updated
                changed = True
        return steps, changed

    def _release_dependencies(
        self,
        workflow: WorkflowRecord,
        steps: dict[str, WorkflowStepRecord],
    ) -> bool:
        changed = False
        for definition in workflow.definition.steps:
            record = steps[definition.id]
            if record.status is not WorkflowStepStatus.BLOCKED:
                continue
            if all(
                steps[dependency].status is WorkflowStepStatus.SUCCEEDED
                for dependency in definition.dependencies
            ):
                steps[definition.id] = WorkflowStepRecord(
                    step_id=definition.id,
                    status=WorkflowStepStatus.READY,
                )
                changed = True
        return changed

    async def _schedule_ready(
        self,
        workflow: WorkflowRecord,
        steps: dict[str, WorkflowStepRecord],
        now: datetime,
    ) -> tuple[dict[str, WorkflowStepRecord], bool]:
        changed = False
        for definition in workflow.definition.steps:
            record = steps[definition.id]
            if record.status is not WorkflowStepStatus.READY:
                continue
            job_id = workflow_job_id(workflow.id, definition.id)
            job = await self._jobs.get(job_id)
            if job is None:
                try:
                    job = await self._jobs.schedule(
                        _job_spec(workflow, definition, now),
                        job_id=job_id,
                        now=now,
                    )
                except JobAlreadyExistsError:
                    job = await self._jobs.get(job_id)
            if job is None:
                steps[definition.id] = WorkflowStepRecord(
                    step_id=definition.id,
                    status=WorkflowStepStatus.FAILED,
                    job_id=job_id,
                    started_at=now,
                    finished_at=now,
                    error="WorkflowJobMissing",
                )
            else:
                running = WorkflowStepRecord(
                    step_id=definition.id,
                    status=WorkflowStepStatus.RUNNING,
                    job_id=job.id,
                    started_at=job.created_at,
                )
                steps[definition.id] = _step_from_job(
                    running,
                    job.status,
                    job.updated_at,
                    job.output,
                    job.error,
                )
            changed = True
        return steps, changed

    async def _terminal_transition(
        self,
        current: WorkflowRecord,
        steps: dict[str, WorkflowStepRecord],
        now: datetime,
    ) -> WorkflowRecord | None:
        failed = next(
            (
                record
                for definition in current.definition.steps
                if (record := steps[definition.id]).status is WorkflowStepStatus.FAILED
            ),
            None,
        )
        if failed is not None:
            await self._cancel_jobs(steps, now)
            cancelled = self._cancel_open_steps(steps, now)
            error = failed.error or "WorkflowStepFailed"
            return replace(
                current,
                status=WorkflowStatus.FAILED,
                steps=cancelled,
                revision=current.revision + 1,
                updated_at=now,
                finished_at=now,
                error=f"{failed.step_id}: {error}",
            )

        if any(record.status is WorkflowStepStatus.CANCELLED for record in steps.values()):
            await self._cancel_jobs(steps, now)
            return replace(
                current,
                status=WorkflowStatus.CANCELLED,
                steps=self._cancel_open_steps(steps, now),
                revision=current.revision + 1,
                updated_at=now,
                finished_at=now,
                error=None,
            )

        if all(record.status is WorkflowStepStatus.SUCCEEDED for record in steps.values()):
            return replace(
                current,
                status=WorkflowStatus.SUCCEEDED,
                steps=steps,
                revision=current.revision + 1,
                updated_at=now,
                finished_at=now,
                error=None,
            )
        return None

    async def _cancel_jobs(
        self,
        steps: dict[str, WorkflowStepRecord],
        now: datetime,
    ) -> None:
        for record in steps.values():
            if record.status is WorkflowStepStatus.RUNNING and record.job_id is not None:
                await self._jobs.cancel(record.job_id, now=now)

    def _cancel_open_steps(
        self,
        steps: dict[str, WorkflowStepRecord],
        now: datetime,
    ) -> dict[str, WorkflowStepRecord]:
        cancelled = dict(steps)
        for step_id, record in tuple(cancelled.items()):
            if record.status in {
                WorkflowStepStatus.BLOCKED,
                WorkflowStepStatus.READY,
                WorkflowStepStatus.RUNNING,
            }:
                cancelled[step_id] = replace(
                    record,
                    status=WorkflowStepStatus.CANCELLED,
                    finished_at=now,
                    error=None,
                )
        return cancelled

    async def _require(self, workflow_id: WorkflowId) -> WorkflowRecord:
        record = await self._repository.get(workflow_id)
        if record is None:
            raise WorkflowNotFoundError(f"workflow not found: {workflow_id}")
        return record

    async def _save(
        self,
        current: WorkflowRecord,
        updated: WorkflowRecord,
    ) -> WorkflowRecord:
        saved = await self._repository.replace(
            updated,
            expected_revision=current.revision,
        )
        await self._emit_transitions(current, saved)
        return saved

    async def _emit_transitions(
        self,
        current: WorkflowRecord,
        updated: WorkflowRecord,
    ) -> None:
        names = {
            WorkflowStepStatus.READY: "workflow.step.ready",
            WorkflowStepStatus.RUNNING: "workflow.step.started",
            WorkflowStepStatus.SUCCEEDED: "workflow.step.succeeded",
            WorkflowStepStatus.FAILED: "workflow.step.failed",
            WorkflowStepStatus.CANCELLED: "workflow.step.cancelled",
        }
        for definition in updated.definition.steps:
            before = current.steps[definition.id]
            after = updated.steps[definition.id]
            if before.status is after.status:
                continue
            name = names.get(after.status)
            if name is not None:
                await self._emit(
                    name,
                    updated,
                    step_id=definition.id,
                    step_status=after.status,
                )
        if current.status is not updated.status and updated.status.terminal:
            await self._emit(f"workflow.{updated.status.value}", updated)

    async def _emit(
        self,
        name: str,
        record: WorkflowRecord,
        *,
        step_id: str | None = None,
        step_status: WorkflowStepStatus | None = None,
    ) -> None:
        if self._events is None:
            return
        payload: dict[str, object] = {
            "workflow_id": str(record.id),
            "workflow_name": record.definition.name,
            "workflow_version": record.definition.version,
            "status": record.status.value,
            "revision": record.revision,
        }
        if step_id is not None:
            payload["step_id"] = step_id
        if step_status is not None:
            payload["step_status"] = step_status.value
        await self._events.emit(
            name,
            source=self._source,
            payload=payload,
            correlation_id=str(record.id),
            causation_id=record.id,
        )

    @staticmethod
    def _has_ready(steps: dict[str, WorkflowStepRecord]) -> bool:
        return any(record.status is WorkflowStepStatus.READY for record in steps.values())

    def _ensure_open(self) -> None:
        if self._closed:
            raise WorkflowOrchestratorClosedError("workflow orchestrator is closed")


def workflow_job_id(workflow_id: WorkflowId, step_id: str) -> UUID:
    """Return the stable fencing-friendly job id for one workflow step."""

    normalized = step_id.strip()
    if not normalized:
        raise ValueError("workflow step id must not be blank")
    return uuid5(workflow_id, normalized)


def _job_spec(workflow: WorkflowRecord, step: WorkflowStep, now: datetime) -> JobSpec:
    metadata = dict(step.metadata)
    metadata.update(
        {
            "phoenix.workflow_id": str(workflow.id),
            "phoenix.workflow_name": workflow.definition.name,
            "phoenix.workflow_step": step.id,
            "phoenix.workflow_version": workflow.definition.version,
        }
    )
    return JobSpec(
        capability=step.capability,
        schedule=JobSchedule(now),
        arguments=step.arguments,
        context=step.context,
        retry=step.retry,
        deadline=step.deadline,
        metadata=metadata,
    )


def _step_from_job(
    record: WorkflowStepRecord,
    status: JobStatus,
    updated_at: datetime,
    output: Mapping[str, object],
    error: str | None,
) -> WorkflowStepRecord:
    if status is JobStatus.SUCCEEDED:
        return replace(
            record,
            status=WorkflowStepStatus.SUCCEEDED,
            finished_at=updated_at,
            output=output,
            error=None,
        )
    if status is JobStatus.DEAD_LETTER:
        return replace(
            record,
            status=WorkflowStepStatus.FAILED,
            finished_at=updated_at,
            error=error or "JobDeadLettered",
        )
    if status is JobStatus.CANCELLED:
        return replace(
            record,
            status=WorkflowStepStatus.CANCELLED,
            finished_at=updated_at,
            error=None,
        )
    return record


def _now(value: datetime | None) -> datetime:
    result = datetime.now(UTC) if value is None else value
    if result.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    return result
