"""Canonical JSON-safe serialization for dashboard queries and command receipts."""

from __future__ import annotations

from datetime import datetime

from phoenix_os.control_plane.command_api import ControlPlaneCommandAvailability
from phoenix_os.control_plane.commands import ControlPlaneCommandReceipt
from phoenix_os.control_plane.confirmation import ControlPlaneConfirmationChallenge
from phoenix_os.control_plane.contracts import (
    AuditSummary,
    CapabilityPage,
    ControlPlaneSnapshot,
    EventBatch,
    JobPage,
    PageInfo,
    PluginPage,
    WorkflowPage,
    WorkflowSummary,
)
from phoenix_os.control_plane.csrf import ControlPlaneCsrfToken
from phoenix_os.control_plane.job_commands import ControlPlaneJobCommandResult
from phoenix_os.control_plane.journal_contracts import (
    ControlPlaneCommandJournalPageInfo,
    ControlPlaneCommandJournalSnapshot,
)
from phoenix_os.control_plane.journal_history import ControlPlaneCommandHistoryPage
from phoenix_os.control_plane.operator_api import (
    ControlPlaneOperatorCredentialGrant,
    ControlPlaneOperatorView,
    ControlPlaneOperatorViewPage,
)
from phoenix_os.control_plane.operator_management import ControlPlaneOperatorMutationReceipt
from phoenix_os.control_plane.workflow_commands import ControlPlaneWorkflowCommandResult
from phoenix_os.jobs import JobSchedulerSnapshot, JobWorkerSnapshot
from phoenix_os.runtime import RuntimeSnapshot
from phoenix_os.workflows import WorkflowWorkerSnapshot


def command_receipt_to_dict(receipt: ControlPlaneCommandReceipt) -> dict[str, object]:
    """Serialize only allowlisted command result fields."""

    return {
        "schema_version": receipt.schema_version,
        "command_id": str(receipt.command_id),
        "action": receipt.action.value,
        "target": receipt.target,
        "status": receipt.status.value,
        "created_at": _timestamp(receipt.created_at),
        "completed_at": _optional_timestamp(receipt.completed_at),
        "result_code": receipt.result_code,
    }


def command_availability_to_dict(
    availability: ControlPlaneCommandAvailability,
) -> dict[str, object]:
    return {
        "schema_version": availability.schema_version,
        "actions": {
            "job.create": availability.create_job,
            "job.cancel": availability.cancel_job,
            "job.retry-dead-letter": availability.retry_dead_letter_job,
            "workflow.cancel": availability.cancel_workflow,
        },
    }


def csrf_token_to_dict(token: ControlPlaneCsrfToken) -> dict[str, object]:
    return {"schema_version": 1, "csrf_token": token.value}


def confirmation_challenge_to_dict(
    challenge: ControlPlaneConfirmationChallenge,
) -> dict[str, object]:
    return {
        "schema_version": challenge.schema_version,
        "command_id": str(challenge.command_id),
        "action": challenge.action.value,
        "target": challenge.target,
        "issued_at": _timestamp(challenge.issued_at),
        "expires_at": _timestamp(challenge.expires_at),
        "confirmation_proof": challenge.proof.value,
    }


def job_command_result_to_dict(result: ControlPlaneJobCommandResult) -> dict[str, object]:
    payload = command_receipt_to_dict(result.receipt)
    payload["job_id"] = None if result.job_id is None else str(result.job_id)
    return payload


def workflow_command_result_to_dict(
    result: ControlPlaneWorkflowCommandResult,
) -> dict[str, object]:
    return command_receipt_to_dict(result.receipt)


def operator_view_to_dict(view: ControlPlaneOperatorView) -> dict[str, object]:
    """Serialize operator metadata without token digests or plaintext credentials."""

    return {
        "schema_version": view.schema_version,
        "operator_id": str(view.operator_id),
        "username": view.username,
        "display_name": view.display_name,
        "role": view.role.value,
        "status": view.status.value,
        "additional_permissions": list(view.additional_permissions),
        "effective_permissions": list(view.effective_permissions),
        "created_at": _timestamp(view.created_at),
        "updated_at": _timestamp(view.updated_at),
        "disabled_at": _optional_timestamp(view.disabled_at),
        "revoked_at": _optional_timestamp(view.revoked_at),
        "token_version": view.token_version,
        "revision": view.revision,
    }


def operator_view_page_to_dict(page: ControlPlaneOperatorViewPage) -> dict[str, object]:
    return {
        "schema_version": page.schema_version,
        "items": [operator_view_to_dict(item) for item in page.items],
        "page": {
            "offset": page.page.offset,
            "limit": page.page.limit,
            "returned": page.page.returned,
            "total": page.page.total,
            "next_offset": page.page.next_offset,
        },
    }


def operator_credential_grant_to_dict(
    grant: ControlPlaneOperatorCredentialGrant,
) -> dict[str, object]:
    payload = operator_view_to_dict(grant.operator)
    payload.update({"result_code": grant.result_code, "token": grant.token.value})
    return payload


def operator_mutation_receipt_to_dict(
    receipt: ControlPlaneOperatorMutationReceipt,
) -> dict[str, object]:
    return {
        "schema_version": receipt.schema_version,
        "operator_id": str(receipt.operator_id),
        "username": receipt.username,
        "action": receipt.action.value,
        "status": receipt.status.value,
        "token_version": receipt.token_version,
        "revision": receipt.revision,
        "changed_at": _timestamp(receipt.changed_at),
        "result_code": receipt.result_code,
    }


def snapshot_to_dict(snapshot: ControlPlaneSnapshot) -> dict[str, object]:
    """Serialize only the bounded fields approved for control-plane clients."""

    return {
        "schema_version": snapshot.schema_version,
        "generated_at": _timestamp(snapshot.generated_at),
        "health": snapshot.health.value,
        "runtime": _runtime(snapshot.runtime),
        "jobs": _jobs(snapshot.jobs),
        "workflows": _workflows(snapshot.workflows),
        "job_worker": _job_worker(snapshot.job_worker),
        "workflow_worker": _workflow_worker(snapshot.workflow_worker),
        "command_journal": _command_journal(snapshot.command_journal),
    }


def command_history_page_to_dict(page: ControlPlaneCommandHistoryPage) -> dict[str, object]:
    """Serialize allowlisted operation history without stored digests or fingerprints."""

    return {
        "schema_version": page.schema_version,
        "items": [
            {
                "command_id": str(item.command_id),
                "action": item.action.value,
                "target": item.target,
                "principal": item.principal,
                "status": item.status.value,
                "requested_at": _timestamp(item.requested_at),
                "updated_at": _timestamp(item.updated_at),
                "completed_at": _optional_timestamp(item.completed_at),
                "result_code": item.result_code,
                "revision": item.revision,
            }
            for item in page.items
        ],
        "page": _journal_page(page.page),
    }


def event_batch_to_dict(batch: EventBatch) -> dict[str, object]:
    """Serialize safe event headers and cursor/backpressure diagnostics."""

    return {
        "schema_version": batch.schema_version,
        "items": [
            {
                "sequence": item.sequence,
                "id": str(item.id),
                "name": item.name,
                "source": item.source,
                "occurred_at": _timestamp(item.occurred_at),
                "correlation_id": item.correlation_id,
                "causation_id": (None if item.causation_id is None else str(item.causation_id)),
            }
            for item in batch.items
        ],
        "cursor": batch.cursor,
        "retention": {
            "oldest_cursor": batch.oldest_cursor,
            "latest_cursor": batch.latest_cursor,
            "gap": batch.gap,
            "dropped": batch.dropped,
        },
        "timed_out": batch.timed_out,
    }


def job_page_to_dict(page: JobPage) -> dict[str, object]:
    return {
        "items": [
            {
                "id": str(item.id),
                "capability": item.capability,
                "status": item.status.value,
                "attempts": item.attempts,
                "max_attempts": item.max_attempts,
                "recurring": item.recurring,
                "created_at": _timestamp(item.created_at),
                "updated_at": _timestamp(item.updated_at),
                "next_run_at": _timestamp(item.next_run_at),
                "has_error": item.has_error,
            }
            for item in page.items
        ],
        "page": _page(page.page),
    }


def workflow_page_to_dict(page: WorkflowPage) -> dict[str, object]:
    return {
        "items": [
            {
                "id": str(item.id),
                "name": item.name,
                "version": item.version,
                "status": item.status.value,
                "revision": item.revision,
                "created_at": _timestamp(item.created_at),
                "updated_at": _timestamp(item.updated_at),
                "finished_at": _optional_timestamp(item.finished_at),
                "completed_steps": item.completed_steps,
                "total_steps": item.total_steps,
                "has_error": item.has_error,
                "steps": [
                    {
                        "id": step.id,
                        "status": step.status.value,
                        "job_id": None if step.job_id is None else str(step.job_id),
                        "started_at": _optional_timestamp(step.started_at),
                        "finished_at": _optional_timestamp(step.finished_at),
                        "has_error": step.has_error,
                    }
                    for step in item.steps
                ],
            }
            for item in page.items
        ],
        "page": _page(page.page),
    }


def capability_page_to_dict(page: CapabilityPage) -> dict[str, object]:
    return {
        "items": [
            {
                "name": item.name,
                "description": item.description,
                "version": item.version,
                "risk": item.risk.value,
                "required_permissions": list(item.required_permissions),
                "confirmation_required": item.confirmation_required,
                "default_timeout": item.default_timeout,
                "tags": list(item.tags),
            }
            for item in page.items
        ],
        "page": _page(page.page),
    }


def plugin_page_to_dict(page: PluginPage) -> dict[str, object]:
    return {
        "items": [
            {
                "plugin_id": item.plugin_id,
                "name": item.name,
                "version": item.version,
                "api_version": item.api_version,
                "status": item.status.value,
                "dependencies": list(item.dependencies),
                "permissions": list(item.permissions),
                "exports": {
                    "capabilities": item.capability_exports,
                    "state_stores": item.state_store_exports,
                    "services": item.service_exports,
                },
                "has_failure": item.has_failure,
            }
            for item in page.items
        ],
        "page": _page(page.page),
    }


def audit_summary_to_dict(summary: AuditSummary | None) -> dict[str, object]:
    if summary is None:
        return {"available": False}
    return {
        "available": True,
        "closed": summary.closed,
        "records": summary.records,
        "head_sequence": summary.head_sequence,
        "signed_records": summary.signed_records,
        "appended": summary.appended,
        "reads": summary.reads,
        "verifications": summary.verifications,
        "verification_failures": summary.verification_failures,
        "denied_operations": summary.denied_operations,
    }


def _journal_page(page: ControlPlaneCommandJournalPageInfo) -> dict[str, object]:
    return {
        "offset": page.offset,
        "limit": page.limit,
        "returned": page.returned,
        "total": page.total,
        "next_offset": page.next_offset,
    }


def _page(page: PageInfo) -> dict[str, object]:
    return {
        "offset": page.offset,
        "limit": page.limit,
        "returned": page.returned,
        "total": page.total,
        "next_offset": page.next_offset,
    }


def _runtime(snapshot: RuntimeSnapshot) -> dict[str, object]:
    return {
        "runtime_id": str(snapshot.runtime_id),
        "state": snapshot.state.value,
        "components": list(snapshot.components),
        "active_components": list(snapshot.active_components),
        "in_flight_requests": snapshot.in_flight_requests,
        "created_at": _timestamp(snapshot.created_at),
        "started_at": _optional_timestamp(snapshot.started_at),
        "stopped_at": _optional_timestamp(snapshot.stopped_at),
    }


def _jobs(snapshot: JobSchedulerSnapshot) -> dict[str, object]:
    return {
        "closed": snapshot.closed,
        "total": snapshot.jobs,
        "scheduled": snapshot.scheduled,
        "running": snapshot.running,
        "retrying": snapshot.retrying,
        "succeeded": snapshot.succeeded,
        "cancelled": snapshot.cancelled,
        "dead_letter": snapshot.dead_letter,
        "runs": snapshot.runs,
    }


def _workflows(summary: WorkflowSummary) -> dict[str, object]:
    return {
        "total": summary.total,
        "pending": summary.pending,
        "running": summary.running,
        "succeeded": summary.succeeded,
        "failed": summary.failed,
        "cancelled": summary.cancelled,
    }


def _job_worker(snapshot: JobWorkerSnapshot | None) -> dict[str, object] | None:
    if snapshot is None:
        return None
    return {
        "state": snapshot.state.value,
        "worker": snapshot.worker,
        "ticks": snapshot.ticks,
        "runs": snapshot.runs,
        "failures": snapshot.failures,
        "last_tick_at": _optional_timestamp(snapshot.last_tick_at),
        "last_error": snapshot.last_error,
    }


def _workflow_worker(
    snapshot: WorkflowWorkerSnapshot | None,
) -> dict[str, object] | None:
    if snapshot is None:
        return None
    return {
        "state": snapshot.state.value,
        "worker": snapshot.worker,
        "ticks": snapshot.ticks,
        "workflows": snapshot.workflows,
        "failures": snapshot.failures,
        "last_tick_at": _optional_timestamp(snapshot.last_tick_at),
        "last_error": snapshot.last_error,
    }


def _command_journal(
    snapshot: ControlPlaneCommandJournalSnapshot | None,
) -> dict[str, object] | None:
    if snapshot is None:
        return None
    return {
        "closed": snapshot.closed,
        "entries": snapshot.entries,
        "pending": snapshot.pending,
        "executing": snapshot.executing,
        "succeeded": snapshot.succeeded,
        "rejected": snapshot.rejected,
        "failed": snapshot.failed,
        "capacity": snapshot.capacity,
    }


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("control plane timestamps must be timezone-aware")
    return value.isoformat()


def _optional_timestamp(value: datetime | None) -> str | None:
    return None if value is None else _timestamp(value)
