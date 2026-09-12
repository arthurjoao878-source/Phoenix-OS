"""Fail-closed server-owned RFC-0039 task/request mapping.

This module maps reviewed operator configuration into existing integrated-agent
contracts. It does not create policy authority, durable leases, runtime
ownership, HTTP transport, or a second task state machine.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime

from phoenix_os.agent.configuration import AgentServiceConfiguration
from phoenix_os.agent.contracts import (
    AgentMessage,
    AgentMessageRole,
    AgentRunId,
    AgentRunRequest,
)
from phoenix_os.control_plane.operator_configuration import (
    OperatorConfiguration,
    OperatorModelConfiguration,
    OperatorProfileConfiguration,
    OperatorWorkspaceConfiguration,
)
from phoenix_os.integrated_agent.contracts import IntegratedTaskId, IntegratedTaskRequest

TaskRequestClock = Callable[[], datetime]
TaskIdFactory = Callable[[], IntegratedTaskId]
RunIdFactory = Callable[[], AgentRunId]


class TaskRequestMappingError(ValueError):
    """Content-free failure for a mismatched production task request."""


@dataclass(frozen=True, slots=True)
class ServerOwnedTaskRequest:
    """Exact reviewed configuration plus server-owned execution request identities."""

    operator_profile: OperatorProfileConfiguration
    operator_model: OperatorModelConfiguration
    workspace: OperatorWorkspaceConfiguration
    task: IntegratedTaskRequest = field(repr=False)
    run_request: AgentRunRequest = field(repr=False)


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _canonical_reference(value: str, *, label: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{label} must be a string")
    if not value or value != value.strip():
        raise TaskRequestMappingError()
    return value


def _require_timezone_aware(value: datetime) -> None:
    if not isinstance(value, datetime):
        raise TypeError("task request clock must return datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise TaskRequestMappingError()


class ServerOwnedTaskRequestMapper:
    """Map one CLI-selected operator profile onto the Runtime-owned agent identity."""

    def __init__(
        self,
        service_configuration: AgentServiceConfiguration,
        *,
        clock: TaskRequestClock = _utc_now,
        task_id_factory: TaskIdFactory = IntegratedTaskId,
        run_id_factory: RunIdFactory = AgentRunId,
    ) -> None:
        if not isinstance(service_configuration, AgentServiceConfiguration):
            raise TypeError("service_configuration must be AgentServiceConfiguration")
        if not callable(clock):
            raise TypeError("clock must be callable")
        if not callable(task_id_factory):
            raise TypeError("task_id_factory must be callable")
        if not callable(run_id_factory):
            raise TypeError("run_id_factory must be callable")
        self._service_configuration = service_configuration
        self._clock = clock
        self._task_id_factory = task_id_factory
        self._run_id_factory = run_id_factory

    @property
    def service_configuration(self) -> AgentServiceConfiguration:
        return self._service_configuration

    def map(
        self,
        configuration: OperatorConfiguration,
        *,
        profile_name: str,
        workspace_name: str,
        task_text: str,
    ) -> ServerOwnedTaskRequest:
        """Create bounded task/run requests without accepting caller-owned execution IDs."""

        if not isinstance(configuration, OperatorConfiguration):
            raise TypeError("configuration must be OperatorConfiguration")
        if not isinstance(task_text, str):
            raise TypeError("task_text must be a string")

        selected_profile = _canonical_reference(profile_name, label="profile_name")
        selected_workspace = _canonical_reference(workspace_name, label="workspace_name")

        profiles = tuple(
            profile
            for profile in configuration.profiles
            if profile.profile_name == selected_profile
        )
        if len(profiles) != 1:
            raise TaskRequestMappingError()
        operator_profile = profiles[0]

        if operator_profile.workspace_name != selected_workspace:
            raise TaskRequestMappingError()
        if configuration.runtime is None:
            raise TaskRequestMappingError()
        if operator_profile.context_paths or operator_profile.allow_workspace_patch:
            # Context-path resolution and write composition are separate reviewed gates.
            raise TaskRequestMappingError()

        models = tuple(
            model
            for model in configuration.models
            if model.model_name == operator_profile.model_name
        )
        workspaces = tuple(
            workspace
            for workspace in configuration.workspaces
            if workspace.workspace_name == operator_profile.workspace_name
        )
        if len(models) != 1 or len(workspaces) != 1:
            raise TaskRequestMappingError()
        operator_model = models[0]
        workspace = workspaces[0]

        if workspace.kind != "development-checkout":
            raise TaskRequestMappingError()

        service_configuration = self._service_configuration
        descriptor = operator_model.descriptor
        if (
            descriptor.provider_id != service_configuration.provider_id
            or descriptor.model_id != service_configuration.model_id
        ):
            raise TaskRequestMappingError()

        now = self._clock()
        _require_timezone_aware(now)
        task_id = self._task_id_factory()
        run_id = self._run_id_factory()
        if not isinstance(task_id, IntegratedTaskId):
            raise TypeError("task_id_factory must return IntegratedTaskId")
        if not isinstance(run_id, AgentRunId):
            raise TypeError("run_id_factory must return AgentRunId")

        try:
            task = IntegratedTaskRequest(task_id=task_id, objective=task_text)
            run_request = AgentRunRequest(
                agent_id=service_configuration.agent_id,
                provider_id=service_configuration.provider_id,
                model_id=service_configuration.model_id,
                messages=(AgentMessage(AgentMessageRole.USER, task_text),),
                limits=service_configuration.limits,
                run_id=run_id,
                created_at=now,
                deadline=now + service_configuration.limits.total_duration,
            )
        except (TypeError, ValueError, UnicodeError) as exception:
            raise TaskRequestMappingError() from exception

        return ServerOwnedTaskRequest(
            operator_profile=operator_profile,
            operator_model=operator_model,
            workspace=workspace,
            task=task,
            run_request=run_request,
        )
