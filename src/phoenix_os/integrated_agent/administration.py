"""Least-privilege content-free administration for RFC-0036 integrated execution."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from phoenix_os.agent.contracts import AgentRunId
from phoenix_os.agent.service import AgentServiceState
from phoenix_os.integrated_agent.admission import IntegratedAgentAdmission
from phoenix_os.integrated_agent.contracts import (
    MAX_INTEGRATED_PLAN_REVISION,
    IntegratedBudgetUsage,
    IntegratedDataSourceKind,
    IntegratedExecutionProfileGeneration,
    IntegratedExecutionProfileId,
    IntegratedFailureClass,
    IntegratedTaskId,
)
from phoenix_os.integrated_agent.execution_guard import IntegratedAgentExecutionGuard
from phoenix_os.integrated_agent.planning import IntegratedPlanner
from phoenix_os.policy import PrincipalType, SecurityContext

INTEGRATED_AGENT_HEALTH_READ_PERMISSION = "integrated.agent.health.read"
INTEGRATED_AGENT_INSPECTION_READ_PERMISSION = "integrated.agent.inspection.read"
INTEGRATED_AGENT_HEALTH_RESOURCE = "integrated-agent:health"


class IntegratedAgentAdministrationAccessDeniedError(PermissionError):
    """Sanitized denial for the bounded integrated-agent administration surface."""

    def __init__(self) -> None:
        super().__init__("integrated agent administration access denied")


def integrated_agent_inspection_resource(run_id: AgentRunId) -> str:
    """Return the exact service-principal resource for one run inspection."""

    if not isinstance(run_id, AgentRunId):
        raise TypeError("run_id must be AgentRunId")
    return f"integrated-agent:run/{run_id}/inspection"


@runtime_checkable
class _IntegratedAgentAdministrationRuntime(Protocol):
    @property
    def state(self) -> AgentServiceState: ...

    @property
    def admission(self) -> IntegratedAgentAdmission: ...

    @property
    def planner(self) -> IntegratedPlanner | None: ...

    @property
    def execution_guard(self) -> IntegratedAgentExecutionGuard | None: ...

    @property
    def composition(self) -> object | None: ...


@dataclass(frozen=True, slots=True)
class IntegratedAgentAdministrationSnapshot:
    """Content-free bounded health for one configured integrated-agent runtime."""

    runtime_state: AgentServiceState
    profile_id: IntegratedExecutionProfileId
    profile_generation: IntegratedExecutionProfileGeneration
    admission_closed: bool
    planner_configured: bool
    planner_closed: bool | None
    execution_guard_configured: bool
    execution_guard_closed: bool | None
    composition_configured: bool
    schema_version: int = 1

    def __post_init__(self) -> None:
        if not isinstance(self.runtime_state, AgentServiceState):
            raise TypeError("runtime_state must be AgentServiceState")
        if not isinstance(self.profile_id, IntegratedExecutionProfileId):
            raise TypeError("profile_id must be IntegratedExecutionProfileId")
        if not isinstance(
            self.profile_generation,
            IntegratedExecutionProfileGeneration,
        ):
            raise TypeError("profile_generation must be IntegratedExecutionProfileGeneration")
        for label, value in (
            ("admission_closed", self.admission_closed),
            ("planner_configured", self.planner_configured),
            ("execution_guard_configured", self.execution_guard_configured),
            ("composition_configured", self.composition_configured),
        ):
            if type(value) is not bool:
                raise TypeError(f"{label} must be a boolean")
        for label, configured, closed in (
            ("planner", self.planner_configured, self.planner_closed),
            (
                "execution_guard",
                self.execution_guard_configured,
                self.execution_guard_closed,
            ),
        ):
            if closed is not None and type(closed) is not bool:
                raise TypeError(f"{label}_closed must be a boolean or None")
            if configured != (closed is not None):
                raise ValueError(f"{label} configured state must match its closed-state presence")
        if self.schema_version != 1:
            raise ValueError("unsupported integrated administration snapshot version")


@dataclass(frozen=True, slots=True)
class IntegratedAgentRedactedRunInspection:
    """Separately authorized bounded metadata for one active integrated run."""

    task_id: IntegratedTaskId
    run_id: AgentRunId
    profile_id: IntegratedExecutionProfileId
    profile_generation: IntegratedExecutionProfileGeneration
    plan_revision: int | None = None
    budget_usage: IntegratedBudgetUsage | None = None
    failure_class: IntegratedFailureClass | None = None
    provenance_source_kinds: tuple[IntegratedDataSourceKind, ...] = ()
    schema_version: int = 1

    def __post_init__(self) -> None:
        if not isinstance(self.task_id, IntegratedTaskId):
            raise TypeError("task_id must be IntegratedTaskId")
        if not isinstance(self.run_id, AgentRunId):
            raise TypeError("run_id must be AgentRunId")
        if not isinstance(self.profile_id, IntegratedExecutionProfileId):
            raise TypeError("profile_id must be IntegratedExecutionProfileId")
        if not isinstance(
            self.profile_generation,
            IntegratedExecutionProfileGeneration,
        ):
            raise TypeError("profile_generation must be IntegratedExecutionProfileGeneration")
        if self.plan_revision is not None and (
            isinstance(self.plan_revision, bool)
            or not isinstance(self.plan_revision, int)
            or not 1 <= self.plan_revision <= MAX_INTEGRATED_PLAN_REVISION
        ):
            raise ValueError("plan_revision must be a bounded positive integer or None")
        if self.budget_usage is not None and not isinstance(
            self.budget_usage,
            IntegratedBudgetUsage,
        ):
            raise TypeError("budget_usage must be IntegratedBudgetUsage or None")
        if self.failure_class is not None and not isinstance(
            self.failure_class,
            IntegratedFailureClass,
        ):
            raise TypeError("failure_class must be IntegratedFailureClass or None")

        supplied = tuple(self.provenance_source_kinds)
        if any(not isinstance(item, IntegratedDataSourceKind) for item in supplied):
            raise TypeError("provenance_source_kinds must contain IntegratedDataSourceKind values")
        object.__setattr__(
            self,
            "provenance_source_kinds",
            tuple(sorted(set(supplied), key=lambda item: item.value)),
        )
        if self.schema_version != 1:
            raise ValueError("unsupported integrated run inspection version")


class IntegratedAgentAdministration:
    """Expose content-free health and separately authorized redacted run inspection."""

    def __init__(self, runtime: _IntegratedAgentAdministrationRuntime) -> None:
        if not isinstance(runtime, _IntegratedAgentAdministrationRuntime):
            raise TypeError("runtime must implement the integrated administration runtime surface")
        self._runtime = runtime

    async def snapshot(
        self,
        context: SecurityContext,
    ) -> IntegratedAgentAdministrationSnapshot:
        self._authorize(
            context,
            INTEGRATED_AGENT_HEALTH_READ_PERMISSION,
            INTEGRATED_AGENT_HEALTH_RESOURCE,
        )
        runtime = self._runtime
        profile = runtime.admission.profile
        planner = runtime.planner
        guard = runtime.execution_guard
        return IntegratedAgentAdministrationSnapshot(
            runtime_state=runtime.state,
            profile_id=profile.profile_id,
            profile_generation=profile.generation,
            admission_closed=runtime.admission.closed,
            planner_configured=planner is not None,
            planner_closed=None if planner is None else planner.closed,
            execution_guard_configured=guard is not None,
            execution_guard_closed=None if guard is None else guard.closed,
            composition_configured=runtime.composition is not None,
        )

    async def inspect_run(
        self,
        run_id: AgentRunId,
        context: SecurityContext,
    ) -> IntegratedAgentRedactedRunInspection | None:
        if not isinstance(run_id, AgentRunId):
            raise TypeError("run_id must be AgentRunId")
        self._authorize(
            context,
            INTEGRATED_AGENT_INSPECTION_READ_PERMISSION,
            integrated_agent_inspection_resource(run_id),
        )

        runtime = self._runtime
        binding = await runtime.admission.binding_for_run(run_id)
        if binding is None:
            return None

        planner = runtime.planner
        revision = None if planner is None else planner.current_revision(run_id)
        if revision == 0:
            revision = None

        guard = runtime.execution_guard
        budget_usage = None
        failure_class = None
        source_kinds: tuple[IntegratedDataSourceKind, ...] = ()
        if guard is not None:
            budget_usage = guard.current_budget_usage(run_id)
            failure_class = guard.failure_for(run_id)
            provenance = guard.current_provenance(run_id)
            if provenance is not None:
                source_kinds = tuple(atom.source_kind for atom in provenance.atoms)

        return IntegratedAgentRedactedRunInspection(
            task_id=binding.task_id,
            run_id=binding.run_id,
            profile_id=binding.profile_id,
            profile_generation=binding.profile_generation,
            plan_revision=revision,
            budget_usage=budget_usage,
            failure_class=failure_class,
            provenance_source_kinds=source_kinds,
        )

    @staticmethod
    def _authorize(
        context: SecurityContext,
        permission: str,
        resource: str,
    ) -> None:
        if not isinstance(context, SecurityContext):
            raise TypeError("context must be SecurityContext")
        if not context.authenticated:
            raise IntegratedAgentAdministrationAccessDeniedError()
        if permission not in context.permissions and "*" not in context.permissions:
            raise IntegratedAgentAdministrationAccessDeniedError()
        if (
            context.principal_type is PrincipalType.SERVICE
            and context.attributes.get("resource") != resource
        ):
            raise IntegratedAgentAdministrationAccessDeniedError()
