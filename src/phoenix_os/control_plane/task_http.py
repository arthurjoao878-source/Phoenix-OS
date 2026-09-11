"""Durable-session HTTP boundary for bounded RFC-0039 task operations."""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from dataclasses import replace
from datetime import UTC, datetime
from http import HTTPStatus
from typing import Protocol, runtime_checkable
from uuid import UUID

from phoenix_os.agent.contracts import AgentRunId
from phoenix_os.agent.durable_contracts import CheckpointEnvelope
from phoenix_os.agent.errors import (
    AgentAdministrationAccessDeniedError,
    AgentAuthorizationRejectedError,
    AgentError,
    AgentLimitExceededError,
    AgentServiceUnavailableError,
    AgentStateConflictError,
)
from phoenix_os.authority import AuthorityFreshnessValidator
from phoenix_os.control_plane.csrf import ControlPlaneBrowserOrigin
from phoenix_os.control_plane.durable_session_access import (
    ControlPlaneDurableSessionAuthentication,
)
from phoenix_os.control_plane.errors import (
    ControlPlaneDurableSessionCsrfRejectedError,
)
from phoenix_os.control_plane.operator_configuration import (
    OperatorConfiguration,
    OperatorProfileConfiguration,
)
from phoenix_os.control_plane.task_authority_composition import (
    compose_durable_session_task_execution_authority,
)
from phoenix_os.control_plane.task_policy_binding import (
    TaskExecutionPolicyBinding,
    TaskExecutionPolicyBindingError,
    TaskExecutionPolicyTargets,
)
from phoenix_os.control_plane.task_request_mapping import (
    ServerOwnedTaskRequest,
    TaskRequestMappingError,
)
from phoenix_os.control_plane.task_resume_activation import TaskResumeActivationError
from phoenix_os.control_plane.task_resume_context_resupply import (
    MAX_TASK_RESUME_CONTEXT_DOCUMENT_BYTES,
    TaskResumeContextResupply,
    decode_task_resume_context_resupply,
)
from phoenix_os.control_plane.task_resume_execution import execute_same_lease_durable_task_resume
from phoenix_os.control_plane.task_resume_live_probes import (
    compose_server_owned_task_resume_live_probes,
)
from phoenix_os.control_plane.task_resume_preparation import TaskResumePreparationError
from phoenix_os.control_plane.task_runtime_bridge import (
    TaskExecutionAuthority,
    TaskRuntimeBridgeValidationError,
    TaskStatusSummary,
    project_authorized_durable_task_status,
)
from phoenix_os.control_plane.task_runtime_composition import (
    ServerOwnedDurableIntegratedTaskRuntime,
    compose_server_owned_durable_integrated_task_resume_support,
)
from phoenix_os.integrated_agent.durable_run import integrated_durable_run_id
from phoenix_os.policy import PolicyEngine

TASK_CONTROL_PLANE_BASE_PATH = "/v1/control-plane/tasks"
_NO_STORE = {"Cache-Control": "no-store"}


class ControlPlaneTaskHttpCsrfVerifier(Protocol):
    """Durable-session CSRF verification required for task mutations."""

    async def verify_csrf(
        self,
        token_value: str | None,
        authentication: ControlPlaneDurableSessionAuthentication,
        *,
        supplied_origin: ControlPlaneBrowserOrigin,
        expected_origin: ControlPlaneBrowserOrigin,
    ) -> object: ...


@runtime_checkable
class ControlPlaneTaskHttpAdministration(Protocol):
    """Caller-authorized server-owned task operations exposed to HTTP."""

    async def run(
        self,
        authentication: ControlPlaneDurableSessionAuthentication,
        *,
        profile_name: str,
        workspace_name: str,
        task_text: str,
    ) -> TaskStatusSummary: ...

    async def status(
        self,
        authentication: ControlPlaneDurableSessionAuthentication,
        *,
        run_id: str,
    ) -> TaskStatusSummary: ...

    async def cancel(
        self,
        authentication: ControlPlaneDurableSessionAuthentication,
        *,
        run_id: str,
    ) -> TaskStatusSummary: ...

    async def resume(
        self,
        authentication: ControlPlaneDurableSessionAuthentication,
        *,
        run_id: str,
        context_resupply: TaskResumeContextResupply,
    ) -> TaskStatusSummary: ...


def _utc_now() -> datetime:
    return datetime.now(UTC)


class ServerOwnedControlPlaneTaskHttpAdministration:
    """Bind durable operator HTTP calls to the reviewed server-owned task runtime."""

    def __init__(
        self,
        *,
        owner: ServerOwnedDurableIntegratedTaskRuntime,
        policy: PolicyEngine,
        lease_owner_id: str,
        authority_freshness: AuthorityFreshnessValidator | None = None,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        if not isinstance(owner, ServerOwnedDurableIntegratedTaskRuntime):
            raise TypeError("owner must be ServerOwnedDurableIntegratedTaskRuntime")
        if not isinstance(policy, PolicyEngine):
            raise TypeError("policy must be PolicyEngine")
        if policy.closed:
            raise TaskRuntimeBridgeValidationError()
        if (
            owner.operator_configuration is None
            or owner.operator_profile is None
            or owner.composition is None
        ):
            raise TaskRuntimeBridgeValidationError()
        if authority_freshness is not None and not isinstance(
            authority_freshness,
            AuthorityFreshnessValidator,
        ):
            raise TypeError("authority_freshness must implement AuthorityFreshnessValidator")
        if not isinstance(lease_owner_id, str):
            raise TypeError("lease_owner_id must be a string")
        if not lease_owner_id.strip() or lease_owner_id != lease_owner_id.strip():
            raise ValueError("lease_owner_id must be a non-blank canonical string")
        if not callable(clock):
            raise TypeError("clock must be callable")
        self._owner = owner
        self._policy = policy
        self._lease_owner_id = lease_owner_id
        self._authority_freshness = authority_freshness
        self._clock = clock

    @property
    def owner(self) -> ServerOwnedDurableIntegratedTaskRuntime:
        return self._owner

    @property
    def policy(self) -> PolicyEngine:
        return self._policy

    @property
    def lease_owner_id(self) -> str:
        return self._lease_owner_id

    @property
    def authority_freshness(self) -> AuthorityFreshnessValidator | None:
        return self._authority_freshness

    async def run(
        self,
        authentication: ControlPlaneDurableSessionAuthentication,
        *,
        profile_name: str,
        workspace_name: str,
        task_text: str,
    ) -> TaskStatusSummary:
        authority = self._authority(authentication)
        configuration, _operator_profile = self._configuration()
        mapped = self._owner.request_mapper.map(
            configuration,
            profile_name=profile_name,
            workspace_name=workspace_name,
            task_text=task_text,
        )
        targets = self._owner.derive_policy_targets(mapped)
        binding = await self._open_binding(authority, targets)
        try:
            if self._authority_freshness is None:
                await self._owner.runtime.run(
                    mapped.task,
                    mapped.run_request,
                    binding.context,
                )
            else:
                await self._owner.runtime.run(
                    mapped.task,
                    mapped.run_request,
                    binding.context,
                    _authority_freshness=self._authority_freshness,
                )
            checkpoint = await self._current_checkpoint(mapped.run_request.run_id)
            return self._project(checkpoint)
        finally:
            await binding.close()

    async def status(
        self,
        authentication: ControlPlaneDurableSessionAuthentication,
        *,
        run_id: str,
    ) -> TaskStatusSummary:
        self._authority(authentication)
        checkpoint = await self._current_checkpoint(_agent_run_id(run_id))
        return self._project(checkpoint)

    async def cancel(
        self,
        authentication: ControlPlaneDurableSessionAuthentication,
        *,
        run_id: str,
    ) -> TaskStatusSummary:
        authority = self._authority(authentication)
        agent_run_id = _agent_run_id(run_id)
        checkpoint = await self._owner.coordinator.cancel_active(
            agent_run_id,
            authority.context,
            actor_id=authority.context.principal,
        )
        return self._project(checkpoint)

    async def resume(
        self,
        authentication: ControlPlaneDurableSessionAuthentication,
        *,
        run_id: str,
        context_resupply: TaskResumeContextResupply,
    ) -> TaskStatusSummary:
        if not isinstance(context_resupply, TaskResumeContextResupply):
            raise TypeError("context_resupply must be TaskResumeContextResupply")
        authority = self._authority(authentication)
        agent_run_id = _agent_run_id(run_id)
        configuration, operator_profile = self._configuration()
        service_configuration = self._owner.request_mapper.service_configuration
        supplied_request = context_resupply.request
        if (
            supplied_request.run_id != agent_run_id
            or supplied_request.limits != service_configuration.limits
        ):
            raise TaskRuntimeBridgeValidationError()
        request = replace(
            supplied_request,
            limits=service_configuration.limits,
        )
        try:
            operator_model = configuration.model(operator_profile.model_name)
            workspace = configuration.workspace(operator_profile.workspace_name)
        except KeyError as exception:
            raise TaskRuntimeBridgeValidationError() from exception
        mapped = ServerOwnedTaskRequest(
            operator_profile=operator_profile,
            operator_model=operator_model,
            workspace=workspace,
            task=context_resupply.task,
            run_request=request,
        )
        targets = self._owner.derive_policy_targets(mapped)
        binding = await self._open_binding(authority, targets)
        try:
            probes = compose_server_owned_task_resume_live_probes(
                self._owner,
                task=context_resupply.task,
                request=request,
            )
            support = compose_server_owned_durable_integrated_task_resume_support(
                self._owner,
                context=binding.context,
                probes=probes,
                authority_freshness=self._authority_freshness,
            )
            try:
                await execute_same_lease_durable_task_resume(
                    owner=self._owner,
                    support=support,
                    durable_run_id=integrated_durable_run_id(agent_run_id),
                    authority=authority,
                    lease_owner_id=self._lease_owner_id,
                    task=context_resupply.task,
                    request=request,
                    provenance=context_resupply.provenance,
                    budget_usage=context_resupply.budget_usage,
                    plan=context_resupply.plan,
                    now=self._now(),
                    clock=self._clock,
                )
            except (TaskResumePreparationError, TaskResumeActivationError) as exception:
                raise AgentStateConflictError() from exception
            checkpoint = await self._current_checkpoint(agent_run_id)
            return self._project(checkpoint)
        finally:
            await binding.close()

    def _authority(
        self,
        authentication: ControlPlaneDurableSessionAuthentication,
    ) -> TaskExecutionAuthority:
        if self._policy.closed:
            raise AgentServiceUnavailableError()
        return compose_durable_session_task_execution_authority(
            policy=self._policy,
            authentication=authentication,
        )

    def _configuration(
        self,
    ) -> tuple[OperatorConfiguration, OperatorProfileConfiguration]:
        configuration = self._owner.operator_configuration
        operator_profile = self._owner.operator_profile
        if configuration is None or operator_profile is None:
            raise TaskRuntimeBridgeValidationError()
        return configuration, operator_profile

    async def _open_binding(
        self,
        authority: TaskExecutionAuthority,
        targets: TaskExecutionPolicyTargets,
    ) -> TaskExecutionPolicyBinding:
        try:
            return await TaskExecutionPolicyBinding.open(authority, targets)
        except TaskExecutionPolicyBindingError as exception:
            raise AgentAuthorizationRejectedError() from exception

    async def _current_checkpoint(self, run_id: AgentRunId) -> CheckpointEnvelope:
        durable_run_id = integrated_durable_run_id(run_id)
        checkpoint = await self._owner.durable_stack.store.get_current(durable_run_id)
        if (
            checkpoint is None
            or checkpoint.agent_run_id != run_id
            or checkpoint.durable_run_id != durable_run_id
        ):
            raise AgentStateConflictError()
        return checkpoint

    def _project(self, checkpoint: CheckpointEnvelope) -> TaskStatusSummary:
        configuration, operator_profile = self._configuration()
        return project_authorized_durable_task_status(
            configuration=configuration,
            operator_profile=operator_profile,
            execution_profile=self._owner.profile,
            checkpoint=checkpoint,
            now=self._now(),
        )

    def _now(self) -> datetime:
        value = self._clock()
        if not isinstance(value, datetime):
            raise TypeError("task HTTP clock must return datetime")
        if value.tzinfo is None or value.utcoffset() is None:
            raise TaskRuntimeBridgeValidationError()
        return value


def _agent_run_id(value: str) -> AgentRunId:
    if not isinstance(value, str):
        raise TypeError("run_id must be a string")
    if not value or value != value.strip():
        raise ValueError("run_id must be a canonical UUID string")
    parsed = UUID(value)
    if str(parsed) != value:
        raise ValueError("run_id must be a canonical UUID string")
    return AgentRunId(parsed)


class _AdministrationContractError(Exception):
    pass


class ControlPlaneTaskHttpAdapter:
    """Expose bounded task run/status/cancel/resume to durable operator sessions."""

    def __init__(
        self,
        *,
        administration: ControlPlaneTaskHttpAdministration,
        boundary: ControlPlaneTaskHttpCsrfVerifier,
    ) -> None:
        if not isinstance(administration, ControlPlaneTaskHttpAdministration):
            raise TypeError("task HTTP requires task administration")
        if not callable(getattr(boundary, "verify_csrf", None)):
            raise TypeError("task HTTP requires a CSRF boundary")
        self._administration = administration
        self._boundary = boundary

    @property
    def administration(self) -> ControlPlaneTaskHttpAdministration:
        return self._administration

    @staticmethod
    def handles(path: str) -> bool:
        return _task_route(path) is not None

    @staticmethod
    def body_limit(path: str) -> int | None:
        route = _task_route(path)
        if route is None:
            return None
        action, _run_id = route
        if action == "resume":
            return MAX_TASK_RESUME_CONTEXT_DOCUMENT_BYTES
        return None

    async def dispatch(
        self,
        *,
        authentication: ControlPlaneDurableSessionAuthentication,
        method: str,
        path: str,
        query: Mapping[str, tuple[str, ...]],
        headers: Mapping[str, tuple[str, ...]],
        body: bytes,
        server_origin: ControlPlaneBrowserOrigin,
    ) -> tuple[HTTPStatus, Mapping[str, object], dict[str, str]]:
        if not isinstance(authentication, ControlPlaneDurableSessionAuthentication):
            raise TypeError("authentication must be ControlPlaneDurableSessionAuthentication")

        route = _task_route(path)
        if route is None:
            return HTTPStatus.NOT_FOUND, {"error": "not_found"}, dict(_NO_STORE)
        action, run_id = route

        allowed_method = "GET" if action == "status" else "POST"
        if method != allowed_method:
            return (
                HTTPStatus.METHOD_NOT_ALLOWED,
                {"error": "method_not_allowed"},
                {"Allow": allowed_method, **_NO_STORE},
            )
        if query:
            return HTTPStatus.BAD_REQUEST, {"error": "invalid_request"}, dict(_NO_STORE)

        try:
            if action != "status":
                await self._verify_csrf(authentication, headers, server_origin)

            if action == "run":
                document = _json_object(body)
                _require_fields(
                    document,
                    required={"profile_name", "workspace_name", "task_text"},
                )
                summary = await self._administration.run(
                    authentication,
                    profile_name=_canonical_reference(document, "profile_name"),
                    workspace_name=_canonical_reference(document, "workspace_name"),
                    task_text=_task_text(document),
                )
                response_status = HTTPStatus.CREATED
            elif action == "status":
                if body:
                    raise ValueError("task status request body must be empty")
                if run_id is None:
                    raise _AdministrationContractError()
                summary = await self._administration.status(
                    authentication,
                    run_id=run_id,
                )
                response_status = HTTPStatus.OK
            elif action == "cancel":
                if body:
                    raise ValueError("task cancel request body must be empty")
                if run_id is None:
                    raise _AdministrationContractError()
                summary = await self._administration.cancel(
                    authentication,
                    run_id=run_id,
                )
                response_status = HTTPStatus.OK
            elif action == "resume":
                if run_id is None:
                    raise _AdministrationContractError()
                context_resupply = decode_task_resume_context_resupply(body)
                summary = await self._administration.resume(
                    authentication,
                    run_id=run_id,
                    context_resupply=context_resupply,
                )
                response_status = HTTPStatus.OK
            else:
                raise _AdministrationContractError()

            if not isinstance(summary, TaskStatusSummary):
                raise _AdministrationContractError()
            return response_status, _summary_to_dict(summary), dict(_NO_STORE)
        except ControlPlaneDurableSessionCsrfRejectedError:
            return HTTPStatus.FORBIDDEN, {"error": "request_rejected"}, dict(_NO_STORE)
        except (
            AgentAdministrationAccessDeniedError,
            AgentAuthorizationRejectedError,
        ):
            return HTTPStatus.FORBIDDEN, {"error": "forbidden"}, dict(_NO_STORE)
        except AgentStateConflictError:
            return HTTPStatus.CONFLICT, {"error": "task_conflict"}, dict(_NO_STORE)
        except AgentLimitExceededError:
            return (
                HTTPStatus.TOO_MANY_REQUESTS,
                {"error": "task_capacity_exhausted"},
                {"Retry-After": "1", **_NO_STORE},
            )
        except (AgentServiceUnavailableError, TaskExecutionPolicyBindingError):
            return HTTPStatus.SERVICE_UNAVAILABLE, {"error": "task_unavailable"}, dict(_NO_STORE)
        except (
            TaskRequestMappingError,
            TaskRuntimeBridgeValidationError,
            KeyError,
            TypeError,
            ValueError,
            UnicodeDecodeError,
            json.JSONDecodeError,
        ):
            return HTTPStatus.BAD_REQUEST, {"error": "invalid_task_request"}, dict(_NO_STORE)
        except (AgentError, _AdministrationContractError):
            return HTTPStatus.SERVICE_UNAVAILABLE, {"error": "task_unavailable"}, dict(_NO_STORE)

    async def _verify_csrf(
        self,
        authentication: ControlPlaneDurableSessionAuthentication,
        headers: Mapping[str, tuple[str, ...]],
        server_origin: ControlPlaneBrowserOrigin,
    ) -> None:
        supplied_origin = _exact_origin(headers, server_origin)
        await self._boundary.verify_csrf(
            _one_optional_header(headers, "x-phoenix-csrf"),
            authentication,
            supplied_origin=supplied_origin,
            expected_origin=server_origin,
        )


def _task_route(path: str) -> tuple[str, str | None] | None:
    if path == TASK_CONTROL_PLANE_BASE_PATH:
        return "run", None
    prefix = f"{TASK_CONTROL_PLANE_BASE_PATH}/"
    if not path.startswith(prefix):
        return None
    suffix = path[len(prefix) :]
    parts = suffix.split("/")
    if not parts or not parts[0]:
        return None
    try:
        run_id = str(UUID(parts[0]))
    except ValueError:
        return None
    if len(parts) == 1:
        return "status", run_id
    if len(parts) == 2 and parts[1] in {"cancel", "resume"}:
        return parts[1], run_id
    return None


def _summary_to_dict(summary: TaskStatusSummary) -> dict[str, object]:
    return {
        "schema_version": summary.schema_version,
        "task_id": summary.task_id,
        "run_id": summary.run_id,
        "profile_name": summary.profile_name,
        "provider_id": summary.provider_id,
        "model_id": summary.model_id,
        "run_state": summary.run_state,
        "current_step_category": summary.current_step_category,
        "model_turns_used": summary.model_turns_used,
        "model_turns_max": summary.model_turns_max,
        "tool_calls_used": summary.tool_calls_used,
        "tool_calls_max": summary.tool_calls_max,
        "accepted_tool_proposals": summary.accepted_tool_proposals,
        "rejected_tool_proposals": summary.rejected_tool_proposals,
        "deadline_state": summary.deadline_state,
        "cancellation_state": summary.cancellation_state,
        "provider_failure_category": summary.provider_failure_category,
        "durable_recovery_disposition": summary.durable_recovery_disposition,
        "terminal_category": summary.terminal_category,
    }


def _json_object(body: bytes) -> dict[str, object]:
    if not body:
        raise ValueError("JSON body is required")
    document = json.loads(body.decode("utf-8"))
    if not isinstance(document, dict):
        raise TypeError("JSON body must be an object")
    if not all(isinstance(key, str) for key in document):
        raise TypeError("JSON object keys must be strings")
    return document


def _require_fields(
    document: Mapping[str, object],
    *,
    required: set[str],
) -> None:
    if set(document) != required:
        raise ValueError("JSON object fields do not match the exact contract")


def _canonical_reference(document: Mapping[str, object], field_name: str) -> str:
    value = document[field_name]
    if not isinstance(value, str) or not value or value != value.strip():
        raise TypeError(f"{field_name} must be a canonical non-empty string")
    return value


def _task_text(document: Mapping[str, object]) -> str:
    value = document["task_text"]
    if not isinstance(value, str) or not value.strip():
        raise TypeError("task_text must be a non-blank string")
    return value


def _one_optional_header(
    headers: Mapping[str, tuple[str, ...]],
    name: str,
) -> str | None:
    values = headers.get(name, ())
    if not values:
        return None
    if len(values) != 1 or not values[0]:
        raise ValueError(f"one {name} header is required")
    return values[0]


def _exact_origin(
    headers: Mapping[str, tuple[str, ...]],
    server_origin: ControlPlaneBrowserOrigin,
) -> ControlPlaneBrowserOrigin:
    try:
        origin = ControlPlaneBrowserOrigin(_one_optional_header(headers, "origin") or "")
    except ValueError:
        raise ControlPlaneDurableSessionCsrfRejectedError("durable task request rejected") from None
    if origin != server_origin:
        raise ControlPlaneDurableSessionCsrfRejectedError("durable task request rejected")
    return origin
