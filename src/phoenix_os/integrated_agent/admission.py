"""Server-owned task/profile admission for RFC-0036 S2."""

from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import dataclass
from typing import Self

from phoenix_os.agent.authorization import AgentRunAuthorityBinding
from phoenix_os.agent.configuration import AgentServiceConfiguration
from phoenix_os.agent.contracts import AgentId, AgentLimits, AgentRunId, AgentRunRequest
from phoenix_os.authority.contracts import AuthorityFreshnessBinding
from phoenix_os.integrated_agent.contracts import (
    IntegratedExecutionProfileGeneration,
    IntegratedExecutionProfileId,
    IntegratedTaskDigest,
    IntegratedTaskId,
    IntegratedTaskRequest,
)
from phoenix_os.integrated_agent.errors import (
    IntegratedAgentConfigurationError,
    IntegratedAgentRejectedError,
    IntegratedAgentStaleError,
    IntegratedAgentValidationError,
)
from phoenix_os.integrated_agent.profiles import (
    IntegratedExecutionProfile,
    IntegratedExecutionProfileCatalog,
)


@dataclass(frozen=True, slots=True)
class IntegratedExecutionProfileSelection:
    """Exact server-owned profile identity expected for this integrated service."""

    profile_id: IntegratedExecutionProfileId
    generation: IntegratedExecutionProfileGeneration

    def __post_init__(self) -> None:
        if not isinstance(self.profile_id, IntegratedExecutionProfileId):
            raise TypeError("profile_id must be IntegratedExecutionProfileId")
        if not isinstance(self.generation, IntegratedExecutionProfileGeneration):
            raise TypeError("generation must be IntegratedExecutionProfileGeneration")


@dataclass(frozen=True, slots=True)
class IntegratedAgentRunBinding:
    """Immutable server-owned task/profile binding for one existing AgentRunId."""

    run_id: AgentRunId
    task_id: IntegratedTaskId
    task_digest: IntegratedTaskDigest
    profile_id: IntegratedExecutionProfileId
    profile_generation: IntegratedExecutionProfileGeneration
    agent_id: AgentId
    effective_limits: AgentLimits
    authority: AgentRunAuthorityBinding

    def __post_init__(self) -> None:
        if not isinstance(self.run_id, AgentRunId):
            raise TypeError("run_id must be AgentRunId")
        if not isinstance(self.task_id, IntegratedTaskId):
            raise TypeError("task_id must be IntegratedTaskId")
        if not isinstance(self.task_digest, IntegratedTaskDigest):
            raise TypeError("task_digest must be IntegratedTaskDigest")
        if not isinstance(self.profile_id, IntegratedExecutionProfileId):
            raise TypeError("profile_id must be IntegratedExecutionProfileId")
        if not isinstance(self.profile_generation, IntegratedExecutionProfileGeneration):
            raise TypeError("profile_generation must be IntegratedExecutionProfileGeneration")
        if not isinstance(self.agent_id, AgentId):
            raise TypeError("agent_id must be AgentId")
        if not isinstance(self.effective_limits, AgentLimits):
            raise TypeError("effective_limits must be AgentLimits")
        if not isinstance(self.authority, AgentRunAuthorityBinding):
            raise TypeError("authority must be AgentRunAuthorityBinding")

        expected_parameter_digest = _integrated_authority_parameter_digest(
            self.task_digest,
            self.profile_id,
        )
        if self.authority.parameter_digest != expected_parameter_digest:
            raise ValueError("integrated run authority parameter digest does not match binding")

        expected_attributes = (
            ("integrated_profile_generation", str(self.profile_generation)),
            ("integrated_profile_id", str(self.profile_id)),
            ("integrated_task_digest", str(self.task_digest)),
            ("integrated_task_id", str(self.task_id)),
        )
        if self.authority.attributes != expected_attributes:
            raise ValueError("integrated run authority attributes do not match binding")

        expected_freshness = (
            AuthorityFreshnessBinding(
                kind="integrated.profile",
                identity=f"{self.profile_id}:{self.profile_generation}",
            ),
        )
        if self.authority.freshness_bindings != expected_freshness:
            raise ValueError("integrated run authority freshness does not match binding")


class IntegratedAgentAdmissionLease:
    """One idempotently releasable active integrated-run binding."""

    def __init__(
        self,
        controller: IntegratedAgentAdmission,
        request: AgentRunRequest,
        binding: IntegratedAgentRunBinding,
    ) -> None:
        self._controller = controller
        self._request = request
        self._binding = binding
        self._released = False
        self._lock = asyncio.Lock()

    @property
    def request(self) -> AgentRunRequest:
        return self._request

    @property
    def binding(self) -> IntegratedAgentRunBinding:
        return self._binding

    @property
    def released(self) -> bool:
        return self._released

    async def release(self) -> None:
        async with self._lock:
            if self._released:
                return
            await self._controller._release(self._binding)
            self._released = True

    async def __aenter__(self) -> Self:
        if self._released:
            raise IntegratedAgentStaleError("integrated admission lease is already released")
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: object,
    ) -> None:
        del exc_type, exc_value, traceback
        await self.release()


class IntegratedAgentAdmission:
    """Resolve one immutable profile and bind tasks to existing AgentRunIds."""

    def __init__(
        self,
        catalog: IntegratedExecutionProfileCatalog,
        selection: IntegratedExecutionProfileSelection,
        service_configuration: AgentServiceConfiguration,
    ) -> None:
        if not isinstance(catalog, IntegratedExecutionProfileCatalog):
            raise TypeError("catalog must be IntegratedExecutionProfileCatalog")
        if not isinstance(selection, IntegratedExecutionProfileSelection):
            raise TypeError("selection must be IntegratedExecutionProfileSelection")
        if not isinstance(service_configuration, AgentServiceConfiguration):
            raise TypeError("service_configuration must be AgentServiceConfiguration")

        profile = _resolve_selected_profile(catalog, selection)
        if profile.agent_id != service_configuration.agent_id:
            raise IntegratedAgentConfigurationError()

        self._catalog = catalog
        self._selection = selection
        self._service_configuration = service_configuration
        self._profile = profile
        self._task_digests: dict[IntegratedTaskId, IntegratedTaskDigest] = {}
        self._seen_run_ids: set[AgentRunId] = set()
        self._active: dict[AgentRunId, IntegratedAgentRunBinding] = {}
        self._closed = False
        self._lock = asyncio.Lock()

    @property
    def catalog(self) -> IntegratedExecutionProfileCatalog:
        return self._catalog

    @property
    def selection(self) -> IntegratedExecutionProfileSelection:
        return self._selection

    @property
    def service_configuration(self) -> AgentServiceConfiguration:
        return self._service_configuration

    @property
    def profile(self) -> IntegratedExecutionProfile:
        return self._profile

    @property
    def closed(self) -> bool:
        return self._closed

    async def admit(
        self,
        task: IntegratedTaskRequest,
        request: AgentRunRequest,
    ) -> IntegratedAgentAdmissionLease:
        if not isinstance(task, IntegratedTaskRequest):
            raise TypeError("task must be IntegratedTaskRequest")
        if not isinstance(request, AgentRunRequest):
            raise TypeError("request must be AgentRunRequest")

        configuration = self._service_configuration
        profile = self._profile
        if (
            request.agent_id != profile.agent_id
            or request.agent_id != configuration.agent_id
            or request.provider_id != configuration.provider_id
            or request.model_id != configuration.model_id
        ):
            raise IntegratedAgentValidationError(
                "agent run does not match the server-owned integrated execution binding"
            )

        effective_limits = most_restrictive_agent_limits(
            request.limits,
            profile.limits,
            configuration.limits,
        )
        effective_deadline = min(
            request.deadline,
            request.created_at + effective_limits.total_duration,
        )
        effective_request = AgentRunRequest(
            agent_id=request.agent_id,
            provider_id=request.provider_id,
            model_id=request.model_id,
            messages=request.messages,
            limits=effective_limits,
            metadata=request.metadata,
            run_id=request.run_id,
            created_at=request.created_at,
            deadline=effective_deadline,
        )
        task_digest = task.digest
        authority = _integrated_agent_run_authority(
            task_id=task.task_id,
            task_digest=task_digest,
            profile=profile,
        )
        binding = IntegratedAgentRunBinding(
            run_id=effective_request.run_id,
            task_id=task.task_id,
            task_digest=task_digest,
            profile_id=profile.profile_id,
            profile_generation=profile.generation,
            agent_id=profile.agent_id,
            effective_limits=effective_limits,
            authority=authority,
        )

        async with self._lock:
            if self._closed:
                raise IntegratedAgentRejectedError("integrated agent admission is closed")
            known_digest = self._task_digests.get(task.task_id)
            if known_digest is not None and known_digest != task_digest:
                raise IntegratedAgentValidationError(
                    "integrated task identity cannot be reused with changed canonical bytes"
                )
            if effective_request.run_id in self._seen_run_ids:
                raise IntegratedAgentRejectedError(
                    "agent run id cannot be reused for integrated execution"
                )
            self._task_digests.setdefault(task.task_id, task_digest)
            self._seen_run_ids.add(effective_request.run_id)
            self._active[effective_request.run_id] = binding

        return IntegratedAgentAdmissionLease(self, effective_request, binding)

    async def binding_for_run(
        self,
        run_id: AgentRunId,
    ) -> IntegratedAgentRunBinding | None:
        if not isinstance(run_id, AgentRunId):
            raise TypeError("run_id must be AgentRunId")
        async with self._lock:
            return self._active.get(run_id)

    async def close(self) -> None:
        async with self._lock:
            self._closed = True

    async def _release(self, binding: IntegratedAgentRunBinding) -> None:
        async with self._lock:
            current = self._active.get(binding.run_id)
            if current is None or current != binding:
                raise IntegratedAgentStaleError(
                    "integrated run binding is no longer the active binding"
                )
            del self._active[binding.run_id]


def most_restrictive_agent_limits(*limits: AgentLimits) -> AgentLimits:
    """Return the pointwise most restrictive valid AgentLimits."""

    supplied = tuple(limits)
    if not supplied:
        raise ValueError("at least one AgentLimits value is required")
    if any(not isinstance(item, AgentLimits) for item in supplied):
        raise TypeError("limits must contain AgentLimits values")

    return AgentLimits(
        max_steps=min(item.max_steps for item in supplied),
        max_model_turns=min(item.max_model_turns for item in supplied),
        max_tool_calls=min(item.max_tool_calls for item in supplied),
        max_prompt_bytes=min(item.max_prompt_bytes for item in supplied),
        max_model_output_bytes=min(item.max_model_output_bytes for item in supplied),
        max_tool_result_bytes=min(item.max_tool_result_bytes for item in supplied),
        max_input_tokens=min(item.max_input_tokens for item in supplied),
        max_output_tokens=min(item.max_output_tokens for item in supplied),
        max_argument_bytes=min(item.max_argument_bytes for item in supplied),
        max_result_bytes=min(item.max_result_bytes for item in supplied),
        max_structured_depth=min(item.max_structured_depth for item in supplied),
        max_structured_items=min(item.max_structured_items for item in supplied),
        max_queue_depth=min(item.max_queue_depth for item in supplied),
        max_concurrent_runs=min(item.max_concurrent_runs for item in supplied),
        max_concurrent_model_calls=min(item.max_concurrent_model_calls for item in supplied),
        max_concurrent_tool_calls=min(item.max_concurrent_tool_calls for item in supplied),
        model_turn_timeout=min(item.model_turn_timeout for item in supplied),
        tool_call_timeout=min(item.tool_call_timeout for item in supplied),
        approval_wait_timeout=min(item.approval_wait_timeout for item in supplied),
        total_duration=min(item.total_duration for item in supplied),
        cancellation_grace=min(item.cancellation_grace for item in supplied),
        shutdown_grace=min(item.shutdown_grace for item in supplied),
    )


def _resolve_selected_profile(
    catalog: IntegratedExecutionProfileCatalog,
    selection: IntegratedExecutionProfileSelection,
) -> IntegratedExecutionProfile:
    try:
        profile = catalog.require_profile(selection.profile_id)
    except KeyError as exception:
        raise IntegratedAgentConfigurationError() from exception
    if not profile.enabled:
        raise IntegratedAgentConfigurationError()
    if profile.generation != selection.generation:
        raise IntegratedAgentStaleError("integrated execution profile generation is stale")
    return profile


def _integrated_agent_run_authority(
    *,
    task_id: IntegratedTaskId,
    task_digest: IntegratedTaskDigest,
    profile: IntegratedExecutionProfile,
) -> AgentRunAuthorityBinding:
    return AgentRunAuthorityBinding(
        parameter_digest=_integrated_authority_parameter_digest(
            task_digest,
            profile.profile_id,
        ),
        freshness_bindings=(
            AuthorityFreshnessBinding(
                kind="integrated.profile",
                identity=f"{profile.profile_id}:{profile.generation}",
            ),
        ),
        attributes=(
            ("integrated_task_id", str(task_id)),
            ("integrated_task_digest", str(task_digest)),
            ("integrated_profile_id", str(profile.profile_id)),
            ("integrated_profile_generation", str(profile.generation)),
        ),
    )


def _integrated_authority_parameter_digest(
    task_digest: IntegratedTaskDigest,
    profile_id: IntegratedExecutionProfileId,
) -> str:
    if not isinstance(task_digest, IntegratedTaskDigest):
        raise TypeError("task_digest must be IntegratedTaskDigest")
    if not isinstance(profile_id, IntegratedExecutionProfileId):
        raise TypeError("profile_id must be IntegratedExecutionProfileId")
    encoded = json.dumps(
        {
            "schema": "phoenix.integrated-agent.agent-run-authority/v1",
            "integrated_task_digest": str(task_digest),
            "integrated_profile_id": str(profile_id),
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()
