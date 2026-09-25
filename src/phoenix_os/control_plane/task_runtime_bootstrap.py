"""Standalone authenticated RFC-0039 task runtime bootstrap.

The CLI remains a thin boundary. This module composes the already-reviewed
Phoenix owners in-process, authenticates an existing persisted operator, issues
one temporary durable session, delegates to the canonical task administration,
and revokes the session before returning.
"""

from __future__ import annotations

import asyncio
import getpass
import hashlib
import json
from collections.abc import Coroutine
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast
from uuid import UUID

from phoenix_os import (
    AllowAllAuthorizer,
    CapabilityRegistry,
    ConfigLoader,
    ConfigSchema,
    EventBus,
    Kernel,
    MappingConfigSource,
    Router,
    RuntimeAssembler,
)
from phoenix_os.agent.checkout_agent_tools import CHECKOUT_LIST_TOOL_ID, CHECKOUT_READ_TOOL_ID
from phoenix_os.agent.checkout_authorization import PolicyEngineCheckoutWorkspaceAuthorizer
from phoenix_os.agent.checkout_patch_agent_tool import CHECKOUT_PATCH_TOOL_ID
from phoenix_os.agent.checkout_workspace import RegisteredDevelopmentCheckoutAdapter
from phoenix_os.agent.configuration import AgentServiceConfiguration, AgentToolConfiguration
from phoenix_os.agent.contracts import AgentId, AgentRunId, ToolId
from phoenix_os.agent.durable_compatibility import (
    StaticDurableCompatibilityValidator,
    create_ollama_metadata_only_durable_compatibility_policy,
)
from phoenix_os.agent.durable_sqlite import CheckoutRegistrationIdentity, SQLiteDurableRunStore
from phoenix_os.agent.registry import ToolRegistry
from phoenix_os.control_plane.authority_integration import (
    ControlPlaneDurableAuthorityFreshnessValidator,
)
from phoenix_os.control_plane.durable_session_access import ControlPlaneDurableSessionAccessService
from phoenix_os.control_plane.durable_session_contracts import ControlPlaneDurableSessionRepository
from phoenix_os.control_plane.operator_authentication import ControlPlaneOperatorAuthenticator
from phoenix_os.control_plane.operator_configuration import (
    OperatorConfiguration,
    OperatorModelConfiguration,
    OperatorProfileConfiguration,
    OperatorRuntimeConfiguration,
    OperatorWorkspaceConfiguration,
)
from phoenix_os.control_plane.operator_contracts import ControlPlaneOperatorRegistry
from phoenix_os.control_plane.operator_state import StateControlPlaneOperatorRegistry
from phoenix_os.control_plane.task_http import ServerOwnedControlPlaneTaskHttpAdministration
from phoenix_os.control_plane.task_resume_context_resupply import TaskResumeContextResupply
from phoenix_os.control_plane.task_runtime_bridge import TaskStatusSummary
from phoenix_os.control_plane.task_runtime_composition import (
    ServerOwnedDurableIntegratedTaskRuntime,
)
from phoenix_os.inference.configuration import InferenceProviderConfiguration
from phoenix_os.inference.ollama import OllamaModelProvider
from phoenix_os.integrated_agent.checkout_durable_history import (
    create_integrated_checkout_durable_history_validator,
)
from phoenix_os.integrated_agent.composition import (
    IntegratedAgentToolComposition,
    integrated_checkout_patch_tool_registration,
    integrated_checkout_tool_registrations,
    integrated_development_checkout_dogfood_profile,
    integrated_plan_update_registration,
)
from phoenix_os.integrated_agent.contracts import (
    IntegratedDataFlowPolicy,
    IntegratedExecutionProfileGeneration,
    IntegratedExecutionProfileId,
)
from phoenix_os.integrated_agent.durable_run import integrated_durable_run_id
from phoenix_os.integrated_agent.durable_transitions import (
    IntegratedDurableCheckpointMetadataProjector,
)
from phoenix_os.integrated_agent.execution_guard import IntegratedAgentExecutionGuard
from phoenix_os.integrated_agent.planning import IntegratedPlanner
from phoenix_os.integrated_agent.profiles import (
    INTEGRATED_PLAN_UPDATE_TOOL_ID,
    IntegratedDownstreamBridgeBinding,
    IntegratedExecutionProfile,
    IntegratedLocalTransformBinding,
)
from phoenix_os.policy import PolicyEngine
from phoenix_os.state.sqlite import SQLiteStateStore

if TYPE_CHECKING:
    from phoenix_os.control_plane.task_cli import TaskRunSummary

_ACTOR_ID = "rfc0039-task"
_OWNER_ID = "rfc0039-task-runtime"
_DURABILITY_PROFILE = "rfc0039-development-checkout"
_CREDENTIAL_PROMPT = "Operator credential: "


@dataclass(frozen=True, slots=True)
class _RuntimeSurface:
    runtime: Any
    policy: PolicyEngine
    profile: OperatorProfileConfiguration


class StandaloneTaskRuntimeBridge:
    """Synchronous CLI bridge over one-shot authenticated in-process runtimes."""

    requires_resume_context_resupply = True

    def run(
        self,
        *,
        configuration: OperatorConfiguration,
        profile: OperatorProfileConfiguration,
        workspace: OperatorWorkspaceConfiguration,
        task_text: str,
    ) -> TaskRunSummary:
        return _run_async(
            self._run(
                configuration=configuration,
                profile=profile,
                workspace=workspace,
                task_text=task_text,
            )
        )

    def status(self, *, configuration: OperatorConfiguration, run_id: str) -> TaskStatusSummary:
        return _run_async(self._status(configuration=configuration, run_id=run_id))

    def cancel(self, *, configuration: OperatorConfiguration, run_id: str) -> TaskRunSummary:
        return _run_async(self._cancel(configuration=configuration, run_id=run_id))

    def resume(
        self,
        *,
        configuration: OperatorConfiguration,
        run_id: str,
        context_resupply: TaskResumeContextResupply | None = None,
    ) -> TaskRunSummary:
        if context_resupply is None:
            raise ValueError("resume context resupply is required")
        return _run_async(
            self._resume(
                configuration=configuration,
                run_id=run_id,
                context_resupply=context_resupply,
            )
        )

    async def _run(
        self,
        *,
        configuration: OperatorConfiguration,
        profile: OperatorProfileConfiguration,
        workspace: OperatorWorkspaceConfiguration,
        task_text: str,
    ) -> TaskRunSummary:
        if profile.workspace_name != workspace.workspace_name:
            raise ValueError("operator profile workspace mismatch")
        return cast(
            "TaskRunSummary",
            await self._invoke(
                configuration=configuration,
                profile=profile,
                action="run",
                task_text=task_text,
            ),
        )

    async def _status(
        self, *, configuration: OperatorConfiguration, run_id: str
    ) -> TaskStatusSummary:
        profile = await _profile_for_existing_run(configuration, run_id)
        return cast(
            TaskStatusSummary,
            await self._invoke(
                configuration=configuration,
                profile=profile,
                action="status",
                run_id=run_id,
            ),
        )

    async def _cancel(self, *, configuration: OperatorConfiguration, run_id: str) -> TaskRunSummary:
        profile = await _profile_for_existing_run(configuration, run_id)
        return cast(
            "TaskRunSummary",
            await self._invoke(
                configuration=configuration,
                profile=profile,
                action="cancel",
                run_id=run_id,
            ),
        )

    async def _resume(
        self,
        *,
        configuration: OperatorConfiguration,
        run_id: str,
        context_resupply: TaskResumeContextResupply,
    ) -> TaskRunSummary:
        profile = await _profile_for_existing_run(configuration, run_id)
        return cast(
            "TaskRunSummary",
            await self._invoke(
                configuration=configuration,
                profile=profile,
                action="resume",
                run_id=run_id,
                context_resupply=context_resupply,
            ),
        )

    async def _invoke(
        self,
        *,
        configuration: OperatorConfiguration,
        profile: OperatorProfileConfiguration,
        action: str,
        run_id: str | None = None,
        task_text: str | None = None,
        context_resupply: TaskResumeContextResupply | None = None,
    ) -> TaskRunSummary | TaskStatusSummary:
        credential = _read_operator_credential()
        surface = await _compose_runtime(configuration, profile)
        runtime = surface.runtime
        await runtime.start()
        access: ControlPlaneDurableSessionAccessService | None = None
        session_token: str | None = None
        try:
            registry = cast(
                ControlPlaneOperatorRegistry, runtime.service("control_plane.operator-registry")
            )
            access_service = runtime.service("control_plane.operator-access")
            sessions = cast(
                ControlPlaneDurableSessionRepository,
                runtime.service("control_plane.operator-sessions"),
            )
            owner = runtime.service("control_plane.task-runtime")
            if not isinstance(access_service, ControlPlaneDurableSessionAccessService):
                raise RuntimeError("durable operator access service is unavailable")
            if not isinstance(owner, ServerOwnedDurableIntegratedTaskRuntime):
                raise RuntimeError("task runtime owner is unavailable")
            access = access_service

            evidence = await ControlPlaneOperatorAuthenticator(registry).authenticate(
                f"Bearer {credential}"
            )
            if evidence is None:
                raise PermissionError("operator authentication rejected")
            grant = await access.issue(evidence)
            session_token = grant.token.value
            authentication = await access.authenticate(session_token)
            if authentication is None:
                raise PermissionError("durable operator session rejected")

            freshness = ControlPlaneDurableAuthorityFreshnessValidator(
                repository=sessions,
                registry=registry,
            )
            administration = ServerOwnedControlPlaneTaskHttpAdministration(
                owner=owner,
                policy=surface.policy,
                lease_owner_id=_OWNER_ID,
                authority_freshness=freshness,
            )
            if action == "run":
                if task_text is None:
                    raise ValueError("task text is required")
                return _task_run_summary(
                    await administration.run(
                        authentication,
                        profile_name=profile.profile_name,
                        workspace_name=profile.workspace_name,
                        task_text=task_text,
                    )
                )
            if run_id is None:
                raise ValueError("run id is required")
            if action == "status":
                return await administration.status(authentication, run_id=run_id)
            if action == "cancel":
                return _task_run_summary(await administration.cancel(authentication, run_id=run_id))
            if action == "resume":
                if context_resupply is None:
                    raise ValueError("resume context resupply is required")
                return _task_run_summary(
                    await administration.resume(
                        authentication,
                        run_id=run_id,
                        context_resupply=context_resupply,
                    )
                )
            raise RuntimeError("unknown task action")
        finally:
            credential = ""
            if access is not None and session_token is not None:
                try:
                    await access.logout(session_token)
                finally:
                    session_token = None
            await runtime.stop()


def _task_run_summary(summary: TaskStatusSummary) -> TaskRunSummary:
    # Import lazily so task_cli can lazily import this module without a module-init cycle.
    from phoenix_os.control_plane.task_cli import TaskRunSummary

    return TaskRunSummary(
        schema_version=summary.schema_version,
        task_id=summary.task_id,
        run_id=summary.run_id,
        status=summary.run_state,
    )


def _run_async[T](awaitable: Coroutine[Any, Any, T]) -> T:
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(awaitable)
    raise RuntimeError("task CLI bridge cannot run inside an active event loop")


def _read_operator_credential() -> str:
    credential = getpass.getpass(_CREDENTIAL_PROMPT)
    if not isinstance(credential, str) or not credential or credential != credential.strip():
        raise PermissionError("operator credential rejected")
    return credential


async def _profile_for_existing_run(
    configuration: OperatorConfiguration,
    run_id: str,
) -> OperatorProfileConfiguration:
    runtime_configuration = _runtime_configuration(configuration)
    store = SQLiteDurableRunStore(runtime_configuration.durable_state_path)
    try:
        checkpoint = await store.get_current(integrated_durable_run_id(AgentRunId(UUID(run_id))))
    finally:
        await store.close()
    if checkpoint is None:
        raise KeyError(run_id)
    matches = tuple(
        profile
        for profile in configuration.profiles
        if _agent_id(profile) == checkpoint.metadata.agent_id
    )
    if len(matches) != 1:
        raise ValueError("existing task profile cannot be resolved uniquely")
    return matches[0]


async def _compose_runtime(
    configuration: OperatorConfiguration,
    operator_profile: OperatorProfileConfiguration,
) -> _RuntimeSurface:
    runtime_configuration = _runtime_configuration(configuration)
    if configuration.inference is None:
        raise ValueError("task runtime requires inference configuration")
    operator_model = configuration.model(operator_profile.model_name)
    workspace = configuration.workspace(operator_profile.workspace_name)

    identity = await _checkout_identity(
        runtime_configuration.durable_state_path,
        workspace,
    )
    checkout = RegisteredDevelopmentCheckoutAdapter(
        workspace_id=identity.workspace_id,
        workspace_name=workspace.workspace_name,
        generation=identity.generation,
        root=Path(workspace.root),
        read_prefixes=workspace.read_prefixes,
    )

    policy = PolicyEngine()
    execution_profile_id = IntegratedExecutionProfileId(
        f"rfc0039-{_stable_token(operator_profile.profile_name)}"
    )
    execution_profile = integrated_development_checkout_dogfood_profile(
        profile_id=execution_profile_id,
        generation=IntegratedExecutionProfileGeneration(identity.generation),
        agent_id=_agent_id(operator_profile),
        data_flow_policy=IntegratedDataFlowPolicy(),
        registration=checkout.registration,
        durability_profile=_DURABILITY_PROFILE,
        allow_workspace_patch=operator_profile.allow_workspace_patch,
    ).execution_profile
    guard = IntegratedAgentExecutionGuard(execution_profile)
    planner = IntegratedPlanner(execution_profile, provenance_provider=guard)
    authorizer = PolicyEngineCheckoutWorkspaceAuthorizer(policy)
    composition = _tool_composition(
        execution_profile,
        checkout,
        authorizer,
        guard,
        planner,
    )
    service_configuration = AgentServiceConfiguration(
        agent_id=execution_profile.agent_id,
        provider_id=operator_model.descriptor.provider_id,
        model_id=operator_model.descriptor.model_id,
        tools=tuple(AgentToolConfiguration(item) for item in composition.descriptors),
    )

    compatibility_registry = ToolRegistry()
    for registration in composition.registrations:
        compatibility_registry.register_tool(
            registration.descriptor,
            resolver=registration.resolver,
            adapter=registration.adapter,
        )
    compatibility_registry.seal()
    provider_configuration = _provider_configuration(configuration, operator_model)
    compatibility_policy = create_ollama_metadata_only_durable_compatibility_policy(
        configuration=service_configuration,
        registry=compatibility_registry,
        provider_configuration=provider_configuration,
        binding=operator_model.binding,
    )
    compatibility_validator = StaticDurableCompatibilityValidator((compatibility_policy,))

    generic_configuration = await ConfigLoader(
        ConfigSchema(()),
        (MappingConfigSource({}),),
    ).load()
    events = EventBus()
    kernel = Kernel(
        router=Router(),
        authorizer=AllowAllAuthorizer(),
        events=events,
    )
    capabilities = CapabilityRegistry(events=events)
    state_store = SQLiteStateStore(
        runtime_configuration.durable_state_path,
        events=events,
    )
    operator_registry = StateControlPlaneOperatorRegistry(state_store)
    providers = _ollama_providers(configuration)

    runtime = await RuntimeAssembler(
        kernel=kernel,
        events=events,
        capabilities=capabilities,
        configuration=generic_configuration,
        policy=policy,
        state=state_store,
        inference_enabled=True,
        inference_configuration=configuration.inference,
        inference_providers=providers,
        agent_enabled=True,
        agent_configuration=service_configuration,
        agent_execution_interceptor=guard,
        agent_tool_resolvers=composition.runtime_resolvers,
        agent_tool_adapters=composition.adapters,
        agent_durable_enabled=True,
        agent_durable_sqlite_path=runtime_configuration.durable_state_path,
        agent_durable_compatibility_validator=compatibility_validator,
        agent_durable_metadata_projector=IntegratedDurableCheckpointMetadataProjector(
            execution_guard=guard,
            planner=planner,
        ),
        agent_durable_history_validator=create_integrated_checkout_durable_history_validator(),
        agent_integrated_task_runtime_enabled=True,
        agent_integrated_profile=execution_profile,
        agent_integrated_composition=composition,
        agent_integrated_compatibility_policy=compatibility_policy,
        agent_integrated_actor_id=_ACTOR_ID,
        agent_integrated_owner_id=_OWNER_ID,
        agent_integrated_operator_configuration=configuration,
        agent_integrated_operator_profile=operator_profile,
        control_plane_operator_registry=operator_registry,
    ).assemble()
    return _RuntimeSurface(runtime=runtime, policy=policy, profile=operator_profile)


def _tool_composition(
    execution_profile: IntegratedExecutionProfile,
    checkout: RegisteredDevelopmentCheckoutAdapter,
    authorizer: PolicyEngineCheckoutWorkspaceAuthorizer,
    guard: IntegratedAgentExecutionGuard,
    planner: IntegratedPlanner,
) -> IntegratedAgentToolComposition:
    plan_binding = execution_profile.require_tool_binding(INTEGRATED_PLAN_UPDATE_TOOL_ID)
    if not isinstance(plan_binding, IntegratedLocalTransformBinding):
        raise TypeError("plan binding is invalid")
    list_registration, read_registration = integrated_checkout_tool_registrations(
        _bridge(execution_profile, CHECKOUT_LIST_TOOL_ID),
        _bridge(execution_profile, CHECKOUT_READ_TOOL_ID),
        checkout,
        authorizer,
    )
    registrations = [
        integrated_plan_update_registration(plan_binding, planner),
        list_registration,
        read_registration,
    ]
    patch_tool_id = CHECKOUT_PATCH_TOOL_ID
    if patch_tool_id in execution_profile.tool_ids:
        registrations.append(
            integrated_checkout_patch_tool_registration(
                _bridge(execution_profile, patch_tool_id),
                checkout,
                authorizer,
            )
        )
    return IntegratedAgentToolComposition(execution_profile, tuple(registrations))


def _bridge(
    execution_profile: IntegratedExecutionProfile, tool_id: ToolId
) -> IntegratedDownstreamBridgeBinding:
    binding = execution_profile.require_tool_binding(tool_id)
    if not isinstance(binding, IntegratedDownstreamBridgeBinding):
        raise TypeError("integrated checkout binding is invalid")
    return binding


async def _checkout_identity(
    path: Path, workspace: OperatorWorkspaceConfiguration
) -> CheckoutRegistrationIdentity:
    key = hashlib.sha256(f"rfc0039-workspace:{workspace.workspace_name}".encode()).hexdigest()
    document = json.dumps(
        {
            "workspace_name": workspace.workspace_name,
            "kind": workspace.kind,
            "root": workspace.root,
            "read_prefixes": list(workspace.read_prefixes),
            "patch_prefixes": list(workspace.patch_prefixes),
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    digest = hashlib.sha256(document).hexdigest()
    store = SQLiteDurableRunStore(path)
    try:
        return await store.resolve_checkout_registration_identity(
            registration_key=key,
            registration_digest=digest,
        )
    finally:
        await store.close()


def _provider_configuration(
    configuration: OperatorConfiguration,
    model: OperatorModelConfiguration,
) -> InferenceProviderConfiguration:
    if configuration.inference is None:
        raise ValueError("inference configuration is absent")
    for provider in configuration.inference.providers:
        if provider.provider_id == model.descriptor.provider_id:
            return provider
    raise KeyError(str(model.descriptor.provider_id))


def _ollama_providers(configuration: OperatorConfiguration) -> tuple[OllamaModelProvider, ...]:
    if configuration.inference is None:
        raise ValueError("inference configuration is absent")
    providers: list[OllamaModelProvider] = []
    for provider_configuration in configuration.inference.providers:
        bindings = tuple(
            model.binding
            for model in configuration.models
            if model.descriptor.provider_id == provider_configuration.provider_id
        )
        if bindings:
            providers.append(OllamaModelProvider(provider_configuration, bindings))
    if not providers:
        raise ValueError("no Ollama provider is configured")
    return tuple(providers)


def _runtime_configuration(
    configuration: OperatorConfiguration,
) -> OperatorRuntimeConfiguration:
    if configuration.runtime is None:
        raise ValueError("durable runtime configuration is required")
    return configuration.runtime


def _agent_id(profile: OperatorProfileConfiguration) -> AgentId:
    return AgentId(f"rfc0039-{_stable_token(profile.profile_name)}")


def _stable_token(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:24]
