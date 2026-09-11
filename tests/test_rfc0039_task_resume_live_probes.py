from __future__ import annotations

import hashlib
from collections.abc import Awaitable
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast
from uuid import UUID

import pytest

from phoenix_os.agent.checkout_agent_tools import (
    CHECKOUT_LIST_TOOL_ID,
    CHECKOUT_READ_TOOL_ID,
)
from phoenix_os.agent.checkout_authorization import (
    CheckoutListAuthorizationRequest,
    CheckoutReadAuthorizationRequest,
)
from phoenix_os.agent.checkout_workspace import (
    RegisteredDevelopmentCheckoutAdapter,
    checkout_path_resource,
    checkout_prefix_resource,
)
from phoenix_os.agent.contracts import (
    AgentId,
    AgentMessage,
    AgentMessageRole,
    AgentRunId,
    AgentRunRequest,
    ToolCallId,
    ToolId,
    canonical_agent_json_bytes,
    freeze_agent_json_object,
)
from phoenix_os.agent.durable_contracts import CheckpointNextOperation, DurableRunStatus
from phoenix_os.control_plane import task_resume_live_probes as live_probe_module
from phoenix_os.control_plane.task_resume_live_probes import (
    compose_server_owned_task_resume_live_probes,
)
from phoenix_os.control_plane.task_runtime_composition import (
    ServerOwnedDurableIntegratedTaskRuntime,
)
from phoenix_os.inference import ModelId, ModelProviderId
from phoenix_os.integrated_agent.composition import (
    IntegratedAgentToolComposition,
    integrated_checkout_tool_registrations,
    integrated_development_checkout_dogfood_profile,
    integrated_plan_update_registration,
)
from phoenix_os.integrated_agent.contracts import (
    IntegratedDataFlowPolicy,
    IntegratedDataProvenance,
    IntegratedDataProvenanceAtom,
    IntegratedDataSourceKind,
    IntegratedExecutionProfileGeneration,
    IntegratedExecutionProfileId,
    IntegratedTaskId,
    IntegratedTaskRequest,
)
from phoenix_os.integrated_agent.durable_run import integrated_durable_run_id
from phoenix_os.integrated_agent.planning import IntegratedPlanner
from phoenix_os.integrated_agent.profiles import (
    INTEGRATED_PLAN_UPDATE_TOOL_ID,
    IntegratedDownstreamBridgeBinding,
    IntegratedExecutionProfile,
    IntegratedLocalTransformBinding,
)
from phoenix_os.policy import SecurityContext

_AGENT_ID = AgentId("rfc0039-resume-live-probe")

_PROFILE_ID = IntegratedExecutionProfileId("rfc0039-resume-live-probe")

_PROFILE_GENERATION = IntegratedExecutionProfileGeneration(7)

_WORKSPACE_ID = UUID("40e3df88-bdfb-47b8-aee0-4ac850592fb9")

_RUN_ID = AgentRunId(UUID("20000000-0000-4000-8000-000000000039"))

_TASK_ID = IntegratedTaskId(UUID("70000000-0000-4000-8000-000000000039"))

_STEP_ID = UUID("30000000-0000-4000-8000-000000000039")

_CALL_ID = ToolCallId(UUID("40000000-0000-4000-8000-000000000039"))


class _CheckoutAuthorizer:
    async def authorize_list(
        self,
        request: CheckoutListAuthorizationRequest,
        context: SecurityContext,
    ) -> None:

        del request, context

    async def authorize_read(
        self,
        request: CheckoutReadAuthorizationRequest,
        context: SecurityContext,
    ) -> None:

        del request, context


class _Store:
    def __init__(self) -> None:

        self.current: object | None = None

        self.calls: list[object] = []

    async def get_current(self, run_id: object) -> object | None:

        self.calls.append(run_id)

        return self.current


async def _resolve_probe(value: bool | Awaitable[bool]) -> bool:
    if isinstance(value, bool):
        return value
    return await value


def _profile(checkout: RegisteredDevelopmentCheckoutAdapter) -> IntegratedExecutionProfile:

    return integrated_development_checkout_dogfood_profile(
        profile_id=_PROFILE_ID,
        generation=_PROFILE_GENERATION,
        agent_id=_AGENT_ID,
        data_flow_policy=IntegratedDataFlowPolicy(),
        registration=checkout.registration,
        durability_profile="rfc0039-development-checkout",
    ).execution_profile


def _bridge(
    profile: IntegratedExecutionProfile,
    tool_id: ToolId,
) -> IntegratedDownstreamBridgeBinding:

    binding = profile.require_tool_binding(tool_id)

    assert isinstance(binding, IntegratedDownstreamBridgeBinding)

    return binding


def _fixture(
    tmp_path: Path,
    store: _Store,
) -> tuple[
    ServerOwnedDurableIntegratedTaskRuntime,
    RegisteredDevelopmentCheckoutAdapter,
    Path,
    IntegratedTaskRequest,
    AgentRunRequest,
]:

    root = tmp_path / "checkout"

    (root / "src").mkdir(parents=True)

    target = root / "src" / "readme.txt"

    target.write_bytes(b"hello\n")

    checkout = RegisteredDevelopmentCheckoutAdapter(
        workspace_id=_WORKSPACE_ID,
        workspace_name="rfc0039-development",
        generation=7,
        root=root,
        read_prefixes=("src",),
    )

    profile = _profile(checkout)

    planner = IntegratedPlanner(profile)

    plan_binding = profile.require_tool_binding(INTEGRATED_PLAN_UPDATE_TOOL_ID)

    assert isinstance(plan_binding, IntegratedLocalTransformBinding)

    plan_registration = integrated_plan_update_registration(plan_binding, planner)

    list_registration, read_registration = integrated_checkout_tool_registrations(
        _bridge(profile, CHECKOUT_LIST_TOOL_ID),
        _bridge(profile, CHECKOUT_READ_TOOL_ID),
        checkout,
        _CheckoutAuthorizer(),
    )

    composition = IntegratedAgentToolComposition(
        profile,
        (
            plan_registration,
            list_registration,
            read_registration,
        ),
    )

    task = IntegratedTaskRequest(
        task_id=_TASK_ID,
        objective="Continue the exact reviewed development checkout task.",
    )

    request = AgentRunRequest(
        agent_id=_AGENT_ID,
        provider_id=ModelProviderId("local"),
        model_id=ModelId("chat"),
        messages=(AgentMessage(AgentMessageRole.USER, "continue"),),
        run_id=_RUN_ID,
    )

    owner = ServerOwnedDurableIntegratedTaskRuntime(
        service=cast(Any, object()),
        durable_stack=cast(Any, SimpleNamespace(store=store)),
        profile=profile,
        execution_guard=cast(Any, object()),
        compatibility_policy=cast(Any, object()),
        composition=composition,
        admission=cast(Any, object()),
        root_provider=cast(Any, object()),
        coordinator=cast(Any, object()),
        planner=planner,
        runtime=cast(Any, object()),
        request_mapper=cast(Any, object()),
    )

    return owner, checkout, target, task, request


def _task_atom(task: IntegratedTaskRequest) -> IntegratedDataProvenanceAtom:

    return IntegratedDataProvenanceAtom(
        source_kind=IntegratedDataSourceKind.USER_TASK,
        source_binding=f"integrated-task:{task.task_id}",
        freshness_bindings=(f"task-digest:{task.digest}",),
    )


@pytest.mark.asyncio
async def test_cancellation_probe_reads_exact_durable_run_and_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:

    store = _Store()

    owner, _checkout, _target, task, request = _fixture(tmp_path, store)

    probes = compose_server_owned_task_resume_live_probes(
        owner,
        task=task,
        request=request,
    )

    assert await _resolve_probe(probes.cancellation_probe(_RUN_ID))

    assert store.calls == [integrated_durable_run_id(_RUN_ID)]

    current = SimpleNamespace(
        agent_run_id=_RUN_ID,
        durable_run_id=integrated_durable_run_id(_RUN_ID),
        status=DurableRunStatus.PAUSED_OPERATOR,
        metadata=SimpleNamespace(
            next_operation=CheckpointNextOperation.MODEL_TURN,
            active_attempt=None,
        ),
    )

    store.current = current

    monkeypatch.setattr(
        live_probe_module,
        "durable_cancellation_requested",
        lambda _checkpoint: False,
    )

    assert not await _resolve_probe(probes.cancellation_probe(_RUN_ID))

    monkeypatch.setattr(
        live_probe_module,
        "durable_cancellation_requested",
        lambda _checkpoint: True,
    )

    assert await _resolve_probe(probes.cancellation_probe(_RUN_ID))

    assert await _resolve_probe(probes.cancellation_probe(AgentRunId()))

    assert store.calls == [
        integrated_durable_run_id(_RUN_ID),
        integrated_durable_run_id(_RUN_ID),
        integrated_durable_run_id(_RUN_ID),
    ]


@pytest.mark.asyncio
async def test_context_probe_revalidates_internal_and_checkout_currentness(
    tmp_path: Path,
) -> None:

    store = _Store()

    owner, checkout, target, task, request = _fixture(tmp_path, store)

    probes = compose_server_owned_task_resume_live_probes(
        owner,
        task=task,
        request=request,
    )

    registration = checkout.registration

    listed = await checkout.list("src", max_entries=8)

    listing_output = freeze_agent_json_object(
        {
            "workspace_id": str(listed.workspace_id),
            "registration_generation": listed.registration_generation,
            "prefix": listed.prefix,
            "entries": [
                {
                    "logical_path": entry.logical_path,
                    "category": entry.category.value,
                }
                for entry in listed.entries
            ],
            "excluded_count": listed.excluded_count,
        }
    )

    listing_digest = (
        "sha256:" + hashlib.sha256(canonical_agent_json_bytes(listing_output)).hexdigest()
    )

    snapshot = (await checkout.read("src/readme.txt", run_id=_RUN_ID)).snapshot

    list_atom = IntegratedDataProvenanceAtom(
        source_kind=IntegratedDataSourceKind.WORKSPACE,
        source_binding=checkout_prefix_resource(registration, "src"),
        freshness_bindings=(
            f"tool-call:{_CALL_ID}",
            f"registration-generation:{registration.generation}",
            f"root-identity:{registration.root_identity}",
            "operation:list",
            "list-limit:8",
            f"listing-digest:{listing_digest}",
        ),
    )

    read_atom = IntegratedDataProvenanceAtom(
        source_kind=IntegratedDataSourceKind.WORKSPACE,
        source_binding=checkout_path_resource(registration, "src/readme.txt"),
        freshness_bindings=(
            f"tool-call:{_CALL_ID}",
            f"registration-generation:{registration.generation}",
            f"root-identity:{registration.root_identity}",
            "operation:read",
            f"file-identity:{snapshot.file_identity}",
            f"content-digest:{snapshot.content_digest}",
            f"byte-length:{snapshot.byte_length}",
        ),
    )

    model_atom = IntegratedDataProvenanceAtom(
        source_kind=IntegratedDataSourceKind.MODEL_OUTPUT,
        source_binding=f"agent-run:{_RUN_ID}/step:{_STEP_ID}",
        freshness_bindings=(f"integrated-profile:{_PROFILE_ID}:{_PROFILE_GENERATION}",),
    )

    tool_atom = IntegratedDataProvenanceAtom(
        source_kind=IntegratedDataSourceKind.TOOL_RESULT,
        source_binding=(
            f"agent-run:{_RUN_ID}/step:{_STEP_ID}/tool:{CHECKOUT_READ_TOOL_ID}/call:{_CALL_ID}"
        ),
        freshness_bindings=(f"tool:{CHECKOUT_READ_TOOL_ID}",),
    )

    provenance = IntegratedDataProvenance(
        (
            _task_atom(task),
            list_atom,
            read_atom,
            model_atom,
            tool_atom,
        )
    )

    assert await _resolve_probe(probes.context_freshness_probe(provenance))

    target.write_bytes(b"HELLO\n")

    assert not await _resolve_probe(probes.context_freshness_probe(provenance))


@pytest.mark.asyncio
async def test_context_probe_rejects_unsupported_external_provenance(
    tmp_path: Path,
) -> None:

    store = _Store()

    owner, _checkout, _target, task, request = _fixture(tmp_path, store)

    probes = compose_server_owned_task_resume_live_probes(
        owner,
        task=task,
        request=request,
    )

    provenance = IntegratedDataProvenance(
        (
            _task_atom(task),
            IntegratedDataProvenanceAtom(
                source_kind=IntegratedDataSourceKind.MEMORY,
                source_binding="agent-memory:unsupported",
                freshness_bindings=("version:1",),
            ),
        )
    )

    assert not await _resolve_probe(probes.context_freshness_probe(provenance))
