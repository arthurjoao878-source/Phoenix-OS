from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

import pytest

from phoenix_os.agent.configuration import AgentServiceConfiguration
from phoenix_os.agent.contracts import (
    AgentId,
    AgentLimits,
    AgentMessage,
    AgentMessageRole,
    AgentRunId,
)
from phoenix_os.control_plane.operator_configuration import (
    OperatorConfiguration,
    OperatorModelConfiguration,
    OperatorProfileConfiguration,
    OperatorRuntimeConfiguration,
    OperatorWorkspaceConfiguration,
)
from phoenix_os.control_plane.task_request_mapping import (
    ServerOwnedTaskRequestMapper,
    TaskRequestMappingError,
)
from phoenix_os.inference.contracts import ModelCapabilities, ModelDescriptor, ModelId
from phoenix_os.inference.ollama import OLLAMA_PROVIDER_ID, OllamaModelBinding
from phoenix_os.integrated_agent.contracts import IntegratedTaskId

_NOW = datetime(2026, 9, 8, 12, tzinfo=UTC)
_TASK_ID = IntegratedTaskId(UUID("10000000-0000-0000-0000-000000000039"))
_RUN_ID = AgentRunId(UUID("20000000-0000-0000-0000-000000000039"))


def _operator_model(model_name: str = "dev") -> OperatorModelConfiguration:
    descriptor = ModelDescriptor(
        provider_id=OLLAMA_PROVIDER_ID,
        model_id=ModelId(model_name),
        provider_model_name="qwen3:4b-instruct",
        capabilities=ModelCapabilities(complete=True, streaming=True),
    )
    return OperatorModelConfiguration(
        model_name=model_name,
        provider_name="ollama-local",
        provider_model_name=descriptor.provider_model_name,
        expected_digest=None,
        descriptor=descriptor,
        binding=OllamaModelBinding(descriptor),
    )


def _profile(
    *,
    workspace_name: str = "project",
    context_paths: tuple[str, ...] = (),
    allow_workspace_patch: bool = False,
) -> OperatorProfileConfiguration:
    return OperatorProfileConfiguration(
        profile_name="development",
        model_name="dev",
        workspace_name=workspace_name,
        context_paths=context_paths,
        allow_workspace_patch=allow_workspace_patch,
    )


def _configuration(
    *,
    profiles: tuple[OperatorProfileConfiguration, ...] | None = None,
    runtime: bool = True,
) -> OperatorConfiguration:
    return OperatorConfiguration(
        source=Path("phoenix.toml"),
        runtime=(
            OperatorRuntimeConfiguration(durable_state_path=Path("agent-durable.sqlite3"))
            if runtime
            else None
        ),
        inference=None,
        models=(_operator_model(),),
        workspaces=(
            OperatorWorkspaceConfiguration(
                workspace_name="project",
                kind="development-checkout",
                root="C:/Projects/example",
                read_prefixes=("src", "tests"),
                patch_prefixes=(),
            ),
        ),
        profiles=(_profile(),) if profiles is None else profiles,
    )


def _service_configuration(*, model_name: str = "dev") -> AgentServiceConfiguration:
    return AgentServiceConfiguration(
        agent_id=AgentId("assistant"),
        provider_id=OLLAMA_PROVIDER_ID,
        model_id=ModelId(model_name),
        limits=AgentLimits(max_model_turns=4, max_tool_calls=2),
    )


def _mapper(*, model_name: str = "dev") -> ServerOwnedTaskRequestMapper:
    return ServerOwnedTaskRequestMapper(
        _service_configuration(model_name=model_name),
        clock=lambda: _NOW,
        task_id_factory=lambda: _TASK_ID,
        run_id_factory=lambda: _RUN_ID,
    )


def test_mapper_uses_only_runtime_owned_identity_and_exact_selected_configuration() -> None:
    configuration = _configuration()
    mapper = _mapper()
    task_text = "inspect the reviewed checkout"

    mapped = mapper.map(
        configuration,
        profile_name="development",
        workspace_name="project",
        task_text=task_text,
    )

    assert mapped.operator_profile is configuration.profiles[0]
    assert mapped.operator_model is configuration.models[0]
    assert mapped.workspace is configuration.workspaces[0]
    assert mapped.task.task_id == _TASK_ID
    assert mapped.task.objective == task_text
    assert mapped.task.input_references == ()
    assert mapped.run_request.agent_id == mapper.service_configuration.agent_id
    assert mapped.run_request.provider_id == mapper.service_configuration.provider_id
    assert mapped.run_request.model_id == mapper.service_configuration.model_id
    assert mapped.run_request.run_id == _RUN_ID
    assert mapped.run_request.messages == (AgentMessage(AgentMessageRole.USER, task_text),)
    assert mapped.run_request.limits is mapper.service_configuration.limits
    assert mapped.run_request.created_at == _NOW
    assert mapped.run_request.deadline == _NOW + timedelta(minutes=20)
    assert task_text not in repr(mapped)


def test_mapper_rejects_workspace_substitution_before_request_creation() -> None:
    with pytest.raises(TaskRequestMappingError):
        _mapper().map(
            _configuration(),
            profile_name="development",
            workspace_name="other",
            task_text="task",
        )


@pytest.mark.parametrize(
    ("profile", "runtime"),
    (
        (_profile(context_paths=("src/example.py",)), True),
        (_profile(allow_workspace_patch=True), True),
        (_profile(), False),
    ),
)
def test_mapper_fails_closed_for_not_yet_composed_surfaces(
    profile: OperatorProfileConfiguration,
    runtime: bool,
) -> None:
    with pytest.raises(TaskRequestMappingError):
        _mapper().map(
            _configuration(profiles=(profile,), runtime=runtime),
            profile_name="development",
            workspace_name="project",
            task_text="task",
        )


def test_mapper_rejects_model_substitution_against_runtime_owned_agent() -> None:
    with pytest.raises(TaskRequestMappingError):
        _mapper(model_name="other").map(
            _configuration(),
            profile_name="development",
            workspace_name="project",
            task_text="task",
        )


def test_mapper_rejects_ambiguous_profile_selection() -> None:
    profile = _profile()
    with pytest.raises(TaskRequestMappingError):
        _mapper().map(
            _configuration(profiles=(profile, profile)),
            profile_name="development",
            workspace_name="project",
            task_text="task",
        )


def test_mapper_translates_invalid_task_text_without_echoing_content() -> None:
    secret = "sensitive-task-text"
    oversized = secret + ("x" * 70_000)
    with pytest.raises(TaskRequestMappingError) as error:
        _mapper().map(
            _configuration(),
            profile_name="development",
            workspace_name="project",
            task_text=oversized,
        )

    assert secret not in str(error.value)


def test_mapper_rejects_noncanonical_references() -> None:
    with pytest.raises(TaskRequestMappingError):
        _mapper().map(
            _configuration(),
            profile_name=" development",
            workspace_name="project",
            task_text="task",
        )
