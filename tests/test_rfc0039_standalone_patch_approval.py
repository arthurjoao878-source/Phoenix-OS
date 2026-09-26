from __future__ import annotations

import inspect
import io
import sys
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

import pytest

from phoenix_os.agent.approval import InMemoryToolApprovalService
from phoenix_os.agent.checkout_patch_agent_tool import (
    CHECKOUT_PATCH_TOOL_ID,
    checkout_patch_tool_descriptor,
)
from phoenix_os.agent.configuration import AgentServiceConfiguration
from phoenix_os.agent.contracts import (
    AgentId,
    AgentRunId,
    AgentStepId,
    ToolCallId,
    ToolInvocationRequest,
)
from phoenix_os.agent.workspace_authorization import WORKSPACE_PATCH_ACTION
from phoenix_os.control_plane import task_runtime_bootstrap as bootstrap
from phoenix_os.control_plane.auth import (
    CONTROL_PLANE_READ_PERMISSION,
    ControlPlanePrincipal,
)
from phoenix_os.control_plane.authority_integration import (
    control_plane_authority_security_context,
)
from phoenix_os.control_plane.durable_session_access import (
    ControlPlaneDurableSessionAuthentication,
)
from phoenix_os.control_plane.operator_configuration import (
    OperatorConfiguration,
    load_operator_configuration,
)
from phoenix_os.control_plane.task_request_mapping import (
    ServerOwnedTaskRequestMapper,
    TaskRequestMappingError,
)
from phoenix_os.control_plane.task_runtime_composition import (
    ServerOwnedDurableIntegratedTaskRuntime,
)
from phoenix_os.integrated_agent.contracts import IntegratedTaskId


def _write_configuration(
    tmp_path: Path,
    *,
    context_paths: tuple[str, ...] = (),
    allow_workspace_patch: bool = True,
) -> OperatorConfiguration:
    workspace = tmp_path / "workspace"
    source = workspace / "src"
    source.mkdir(parents=True)
    (source / "example.py").write_text("VALUE = 1\n", encoding="utf-8")
    state = tmp_path / "state" / "agent-durable.sqlite3"
    state.parent.mkdir()

    context_document = ", ".join(f'"{item}"' for item in context_paths)
    config = tmp_path / "phoenix.toml"
    config.write_text(
        "\n".join(
            (
                "schema_version = 1",
                "",
                "[runtime]",
                f'durable_state_path = "{state.as_posix()}"',
                "",
                "[providers.ollama-local]",
                'kind = "ollama-local"',
                "",
                "[models.dev]",
                'provider = "ollama-local"',
                'provider_model_name = "qwen3:4b-instruct"',
                f'expected_digest = "{"0" * 64}"',
                "",
                "[workspaces.project]",
                'kind = "development-checkout"',
                f'root = "{workspace.as_posix()}"',
                'read_prefixes = ["src"]',
                'patch_prefixes = ["src"]',
                "",
                "[profiles.development]",
                'model = "dev"',
                'workspace = "project"',
                f"context_paths = [{context_document}]",
                f"allow_workspace_patch = {str(allow_workspace_patch).lower()}",
                "",
            )
        ),
        encoding="utf-8",
    )
    return load_operator_configuration(config)


def _mapper(configuration: OperatorConfiguration) -> ServerOwnedTaskRequestMapper:
    model = configuration.models[0]
    return ServerOwnedTaskRequestMapper(
        AgentServiceConfiguration(
            agent_id=AgentId("rfc0039-patch-test"),
            provider_id=model.descriptor.provider_id,
            model_id=model.descriptor.model_id,
        ),
        clock=lambda: datetime(2026, 9, 26, 6, tzinfo=UTC),
        task_id_factory=lambda: IntegratedTaskId(UUID("10000000-0000-4000-8000-000000000001")),
        run_id_factory=lambda: AgentRunId(UUID("20000000-0000-4000-8000-000000000001")),
    )


def _authentication() -> ControlPlaneDurableSessionAuthentication:
    now = datetime(2026, 9, 26, 6, tzinfo=UTC)
    return ControlPlaneDurableSessionAuthentication(
        session_id=UUID("30000000-0000-4000-8000-000000000001"),
        operator_id=UUID("40000000-0000-4000-8000-000000000001"),
        principal=ControlPlanePrincipal(
            "local-maintainer",
            frozenset(
                {
                    CONTROL_PLANE_READ_PERMISSION,
                    WORKSPACE_PATCH_ACTION,
                }
            ),
        ),
        generation=1,
        authenticated_at=now,
        absolute_expires_at=now + timedelta(hours=1),
        idle_expires_at=now + timedelta(minutes=30),
    )


def _patch_request(*, now: datetime, call_id: ToolCallId | None = None) -> ToolInvocationRequest:
    return ToolInvocationRequest(
        agent_id=AgentId("rfc0039-patch-test"),
        run_id=AgentRunId(UUID("50000000-0000-4000-8000-000000000001")),
        step_id=AgentStepId(UUID("60000000-0000-4000-8000-000000000001")),
        call_id=call_id or ToolCallId(UUID("70000000-0000-4000-8000-000000000001")),
        tool_id=CHECKOUT_PATCH_TOOL_ID,
        arguments={"logical_path": "src/example.py"},
        resolved_resource="checkout:project",
        created_at=now,
        deadline=now + timedelta(minutes=1),
    )


def test_task_request_mapper_allows_patch_profile_when_context_paths_are_empty(
    tmp_path: Path,
) -> None:
    configuration = _write_configuration(tmp_path)
    mapped = _mapper(configuration).map(
        configuration,
        profile_name="development",
        workspace_name="project",
        task_text="review a bounded source change",
    )

    assert mapped.operator_profile.allow_workspace_patch
    assert mapped.operator_profile.context_paths == ()


def test_task_request_mapper_keeps_context_paths_fail_closed(tmp_path: Path) -> None:
    configuration = _write_configuration(
        tmp_path,
        context_paths=("src/example.py",),
    )

    with pytest.raises(TaskRequestMappingError):
        _mapper(configuration).map(
            configuration,
            profile_name="development",
            workspace_name="project",
            task_text="review a bounded source change",
        )


@pytest.mark.asyncio
async def test_patch_profile_composes_exact_approval_and_patch_policy_targets(
    tmp_path: Path,
) -> None:
    configuration = _write_configuration(tmp_path)
    profile = configuration.profiles[0]

    surface = await bootstrap._compose_runtime(configuration, profile)
    runtime_started = False
    try:
        assert surface.approval_resolver is not None
        assert isinstance(
            surface.approval_resolver.approval_service,
            InMemoryToolApprovalService,
        )

        owner = surface.runtime.service("control_plane.task-runtime")
        assert isinstance(owner, ServerOwnedDurableIntegratedTaskRuntime)

        mapped = owner.request_mapper.map(
            configuration,
            profile_name="development",
            workspace_name="project",
            task_text="review a bounded source change",
        )
        targets = owner.derive_policy_targets(mapped)
        assert CHECKOUT_PATCH_TOOL_ID in {item.tool_id for item in targets.tools}
        assert targets.checkout is not None
        assert tuple(targets.checkout.registration.read_prefixes) == ("src",)
        assert tuple(targets.checkout.registration.patch_prefixes) == ("src",)

        await surface.runtime.start()
        runtime_started = True
        assert (
            surface.runtime.service("agent.approvals") is surface.approval_resolver.approval_service
        )
    finally:
        if runtime_started:
            await surface.runtime.stop()


@pytest.mark.asyncio
async def test_standalone_patch_resolver_requires_prepare_then_exact_apply(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    now = datetime(2026, 9, 26, 6, tzinfo=UTC)
    service = InMemoryToolApprovalService(clock=lambda: now)
    resolver = bootstrap._StandalonePatchApprovalResolver(service)
    authentication = _authentication()
    context = control_plane_authority_security_context(authentication)
    resolver.bind(authentication)
    descriptor = checkout_patch_tool_descriptor()

    generic_request = _patch_request(now=now)
    generic_challenge = await service.request(generic_request, descriptor, context)
    monkeypatch.setattr(sys, "stdin", io.StringIO("PREPARE\n"))

    generic_evidence = await resolver.resolve(generic_challenge)
    await service.verify_and_consume(
        generic_evidence,
        generic_request,
        descriptor,
        context,
    )

    prepared_request = replace(
        generic_request,
        call_id=ToolCallId(UUID("70000000-0000-4000-8000-000000000002")),
        arguments={
            "approval_binding_schema": "rfc0039.workspace.patch.prepared-approval.v1",
            "preparation_digest": "sha256:" + ("a" * 64),
            "review_diff_digest": "sha256:" + ("b" * 64),
        },
    )
    prepared_challenge = await service.request(prepared_request, descriptor, context)
    trusted_diff = (
        "--- a/src/example.py\n"
        "+++ b/src/example.py\n"
        "@@ -1 +1,2 @@\n"
        " VALUE = 1\n"
        "+# reviewed change\n"
    )
    monkeypatch.setattr(sys, "stdin", io.StringIO("APPLY\n"))

    prepared_evidence = await resolver.resolve_prepared_patch(
        prepared_challenge,
        logical_path="src/example.py",
        preparation_digest="sha256:" + ("a" * 64),
        unified_diff=trusted_diff,
    )
    await service.verify_and_consume(
        prepared_evidence,
        prepared_request,
        descriptor,
        context,
    )

    captured = capsys.readouterr()
    assert "Type PREPARE" in captured.err
    assert "BEGIN TRUSTED BOUNDED DIFF" in captured.err
    assert "src/example.py" in captured.err
    assert "# reviewed change" in captured.err
    assert "Type APPLY" in captured.err

    resolver.unbind()
    await service.close()


def test_patch_review_renderer_escapes_terminal_control_characters() -> None:
    rendered = bootstrap._terminal_safe_review_text("line\x1b[31mred\x1b[0m\nnext\u202eline\n")

    assert "\x1b" not in rendered
    assert "\u202e" not in rendered
    assert "\\x1b" in rendered
    assert "\\u202e" in rendered
    assert rendered.endswith("\n")


def test_standalone_bootstrap_binds_approval_to_durable_session_authority() -> None:
    source = inspect.getsource(bootstrap.StandaloneTaskRuntimeBridge._invoke)
    assert "approval_resolver.bind(authentication)" in source
    assert "approval_resolver.unbind()" in source

    composition_source = inspect.getsource(bootstrap._compose_runtime)
    assert "agent_approval_service=approval_service" in composition_source
    assert "agent_approval_resolver=approval_resolver" in composition_source
    assert "patch_prefixes=workspace.patch_prefixes" in composition_source
    assert "protected_paths=" in composition_source

    module_source = inspect.getsource(bootstrap)
    assert "control_plane_authority_security_context(authentication)" in module_source
    assert "SecurityContext(" not in module_source
