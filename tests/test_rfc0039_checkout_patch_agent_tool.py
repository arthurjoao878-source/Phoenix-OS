from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

import pytest

from phoenix_os.agent.checkout_agent_tools import (
    CHECKOUT_LIST_TOOL_ID,
    CHECKOUT_READ_TOOL_ID,
    checkout_tool_descriptors,
)
from phoenix_os.agent.checkout_authorization import (
    CheckoutListAuthorizationRequest,
    CheckoutPatchAuthorizationRequest,
    CheckoutReadAuthorizationRequest,
    CheckoutWorkspaceAuthorizer,
)
from phoenix_os.agent.checkout_patch_agent_tool import (
    CHECKOUT_PATCH_TOOL_ADAPTER_ID,
    CHECKOUT_PATCH_TOOL_ID,
    CHECKOUT_PATCH_TOOL_RESOLVER_ID,
    CheckoutPatchToolAdapter,
    CheckoutPatchToolResourceResolver,
    checkout_patch_tool_descriptor,
)
from phoenix_os.agent.checkout_workspace import RegisteredDevelopmentCheckoutAdapter
from phoenix_os.agent.contracts import (
    AgentId,
    AgentJsonInput,
    AgentRunId,
    AgentStepId,
    ToolCallId,
    ToolEffect,
    ToolInvocationRequest,
)
from phoenix_os.agent.errors import ToolExecutionError
from phoenix_os.agent.tools import (
    ContextualToolAdapter,
    FinalAdmissionContextualToolAdapter,
    ToolFinalAdmissionContext,
    ToolResourceResolver,
)
from phoenix_os.policy import PrincipalType, SecurityContext

_WORKSPACE_ID = UUID("10000000-0000-4000-8000-000000000001")
_RUN_ID = AgentRunId(UUID("20000000-0000-4000-8000-000000000002"))
_STEP_ID = AgentStepId(UUID("30000000-0000-4000-8000-000000000003"))
_CALL_ID = ToolCallId(UUID("40000000-0000-4000-8000-000000000004"))
_AGENT_ID = AgentId("patch-agent")
_NOW = datetime(2026, 9, 12, 15, 0, tzinfo=UTC)


class _RecordingAuthorizer:
    def __init__(self) -> None:
        self.patch_calls: list[tuple[CheckoutPatchAuthorizationRequest, SecurityContext]] = []

    async def authorize_list(
        self,
        request: CheckoutListAuthorizationRequest,
        context: SecurityContext,
    ) -> None:
        del request, context
        raise AssertionError("list authorization is not expected")

    async def authorize_read(
        self,
        request: CheckoutReadAuthorizationRequest,
        context: SecurityContext,
    ) -> None:
        del request, context
        raise AssertionError("read authorization is not expected")

    async def authorize_patch(
        self,
        request: CheckoutPatchAuthorizationRequest,
        context: SecurityContext,
    ) -> None:
        self.patch_calls.append((request, context))


def _context() -> SecurityContext:
    return SecurityContext(
        principal="operator-1",
        principal_type=PrincipalType.USER,
        authenticated=True,
        permissions=frozenset({"tool.invoke", "workspace.patch"}),
    )


def _checkout(tmp_path: Path) -> RegisteredDevelopmentCheckoutAdapter:
    root = tmp_path / "checkout"
    (root / "src").mkdir(parents=True)
    (root / "src" / "example.py").write_bytes(b"alpha\nbeta\n")
    return RegisteredDevelopmentCheckoutAdapter(
        workspace_id=_WORKSPACE_ID,
        workspace_name="project",
        generation=7,
        root=root,
        read_prefixes=("src",),
        patch_prefixes=("src",),
    )


async def _request(
    checkout: RegisteredDevelopmentCheckoutAdapter,
    *,
    logical_path: str = "src/example.py",
    resolved_resource: str | None = None,
) -> ToolInvocationRequest:
    read_result = await checkout.read(logical_path, run_id=_RUN_ID)
    snapshot = read_result.snapshot
    arguments: dict[str, AgentJsonInput] = {
        "logical_path": logical_path,
        "snapshot": {
            "run_id": str(snapshot.run_id),
            "workspace_id": str(snapshot.workspace_id),
            "registration_generation": snapshot.registration_generation,
            "logical_path": snapshot.logical_path,
            "root_identity": snapshot.root_identity,
            "file_identity": snapshot.file_identity,
            "content_digest": snapshot.content_digest,
            "byte_length": snapshot.byte_length,
        },
        "base_content_digest": snapshot.content_digest,
        "edits": [
            {
                "start_byte": 6,
                "end_byte": 10,
                "expected_text": "beta",
                "replacement_text": "gamma",
            }
        ],
    }
    resolver = CheckoutPatchToolResourceResolver(checkout.registration)
    resource = resolver.resolve_resource({}) if resolved_resource is None else resolved_resource
    return ToolInvocationRequest(
        agent_id=_AGENT_ID,
        run_id=_RUN_ID,
        step_id=_STEP_ID,
        call_id=_CALL_ID,
        tool_id=CHECKOUT_PATCH_TOOL_ID,
        arguments=arguments,
        resolved_resource=resource,
        created_at=_NOW,
        deadline=_NOW + timedelta(minutes=1),
    )


def test_patch_descriptor_is_separate_reversible_and_not_integrated_by_read_tuple(
    tmp_path: Path,
) -> None:
    checkout = _checkout(tmp_path)
    descriptor = checkout_patch_tool_descriptor()

    assert descriptor == checkout_patch_tool_descriptor()
    assert descriptor.tool_id == CHECKOUT_PATCH_TOOL_ID
    assert descriptor.effect is ToolEffect.REVERSIBLE_WRITE
    assert descriptor.approval_may_be_required
    assert descriptor.resolver_id == CHECKOUT_PATCH_TOOL_RESOLVER_ID
    assert descriptor.adapter_id == CHECKOUT_PATCH_TOOL_ADAPTER_ID
    assert descriptor.metadata["downstream_action"] == "workspace.patch"
    assert descriptor.metadata["durable_dispatch"] == "specialized"

    read_descriptors = checkout_tool_descriptors()
    assert tuple(item.tool_id for item in read_descriptors) == (
        CHECKOUT_LIST_TOOL_ID,
        CHECKOUT_READ_TOOL_ID,
    )
    assert CHECKOUT_PATCH_TOOL_ID not in {item.tool_id for item in read_descriptors}

    resolver = CheckoutPatchToolResourceResolver(checkout.registration)
    assert isinstance(resolver, ToolResourceResolver)
    assert resolver.resolve_resource({}) == (f"development-checkout:{_WORKSPACE_ID}/generation:7")


@pytest.mark.asyncio
async def test_patch_adapter_decodes_and_authorizes_zero_effect_preparation_request(
    tmp_path: Path,
) -> None:
    checkout = _checkout(tmp_path)
    authorizer = _RecordingAuthorizer()
    assert isinstance(authorizer, CheckoutWorkspaceAuthorizer)
    adapter = CheckoutPatchToolAdapter(checkout, authorizer)
    assert isinstance(adapter, ContextualToolAdapter)
    request = await _request(checkout)
    context = _context()
    before = (tmp_path / "checkout" / "src" / "example.py").read_bytes()

    preparation_request = await adapter.prepare_request_with_context(request, context)

    assert preparation_request.run_id == _RUN_ID
    assert preparation_request.step_id == _STEP_ID
    assert preparation_request.call_id == _CALL_ID
    assert preparation_request.snapshot.logical_path == "src/example.py"
    assert preparation_request.base_content_digest == preparation_request.snapshot.content_digest
    assert len(preparation_request.edits) == 1
    assert preparation_request.edits[0].expected_text == "beta"
    assert preparation_request.edits[0].replacement_text == "gamma"
    assert (tmp_path / "checkout" / "src" / "example.py").read_bytes() == before

    assert len(authorizer.patch_calls) == 1
    authorization, forwarded_context = authorizer.patch_calls[0]
    assert authorization.run_id == _RUN_ID
    assert authorization.registration is checkout.registration
    assert authorization.logical_path == "src/example.py"
    assert forwarded_context is context


@pytest.mark.asyncio
async def test_patch_adapter_generic_contextual_invoke_fails_closed_without_effect(
    tmp_path: Path,
) -> None:
    checkout = _checkout(tmp_path)
    authorizer = _RecordingAuthorizer()
    adapter = CheckoutPatchToolAdapter(checkout, authorizer)
    request = await _request(checkout)
    context = _context()
    target = tmp_path / "checkout" / "src" / "example.py"
    before = target.read_bytes()

    with pytest.raises(ToolExecutionError):
        await adapter.invoke(request)
    with pytest.raises(ToolExecutionError):
        await adapter.invoke_with_context(request, context)

    assert isinstance(adapter, FinalAdmissionContextualToolAdapter)
    final_admission_calls = 0

    async def final_admission(
        details: ToolFinalAdmissionContext,
    ) -> None:
        nonlocal final_admission_calls
        del details
        final_admission_calls += 1

    with pytest.raises(ToolExecutionError):
        await adapter.invoke_with_context_and_final_admission(
            request,
            context,
            final_admission,
        )

    assert final_admission_calls == 0
    assert target.read_bytes() == before
    assert authorizer.patch_calls == []


@pytest.mark.asyncio
async def test_patch_adapter_rejects_wrong_resource_and_snapshot_path_before_authorization(
    tmp_path: Path,
) -> None:
    checkout = _checkout(tmp_path)
    authorizer = _RecordingAuthorizer()
    adapter = CheckoutPatchToolAdapter(checkout, authorizer)
    context = _context()

    wrong_resource = await _request(
        checkout,
        resolved_resource="development-checkout:10000000-0000-4000-8000-000000000099/generation:7",
    )
    with pytest.raises(ToolExecutionError):
        await adapter.prepare_request_with_context(wrong_resource, context)

    good = await _request(checkout)
    arguments = dict(good.arguments)
    snapshot_value = arguments["snapshot"]
    assert isinstance(snapshot_value, Mapping)
    snapshot = dict(snapshot_value)
    snapshot["logical_path"] = "src/other.py"
    arguments["snapshot"] = snapshot
    mismatched = ToolInvocationRequest(
        agent_id=_AGENT_ID,
        run_id=_RUN_ID,
        step_id=_STEP_ID,
        call_id=_CALL_ID,
        tool_id=CHECKOUT_PATCH_TOOL_ID,
        arguments=arguments,
        resolved_resource=good.resolved_resource,
        created_at=_NOW,
        deadline=_NOW + timedelta(minutes=1),
    )
    with pytest.raises(ToolExecutionError):
        await adapter.prepare_request_with_context(mismatched, context)

    assert authorizer.patch_calls == []


def test_patch_output_schema_accepts_terminal_operator_review_metadata() -> None:
    from phoenix_os.agent.checkout_patch_agent_tool import checkout_patch_tool_descriptor
    from phoenix_os.agent.schemas import validate_tool_output

    descriptor = checkout_patch_tool_descriptor()
    output: dict[str, AgentJsonInput] = {
        "workspace_id": "10000000-0000-4000-8000-000000000001",
        "logical_path": "src/example.py",
        "before_content_digest": "sha256:" + ("a" * 64),
        "after_content_digest": "sha256:" + ("b" * 64),
        "preparation_digest": "sha256:" + ("c" * 64),
        "changed_line_count": 1,
        "files_changed": 1,
        "review_status": "approved",
        "status": "applied",
    }

    validate_tool_output(descriptor.output_schema, output)
    assert output["files_changed"] == 1
    assert output["review_status"] == "approved"
