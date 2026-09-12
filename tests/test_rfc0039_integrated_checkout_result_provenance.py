from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

import pytest

from phoenix_os.agent import (
    AgentId,
    AgentJsonInput,
    AgentMessage,
    AgentMessageRole,
    AgentRunRequest,
    AgentStepId,
    ToolCallId,
    ToolId,
    ToolInvocationRequest,
    ToolInvocationResult,
    ToolResultStatus,
)
from phoenix_os.agent.checkout_agent_tools import (
    CHECKOUT_LIST_TOOL_ID,
    CHECKOUT_READ_TOOL_ID,
    CheckoutToolAdapter,
    checkout_integrated_binding_id,
    checkout_tool_surface_resource,
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
    canonical_agent_json_bytes,
    freeze_agent_json_object,
)
from phoenix_os.inference import ModelId, ModelProviderId
from phoenix_os.integrated_agent import (
    IntegratedDataProvenance,
    IntegratedDataProvenanceAtom,
    IntegratedDataSourceKind,
    IntegratedDownstreamBoundary,
    IntegratedDownstreamBridgeBinding,
)
from phoenix_os.integrated_agent.errors import IntegratedAgentValidationError
from phoenix_os.integrated_agent.execution_guard import _tool_result_provenance
from phoenix_os.policy import SecurityContext

_NOW = datetime(2026, 9, 10, 12, tzinfo=UTC)
_WORKSPACE_ID = UUID("10000000-0000-4000-8000-000000000039")


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


def _request() -> AgentRunRequest:
    return AgentRunRequest(
        agent_id=AgentId("rfc0039-checkout-provenance"),
        provider_id=ModelProviderId("local"),
        model_id=ModelId("chat"),
        messages=(AgentMessage(AgentMessageRole.USER, "inspect checkout"),),
        created_at=_NOW,
        deadline=_NOW + timedelta(minutes=5),
    )


def _checkout(root: Path) -> RegisteredDevelopmentCheckoutAdapter:
    (root / "src").mkdir(exist_ok=True)
    return RegisteredDevelopmentCheckoutAdapter(
        workspace_id=_WORKSPACE_ID,
        workspace_name="rfc0039-development",
        generation=7,
        root=root,
        read_prefixes=("src",),
    )


def _adapter(
    checkout: RegisteredDevelopmentCheckoutAdapter,
    tool_id: ToolId,
) -> CheckoutToolAdapter:
    return CheckoutToolAdapter(
        checkout,
        _CheckoutAuthorizer(),
        tool_id=tool_id,
    )


def _invocation(
    adapter: CheckoutToolAdapter,
    *,
    arguments: dict[str, AgentJsonInput],
    call: int,
) -> ToolInvocationRequest:
    request = _request()
    return ToolInvocationRequest(
        agent_id=request.agent_id,
        run_id=request.run_id,
        step_id=AgentStepId(UUID(int=call + 1)),
        call_id=ToolCallId(UUID(int=call)),
        tool_id=adapter.tool_id,
        arguments=arguments,
        resolved_resource=checkout_tool_surface_resource(adapter.registration),
        created_at=_NOW,
        deadline=_NOW + timedelta(minutes=1),
    )


def _binding(adapter: CheckoutToolAdapter) -> IntegratedDownstreamBridgeBinding:
    action = "workspace.list" if adapter.tool_id == CHECKOUT_LIST_TOOL_ID else "workspace.read"
    return IntegratedDownstreamBridgeBinding(
        tool_id=adapter.tool_id,
        boundary=IntegratedDownstreamBoundary.WORKSPACE,
        binding_id=checkout_integrated_binding_id(adapter.registration),
        action_family=action,
        generation=adapter.registration.generation,
    )


def _base_provenance() -> IntegratedDataProvenance:
    return IntegratedDataProvenance(
        (
            IntegratedDataProvenanceAtom(
                source_kind=IntegratedDataSourceKind.USER_TASK,
                source_binding="integrated-task:00000000-0000-4000-8000-000000000039",
            ),
        )
    )


def _result(
    invocation: ToolInvocationRequest,
    output: dict[str, AgentJsonInput],
) -> ToolInvocationResult:
    return ToolInvocationResult(
        run_id=invocation.run_id,
        step_id=invocation.step_id,
        call_id=invocation.call_id,
        tool_id=invocation.tool_id,
        status=ToolResultStatus.SUCCEEDED,
        output=output,
        started_at=_NOW,
        completed_at=_NOW,
    )


def _workspace_atom(
    provenance: IntegratedDataProvenance,
) -> IntegratedDataProvenanceAtom:
    atoms = tuple(
        atom for atom in provenance.atoms if atom.source_kind is IntegratedDataSourceKind.WORKSPACE
    )
    assert len(atoms) == 1
    return atoms[0]


def test_checkout_list_result_uses_exact_prefix_and_replayable_listing_freshness(
    tmp_path: Path,
) -> None:
    checkout = _checkout(tmp_path)
    adapter = _adapter(checkout, CHECKOUT_LIST_TOOL_ID)
    invocation = _invocation(
        adapter,
        arguments={"prefix": "src", "max_entries": 3},
        call=3901,
    )
    output: dict[str, AgentJsonInput] = {
        "workspace_id": str(_WORKSPACE_ID),
        "registration_generation": 7,
        "prefix": "src",
        "entries": [
            {"logical_path": "src/a.py", "category": "file"},
            {"logical_path": "src/pkg", "category": "directory"},
        ],
        "excluded_count": 0,
    }

    provenance = _tool_result_provenance(
        _base_provenance(),
        _binding(adapter),
        invocation,
        _result(invocation, output),
        adapter=adapter,
    )

    atom = _workspace_atom(provenance)
    listing_digest = (
        "sha256:"
        + hashlib.sha256(canonical_agent_json_bytes(freeze_agent_json_object(output))).hexdigest()
    )
    assert atom.source_binding == checkout_prefix_resource(adapter.registration, "src")
    assert set(atom.freshness_bindings) == {
        f"tool-call:{invocation.call_id}",
        "registration-generation:7",
        f"root-identity:{adapter.registration.root_identity}",
        "operation:list",
        "list-limit:3",
        f"listing-digest:{listing_digest}",
    }


def test_checkout_read_result_uses_exact_path_and_snapshot_freshness(
    tmp_path: Path,
) -> None:
    checkout = _checkout(tmp_path)
    adapter = _adapter(checkout, CHECKOUT_READ_TOOL_ID)
    invocation = _invocation(
        adapter,
        arguments={"logical_path": "src/a.py"},
        call=3911,
    )
    file_identity = "sha256:" + ("a" * 64)
    content_digest = "sha256:" + ("b" * 64)
    output: dict[str, AgentJsonInput] = {
        "snapshot": {
            "run_id": str(invocation.run_id),
            "workspace_id": str(_WORKSPACE_ID),
            "registration_generation": 7,
            "logical_path": "src/a.py",
            "root_identity": adapter.registration.root_identity,
            "file_identity": file_identity,
            "content_digest": content_digest,
            "byte_length": 5,
        },
        "content_encoding": "base64-utf8",
        "content_base64_chunks": ["aGVsbG8="],
    }

    provenance = _tool_result_provenance(
        _base_provenance(),
        _binding(adapter),
        invocation,
        _result(invocation, output),
        adapter=adapter,
    )

    atom = _workspace_atom(provenance)
    assert atom.source_binding == checkout_path_resource(adapter.registration, "src/a.py")
    assert set(atom.freshness_bindings) == {
        f"tool-call:{invocation.call_id}",
        "registration-generation:7",
        f"root-identity:{adapter.registration.root_identity}",
        "operation:read",
        f"file-identity:{file_identity}",
        f"content-digest:{content_digest}",
        "byte-length:5",
    }


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("workspace_id", str(UUID("20000000-0000-4000-8000-000000000039"))),
        ("registration_generation", 8),
    ),
)
def test_checkout_list_result_rejects_changed_registration_identity(
    tmp_path: Path,
    field: str,
    replacement: AgentJsonInput,
) -> None:
    checkout = _checkout(tmp_path)
    adapter = _adapter(checkout, CHECKOUT_LIST_TOOL_ID)
    invocation = _invocation(adapter, arguments={"prefix": "src"}, call=3921)
    output: dict[str, AgentJsonInput] = {
        "workspace_id": str(_WORKSPACE_ID),
        "registration_generation": 7,
        "prefix": "src",
        "entries": [],
        "excluded_count": 0,
    }
    output[field] = replacement

    with pytest.raises(IntegratedAgentValidationError):
        _tool_result_provenance(
            _base_provenance(),
            _binding(adapter),
            invocation,
            _result(invocation, output),
            adapter=adapter,
        )


def test_checkout_result_cannot_fall_back_to_generic_workspace_binding(
    tmp_path: Path,
) -> None:
    checkout = _checkout(tmp_path)
    adapter = _adapter(checkout, CHECKOUT_READ_TOOL_ID)
    invocation = _invocation(
        adapter,
        arguments={"logical_path": "src/a.py"},
        call=3931,
    )
    wrong_binding = IntegratedDownstreamBridgeBinding(
        tool_id=adapter.tool_id,
        boundary=IntegratedDownstreamBoundary.WORKSPACE,
        binding_id="agent-workspace:wrong/scope:agent",
        action_family="workspace.read",
        generation=adapter.registration.generation,
    )
    output: dict[str, AgentJsonInput] = {
        "workspace_id": str(_WORKSPACE_ID),
        "registration_generation": 7,
        "snapshot": {
            "run_id": str(invocation.run_id),
            "workspace_id": str(_WORKSPACE_ID),
            "registration_generation": 7,
            "logical_path": "src/a.py",
            "root_identity": adapter.registration.root_identity,
            "file_identity": "sha256:" + ("a" * 64),
            "content_digest": "sha256:" + ("b" * 64),
            "byte_length": 5,
        },
        "content_encoding": "base64-utf8",
        "content_base64_chunks": ["aGVsbG8="],
    }

    with pytest.raises(IntegratedAgentValidationError):
        _tool_result_provenance(
            _base_provenance(),
            wrong_binding,
            invocation,
            _result(invocation, output),
            adapter=adapter,
        )
