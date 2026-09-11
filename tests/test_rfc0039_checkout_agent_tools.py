from __future__ import annotations

import base64
import hashlib
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

import pytest

from phoenix_os.agent.authorization import (
    TOOL_INVOKE_ACTION,
    PolicyEngineToolAuthorizer,
    tool_invocation_resource,
)
from phoenix_os.agent.checkout_agent_tools import (
    CHECKOUT_LIST_TOOL_ID,
    CHECKOUT_READ_BASE64_CHUNK_CHARS,
    CHECKOUT_READ_TOOL_ID,
    CHECKOUT_TOOL_ADAPTER_ID,
    CHECKOUT_TOOL_RESOLVER_ID,
    CheckoutToolAdapter,
    CheckoutToolResourceResolver,
    checkout_tool_descriptors,
    checkout_tool_surface_resource,
)
from phoenix_os.agent.checkout_authorization import (
    CheckoutListAuthorizationRequest,
    CheckoutReadAuthorizationRequest,
    CheckoutWorkspaceAuthorizer,
    PolicyEngineCheckoutWorkspaceAuthorizer,
)
from phoenix_os.agent.checkout_workspace import (
    MAX_CHECKOUT_TEXT_READ_BYTES,
    RegisteredDevelopmentCheckoutAdapter,
    checkout_path_resource,
)
from phoenix_os.agent.contracts import (
    AgentId,
    AgentJsonInput,
    AgentRunId,
    AgentStepId,
    ToolCallId,
    ToolEffect,
    ToolId,
    ToolInvocationRequest,
    ToolResultStatus,
    canonical_agent_json_bytes,
    freeze_agent_json_object,
)
from phoenix_os.agent.errors import (
    AgentAuthorizationRejectedError,
    ToolExecutionError,
)
from phoenix_os.agent.schemas import validate_tool_output
from phoenix_os.agent.tools import (
    ContextualToolAdapter,
    ToolResourceResolver,
)
from phoenix_os.policy import (
    PolicyEffect,
    PolicyEngine,
    PolicyRule,
    PrincipalType,
    SecurityContext,
)

_WORKSPACE_ID = UUID("10000000-0000-4000-8000-000000000001")
_RUN_ID = AgentRunId(UUID("20000000-0000-4000-8000-000000000002"))
_STEP_ID = AgentStepId(UUID("30000000-0000-4000-8000-000000000003"))
_CALL_ID = ToolCallId(UUID("40000000-0000-4000-8000-000000000004"))
_AGENT_ID = AgentId("checkout-agent")
_NOW = datetime(2026, 9, 6, 12, 0, tzinfo=UTC)


class _RecordingCheckoutAuthorizer:
    def __init__(self) -> None:
        self.list_calls: list[tuple[CheckoutListAuthorizationRequest, SecurityContext]] = []
        self.read_calls: list[tuple[CheckoutReadAuthorizationRequest, SecurityContext]] = []

    async def authorize_list(
        self,
        request: CheckoutListAuthorizationRequest,
        context: SecurityContext,
    ) -> None:
        self.list_calls.append((request, context))

    async def authorize_read(
        self,
        request: CheckoutReadAuthorizationRequest,
        context: SecurityContext,
    ) -> None:
        self.read_calls.append((request, context))


def _context() -> SecurityContext:
    return SecurityContext(
        principal="operator-1",
        principal_type=PrincipalType.USER,
        authenticated=True,
        permissions=frozenset(
            {
                TOOL_INVOKE_ACTION,
                "workspace.list",
                "workspace.read",
            }
        ),
    )


def _checkout(
    tmp_path: Path,
    *,
    readme: bytes = b"hello\n",
) -> tuple[RegisteredDevelopmentCheckoutAdapter, Path]:
    root = tmp_path / "checkout"
    (root / "src").mkdir(parents=True)
    (root / "src" / "readme.txt").write_bytes(readme)
    return (
        RegisteredDevelopmentCheckoutAdapter(
            workspace_id=_WORKSPACE_ID,
            workspace_name="project",
            generation=7,
            root=root,
            read_prefixes=("src",),
        ),
        root,
    )


def _request(
    checkout: RegisteredDevelopmentCheckoutAdapter,
    *,
    tool_id: ToolId = CHECKOUT_READ_TOOL_ID,
    arguments: Mapping[str, AgentJsonInput] | None = None,
    resolved_resource: str | None = None,
) -> ToolInvocationRequest:
    if arguments is None:
        arguments = {"logical_path": "src/readme.txt"}
    resource = (
        checkout_tool_surface_resource(checkout.registration)
        if resolved_resource is None
        else resolved_resource
    )
    return ToolInvocationRequest(
        agent_id=_AGENT_ID,
        run_id=_RUN_ID,
        step_id=_STEP_ID,
        call_id=_CALL_ID,
        tool_id=tool_id,
        arguments=arguments,
        resolved_resource=resource,
        created_at=_NOW,
        deadline=_NOW + timedelta(minutes=1),
    )


def test_descriptors_and_resolver_are_stable_registration_bound_and_read_only(
    tmp_path: Path,
) -> None:
    checkout, root = _checkout(tmp_path)
    descriptors = checkout_tool_descriptors()
    assert descriptors == checkout_tool_descriptors()
    assert tuple(item.tool_id for item in descriptors) == (
        CHECKOUT_LIST_TOOL_ID,
        CHECKOUT_READ_TOOL_ID,
    )
    assert all(item.effect is ToolEffect.READ_ONLY for item in descriptors)
    assert all(not item.approval_may_be_required for item in descriptors)
    assert all(item.resolver_id == CHECKOUT_TOOL_RESOLVER_ID for item in descriptors)
    assert all(item.adapter_id == CHECKOUT_TOOL_ADAPTER_ID for item in descriptors)

    resolver = CheckoutToolResourceResolver(checkout.registration)
    assert isinstance(resolver, ToolResourceResolver)
    resource = resolver.resolve_resource({"logical_path": "src/readme.txt"})
    assert resource == checkout_tool_surface_resource(checkout.registration)
    assert resource == (f"development-checkout:{_WORKSPACE_ID}/generation:7")
    assert "readme.txt" not in resource
    assert str(root) not in resource


@pytest.mark.asyncio
async def test_generic_tool_invoke_does_not_replace_exact_checkout_authorization(
    tmp_path: Path,
) -> None:
    checkout, _ = _checkout(tmp_path)
    descriptor = checkout_tool_descriptors()[1]
    request = _request(checkout)
    context = _context()
    policy = PolicyEngine(
        (
            PolicyRule(
                rule_id="generic-tool-only",
                effect=PolicyEffect.ALLOW,
                actions=frozenset({TOOL_INVOKE_ACTION}),
                resources=frozenset({tool_invocation_resource(request)}),
                principals=frozenset({context.principal}),
                principal_types=frozenset({PrincipalType.USER}),
                authenticated=True,
            ),
        )
    )
    generic_authorizer = PolicyEngineToolAuthorizer(policy)
    checkout_authorizer = PolicyEngineCheckoutWorkspaceAuthorizer(policy)
    adapter = CheckoutToolAdapter(
        checkout,
        checkout_authorizer,
        tool_id=CHECKOUT_READ_TOOL_ID,
    )

    try:
        await generic_authorizer.authorize(request, descriptor, context)
        with pytest.raises(AgentAuthorizationRejectedError):
            await adapter.invoke_with_context(request, context)
    finally:
        await policy.close()


@pytest.mark.asyncio
async def test_list_reauthorizes_exact_run_registration_prefix_and_bound(
    tmp_path: Path,
) -> None:
    checkout, _ = _checkout(tmp_path)
    (tmp_path / "checkout" / "src" / "pkg").mkdir()
    authorizer = _RecordingCheckoutAuthorizer()
    assert isinstance(authorizer, CheckoutWorkspaceAuthorizer)
    adapter = CheckoutToolAdapter(
        checkout,
        authorizer,
        tool_id=CHECKOUT_LIST_TOOL_ID,
    )
    assert isinstance(adapter, ContextualToolAdapter)
    assert adapter.authorizer is authorizer
    request = _request(
        checkout,
        tool_id=CHECKOUT_LIST_TOOL_ID,
        arguments={"prefix": "src", "max_entries": 1},
    )
    context = _context()

    result = await adapter.invoke_with_context(request, context)

    assert result.status is ToolResultStatus.SUCCEEDED
    assert result.output is not None
    validate_tool_output(checkout_tool_descriptors()[0].output_schema, result.output)
    assert result.output["workspace_id"] == str(_WORKSPACE_ID)
    assert result.output["registration_generation"] == 7
    assert result.output["prefix"] == "src"
    entries = result.output["entries"]
    assert isinstance(entries, tuple)
    assert len(entries) == 1
    assert result.output["excluded_count"] == 1
    assert len(authorizer.list_calls) == 1
    authorization, forwarded_context = authorizer.list_calls[0]
    assert authorization.run_id == _RUN_ID
    assert authorization.registration is checkout.registration
    assert authorization.prefix == "src"
    assert authorization.max_entries == 1
    assert forwarded_context is context
    assert authorizer.read_calls == []


@pytest.mark.asyncio
async def test_read_preserves_full_one_mib_snapshot_with_bounded_deterministic_chunks(
    tmp_path: Path,
) -> None:
    payload = b"a" * MAX_CHECKOUT_TEXT_READ_BYTES
    checkout, root = _checkout(tmp_path, readme=payload)
    authorizer = _RecordingCheckoutAuthorizer()
    adapter = CheckoutToolAdapter(
        checkout,
        authorizer,
        tool_id=CHECKOUT_READ_TOOL_ID,
    )
    request = _request(checkout)
    context = _context()

    result = await adapter.invoke_with_context(request, context)

    assert result.status is ToolResultStatus.SUCCEEDED
    assert result.output is not None
    validate_tool_output(checkout_tool_descriptors()[1].output_schema, result.output)
    chunks = result.output["content_base64_chunks"]
    assert isinstance(chunks, tuple)
    assert all(isinstance(chunk, str) for chunk in chunks)
    assert all(len(chunk) <= CHECKOUT_READ_BASE64_CHUNK_CHARS for chunk in chunks)
    restored = base64.b64decode("".join(chunks), validate=True)
    assert restored == payload
    assert result.output["content_encoding"] == "base64-utf8"

    snapshot = result.output["snapshot"]
    assert isinstance(snapshot, Mapping)
    assert snapshot["run_id"] == str(_RUN_ID)
    assert snapshot["workspace_id"] == str(_WORKSPACE_ID)
    assert snapshot["registration_generation"] == 7
    assert snapshot["logical_path"] == "src/readme.txt"
    assert snapshot["root_identity"] == checkout.registration.root_identity
    assert snapshot["byte_length"] == MAX_CHECKOUT_TEXT_READ_BYTES
    assert str(root) not in repr(result.output)

    assert len(authorizer.read_calls) == 1
    authorization, forwarded_context = authorizer.read_calls[0]
    assert authorization.run_id == _RUN_ID
    assert authorization.registration is checkout.registration
    assert authorization.logical_path == "src/readme.txt"
    assert forwarded_context is context
    assert authorizer.list_calls == []


@pytest.mark.asyncio
async def test_adapter_fails_closed_on_plain_path_resource_or_canonical_substitution(
    tmp_path: Path,
) -> None:
    checkout, _ = _checkout(tmp_path)
    authorizer = _RecordingCheckoutAuthorizer()
    adapter = CheckoutToolAdapter(
        checkout,
        authorizer,
        tool_id=CHECKOUT_READ_TOOL_ID,
    )
    context = _context()
    good = _request(checkout)

    with pytest.raises(ToolExecutionError):
        await adapter.invoke(good)

    mismatched = _request(
        checkout,
        resolved_resource="development-checkout:10000000-0000-4000-8000-000000000099/generation:7",
    )
    with pytest.raises(ToolExecutionError):
        await adapter.invoke_with_context(mismatched, context)

    noncanonical = _request(
        checkout,
        arguments={"logical_path": "src/../src/readme.txt"},
    )
    with pytest.raises(ToolExecutionError):
        await adapter.invoke_with_context(noncanonical, context)

    wrong_tool = _request(
        checkout,
        tool_id=CHECKOUT_LIST_TOOL_ID,
        arguments={"prefix": "src"},
    )
    with pytest.raises(ToolExecutionError):
        await adapter.invoke_with_context(wrong_tool, context)

    assert authorizer.list_calls == []
    assert authorizer.read_calls == []


@pytest.mark.asyncio
async def test_exact_checkout_policy_allows_read_only_after_separate_tool_admission(
    tmp_path: Path,
) -> None:
    checkout, _ = _checkout(tmp_path)
    descriptor = checkout_tool_descriptors()[1]
    request = _request(checkout)
    context = _context()
    policy = PolicyEngine(
        (
            PolicyRule(
                rule_id="generic-tool",
                effect=PolicyEffect.ALLOW,
                actions=frozenset({TOOL_INVOKE_ACTION}),
                resources=frozenset({tool_invocation_resource(request)}),
                principals=frozenset({context.principal}),
                principal_types=frozenset({PrincipalType.USER}),
                authenticated=True,
            ),
            PolicyRule(
                rule_id="exact-checkout-read",
                effect=PolicyEffect.ALLOW,
                actions=frozenset({"workspace.read"}),
                resources=frozenset(
                    {
                        checkout_path_resource(
                            checkout.registration,
                            "src/readme.txt",
                        )
                    }
                ),
                principals=frozenset({context.principal}),
                principal_types=frozenset({PrincipalType.USER}),
                authenticated=True,
            ),
        )
    )
    generic_authorizer = PolicyEngineToolAuthorizer(policy)
    adapter = CheckoutToolAdapter(
        checkout,
        PolicyEngineCheckoutWorkspaceAuthorizer(policy),
        tool_id=CHECKOUT_READ_TOOL_ID,
    )

    try:
        await generic_authorizer.authorize(request, descriptor, context)
        result = await adapter.invoke_with_context(request, context)
        assert result.status is ToolResultStatus.SUCCEEDED
        assert result.output is not None
        content_chunks = result.output["content_base64_chunks"]
        assert isinstance(content_chunks, tuple)
        assert all(isinstance(chunk, str) for chunk in content_chunks)
        assert base64.b64decode("".join(content_chunks), validate=True) == b"hello\n"
    finally:
        await policy.close()


@pytest.mark.asyncio
async def test_list_result_currentness_reuses_checkout_owner_without_reauthorization(
    tmp_path: Path,
) -> None:
    checkout, root = _checkout(tmp_path)
    authorizer = _RecordingCheckoutAuthorizer()
    adapter = CheckoutToolAdapter(
        checkout,
        authorizer,
        tool_id=CHECKOUT_LIST_TOOL_ID,
    )
    request = _request(
        checkout,
        tool_id=CHECKOUT_LIST_TOOL_ID,
        arguments={"prefix": "src", "max_entries": 8},
    )
    context = _context()

    result = await adapter.invoke_with_context(request, context)
    assert result.output is not None
    listing_digest = (
        "sha256:"
        + hashlib.sha256(
            canonical_agent_json_bytes(freeze_agent_json_object(result.output))
        ).hexdigest()
    )
    authorization_count = len(authorizer.list_calls)

    assert await adapter.is_list_result_current(
        prefix="src",
        max_entries=8,
        registration_generation=checkout.registration.generation,
        root_identity=checkout.registration.root_identity,
        listing_digest=listing_digest,
    )
    assert len(authorizer.list_calls) == authorization_count

    (root / "src" / "changed.py").write_text("changed\n", encoding="utf-8")
    assert not await adapter.is_list_result_current(
        prefix="src",
        max_entries=8,
        registration_generation=checkout.registration.generation,
        root_identity=checkout.registration.root_identity,
        listing_digest=listing_digest,
    )
    assert len(authorizer.list_calls) == authorization_count

    assert not await adapter.is_list_result_current(
        prefix="src",
        max_entries=8,
        registration_generation=checkout.registration.generation + 1,
        root_identity=checkout.registration.root_identity,
        listing_digest=listing_digest,
    )


@pytest.mark.asyncio
async def test_read_result_currentness_reuses_checkout_owner_without_reauthorization(
    tmp_path: Path,
) -> None:
    checkout, root = _checkout(tmp_path)
    authorizer = _RecordingCheckoutAuthorizer()
    adapter = CheckoutToolAdapter(
        checkout,
        authorizer,
        tool_id=CHECKOUT_READ_TOOL_ID,
    )
    request = _request(checkout)
    context = _context()

    result = await adapter.invoke_with_context(request, context)
    assert result.output is not None
    snapshot = result.output["snapshot"]
    assert isinstance(snapshot, Mapping)
    file_identity = snapshot["file_identity"]
    content_digest = snapshot["content_digest"]
    byte_length = snapshot["byte_length"]
    assert isinstance(file_identity, str)
    assert isinstance(content_digest, str)
    assert isinstance(byte_length, int) and not isinstance(byte_length, bool)
    authorization_count = len(authorizer.read_calls)

    assert await adapter.is_read_result_current(
        logical_path="src/readme.txt",
        run_id=_RUN_ID,
        registration_generation=checkout.registration.generation,
        root_identity=checkout.registration.root_identity,
        file_identity=file_identity,
        content_digest=content_digest,
        byte_length=byte_length,
    )
    assert len(authorizer.read_calls) == authorization_count

    (root / "src" / "readme.txt").write_bytes(b"HELLO\n")
    assert not await adapter.is_read_result_current(
        logical_path="src/readme.txt",
        run_id=_RUN_ID,
        registration_generation=checkout.registration.generation,
        root_identity=checkout.registration.root_identity,
        file_identity=file_identity,
        content_digest=content_digest,
        byte_length=byte_length,
    )
    assert len(authorizer.read_calls) == authorization_count

    assert not await adapter.is_read_result_current(
        logical_path="src/readme.txt",
        run_id=_RUN_ID,
        registration_generation=checkout.registration.generation,
        root_identity="sha256:" + ("0" * 64),
        file_identity=file_identity,
        content_digest=content_digest,
        byte_length=byte_length,
    )
