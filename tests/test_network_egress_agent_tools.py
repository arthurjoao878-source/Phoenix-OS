from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta

import pytest

from phoenix_os.agent.contracts import (
    AgentId,
    AgentRunId,
    AgentStepId,
    ToolCallId,
    ToolEffect,
    ToolId,
    ToolInvocationRequest,
    ToolResultStatus,
)
from phoenix_os.agent.errors import AgentSchemaError, ToolExecutionError
from phoenix_os.agent.schemas import validate_tool_input
from phoenix_os.network_egress.agent_tools import (
    MAX_NETWORK_AGENT_TOOL_BODY_BYTES,
    NetworkEgressToolBinding,
    NetworkHttpToolAdapter,
    network_http_tool_descriptor,
    network_http_tool_resolver,
)
from phoenix_os.network_egress.contracts import (
    NetworkEgressOperationId,
    NetworkEgressProfileId,
    NetworkHttpRequest,
    NetworkHttpResponse,
)
from phoenix_os.network_egress.profiles import (
    NetworkDestinationMode,
    NetworkEgressOperation,
    NetworkEgressProfile,
    NetworkHttpMethod,
    NetworkOperationEffect,
    NetworkOperationLimits,
)
from phoenix_os.network_egress.service import (
    NetworkEgressCancellationToken,
    NetworkEgressFailureKind,
    NetworkEgressFinalAdmissionValidator,
    NetworkEgressRequestError,
    NetworkEgressService,
)
from phoenix_os.policy import PrincipalType, SecurityContext

_NOW = datetime(2026, 8, 24, 6, tzinfo=UTC)


def _profile(
    *,
    effect: NetworkOperationEffect = NetworkOperationEffect.READ_ONLY,
    request_body_bytes: int = 0,
    response_body_bytes: int = 64,
) -> NetworkEgressProfile:
    method = (
        NetworkHttpMethod.GET
        if effect is NetworkOperationEffect.READ_ONLY
        else NetworkHttpMethod.POST
    )
    operation = NetworkEgressOperation(
        operation_id=NetworkEgressOperationId("op"),
        method=method,
        request_target="/v1/tool",
        effect=effect,
        limits=NetworkOperationLimits(
            max_request_body_bytes=request_body_bytes,
            max_response_body_bytes=response_body_bytes,
            max_response_headers=8,
            max_response_header_bytes=1024,
            max_resolved_addresses=4,
            connect_timeout_seconds=1,
            total_timeout_seconds=5,
        ),
        content_type="application/octet-stream" if request_body_bytes else None,
        exposed_response_headers=("content-type", "x-visible"),
    )
    return NetworkEgressProfile(
        profile_id=NetworkEgressProfileId("agent-tool"),
        generation=7,
        mode=NetworkDestinationMode.HOSTED_HTTPS,
        host="api.example.com",
        operations=(operation,),
    )


def _binding(
    profile: NetworkEgressProfile,
    *,
    agent_id: str = "assistant",
    tool_id: str = "network.op",
) -> NetworkEgressToolBinding:
    return NetworkEgressToolBinding(
        agent_id=AgentId(agent_id),
        tool_id=ToolId(tool_id),
        profile=profile,
        operation_id=profile.operations[0].operation_id,
    )


def _context() -> SecurityContext:
    return SecurityContext(
        principal="service:agent",
        principal_type=PrincipalType.SERVICE,
        authenticated=True,
    )


def _invocation(
    binding: NetworkEgressToolBinding,
    *,
    arguments: dict[str, str] | None = None,
    agent_id: AgentId | None = None,
    resource: str | None = None,
) -> ToolInvocationRequest:
    return ToolInvocationRequest(
        agent_id=binding.agent_id if agent_id is None else agent_id,
        run_id=AgentRunId(),
        step_id=AgentStepId(),
        call_id=ToolCallId(),
        tool_id=binding.tool_id,
        arguments={} if arguments is None else arguments,
        resolved_resource=binding.resource if resource is None else resource,
        created_at=_NOW,
        deadline=_NOW + timedelta(seconds=4),
    )


class _RecordingService(NetworkEgressService):
    def __init__(
        self,
        *,
        response_body: bytes = b"pong",
        error: NetworkEgressRequestError | None = None,
    ) -> None:
        self.response_body = response_body
        self.error = error
        self.calls: list[
            tuple[
                NetworkHttpRequest,
                SecurityContext,
                NetworkEgressProfile | None,
                NetworkEgressFinalAdmissionValidator | None,
            ]
        ] = []

    async def request(
        self,
        request: NetworkHttpRequest,
        context: SecurityContext,
        *,
        cancellation: NetworkEgressCancellationToken | None = None,
        deadline: datetime | None = None,
        expected_profile: NetworkEgressProfile | None = None,
        final_admission: NetworkEgressFinalAdmissionValidator | None = None,
    ) -> NetworkHttpResponse:
        del cancellation, deadline
        self.calls.append((request, context, expected_profile, final_admission))
        if final_admission is not None:
            await final_admission()
        if self.error is not None:
            raise self.error
        return NetworkHttpResponse(
            request_id=request.request_id,
            profile_id=request.profile_id,
            operation_id=request.operation_id,
            status_code=200,
            body=self.response_body,
            headers={
                "x-visible": "yes",
                "content-type": "application/octet-stream",
            },
            created_at=request.created_at,
        )


def test_descriptor_and_resolver_bind_exact_profile_generation_and_effect() -> None:
    read_binding = _binding(_profile())
    read_descriptor = network_http_tool_descriptor(read_binding)
    resolver = network_http_tool_resolver(read_binding)

    assert read_descriptor.effect is ToolEffect.READ_ONLY
    assert read_descriptor.approval_may_be_required is False
    assert resolver.resource == read_binding.resource
    assert "/generation:7/" in resolver.resource
    assert validate_tool_input(read_descriptor.input_schema, {}) == {}

    with pytest.raises(AgentSchemaError):
        validate_tool_input(
            read_descriptor.input_schema,
            {"url": "https://attacker.invalid/"},
        )

    remote = _binding(
        _profile(
            effect=NetworkOperationEffect.REMOTE_EFFECT,
            request_body_bytes=16,
        ),
        tool_id="network.write",
    )
    descriptor = network_http_tool_descriptor(remote)
    assert descriptor.effect is ToolEffect.EXTERNAL_COMMUNICATION
    assert descriptor.approval_may_be_required is True

    encoded = base64.b64encode(b"abc").decode("ascii")
    assert validate_tool_input(
        descriptor.input_schema,
        {"body_base64": encoded},
    ) == {"body_base64": encoded}


def test_binding_rejects_body_limits_that_cannot_fit_strict_tool_string() -> None:
    profile = _profile(
        response_body_bytes=MAX_NETWORK_AGENT_TOOL_BODY_BYTES + 1,
    )
    with pytest.raises(ValueError, match="response body"):
        _binding(profile)


@pytest.mark.asyncio
async def test_adapter_preserves_requester_binding_and_calls_final_admission_once() -> None:
    binding = _binding(
        _profile(
            effect=NetworkOperationEffect.REMOTE_EFFECT,
            request_body_bytes=64,
        )
    )
    service = _RecordingService()
    adapter = NetworkHttpToolAdapter(service, binding)
    body = b"https://169.254.169.254/\r\nHost: attacker.invalid\r\n"
    request = _invocation(
        binding,
        arguments={"body_base64": base64.b64encode(body).decode("ascii")},
    )
    callbacks = 0

    async def final_admission() -> None:
        nonlocal callbacks
        callbacks += 1

    result = await adapter.invoke_with_context_and_final_admission(
        request,
        _context(),
        final_admission,
    )

    assert callbacks == 1
    assert len(service.calls) == 1
    network_request, context, expected_profile, validator = service.calls[0]
    assert context == _context()
    assert network_request.body == body
    assert network_request.profile_id == binding.profile.profile_id
    assert network_request.operation_id == binding.operation_id
    assert expected_profile == binding.profile
    assert validator is final_admission
    assert result.status is ToolResultStatus.SUCCEEDED
    assert result.output is not None
    encoded_body = result.output["body_base64"]
    assert isinstance(encoded_body, str)
    assert base64.b64decode(encoded_body) == b"pong"
    assert result.output["status_code"] == 200
    assert result.output["headers"] == (
        {
            "name": "content-type",
            "value": "application/octet-stream",
        },
        {"name": "x-visible", "value": "yes"},
    )
    assert "profile_id" not in result.output
    assert "request_id" not in result.output


@pytest.mark.asyncio
async def test_adapter_rejects_cross_agent_or_resource_retarget_before_service() -> None:
    binding = _binding(_profile())
    service = _RecordingService()
    adapter = NetworkHttpToolAdapter(service, binding)

    async def final_admission() -> None:
        return None

    with pytest.raises(ToolExecutionError):
        await adapter.invoke_with_context_and_final_admission(
            _invocation(binding, agent_id=AgentId("other")),
            _context(),
            final_admission,
        )
    with pytest.raises(ToolExecutionError):
        await adapter.invoke_with_context_and_final_admission(
            _invocation(
                binding,
                resource="network-egress:other/generation:1/operation:op",
            ),
            _context(),
            final_admission,
        )
    assert service.calls == []


@pytest.mark.asyncio
async def test_adapter_legacy_and_plain_contextual_paths_fail_closed() -> None:
    binding = _binding(_profile())
    adapter = NetworkHttpToolAdapter(_RecordingService(), binding)
    request = _invocation(binding)

    with pytest.raises(ToolExecutionError):
        await adapter.invoke(request)
    with pytest.raises(ToolExecutionError):
        await adapter.invoke_with_context(request, _context())


@pytest.mark.asyncio
async def test_indeterminate_network_effect_stays_indeterminate_at_tool_boundary() -> None:
    binding = _binding(_profile())
    service = _RecordingService(
        error=NetworkEgressRequestError(
            NetworkEgressFailureKind.INDETERMINATE,
            request_started=True,
        )
    )
    adapter = NetworkHttpToolAdapter(service, binding)

    async def final_admission() -> None:
        return None

    result = await adapter.invoke_with_context_and_final_admission(
        _invocation(binding),
        _context(),
        final_admission,
    )

    assert result.status is ToolResultStatus.INDETERMINATE
    assert result.error_code == "network_indeterminate"
