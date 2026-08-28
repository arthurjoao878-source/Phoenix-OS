"""Reviewed agent-tool facade for exact server-owned network egress operations."""

from __future__ import annotations

import base64
import binascii
from collections.abc import Mapping
from dataclasses import dataclass, field

from phoenix_os.agent.contracts import (
    MAX_AGENT_ARGUMENT_BYTES,
    MAX_AGENT_RESULT_BYTES,
    AgentId,
    AgentJsonInput,
    ToolEffect,
    ToolId,
    ToolInvocationRequest,
    ToolInvocationResult,
    ToolResultStatus,
)
from phoenix_os.agent.errors import ToolExecutionError
from phoenix_os.agent.schemas import (
    MAX_TOOL_SCHEMA_STRING_LENGTH,
    ToolInputSchema,
    ToolOutputSchema,
    ToolSchema,
    ToolSchemaType,
)
from phoenix_os.agent.tools import (
    StaticToolResourceResolver,
    ToolDescriptor,
    ToolFinalAdmissionValidator,
)
from phoenix_os.network_egress.authorization import network_http_resource
from phoenix_os.network_egress.contracts import (
    NetworkEgressOperationId,
    NetworkHttpRequest,
    NetworkHttpResponse,
)
from phoenix_os.network_egress.profiles import (
    NetworkEgressOperation,
    NetworkEgressProfile,
    NetworkOperationEffect,
)
from phoenix_os.network_egress.service import (
    NetworkEgressFailureKind,
    NetworkEgressRequestError,
    NetworkEgressService,
)
from phoenix_os.policy import SecurityContext

MAX_NETWORK_AGENT_TOOL_BODY_BYTES = 196_608
MAX_NETWORK_AGENT_TOOL_INPUT_BYTES = MAX_AGENT_ARGUMENT_BYTES
MAX_NETWORK_AGENT_TOOL_OUTPUT_BYTES = MAX_AGENT_RESULT_BYTES

NETWORK_HTTP_TOOL_RESOLVER_ID = "network-http-resource"
NETWORK_HTTP_TOOL_ADAPTER_ID = "network-http"


@dataclass(frozen=True, slots=True)
class NetworkEgressToolBinding:
    """Server-owned exact tool-to-profile-generation-and-operation binding."""

    agent_id: AgentId
    tool_id: ToolId
    profile: NetworkEgressProfile = field(repr=False)
    operation_id: NetworkEgressOperationId

    def __post_init__(self) -> None:
        if not isinstance(self.agent_id, AgentId):
            raise TypeError("agent_id must be AgentId")
        if not isinstance(self.tool_id, ToolId):
            raise TypeError("tool_id must be ToolId")
        if not isinstance(self.profile, NetworkEgressProfile):
            raise TypeError("profile must be NetworkEgressProfile")
        if not isinstance(self.operation_id, NetworkEgressOperationId):
            raise TypeError("operation_id must be NetworkEgressOperationId")
        operation = self.profile.require_operation(self.operation_id)
        if operation.limits.max_request_body_bytes > MAX_NETWORK_AGENT_TOOL_BODY_BYTES:
            raise ValueError("network tool request body exceeds agent-tool representable bound")
        if operation.limits.max_response_body_bytes > MAX_NETWORK_AGENT_TOOL_BODY_BYTES:
            raise ValueError("network tool response body exceeds agent-tool representable bound")

    @property
    def operation(self) -> NetworkEgressOperation:
        return self.profile.require_operation(self.operation_id)

    @property
    def resource(self) -> str:
        return network_http_resource(self.profile, self.operation)


def network_http_tool_descriptor(binding: NetworkEgressToolBinding) -> ToolDescriptor:
    """Return the strict model-facing descriptor for one exact trusted binding."""

    _require_binding(binding)
    operation = binding.operation
    effect = (
        ToolEffect.READ_ONLY
        if operation.effect is NetworkOperationEffect.READ_ONLY
        else ToolEffect.EXTERNAL_COMMUNICATION
    )
    return ToolDescriptor(
        tool_id=binding.tool_id,
        name="Controlled HTTP operation",
        description="Execute one bounded server-configured HTTP operation.",
        input_schema=ToolInputSchema(_input_schema(operation)),
        output_schema=ToolOutputSchema(_output_schema(operation)),
        effect=effect,
        approval_may_be_required=effect is not ToolEffect.READ_ONLY,
        max_input_bytes=MAX_NETWORK_AGENT_TOOL_INPUT_BYTES,
        max_output_bytes=MAX_NETWORK_AGENT_TOOL_OUTPUT_BYTES,
        timeout=operation.limits.total_timeout,
        resolver_id=NETWORK_HTTP_TOOL_RESOLVER_ID,
        adapter_id=NETWORK_HTTP_TOOL_ADAPTER_ID,
    )


def network_http_tool_resolver(
    binding: NetworkEgressToolBinding,
) -> StaticToolResourceResolver:
    """Bind every admitted call to the exact generation-bound network resource."""

    _require_binding(binding)
    return StaticToolResourceResolver(
        NETWORK_HTTP_TOOL_RESOLVER_ID,
        binding.resource,
    )


class NetworkHttpToolAdapter:
    """Translate one exact tool invocation into intersected fresh network authority."""

    adapter_id = NETWORK_HTTP_TOOL_ADAPTER_ID

    def __init__(
        self,
        service: NetworkEgressService,
        binding: NetworkEgressToolBinding,
    ) -> None:
        if not isinstance(service, NetworkEgressService):
            raise TypeError("service must be NetworkEgressService")
        _require_binding(binding)
        self._service = service
        self._binding = binding

    @property
    def tool_id(self) -> ToolId:
        return self._binding.tool_id

    async def invoke(self, request: ToolInvocationRequest) -> ToolInvocationResult:
        del request
        raise ToolExecutionError()

    async def invoke_with_context(
        self,
        request: ToolInvocationRequest,
        context: SecurityContext,
    ) -> ToolInvocationResult:
        del request, context
        raise ToolExecutionError()

    async def invoke_with_context_and_final_admission(
        self,
        request: ToolInvocationRequest,
        context: SecurityContext,
        final_admission: ToolFinalAdmissionValidator,
    ) -> ToolInvocationResult:
        if not isinstance(context, SecurityContext):
            raise TypeError("context must be SecurityContext")
        if not callable(final_admission):
            raise TypeError("final_admission must be callable")

        body = self._validated_body(request)
        network_request = NetworkHttpRequest(
            profile_id=self._binding.profile.profile_id,
            operation_id=self._binding.operation_id,
            body=body,
            created_at=request.created_at,
        )
        try:
            response = await self._service.request(
                network_request,
                context,
                deadline=request.deadline,
                expected_profile=self._binding.profile,
                final_admission=final_admission,
            )
        except NetworkEgressRequestError as exception:
            return _network_failure_result(request, exception)

        output = self._validated_output(network_request, response)
        return ToolInvocationResult(
            run_id=request.run_id,
            step_id=request.step_id,
            call_id=request.call_id,
            tool_id=request.tool_id,
            status=ToolResultStatus.SUCCEEDED,
            output=output,
            started_at=request.created_at,
            completed_at=request.created_at,
        )

    def _validated_body(self, request: ToolInvocationRequest) -> bytes:
        if not isinstance(request, ToolInvocationRequest):
            raise TypeError("request must be ToolInvocationRequest")
        if (
            request.agent_id != self._binding.agent_id
            or request.tool_id != self._binding.tool_id
            or request.resolved_resource != self._binding.resource
        ):
            raise ToolExecutionError()

        maximum = self._binding.operation.limits.max_request_body_bytes
        if maximum == 0:
            if request.arguments:
                raise ToolExecutionError()
            return b""

        if frozenset(request.arguments) != frozenset({"body_base64"}):
            raise ToolExecutionError()
        encoded = request.arguments.get("body_base64")
        if not isinstance(encoded, str):
            raise ToolExecutionError()
        try:
            ascii_bytes = encoded.encode("ascii")
            body = base64.b64decode(ascii_bytes, validate=True)
        except (UnicodeEncodeError, binascii.Error, ValueError):
            raise ToolExecutionError() from None
        if base64.b64encode(body) != ascii_bytes:
            raise ToolExecutionError()
        if len(body) > maximum or len(body) > MAX_NETWORK_AGENT_TOOL_BODY_BYTES:
            raise ToolExecutionError()
        return body

    def _validated_output(
        self,
        network_request: NetworkHttpRequest,
        response: NetworkHttpResponse,
    ) -> Mapping[str, AgentJsonInput]:
        if not isinstance(response, NetworkHttpResponse):
            raise ToolExecutionError()
        if (
            response.request_id != network_request.request_id
            or response.profile_id != self._binding.profile.profile_id
            or response.operation_id != self._binding.operation_id
            or len(response.body) > self._binding.operation.limits.max_response_body_bytes
            or len(response.body) > MAX_NETWORK_AGENT_TOOL_BODY_BYTES
        ):
            raise ToolExecutionError()

        body_base64 = base64.b64encode(response.body).decode("ascii")
        if len(body_base64) > MAX_TOOL_SCHEMA_STRING_LENGTH:
            raise ToolExecutionError()
        headers: list[dict[str, AgentJsonInput]] = [
            {"name": name, "value": value} for name, value in sorted(response.headers.items())
        ]
        return {
            "status_code": response.status_code,
            "body_base64": body_base64,
            "headers": headers,
        }


def _input_schema(operation: NetworkEgressOperation) -> ToolSchema:
    maximum = operation.limits.max_request_body_bytes
    if maximum == 0:
        return ToolSchema(kind=ToolSchemaType.OBJECT)

    return ToolSchema(
        kind=ToolSchemaType.OBJECT,
        properties={
            "body_base64": ToolSchema(
                kind=ToolSchemaType.STRING,
                max_length=_base64_length(maximum),
            )
        },
        required=frozenset({"body_base64"}),
    )


def _output_schema(operation: NetworkEgressOperation) -> ToolSchema:
    header = ToolSchema(
        kind=ToolSchemaType.OBJECT,
        properties={
            "name": ToolSchema(kind=ToolSchemaType.STRING, min_length=1, max_length=128),
            "value": ToolSchema(kind=ToolSchemaType.STRING, max_length=8_192),
        },
        required=frozenset({"name", "value"}),
    )
    return ToolSchema(
        kind=ToolSchemaType.OBJECT,
        properties={
            "status_code": ToolSchema(
                kind=ToolSchemaType.INTEGER,
                minimum=200,
                maximum=599,
            ),
            "body_base64": ToolSchema(
                kind=ToolSchemaType.STRING,
                max_length=_base64_length(operation.limits.max_response_body_bytes),
            ),
            "headers": ToolSchema(
                kind=ToolSchemaType.ARRAY,
                items=header,
                max_items=operation.limits.max_response_headers,
            ),
        },
        required=frozenset({"status_code", "body_base64", "headers"}),
    )


def _base64_length(raw_bytes: int) -> int:
    if isinstance(raw_bytes, bool) or not isinstance(raw_bytes, int) or raw_bytes < 0:
        raise TypeError("raw_bytes must be a non-negative integer")
    encoded = 4 * ((raw_bytes + 2) // 3)
    if encoded > MAX_TOOL_SCHEMA_STRING_LENGTH:
        raise ValueError("body cannot be represented by the agent tool schema")
    return encoded


def _network_failure_result(
    request: ToolInvocationRequest,
    error: NetworkEgressRequestError,
) -> ToolInvocationResult:
    if error.request_started or error.kind is NetworkEgressFailureKind.INDETERMINATE:
        status = ToolResultStatus.INDETERMINATE
        code = "network_indeterminate"
    elif error.kind is NetworkEgressFailureKind.CANCELLED:
        status = ToolResultStatus.CANCELLED
        code = "network_cancelled"
    elif error.kind is NetworkEgressFailureKind.TIMED_OUT:
        status = ToolResultStatus.FAILED
        code = "network_timeout"
    elif error.kind is NetworkEgressFailureKind.REJECTED:
        status = ToolResultStatus.FAILED
        code = "network_rejected"
    else:
        status = ToolResultStatus.FAILED
        code = "network_failed"
    return ToolInvocationResult(
        run_id=request.run_id,
        step_id=request.step_id,
        call_id=request.call_id,
        tool_id=request.tool_id,
        status=status,
        error_code=code,
        started_at=request.created_at,
        completed_at=request.created_at,
    )


def _require_binding(binding: NetworkEgressToolBinding) -> None:
    if not isinstance(binding, NetworkEgressToolBinding):
        raise TypeError("binding must be NetworkEgressToolBinding")
