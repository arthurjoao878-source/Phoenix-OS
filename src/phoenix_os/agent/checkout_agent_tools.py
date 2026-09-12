"""Reviewed tool adapters for confined RFC-0039 development-checkout reads."""

from __future__ import annotations

import base64
import hashlib
from collections.abc import Mapping
from datetime import timedelta
from typing import Protocol, cast, runtime_checkable

from phoenix_os.agent.checkout_authorization import (
    CheckoutListAuthorizationRequest,
    CheckoutReadAuthorizationRequest,
    CheckoutWorkspaceAuthorizer,
)
from phoenix_os.agent.checkout_workspace import (
    MAX_CHECKOUT_LIST_ENTRIES,
    MAX_CHECKOUT_LOGICAL_PATH_BYTES,
    MAX_CHECKOUT_TEXT_READ_BYTES,
    CheckoutEntryCategory,
    CheckoutFileSnapshot,
    CheckoutListResult,
    CheckoutReadResult,
    RegisteredDevelopmentCheckout,
    RegisteredDevelopmentCheckoutAdapter,
    canonical_checkout_logical_path,
)
from phoenix_os.agent.contracts import (
    AgentJsonInput,
    AgentJsonValue,
    AgentRunId,
    ToolEffect,
    ToolId,
    ToolInvocationRequest,
    ToolInvocationResult,
    ToolResultStatus,
    canonical_agent_json_bytes,
    freeze_agent_json_object,
)
from phoenix_os.agent.errors import AgentError, ToolExecutionError
from phoenix_os.agent.schemas import (
    MAX_TOOL_SCHEMA_STRING_LENGTH,
    ToolInputSchema,
    ToolOutputSchema,
    ToolSchema,
    ToolSchemaType,
)
from phoenix_os.agent.tools import ToolDescriptor
from phoenix_os.policy import SecurityContext

CHECKOUT_LIST_TOOL_ID = ToolId("workspace.list")
CHECKOUT_READ_TOOL_ID = ToolId("workspace.read")
CHECKOUT_TOOL_RESOLVER_ID = "development-checkout-resource"
CHECKOUT_TOOL_ADAPTER_ID = "development-checkout-read"
CHECKOUT_TOOL_MAX_INPUT_BYTES = 8_192
CHECKOUT_LIST_TOOL_MAX_OUTPUT_BYTES = 262_144
CHECKOUT_READ_TOOL_MAX_OUTPUT_BYTES = 2_097_152
CHECKOUT_READ_BASE64_CHUNK_CHARS = 65_536
MAX_CHECKOUT_READ_BASE64_CHUNKS = (
    (((MAX_CHECKOUT_TEXT_READ_BYTES + 2) // 3) * 4) + CHECKOUT_READ_BASE64_CHUNK_CHARS - 1
) // CHECKOUT_READ_BASE64_CHUNK_CHARS

if CHECKOUT_READ_BASE64_CHUNK_CHARS > MAX_TOOL_SCHEMA_STRING_LENGTH:
    raise RuntimeError("checkout read chunk exceeds tool schema string limit")


def checkout_tool_descriptors() -> tuple[ToolDescriptor, ToolDescriptor]:
    """Return stable descriptors for the isolated checkout list/read surface."""

    return (
        _descriptor(CHECKOUT_LIST_TOOL_ID),
        _descriptor(CHECKOUT_READ_TOOL_ID),
    )


def checkout_tool_surface_resource(registration: RegisteredDevelopmentCheckout) -> str:
    """Return the server-owned resource used only for generic ``tool.invoke`` admission."""

    _require_registration(registration)
    return f"development-checkout:{registration.workspace_id}/generation:{registration.generation}"


def checkout_integrated_binding_id(registration: RegisteredDevelopmentCheckout) -> str:
    """Return the stable integrated capability identity for one registered checkout."""

    _require_registration(registration)
    return f"development-checkout:{registration.workspace_id}"


class CheckoutToolResourceResolver:
    """Bind generic tool admission to one exact server-registered checkout generation."""

    resolver_id = CHECKOUT_TOOL_RESOLVER_ID

    def __init__(self, registration: RegisteredDevelopmentCheckout) -> None:
        _require_registration(registration)
        self._registration = registration

    @property
    def registration(self) -> RegisteredDevelopmentCheckout:
        return self._registration

    def resolve_resource(self, arguments: Mapping[str, AgentJsonValue]) -> str:
        if not isinstance(arguments, Mapping):
            raise TypeError("arguments must be a mapping")
        return checkout_tool_surface_resource(self._registration)


@runtime_checkable
class CheckoutReadByteLimitProvider(Protocol):
    """Provide one server-owned byte cap for an already-prepared checkout read."""

    def take_read_byte_limit(self, request: ToolInvocationRequest) -> int: ...

    def discard_read_byte_limit(self, request: ToolInvocationRequest) -> None: ...


class CheckoutToolAdapter:
    """Authorize an exact checkout operation again before touching the filesystem."""

    adapter_id = CHECKOUT_TOOL_ADAPTER_ID

    def __init__(
        self,
        checkout: RegisteredDevelopmentCheckoutAdapter,
        authorizer: CheckoutWorkspaceAuthorizer,
        *,
        tool_id: ToolId,
        read_byte_limit_provider: CheckoutReadByteLimitProvider | None = None,
    ) -> None:
        if not isinstance(checkout, RegisteredDevelopmentCheckoutAdapter):
            raise TypeError("checkout must be RegisteredDevelopmentCheckoutAdapter")
        if not isinstance(authorizer, CheckoutWorkspaceAuthorizer):
            raise TypeError("authorizer must implement CheckoutWorkspaceAuthorizer")
        if tool_id not in {CHECKOUT_LIST_TOOL_ID, CHECKOUT_READ_TOOL_ID}:
            raise ValueError("tool_id must be workspace.list or workspace.read")
        if read_byte_limit_provider is not None and not isinstance(
            read_byte_limit_provider,
            CheckoutReadByteLimitProvider,
        ):
            raise TypeError(
                "read_byte_limit_provider must implement CheckoutReadByteLimitProvider or None"
            )
        self._checkout = checkout
        self._registration = checkout.registration
        self._authorizer = authorizer
        self._tool_id = tool_id
        self._read_byte_limit_provider = read_byte_limit_provider
        self._resolver = CheckoutToolResourceResolver(self._registration)

    @property
    def tool_id(self) -> ToolId:
        return self._tool_id

    @property
    def registration(self) -> RegisteredDevelopmentCheckout:
        return self._registration

    @property
    def authorizer(self) -> CheckoutWorkspaceAuthorizer:
        "Return the exact server-owned authorizer bound to this adapter."

        return self._authorizer

    async def is_list_result_current(
        self,
        *,
        prefix: str,
        max_entries: int,
        registration_generation: int,
        root_identity: str,
        listing_digest: str,
    ) -> bool:
        """Re-read one admitted list target and compare only content-free freshness evidence."""

        if (
            self._tool_id != CHECKOUT_LIST_TOOL_ID
            or registration_generation != self._registration.generation
            or root_identity != self._registration.root_identity
        ):
            return False
        try:
            result = await self._checkout.list(prefix, max_entries=max_entries)
            _validate_list_result(result, self._registration, prefix)
            output = _list_result_output(result)
            current_digest = (
                "sha256:"
                + hashlib.sha256(
                    canonical_agent_json_bytes(cast(Mapping[str, AgentJsonValue], output))
                ).hexdigest()
            )
        except (AgentError, TypeError, ValueError):
            return False
        return current_digest == listing_digest

    async def is_read_result_current(
        self,
        *,
        logical_path: str,
        run_id: AgentRunId,
        registration_generation: int,
        root_identity: str,
        file_identity: str,
        content_digest: str,
        byte_length: int,
    ) -> bool:
        """Re-read one admitted file and compare only content-free snapshot freshness evidence."""

        if (
            self._tool_id != CHECKOUT_READ_TOOL_ID
            or registration_generation != self._registration.generation
            or root_identity != self._registration.root_identity
        ):
            return False
        try:
            result = await self._checkout.read(logical_path, run_id=run_id)
            _validate_read_result(
                result,
                registration=self._registration,
                run_id=run_id,
                logical_path=logical_path,
            )
        except (AgentError, TypeError, ValueError):
            return False

        snapshot = result.snapshot
        return (
            snapshot.file_identity == file_identity
            and snapshot.content_digest == content_digest
            and snapshot.byte_length == byte_length
        )

    def bind_read_byte_limit_provider(
        self,
        provider: CheckoutReadByteLimitProvider,
    ) -> CheckoutToolAdapter:
        """Return one run-scoped read adapter without mutating this registry-owned adapter."""

        if self._tool_id != CHECKOUT_READ_TOOL_ID:
            raise ValueError("read byte limit provider binding requires workspace.read")
        if not isinstance(provider, CheckoutReadByteLimitProvider):
            raise TypeError("provider must implement CheckoutReadByteLimitProvider")
        if self._read_byte_limit_provider is not None:
            raise ValueError("checkout read adapter is already byte-limit bound")
        return CheckoutToolAdapter(
            self._checkout,
            self._authorizer,
            tool_id=self._tool_id,
            read_byte_limit_provider=provider,
        )

    async def invoke(self, request: ToolInvocationRequest) -> ToolInvocationResult:
        del request
        raise ToolExecutionError()

    async def invoke_with_context(
        self,
        request: ToolInvocationRequest,
        context: SecurityContext,
    ) -> ToolInvocationResult:
        if not isinstance(request, ToolInvocationRequest):
            raise TypeError("request must be ToolInvocationRequest")
        if not isinstance(context, SecurityContext):
            raise TypeError("context must be SecurityContext")
        self._validate_request_binding(request)
        if self._tool_id == CHECKOUT_LIST_TOOL_ID:
            output = await self._list(request, context)
            maximum = CHECKOUT_LIST_TOOL_MAX_OUTPUT_BYTES
        else:
            output = await self._read(request, context)
            maximum = CHECKOUT_READ_TOOL_MAX_OUTPUT_BYTES
        frozen_output = freeze_agent_json_object(output)
        if len(canonical_agent_json_bytes(frozen_output)) > maximum:
            raise ToolExecutionError()
        return _success(request, output)

    def _validate_request_binding(self, request: ToolInvocationRequest) -> None:
        if request.tool_id != self._tool_id:
            raise ToolExecutionError()
        expected = self._resolver.resolve_resource(
            cast(Mapping[str, AgentJsonValue], request.arguments)
        )
        if request.resolved_resource != expected:
            raise ToolExecutionError()

    async def _list(
        self,
        request: ToolInvocationRequest,
        context: SecurityContext,
    ) -> Mapping[str, AgentJsonInput]:
        prefix = _logical_path_argument(request.arguments, "prefix")
        max_entries = _optional_max_entries(request.arguments)
        await self._authorizer.authorize_list(
            CheckoutListAuthorizationRequest(
                run_id=request.run_id,
                registration=self._registration,
                prefix=prefix,
                max_entries=max_entries,
                created_at=request.created_at,
            ),
            context,
        )
        result = await self._checkout.list(prefix, max_entries=max_entries)
        _validate_list_result(result, self._registration, prefix)
        return _list_result_output(result)

    async def _read(
        self,
        request: ToolInvocationRequest,
        context: SecurityContext,
    ) -> Mapping[str, AgentJsonInput]:
        logical_path = _logical_path_argument(request.arguments, "logical_path")
        limit_provider = self._read_byte_limit_provider
        try:
            await self._authorizer.authorize_read(
                CheckoutReadAuthorizationRequest(
                    run_id=request.run_id,
                    registration=self._registration,
                    logical_path=logical_path,
                    created_at=request.created_at,
                ),
                context,
            )
            max_content_bytes = (
                None if limit_provider is None else limit_provider.take_read_byte_limit(request)
            )
            result = await self._checkout.read(
                logical_path,
                run_id=request.run_id,
                max_content_bytes=max_content_bytes,
            )
        finally:
            if limit_provider is not None:
                limit_provider.discard_read_byte_limit(request)
        _validate_read_result(
            result,
            registration=self._registration,
            run_id=request.run_id,
            logical_path=logical_path,
        )
        payload = result.text.encode("utf-8")
        encoded = base64.b64encode(payload).decode("ascii")
        chunks = [
            encoded[offset : offset + CHECKOUT_READ_BASE64_CHUNK_CHARS]
            for offset in range(0, len(encoded), CHECKOUT_READ_BASE64_CHUNK_CHARS)
        ]
        if len(chunks) > MAX_CHECKOUT_READ_BASE64_CHUNKS:
            raise ToolExecutionError()
        return {
            "snapshot": _snapshot_output(result.snapshot),
            "content_encoding": "base64-utf8",
            "content_base64_chunks": chunks,
        }


def _descriptor(tool_id: ToolId) -> ToolDescriptor:
    if tool_id == CHECKOUT_LIST_TOOL_ID:
        input_schema = ToolInputSchema(
            _object(
                {
                    "prefix": _logical_path_schema(),
                    "max_entries": _positive_integer(maximum=MAX_CHECKOUT_LIST_ENTRIES),
                },
                required={"prefix"},
            )
        )
        output_schema = ToolOutputSchema(
            _object(
                {
                    "workspace_id": _uuid_schema(),
                    "registration_generation": _positive_integer(),
                    "prefix": _logical_path_schema(),
                    "entries": ToolSchema(
                        kind=ToolSchemaType.ARRAY,
                        items=_object(
                            {
                                "logical_path": _logical_path_schema(),
                                "category": _string(
                                    enum=tuple(item.value for item in CheckoutEntryCategory)
                                ),
                            },
                            required={"logical_path", "category"},
                        ),
                        max_items=MAX_CHECKOUT_LIST_ENTRIES,
                    ),
                    "excluded_count": _non_negative_integer(),
                },
                required={
                    "workspace_id",
                    "registration_generation",
                    "prefix",
                    "entries",
                    "excluded_count",
                },
            )
        )
        name = "List development checkout"
        description = "List one bounded canonical prefix in the registered development checkout."
        maximum_output = CHECKOUT_LIST_TOOL_MAX_OUTPUT_BYTES
    elif tool_id == CHECKOUT_READ_TOOL_ID:
        input_schema = ToolInputSchema(
            _object(
                {"logical_path": _logical_path_schema()},
                required={"logical_path"},
            )
        )
        output_schema = ToolOutputSchema(
            _object(
                {
                    "snapshot": _snapshot_schema(),
                    "content_encoding": _string(enum=("base64-utf8",)),
                    "content_base64_chunks": ToolSchema(
                        kind=ToolSchemaType.ARRAY,
                        items=_string(max_length=CHECKOUT_READ_BASE64_CHUNK_CHARS),
                        max_items=MAX_CHECKOUT_READ_BASE64_CHUNKS,
                    ),
                },
                required={
                    "snapshot",
                    "content_encoding",
                    "content_base64_chunks",
                },
            )
        )
        name = "Read development checkout"
        description = (
            "Read one bounded canonical UTF-8 file from the registered development checkout."
        )
        maximum_output = CHECKOUT_READ_TOOL_MAX_OUTPUT_BYTES
    else:
        raise ValueError("unsupported checkout tool id")

    return ToolDescriptor(
        tool_id=tool_id,
        name=name,
        description=description,
        input_schema=input_schema,
        output_schema=output_schema,
        effect=ToolEffect.READ_ONLY,
        approval_may_be_required=False,
        max_input_bytes=CHECKOUT_TOOL_MAX_INPUT_BYTES,
        max_output_bytes=maximum_output,
        timeout=timedelta(minutes=2),
        resolver_id=CHECKOUT_TOOL_RESOLVER_ID,
        adapter_id=CHECKOUT_TOOL_ADAPTER_ID,
        metadata={
            "surface": "development-checkout",
            "downstream_action": str(tool_id),
        },
    )


def _snapshot_schema() -> ToolSchema:
    return _object(
        {
            "run_id": _uuid_schema(),
            "workspace_id": _uuid_schema(),
            "registration_generation": _positive_integer(),
            "logical_path": _logical_path_schema(),
            "root_identity": _digest_schema(),
            "file_identity": _digest_schema(),
            "content_digest": _digest_schema(),
            "byte_length": _non_negative_integer(maximum=MAX_CHECKOUT_TEXT_READ_BYTES),
        },
        required={
            "run_id",
            "workspace_id",
            "registration_generation",
            "logical_path",
            "root_identity",
            "file_identity",
            "content_digest",
            "byte_length",
        },
    )


def _list_result_output(result: CheckoutListResult) -> dict[str, AgentJsonInput]:
    if not isinstance(result, CheckoutListResult):
        raise ToolExecutionError()
    return {
        "workspace_id": str(result.workspace_id),
        "registration_generation": result.registration_generation,
        "prefix": result.prefix,
        "entries": [
            {
                "logical_path": entry.logical_path,
                "category": entry.category.value,
            }
            for entry in result.entries
        ],
        "excluded_count": result.excluded_count,
    }


def _snapshot_output(snapshot: CheckoutFileSnapshot) -> dict[str, AgentJsonInput]:
    if not isinstance(snapshot, CheckoutFileSnapshot):
        raise ToolExecutionError()
    return {
        "run_id": str(snapshot.run_id),
        "workspace_id": str(snapshot.workspace_id),
        "registration_generation": snapshot.registration_generation,
        "logical_path": snapshot.logical_path,
        "root_identity": snapshot.root_identity,
        "file_identity": snapshot.file_identity,
        "content_digest": snapshot.content_digest,
        "byte_length": snapshot.byte_length,
    }


def _validate_list_result(
    result: CheckoutListResult,
    registration: RegisteredDevelopmentCheckout,
    prefix: str,
) -> None:
    if (
        not isinstance(result, CheckoutListResult)
        or result.workspace_id != registration.workspace_id
        or result.registration_generation != registration.generation
        or result.prefix != prefix
    ):
        raise ToolExecutionError()


def _validate_read_result(
    result: CheckoutReadResult,
    *,
    registration: RegisteredDevelopmentCheckout,
    run_id: AgentRunId,
    logical_path: str,
) -> None:
    if not isinstance(result, CheckoutReadResult):
        raise ToolExecutionError()
    snapshot = result.snapshot
    if (
        snapshot.run_id != run_id
        or snapshot.workspace_id != registration.workspace_id
        or snapshot.registration_generation != registration.generation
        or snapshot.logical_path != logical_path
        or snapshot.root_identity != registration.root_identity
        or snapshot.byte_length != len(result.text.encode("utf-8"))
    ):
        raise ToolExecutionError()


def _logical_path_argument(
    arguments: Mapping[str, AgentJsonInput],
    key: str,
) -> str:
    value = arguments.get(key)
    if not isinstance(value, str):
        raise ToolExecutionError()
    try:
        return canonical_checkout_logical_path(value)
    except (TypeError, ValueError):
        raise ToolExecutionError() from None


def _optional_max_entries(arguments: Mapping[str, AgentJsonInput]) -> int:
    value = arguments.get("max_entries", MAX_CHECKOUT_LIST_ENTRIES)
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 1 <= value <= MAX_CHECKOUT_LIST_ENTRIES
    ):
        raise ToolExecutionError()
    return value


def _object(
    properties: Mapping[str, ToolSchema],
    *,
    required: set[str] | frozenset[str] | None = None,
) -> ToolSchema:
    return ToolSchema(
        kind=ToolSchemaType.OBJECT,
        properties=properties,
        required=frozenset() if required is None else frozenset(required),
    )


def _string(
    *,
    min_length: int = 1,
    max_length: int = MAX_TOOL_SCHEMA_STRING_LENGTH,
    enum: tuple[str, ...] = (),
) -> ToolSchema:
    return ToolSchema(
        kind=ToolSchemaType.STRING,
        min_length=min_length,
        max_length=max_length,
        enum=enum,
    )


def _logical_path_schema() -> ToolSchema:
    return _string(max_length=MAX_CHECKOUT_LOGICAL_PATH_BYTES)


def _uuid_schema() -> ToolSchema:
    return _string(min_length=36, max_length=36)


def _digest_schema() -> ToolSchema:
    return _string(min_length=71, max_length=71)


def _positive_integer(*, maximum: int = 2**63 - 1) -> ToolSchema:
    return ToolSchema(
        kind=ToolSchemaType.INTEGER,
        minimum=1,
        maximum=maximum,
    )


def _non_negative_integer(*, maximum: int = 2**63 - 1) -> ToolSchema:
    return ToolSchema(
        kind=ToolSchemaType.INTEGER,
        minimum=0,
        maximum=maximum,
    )


def _require_registration(value: RegisteredDevelopmentCheckout) -> None:
    if not isinstance(value, RegisteredDevelopmentCheckout):
        raise TypeError("registration must be RegisteredDevelopmentCheckout")


def _success(
    request: ToolInvocationRequest,
    output: Mapping[str, AgentJsonInput],
) -> ToolInvocationResult:
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
