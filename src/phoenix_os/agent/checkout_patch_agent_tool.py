"""Narrow RFC-0039 workspace.patch tool descriptor and zero-effect request adapter."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import timedelta
from typing import cast
from uuid import UUID

from phoenix_os.agent.checkout_agent_tools import checkout_tool_surface_resource
from phoenix_os.agent.checkout_authorization import (
    CheckoutPatchAuthorizationRequest,
    CheckoutWorkspaceAuthorizer,
)
from phoenix_os.agent.checkout_patch_preparation import (
    MAX_CHECKOUT_PATCH_AFFECTED_LINES,
    MAX_CHECKOUT_PATCH_EDITS,
    MAX_CHECKOUT_PATCH_REPLACEMENT_BYTES,
    MAX_CHECKOUT_PATCH_REQUEST_BYTES,
    MAX_CHECKOUT_PATCH_TARGET_BYTES,
    CheckoutPatchEdit,
    CheckoutPatchPreparationRequest,
)
from phoenix_os.agent.checkout_workspace import (
    MAX_CHECKOUT_LOGICAL_PATH_BYTES,
    CheckoutFileSnapshot,
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
)
from phoenix_os.agent.errors import ToolExecutionError
from phoenix_os.agent.schemas import (
    MAX_TOOL_SCHEMA_STRING_LENGTH,
    ToolInputSchema,
    ToolOutputSchema,
    ToolSchema,
    ToolSchemaType,
)
from phoenix_os.agent.tools import ToolDescriptor, ToolFinalAdmissionValidator
from phoenix_os.policy import SecurityContext

CHECKOUT_PATCH_TOOL_ID = ToolId("workspace.patch")
CHECKOUT_PATCH_TOOL_RESOLVER_ID = "development-checkout-patch-resource"
CHECKOUT_PATCH_TOOL_ADAPTER_ID = "development-checkout-patch"
CHECKOUT_PATCH_TOOL_MAX_OUTPUT_BYTES = 8_192


def checkout_patch_tool_descriptor() -> ToolDescriptor:
    """Return the model-facing descriptor without enabling integrated dispatch."""

    edit_schema = _object(
        {
            "start_byte": _non_negative_integer(maximum=MAX_CHECKOUT_PATCH_TARGET_BYTES),
            "end_byte": _non_negative_integer(maximum=MAX_CHECKOUT_PATCH_TARGET_BYTES),
            "expected_text": _string(
                min_length=0,
                max_length=MAX_CHECKOUT_PATCH_REPLACEMENT_BYTES,
            ),
            "replacement_text": _string(
                min_length=0,
                max_length=MAX_CHECKOUT_PATCH_REPLACEMENT_BYTES,
            ),
        },
        required={
            "start_byte",
            "end_byte",
            "expected_text",
            "replacement_text",
        },
    )
    input_schema = ToolInputSchema(
        _object(
            {
                "logical_path": _string(max_length=MAX_CHECKOUT_LOGICAL_PATH_BYTES),
                "snapshot": _snapshot_schema(),
                "base_content_digest": _digest_schema(),
                "edits": ToolSchema(
                    kind=ToolSchemaType.ARRAY,
                    items=edit_schema,
                    min_items=1,
                    max_items=MAX_CHECKOUT_PATCH_EDITS,
                ),
            },
            required={
                "logical_path",
                "snapshot",
                "base_content_digest",
                "edits",
            },
        )
    )
    output_schema = ToolOutputSchema(
        _object(
            {
                "workspace_id": _uuid_schema(),
                "logical_path": _string(max_length=MAX_CHECKOUT_LOGICAL_PATH_BYTES),
                "before_content_digest": _digest_schema(),
                "after_content_digest": _digest_schema(),
                "preparation_digest": _digest_schema(),
                "changed_line_count": _positive_integer(maximum=MAX_CHECKOUT_PATCH_AFFECTED_LINES),
                "files_changed": _positive_integer(maximum=1),
                "review_status": _string(enum=("approved",)),
                "status": _string(enum=("applied",)),
            },
            required={
                "workspace_id",
                "logical_path",
                "before_content_digest",
                "after_content_digest",
                "preparation_digest",
                "changed_line_count",
                "files_changed",
                "review_status",
                "status",
            },
        )
    )
    return ToolDescriptor(
        tool_id=CHECKOUT_PATCH_TOOL_ID,
        name="Patch development checkout",
        description=(
            "Apply one bounded stale-safe UTF-8 text patch to an explicitly registered "
            "development checkout."
        ),
        input_schema=input_schema,
        output_schema=output_schema,
        effect=ToolEffect.REVERSIBLE_WRITE,
        approval_may_be_required=True,
        max_input_bytes=MAX_CHECKOUT_PATCH_REQUEST_BYTES,
        max_output_bytes=CHECKOUT_PATCH_TOOL_MAX_OUTPUT_BYTES,
        timeout=timedelta(minutes=2),
        resolver_id=CHECKOUT_PATCH_TOOL_RESOLVER_ID,
        adapter_id=CHECKOUT_PATCH_TOOL_ADAPTER_ID,
        metadata={
            "surface": "development-checkout",
            "downstream_action": str(CHECKOUT_PATCH_TOOL_ID),
            "durable_dispatch": "specialized",
        },
    )


class CheckoutPatchToolResourceResolver:
    """Bind generic tool admission to one exact checkout registration generation."""

    resolver_id = CHECKOUT_PATCH_TOOL_RESOLVER_ID

    def __init__(self, registration: RegisteredDevelopmentCheckout) -> None:
        if not isinstance(registration, RegisteredDevelopmentCheckout):
            raise TypeError("registration must be RegisteredDevelopmentCheckout")
        self._registration = registration

    @property
    def registration(self) -> RegisteredDevelopmentCheckout:
        return self._registration

    def resolve_resource(self, arguments: Mapping[str, AgentJsonValue]) -> str:
        if not isinstance(arguments, Mapping):
            raise TypeError("arguments must be a mapping")
        return checkout_tool_surface_resource(self._registration)


class CheckoutPatchToolAdapter:
    """Decode and exactly authorize patch requests without owning physical dispatch."""

    adapter_id = CHECKOUT_PATCH_TOOL_ADAPTER_ID

    def __init__(
        self,
        checkout: RegisteredDevelopmentCheckoutAdapter,
        authorizer: CheckoutWorkspaceAuthorizer,
    ) -> None:
        if not isinstance(checkout, RegisteredDevelopmentCheckoutAdapter):
            raise TypeError("checkout must be RegisteredDevelopmentCheckoutAdapter")
        if not isinstance(authorizer, CheckoutWorkspaceAuthorizer):
            raise TypeError("authorizer must implement CheckoutWorkspaceAuthorizer")
        self._checkout = checkout
        self._registration = checkout.registration
        self._authorizer = authorizer
        self._resolver = CheckoutPatchToolResourceResolver(self._registration)

    @property
    def tool_id(self) -> ToolId:
        return CHECKOUT_PATCH_TOOL_ID

    @property
    def checkout(self) -> RegisteredDevelopmentCheckoutAdapter:
        return self._checkout

    @property
    def registration(self) -> RegisteredDevelopmentCheckout:
        return self._registration

    @property
    def authorizer(self) -> CheckoutWorkspaceAuthorizer:
        return self._authorizer

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
        if not callable(final_admission):
            raise TypeError("final_admission must be callable")
        del request, context, final_admission
        raise ToolExecutionError()

    async def prepare_request_with_context(
        self,
        request: ToolInvocationRequest,
        context: SecurityContext,
    ) -> CheckoutPatchPreparationRequest:
        """Decode and authorize one zero-effect request for specialized durable dispatch."""

        if not isinstance(request, ToolInvocationRequest):
            raise TypeError("request must be ToolInvocationRequest")
        if not isinstance(context, SecurityContext):
            raise TypeError("context must be SecurityContext")
        if request.tool_id != CHECKOUT_PATCH_TOOL_ID:
            raise ToolExecutionError()
        expected_resource = self._resolver.resolve_resource(
            cast(Mapping[str, AgentJsonValue], request.arguments)
        )
        if request.resolved_resource != expected_resource:
            raise ToolExecutionError()

        preparation_request = _preparation_request(request)
        snapshot = preparation_request.snapshot
        if (
            snapshot.workspace_id != self._registration.workspace_id
            or snapshot.registration_generation != self._registration.generation
            or snapshot.root_identity != self._registration.root_identity
            or preparation_request.base_content_digest != snapshot.content_digest
        ):
            raise ToolExecutionError()
        await self._authorizer.authorize_patch(
            CheckoutPatchAuthorizationRequest(
                run_id=request.run_id,
                registration=self._registration,
                logical_path=preparation_request.snapshot.logical_path,
                created_at=request.created_at,
            ),
            context,
        )
        return preparation_request


def _preparation_request(request: ToolInvocationRequest) -> CheckoutPatchPreparationRequest:
    arguments = request.arguments
    logical_path = _required_string(arguments, "logical_path")
    try:
        canonical_path = canonical_checkout_logical_path(logical_path)
    except (TypeError, ValueError):
        raise ToolExecutionError() from None

    snapshot = _snapshot_argument(arguments)
    if snapshot.logical_path != canonical_path:
        raise ToolExecutionError()

    base_content_digest = _required_string(arguments, "base_content_digest")
    raw_edits = arguments.get("edits")
    if not isinstance(raw_edits, tuple):
        raise ToolExecutionError()

    edits: list[CheckoutPatchEdit] = []
    try:
        for item in raw_edits:
            if not isinstance(item, Mapping):
                raise ToolExecutionError()
            edits.append(
                CheckoutPatchEdit(
                    start_byte=_required_integer(item, "start_byte"),
                    end_byte=_required_integer(item, "end_byte"),
                    expected_text=_required_string(item, "expected_text", allow_empty=True),
                    replacement_text=_required_string(
                        item,
                        "replacement_text",
                        allow_empty=True,
                    ),
                )
            )
        return CheckoutPatchPreparationRequest(
            run_id=request.run_id,
            step_id=request.step_id,
            call_id=request.call_id,
            snapshot=snapshot,
            base_content_digest=base_content_digest,
            edits=tuple(edits),
        )
    except (TypeError, ValueError):
        raise ToolExecutionError() from None


def _snapshot_argument(arguments: Mapping[str, AgentJsonInput]) -> CheckoutFileSnapshot:
    raw = arguments.get("snapshot")
    if not isinstance(raw, Mapping):
        raise ToolExecutionError()
    try:
        run_id = AgentRunId(UUID(_required_string(raw, "run_id")))
        workspace_id = UUID(_required_string(raw, "workspace_id"))
        return CheckoutFileSnapshot(
            run_id=run_id,
            workspace_id=workspace_id,
            registration_generation=_required_integer(raw, "registration_generation"),
            logical_path=_required_string(raw, "logical_path"),
            root_identity=_required_string(raw, "root_identity"),
            file_identity=_required_string(raw, "file_identity"),
            content_digest=_required_string(raw, "content_digest"),
            byte_length=_required_integer(raw, "byte_length"),
        )
    except (TypeError, ValueError):
        raise ToolExecutionError() from None


def _required_string(
    values: Mapping[str, object],
    key: str,
    *,
    allow_empty: bool = False,
) -> str:
    value = values.get(key)
    if not isinstance(value, str) or (not allow_empty and not value):
        raise ToolExecutionError()
    return value


def _required_integer(values: Mapping[str, object], key: str) -> int:
    value = values.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ToolExecutionError()
    return value


def _snapshot_schema() -> ToolSchema:
    return _object(
        {
            "run_id": _uuid_schema(),
            "workspace_id": _uuid_schema(),
            "registration_generation": _positive_integer(),
            "logical_path": _string(max_length=MAX_CHECKOUT_LOGICAL_PATH_BYTES),
            "root_identity": _digest_schema(),
            "file_identity": _digest_schema(),
            "content_digest": _digest_schema(),
            "byte_length": _non_negative_integer(maximum=MAX_CHECKOUT_PATCH_TARGET_BYTES),
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


def _uuid_schema() -> ToolSchema:
    return _string(min_length=36, max_length=36)


def _digest_schema() -> ToolSchema:
    return _string(min_length=71, max_length=71)


def _positive_integer(*, maximum: int = 2**63 - 1) -> ToolSchema:
    return ToolSchema(kind=ToolSchemaType.INTEGER, minimum=1, maximum=maximum)


def _non_negative_integer(*, maximum: int = 2**63 - 1) -> ToolSchema:
    return ToolSchema(kind=ToolSchemaType.INTEGER, minimum=0, maximum=maximum)
