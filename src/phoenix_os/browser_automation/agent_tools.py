"""Reviewed RFC-0027 to RFC-0035 browser tool composition for S6."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import timedelta
from uuid import UUID

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
from phoenix_os.browser_automation.authorization import (
    BROWSER_ELEMENT_CLICK_ACTION,
    BROWSER_ELEMENT_FILL_ACTION,
    BROWSER_PAGE_NAVIGATE_ACTION,
    BROWSER_PAGE_READ_ACTION,
    BROWSER_SESSION_CLOSE_ACTION,
    BROWSER_SESSION_OPEN_ACTION,
)
from phoenix_os.browser_automation.contracts import (
    MAX_BROWSER_PAGE_REVISION,
    BrowserAgentScope,
    BrowserElementId,
    BrowserFillInput,
    BrowserNavigationTargetId,
    BrowserOperationResult,
    BrowserPageDescriptor,
    BrowserPageId,
    BrowserPageRevision,
    BrowserPageSnapshot,
    BrowserProfileId,
    BrowserSessionId,
)
from phoenix_os.browser_automation.errors import (
    BrowserAutomationError,
    BrowserAutomationIndeterminateEffectError,
)
from phoenix_os.browser_automation.profiles import BrowserProfile
from phoenix_os.browser_automation.service import BrowserAutomationService
from phoenix_os.policy import SecurityContext

_BROWSER_ACTIONS = frozenset(
    {
        BROWSER_SESSION_OPEN_ACTION,
        BROWSER_SESSION_CLOSE_ACTION,
        BROWSER_PAGE_NAVIGATE_ACTION,
        BROWSER_PAGE_READ_ACTION,
        BROWSER_ELEMENT_FILL_ACTION,
        BROWSER_ELEMENT_CLICK_ACTION,
    }
)
_UUID_TEXT_LENGTH = 36


@dataclass(frozen=True, slots=True)
class BrowserToolBinding:
    """Server-owned binding from one exact agent tool to one exact browser boundary."""

    agent_id: AgentId
    tool_id: ToolId
    browser_action: str
    profile_id: BrowserProfileId
    profile_generation: int
    navigation_target_id: BrowserNavigationTargetId | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.agent_id, AgentId):
            raise TypeError("agent_id must be AgentId")
        if not isinstance(self.tool_id, ToolId):
            raise TypeError("tool_id must be ToolId")
        if not isinstance(self.browser_action, str) or self.browser_action not in _BROWSER_ACTIONS:
            raise ValueError("browser_action is not a finite RFC-0035 action")
        if not isinstance(self.profile_id, BrowserProfileId):
            raise TypeError("profile_id must be BrowserProfileId")
        if (
            isinstance(self.profile_generation, bool)
            or not isinstance(self.profile_generation, int)
            or self.profile_generation <= 0
        ):
            raise ValueError("profile_generation must be a positive integer")
        target = self.navigation_target_id
        if self.browser_action == BROWSER_PAGE_NAVIGATE_ACTION:
            if not isinstance(target, BrowserNavigationTargetId):
                raise ValueError("browser.page.navigate tool binding requires a fixed target")
        elif target is not None:
            raise ValueError("navigation_target_id is valid only for browser.page.navigate")

    @property
    def resolver_id(self) -> str:
        return _binding_implementation_id("resolver", self)

    @property
    def adapter_id(self) -> str:
        return _binding_implementation_id("adapter", self)


def browser_tool_resource(binding: BrowserToolBinding) -> str:
    """Return the static tool.invoke resource for one server-owned browser binding."""

    if not isinstance(binding, BrowserToolBinding):
        raise TypeError("binding must be BrowserToolBinding")
    resource = (
        f"browser:{binding.profile_id}/generation:{binding.profile_generation}"
        f"/action:{binding.browser_action}/tool:{binding.tool_id}"
    )
    if binding.navigation_target_id is not None:
        resource += f"/target:{binding.navigation_target_id}"
    return resource


def browser_tool_resolver(binding: BrowserToolBinding) -> StaticToolResourceResolver:
    if not isinstance(binding, BrowserToolBinding):
        raise TypeError("binding must be BrowserToolBinding")
    return StaticToolResourceResolver(binding.resolver_id, browser_tool_resource(binding))


def browser_tool_descriptor(
    binding: BrowserToolBinding,
    profile: BrowserProfile,
) -> ToolDescriptor:
    """Build one strict descriptor with no URL/selector/script escape hatches."""

    _require_binding_profile(binding, profile)
    if binding.navigation_target_id is not None:
        try:
            profile.require_target(binding.navigation_target_id)
        except KeyError as exception:
            raise ValueError("bound navigation target is not in the exact profile") from exception
    action = binding.browser_action
    effect = {
        BROWSER_SESSION_OPEN_ACTION: ToolEffect.REVERSIBLE_WRITE,
        BROWSER_SESSION_CLOSE_ACTION: ToolEffect.REVERSIBLE_WRITE,
        BROWSER_PAGE_NAVIGATE_ACTION: ToolEffect.EXTERNAL_COMMUNICATION,
        BROWSER_PAGE_READ_ACTION: ToolEffect.READ_ONLY,
        BROWSER_ELEMENT_FILL_ACTION: ToolEffect.REVERSIBLE_WRITE,
        BROWSER_ELEMENT_CLICK_ACTION: ToolEffect.EXTERNAL_COMMUNICATION,
    }[action]
    return ToolDescriptor(
        tool_id=binding.tool_id,
        name=_tool_name(action),
        description=_tool_description(action),
        input_schema=ToolInputSchema(_input_schema(action, profile)),
        output_schema=ToolOutputSchema(_output_schema(action, profile)),
        effect=effect,
        approval_may_be_required=False,
        max_input_bytes=MAX_AGENT_ARGUMENT_BYTES,
        max_output_bytes=MAX_AGENT_RESULT_BYTES,
        timeout=timedelta(seconds=profile.limits.operation_timeout_seconds),
        resolver_id=binding.resolver_id,
        adapter_id=binding.adapter_id,
    )


class BrowserToolAdapter:
    """Translate one exact server-owned tool binding into fresh browser authority."""

    def __init__(
        self,
        service: BrowserAutomationService,
        *,
        binding: BrowserToolBinding,
        profile: BrowserProfile,
    ) -> None:
        if not isinstance(service, BrowserAutomationService):
            raise TypeError("service must be BrowserAutomationService")
        _require_binding_profile(binding, profile)
        if binding.navigation_target_id is not None:
            try:
                profile.require_target(binding.navigation_target_id)
            except KeyError as exception:
                raise ValueError(
                    "bound navigation target is not in the exact profile"
                ) from exception
        self._service = service
        self._binding = binding
        self._profile = profile
        self._resource = browser_tool_resource(binding)

    @property
    def adapter_id(self) -> str:
        return self._binding.adapter_id

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
        if not isinstance(request, ToolInvocationRequest):
            raise TypeError("request must be ToolInvocationRequest")
        if not isinstance(context, SecurityContext):
            raise TypeError("context must be SecurityContext")
        if not callable(final_admission):
            raise TypeError("final_admission must be callable")

        if (
            request.tool_id != self.tool_id
            or request.agent_id != self._binding.agent_id
            or request.resolved_resource != self._resource
        ):
            raise ToolExecutionError()

        scope = BrowserAgentScope(
            agent_id=str(self._binding.agent_id),
            run_id=request.run_id.value,
        )
        action = self._binding.browser_action
        try:
            if action == BROWSER_SESSION_OPEN_ACTION:
                _require_keys(request.arguments, frozenset())
                result = await self._service.open_session(
                    self._profile.profile_id,
                    context,
                    deadline=request.deadline,
                    agent_scope=scope,
                    final_admission=final_admission,
                    expected_profile=self._profile,
                )
                output: Mapping[str, AgentJsonInput] = {
                    "profile_id": str(result.session.profile_id),
                    "profile_generation": result.session.profile_generation,
                    "session_id": str(result.session.session_id),
                    "page_id": str(result.page.page_id),
                    "revision": result.page.revision.value,
                }
            elif action == BROWSER_SESSION_CLOSE_ACTION:
                session_id = _session_only(request.arguments)
                operation = await self._service.close_session(
                    session_id,
                    context,
                    deadline=request.deadline,
                    agent_scope=scope,
                    final_admission=final_admission,
                )
                output = _operation_output(operation)
            elif action == BROWSER_PAGE_NAVIGATE_ACTION:
                page = _page_arguments(request.arguments)
                target_id = self._binding.navigation_target_id
                if target_id is None:  # pragma: no cover - binding invariant
                    raise ToolExecutionError()
                operation = await self._service.navigate(
                    page,
                    target_id,
                    context,
                    deadline=request.deadline,
                    agent_scope=scope,
                    final_admission=final_admission,
                )
                output = _operation_output(operation)
            elif action == BROWSER_PAGE_READ_ACTION:
                page = _page_arguments(request.arguments)
                snapshot = await self._service.read_page(
                    page,
                    context,
                    deadline=request.deadline,
                    agent_scope=scope,
                    final_admission=final_admission,
                )
                output = _snapshot_output(snapshot)
            elif action == BROWSER_ELEMENT_FILL_ACTION:
                page, element_id, value = _fill_arguments(request.arguments)
                operation = await self._service.fill_element(
                    page,
                    element_id,
                    value,
                    context,
                    deadline=request.deadline,
                    agent_scope=scope,
                    final_admission=final_admission,
                )
                output = _operation_output(operation)
            elif action == BROWSER_ELEMENT_CLICK_ACTION:
                page, element_id = _click_arguments(request.arguments)
                operation = await self._service.click_element(
                    page,
                    element_id,
                    context,
                    deadline=request.deadline,
                    agent_scope=scope,
                    final_admission=final_admission,
                )
                output = _operation_output(operation)
            else:  # pragma: no cover - finite binding invariant
                raise ToolExecutionError()
        except BrowserAutomationIndeterminateEffectError:
            return ToolInvocationResult(
                run_id=request.run_id,
                step_id=request.step_id,
                call_id=request.call_id,
                tool_id=request.tool_id,
                status=ToolResultStatus.INDETERMINATE,
                error_code="browser_indeterminate",
                started_at=request.created_at,
                completed_at=request.created_at,
            )
        except BrowserAutomationError as exception:
            raise ToolExecutionError() from exception

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


def _binding_implementation_id(kind: str, binding: BrowserToolBinding) -> str:
    material = (
        f"{kind}|{binding.agent_id}|{binding.tool_id}|{binding.browser_action}|"
        f"{binding.profile_id}|{binding.profile_generation}|{binding.navigation_target_id}"
    )
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:24]
    return f"browser-{kind}-{digest}"


def _require_binding_profile(binding: BrowserToolBinding, profile: BrowserProfile) -> None:
    if not isinstance(binding, BrowserToolBinding):
        raise TypeError("binding must be BrowserToolBinding")
    if not isinstance(profile, BrowserProfile):
        raise TypeError("profile must be BrowserProfile")
    if profile.profile_id != binding.profile_id or profile.generation != binding.profile_generation:
        raise ValueError("browser tool binding does not match the exact profile generation")


def _tool_name(action: str) -> str:
    return {
        BROWSER_SESSION_OPEN_ACTION: "Open bounded browser session",
        BROWSER_SESSION_CLOSE_ACTION: "Close bounded browser session",
        BROWSER_PAGE_NAVIGATE_ACTION: "Navigate to configured browser target",
        BROWSER_PAGE_READ_ACTION: "Read bounded browser page",
        BROWSER_ELEMENT_FILL_ACTION: "Fill exact browser element",
        BROWSER_ELEMENT_CLICK_ACTION: "Click exact browser element",
    }[action]


def _tool_description(action: str) -> str:
    return {
        BROWSER_SESSION_OPEN_ACTION: "Open one exact server-configured ephemeral browser session.",
        BROWSER_SESSION_CLOSE_ACTION: "Close one exact opaque browser session.",
        BROWSER_PAGE_NAVIGATE_ACTION: (
            "Navigate the current page to this tool's fixed server-owned target."
        ),
        BROWSER_PAGE_READ_ACTION: "Read one bounded current browser page snapshot.",
        BROWSER_ELEMENT_FILL_ACTION: "Fill one exact opaque current element with bounded text.",
        BROWSER_ELEMENT_CLICK_ACTION: (
            "Click one exact opaque current element under fresh browser and network admission."
        ),
    }[action]


def _uuid_schema() -> ToolSchema:
    return ToolSchema(
        kind=ToolSchemaType.STRING,
        min_length=_UUID_TEXT_LENGTH,
        max_length=_UUID_TEXT_LENGTH,
    )


def _page_properties() -> dict[str, ToolSchema]:
    return {
        "session_id": _uuid_schema(),
        "page_id": _uuid_schema(),
        "revision": ToolSchema(
            kind=ToolSchemaType.INTEGER,
            minimum=1,
            maximum=MAX_BROWSER_PAGE_REVISION,
        ),
    }


def _object_schema(
    properties: Mapping[str, ToolSchema],
    *,
    required: frozenset[str],
) -> ToolSchema:
    return ToolSchema(
        kind=ToolSchemaType.OBJECT,
        properties=properties,
        required=required,
    )


def _input_schema(action: str, profile: BrowserProfile) -> ToolSchema:
    if action == BROWSER_SESSION_OPEN_ACTION:
        return _object_schema({}, required=frozenset())
    if action == BROWSER_SESSION_CLOSE_ACTION:
        return _object_schema(
            {"session_id": _uuid_schema()},
            required=frozenset({"session_id"}),
        )
    page = _page_properties()
    if action in {BROWSER_PAGE_NAVIGATE_ACTION, BROWSER_PAGE_READ_ACTION}:
        return _object_schema(page, required=frozenset(page))
    page["element_id"] = _uuid_schema()
    if action == BROWSER_ELEMENT_CLICK_ACTION:
        return _object_schema(page, required=frozenset(page))
    if action == BROWSER_ELEMENT_FILL_ACTION:
        page["value"] = ToolSchema(
            kind=ToolSchemaType.STRING,
            max_length=profile.limits.max_fill_text_chars,
        )
        return _object_schema(page, required=frozenset(page))
    raise ValueError("unsupported browser tool action")


def _operation_output_schema() -> ToolSchema:
    properties = {
        "session_id": _uuid_schema(),
        "page_id": _uuid_schema(),
        "revision": ToolSchema(
            kind=ToolSchemaType.INTEGER,
            minimum=1,
            maximum=MAX_BROWSER_PAGE_REVISION,
        ),
        "effect_started": ToolSchema(kind=ToolSchemaType.BOOLEAN),
    }
    return _object_schema(properties, required=frozenset(properties))


def _output_schema(action: str, profile: BrowserProfile) -> ToolSchema:
    if action == BROWSER_SESSION_OPEN_ACTION:
        properties = {
            "profile_id": ToolSchema(kind=ToolSchemaType.STRING, min_length=1, max_length=128),
            "profile_generation": ToolSchema(
                kind=ToolSchemaType.INTEGER,
                minimum=1,
                maximum=2_147_483_647,
            ),
            "session_id": _uuid_schema(),
            "page_id": _uuid_schema(),
            "revision": ToolSchema(
                kind=ToolSchemaType.INTEGER,
                minimum=1,
                maximum=MAX_BROWSER_PAGE_REVISION,
            ),
        }
        return _object_schema(properties, required=frozenset(properties))
    if action == BROWSER_PAGE_READ_ACTION:
        element_properties = {
            "element_id": _uuid_schema(),
            "kind": ToolSchema(
                kind=ToolSchemaType.STRING,
                enum=(
                    "link",
                    "button",
                    "submit",
                    "text_input",
                    "text_area",
                    "checkbox",
                    "radio",
                ),
            ),
            "name": ToolSchema(
                kind=ToolSchemaType.STRING,
                max_length=profile.limits.max_element_name_chars,
            ),
            "value": ToolSchema(
                kind=ToolSchemaType.STRING,
                max_length=profile.limits.max_element_value_chars,
            ),
            "actions": ToolSchema(
                kind=ToolSchemaType.ARRAY,
                items=ToolSchema(
                    kind=ToolSchemaType.STRING,
                    enum=("click", "fill"),
                ),
                max_items=2,
            ),
        }
        element_schema = _object_schema(
            element_properties,
            required=frozenset({"element_id", "kind", "name", "actions"}),
        )
        properties = {
            "session_id": _uuid_schema(),
            "page_id": _uuid_schema(),
            "revision": ToolSchema(
                kind=ToolSchemaType.INTEGER,
                minimum=1,
                maximum=MAX_BROWSER_PAGE_REVISION,
            ),
            "title": ToolSchema(
                kind=ToolSchemaType.STRING,
                max_length=profile.limits.max_snapshot_title_chars,
            ),
            "text": ToolSchema(
                kind=ToolSchemaType.STRING,
                max_length=profile.limits.max_snapshot_text_chars,
            ),
            "elements": ToolSchema(
                kind=ToolSchemaType.ARRAY,
                items=element_schema,
                max_items=profile.limits.max_snapshot_elements,
            ),
        }
        return _object_schema(properties, required=frozenset(properties))
    return _operation_output_schema()


def _require_keys(
    arguments: Mapping[str, AgentJsonInput],
    expected: frozenset[str],
) -> None:
    if not isinstance(arguments, Mapping) or frozenset(arguments) != expected:
        raise ToolExecutionError()


def _uuid_argument(arguments: Mapping[str, AgentJsonInput], key: str) -> UUID:
    value = arguments.get(key)
    if not isinstance(value, str):
        raise ToolExecutionError()
    try:
        return UUID(value)
    except ValueError:
        raise ToolExecutionError() from None


def _revision_argument(arguments: Mapping[str, AgentJsonInput]) -> BrowserPageRevision:
    value = arguments.get("revision")
    if isinstance(value, bool) or not isinstance(value, int):
        raise ToolExecutionError()
    try:
        return BrowserPageRevision(value)
    except (TypeError, ValueError):
        raise ToolExecutionError() from None


def _page_arguments(arguments: Mapping[str, AgentJsonInput]) -> BrowserPageDescriptor:
    expected = frozenset({"session_id", "page_id", "revision"})
    _require_keys(arguments, expected)
    return BrowserPageDescriptor(
        session_id=BrowserSessionId(_uuid_argument(arguments, "session_id")),
        page_id=BrowserPageId(_uuid_argument(arguments, "page_id")),
        revision=_revision_argument(arguments),
    )


def _session_only(arguments: Mapping[str, AgentJsonInput]) -> BrowserSessionId:
    _require_keys(arguments, frozenset({"session_id"}))
    return BrowserSessionId(_uuid_argument(arguments, "session_id"))


def _fill_arguments(
    arguments: Mapping[str, AgentJsonInput],
) -> tuple[BrowserPageDescriptor, BrowserElementId, BrowserFillInput]:
    expected = frozenset({"session_id", "page_id", "revision", "element_id", "value"})
    _require_keys(arguments, expected)
    page = BrowserPageDescriptor(
        session_id=BrowserSessionId(_uuid_argument(arguments, "session_id")),
        page_id=BrowserPageId(_uuid_argument(arguments, "page_id")),
        revision=_revision_argument(arguments),
    )
    value = arguments.get("value")
    if not isinstance(value, str):
        raise ToolExecutionError()
    try:
        fill = BrowserFillInput(value)
    except (TypeError, ValueError):
        raise ToolExecutionError() from None
    return page, BrowserElementId(_uuid_argument(arguments, "element_id")), fill


def _click_arguments(
    arguments: Mapping[str, AgentJsonInput],
) -> tuple[BrowserPageDescriptor, BrowserElementId]:
    expected = frozenset({"session_id", "page_id", "revision", "element_id"})
    _require_keys(arguments, expected)
    page = BrowserPageDescriptor(
        session_id=BrowserSessionId(_uuid_argument(arguments, "session_id")),
        page_id=BrowserPageId(_uuid_argument(arguments, "page_id")),
        revision=_revision_argument(arguments),
    )
    return page, BrowserElementId(_uuid_argument(arguments, "element_id"))


def _operation_output(operation: BrowserOperationResult) -> Mapping[str, AgentJsonInput]:
    if not isinstance(operation, BrowserOperationResult):
        raise ToolExecutionError()
    if operation.session_id is None or operation.page_id is None or operation.revision is None:
        raise ToolExecutionError()
    return {
        "session_id": str(operation.session_id),
        "page_id": str(operation.page_id),
        "revision": operation.revision.value,
        "effect_started": operation.effect_started,
    }


def _snapshot_output(snapshot: BrowserPageSnapshot) -> Mapping[str, AgentJsonInput]:
    if not isinstance(snapshot, BrowserPageSnapshot):
        raise ToolExecutionError()
    elements: list[dict[str, AgentJsonInput]] = []
    for element in snapshot.elements:
        item: dict[str, AgentJsonInput] = {
            "element_id": str(element.element_id),
            "kind": element.kind.value,
            "name": element.name,
            "actions": [action.value for action in element.actions],
        }
        if element.value is not None:
            item["value"] = element.value
        elements.append(item)
    return {
        "session_id": str(snapshot.session_id),
        "page_id": str(snapshot.page_id),
        "revision": snapshot.revision.value,
        "title": snapshot.title,
        "text": snapshot.text,
        "elements": elements,
    }
