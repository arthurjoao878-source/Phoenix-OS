"""Explicit Phoenix Runtime lifecycle ownership for browser automation."""

from __future__ import annotations

from phoenix_os.browser_automation.service import BrowserAutomationService
from phoenix_os.runtime import ComponentSpec, PhoenixRuntime, RuntimeContext, RuntimeState

BROWSER_AUTOMATION_RUNTIME_COMPONENT_NAME = "browser_automation"
BROWSER_AUTOMATION_RUNTIME_SERVICE_NAME = "browser_automation"


class BrowserAutomationRuntimeComponent:
    """Bind one BrowserAutomationService to a PhoenixRuntime one-shot lifecycle."""

    def __init__(self, service: BrowserAutomationService) -> None:
        if not isinstance(service, BrowserAutomationService):
            raise TypeError("service must be BrowserAutomationService")
        self._service = service
        self._runtime: PhoenixRuntime | None = None
        service._bind_runtime_lifecycle()

    async def start(self, context: RuntimeContext) -> None:
        if not isinstance(context, RuntimeContext):
            raise TypeError("context must be RuntimeContext")
        if context.services.get(BROWSER_AUTOMATION_RUNTIME_SERVICE_NAME) is not self._service:
            raise RuntimeError("runtime browser_automation service identity mismatch")
        runtime = context.services.get("runtime")
        if not isinstance(runtime, PhoenixRuntime):
            raise RuntimeError("browser automation Runtime component requires PhoenixRuntime")
        if self._runtime is not None and self._runtime is not runtime:
            raise RuntimeError("browser automation Runtime component cannot change owners")
        self._runtime = runtime
        self._service._activate_runtime_lifecycle(lambda: runtime.state is RuntimeState.RUNNING)

    async def stop(self, context: RuntimeContext) -> None:
        if not isinstance(context, RuntimeContext):
            raise TypeError("context must be RuntimeContext")
        if context.services.get(BROWSER_AUTOMATION_RUNTIME_SERVICE_NAME) is not self._service:
            raise RuntimeError("runtime browser_automation service identity mismatch")
        await self._service.close()


def browser_automation_runtime_component_spec(
    service: BrowserAutomationService,
) -> ComponentSpec:
    """Return the canonical deterministic Runtime component registration."""

    return ComponentSpec(
        BROWSER_AUTOMATION_RUNTIME_COMPONENT_NAME,
        BrowserAutomationRuntimeComponent(service),
    )
