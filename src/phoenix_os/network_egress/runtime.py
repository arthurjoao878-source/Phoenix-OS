"""Explicit Phoenix Runtime lifecycle ownership for network egress."""

from __future__ import annotations

from phoenix_os.network_egress.service import NetworkEgressService
from phoenix_os.runtime import ComponentSpec, PhoenixRuntime, RuntimeContext, RuntimeState

NETWORK_EGRESS_RUNTIME_COMPONENT_NAME = "network_egress"
NETWORK_EGRESS_RUNTIME_SERVICE_NAME = "network_egress"


class NetworkEgressRuntimeComponent:
    """Bind one NetworkEgressService to a PhoenixRuntime one-shot lifecycle."""

    def __init__(self, service: NetworkEgressService) -> None:
        if not isinstance(service, NetworkEgressService):
            raise TypeError("service must be NetworkEgressService")
        self._service = service
        self._runtime: PhoenixRuntime | None = None
        service._bind_runtime_lifecycle()

    async def start(self, context: RuntimeContext) -> None:
        if not isinstance(context, RuntimeContext):
            raise TypeError("context must be RuntimeContext")
        if context.services.get(NETWORK_EGRESS_RUNTIME_SERVICE_NAME) is not self._service:
            raise RuntimeError("runtime network_egress service identity mismatch")
        runtime = context.services.get("runtime")
        if not isinstance(runtime, PhoenixRuntime):
            raise RuntimeError("network egress Runtime component requires PhoenixRuntime")
        if self._runtime is not None and self._runtime is not runtime:
            raise RuntimeError("network egress Runtime component cannot change owners")
        self._runtime = runtime
        self._service._activate_runtime_lifecycle(lambda: runtime.state is RuntimeState.RUNNING)

    async def stop(self, context: RuntimeContext) -> None:
        if not isinstance(context, RuntimeContext):
            raise TypeError("context must be RuntimeContext")
        if context.services.get(NETWORK_EGRESS_RUNTIME_SERVICE_NAME) is not self._service:
            raise RuntimeError("runtime network_egress service identity mismatch")
        await self._service.close()


def network_egress_runtime_component_spec(
    service: NetworkEgressService,
) -> ComponentSpec:
    """Return the canonical deterministic Runtime component registration."""

    return ComponentSpec(
        NETWORK_EGRESS_RUNTIME_COMPONENT_NAME,
        NetworkEgressRuntimeComponent(service),
    )
