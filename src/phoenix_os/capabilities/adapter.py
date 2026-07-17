"""Adapters that expose capabilities through Phoenix Kernel handlers."""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable

from phoenix_os.capabilities.contracts import CapabilityContext
from phoenix_os.capabilities.errors import CapabilityError
from phoenix_os.capabilities.registry import CapabilityRegistry
from phoenix_os.kernel import Request, Response

type CapabilityContextFactory = Callable[
    [Request], Awaitable[CapabilityContext] | CapabilityContext
]


def request_context(request: Request) -> CapabilityContext:
    """Build the conservative default context: no implicit permissions."""

    return CapabilityContext(
        principal=request.principal,
        request_id=request.id,
        correlation_id=request.correlation_id,
        confirmed=request.confirmed,
    )


class CapabilityHandler:
    """Translate a Kernel Request into a registry invocation and safe Response."""

    def __init__(
        self,
        registry: CapabilityRegistry,
        capability: str,
        *,
        context_factory: CapabilityContextFactory = request_context,
        timeout: float | None = None,
        success_status: int = 200,
    ) -> None:
        if not capability.strip():
            raise ValueError("capability must not be blank")
        if timeout is not None and timeout <= 0:
            raise ValueError("timeout must be greater than zero")
        self._registry = registry
        self._capability = capability.strip()
        self._context_factory = context_factory
        self._timeout = timeout
        self._success_status = success_status

    async def __call__(self, request: Request) -> Response:
        context = self._context_factory(request)
        if inspect.isawaitable(context):
            context = await context

        try:
            result = await self._registry.invoke(
                self._capability,
                request.payload,
                context=context,
                deadline=self._timeout,
            )
        except CapabilityError as exception:
            return Response(
                status=exception.status,
                body={"error": exception.code, "message": str(exception)},
                request_id=request.id,
            )
        return Response(
            status=self._success_status,
            body=result.output,
            request_id=request.id,
        )
