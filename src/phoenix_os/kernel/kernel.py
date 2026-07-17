"""Headless asynchronous request orchestrator."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping

from phoenix_os.events import EventBus
from phoenix_os.kernel.contracts import (
    AuthorizationStatus,
    Authorizer,
    Request,
    Response,
)
from phoenix_os.kernel.errors import (
    AuthorizationDeniedError,
    ConfirmationRequiredError,
    DeadlineExceededError,
    KernelError,
)
from phoenix_os.kernel.router import Router


class Kernel:
    def __init__(
        self,
        *,
        router: Router,
        authorizer: Authorizer,
        events: EventBus | None = None,
        source: str = "phoenix.kernel",
    ) -> None:
        self._router = router
        self._authorizer = authorizer
        self._events = events
        self._source = source

    async def handle(self, request: Request, *, deadline: float | None = None) -> Response:
        try:
            if deadline is None:
                return await self._handle(request)
            try:
                async with asyncio.timeout(deadline):
                    return await self._handle(request)
            except TimeoutError as exception:
                raise DeadlineExceededError("request deadline exceeded") from exception
        except asyncio.CancelledError:
            await self._emit("kernel.request.cancelled", request)
            raise
        except KernelError as exception:
            await self._emit(
                "kernel.request.failed",
                request,
                {"code": exception.code, "status": exception.status},
            )
            return Response(
                status=exception.status,
                body={"error": exception.code, "message": str(exception)},
                request_id=request.id,
            )
        except Exception:
            await self._emit(
                "kernel.request.failed",
                request,
                {"code": "internal_error", "status": 500},
            )
            return Response(
                status=500,
                body={"error": "internal_error", "message": "internal request failure"},
                request_id=request.id,
            )

    async def _handle(self, request: Request) -> Response:
        await self._emit("kernel.request.received", request)
        route = self._router.resolve(request.action)
        await self._emit("kernel.route.resolved", request, {"action": route.action})

        decision = await self._authorizer.authorize(request, route)
        if decision.status is AuthorizationStatus.DENY:
            raise AuthorizationDeniedError(decision.reason or "request denied")
        if decision.status is AuthorizationStatus.CONFIRM and not request.confirmed:
            raise ConfirmationRequiredError(decision.reason or "explicit confirmation required")
        if route.sensitive and not request.confirmed:
            raise ConfirmationRequiredError("sensitive route requires explicit confirmation")

        await self._emit("kernel.handler.started", request)
        response = await route.handler(request)
        normalized = Response(
            status=response.status,
            body=response.body,
            request_id=request.id,
        )
        await self._emit(
            "kernel.request.completed",
            request,
            {"status": normalized.status},
        )
        return normalized

    async def _emit(
        self,
        name: str,
        request: Request,
        extra: Mapping[str, object] | None = None,
    ) -> None:
        if self._events is None:
            return
        payload: dict[str, object] = {
            "request_id": str(request.id),
            "action": request.action,
            "principal": request.principal,
        }
        if extra is not None:
            payload.update(extra)
        await self._events.emit(
            name,
            source=self._source,
            payload=payload,
            correlation_id=request.correlation_id,
            causation_id=request.id,
        )
