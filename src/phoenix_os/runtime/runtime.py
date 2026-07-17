"""Deterministic composition and lifecycle ownership for Phoenix OS."""

from __future__ import annotations

import asyncio
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from types import TracebackType

from phoenix_os.capabilities import CapabilityRegistry
from phoenix_os.events import EventBus
from phoenix_os.kernel import Kernel, Request, Response
from phoenix_os.runtime.contracts import (
    ComponentFailure,
    ComponentSpec,
    RuntimeContext,
    RuntimePhase,
    RuntimeSnapshot,
    RuntimeState,
)
from phoenix_os.runtime.errors import (
    RuntimeDeadlineExceededError,
    RuntimeNotRunningError,
    RuntimeServiceNotFoundError,
    RuntimeStartError,
    RuntimeStateError,
    RuntimeStopError,
)

_RESERVED_SERVICES = frozenset({"kernel", "events", "capabilities", "runtime"})


class PhoenixRuntime:
    """Compose core services and own a deterministic, one-shot lifecycle."""

    def __init__(
        self,
        *,
        kernel: Kernel,
        events: EventBus,
        capabilities: CapabilityRegistry,
        components: Iterable[ComponentSpec] = (),
        services: Mapping[str, object] | None = None,
        metadata: Mapping[str, str] | None = None,
        source: str = "phoenix.runtime",
    ) -> None:
        normalized_source = source.strip()
        if not normalized_source:
            raise ValueError("source must not be blank")

        component_specs = tuple(components)
        component_names = [spec.name for spec in component_specs]
        if len(component_names) != len(set(component_names)):
            raise ValueError("component names must be unique")

        custom_services = {} if services is None else dict(services)
        conflicting = _RESERVED_SERVICES.intersection(name.strip() for name in custom_services)
        if conflicting:
            names = ", ".join(sorted(conflicting))
            raise ValueError(f"reserved service names cannot be replaced: {names}")

        composed_services: dict[str, object] = {
            "kernel": kernel,
            "events": events,
            "capabilities": capabilities,
        }
        composed_services.update(custom_services)
        self._context = RuntimeContext(
            services=composed_services,
            metadata={} if metadata is None else metadata,
        )
        # Expose the runtime itself without weakening the frozen context mapping.
        runtime_services = dict(self._context.services)
        runtime_services["runtime"] = self
        self._context = RuntimeContext(
            services=runtime_services,
            metadata=self._context.metadata,
            id=self._context.id,
            created_at=self._context.created_at,
        )

        self._kernel = kernel
        self._events = events
        self._capabilities = capabilities
        self._components = component_specs
        self._active: list[ComponentSpec] = []
        self._source = normalized_source
        self._state = RuntimeState.CREATED
        self._started_at: datetime | None = None
        self._stopped_at: datetime | None = None
        self._in_flight = 0
        self._current_component = "runtime"
        self._transition_lock = asyncio.Lock()
        self._activity = asyncio.Condition()

    @property
    def state(self) -> RuntimeState:
        return self._state

    @property
    def context(self) -> RuntimeContext:
        return self._context

    @property
    def services(self) -> Mapping[str, object]:
        return self._context.services

    def service(self, name: str) -> object:
        normalized = name.strip()
        if not normalized:
            raise ValueError("service name must not be blank")
        try:
            return self._context.services[normalized]
        except KeyError as exception:
            message = f"runtime service not found: {normalized}"
            raise RuntimeServiceNotFoundError(message) from exception

    async def snapshot(self) -> RuntimeSnapshot:
        async with self._activity:
            return RuntimeSnapshot(
                runtime_id=self._context.id,
                state=self._state,
                components=tuple(spec.name for spec in self._components),
                active_components=tuple(spec.name for spec in self._active),
                in_flight_requests=self._in_flight,
                created_at=self._context.created_at,
                started_at=self._started_at,
                stopped_at=self._stopped_at,
            )

    async def start(self, *, deadline: float | None = None) -> None:
        self._validate_deadline(deadline)
        async with self._transition_lock:
            if self._state is RuntimeState.RUNNING:
                return
            if self._state is not RuntimeState.CREATED:
                raise RuntimeStateError(f"cannot start runtime from state {self._state.value}")

            await self._set_state(RuntimeState.STARTING)
            self._started_at = datetime.now(UTC)
            await self._emit("runtime.starting")
            self._current_component = "runtime"

            try:
                if deadline is None:
                    await self._start_components()
                else:
                    async with asyncio.timeout(deadline):
                        await self._start_components()
            except asyncio.CancelledError:
                rollback_failures = await self._rollback()
                await self._set_state(RuntimeState.FAILED)
                await self._emit(
                    "runtime.start.cancelled",
                    {"rollback_failures": len(rollback_failures)},
                )
                raise
            except TimeoutError as exception:
                rollback_failures = await self._rollback()
                await self._set_state(RuntimeState.FAILED)
                await self._emit(
                    "runtime.start.failed",
                    {
                        "code": "deadline_exceeded",
                        "component": self._current_component,
                        "rollback_failures": len(rollback_failures),
                    },
                )
                raise RuntimeDeadlineExceededError(
                    RuntimePhase.START,
                    rollback_failures,
                ) from exception
            except Exception as exception:
                failure = ComponentFailure(self._current_component, RuntimePhase.START, exception)
                rollback_failures = await self._rollback()
                await self._set_state(RuntimeState.FAILED)
                await self._emit(
                    "runtime.start.failed",
                    {
                        "code": "component_failure",
                        "component": self._current_component,
                        "rollback_failures": len(rollback_failures),
                    },
                )
                raise RuntimeStartError(failure, rollback_failures) from exception

            await self._set_state(RuntimeState.RUNNING)
            await self._emit("runtime.started")

    async def stop(self, *, deadline: float | None = None) -> None:
        self._validate_deadline(deadline)
        async with self._transition_lock:
            if self._state is RuntimeState.STOPPED:
                return
            if self._state not in {
                RuntimeState.CREATED,
                RuntimeState.RUNNING,
                RuntimeState.FAILED,
            }:
                raise RuntimeStateError(f"cannot stop runtime from state {self._state.value}")

            await self._set_state(RuntimeState.STOPPING)
            await self._emit("runtime.stopping")

            try:
                if deadline is None:
                    failures = await self._stop_operation()
                else:
                    async with asyncio.timeout(deadline):
                        failures = await self._stop_operation()
            except asyncio.CancelledError:
                await self._set_state(RuntimeState.FAILED)
                await self._emit("runtime.stop.cancelled")
                raise
            except TimeoutError as exception:
                await self._set_state(RuntimeState.FAILED)
                await self._emit("runtime.stop.failed", {"code": "deadline_exceeded"})
                raise RuntimeDeadlineExceededError(RuntimePhase.STOP) from exception

            if failures:
                await self._set_state(RuntimeState.FAILED)
                await self._emit(
                    "runtime.stop.failed",
                    {
                        "code": "component_failure",
                        "failures": len(failures),
                    },
                )
                raise RuntimeStopError(failures)

            await self._capabilities.close()
            self._stopped_at = datetime.now(UTC)
            await self._set_state(RuntimeState.STOPPED)
            await self._emit("runtime.stopped")
            await self._events.close()

    async def close(self, *, deadline: float | None = None) -> None:
        await self.stop(deadline=deadline)

    async def handle(self, request: Request, *, deadline: float | None = None) -> Response:
        async with self._activity:
            if self._state is not RuntimeState.RUNNING:
                raise RuntimeNotRunningError(
                    f"runtime is not accepting requests in state {self._state.value}"
                )
            self._in_flight += 1

        try:
            return await self._kernel.handle(request, deadline=deadline)
        finally:
            async with self._activity:
                self._in_flight -= 1
                self._activity.notify_all()

    async def __aenter__(self) -> PhoenixRuntime:
        try:
            await self.start()
        except BaseException:
            try:
                await self.stop()
            except BaseException:
                pass
            raise
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del exc_type, exc, traceback
        await self.stop()

    async def _start_components(self) -> None:
        for spec in self._components:
            self._current_component = spec.name
            await self._start_component(spec)

    async def _start_component(self, spec: ComponentSpec) -> None:
        await self._emit(
            "runtime.component.starting",
            {"component": spec.name, "phase": RuntimePhase.START.value},
        )
        await spec.component.start(self._context)
        self._active.append(spec)
        await self._emit(
            "runtime.component.started",
            {"component": spec.name, "phase": RuntimePhase.START.value},
        )

    async def _rollback(self) -> tuple[ComponentFailure, ...]:
        failures: list[ComponentFailure] = []
        for spec in tuple(reversed(self._active)):
            await self._emit(
                "runtime.component.stopping",
                {"component": spec.name, "phase": RuntimePhase.ROLLBACK.value},
            )
            try:
                await spec.component.stop(self._context)
            except asyncio.CancelledError:
                raise
            except Exception as exception:
                failures.append(ComponentFailure(spec.name, RuntimePhase.ROLLBACK, exception))
            else:
                self._active.remove(spec)
                await self._emit(
                    "runtime.component.stopped",
                    {"component": spec.name, "phase": RuntimePhase.ROLLBACK.value},
                )
        return tuple(failures)

    async def _stop_operation(self) -> tuple[ComponentFailure, ...]:
        await self._wait_for_requests()
        failures: list[ComponentFailure] = []
        for spec in tuple(reversed(self._active)):
            await self._emit(
                "runtime.component.stopping",
                {"component": spec.name, "phase": RuntimePhase.STOP.value},
            )
            try:
                await spec.component.stop(self._context)
            except asyncio.CancelledError:
                raise
            except Exception as exception:
                failures.append(ComponentFailure(spec.name, RuntimePhase.STOP, exception))
            else:
                self._active.remove(spec)
                await self._emit(
                    "runtime.component.stopped",
                    {"component": spec.name, "phase": RuntimePhase.STOP.value},
                )
        return tuple(failures)

    async def _wait_for_requests(self) -> None:
        async with self._activity:
            while self._in_flight:
                await self._activity.wait()

    async def _set_state(self, state: RuntimeState) -> None:
        async with self._activity:
            self._state = state
            self._activity.notify_all()

    async def _emit(
        self,
        name: str,
        extra: Mapping[str, object] | None = None,
    ) -> None:
        payload: dict[str, object] = {
            "runtime_id": str(self._context.id),
            "state": self._state.value,
        }
        if extra is not None:
            payload.update(extra)
        await self._events.emit(
            name,
            source=self._source,
            payload=payload,
            correlation_id=str(self._context.id),
            causation_id=self._context.id,
        )

    @staticmethod
    def _validate_deadline(deadline: float | None) -> None:
        if deadline is not None and deadline <= 0:
            raise ValueError("deadline must be greater than zero")
