"""Secure, deterministic registry and invocation boundary for capabilities."""

from __future__ import annotations

import asyncio
import inspect
from collections.abc import Mapping
from dataclasses import dataclass
from uuid import UUID, uuid4

from phoenix_os.capabilities.contracts import (
    CapabilityContext,
    CapabilityDescriptor,
    CapabilityInvocation,
    CapabilityProvider,
    CapabilityRegistration,
    CapabilityResult,
    ConfirmationPolicy,
    ConfirmationStatus,
    PermissionPolicy,
    PermissionStatus,
)
from phoenix_os.capabilities.errors import (
    CapabilityAlreadyRegisteredError,
    CapabilityConfirmationRequiredError,
    CapabilityDeadlineExceededError,
    CapabilityExecutionError,
    CapabilityNotFoundError,
    CapabilityPermissionDeniedError,
    CapabilityPolicyError,
    CapabilityRegistryClosedError,
)
from phoenix_os.capabilities.policies import (
    DescriptorConfirmationPolicy,
    RequiredPermissionsPolicy,
)
from phoenix_os.events import EventBus


@dataclass(slots=True)
class _RegisteredCapability:
    registration: CapabilityRegistration
    descriptor: CapabilityDescriptor
    provider: CapabilityProvider
    sequence: int


class CapabilityRegistry:
    """Own capability discovery, policy evaluation, execution, and observation."""

    def __init__(
        self,
        *,
        permission_policy: PermissionPolicy | None = None,
        confirmation_policy: ConfirmationPolicy | None = None,
        events: EventBus | None = None,
        source: str = "phoenix.capabilities",
    ) -> None:
        self._permission_policy = permission_policy or RequiredPermissionsPolicy()
        self._confirmation_policy = confirmation_policy or DescriptorConfirmationPolicy()
        self._events = events
        self._source = source
        self._by_name: dict[str, _RegisteredCapability] = {}
        self._by_id: dict[UUID, str] = {}
        self._sequence = 0
        self._closed = False
        self._lock = asyncio.Lock()

    @property
    def closed(self) -> bool:
        return self._closed

    async def register(
        self,
        descriptor: CapabilityDescriptor,
        provider: CapabilityProvider,
    ) -> CapabilityRegistration:
        self._ensure_open()
        if not callable(provider):
            raise TypeError("provider must be callable")

        async with self._lock:
            self._ensure_open()
            if descriptor.name in self._by_name:
                raise CapabilityAlreadyRegisteredError(
                    f"capability already registered: {descriptor.name}"
                )
            registration = CapabilityRegistration(id=uuid4(), name=descriptor.name)
            registered = _RegisteredCapability(
                registration=registration,
                descriptor=descriptor,
                provider=provider,
                sequence=self._sequence,
            )
            self._sequence += 1
            self._by_name[descriptor.name] = registered
            self._by_id[registration.id] = descriptor.name
            return registration

    async def unregister(self, registration: CapabilityRegistration) -> bool:
        self._ensure_open()
        async with self._lock:
            self._ensure_open()
            name = self._by_id.get(registration.id)
            if name is None or name != registration.name:
                return False
            current = self._by_name.get(name)
            if current is None or current.registration != registration:
                return False
            del self._by_id[registration.id]
            del self._by_name[name]
            return True

    async def describe(self, name: str) -> CapabilityDescriptor:
        return (await self._resolve(name)).descriptor

    async def list_descriptors(self) -> tuple[CapabilityDescriptor, ...]:
        self._ensure_open()
        async with self._lock:
            self._ensure_open()
            registered = sorted(self._by_name.values(), key=lambda item: item.sequence)
            return tuple(item.descriptor for item in registered)

    async def invoke(
        self,
        name: str,
        arguments: Mapping[str, object] | None = None,
        *,
        context: CapabilityContext | None = None,
        deadline: float | None = None,
    ) -> CapabilityResult:
        self._ensure_open()
        if deadline is not None and deadline <= 0:
            raise ValueError("deadline must be greater than zero")

        registered = await self._resolve(name)
        invocation = CapabilityInvocation(
            capability=registered.descriptor.name,
            arguments={} if arguments is None else arguments,
            context=CapabilityContext() if context is None else context,
        )
        await self._emit("capability.invocation.received", invocation)

        try:
            permission = await self._permission_policy.decide(
                invocation,
                registered.descriptor,
            )
        except asyncio.CancelledError:
            await self._emit("capability.invocation.cancelled", invocation)
            raise
        except Exception as exception:
            await self._emit_failure(invocation, CapabilityPolicyError.code)
            raise CapabilityPolicyError("permission policy evaluation failed") from exception

        if permission.status is PermissionStatus.DENY:
            await self._emit(
                "capability.permission.denied",
                invocation,
                {"reason": permission.reason},
            )
            raise CapabilityPermissionDeniedError(
                permission.reason or "capability permission denied"
            )
        await self._emit("capability.permission.allowed", invocation)

        try:
            confirmation = await self._confirmation_policy.decide(
                invocation,
                registered.descriptor,
            )
        except asyncio.CancelledError:
            await self._emit("capability.invocation.cancelled", invocation)
            raise
        except Exception as exception:
            await self._emit_failure(invocation, CapabilityPolicyError.code)
            raise CapabilityPolicyError("confirmation policy evaluation failed") from exception

        if confirmation.status is ConfirmationStatus.REQUIRED and not invocation.context.confirmed:
            await self._emit(
                "capability.confirmation.required",
                invocation,
                {"reason": confirmation.reason},
            )
            raise CapabilityConfirmationRequiredError(
                confirmation.reason or "explicit capability confirmation required"
            )

        effective_timeout = (
            deadline if deadline is not None else registered.descriptor.default_timeout
        )
        await self._emit("capability.invocation.started", invocation)

        try:
            output = await self._execute(
                registered.provider,
                invocation,
                effective_timeout,
            )
        except asyncio.CancelledError:
            await self._emit("capability.invocation.cancelled", invocation)
            raise
        except TimeoutError as exception:
            await self._emit_failure(invocation, CapabilityDeadlineExceededError.code)
            raise CapabilityDeadlineExceededError(
                "capability execution deadline exceeded"
            ) from exception
        except Exception as exception:
            await self._emit_failure(invocation, CapabilityExecutionError.code)
            raise CapabilityExecutionError("capability execution failed") from exception

        result = CapabilityResult(invocation_id=invocation.id, output=output)
        await self._emit(
            "capability.invocation.completed",
            invocation,
            {"output_keys": tuple(sorted(output))},
        )
        return result

    async def close(self) -> None:
        async with self._lock:
            self._by_name.clear()
            self._by_id.clear()
            self._closed = True

    async def _resolve(self, name: str) -> _RegisteredCapability:
        self._ensure_open()
        normalized = name.strip()
        if not normalized:
            raise ValueError("capability name must not be blank")
        async with self._lock:
            self._ensure_open()
            try:
                return self._by_name[normalized]
            except KeyError as exception:
                raise CapabilityNotFoundError(f"capability not found: {normalized}") from exception

    async def _execute(
        self,
        provider: CapabilityProvider,
        invocation: CapabilityInvocation,
        deadline: float | None,
    ) -> Mapping[str, object]:
        async def run() -> Mapping[str, object]:
            output = provider(invocation)
            if inspect.isawaitable(output):
                output = await output
            if not isinstance(output, Mapping):
                raise TypeError("capability provider must return a mapping")
            return output

        if deadline is None:
            return await run()
        async with asyncio.timeout(deadline):
            return await run()

    async def _emit_failure(self, invocation: CapabilityInvocation, code: str) -> None:
        await self._emit(
            "capability.invocation.failed",
            invocation,
            {"code": code},
        )

    async def _emit(
        self,
        name: str,
        invocation: CapabilityInvocation,
        extra: Mapping[str, object] | None = None,
    ) -> None:
        if self._events is None:
            return
        payload: dict[str, object] = {
            "invocation_id": str(invocation.id),
            "capability": invocation.capability,
            "principal": invocation.context.principal,
        }
        if invocation.context.request_id is not None:
            payload["request_id"] = str(invocation.context.request_id)
        if extra is not None:
            payload.update(extra)
        await self._events.emit(
            name,
            source=self._source,
            payload=payload,
            correlation_id=invocation.context.correlation_id,
            causation_id=invocation.context.request_id,
        )

    def _ensure_open(self) -> None:
        if self._closed:
            raise CapabilityRegistryClosedError("capability registry is closed")
