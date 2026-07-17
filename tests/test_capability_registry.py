import asyncio
from collections.abc import Mapping
from typing import cast
from uuid import uuid4

import pytest

from phoenix_os.capabilities import (
    CapabilityAlreadyRegisteredError,
    CapabilityConfirmationRequiredError,
    CapabilityContext,
    CapabilityDeadlineExceededError,
    CapabilityDescriptor,
    CapabilityExecutionError,
    CapabilityInvocation,
    CapabilityNotFoundError,
    CapabilityPermissionDeniedError,
    CapabilityPolicyError,
    CapabilityProvider,
    CapabilityRegistry,
    CapabilityRegistryClosedError,
    ConfirmationDecision,
    ConfirmationStatus,
    PermissionDecision,
    PermissionStatus,
)
from phoenix_os.events import Event, EventBus


@pytest.mark.asyncio
async def test_register_describe_and_list_preserve_registration_order() -> None:
    registry = CapabilityRegistry()

    async def provider(invocation: CapabilityInvocation) -> Mapping[str, object]:
        del invocation
        return {}

    second = CapabilityDescriptor(name="system.second")
    first = CapabilityDescriptor(name="system.first")
    await registry.register(second, provider)
    await registry.register(first, provider)

    assert await registry.describe("system.first") == first
    assert await registry.list_descriptors() == (second, first)


@pytest.mark.asyncio
async def test_duplicate_registration_is_rejected() -> None:
    registry = CapabilityRegistry()

    async def provider(invocation: CapabilityInvocation) -> Mapping[str, object]:
        del invocation
        return {}

    descriptor = CapabilityDescriptor(name="system.echo")
    await registry.register(descriptor, provider)

    with pytest.raises(CapabilityAlreadyRegisteredError):
        await registry.register(descriptor, provider)


@pytest.mark.asyncio
async def test_unregister_uses_opaque_handle() -> None:
    registry = CapabilityRegistry()

    async def provider(invocation: CapabilityInvocation) -> Mapping[str, object]:
        del invocation
        return {}

    registration = await registry.register(CapabilityDescriptor("system.echo"), provider)

    assert await registry.unregister(registration) is True
    assert await registry.unregister(registration) is False
    with pytest.raises(CapabilityNotFoundError):
        await registry.describe("system.echo")


@pytest.mark.asyncio
async def test_unregister_rejects_forged_or_unrelated_handle() -> None:
    registry = CapabilityRegistry()

    async def provider(invocation: CapabilityInvocation) -> Mapping[str, object]:
        del invocation
        return {}

    registration = await registry.register(CapabilityDescriptor("system.echo"), provider)
    forged_name = type(registration)(id=registration.id, name="system.other")
    unrelated = type(registration)(id=uuid4(), name="system.echo")

    assert await registry.unregister(forged_name) is False
    assert await registry.unregister(unrelated) is False
    assert await registry.describe("system.echo") == CapabilityDescriptor("system.echo")


@pytest.mark.asyncio
async def test_missing_capability_is_rejected() -> None:
    registry = CapabilityRegistry()

    with pytest.raises(CapabilityNotFoundError):
        await registry.invoke("missing")


@pytest.mark.asyncio
async def test_async_provider_receives_invocation_and_returns_normalized_result() -> None:
    registry = CapabilityRegistry()
    captured: list[CapabilityInvocation] = []

    async def provider(invocation: CapabilityInvocation) -> Mapping[str, object]:
        captured.append(invocation)
        return {"echo": invocation.arguments["value"]}

    await registry.register(CapabilityDescriptor("system.echo"), provider)
    context = CapabilityContext(principal="joao", correlation_id="corr-1")

    result = await registry.invoke("system.echo", {"value": "ok"}, context=context)

    assert result.output == {"echo": "ok"}
    assert result.invocation_id == captured[0].id
    assert captured[0].context is context


@pytest.mark.asyncio
async def test_synchronous_provider_is_supported() -> None:
    registry = CapabilityRegistry()

    def provider(invocation: CapabilityInvocation) -> Mapping[str, object]:
        return {"name": invocation.capability}

    await registry.register(CapabilityDescriptor("system.name"), provider)

    result = await registry.invoke("system.name")

    assert result.output == {"name": "system.name"}


@pytest.mark.asyncio
async def test_default_permission_policy_denies_missing_permissions() -> None:
    registry = CapabilityRegistry()
    called = False

    async def provider(invocation: CapabilityInvocation) -> Mapping[str, object]:
        nonlocal called
        del invocation
        called = True
        return {}

    await registry.register(
        CapabilityDescriptor(
            "files.read",
            required_permissions=frozenset({"files.read"}),
        ),
        provider,
    )

    with pytest.raises(CapabilityPermissionDeniedError, match=r"files\.read"):
        await registry.invoke("files.read", context=CapabilityContext(principal="joao"))

    assert called is False


@pytest.mark.asyncio
async def test_default_permission_policy_allows_complete_permissions() -> None:
    registry = CapabilityRegistry()

    async def provider(invocation: CapabilityInvocation) -> Mapping[str, object]:
        del invocation
        return {"allowed": True}

    await registry.register(
        CapabilityDescriptor(
            "files.read",
            required_permissions=frozenset({"files.read", "workspace.access"}),
        ),
        provider,
    )
    context = CapabilityContext(
        principal="joao",
        permissions=frozenset({"files.read", "workspace.access"}),
    )

    result = await registry.invoke("files.read", context=context)

    assert result.output == {"allowed": True}


@pytest.mark.asyncio
async def test_descriptor_confirmation_policy_requires_explicit_confirmation() -> None:
    registry = CapabilityRegistry()

    async def provider(invocation: CapabilityInvocation) -> Mapping[str, object]:
        del invocation
        return {"deleted": True}

    await registry.register(
        CapabilityDescriptor("files.delete", confirmation_required=True),
        provider,
    )

    with pytest.raises(CapabilityConfirmationRequiredError):
        await registry.invoke("files.delete")

    result = await registry.invoke(
        "files.delete",
        context=CapabilityContext(confirmed=True),
    )
    assert result.output == {"deleted": True}


@pytest.mark.asyncio
async def test_custom_policies_are_evaluated_in_permission_then_confirmation_order() -> None:
    calls: list[str] = []

    class PermissionPolicy:
        async def decide(
            self,
            invocation: CapabilityInvocation,
            descriptor: CapabilityDescriptor,
        ) -> PermissionDecision:
            del invocation, descriptor
            calls.append("permission")
            return PermissionDecision(PermissionStatus.ALLOW)

    class ConfirmationPolicy:
        async def decide(
            self,
            invocation: CapabilityInvocation,
            descriptor: CapabilityDescriptor,
        ) -> ConfirmationDecision:
            del invocation, descriptor
            calls.append("confirmation")
            return ConfirmationDecision(ConfirmationStatus.NOT_REQUIRED)

    async def provider(invocation: CapabilityInvocation) -> Mapping[str, object]:
        del invocation
        calls.append("provider")
        return {}

    registry = CapabilityRegistry(
        permission_policy=PermissionPolicy(),
        confirmation_policy=ConfirmationPolicy(),
    )
    await registry.register(CapabilityDescriptor("system.echo"), provider)

    await registry.invoke("system.echo")

    assert calls == ["permission", "confirmation", "provider"]


@pytest.mark.asyncio
async def test_explicit_timeout_overrides_descriptor_timeout() -> None:
    registry = CapabilityRegistry()

    async def provider(invocation: CapabilityInvocation) -> Mapping[str, object]:
        del invocation
        await asyncio.sleep(0.02)
        return {"done": True}

    await registry.register(
        CapabilityDescriptor("system.slow", default_timeout=0.001),
        provider,
    )

    result = await registry.invoke("system.slow", deadline=0.1)

    assert result.output == {"done": True}


@pytest.mark.asyncio
async def test_descriptor_timeout_becomes_safe_domain_error() -> None:
    registry = CapabilityRegistry()

    async def provider(invocation: CapabilityInvocation) -> Mapping[str, object]:
        del invocation
        await asyncio.sleep(1)
        return {}

    await registry.register(
        CapabilityDescriptor("system.slow", default_timeout=0.001),
        provider,
    )

    with pytest.raises(CapabilityDeadlineExceededError):
        await registry.invoke("system.slow")


@pytest.mark.asyncio
async def test_non_positive_explicit_timeout_is_rejected() -> None:
    registry = CapabilityRegistry()

    with pytest.raises(ValueError, match="deadline"):
        await registry.invoke("system.echo", deadline=0)


@pytest.mark.asyncio
async def test_provider_failure_is_wrapped_without_leaking_message() -> None:
    registry = CapabilityRegistry()

    async def provider(invocation: CapabilityInvocation) -> Mapping[str, object]:
        del invocation
        raise RuntimeError("secret credential and path")

    await registry.register(CapabilityDescriptor("system.fail"), provider)

    with pytest.raises(CapabilityExecutionError) as captured:
        await registry.invoke("system.fail")

    assert str(captured.value) == "capability execution failed"
    assert isinstance(captured.value.__cause__, RuntimeError)


@pytest.mark.asyncio
async def test_non_mapping_provider_result_is_rejected_safely() -> None:
    registry = CapabilityRegistry()

    def invalid_provider(invocation: CapabilityInvocation) -> str:
        del invocation
        return "invalid"

    await registry.register(
        CapabilityDescriptor("system.invalid"),
        cast(CapabilityProvider, invalid_provider),
    )

    with pytest.raises(CapabilityExecutionError):
        await registry.invoke("system.invalid")


@pytest.mark.asyncio
async def test_permission_policy_failure_is_wrapped() -> None:
    class BrokenPermissionPolicy:
        async def decide(
            self,
            invocation: CapabilityInvocation,
            descriptor: CapabilityDescriptor,
        ) -> PermissionDecision:
            del invocation, descriptor
            raise RuntimeError("policy internals")

    registry = CapabilityRegistry(permission_policy=BrokenPermissionPolicy())

    async def provider(invocation: CapabilityInvocation) -> Mapping[str, object]:
        del invocation
        return {}

    await registry.register(CapabilityDescriptor("system.echo"), provider)

    with pytest.raises(CapabilityPolicyError, match="permission"):
        await registry.invoke("system.echo")


@pytest.mark.asyncio
async def test_confirmation_policy_failure_is_wrapped() -> None:
    class BrokenConfirmationPolicy:
        async def decide(
            self,
            invocation: CapabilityInvocation,
            descriptor: CapabilityDescriptor,
        ) -> ConfirmationDecision:
            del invocation, descriptor
            raise RuntimeError("policy internals")

    registry = CapabilityRegistry(confirmation_policy=BrokenConfirmationPolicy())

    async def provider(invocation: CapabilityInvocation) -> Mapping[str, object]:
        del invocation
        return {}

    await registry.register(CapabilityDescriptor("system.echo"), provider)

    with pytest.raises(CapabilityPolicyError, match="confirmation"):
        await registry.invoke("system.echo")


@pytest.mark.asyncio
async def test_caller_cancellation_propagates() -> None:
    registry = CapabilityRegistry()
    started = asyncio.Event()

    async def provider(invocation: CapabilityInvocation) -> Mapping[str, object]:
        del invocation
        started.set()
        await asyncio.sleep(10)
        return {}

    await registry.register(CapabilityDescriptor("system.wait"), provider)
    task = asyncio.create_task(registry.invoke("system.wait"))
    await started.wait()
    task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await task


@pytest.mark.asyncio
async def test_successful_invocation_emits_ordered_correlated_events() -> None:
    events = EventBus()
    observed: list[Event] = []

    async def observer(event: Event) -> None:
        observed.append(event)

    await events.subscribe("*", observer)
    registry = CapabilityRegistry(events=events)

    async def provider(invocation: CapabilityInvocation) -> Mapping[str, object]:
        del invocation
        return {"reply": "pong"}

    await registry.register(CapabilityDescriptor("system.ping"), provider)
    context = CapabilityContext(principal="joao", correlation_id="corr-7")

    result = await registry.invoke("system.ping", context=context)

    assert [event.name for event in observed] == [
        "capability.invocation.received",
        "capability.permission.allowed",
        "capability.invocation.started",
        "capability.invocation.completed",
    ]
    assert all(event.correlation_id == "corr-7" for event in observed)
    assert all(event.payload["invocation_id"] == str(result.invocation_id) for event in observed)
    assert observed[-1].payload["output_keys"] == ("reply",)


@pytest.mark.asyncio
async def test_denied_invocation_emits_denial_without_starting_provider() -> None:
    events = EventBus()
    observed: list[str] = []

    async def observer(event: Event) -> None:
        observed.append(event.name)

    await events.subscribe("*", observer)
    registry = CapabilityRegistry(events=events)

    async def provider(invocation: CapabilityInvocation) -> Mapping[str, object]:
        del invocation
        return {}

    await registry.register(
        CapabilityDescriptor(
            "files.read",
            required_permissions=frozenset({"files.read"}),
        ),
        provider,
    )

    with pytest.raises(CapabilityPermissionDeniedError):
        await registry.invoke("files.read")

    assert observed == [
        "capability.invocation.received",
        "capability.permission.denied",
    ]


@pytest.mark.asyncio
async def test_event_observer_failure_does_not_break_invocation() -> None:
    events = EventBus()

    async def broken(event: Event) -> None:
        del event
        raise RuntimeError("observer failed")

    await events.subscribe("*", broken)
    registry = CapabilityRegistry(events=events)

    async def provider(invocation: CapabilityInvocation) -> Mapping[str, object]:
        del invocation
        return {"ok": True}

    await registry.register(CapabilityDescriptor("system.ok"), provider)

    result = await registry.invoke("system.ok")

    assert result.output == {"ok": True}


@pytest.mark.asyncio
async def test_close_is_idempotent_and_rejects_future_operations() -> None:
    registry = CapabilityRegistry()
    await registry.close()
    await registry.close()

    assert registry.closed
    with pytest.raises(CapabilityRegistryClosedError):
        await registry.list_descriptors()
    with pytest.raises(CapabilityRegistryClosedError):
        await registry.invoke("system.echo")
