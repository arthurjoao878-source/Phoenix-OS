from __future__ import annotations

import pytest

from phoenix_os import (
    CapabilityConfirmationRequiredError,
    CapabilityContext,
    CapabilityDescriptor,
    CapabilityInvocation,
    CapabilityPermissionDeniedError,
    CapabilityRegistry,
    EventBus,
    HookPlugin,
    MemoryStateStore,
    PluginManager,
    PluginManifest,
    PluginSetupError,
    PolicyConfirmationPolicy,
    PolicyDeniedError,
    PolicyEffect,
    PolicyEngine,
    PolicyPermissionPolicy,
    PolicyProtectedPlugin,
    PolicyRule,
    PolicyStateStore,
    PrincipalType,
    SecurityContext,
    StateKey,
    StateOperationContext,
    capability_security_context,
    state_security_context,
)


def state_context() -> StateOperationContext:
    return StateOperationContext(
        correlation_id="request-1",
        metadata={
            "principal": "arthur",
            "principal_type": "user",
            "authenticated": "true",
            "roles": "admin,user",
            "permissions": "state.read,state.write",
            "scopes": "profile",
        },
    )


def test_capability_context_translation_is_explicit() -> None:
    invocation = CapabilityInvocation(
        "demo.echo",
        context=CapabilityContext(
            principal="arthur",
            permissions=frozenset({"demo.invoke"}),
            metadata={"roles": "admin,user", "scopes": "workspace"},
            correlation_id="request-1",
        ),
    )
    context = capability_security_context(invocation)
    assert context.principal_type is PrincipalType.USER
    assert context.authenticated
    assert context.roles == frozenset({"admin", "user"})
    assert context.permissions == frozenset({"demo.invoke"})
    assert context.scopes == frozenset({"workspace"})


def test_state_context_translation_uses_reserved_metadata() -> None:
    context = state_security_context(state_context())
    assert context.principal == "arthur"
    assert context.principal_type is PrincipalType.USER
    assert context.authenticated
    assert context.roles == frozenset({"admin", "user"})
    assert context.scopes == frozenset({"profile"})


@pytest.mark.asyncio
async def test_capability_registry_uses_central_allow_policy() -> None:
    engine = PolicyEngine(
        (
            PolicyRule(
                "allow-echo",
                PolicyEffect.ALLOW,
                actions=frozenset({"capability.invoke"}),
                resources=frozenset({"capability:demo.echo"}),
                principals=frozenset({"arthur"}),
            ),
        )
    )
    registry = CapabilityRegistry(
        permission_policy=PolicyPermissionPolicy(engine),
        confirmation_policy=PolicyConfirmationPolicy(engine),
    )

    async def provider(invocation: CapabilityInvocation) -> dict[str, object]:
        return {"value": invocation.arguments["value"]}

    await registry.register(CapabilityDescriptor("demo.echo"), provider)
    result = await registry.invoke(
        "demo.echo",
        {"value": 42},
        context=CapabilityContext(principal="arthur"),
    )
    assert result.output == {"value": 42}


@pytest.mark.asyncio
async def test_capability_registry_translates_policy_denial() -> None:
    engine = PolicyEngine()
    registry = CapabilityRegistry(
        permission_policy=PolicyPermissionPolicy(engine),
        confirmation_policy=PolicyConfirmationPolicy(engine),
    )
    await registry.register(CapabilityDescriptor("demo.echo"), lambda invocation: {})

    with pytest.raises(CapabilityPermissionDeniedError, match="default deny"):
        await registry.invoke("demo.echo", context=CapabilityContext(principal="arthur"))


@pytest.mark.asyncio
async def test_capability_registry_translates_confirmation_policy() -> None:
    engine = PolicyEngine(
        (
            PolicyRule(
                "confirm-delete",
                PolicyEffect.REQUIRE_CONFIRMATION,
                actions=frozenset({"capability.invoke"}),
                resources=frozenset({"capability:files.delete"}),
            ),
        )
    )
    registry = CapabilityRegistry(
        permission_policy=PolicyPermissionPolicy(engine),
        confirmation_policy=PolicyConfirmationPolicy(engine),
    )
    await registry.register(CapabilityDescriptor("files.delete"), lambda invocation: {})

    with pytest.raises(CapabilityConfirmationRequiredError):
        await registry.invoke("files.delete", context=CapabilityContext(principal="arthur"))
    result = await registry.invoke(
        "files.delete",
        context=CapabilityContext(principal="arthur", confirmed=True),
    )
    assert result.output == {}


@pytest.mark.asyncio
async def test_policy_state_store_allows_scoped_operations() -> None:
    engine = PolicyEngine(
        (
            PolicyRule(
                "profile-access",
                PolicyEffect.ALLOW,
                actions=frozenset({"state.read", "state.write", "state.list"}),
                resources=frozenset({"state:profile:*"}),
                principals=frozenset({"arthur"}),
                required_scopes=frozenset({"profile"}),
            ),
        )
    )
    store = PolicyStateStore(MemoryStateStore(), engine)
    key = StateKey("profile", "arthur", dict)
    written = await store.put(key, {"name": "Arthur"}, context=state_context())
    loaded = await store.get(key, context=state_context())
    listed = await store.list(namespace="profile", context=state_context())

    assert written.version == 1
    assert loaded is not None and loaded.value == {"name": "Arthur"}
    assert [record.key.canonical for record in listed] == ["profile:arthur"]


@pytest.mark.asyncio
async def test_policy_state_store_denies_other_namespaces() -> None:
    engine = PolicyEngine(
        (
            PolicyRule(
                "profile-only",
                PolicyEffect.ALLOW,
                actions=frozenset({"state.*"}),
                resources=frozenset({"state:profile:*"}),
            ),
        )
    )
    store = PolicyStateStore(MemoryStateStore(), engine)
    with pytest.raises(PolicyDeniedError, match="default deny"):
        await store.put(StateKey("system", "token", str), "secret", context=state_context())


@pytest.mark.asyncio
async def test_policy_state_transaction_authorizes_entry_and_operations() -> None:
    engine = PolicyEngine(
        (
            PolicyRule(
                "transaction",
                PolicyEffect.ALLOW,
                actions=frozenset({"state.transaction", "state.read", "state.write"}),
                resources=frozenset({"state:*"}),
                principals=frozenset({"arthur"}),
            ),
        )
    )
    store = PolicyStateStore(MemoryStateStore(), engine)
    key = StateKey("profile", "arthur", int)
    async with store.transaction(context=state_context()) as transaction:
        await transaction.put(key, 42)
        record = await transaction.get(key)
    assert record is not None and record.value == 42


@pytest.mark.asyncio
async def test_policy_protected_plugin_authorizes_lifecycle() -> None:
    calls: list[str] = []
    plugin = HookPlugin(
        PluginManifest("demo", "Demo", "1.0.0"),
        setup=lambda context: calls.append("setup"),
        start=lambda context: calls.append("start"),
        stop=lambda context: calls.append("stop"),
    )
    engine = PolicyEngine(
        (
            PolicyRule(
                "allow-demo",
                PolicyEffect.ALLOW,
                actions=frozenset({"plugin.setup", "plugin.start"}),
                resources=frozenset({"plugin:demo"}),
            ),
        )
    )
    bus = EventBus()
    capabilities = CapabilityRegistry(events=bus)
    manager = PluginManager(
        (PolicyProtectedPlugin(plugin, engine),),
        capabilities=capabilities,
        events=bus,
    )

    await manager.prepare()
    await manager.start(object())
    await manager.stop(object())
    assert calls == ["setup", "start", "stop"]


@pytest.mark.asyncio
async def test_policy_protected_plugin_denies_before_running_setup_hook() -> None:
    calls: list[str] = []
    plugin = HookPlugin(
        PluginManifest("demo", "Demo", "1.0.0"),
        setup=lambda context: calls.append("setup"),
        stop=lambda context: calls.append("stop"),
    )
    bus = EventBus()
    manager = PluginManager(
        (PolicyProtectedPlugin(plugin, PolicyEngine()),),
        capabilities=CapabilityRegistry(events=bus),
        events=bus,
    )

    with pytest.raises(PluginSetupError):
        await manager.prepare()
    assert calls == []


def test_security_context_can_represent_system_principal() -> None:
    context = SecurityContext(
        principal="phoenix.runtime",
        principal_type=PrincipalType.SYSTEM,
        authenticated=True,
    )
    assert context.principal_type is PrincipalType.SYSTEM
