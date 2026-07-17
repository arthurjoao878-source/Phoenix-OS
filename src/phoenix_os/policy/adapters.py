"""Adapters that apply the central policy engine at Phoenix boundaries."""

from __future__ import annotations

import inspect
from collections.abc import Callable
from datetime import timedelta
from typing import TypeVar, cast

from phoenix_os.capabilities import (
    CapabilityDescriptor,
    CapabilityInvocation,
    ConfirmationDecision,
    ConfirmationStatus,
    PermissionDecision,
    PermissionStatus,
)
from phoenix_os.plugins import Plugin, PluginContext, PluginManifest
from phoenix_os.policy.contracts import (
    PolicyEffect,
    PolicyRequest,
    PrincipalType,
    SecurityContext,
)
from phoenix_os.policy.engine import PolicyEngine
from phoenix_os.state import (
    RestoreMode,
    StateKey,
    StateOperationContext,
    StateRecord,
    StateSnapshot,
    StateStore,
    StateStoreStats,
    StateTransaction,
)

T = TypeVar("T")
type StateSecurityContextResolver = Callable[[StateOperationContext | None], SecurityContext]


def _split(value: str | None) -> frozenset[str]:
    if value is None:
        return frozenset()
    return frozenset(item.strip().lower() for item in value.split(",") if item.strip())


def capability_security_context(invocation: CapabilityInvocation) -> SecurityContext:
    """Translate a trusted CapabilityContext into the central security model."""

    context = invocation.context
    anonymous = context.principal.strip().lower() == "anonymous"
    return SecurityContext(
        principal=context.principal,
        principal_type=PrincipalType.ANONYMOUS if anonymous else PrincipalType.USER,
        authenticated=not anonymous,
        roles=_split(context.metadata.get("roles")),
        permissions=context.permissions,
        scopes=_split(context.metadata.get("scopes")),
        attributes=context.metadata,
        correlation_id=context.correlation_id,
        causation_id=context.request_id,
        confirmed=context.confirmed,
    )


class PolicyPermissionPolicy:
    """Capability permission adapter backed by a PolicyEngine."""

    def __init__(self, engine: PolicyEngine) -> None:
        self._engine = engine

    async def decide(
        self,
        invocation: CapabilityInvocation,
        descriptor: CapabilityDescriptor,
    ) -> PermissionDecision:
        decision = await self._engine.evaluate(
            PolicyRequest(
                action="capability.invoke",
                resource=f"capability:{descriptor.name}",
                context=capability_security_context(invocation),
                attributes={
                    "risk": descriptor.risk.value,
                    "version": descriptor.version,
                },
            )
        )
        if decision.effect is PolicyEffect.DENY:
            return PermissionDecision(PermissionStatus.DENY, decision.reason)
        return PermissionDecision(PermissionStatus.ALLOW, decision.reason)


class PolicyConfirmationPolicy:
    """Capability confirmation adapter backed by the same central rules."""

    def __init__(self, engine: PolicyEngine) -> None:
        self._engine = engine

    async def decide(
        self,
        invocation: CapabilityInvocation,
        descriptor: CapabilityDescriptor,
    ) -> ConfirmationDecision:
        decision = await self._engine.evaluate(
            PolicyRequest(
                action="capability.invoke",
                resource=f"capability:{descriptor.name}",
                context=capability_security_context(invocation),
                attributes={
                    "risk": descriptor.risk.value,
                    "version": descriptor.version,
                },
            )
        )
        if decision.effect is PolicyEffect.REQUIRE_CONFIRMATION:
            return ConfirmationDecision(ConfirmationStatus.REQUIRED, decision.reason)
        return ConfirmationDecision(ConfirmationStatus.NOT_REQUIRED, decision.reason)


def state_security_context(context: StateOperationContext | None) -> SecurityContext:
    """Build a security context from reserved StateOperationContext metadata."""

    if context is None:
        return SecurityContext()
    metadata = context.metadata
    principal = metadata.get("principal", "anonymous")
    anonymous = principal.strip().lower() == "anonymous"
    principal_type_value = metadata.get(
        "principal_type",
        PrincipalType.ANONYMOUS.value if anonymous else PrincipalType.USER.value,
    )
    return SecurityContext(
        principal=principal,
        principal_type=PrincipalType(principal_type_value),
        authenticated=metadata.get("authenticated", "false").lower() == "true",
        roles=_split(metadata.get("roles")),
        permissions=_split(metadata.get("permissions")),
        scopes=_split(metadata.get("scopes")),
        attributes=metadata,
        correlation_id=context.correlation_id,
        causation_id=context.causation_id,
        confirmed=metadata.get("confirmed", "false").lower() == "true",
    )


class PolicyStateStore:
    """StateStore decorator that authorizes every public operation."""

    def __init__(
        self,
        store: StateStore,
        engine: PolicyEngine,
        *,
        context_resolver: StateSecurityContextResolver = state_security_context,
        resource_prefix: str = "state",
    ) -> None:
        normalized = resource_prefix.strip().lower()
        if not normalized:
            raise ValueError("resource_prefix must not be blank")
        self._store = store
        self._engine = engine
        self._context_resolver = context_resolver
        self._resource_prefix = normalized

    @property
    def closed(self) -> bool:
        return self._store.closed

    async def get(
        self,
        key: StateKey[T],
        *,
        context: StateOperationContext | None = None,
    ) -> StateRecord[T] | None:
        await self._authorize("state.read", key.canonical, context)
        return await self._store.get(key, context=context)

    async def put(
        self,
        key: StateKey[T],
        value: T,
        *,
        expected_version: int | None = None,
        ttl: timedelta | None = None,
        context: StateOperationContext | None = None,
    ) -> StateRecord[T]:
        await self._authorize("state.write", key.canonical, context)
        return await self._store.put(
            key,
            value,
            expected_version=expected_version,
            ttl=ttl,
            context=context,
        )

    async def delete(
        self,
        key: StateKey[object],
        *,
        expected_version: int | None = None,
        context: StateOperationContext | None = None,
    ) -> bool:
        await self._authorize("state.delete", key.canonical, context)
        return await self._store.delete(
            key,
            expected_version=expected_version,
            context=context,
        )

    async def list(
        self,
        *,
        namespace: str | None = None,
        prefix: str | None = None,
        context: StateOperationContext | None = None,
    ) -> tuple[StateRecord[object], ...]:
        target = "*" if namespace is None else f"{namespace}:{prefix or '*'}"
        await self._authorize("state.list", target, context)
        return await self._store.list(namespace=namespace, prefix=prefix, context=context)

    def transaction(
        self,
        *,
        context: StateOperationContext | None = None,
    ) -> StateTransaction:
        # Transaction creation is synchronous in the StateStore contract. Per-operation
        # authorization remains enforced by wrapping the returned transaction.
        return _PolicyStateTransaction(
            self._store.transaction(context=context),
            self._engine,
            self._context_resolver(context),
            self._resource_prefix,
        )

    async def snapshot(
        self,
        *,
        context: StateOperationContext | None = None,
    ) -> StateSnapshot:
        await self._authorize("state.snapshot", "*", context)
        return await self._store.snapshot(context=context)

    async def restore(
        self,
        snapshot: StateSnapshot,
        *,
        mode: RestoreMode = RestoreMode.REPLACE,
        context: StateOperationContext | None = None,
    ) -> int:
        await self._authorize("state.restore", "*", context)
        return await self._store.restore(snapshot, mode=mode, context=context)

    async def purge_expired(
        self,
        *,
        context: StateOperationContext | None = None,
    ) -> int:
        await self._authorize("state.maintain", "*", context)
        return await self._store.purge_expired(context=context)

    async def stats(self) -> StateStoreStats:
        await self._engine.enforce(
            PolicyRequest(
                action="state.stats",
                resource=f"{self._resource_prefix}:*",
                context=SecurityContext(
                    principal="phoenix.state",
                    principal_type=PrincipalType.SYSTEM,
                    authenticated=True,
                ),
            )
        )
        return await self._store.stats()

    async def close(self) -> None:
        await self._store.close()

    async def start(self, context: object) -> None:
        await self._store.start(context)

    async def stop(self, context: object) -> None:
        await self._store.stop(context)

    async def _authorize(
        self,
        action: str,
        target: str,
        context: StateOperationContext | None,
    ) -> None:
        await self._engine.enforce(
            PolicyRequest(
                action=action,
                resource=f"{self._resource_prefix}:{target}",
                context=self._context_resolver(context),
            )
        )


class _PolicyStateTransaction:
    def __init__(
        self,
        transaction: StateTransaction,
        engine: PolicyEngine,
        context: SecurityContext,
        resource_prefix: str,
    ) -> None:
        self._transaction = transaction
        self._engine = engine
        self._context = context
        self._resource_prefix = resource_prefix

    @property
    def state(self):  # type: ignore[no-untyped-def]
        return self._transaction.state

    async def __aenter__(self) -> StateTransaction:
        await self._engine.enforce(
            PolicyRequest(
                "state.transaction",
                f"{self._resource_prefix}:*",
                self._context,
            )
        )
        await self._transaction.__aenter__()
        return cast(StateTransaction, self)

    async def __aexit__(self, exc_type, exc, traceback):  # type: ignore[no-untyped-def]
        await self._transaction.__aexit__(exc_type, exc, traceback)

    async def get(self, key: StateKey[T]) -> StateRecord[T] | None:
        await self._authorize("state.read", key.canonical)
        return await self._transaction.get(key)

    async def put(
        self,
        key: StateKey[T],
        value: T,
        *,
        expected_version: int | None = None,
        ttl: timedelta | None = None,
    ) -> StateRecord[T]:
        await self._authorize("state.write", key.canonical)
        return await self._transaction.put(
            key,
            value,
            expected_version=expected_version,
            ttl=ttl,
        )

    async def delete(
        self,
        key: StateKey[object],
        *,
        expected_version: int | None = None,
    ) -> bool:
        await self._authorize("state.delete", key.canonical)
        return await self._transaction.delete(key, expected_version=expected_version)

    async def list(
        self,
        *,
        namespace: str | None = None,
        prefix: str | None = None,
    ) -> tuple[StateRecord[object], ...]:
        target = "*" if namespace is None else f"{namespace}:{prefix or '*'}"
        await self._authorize("state.list", target)
        return await self._transaction.list(namespace=namespace, prefix=prefix)

    async def commit(self) -> None:
        await self._transaction.commit()

    async def rollback(self) -> None:
        await self._transaction.rollback()

    async def _authorize(self, action: str, target: str) -> None:
        await self._engine.enforce(
            PolicyRequest(
                action,
                f"{self._resource_prefix}:{target}",
                self._context,
            )
        )


class PolicyProtectedPlugin:
    """Plugin decorator that authorizes setup and activation."""

    def __init__(self, plugin: Plugin, engine: PolicyEngine) -> None:
        self._plugin = plugin
        self._engine = engine
        self.manifest: PluginManifest = plugin.manifest

    async def setup(self, context: PluginContext) -> None:
        await self._authorize("plugin.setup")
        await _invoke(self._plugin, "setup", context)

    async def start(self, context: PluginContext) -> None:
        await self._authorize("plugin.start")
        await _invoke(self._plugin, "start", context)

    async def stop(self, context: PluginContext) -> None:
        # Cleanup must never be blocked after a plugin acquired resources.
        await _invoke(self._plugin, "stop", context)

    async def _authorize(self, action: str) -> None:
        permissions = frozenset(item.value for item in self.manifest.permissions)
        await self._engine.enforce(
            PolicyRequest(
                action=action,
                resource=f"plugin:{self.manifest.plugin_id}",
                context=SecurityContext(
                    principal=f"plugin:{self.manifest.plugin_id}",
                    principal_type=PrincipalType.PLUGIN,
                    authenticated=True,
                    permissions=permissions,
                    attributes={"version": str(self.manifest.version)},
                ),
            )
        )


async def _invoke(plugin: Plugin, name: str, context: PluginContext) -> None:
    hook = getattr(plugin, name, None)
    if hook is None:
        return
    result = hook(context)
    if inspect.isawaitable(result):
        await result
