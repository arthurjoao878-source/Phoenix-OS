"""Policy Engine, Capability Registry, and State Store integration example."""

from __future__ import annotations

import asyncio

from phoenix_os import (
    CapabilityContext,
    CapabilityDescriptor,
    CapabilityInvocation,
    CapabilityRegistry,
    MemoryStateStore,
    PolicyConfirmationPolicy,
    PolicyEffect,
    PolicyEngine,
    PolicyPermissionPolicy,
    PolicyRequest,
    PolicyRule,
    PolicyStateStore,
    PrincipalType,
    SecurityContext,
    StateKey,
    StateOperationContext,
)


async def main() -> None:
    policy = PolicyEngine(
        (
            PolicyRule(
                "allow-profile",
                PolicyEffect.ALLOW,
                actions=frozenset({"state.read", "state.write"}),
                resources=frozenset({"state:profile:*"}),
                principals=frozenset({"arthur"}),
                required_scopes=frozenset({"profile"}),
                priority=100,
            ),
            PolicyRule(
                "confirm-delete",
                PolicyEffect.REQUIRE_CONFIRMATION,
                actions=frozenset({"capability.invoke"}),
                resources=frozenset({"capability:files.delete"}),
                priority=100,
            ),
        )
    )

    state = PolicyStateStore(MemoryStateStore(), policy)
    context = StateOperationContext(
        metadata={
            "principal": "arthur",
            "principal_type": "user",
            "authenticated": "true",
            "scopes": "profile",
        }
    )
    profile = StateKey("profile", "arthur", dict)
    await state.put(profile, {"level": 9}, context=context)
    print((await state.get(profile, context=context)).value)  # type: ignore[union-attr]

    capabilities = CapabilityRegistry(
        permission_policy=PolicyPermissionPolicy(policy),
        confirmation_policy=PolicyConfirmationPolicy(policy),
    )

    async def delete_file(invocation: CapabilityInvocation) -> dict[str, object]:
        return {"deleted": invocation.arguments["path"]}

    await capabilities.register(CapabilityDescriptor("files.delete"), delete_file)
    result = await capabilities.invoke(
        "files.delete",
        {"path": "draft.txt"},
        context=CapabilityContext(principal="arthur", confirmed=True),
    )
    print(dict(result.output))

    decision = await policy.evaluate(
        PolicyRequest(
            "state.read",
            "state:profile:arthur",
            SecurityContext(
                principal="arthur",
                principal_type=PrincipalType.USER,
                authenticated=True,
                scopes=frozenset({"profile"}),
            ),
        )
    )
    print(decision.effect, decision.rule_id)


if __name__ == "__main__":
    asyncio.run(main())
