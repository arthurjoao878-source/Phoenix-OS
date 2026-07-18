"""Create, rotate, lease, and revoke a Phoenix secret."""

from __future__ import annotations

import asyncio
from datetime import timedelta

from phoenix_os import (
    KeyRef,
    PolicyEffect,
    PolicyEngine,
    PolicyRule,
    PrincipalType,
    SecretRef,
    SecretsManager,
    SecretValue,
    SecurityContext,
)


async def main() -> None:
    policy = PolicyEngine(
        (
            PolicyRule(
                "allow-demo-secrets",
                PolicyEffect.ALLOW,
                actions=frozenset(
                    {
                        "secret.create",
                        "secret.rotate",
                        "secret.read",
                        "secret.describe",
                        "secret.revoke",
                    }
                ),
                resources=frozenset({"secret:demo/*"}),
                principals=frozenset({"service:demo"}),
                authenticated=True,
            ),
        )
    )
    context = SecurityContext(
        principal="service:demo",
        principal_type=PrincipalType.SERVICE,
        authenticated=True,
        correlation_id="demo-secret-flow",
    )
    manager = SecretsManager(policy=policy)
    ref = SecretRef("database-password", "demo")

    created = await manager.create(
        ref,
        SecretValue("first-value"),
        context,
        protection_key=KeyRef("primary", "external-kms", 1),
    )
    rotated = await manager.rotate(
        ref,
        SecretValue("second-value"),
        context,
        protection_key=KeyRef("primary", "external-kms", 2),
    )
    lease = await manager.lease(ref, context, ttl=timedelta(minutes=1))

    print("created", created.ref)
    print("rotated", rotated.ref, "using", rotated.protection_key)
    print("leased", lease.ref, "until", lease.expires_at.isoformat())
    print("material is redacted:", lease.value)

    await manager.revoke(rotated.ref, context, reason="demo complete")
    await manager.close()
    await policy.close()


if __name__ == "__main__":
    asyncio.run(main())
