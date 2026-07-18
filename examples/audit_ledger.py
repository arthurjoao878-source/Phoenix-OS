"""Append, journal, inspect, and verify redacted Phoenix audit facts."""

import asyncio

from phoenix_os import (
    AuditLedger,
    AuditQuery,
    EventBus,
    InMemoryAuditStore,
    PrincipalType,
    SecurityContext,
    SecurityJournal,
)


async def main() -> None:
    events = EventBus()
    store = InMemoryAuditStore()
    ledger = AuditLedger(store, events=events)
    journal = SecurityJournal(events=events, ledger=ledger)
    await journal.start(object())

    await events.emit(
        "policy.evaluated",
        source="phoenix.policy",
        payload={
            "principal": "nova-service",
            "action": "secret.read",
            "resource": "secret:production/database-password",
            "effect": "deny",
            "password": "redacted-before-persistence",
        },
        correlation_id="request-42",
    )

    auditor = SecurityContext(
        principal="security-auditor",
        principal_type=PrincipalType.USER,
        authenticated=True,
        permissions=frozenset({"audit.read", "audit.verify"}),
    )
    records = await ledger.read(AuditQuery(limit=100), auditor)
    verification = await ledger.verify(auditor)

    print(records[0].sequence, records[0].event.category, records[0].event.outcome)
    print(records[0].event.details)
    print("valid:", verification.valid, "head:", verification.head_digest)

    await journal.stop(object())
    await ledger.close()
    await events.close()


if __name__ == "__main__":
    asyncio.run(main())
