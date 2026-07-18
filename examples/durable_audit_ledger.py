"""Persist, reopen, inspect, and verify a Phoenix SQLite audit ledger."""

import asyncio
from tempfile import TemporaryDirectory

from phoenix_os import (
    AuditCategory,
    AuditLedger,
    AuditOutcome,
    AuditQuery,
    PrincipalType,
    SecurityContext,
    SQLiteAuditStore,
)


async def main() -> None:
    auditor = SecurityContext(
        principal="security-auditor",
        principal_type=PrincipalType.USER,
        authenticated=True,
        permissions=frozenset({"audit.read", "audit.verify"}),
    )

    with TemporaryDirectory(prefix="phoenix-audit-") as directory:
        database = f"{directory}/ledger.sqlite3"
        ledger = AuditLedger(SQLiteAuditStore(database))
        await ledger.start(object())
        first = await ledger.record_security(
            "secrets.access.denied",
            category=AuditCategory.SECRETS,
            action="secret.read",
            resource="secret:production/database-password",
            actor="nova-service",
            outcome=AuditOutcome.DENIED,
            details={"password": "never persisted", "reason": "policy denied"},
        )
        await ledger.close()

        reopened = AuditLedger(SQLiteAuditStore(database))
        await reopened.start(object())
        records = await reopened.read(AuditQuery(limit=100), auditor)
        verification = await reopened.verify(auditor)

        print("recovered:", len(records), "sequence:", records[0].sequence)
        print("redacted:", records[0].event.details["password"])
        print("same head:", verification.head_digest == first.digest)
        print("valid:", verification.valid)
        await reopened.close()


if __name__ == "__main__":
    asyncio.run(main())
