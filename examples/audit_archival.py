import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from uuid import UUID

from phoenix_os import (
    AuditArchiveManager,
    AuditCategory,
    AuditEvent,
    AuditRetentionPolicy,
    InMemoryAuditStore,
)


async def main() -> None:
    store = InMemoryAuditStore()
    recorded_at = datetime(2026, 1, 1, tzinfo=UTC)
    for index in range(1, 6):
        await store.append(
            AuditEvent(
                id=UUID(int=index),
                name="security.changed",
                source="phoenix.example",
                category=AuditCategory.SYSTEM,
                action="security.change",
                resource=f"system:item/{index}",
                actor="nova-service",
                details={"index": index, "password": "never-archive-raw"},
                occurred_at=recorded_at + timedelta(seconds=index),
            ),
            recorded_at=recorded_at + timedelta(seconds=index),
        )

    with TemporaryDirectory() as temporary:
        manager = AuditArchiveManager(Path(temporary) / "archives")
        archives = await manager.rotate(store, segment_records=2, include_partial=True)
        verification = await manager.verify_chain()
        plan = manager.plan_retention(
            AuditRetentionPolicy(keep_last=2),
            now=datetime(2026, 2, 1, tzinfo=UTC),
        )

        print("archives:", len(archives), "records:", verification.checked_records)
        print("valid:", verification.valid, "head:", verification.head_digest)
        print("retention candidates:", len(plan.delete_archive_ids))
        print("confirmation digest:", plan.digest)


if __name__ == "__main__":
    asyncio.run(main())
