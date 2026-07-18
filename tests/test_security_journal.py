from datetime import UTC, datetime

import pytest

from phoenix_os import (
    AuditCategory,
    AuditEvent,
    AuditLedger,
    AuditOutcome,
    AuditQuery,
    AuditSeverity,
    Event,
    EventBus,
    InMemoryAuditStore,
    SecurityJournal,
    SecurityJournalStateError,
)


@pytest.mark.asyncio
async def test_journal_maps_policy_event_and_prevents_audit_recursion() -> None:
    events = EventBus()
    store = InMemoryAuditStore()
    ledger = AuditLedger(store, events=events)
    journal = SecurityJournal(events=events, ledger=ledger)
    await journal.start(object())

    report = await events.emit(
        "policy.evaluated",
        source="phoenix.policy",
        payload={
            "principal": "arthur",
            "action": "secret.read",
            "resource": "secret:prod/api",
            "effect": "deny",
        },
        correlation_id="corr-1",
    )

    assert report.succeeded
    records = await store.read(AuditQuery())
    assert len(records) == 1
    record = records[0]
    assert record.event.category is AuditCategory.AUTHORIZATION
    assert record.event.outcome is AuditOutcome.DENIED
    assert record.event.severity is AuditSeverity.WARNING
    assert record.event.actor == "arthur"
    assert record.event.correlation_id == "corr-1"
    snapshot = await journal.snapshot()
    assert snapshot.captured == 1
    assert snapshot.ignored == 1


@pytest.mark.asyncio
async def test_journal_redacts_sensitive_event_payload_before_append() -> None:
    events = EventBus()
    store = InMemoryAuditStore()
    journal = SecurityJournal(events=events, ledger=AuditLedger(store, events=events))
    await journal.start(object())
    await events.emit(
        "identity.authenticated",
        source="Phoenix Identity Provider",
        payload={"principal": "arthur", "password": "do-not-store", "token": "hidden"},
    )
    record = (await store.read(AuditQuery()))[0]
    payload = record.event.details["payload"]
    assert payload["password"] == "***"  # type: ignore[index]
    assert payload["token"] == "***"  # type: ignore[index]
    assert "do-not-store" not in repr(record)
    assert record.event.source == "phoenix.identity.provider"


@pytest.mark.asyncio
async def test_journal_derives_failure_and_revocation_severity() -> None:
    events = EventBus()
    store = InMemoryAuditStore()
    journal = SecurityJournal(events=events, ledger=AuditLedger(store, events=events))
    await journal.start(object())
    await events.emit("plugin.start.failed", source="phoenix.plugins", payload={"plugin": "voice"})
    await events.emit("secrets.revoked", source="phoenix.secrets", payload={"principal": "admin"})
    records = await store.read(AuditQuery())
    assert records[0].event.outcome is AuditOutcome.FAILED
    assert records[0].event.severity is AuditSeverity.ERROR
    assert records[1].event.category is AuditCategory.SECRETS
    assert records[1].event.severity is AuditSeverity.WARNING


@pytest.mark.asyncio
async def test_journal_stop_unsubscribes() -> None:
    events = EventBus()
    store = InMemoryAuditStore()
    journal = SecurityJournal(events=events, ledger=AuditLedger(store, events=events))
    await journal.start(object())
    await journal.stop(object())
    await events.emit("system.changed", source="phoenix.system")
    assert await store.read(AuditQuery()) == ()
    assert not (await journal.snapshot()).started


@pytest.mark.asyncio
async def test_journal_rejects_double_start() -> None:
    journal = SecurityJournal(events=EventBus(), ledger=AuditLedger())
    await journal.start(object())
    with pytest.raises(SecurityJournalStateError):
        await journal.start(object())


@pytest.mark.asyncio
async def test_custom_async_mapper_can_ignore_or_replace_events() -> None:
    events = EventBus()
    store = InMemoryAuditStore()

    async def mapper(event: Event) -> AuditEvent | None:
        if event.name == "ignore.me":
            return None
        return AuditEvent(
            name="system.custom",
            source="phoenix.custom",
            category=AuditCategory.SYSTEM,
            action="system.custom",
            resource="system:custom",
            actor="mapper",
            occurred_at=datetime(2026, 1, 1, tzinfo=UTC),
        )

    journal = SecurityJournal(
        events=events,
        ledger=AuditLedger(store, events=events),
        mapper=mapper,
    )
    await journal.start(object())
    await events.emit("ignore.me", source="test")
    await events.emit("replace.me", source="test")
    records = await store.read(AuditQuery())
    assert [record.event.name for record in records] == ["system.custom"]
    snapshot = await journal.snapshot()
    assert snapshot.ignored >= 1
    assert snapshot.captured == 1


@pytest.mark.asyncio
async def test_mapper_failure_is_visible_in_dispatch_report() -> None:
    events = EventBus()

    def mapper(event: Event) -> AuditEvent | None:
        del event
        raise RuntimeError("mapper failed")

    journal = SecurityJournal(events=events, ledger=AuditLedger(), mapper=mapper)
    await journal.start(object())
    report = await events.publish(Event("system.changed", "test"))
    assert len(report.failures) == 1
    assert (await journal.snapshot()).failures == 1
