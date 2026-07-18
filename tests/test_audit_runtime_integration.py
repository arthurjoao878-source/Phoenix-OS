import pytest

from phoenix_os import (
    AllowAllAuthorizer,
    AuditLedger,
    AuditQuery,
    CapabilityRegistry,
    ConfigLoader,
    ConfigSchema,
    EventBus,
    InMemoryAuditStore,
    Kernel,
    MappingConfigSource,
    Router,
    RuntimeAssembler,
    ServiceDefinition,
)


@pytest.mark.asyncio
async def test_runtime_exposes_audit_and_journals_lifecycle_events() -> None:
    configuration = await ConfigLoader(ConfigSchema(()), (MappingConfigSource({}),)).load()
    events = EventBus()
    store = InMemoryAuditStore()
    ledger = AuditLedger(store, events=events)
    runtime = await RuntimeAssembler(
        kernel=Kernel(router=Router(), authorizer=AllowAllAuthorizer(), events=events),
        events=events,
        capabilities=CapabilityRegistry(events=events),
        configuration=configuration,
        audit=ledger,
    ).assemble()

    assert runtime.service("audit") is ledger
    await runtime.start()
    await runtime.stop()

    assert ledger.closed
    records = await store.read(AuditQuery(limit=1000))
    assert records
    assert any(record.event.name.startswith("runtime.") for record in records)
    assert (await store.verify()).valid


@pytest.mark.asyncio
async def test_runtime_can_disable_event_journal_while_owning_ledger() -> None:
    configuration = await ConfigLoader(ConfigSchema(()), (MappingConfigSource({}),)).load()
    events = EventBus()
    store = InMemoryAuditStore()
    ledger = AuditLedger(store, events=events)
    runtime = await RuntimeAssembler(
        kernel=Kernel(router=Router(), authorizer=AllowAllAuthorizer(), events=events),
        events=events,
        capabilities=CapabilityRegistry(events=events),
        configuration=configuration,
        audit=ledger,
        journal_events=False,
    ).assemble()
    await runtime.start()
    await runtime.stop()
    assert await store.read(AuditQuery()) == ()


def test_audit_is_a_reserved_service_name() -> None:
    with pytest.raises(ValueError, match="reserved"):
        ServiceDefinition("audit", lambda resolver, config: object())
