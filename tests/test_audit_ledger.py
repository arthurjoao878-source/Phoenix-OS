from datetime import UTC, datetime

import pytest

from phoenix_os import (
    AuditAccessDeniedError,
    AuditCategory,
    AuditEvent,
    AuditLedger,
    AuditLedgerClosedError,
    AuditOutcome,
    AuditQuery,
    EventBus,
    InMemoryAuditStore,
    InMemorySink,
    ObservabilityHub,
    PolicyEffect,
    PolicyEngine,
    PolicyRule,
    PrincipalType,
    SecretValue,
    SecurityContext,
)


def context(*permissions: str, principal: str = "arthur") -> SecurityContext:
    return SecurityContext(
        principal=principal,
        principal_type=PrincipalType.USER,
        authenticated=True,
        permissions=frozenset(permissions),
        correlation_id="corr-audit",
    )


def fact(*, details: dict[str, object] | None = None) -> AuditEvent:
    return AuditEvent(
        name="identity.authenticated",
        source="phoenix.identity",
        category=AuditCategory.AUTHENTICATION,
        action="identity.authenticate",
        resource="identity:arthur",
        actor="arthur",
        details={} if details is None else details,
        occurred_at=datetime(2026, 1, 1, tzinfo=UTC),
        correlation_id="corr-audit",
    )


@pytest.mark.asyncio
async def test_record_read_verify_and_snapshot() -> None:
    current = [datetime(2026, 1, 1, tzinfo=UTC)]
    ledger = AuditLedger(clock=lambda: current[0])
    record = await ledger.record(fact())
    reader = context("audit.read", "audit.verify")

    records = await ledger.read(AuditQuery(), reader)
    verification = await ledger.verify(reader)
    snapshot = await ledger.snapshot()

    assert records == (record,)
    assert verification.valid
    assert snapshot.records == 1
    assert snapshot.appended == 1
    assert snapshot.reads == 1
    assert snapshot.verifications == 1


@pytest.mark.asyncio
async def test_record_security_derives_identity_context() -> None:
    store = InMemoryAuditStore()
    ledger = AuditLedger(store)
    security_context = context("audit.read")
    await ledger.record_security(
        "secrets.revoked",
        category=AuditCategory.SECRETS,
        action="secret.revoke",
        resource="secret:production/api",
        outcome=AuditOutcome.SUCCEEDED,
        details={"reason": "compromised"},
        context=security_context,
    )
    record = (await ledger.read(AuditQuery(), security_context))[0]
    assert record.event.actor == "arthur"
    assert record.event.correlation_id == "corr-audit"


@pytest.mark.asyncio
async def test_read_and_verify_require_authenticated_permissions() -> None:
    ledger = AuditLedger()
    await ledger.record(fact())
    with pytest.raises(AuditAccessDeniedError):
        await ledger.read(AuditQuery(), SecurityContext())
    with pytest.raises(AuditAccessDeniedError):
        await ledger.verify(context())
    snapshot = await ledger.snapshot()
    assert snapshot.denied_operations == 2


@pytest.mark.asyncio
async def test_policy_engine_can_authorize_inspection_without_local_permissions() -> None:
    policy = PolicyEngine(
        (
            PolicyRule(
                "allow-audit",
                PolicyEffect.ALLOW,
                actions=frozenset({"audit.read", "audit.verify"}),
                resources=frozenset({"audit:ledger"}),
                authenticated=True,
            ),
        )
    )
    ledger = AuditLedger(policy=policy)
    await ledger.record(fact())
    user = context()
    assert len(await ledger.read(AuditQuery(), user)) == 1
    assert (await ledger.verify(user)).valid


@pytest.mark.asyncio
async def test_policy_denial_is_translated_to_audit_error() -> None:
    policy = PolicyEngine((PolicyRule("deny-audit", PolicyEffect.DENY, reason="blocked"),))
    ledger = AuditLedger(policy=policy)
    with pytest.raises(AuditAccessDeniedError, match="blocked"):
        await ledger.read(AuditQuery(), context())


@pytest.mark.asyncio
async def test_signals_and_observability_do_not_export_arbitrary_details() -> None:
    events = EventBus()
    captured: list[object] = []
    await events.subscribe("*", lambda event: captured.append(event))
    sink = InMemorySink()
    hub = ObservabilityHub((sink,))
    ledger = AuditLedger(events=events, observability=hub)

    await ledger.record(fact(details={"password": "never-log", "value": SecretValue("hidden")}))

    observations = (await sink.snapshot()).records
    assert "never-log" not in repr(captured)
    assert "never-log" not in repr(observations)
    assert "hidden" not in repr(captured)
    assert "hidden" not in repr(observations)
    assert captured[0].name == "audit.recorded"  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_verify_emits_valid_result_signal() -> None:
    events = EventBus()
    captured: list[object] = []
    await events.subscribe("*", lambda event: captured.append(event))
    ledger = AuditLedger(events=events)
    await ledger.record(fact())
    await ledger.verify(context("audit.verify"))
    assert {event.name for event in captured} == {  # type: ignore[attr-defined]
        "audit.recorded",
        "audit.verified",
    }


@pytest.mark.asyncio
async def test_close_is_idempotent_and_rejects_operations() -> None:
    ledger = AuditLedger()
    await ledger.close()
    await ledger.close()
    assert (await ledger.snapshot()).closed
    with pytest.raises(AuditLedgerClosedError):
        await ledger.record(fact())
    with pytest.raises(AuditLedgerClosedError):
        await ledger.read(AuditQuery(), context("audit.read"))
