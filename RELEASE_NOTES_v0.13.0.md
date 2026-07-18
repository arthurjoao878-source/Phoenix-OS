# Phoenix OS v0.13.0 — Durable Audit Storage and Recovery

Phoenix OS v0.13.0 implements RFC-0013 and adds a crash-consistent local SQLite reference backend to
the RFC-0012 Audit Ledger.

## Highlights

- New `SQLiteAuditStore` built on Python's standard-library SQLite driver.
- WAL journaling and `synchronous=FULL` for local transactional durability.
- Atomic record insertion and chain-head metadata update under `BEGIN IMMEDIATE`.
- Durable recovery of redacted events, sequence, correlation, causation, digests, and optional seals.
- Complete-chain verification before reopened stores accept appends by default.
- Refusal to extend corrupt chains through `AuditRecoveryError`.
- Versioned schema validation through `AuditSchemaError`.
- Append-only SQL triggers blocking update, delete, sequence gaps, and broken links.
- Parameterized persistent `AuditQuery` filters ordered by ascending sequence.
- Forensic read, verification, and snapshots after writer shutdown.
- Durable Runtime lifecycle integration and executable `durable_audit_ledger.py` example.
- RFC-0013 plus ADR-0026 and ADR-0027 documentation.

## Security and durability model

The adapter is locally durable and crash-consistent within SQLite, operating-system, filesystem, and
hardware guarantees. It is not WORM storage and does not prevent a privileged administrator from
replacing the complete database or rolling back to an older internally valid copy.

Redaction still occurs before persistence. Database files nevertheless contain security metadata and
must be protected with appropriate filesystem access, volume encryption, backup handling, retention,
and privacy controls. Stronger origin authentication continues to require an external `AuditSigner`
and protected `KeyRef`.

## Compatibility

Version 0.13.0 is additive. Existing RFC-0001 through RFC-0012 contracts remain compatible.
`InMemoryAuditStore` remains the deterministic ephemeral backend, while `SQLiteAuditStore` is the
new durable local reference adapter. Plugin compatibility metadata now reports Phoenix `0.13.0`.
