# Phoenix OS v0.12.0 — Audit Ledger and Security Journal

Phoenix OS v0.12.0 implements RFC-0012 and adds a provider-neutral, append-only security audit
boundary to the existing Runtime, Policy, Identity, Secrets, Event Bus, and Observability stack.

## Highlights

- Immutable, redacted `AuditEvent` and hash-linked `AuditRecord` contracts.
- Deterministic canonical UTF-8 JSON and SHA-256 previous-digest chaining.
- Fixed genesis digest, contiguous positive sequences, and complete-chain verification.
- Optional external record signatures through `AuditSigner` and provider-neutral `KeyRef` metadata.
- Asynchronous `AuditStore` protocol and deterministic `InMemoryAuditStore` reference backend.
- Authenticated, deny-by-default `audit.read` and `audit.verify` authorization.
- `SecurityJournal` Event Bus bridge with stable categorization, outcome/severity derivation,
  correlation preservation, recursive redaction, and recursion prevention.
- Safe Event Bus and Observability signals that never export arbitrary audit details.
- `RuntimeAssembler(audit=...)` ownership and optional automatic journal lifecycle.

## Integrity model

Every record digest covers its complete redacted event, sequence, recording timestamp, and previous
record digest. Verification detects changed fields, sequence gaps, reordering, and broken links when
the complete chain is available. The optional signer boundary can authenticate record digests without
placing raw signing keys or a concrete algorithm in the Phoenix core.

An unsigned hash chain is tamper-evident rather than tamper-proof. `InMemoryAuditStore` is non-durable
and provides no write-once protection, replication, backup, independent clock, or regulatory
retention guarantee. Production deployments should provide reviewed external stores and signers.

## Compatibility

Version 0.12.0 is additive. Existing RFC-0001 through RFC-0011 contracts remain compatible. Plugin
compatibility metadata now reports Phoenix `0.12.0`.
