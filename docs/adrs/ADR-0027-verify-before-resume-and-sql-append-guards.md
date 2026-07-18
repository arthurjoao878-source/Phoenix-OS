# ADR-0027 — Verify before resume and enforce SQL append guards

- Status: Accepted
- Date: 2026-07-18

## Context

A durable ledger can outlive the process that created it. Restarting blindly from a corrupted or
inconsistent head could extend an invalid history and make investigation harder. SQLite also permits
direct SQL mutation unless the schema actively rejects it.

## Decision

`SQLiteAuditStore` verifies existing records, optional signatures, and head metadata before accepting
new appends by default. Recovery failure raises `AuditRecoveryError`. The schema also installs
triggers that reject record updates, record deletes, non-contiguous inserts, broken previous-digest
links, and metadata deletion.

Explicit `verify()` remains available for forensic inspection. SQL triggers are treated as defense in
depth rather than a trusted hardware boundary.

## Consequences

Normal restart fails closed instead of extending a detected invalid chain. Ordinary application or
administrative SQL mistakes are rejected near the storage boundary. Startup verification cost grows
with ledger length, and privileged file or database replacement remains possible. Large deployments
may implement externally anchored checkpoints or another `AuditStore` while preserving the public
contracts.
