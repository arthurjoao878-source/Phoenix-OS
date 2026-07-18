# ADR-0024 — Canonical hash-chained audit records

- Status: Accepted
- Date: 2026-07-18

## Context

Audit facts must be ordered and independently verifiable without coupling Phoenix OS to a database,
serialization library, signature algorithm, or vendor. Plain mutable log messages cannot detect
reordering, gaps, or changed historical fields.

## Decision

Phoenix stores immutable `AuditRecord` values in a positive sequence. Every record digest is SHA-256
over deterministic UTF-8 JSON containing the complete redacted event, sequence, recording time, and
previous digest. The first record references a fixed all-zero genesis digest. Optional signatures
are delegated to `AuditSigner` using provider-neutral `KeyRef` metadata.

## Consequences

Complete-chain verification detects field changes, reordered records, gaps, and broken links. Hash
chaining alone does not prove authorship or prevent a privileged attacker from replacing and
rehashing an entire unsigned ledger. Stronger guarantees require protected external storage and an
external signer.
