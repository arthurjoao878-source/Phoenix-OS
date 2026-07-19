# ADR-0038 — State Store-backed command journal

- Status: Accepted
- Date: 2026-07-19

## Context

Administrative commands need restart-safe idempotency and receipts, but persisting request bodies,
arguments, outputs, tokens, proofs, or exception text would expand the sensitive-data boundary.

## Decision

Phoenix OS persists one allowlisted command journal record and one idempotency index through the
provider-neutral State Store. Records contain command identity, action, target, principal, protected
digests, lifecycle timestamps, revision, terminal status, and stable result code only. Canonical JSON
and SHA-256 checksums detect corruption. State transactions create and delete record/index pairs
atomically, while optimistic revisions fence concurrent transitions.

`RuntimeAssembler` uses the default State Store when available and otherwise selects the bounded
in-memory reference repository. The journal borrows the State Store lifecycle and never closes the
underlying provider.

## Consequences

Completed receipts and idempotency survive process restart without retaining executable payloads.
Storage providers must support the existing State Store transaction guarantees. Unknown schemas,
missing links, checksum mismatches, and inconsistent indexes fail closed.
