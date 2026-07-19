# Phoenix OS v0.19.0 — Durable Command Journal and Recovery

Phoenix OS 0.19.0 implements RFC-0019 and makes Dashboard command identity, idempotency, receipts,
recovery, history, and retention durable without persisting command payloads.

## Highlights

- schema-versioned payload-free command journal contracts;
- bounded in-memory and State Store-backed repositories;
- canonical JSON checksums and strict corruption detection;
- restart-safe SHA-256 idempotency indexes and terminal receipts;
- reconciliation of interrupted job and workflow commands before any replay;
- Runtime-owned bounded recovery and terminal-retention workers;
- authenticated paginated command-history API;
- Dashboard history table and command-journal health counters;
- RuntimeAssembler automatic durable repository selection;
- accepted RFC-0019 and ADR-0038/0039.

## Safety model

The journal stores no request bodies, arguments, outputs, contexts, tokens, CSRF values, confirmation
proofs, plaintext idempotency keys, secrets, or exception messages. Recovery probes deterministic
external state and defers uncertain commands. Retention deletes only terminal records using
revision-bound candidates and atomic record/index removal.

## Validation

- Ruff lint and formatting passed;
- mypy strict passed;
- complete regression suite passed;
- wheel and source distribution passed Twine validation;
- dashboard assets and durable command modules are packaged in the wheel;
- package and plugin compatibility versions report 0.19.0.
