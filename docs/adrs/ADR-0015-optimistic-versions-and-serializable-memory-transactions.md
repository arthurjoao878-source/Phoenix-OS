# ADR-0015 — Optimistic versions and serializable memory transactions

- **Status:** Accepted
- **Date:** 2026-07-17

Every live state mutation receives a monotonically increasing store revision. Version zero means
"must be absent" and positive expected versions require an exact match. Snapshot restoration assigns
fresh versions instead of rewinding historical ones. The reference in-memory backend implements
transactions by holding its asynchronous lock for the transaction lifetime and committing an
isolated working set atomically. This provides deterministic serializable behavior and rollback
without hidden retries. Distributed transactions, database isolation levels, and adapter-native
retry policies remain outside the core.
