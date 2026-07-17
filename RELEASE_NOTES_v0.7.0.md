# Phoenix OS v0.7.0 — State Store and Persistence

Phoenix OS v0.7.0 implements RFC-0007 and introduces a safe asynchronous persistence boundary
without coupling the core to a database vendor.

## Highlights

- Typed, normalized, namespace-qualified `StateKey` contracts.
- Fresh decoded values and immutable versioned `StateRecord` metadata.
- Deterministic UTF-8 JSON serialization without arbitrary code execution.
- Explicit rejection of unsupported objects, non-finite numbers, and wrapped secrets.
- Optimistic concurrency using absent and exact expected versions.
- Optional TTL with lazy and explicit expiration.
- Serializable in-memory transactions with atomic commit and rollback.
- Logical snapshots with replace and merge restoration.
- Named `StateStoreRegistry` with deterministic lifecycle ownership.
- Correlated Event Bus facts, structured logs, metrics, and spans.
- Optional State service composition through `RuntimeAssembler`.

## Python 3.12 compatibility

- Parameterized construction such as `StateKey[object](...)` and `StateRecord[object](...)` is supported on Python 3.12.
- A regression test protects the frozen-slots generic compatibility path.

## Compatibility

The release adds an optional package and assembler argument. Existing Kernel, Event Bus, Capability
Registry, Runtime, Configuration, and Observability APIs remain valid. Durable persistence adapters
can implement the `StateStore` protocol outside the core.

## Security

The default codec never reconstructs Python objects or executes persisted code. Phoenix
`SecretValue` wrappers must be revealed explicitly before persistence. State signals include keys,
versions, counts, and timestamps, but never values automatically. Authorization, encryption, tenant
isolation, retention, backups, and database credentials remain host responsibilities.
