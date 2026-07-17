# RFC-0007 — State Store and Persistence

- **Status:** Accepted
- **Version:** 0.7.0
- **Date:** 2026-07-17

## Summary

Phoenix OS needs a stable persistence boundary for session state, caches, checkpoints, adapter
metadata, and future memory implementations without coupling the core to SQLite, PostgreSQL, Redis,
cloud databases, pickle, filesystem layouts, or vendor SDKs. This RFC defines typed keys, immutable
records, safe serialization, optimistic concurrency, TTL, serializable transactions, logical
snapshots, named stores, lifecycle ownership, events, and structured diagnostics.

The reference `MemoryStateStore` is deterministic and process-local. Durable databases remain
external adapters implementing the same `StateStore` protocol.

## Goals

- Define an asynchronous persistence contract independent of storage technology.
- Qualify every value with a normalized namespace and key name.
- Allow callers to associate a concrete expected type with a key.
- isolate stored values through deterministic, non-executable JSON serialization.
- Detect concurrent updates through explicit record versions.
- Support atomic commit and rollback through serializable transactions.
- Expire records using optional TTL values and timezone-aware timestamps.
- Create and restore logical snapshots without rewinding live concurrency versions.
- Resolve multiple named stores through a deterministic registry.
- Emit state lifecycle facts and structured diagnostics with correlation metadata.
- Integrate state lifecycle ownership with `RuntimeAssembler`.

## Non-goals

- Implementing SQLite, PostgreSQL, Redis, document databases, object stores, or replication.
- Defining database migrations, indexes, query languages, joins, secondary indexes, or SQL.
- Persisting arbitrary Python objects, functions, classes, exceptions, or executable bytecode.
- Providing encryption, credential management, multi-process locking, distributed consensus, or
  cross-host transactions.
- Replacing the Event Bus with a durable queue or event-sourcing system.
- Implementing semantic memory, embeddings, vector search, AI recall, or prompt history.
- Guaranteeing durability from the reference in-memory backend.

## Key and record contracts

`StateKey[T]` combines a normalized namespace, name, and optional expected concrete type. Namespace
and name use lowercase identifiers containing letters, numbers, underscores, dots, and hyphens. The
canonical identity is `namespace:name`. Type information is not part of identity, so the same stored
value can be read through an untyped key or validated through a typed key.

`StateRecord[T]` contains the key, decoded value, positive version, creation and update timestamps,
and optional expiration timestamp. Contracts are frozen dataclasses. Stored values are decoded from
serialized bytes on every read, so mutation of a returned JSON object cannot mutate the stored copy.

Version `0` is reserved as `ABSENT_VERSION`. Passing it as `expected_version` requires that no live
record exists. Positive expected versions require an exact match. Omitting `expected_version`
performs an unconditional write or delete.

## Safe serialization

The default `JsonStateCodec` accepts JSON-compatible scalars, mappings with string keys, and ordered
sequences. Documents are encoded as deterministic UTF-8 JSON with sorted keys, compact separators,
and non-finite numbers disabled. Decoding never imports modules or executes constructors.

Unsupported objects, byte strings, non-string mapping keys, non-finite numbers, and Phoenix
`SecretValue` wrappers are rejected. A caller must explicitly reveal a secret before persistence,
which makes the security boundary visible in application code. External adapters may supply another
`StateCodec`, but unsafe object deserialization is outside the Phoenix core.

## Memory store

`MemoryStateStore` serializes access with an asynchronous lock. It provides:

- `get`, `put`, `delete`, and deterministic `list` operations;
- optional expected-version checks;
- optional positive TTL values;
- lazy expiration during reads and writes plus explicit `purge_expired`;
- logical snapshots and replace-or-merge restoration;
- point-in-time statistics;
- idempotent close and Runtime lifecycle hooks.

Store revisions increase for writes, deletes, expiration, and restored records. A restored snapshot
recreates logical values but assigns fresh live versions. This prevents version rewind and ABA-style
confusion when restoring an older snapshot into a store that has continued to mutate.

Closing the memory store clears its process-local contents and rejects future operations. A durable
adapter may define close semantics appropriate to its connection pool while preserving the public
contract.

## Transactions

`MemoryStateStore.transaction()` returns a one-shot asynchronous context manager. Entering acquires
exclusive ownership of the store and creates an isolated working set. Operations inside the
transaction see their own writes. Successful context exit commits the working set atomically;
exceptional exit rolls it back. Explicit `commit()` and `rollback()` are also supported.

The reference implementation holds the store lock for the transaction lifetime, giving serializable
behavior without hidden retries. Competing operations wait until commit or rollback. Transaction
objects cannot be re-entered or reused after completion. Cancellation follows normal Python
exception semantics and therefore rolls back through the asynchronous context manager.

## TTL and expiration

TTL is expressed as a positive `timedelta`. Expiration timestamps are timezone-aware. Expired values
are treated as absent for reads, expected-version checks, listing, snapshots, and transactions.
Expiration is performed lazily when a key or collection is touched, or eagerly through
`purge_expired()`.

TTL is not a real-time scheduler. The core creates no background task. External stores may use native
expiration facilities provided that observable reads preserve the same absence semantics.

## Snapshots and restoration

`StateSnapshot` is a portable logical set of non-expired records plus the source revision and
creation time. `RestoreMode.REPLACE` clears current logical contents before restoration;
`RestoreMode.MERGE` overwrites matching keys and preserves unrelated records.

Snapshot values pass through the configured codec during restore. Unsupported or unsafe values fail
before the store is mutated. Expired snapshot records are skipped. Restored records receive new
versions and retain their original creation time where possible.

Snapshots are not database backups, encrypted archives, or replication logs. Adapters are
responsible for durable backup formats and integrity mechanisms.

## Named store registry

`StateStoreRegistry` resolves stores by normalized name and can expose one default store. Registration
order is deterministic. The registry starts stores in registration order and stops them in reverse
order. Mutation of registrations is allowed only before startup.

A registry may separate domains such as `primary`, `cache`, and `session` while keeping consumers on
the common `StateStore` contract. The registry does not route keys automatically or copy values
between stores.

## Events and observability

When configured, the memory store emits Event Bus facts including reads, writes, deletes, conflicts,
expiration, snapshot creation and restoration, transaction completion, and closure. A
`StateOperationContext` propagates correlation ID, causation ID, and string metadata.

When an `ObservabilityHub` is configured, public operations create spans and emit structured logs and
counter metrics. Diagnostic channels are optional. Already-closed Event Bus or Observability
instances do not invalidate a completed state mutation. Cancellation is never translated.

Values are never included automatically in events or diagnostics. Signals contain keys, versions,
counts, modes, and expiration timestamps only.

## Runtime integration

`RuntimeAssembler` accepts an optional state store or `StateStoreRegistry`. It exposes the object as
the named `state` service and registers it as a lifecycle component after observability components.
Shutdown is reversed, so state closes before the Event Observer and Observability Hub. Existing
construction without state remains unchanged.

The name `state` is reserved in `ServiceDefinition` composition when supplied through the assembler.
External durable stores should be created in the composition root or by an explicit factory and
passed behind the protocol.

## Security and failure model

The State Store is a persistence boundary, not an authorization boundary. Callers remain responsible
for permission checks, tenant isolation, classification, retention, encryption, and data minimization.
Capabilities should authorize sensitive state access before invoking a store.

Optimistic conflicts are explicit `StateConflictError` failures. Serialization and type failures are
also explicit and do not partially mutate state. Transactions guarantee atomicity only inside one
store instance. Cross-store and distributed transactions are outside this RFC.

## Compatibility

RFC-0007 adds the `phoenix_os.state` package, optional Runtime assembly support, and new public
exports. Existing Kernel, Event Bus, Capability Registry, Runtime, Configuration, and Observability
APIs remain valid.

## Acceptance criteria

- Keys, records, snapshots, operation contexts, registrations, and statistics are immutable.
- The default codec performs deterministic, non-executable serialization.
- Returned mutable JSON values cannot mutate stored bytes.
- Expected versions detect absent, stale, and conflicting writes and deletes.
- TTL values expire consistently without a hidden scheduler.
- Transactions commit atomically, roll back on failure, and serialize competing operations.
- Snapshots restore in replace and merge modes with fresh live versions.
- Named stores start and stop deterministically.
- Events and structured diagnostics propagate safe correlation metadata without values.
- Runtime composition exposes and owns optional state.
- Ruff, Ruff Format, mypy strict, pytest, examples, build, and isolated installation pass.
