# RFC-0013 — Durable Audit Storage and Recovery

- Status: Accepted
- Target: Phoenix OS 0.13.0
- Authors: Phoenix contributors
- Updated: 2026-07-18

## Summary

RFC-0012 established provider-neutral audit contracts and a deterministic process-local reference
store. RFC-0013 adds a durable local reference adapter, `SQLiteAuditStore`, for deployments that need
records to survive process restarts without introducing a third-party database dependency.

The adapter uses Python's standard-library SQLite driver, WAL journaling, `synchronous=FULL`, atomic
append transactions, a versioned schema, persisted chain-head metadata, SQL append-only guards, and
complete-chain recovery verification before accepting new records. It preserves the existing
`AuditStore` contract, canonical SHA-256 chain, optional external signatures, policy-protected
inspection, and Security Journal behavior.

This RFC provides crash-consistent local persistence. It does not claim write-once storage,
independent anti-rollback protection, remote availability, encryption at rest, backup, replication,
or regulatory compliance.

## Goals

- provide a standard-library durable `AuditStore` implementation;
- preserve records, sequence allocation, digests, redacted details, correlation, causation, and seals
  across process restarts;
- allocate the next sequence and previous digest within one SQLite write transaction;
- use WAL mode and full synchronous durability for the reference adapter;
- reject ordinary SQL update and delete operations against audit records;
- reject direct inserts with sequence gaps or a previous digest that does not match the current head;
- persist schema version and chain-head metadata transactionally with each append;
- verify an existing chain before a reopened store accepts additional appends by default;
- refuse recovery when persisted content, signatures, sequence, links, or head metadata are invalid;
- preserve bounded deterministic `AuditQuery` filters in ascending sequence order;
- preserve forensic read, verification, and snapshot access after store shutdown;
- integrate durable-store startup verification through `AuditLedger` lifecycle ownership;
- remain compatible with optional external `AuditSigner` and `KeyRef` providers;
- add executable recovery examples, tests, ADRs, release notes, and migration guidance.

## Non-goals

The reference adapter does not:

- provide a WORM device, transparency log, immutable object store, or hardware security boundary;
- prevent a privileged filesystem or database administrator from replacing the complete database;
- independently detect rollback to an older internally valid database snapshot;
- encrypt database pages, WAL files, temporary files, backups, or process memory;
- provide remote transport, replication, quorum, failover, sharding, or multi-region availability;
- define backup schedules, point-in-time restore, retention, legal hold, deletion, or privacy policy;
- migrate arbitrary future schema versions automatically;
- replace an external signature provider, HSM, KMS, timestamp authority, or independent checkpoint;
- promise that an operating-system or hardware crash has honored every storage flush request;
- make SQLite suitable for every write rate, topology, or regulatory workload.

Deployments requiring those properties should implement the existing `AuditStore` and `AuditSigner`
boundaries with reviewed infrastructure.

## Public API

### SQLiteAuditStore

`SQLiteAuditStore(path, ...)` implements `AuditStore` and accepts:

- a filesystem path identifying one durable SQLite database;
- an optional paired `AuditSigner` and `KeyRef` for new record seals and historical verification;
- an external signature algorithm label;
- `verify_on_open`, enabled by default;
- a bounded SQLite busy timeout;
- optional parent-directory creation.

The adapter rejects `:memory:` because the class specifically represents durable storage. The path is
exposed as a normalized `Path` for diagnostics without exposing record content.

### Errors

RFC-0013 adds:

- `AuditPersistenceError` for durable storage operation failures;
- `AuditSchemaError` for missing or incompatible schema metadata;
- `AuditStoreCorruptionError` when persisted records cannot be decoded safely for inspection;
- `AuditRecoveryError` when an existing ledger cannot safely resume appending.

Signature provider failures continue to use `AuditSignerError`. Appends after close continue to use
`AuditStoreClosedError`.

## SQLite schema

Schema version 1 stores one metadata row and one append-only record table.

The record table persists every `AuditRecord` and `AuditEvent` field required to reproduce the
canonical digest input:

- positive sequence and event UUID;
- normalized name, source, category, action, resource, actor, outcome, and severity;
- deterministic redacted details JSON;
- event, recording, correlation, and causation data;
- previous digest and digest;
- optional seal key provider/name/version, algorithm, and signature bytes.

The metadata row stores the schema version and transactionally updated head sequence and digest.
Metadata is not an independent external anchor, but it detects accidental tail or head inconsistency
when records and metadata no longer agree.

## Transaction model

Append executes under `BEGIN IMMEDIATE`:

1. read and validate persisted chain-head metadata;
2. perform recovery verification when required;
3. read the current record head;
4. allocate the next positive sequence;
5. calculate the canonical digest from the event, sequence, recording time, and previous digest;
6. request an optional external signature;
7. insert the complete record;
8. update metadata to the new sequence and digest;
9. commit both changes atomically.

A duplicate event UUID, SQL guard failure, lock timeout, or database error rolls back the transaction.
No partially inserted record or advanced metadata row is committed through the adapter.

SQLite serializes competing writers. Separate `SQLiteAuditStore` instances that target the same file
observe one contiguous sequence as long as all writers honor the same database and schema.

## Append-only SQL guards

The schema creates triggers that reject:

- updates to `audit_records`;
- deletes from `audit_records`;
- inserts whose sequence is not exactly the current maximum plus one;
- inserts whose `previous_digest` is not the current head digest or the fixed genesis digest;
- deletion of the singleton metadata row.

These guards protect ordinary application and administrative SQL mistakes. A privileged attacker who
can drop triggers, rewrite files, or replace the whole database remains outside this guarantee.
Complete-chain verification detects many such changes, but not replacement with an older or fully
rehashable unsigned history without an independent external anchor.

## Recovery verification

With `verify_on_open=True`, lifecycle startup verifies the complete persisted chain before the runtime
becomes operational. Append also re-verifies when the observed persisted head differs from the last
verified head for that store instance.

Recovery checks:

- decodability and contract validity of every record;
- contiguous positive sequences;
- previous-digest links;
- canonical record digests;
- optional external signatures when present;
- metadata head sequence and digest agreement.

A failed recovery raises `AuditRecoveryError` and refuses the append. Explicit `verify()` still
returns the detailed `AuditVerification` result for investigation. `verify_on_open=False` may be used
only when a deployment deliberately provides an equivalent external recovery control; it does not
disable explicit verification.

## Durability and shutdown

The reference adapter configures WAL mode and `synchronous=FULL`. SQLite commits provide local
transactional crash consistency subject to operating-system, filesystem, storage-controller, and
hardware behavior.

`close()` releases the writer connection and prevents new appends. Historical reads, verification,
and snapshots remain available through transient connections for forensic diagnostics, matching the
read-after-close behavior of the in-memory reference store.

## Query behavior

`AuditQuery` filters are translated to parameterized SQL for sequence bounds and exact category,
outcome, source, actor, and action membership. Results are always ordered by ascending sequence and
bounded by the existing limit of 1 to 1000 records.

Arbitrary SQL, predicates, expressions, joins, mutation, and executable query callbacks are not
exposed through the public API.

## Runtime integration

`AuditLedger.start()` now detects an optional store lifecycle `start` hook. Consequently,
`RuntimeAssembler(audit=AuditLedger(SQLiteAuditStore(...)))` initializes the durable schema and
performs recovery verification before later Policy, State, Identity, Secrets, custom, and Plugin
components start.

Shutdown remains reversed: Security Journal stops before Audit Ledger, and Audit Ledger closes the
SQLite writer before Event Bus shutdown.

## Security considerations

Redaction still occurs before JSON persistence and hashing. SQLite files nevertheless contain actor,
resource, action, timing, correlation, outcome, and other operational metadata that can be sensitive.
Filesystem permissions, volume encryption, backup handling, access review, retention, and incident
response remain deployment responsibilities.

The local database and its WAL must be protected together. Copying only the main database file while
writers are active is not a supported backup procedure. Use a reviewed SQLite backup or checkpoint
workflow outside the Phoenix core.

## Compatibility

RFC-0013 is additive. `InMemoryAuditStore`, `AuditStore`, `AuditLedger`, `SecurityJournal`, canonical
hashes, permissions, and existing RFC-0012 records retain their behavior. No third-party runtime
dependency is added because SQLite is provided by Python's standard library.

RFC-0013 supersedes only RFC-0012's statement that the core provides no database implementation. The
provider-neutral `AuditStore` boundary and the recommendation to use reviewed external adapters for
stronger production requirements remain unchanged.

## Acceptance criteria

- records survive close and reopen with identical sequence, event, digest, details, and seal values;
- reopened append resumes at the next sequence and links to the persisted head;
- duplicate event IDs roll back without advancing the chain;
- queries preserve filters, limits, and ascending sequence;
- ordinary SQL update and delete attempts are rejected;
- content corruption and metadata mismatch are detected;
- default recovery refuses append to an invalid chain;
- signed records remain verifiable after reopen when the signer is available;
- missing signature verification capability produces an invalid verification result;
- close blocks append while preserving forensic reads, verification, and snapshots;
- unsupported schema versions fail explicitly;
- separate store instances preserve one contiguous chain;
- Runtime lifecycle starts recovery and persists journaled lifecycle events;
- Ruff, Ruff Format, mypy strict, pytest, examples, compilation, wheel build, and isolated installation
  pass.
