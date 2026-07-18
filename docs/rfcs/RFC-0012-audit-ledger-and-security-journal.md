# RFC-0012 — Audit Ledger and Security Journal

- Status: Accepted
- Target: Phoenix OS 0.12.0
- Authors: Phoenix contributors
- Updated: 2026-07-18
- Superseded in part: durable local storage non-goal by RFC-0013

## Summary

Phoenix OS requires a durable boundary for security-relevant facts, deterministic investigation,
and explicit integrity verification. This RFC introduces an append-only Audit Ledger, immutable
security facts, deterministic canonical serialization, SHA-256 hash chaining, optional external
signatures, policy-protected inspection, and a Security Journal bridge that converts Event Bus facts
into redacted audit records.

The core provides a deterministic in-memory implementation for tests and ephemeral processes. It
does not claim durable retention, tamper-proof storage, non-repudiation, regulatory compliance, or a
specific cryptographic signature algorithm.

## Goals

- define immutable `AuditEvent`, `AuditRecord`, query, verification, seal, and snapshot contracts;
- append records in a single deterministic positive sequence;
- hash canonical record content together with the previous record digest;
- verify sequence, previous-digest links, canonical digests, and optional external signatures;
- redact sensitive keys and `SecretValue` instances before persistence;
- keep records safe for representations, events, logs, metrics, and diagnostics;
- expose an asynchronous provider-neutral `AuditStore` boundary;
- provide an `InMemoryAuditStore` for tests, development, and ephemeral processes;
- define an external `AuditSigner` boundary addressed by provider-neutral `KeyRef` values;
- protect ledger reads and integrity verification with authenticated `SecurityContext` and Policy
  Engine decisions or explicit fallback permissions;
- bridge Event Bus facts into categorized security records through `SecurityJournal`;
- prevent audit events from recursively generating more audit events;
- integrate Audit Ledger and Security Journal lifecycle through `RuntimeAssembler`.

## Non-goals

The core does not:

- provide a database, write-once medium, remote collector, replication, backup, or retention engine;
- make an in-memory process resistant to an attacker with arbitrary process-memory access;
- implement RSA, ECDSA, EdDSA, HMAC, PKI, timestamp authorities, or key custody;
- claim that a SHA-256 hash chain alone proves authorship or prevents record replacement;
- define jurisdiction-specific compliance, evidence, legal-hold, or deletion policy;
- guarantee Event Bus delivery across process crashes or network partitions;
- accept arbitrary executable query predicates or dynamic policy code;
- sandbox hostile in-process plugins.

Those concerns belong to external `AuditStore`, `AuditSigner`, plugin, deployment, and governance
adapters.

## Contracts

### AuditEvent

An `AuditEvent` is an immutable, redacted security fact before ledger sequencing. It includes a
normalized name, source, category, action, resource, actor, outcome, severity, timestamp,
correlation, causation, and deterministic structured details. Sensitive-key values and
`SecretValue` instances are replaced before a store sees the event.

### AuditRecord

An `AuditRecord` binds one event to a positive sequence, ledger recording time, previous digest,
record digest, and optional external seal. The first record uses the fixed all-zero genesis digest.
Records are immutable after creation.

### AuditQuery

`AuditQuery` defines bounded deterministic inspection by sequence range and optional exact category,
outcome, source, actor, and action filters. Results remain ordered by ascending sequence. No dynamic
predicates or code evaluation are accepted.

### AuditVerification

`AuditVerification` reports whether the inspected chain is valid, how many records were checked, the
head digest, optional failing sequence, the reason, and how many external signatures were verified.
An empty ledger is valid and has the genesis digest as its head.

### AuditStore

An `AuditStore` implements asynchronous append, read, verify, snapshot, and close operations. Append
must atomically allocate the next sequence and previous digest for its own consistency model.
External stores may provide stronger durability and concurrency guarantees but must preserve the
public record semantics.

### AuditSigner and AuditSeal

`AuditSigner` is an optional external cryptographic provider boundary. The core passes a SHA-256
record digest and a `KeyRef` to `sign` or `verify`; it never obtains raw signing keys and chooses no
algorithm. `AuditSeal` stores only provider-neutral key metadata, an algorithm label, and signature
bytes.

## Canonical chain

The ledger canonicalizes these values with deterministic JSON:

- sequence;
- recording timestamp;
- previous digest;
- every immutable `AuditEvent` field and redacted detail value.

Keys are sorted, separators are fixed, UTF-8 is used, and non-finite numeric values are represented
as strings by the redaction boundary. The record digest is lowercase hexadecimal SHA-256 over those
canonical bytes. The digest and optional seal are not included in the digest input.

The genesis previous digest is sixty-four zero characters. Each later record must reference the
immediately preceding record digest. This construction detects sequence gaps, reordered records,
changed fields, and broken links when the complete chain is verified. It is tamper-evident, not
independently tamper-proof: an attacker able to rewrite every record can recompute an unsigned chain.
Deployments requiring origin authentication should supply an external `AuditSigner` and protected
storage.

## Authorization

Appending is a trusted in-process operation intended for Phoenix subsystems and the Security Journal.
It does not disclose or mutate historical records. Phoenix does not claim isolation from hostile code
already executing inside the process.

Reading and verification require an authenticated `SecurityContext`. With a Policy Engine, the
ledger evaluates:

- `audit.read` on `audit:ledger`;
- `audit.verify` on `audit:ledger`.

Policy denial and confirmation requirements are translated to `AuditAccessDeniedError`. Without a
Policy Engine, the caller must hold the exact action, `audit.*`, or `*`. This fallback remains
deny-by-default.

## Security Journal

`SecurityJournal` subscribes to the Event Bus wildcard and maps non-audit events into `AuditEvent`
records. The default mapper:

- categorizes identity, policy, secrets, plugin, capability, state, runtime, kernel, configuration,
  and system events by stable name prefix;
- derives actor, action, resource, outcome, and severity from structured payload fields and event
  names;
- preserves event timestamp and correlation;
- records the original Event ID and metadata as redacted details;
- ignores `audit.*` events to prevent recursive recording.

The Event Bus remains an in-process delivery mechanism. Direct ledger writes should be used when an
operation must fail if its audit append fails. Journal observer failures remain visible in normal
Event Bus dispatch reports.

## In-memory backend

`InMemoryAuditStore` serializes appends through an asynchronous lock, preserves immutable records
after close for diagnostics, and optionally signs each digest through an external signer. It is
suitable for tests, development, and ephemeral processes only. It provides no durable retention,
write-once protection, crash recovery, replication, or independent clock assurance.

## Events and diagnostics

The ledger may emit:

- `audit.recorded`;
- `audit.verified`;
- `audit.verification.failed`.

Signals contain only safe metadata such as sequence, category, outcome, source, actor, action,
resource, digest, valid status, and checked-record counts. They do not include arbitrary event
details, secret material, credentials, bearer tokens, or raw key material.

## Runtime composition

`RuntimeAssembler(audit=ledger)` exposes the reserved `audit` service and owns its lifecycle. When
`journal_events=True`, an `audit.events` Security Journal component starts immediately after the
ledger and before Policy, State, Identity, Secrets, custom services, and Plugins. Reverse shutdown
keeps the journal and ledger alive while later security services stop, then closes the journal before
the ledger and before the Event Bus.

## Compatibility

This RFC adds APIs and one optional Runtime service without changing the public behavior of Kernel,
Event Bus, Capability Registry, Runtime, Configuration, Observability, State Store, Plugin System,
Policy Engine, Identity, or Secrets.

## Acceptance criteria

- public contracts are immutable and strictly typed;
- detail redaction occurs before persistence and canonical hashing;
- deterministic sequence allocation, canonical digests, links, queries, and snapshots are tested;
- chain corruption, gaps, digest changes, and invalid optional signatures are detected;
- authenticated deny-by-default read and verification authorization are tested;
- Security Journal mapping, categorization, correlation, redaction, and recursion prevention are
  tested;
- Event Bus, Observability, Policy Engine, `KeyRef`, and RuntimeAssembler integrations are tested;
- no claim is made that an unsigned hash chain is tamper-proof or that the in-memory store is durable;
- Ruff, Ruff Format, mypy strict, pytest, examples, wheel build, and isolated installation pass.
