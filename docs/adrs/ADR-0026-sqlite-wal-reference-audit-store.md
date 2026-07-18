# ADR-0026 — SQLite WAL reference audit store

- Status: Accepted
- Date: 2026-07-18

## Context

RFC-0012 defines a provider-neutral asynchronous `AuditStore` but includes only a process-local
implementation. Phoenix needs one dependency-free durable reference adapter for local services,
operator tools, development deployments, and recovery testing without choosing a remote database
vendor.

## Decision

Phoenix provides `SQLiteAuditStore` using Python's standard-library `sqlite3` module. The adapter uses
one versioned local database, WAL journaling, `synchronous=FULL`, parameterized bounded reads, and
`BEGIN IMMEDIATE` append transactions that atomically insert a record and advance persisted head
metadata.

The `AuditStore` protocol remains the architectural boundary. SQLite is a reference local adapter,
not a mandate for distributed or high-throughput deployments.

## Consequences

Audit history can survive process restart without third-party dependencies, and SQLite serializes
competing local writers. The adapter inherits SQLite's operational envelope and filesystem
assumptions. It does not provide remote availability, replication, encryption at rest, WORM
semantics, backup policy, or independent anti-rollback evidence. Deployments requiring those
properties must supply another `AuditStore`.
