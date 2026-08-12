# ADR-0054: Authoritative memory records with derived retrieval indexes

- **Status:** Accepted
- **Date:** 2026-08-12
- **Related:** RFC-0030

## Context

Lexical and semantic retrieval indexes can lag writes, receive stale provider
responses, survive deletion, or return a candidate for the wrong version. If an
index becomes record truth, stale state can disclose superseded content or resurrect
deleted/expired memory.

## Decision

The memory source store is authoritative for record existence, exact scope,
`MemoryId`, logical version, content digest, retention, tombstone state, content,
metadata, and provenance.

Retrieval adapters are candidate selectors only. Every candidate identity and finite
ranking value is validated, then Phoenix re-reads the authoritative source and
rejects wrong-scope, missing, expired, tombstoned, stale-version, or wrong-digest
hits before disclosure.

Semantic/vector retrieval is optional and provider-neutral. The derived reference
index stores candidate identity/version/digest plus normalized vector data, never
authoritative record content or provenance. Provider SDK and vector-database objects
do not appear in Phoenix public contracts.

Writes and deletes use optimistic logical versions. Recovery rebuilds derived state
only from active authoritative records, so stale indexes, delayed provider results,
or snapshots cannot independently resurrect memory.

## Consequences

- Retrieval infrastructure may be replaced without changing record authority.
- Index lag can reduce availability/relevance but cannot override authoritative
  deletion or expiry.
- External semantic systems require revalidation on every disclosure path.
- Exactly-once external indexing is unnecessary for correctness.

## Alternatives considered

- **Let the vector database be the source of truth.** Rejected because retrieval
  infrastructure then controls retention and deletion semantics.
- **Trust provider candidate versions without a source re-read.** Rejected because
  delayed/stale results can disclose superseded data.
- **Store full memory content in the derived reference index.** Rejected because it
  duplicates sensitive persistence outside the authoritative retention boundary.

## Supersession criteria

A replacement must preserve one authoritative source of record truth, exact
version/digest revalidation before disclosure, anti-resurrection deletion/expiry
semantics, and provider-neutral optional retrieval.
