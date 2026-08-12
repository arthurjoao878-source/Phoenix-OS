# RFC-0030: Secure Agent Memory and Context Retrieval

- Status: Accepted
- Target release: Phoenix OS v0.30.0
- Owners: Phoenix OS maintainers
- Depends on: RFC-0004, RFC-0005, RFC-0007, RFC-0009, RFC-0010, RFC-0011, RFC-0012, RFC-0026, RFC-0027, RFC-0028, and RFC-0029

## Summary

RFC-0030 defines optional, bounded, policy-controlled persistent memory and context
retrieval for Phoenix agents.

Memory informs work, never authority. Stored or retrieved memory is untrusted data.
It cannot grant permissions, reuse approvals, reveal credentials, mutate policy,
select privileged tools, authorize models, or become a system-level instruction.
Every memory operation is admitted against current Phoenix-owned scope,
configuration, and policy.

The subsystem is disabled by default. When agent memory is omitted, Phoenix OS
preserves v0.29.0 behavior.

RFC-0030 builds on RFC-0007 persistence but does not turn the State Store into an
authorization boundary. It adds a dedicated memory boundary with explicit scope,
provenance, retention, authorization, bounded retrieval, context assembly, and
derived-index consistency.

## Goals

- Optional agent memory disabled by default
- Stable Phoenix-owned memory identities
- Explicit run, agent, and principal memory scopes
- Exact independent memory authorization
- No implicit cross-scope or parent/child sharing
- Explicit writes with immutable provenance
- Strict content, metadata, count, byte, query, and result bounds
- Bounded context assembly
- Prompt-injection and memory-poisoning resistance
- Optimistic versioning and conflict detection
- Explicit retention, expiry, deletion, and tombstones
- Source-of-truth records independent from retrieval indexes
- Provider-neutral retrieval and optional semantic indexing
- Fail-closed recovery from stale, corrupt, deleted, or expired state
- Content-free operational observability
- Runtime-owned finite lifecycle
- Compatibility with Phoenix OS v0.29.0 by omission

## Non-goals

- Human-like subconscious or implicit memory
- Automatically storing every prompt, response, tool result, or conversation
- Persisting chain-of-thought or hidden reasoning
- Using memory as policy, identity, approval, credential, or authorization state
- A global shared memory visible to every agent
- Implicit memory sharing between parent and child agents
- Training or fine-tuning models from stored memory
- Implementing a vector database inside the Phoenix core
- Requiring embeddings or semantic retrieval
- Exposing provider SDK embedding/vector objects in public contracts
- Replacing RFC-0007 general-purpose persistence
- Replacing RFC-0011 secrets management
- Exactly-once external indexing side effects
- Generic shell, filesystem, network, browser, desktop, or OS authority

## Terminology

- **Memory record:** one immutable-versioned, bounded persisted memory item.
- **Memory ID:** stable Phoenix-owned identity for one logical record.
- **Memory namespace:** server-owned partition for one configured memory domain.
- **Memory scope:** exact Phoenix-owned visibility boundary for a run, agent, or principal.
- **Scope kind:** one of the finite supported scope categories.
- **Scope ID:** trusted Phoenix-owned identity inside a scope kind.
- **Provenance:** immutable origin metadata describing how a memory record was admitted.
- **Retention policy:** configured TTL and maximum-retention rules for one namespace/scope.
- **Source store:** authoritative memory-record persistence.
- **Retrieval adapter:** optional provider-neutral candidate-selection boundary.
- **Retrieval hit:** bounded candidate reference plus validated finite ranking metadata.
- **Context block:** bounded, provenance-preserving untrusted memory supplied to an agent run.
- **Tombstone:** durable deletion marker preventing stale indexes or recovery from resurrecting data.

## Threat model

The subsystem treats proposed memory content, model-generated write requests, retrieved
content, search queries, metadata, adapter scores, embeddings, derived indexes,
persisted records, recovery state, and external index responses as untrusted until
validated.

It must address memory poisoning, stored prompt injection, cross-agent and
cross-principal disclosure, forged scopes, stale authorization, implicit parent/child
sharing, secret persistence, unbounded accumulation, oversized queries/results,
context-window amplification, score manipulation, stale indexes, deleted-record
resurrection, rollback/ABA confusion, corrupt persisted state, malicious metadata,
provider-object leakage, raw-content observability, and attempts to use remembered
content as authority.

## Security invariants

1. Agent memory is disabled unless explicitly configured.
2. Enabling memory creates no record, permission, approval, credential, model grant, tool grant, delegation grant, schedule, or external authority.
3. Every logical memory record has one stable Phoenix-owned `MemoryId`.
4. Every memory record belongs to one explicit Phoenix-owned namespace and scope.
5. Supported scope kinds are finite and server-owned; the initial set is run, agent, and principal.
6. Namespace, scope kind, and scope identity are derived from trusted configuration or authenticated Phoenix context, never arbitrary model text.
7. Model content cannot create, widen, replace, or mutate a memory scope.
8. Every search requires fresh exact `memory.search` authorization.
9. Every direct record read requires fresh exact `memory.read` authorization.
10. Every write requires fresh exact `memory.write` authorization.
11. Every delete requires fresh exact `memory.delete` authorization.
12. Every administrative operation requires fresh exact `memory.admin` authorization.
13. Memory authorization is separate from `agent.run`, `model.infer`, `tool.invoke`, `agent.delegate`, `agent.resume`, and `agent.reconcile`.
14. Memory authorization resources include the exact namespace and scope.
15. Direct record read/delete resources include the exact `MemoryId`.
16. Stored memory never carries or reconstructs policy authority.
17. Persisted permissions, approvals, credentials, tokens, grants, or policy decisions are never interpreted as live authority.
18. Current policy always wins over persisted memory metadata.
19. Current namespace/scope configuration always wins over persisted memory metadata.
20. Cross-namespace, cross-scope, and cross-record substitution fail closed.
21. Memory is never implicitly shared across agents, principals, or runs.
22. Parent and child agents do not share memory by default.
23. Global shared memory is not supported in the initial version.
24. Phoenix does not automatically capture every prompt, response, tool result, or conversation as memory.
25. Every memory write is an explicit server-admitted operation.
26. Every record has immutable bounded provenance.
27. Memory content is untrusted data.
28. Retrieved memory never becomes system policy, an authorization decision, a tool directive, or executable authority.
29. Stored prompt injection cannot alter current authorization, policy, scope, model, tool, delegation, or approval decisions.
30. Chain-of-thought and hidden reasoning are never persisted by this subsystem.
31. Secrets and secret wrappers are rejected by default; secrets belong behind RFC-0011 references and policy.
32. Record content has a strict configured byte bound.
33. Record metadata and provenance have strict item, key, value, and depth bounds.
34. Every scope has finite configured record-count and total-byte limits.
35. Search queries have strict byte and structural bounds.
36. Retrieval result count and total returned content bytes are strictly bounded.
37. Context assembly has strict item, byte, and ordering bounds.
38. Retrieval ordering is deterministic for equal validated ranking values.
39. Adapter-provided scores are untrusted, finite, bounded, and validated before ordering.
40. Every retrieval hit is revalidated against the authoritative source record before disclosure.
41. Semantic/vector retrieval is optional and provider-neutral; provider SDK objects never appear in public contracts.
42. Embeddings and provider vector objects are not exposed through public operational surfaces.
43. Authoritative records carry stable version and digest information sufficient to reject stale derived-index associations.
44. Writes and deletes use explicit optimistic version checks where mutation races are possible.
45. Deleted memory cannot silently reappear through stale indexes, restart recovery, snapshot restore, or delayed adapter responses.
46. Every namespace/scope has an explicit retention policy with finite configured bounds.
47. Expired or tombstoned records are absent from reads, retrieval, context assembly, and recovery.
48. Unknown schema versions, corrupt records, invalid provenance, and inconsistent index references fail closed.
49. Runtime-owned indexing, cleanup, and recovery work has finite concurrency, queue, deadline, and shutdown bounds.
50. Logs, audit, metrics, health, and administration expose content-free memory metadata only.
51. Public failures expose no memory content, query text, embedding, secret, credential, approval, provider body, or raw exception.
52. Context blocks preserve provenance and are explicitly labeled as untrusted retrieved data.
53. Memory grants no generic shell, filesystem, network, browser, desktop, or OS authority.
54. Existing Phoenix OS v0.29.0 behavior remains unchanged when memory configuration is absent.

## Proposed contracts

- `MemoryId`
- `MemoryNamespace`
- `MemoryScopeKind`
- `MemoryScopeId`
- `MemoryScope`
- `MemoryRecordVersion`
- `MemoryRecordStatus`
- `MemoryProvenance`
- `MemoryRetentionPolicy`
- `MemoryLimits`
- `MemoryRecord`
- `MemoryWriteRequest`
- `MemoryReadRequest`
- `MemorySearchRequest`
- `MemorySearchHit`
- `MemorySearchResult`
- `MemoryDeleteRequest`
- `MemoryContextBlock`
- `MemoryStore`
- `MemoryRetrievalAdapter`
- `AgentMemoryService`
- `AgentMemoryRuntime`
- `AgentMemoryObserver`
- `AgentMemoryAdministration`
- `AgentMemoryError`

All public contracts are immutable, bounded, provider-neutral, and contain no
provider SDK, embedding-client, vector-database driver, task, callback, thread,
file-handle, socket, database connection, or executable object.

## Authorization boundary

The exact initial actions are:

```text
memory.search
memory.read
memory.write
memory.delete
memory.admin
```

Collection-level operations authorize an exact resource of the form:

```text
agent-memory:<namespace>/scope:<scope-kind>:<scope-id>
```

Direct record operations authorize the exact record resource:

```text
agent-memory:<namespace>/scope:<scope-kind>:<scope-id>/record:<memory-id>
```

A successful memory decision permits only the named operation against that exact
resource. It does not imply agent execution, inference, tool invocation, delegation,
approval, credential access, durable resume, reconciliation, or another memory
operation.

## Scope and isolation

The initial scope kinds are `run`, `agent`, and `principal`.

Scope identity is Phoenix-owned and derived from trusted runtime/configuration or
authenticated security context. Model content may propose memory content or a search
query but cannot choose an arbitrary foreign principal, agent, run, namespace, or
resource string.

There is no implicit inheritance across scopes. In particular, a delegated child does
not automatically receive the parent's agent, principal, or run memory.

Cross-scope copy or promotion requires an explicit server-owned operation and
independent authorization; such promotion is outside the initial RFC-0030 public
surface.

## Writes and provenance

Memory writes are explicit. Phoenix never treats normal conversation, model output,
tool output, child results, or checkpoints as an automatic persistence request.

Each admitted record carries bounded immutable provenance including a Phoenix-owned
origin category, relevant trusted run/agent/principal identifiers where applicable,
creation time, content digest, and source version metadata.

Provenance describes origin; it never grants trust or authority.

## Authoritative store and versioning

The source store is authoritative for record existence, version, content digest,
retention, and tombstone state.

RFC-0007 may back the reference implementation, but RFC-0030 keeps memory
authorization, isolation, retention, provenance, and retrieval semantics above the
generic State Store boundary.

Mutations use optimistic versioning. Stale writes and deletes fail explicitly instead
of silently overwriting a newer record.

## Retention and deletion

Every configured memory domain has finite record-count, total-byte, per-record,
retention, and expiry bounds.

Deletion creates authoritative absence and, where required for derived-index
consistency, a durable tombstone. Expired and tombstoned records cannot be returned
from direct reads, retrieval, context assembly, snapshots, recovery, or stale index
responses.

Cleanup is bounded Runtime-owned maintenance, not an unbounded hidden scheduler.

## Retrieval and derived indexes

Retrieval adapters are optional candidate selectors. They are not sources of
authority or record truth.

A retrieval adapter may implement deterministic lexical search, semantic/vector
search, or another reviewed strategy. It returns bounded candidate identities and
ranking metadata. Phoenix validates identifiers and finite ranking values, then
re-reads every candidate from the authoritative source store and rejects stale,
deleted, expired, mismatched-scope, wrong-version, or wrong-digest hits.

Equal validated ranking values use deterministic Phoenix-owned tie-breaking.

The core does not require a vector database or embedding provider. External semantic
indexes and embedding providers remain behind provider-neutral adapters.

## Context assembly

Retrieved records enter agent execution only through a bounded `MemoryContextBlock`.

A context block preserves record identity and provenance, is explicitly labeled as
untrusted retrieved data, and cannot become a system/policy message merely because it
came from Phoenix memory.

Context assembly enforces item and byte limits before inference. Memory cannot expand
the run's configured model/input/token authority beyond existing agent and inference
budgets.

## Poisoning resistance

Memory content can contain malicious instructions.

Phoenix therefore treats retrieved memory like other untrusted external data:
authorization and policy are resolved before and independently from remembered
content; remembered text cannot select a privileged scope, approve a tool, authorize a
model, grant delegation, reveal a credential, or alter current policy.

Applications remain responsible for domain-specific trust scoring and content
moderation, but the core guarantees that stored content is never itself an authority
channel.

## Observability and safe failures

Operational events use fixed Phoenix-owned types and content-free metadata such as
record IDs, namespace/scope identifiers, versions, counts, status, expiry, durations,
and bounded reason codes.

Logs, metrics, health, audit, administration, and public errors do not expose memory
content, search query text, embeddings, secret material, credentials, approval
tokens, provider bodies, or raw exceptions.

## Runtime lifecycle

`RuntimeAssembler` memory composition is opt-in.

When configured, Runtime owns source-store lifecycle, retrieval/index workers,
cleanup/recovery tasks, finite queues, cancellation, and reverse-order shutdown.
Construction without memory creates none of these objects or tasks.

## Compatibility

When memory configuration is omitted, no memory store, scope registry, retrieval
adapter, index, worker, cleanup task, or context injection is created.

Existing Phoenix OS v0.29.0 agent, durable-agent, and multi-agent behavior remains
unchanged.

## Release-candidate evidence

Phoenix OS v0.30.0 release-candidate evidence is maintained in:

- `docs/security/RFC-0030-agent-memory-threat-model-review.md`;
- `docs/migrations/v0.29.0-to-v0.30.0-agent-memory.md`;
- `docs/adrs/ADR-0052-memory-informs-work-never-authority.md`;
- `docs/adrs/ADR-0053-phoenix-owned-exact-memory-scopes.md`;
- `docs/adrs/ADR-0054-authoritative-memory-records-derived-indexes.md`;
- `docs/adrs/ADR-0055-finite-retention-runtime-owned-memory-lifecycle.md`;
- `docs/releases/v0.30.0.md`;
- `scripts/check_agent_memory_release.py`.

The named gate builds and validates wheel and sdist archives, rebuilds a wheel from
the validated sdist, and installs both wheel forms with `--no-deps --no-index` in
isolated environments before executing the packaged agent-memory surface without
source-tree imports. Release publication uses Git tag `v0.30.0`, wheel and sdist
artifacts, and `SHA256SUMS`.

## Slice plan

### Slice 0 - RFC foundation and executable specification

- [x] Draft RFC-0030 with explicit security invariants
- [x] Define exact memory action/resource naming
- [x] Define scope-isolation and untrusted-context principles
- [x] Establish compatibility-by-omission contract
- [x] Add RFC structure and regression tests

### Slice 1 - Contracts, scopes, and authorization

- [x] Immutable memory identifiers, scopes, versions, provenance, retention, and limits
- [x] Exact `memory.search`, `memory.read`, `memory.write`, `memory.delete`, and `memory.admin` constants/resources
- [x] Server-owned run, agent, and principal scope derivation
- [x] Independent current-policy authorization
- [x] Deterministic contract and authorization tests

### Slice 2 - Authoritative store, retention, and mutation safety

- [x] Reference authoritative memory store
- [x] Bounded record content, metadata, provenance, count, and total bytes
- [x] Optimistic write/delete versioning
- [x] TTL, retention, expiry, tombstone, and anti-resurrection behavior
- [x] State Store-backed reference composition
- [x] Deterministic persistence and race tests

### Slice 3 - Retrieval, context assembly, and agent integration

- [x] Bounded retrieval requests and results
- [x] Deterministic reference retrieval adapter
- [x] Candidate score/identity validation and source-record revalidation
- [x] Provenance-preserving untrusted `MemoryContextBlock`
- [x] Agent-loop opt-in context integration without authority promotion
- [x] Prompt-injection and cross-scope regression tests

### Slice 4 - Semantic adapters, recovery, and Runtime ownership

- [x] Provider-neutral optional semantic/vector retrieval boundary
- [x] Derived-index version/digest consistency
- [x] Stale/deleted/expired hit rejection
- [x] Restart recovery without memory resurrection
- [x] Runtime-owned bounded indexing, cleanup, and shutdown
- [x] Content-free observer and administration

### Slice 5 - Security review, migration, and release hardening

- [x] Threat-model/security-invariant review
- [x] ADRs for memory authority, scope isolation, source-of-truth indexing, and retention
- [x] v0.29.0 to v0.30.0 migration guidance
- [x] Named agent-memory release gate
- [x] Offline wheel/sdist validation
- [x] Release notes and package version 0.30.0
- [x] Tag, artifacts, and checksums

## Acceptance

RFC-0030 may be accepted for Phoenix OS v0.30.0 only when every Slice plan item is
complete and the full repository quality gate passes.

Acceptance requires evidence that remembered content cannot create authority,
cross-scope access fails closed, writes are explicit, retrieval and context are
strictly bounded, prompt injection cannot alter current policy, stale indexes cannot
resurrect deleted/expired records, semantic providers remain optional, operational
surfaces remain content-free, and omitting memory preserves Phoenix OS v0.29.0
behavior.

RFC-0030 is accepted for Phoenix OS 0.30.0.
