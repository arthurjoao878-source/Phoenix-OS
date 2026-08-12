# RFC-0030 agent-memory threat-model and security-invariant review

- **Reviewed:** 2026-08-12
- **Release candidate:** Phoenix OS v0.30.0
- **Scope:** memory identities, exact scopes, authorization, explicit writes,
  provenance, authoritative persistence, retention, deletion, retrieval, context
  assembly, semantic adapters, derived indexes, recovery, Runtime ownership,
  observability, administration, migration, and packaging
- **Result:** Accepted for the v0.30.0 agent-memory release-candidate gate

## Review method

This review maps the RFC-0030 threat model and all fifty-four security invariants
to implementation boundaries and executable regression suites. Proposed memory
content, model output, search queries, metadata, provenance input, adapter ranking
values, derived-index entries, persisted records, restored state, provider output,
and remembered instructions are treated as untrusted until the relevant
Phoenix-owned boundary validates them.

A passing suite does not prove an installed model, tool, policy, storage, embedding,
semantic-index, or other deployment adapter is benign. Installed adapters remain
trusted deployment code and must receive only authority explicitly granted by their
reviewed interface.

The evidence classes are:

1. immutable identities, exact Phoenix-owned scopes, and fresh independent policy;
2. explicit writes, immutable provenance, no automatic capture, and untrusted content;
3. strict record/query/result/context bounds and deterministic validated ranking;
4. authoritative source truth, optimistic versions, tombstones, retention, and
   anti-resurrection revalidation;
5. optional provider-neutral semantic indexing, bounded recovery/cleanup/shutdown,
   content-free operations, migration-by-omission, and isolated package execution.

## Trust boundaries

### Untrusted

- proposed memory text and metadata;
- model-generated write or search proposals;
- search query text and remembered instructions;
- retrieval-adapter identities and scores until validated;
- embeddings, vector responses, and derived-index associations;
- persisted records until strict decode, identity, version, provenance, and retention
  validation;
- restored snapshots or delayed provider responses;
- historical policy-like text, approvals, credentials, grants, or tokens contained in
  memory.

### Trusted but least-authority

- current reviewed Phoenix configuration and Runtime composition;
- Phoenix-owned `MemoryId`, namespace, scope kind, and trusted scope derivation;
- current Policy Engine decisions and authenticated security contexts;
- the authoritative memory store after strict validation;
- Phoenix-owned version/digest/tombstone semantics;
- reviewed installed storage, embedding, semantic-index, and policy adapters.

Memory informs work, never authority. RFC-0030 is not a hostile-code sandbox.
Remembered content and derived indexes remain data even when produced by trusted
deployment adapters.

## Threat review

| Threat | Required control | Evidence |
| --- | --- | --- |
| Enabling memory silently grants authority | Opt-in composition; no implicit grants or records | `test_agent_memory_runtime_assembler.py`, `test_agent_memory_authorization.py` |
| Model chooses a foreign namespace or scope | Server-owned run/agent/principal scope derivation | `test_agent_memory_authorization.py`, `test_agent_memory_context_integration.py` |
| Existing agent/model/tool/delegation permission implies memory access | Fresh exact memory action/resource authorization | `test_agent_memory_authorization.py` |
| Historical remembered policy becomes current authority | Current policy wins; memory content is untrusted | `test_agent_memory_context_integration.py`, `test_agent_memory_retrieval.py` |
| Parent and child silently share remembered data | No implicit cross-agent/principal/run sharing | `test_agent_memory_authorization.py`, `test_agent_memory_context_integration.py` |
| Normal prompts or hidden reasoning are captured automatically | Explicit writes only; no chain-of-thought persistence | `test_agent_memory_contracts.py`, `test_rfc_0030.py` |
| Secret material is treated as ordinary memory | Default-sensitive-content rejection contract and explicit RFC-0011 boundary | `test_agent_memory_contracts.py`, `test_rfc_0030.py` |
| Stored prompt injection changes policy/tool/model decisions | Untrusted USER context block; authorization remains independent | `test_agent_memory_context_integration.py` |
| Large records, queries, or result sets amplify work | Finite content/count/byte/query/result/context limits | `test_agent_memory_contracts.py`, `test_agent_memory_retrieval.py` |
| Adapter score manipulation changes deterministic ordering | Finite bounded validated scores and Phoenix tie-breaking | `test_agent_memory_retrieval.py` |
| Stale semantic hit returns superseded content | Source-store re-read plus exact version/digest validation | `test_agent_memory_retrieval.py`, `test_agent_memory_semantic_runtime.py` |
| Deleted or expired data reappears after restart | Tombstones, retention checks, source revalidation, rebuild from active records only | `test_agent_memory_store.py`, `test_agent_memory_semantic_runtime.py` |
| Corrupt or substituted state widens disclosure | Strict schema/identity/provenance decode and fail-closed errors | `test_agent_memory_store.py` |
| Semantic provider or index becomes record truth | Provider-neutral candidate-only boundary; source store remains authoritative | `test_agent_memory_semantic_runtime.py` |
| Provider/index work hangs startup or shutdown | Finite operation deadlines and self-cleaning Runtime lifecycle | `test_agent_memory_semantic_runtime.py`, `test_agent_memory_runtime_assembler.py` |
| Logs, events, or administration leak memory text/query/vector | Content-free projections and fixed reason codes | `test_agent_memory_semantic_runtime.py` |
| Upgrade changes v0.29 behavior without opt-in | Memory composition absent by omission | `test_agent_memory_runtime_assembler.py`, `test_agent_memory_migration_guidance.py` |
| Package omits memory modules or docs | Named gate validates wheel/sdist, rebuild, and isolated install | `test_agent_memory_release_gate.py` |

## Security-invariant review

### Invariants 1-7: opt-in memory, stable identity, and Phoenix-owned scopes

**Result: satisfied.** Memory is absent unless configured, enabling it grants no
permission or external authority, logical records use stable Phoenix-owned identity,
scope kinds are finite, and namespace/scope identity comes only from trusted
configuration or authenticated Phoenix context.

Evidence: `test_agent_memory_contracts.py`,
`test_agent_memory_authorization.py`, and
`test_agent_memory_runtime_assembler.py`.

### Invariants 8-15: fresh exact independent memory authorization

**Result: satisfied.** Search, direct read, write, delete, and administration use
independent exact memory actions. Collection resources bind namespace and scope;
direct record resources additionally bind `MemoryId`. Agent, model, tool,
delegation, resume, and reconciliation authority never substitute for a memory
decision.

Evidence: `test_agent_memory_authorization.py`.

### Invariants 16-23: memory never carries authority or implicit sharing

**Result: satisfied.** Persisted policy-like text, approvals, credentials, tokens,
grants, and historical decisions are data only. Current policy and current scope
configuration win. Cross-namespace/scope/record substitution fails closed, and
agent, principal, run, parent, and child scopes are not implicitly shared. No global
shared scope exists in RFC-0030 v1.

Evidence: `test_agent_memory_authorization.py`,
`test_agent_memory_retrieval.py`, and
`test_agent_memory_context_integration.py`.

### Invariants 24-31: explicit writes, provenance, poisoning resistance, and secrets

**Result: satisfied.** Phoenix does not automatically capture ordinary prompts,
responses, tool output, conversations, chain-of-thought, or hidden reasoning.
Writes are explicit and carry bounded immutable provenance. Memory content remains
untrusted and cannot become system policy, executable authority, approval, model
grant, tool grant, delegation grant, or policy mutation. Secrets remain outside the
default memory contract and behind the RFC-0011 boundary.

Evidence: `test_agent_memory_contracts.py`,
`test_agent_memory_context_integration.py`, and `test_rfc_0030.py`.

### Invariants 32-39: finite storage, retrieval, context, and ranking

**Result: satisfied.** Record bytes, metadata/provenance, per-scope count/bytes,
queries, retrieval result count/bytes, and context item/bytes are finite. Equal
validated scores use deterministic ordering, while adapter scores must be finite and
bounded before they affect ranking.

Evidence: `test_agent_memory_contracts.py`,
`test_agent_memory_store.py`, and `test_agent_memory_retrieval.py`.

### Invariants 40-45: authoritative source truth and anti-resurrection

**Result: satisfied.** Every candidate is re-read from the authoritative source.
Semantic/vector selection is optional and provider-neutral. Derived index entries
carry only candidate identity/version/digest plus vector data. Mutations use
optimistic versions, and stale, deleted, expired, wrong-scope, wrong-version, or
wrong-digest associations cannot disclose a record or resurrect it after restart.

Evidence: `test_agent_memory_store.py`,
`test_agent_memory_retrieval.py`, and
`test_agent_memory_semantic_runtime.py`.

### Invariants 46-49: finite retention, fail-closed recovery, and Runtime lifecycle

**Result: satisfied.** Retention and tombstone periods are finite. Expired and
tombstoned records are absent from reads/retrieval/context/recovery. Unknown schema,
corrupt identity/provenance, and inconsistent references fail closed. Runtime-owned
indexing, cleanup, recovery, provider calls, startup, cancellation, and shutdown are
bounded; failed startup self-cleans its store/index wrapper before re-raising.

Evidence: `test_agent_memory_store.py`,
`test_agent_memory_semantic_runtime.py`, and
`test_agent_memory_runtime_assembler.py`.

### Invariants 50-53: content-free operations, untrusted context, and no ambient OS authority

**Result: satisfied.** Events and administration expose only fixed content-free
identifiers, counters, status, and reason codes. Public failures omit memory text,
query text, vectors, secrets, approvals, credentials, provider bodies, and raw
exceptions. Context preserves provenance and is explicitly labeled untrusted.
Memory grants no shell, filesystem, network, browser, desktop, or operating-system
authority.

Evidence: `test_agent_memory_context_integration.py`,
`test_agent_memory_semantic_runtime.py`, and `test_rfc_0030.py`.

### Invariant 54: v0.29 compatibility

**Result: satisfied.** When memory configuration is omitted, Phoenix creates no
memory store, derived index, retrieval worker, cleanup/recovery task, context block,
permission, or record, and existing agent, durable-agent, and multi-agent behavior
remains unchanged.

Evidence: `test_agent_memory_runtime_assembler.py`,
`test_agent_memory_context_integration.py`, and
`test_agent_memory_migration_guidance.py`.

## Residual risks

- A malicious or defective installed model, tool, policy, storage, embedding, or
  semantic-index adapter can misuse authority explicitly granted to that deployment
  code. Process isolation and external-system permissions remain deployment
  responsibilities.
- Remembered content can still influence model behavior as untrusted context. The
  core prevents authority promotion but cannot guarantee that a model ignores every
  malicious instruction semantically.
- Stable memory IDs, scope IDs, versions, counts, sizes, expiry categories, and
  timing can reveal operational traffic patterns even when content is excluded.
- A remote semantic provider may receive memory text or queries if a deployment
  explicitly installs and configures such an adapter. Provider privacy and data
  residency remain deployment responsibilities.
- Restoring an old authoritative database can restore records that are still valid
  under that snapshot. Current policy, scope configuration, expiry, tombstones, and
  source revalidation must still win before disclosure.
- The in-process reference derived index is not a distributed vector database, and
  RFC-0030 does not promise exactly-once external indexing effects.
- Future global sharing, automatic capture, memory promotion/copy, training from
  memory, privileged trusted-memory roles, or autonomous write policy require a
  separate RFC and security review.

## Release conclusion

The RFC-0030 threat model and all fifty-four security invariants are accepted for
the Phoenix OS v0.30.0 agent-memory release-candidate gate.

This review does not by itself publish v0.30.0. Final publication still requires the
full project quality gate, every earlier named release gate, the named agent-memory
release gate, wheel and sdist inspection, isolated offline package execution, the
release commit, tag, artifacts, and checksums.
