# RFC-0031: Secure Agent Workspaces and Artifact Handling

- Status: Draft
- Target release: Phoenix OS v0.31.0
- Owners: Phoenix OS maintainers
- Depends on: RFC-0004, RFC-0005, RFC-0007, RFC-0009, RFC-0010, RFC-0011, RFC-0012, RFC-0026, RFC-0027, RFC-0028, RFC-0029, and RFC-0030

## Summary

RFC-0031 defines optional, bounded, policy-controlled workspaces for files and
artifacts used by Phoenix agents.

Files carry data, never authority. Workspace content, filenames, media types,
metadata, provenance, imported bytes, exported bytes, model-proposed paths, and
derived previews are untrusted data. They cannot grant permissions, select host
paths, authorize tools, execute programs, reveal credentials, widen network access,
mutate policy, reuse approvals, or become system-level instructions.

The subsystem is disabled by default. When agent workspaces are omitted, Phoenix OS
preserves v0.30.0 behavior.

RFC-0031 introduces a dedicated workspace boundary above storage providers. A local
filesystem reference adapter may exist, but the Phoenix core never treats an
arbitrary host filesystem path as an agent resource or as ambient authority.

## Principle

> **Files carry data, never authority.**

An artifact may inform model or tool work after explicit admission. It never carries
identity, policy, approval, credential, execution, network, filesystem, desktop,
browser, shell, or operating-system authority.

## Goals

- Optional agent workspaces disabled by default
- Stable Phoenix-owned workspace and artifact identities
- Explicit run, agent, and principal workspace scopes
- Exact independent workspace authorization
- Canonical Phoenix-owned logical paths
- No arbitrary host-path authority
- Strict path, name, metadata, content, count, byte, and operation bounds
- Atomic authoritative writes with optimistic versions
- Explicit finite retention and cleanup
- Immutable bounded provenance and digests
- Safe import and export boundaries with independent authority
- Provider-neutral backing-store and transfer adapters
- Explicit untrusted artifact attachment to agent context
- Fail-closed recovery from corrupt or inconsistent persisted state
- Content-free operational observability and public failures
- Runtime-owned finite lifecycle
- Compatibility with Phoenix OS v0.30.0 by omission

## Non-goals

- General-purpose unrestricted host filesystem access
- A shell, command runner, process launcher, or executable sandbox
- Implicit execution of scripts, binaries, documents, macros, installers, or archives
- Arbitrary absolute paths, drive-letter paths, UNC paths, device paths, or traversal
- Treating symlinks, hardlinks, reparse points, FIFOs, sockets, or device nodes as artifacts
- Automatically mounting a user's home directory, Downloads, Desktop, or project tree
- Automatically importing every tool result, model output, memory record, or conversation
- Automatically exporting artifacts to external destinations
- Granting network access through workspace import or export
- Replacing RFC-0011 secrets management
- Replacing RFC-0007 general-purpose structured persistence
- Implementing an object-storage service inside the Phoenix core
- Implementing malware scanning, DLP, OCR, archive extraction, or document parsing in the core
- Requiring a cloud blob provider or remote object store
- Persisting hidden chain-of-thought or private model reasoning
- Generic browser, desktop, shell, network, host-filesystem, or OS authority

## Terminology

- **Workspace:** one Phoenix-owned artifact namespace bound to one exact scope.
- **Workspace ID:** stable Phoenix-owned identity for one configured workspace.
- **Workspace namespace:** server-owned partition for one configured workspace domain.
- **Workspace scope:** exact Phoenix-owned visibility boundary for a run, agent, or principal.
- **Artifact:** one bounded immutable-versioned logical file object.
- **Artifact ID:** stable Phoenix-owned identity for one logical artifact.
- **Logical path:** canonical Phoenix-owned relative path used for organization, never a host path.
- **Artifact version:** monotonic logical mutation version for one artifact.
- **Digest:** canonical content digest used to detect stale or substituted bytes.
- **Media type:** bounded validated descriptive metadata; never executable trust.
- **Provenance:** immutable bounded origin metadata describing how an artifact was admitted.
- **Authoritative store:** source of truth for artifact identity, bytes, version, digest, retention, and deletion state.
- **Backing adapter:** provider-neutral storage boundary used by an authoritative workspace store.
- **Transfer adapter:** explicit provider-neutral import/export boundary.
- **Artifact context block:** bounded, provenance-preserving untrusted artifact data supplied to an agent run.

## Threat model

The subsystem treats model-proposed filenames, logical paths, file bytes, text,
metadata, media types, digests supplied by external systems, import sources, export
destinations, transfer-provider responses, backing-store responses, persisted
records, derived previews, and context attachments as untrusted until validated.

It must address path traversal, absolute-path injection, drive/UNC/device-path
confusion, case and normalization collisions, symlink/hardlink/reparse escapes,
special-file substitution, TOCTOU races, partial writes, quota races, stale versions,
cross-agent and cross-principal disclosure, forged scopes, stale authorization,
artifact poisoning, stored prompt injection, executable-content confusion, archive
bombs, content-type spoofing, secret leakage, unsafe export, stale recovery,
deleted-artifact resurrection, corrupt metadata, raw-content observability, and
attempts to use workspace content as authority.

## Security invariants

1. Agent workspaces are disabled unless explicitly configured.
2. Enabling workspaces creates no artifact, permission, approval, credential, model grant, tool grant, delegation grant, schedule, process, network connection, mount, or external authority.
3. Every configured workspace has one stable Phoenix-owned `WorkspaceId`.
4. Every logical artifact has one stable Phoenix-owned `ArtifactId`.
5. Every artifact belongs to one explicit Phoenix-owned namespace and scope.
6. Supported scope kinds are finite and server-owned; the initial set is run, agent, and principal.
7. Namespace, scope kind, and scope identity are derived from trusted configuration or authenticated Phoenix context, never arbitrary model text.
8. Model content cannot create, widen, replace, or mutate a workspace scope.
9. Model content cannot choose an arbitrary host filesystem path.
10. Every list operation requires fresh exact `workspace.list` authorization.
11. Every direct artifact read requires fresh exact `workspace.read` authorization.
12. Every write requires fresh exact `workspace.write` authorization.
13. Every delete requires fresh exact `workspace.delete` authorization.
14. Every import requires fresh exact `workspace.import` authorization.
15. Every export requires fresh exact `workspace.export` authorization.
16. Every administrative operation requires fresh exact `workspace.admin` authorization.
17. Workspace authorization is separate from `agent.run`, `model.infer`, `tool.invoke`, `agent.delegate`, `agent.resume`, `agent.reconcile`, and every `memory.*` action.
18. Collection authorization resources include the exact namespace and scope.
19. Direct artifact resources include the exact Phoenix-owned `ArtifactId`.
20. Current policy always wins over persisted workspace metadata, prior decisions, artifact content, filenames, media types, and provenance.
21. Stored artifact content never carries or reconstructs policy authority.
22. Persisted permissions, approvals, credentials, tokens, grants, or policy decisions are never interpreted as live authority.
23. A workspace never grants generic host-filesystem authority.
24. A logical path is canonical, relative, bounded, Phoenix-validated, and never interpreted as an arbitrary native host path.
25. Logical paths reject traversal, empty segments, dot segments, absolute prefixes, drive prefixes, UNC/device forms, NUL, and platform-reserved escape forms.
26. Canonicalization prevents case, separator, Unicode-normalization, and alias collisions from resolving two logical names to unsafe or ambiguous backing locations.
27. Symlinks, hardlinks, reparse points, FIFOs, sockets, device nodes, and other special filesystem objects are not valid artifact payload entries.
28. Backing adapters must fail closed if a resolved storage object escapes the configured workspace root or violates adapter confinement.
29. Artifact IDs are never reused to resurrect a deleted logical artifact.
30. Workspaces are never implicitly shared across agents, principals, or runs.
31. Parent and child agents do not share workspaces by default.
32. A global workspace visible to all agents is not supported in the initial version.
33. Phoenix does not automatically capture every prompt, response, tool result, memory record, child result, conversation, or checkpoint as an artifact.
34. Every artifact write is an explicit server-admitted operation.
35. Artifact content has a strict configured byte bound.
36. Logical path length, segment count, segment length, metadata item count, metadata key/value size, and media-type size are strictly bounded.
37. Every workspace has finite configured artifact-count and total-byte limits.
38. Quota admission and artifact mutation are atomic with respect to concurrent writers.
39. Authoritative records carry explicit version and canonical content digest.
40. Writes and deletes use optimistic version checks where mutation races are possible.
41. A successful write never exposes a partially written authoritative artifact.
42. Failed or cancelled writes do not become visible as committed artifacts.
43. Deleted or expired artifacts are absent from reads, listings, context assembly, import/export continuation, snapshots, and recovery.
44. Retention and expiry are explicit, finite, and bounded by configuration.
45. Cleanup is bounded Runtime-owned maintenance with finite concurrency, queue, deadline, and shutdown behavior.
46. Every admitted artifact has immutable bounded provenance.
47. Provenance describes origin and never grants trust or authority.
48. Media type, filename extension, provider metadata, and external digest claims are descriptive and untrusted until Phoenix validation.
49. Artifact bytes are never executed merely because they exist in a workspace.
50. Archive extraction, macro execution, document rendering, OCR, parsing, compilation, and script execution are not implicit workspace operations.
51. Import is an explicit server-mediated transfer; an import source cannot widen scope, network authority, credentials, or destination path authority.
52. Export is an explicit server-mediated transfer; an export destination cannot be selected merely by untrusted artifact content.
53. Import and export authority are independent from read/write authority and from each other.
54. External transfer adapters expose provider-neutral bounded results; provider SDK objects, sockets, file handles, credentials, and raw response bodies never enter public contracts.
55. The Phoenix core performs no implicit remote network fetch as a workspace read.
56. Secret values and secret wrappers are never automatically materialized into artifacts; RFC-0011 remains the authority boundary for secrets.
57. Hidden chain-of-thought and private model reasoning are never persisted by this subsystem.
58. Artifact content supplied to model context is explicitly labeled untrusted and cannot become a system/policy message merely because Phoenix stored it.
59. Artifact context assembly has strict item, byte, text-decoding, and ordering bounds.
60. Binary artifacts are never silently decoded or injected into a model prompt.
61. Text decoding failures fail closed or require an explicit reviewed transformation outside the core workspace boundary.
62. Stored prompt injection cannot alter current authorization, policy, scope, model, tool, delegation, approval, memory, import, or export decisions.
63. Unknown schema versions, corrupt records, invalid provenance, digest mismatches, scope substitution, and inconsistent backing objects fail closed.
64. Recovery never resurrects deleted, expired, wrong-scope, wrong-version, or digest-mismatched artifacts.
65. Logs, audit, metrics, health, and administration expose content-free workspace metadata only.
66. Public failures expose no artifact bytes, text content, host path, secret, credential, approval token, provider body, or raw exception.
67. A local filesystem reference adapter is confined to a configured Phoenix-owned root and cannot treat arbitrary native paths as artifact identities.
68. Backing-store and transfer adapters are optional and provider-neutral; the Phoenix core requires no cloud object store.
69. Runtime owns backing-store lifecycle, transfer workers, cleanup/recovery tasks, bounded queues, cancellation, and reverse-order shutdown.
70. Workspaces grant no generic shell, process, browser, desktop, network, host-filesystem, or operating-system authority.
71. Existing Phoenix OS v0.30.0 behavior remains unchanged when workspace configuration is absent.

## Proposed contracts

- `WorkspaceId`
- `WorkspaceNamespace`
- `WorkspaceScopeKind`
- `WorkspaceScopeId`
- `WorkspaceScope`
- `ArtifactId`
- `ArtifactLogicalPath`
- `ArtifactVersion`
- `ArtifactDigest`
- `ArtifactMediaType`
- `ArtifactMetadata`
- `ArtifactProvenance`
- `WorkspaceLimits`
- `WorkspaceRetentionPolicy`
- `ArtifactStatus`
- `ArtifactRecord`
- `ArtifactListRequest`
- `ArtifactListResult`
- `ArtifactReadRequest`
- `ArtifactWriteRequest`
- `ArtifactDeleteRequest`
- `ArtifactImportRequest`
- `ArtifactExportRequest`
- `ArtifactTransferReceipt`
- `ArtifactContextBlock`
- `WorkspaceStore`
- `WorkspaceBackingAdapter`
- `WorkspaceTransferAdapter`
- `AgentWorkspaceService`
- `AgentWorkspaceRuntime`
- `AgentWorkspaceObserver`
- `AgentWorkspaceAdministration`
- `AgentWorkspaceError`

All public contracts are immutable, bounded, provider-neutral, and contain no provider
SDK object, task, callback, thread, native path handle, open file handle, socket,
database connection, process handle, executable object, credential, or secret value.

## Authorization boundary

The exact initial actions are:

```text
workspace.list
workspace.read
workspace.write
workspace.delete
workspace.import
workspace.export
workspace.admin
```

Collection-level operations authorize an exact resource of the form:

```text
agent-workspace:<namespace>/scope:<scope-kind>:<scope-id>
```

Direct artifact operations authorize the exact artifact resource:

```text
agent-workspace:<namespace>/scope:<scope-kind>:<scope-id>/artifact:<artifact-id>
```

A successful workspace decision permits only the named operation against that exact
resource. It does not imply agent execution, inference, tool invocation, memory
access, delegation, approval, credential access, durable resume, reconciliation,
another workspace operation, native filesystem access, process execution, or network
access.

## Scope and isolation

The initial scope kinds are `run`, `agent`, and `principal`.

Scope identity is Phoenix-owned and derived from trusted runtime/configuration or
authenticated security context. Model content may propose artifact content or a
logical filename but cannot choose a foreign principal, agent, run, namespace, host
path, or authorization resource.

There is no implicit inheritance across scopes. A delegated child does not
automatically receive the parent's run, agent, or principal workspace.

Cross-scope copy or promotion requires an explicit server-owned transfer with
independent source and destination authorization; generic promotion is outside the
initial RFC-0031 public surface.

## Logical paths and host confinement

Phoenix logical paths are portable relative identifiers, not native filesystem paths.

The core canonicalizes and validates logical paths before authorization-sensitive
store access. Backing adapters receive a validated Phoenix representation and must
confine all physical operations beneath their configured root or provider namespace.

The local filesystem reference adapter must reject traversal, absolute paths,
drive/UNC/device forms, unsafe aliases, special files, link escapes, and inconsistent
case/normalization mappings. Native path details are never accepted as model authority
and are not exposed by normal public errors or operational telemetry.

## Authoritative store and mutation safety

The authoritative workspace store owns artifact identity, logical path, version,
digest, byte length, retention, provenance, and deletion/expiry state.

Writes are atomic from the logical API perspective. A new version becomes visible
only after its complete bytes and metadata have passed validation and authoritative
commit.

Concurrent writes and deletes use optimistic versions. Quota accounting is part of
the same logical mutation decision so races cannot exceed configured count or byte
limits through independent checks.

## Retention and deletion

Every configured workspace domain has finite per-artifact, artifact-count,
total-byte, retention, and expiry bounds.

Deleted IDs are not silently reused. Expired and deleted artifacts are absent from
reads, listings, context assembly, transfer continuation, snapshots, and recovery.

Cleanup is bounded Runtime-owned maintenance, not an unbounded hidden scheduler.

## Import and export

Import and export are explicit transfer operations behind a provider-neutral adapter.

An import source may identify an external object through a reviewed server-owned
adapter contract, but imported filenames, paths, metadata, media types, and bytes
remain untrusted. Import never creates network authority or credentials on its own.

Export requires separate `workspace.export` authority for the exact artifact and a
reviewed server-owned destination configuration. Artifact bytes cannot embed or
select privileged destination authority.

The core performs no implicit remote fetch, upload, archive extraction, or executable
content handling.

## Agent context integration

Artifacts may enter agent inference only through an explicit bounded
`ArtifactContextBlock` or another reviewed transformation.

Context preserves artifact identity, version, digest, media type, and provenance and
is labeled as untrusted artifact data. Binary content is not silently decoded into
text. Text decoding and context assembly remain bounded and cannot increase existing
agent/inference authority or budgets.

A stored instruction remains data. It cannot approve a tool, authorize a model,
change memory scope, select an import/export destination, or become a system message.

## Observability and safe failures

Operational events use Phoenix-owned event types and content-free metadata such as
workspace/artifact IDs, scope identifiers, versions, byte counts, status, expiry,
durations, transfer direction, and bounded reason codes.

Logs, metrics, health, audit, administration, and public errors do not expose
artifact content, native host paths, secrets, credentials, approval tokens, provider
bodies, or raw exceptions.

## Runtime lifecycle

`RuntimeAssembler` workspace composition is opt-in.

When configured, Runtime owns authoritative store/backing-adapter lifecycle, transfer
workers, cleanup/recovery tasks, finite queues, deadlines, cancellation, and
reverse-order shutdown.

Construction without workspace configuration creates none of these objects, roots,
workers, queues, transfer clients, cleanup tasks, or context attachments.

## Compatibility

When workspace configuration is omitted, no workspace store, backing adapter, local
root, transfer adapter, worker, cleanup task, recovery task, import/export path, or
artifact context injection is created.

Existing Phoenix OS v0.30.0 inference, agent, durable-agent, multi-agent, and memory
behavior remains unchanged.

## Slice plan

### Slice 0 - RFC foundation and executable specification

- [x] Draft RFC-0031 with explicit security invariants
- [x] Define exact workspace action/resource naming
- [x] Define logical-path and host-confinement principles
- [x] Define explicit import/export and untrusted-context boundaries
- [x] Establish compatibility-by-omission contract
- [x] Add RFC structure and regression tests

### Slice 1 - Contracts, scopes, paths, and authorization

- [x] Immutable workspace/artifact identifiers, versions, digests, provenance, retention, and limits
- [x] Canonical bounded Phoenix logical paths
- [x] Exact `workspace.*` constants and resources
- [x] Server-owned run, agent, and principal scope derivation
- [x] Independent current-policy authorization
- [x] Deterministic contract/path/authorization tests

### Slice 2 - Authoritative store, quotas, and mutation safety

- [ ] Reference authoritative workspace store
- [ ] Bounded artifact bytes, metadata, counts, and total quota
- [ ] Atomic writes and optimistic write/delete versions
- [ ] Retention, expiry, deletion, and ID anti-reuse behavior
- [ ] Provider-neutral backing adapter plus confined local reference adapter
- [ ] Persistence, path-escape, quota-race, and recovery tests

### Slice 3 - Transfers and agent context integration

- [ ] Explicit bounded import contract and service path
- [ ] Explicit bounded export contract and service path
- [ ] Independent source/destination transfer authorization
- [ ] Provenance-preserving untrusted `ArtifactContextBlock`
- [ ] Agent-loop opt-in artifact context integration without authority promotion
- [ ] Injection, binary-decoding, cross-scope, and transfer regressions

### Slice 4 - Recovery, observability, administration, and Runtime ownership

- [ ] Fail-closed startup/recovery for corrupt or inconsistent backing state
- [ ] Runtime-owned bounded cleanup, transfer workers, cancellation, and shutdown
- [ ] Content-free observer events and safe public errors
- [ ] Content-free bounded administration
- [ ] Restart recovery without deleted/expired artifact resurrection
- [ ] Runtime assembler ownership and disabled-by-default compatibility tests

### Slice 5 - Security review, migration, and release hardening

- [ ] Threat-model/security-invariant review
- [ ] ADRs for file authority, logical paths, authoritative stores, and transfer boundaries
- [ ] v0.30.0 to v0.31.0 migration guidance
- [ ] Named agent-workspace release gate
- [ ] Offline wheel/sdist validation
- [ ] Release notes and package version 0.31.0
- [ ] Tag, artifacts, and checksums

## Acceptance

RFC-0031 is complete when workspaces are opt-in and bounded, scope and logical paths
are Phoenix-owned, arbitrary host paths cannot become agent authority, every
workspace operation has fresh exact authorization, authoritative mutations are
atomic and quota-safe, link/special-file/path escapes fail closed, imports and
exports are explicit independently authorized transfers, artifact context remains
untrusted, deleted/expired artifacts do not resurrect across restart, operational
surfaces are content-free, Runtime owns finite lifecycle, and omitting workspace
configuration preserves Phoenix OS v0.30.0 behavior.
