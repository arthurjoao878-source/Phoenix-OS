# RFC-0031 agent-workspace threat-model and security-invariant review

- **Reviewed:** 2026-08-14
- **Release candidate:** Phoenix OS v0.31.0
- **Scope:** workspace identities, exact scopes, logical paths, authorization,
  authoritative persistence, backing confinement, atomic mutation, quota, retention,
  deletion, import/export, artifact context, recovery, cleanup, Runtime ownership,
  observability, administration, migration, and packaging boundaries
- **Result:** Accepted for the v0.31.0 agent-workspace release-candidate review;
  final release publication remains pending

## Review method

This review maps the RFC-0031 threat model and all seventy-one security invariants to
implementation boundaries and executable regression suites. Proposed artifact bytes,
logical paths, filenames, media types, metadata, provenance input, transfer
references, persisted records, backing objects, restored state, provider output, and
stored instructions are treated as untrusted until the relevant Phoenix-owned
boundary validates them.

A passing suite does not prove an installed model, tool, policy, storage, transfer,
parser, renderer, or other deployment adapter is benign. Installed adapters remain
trusted deployment code and must receive only authority explicitly granted by their
reviewed interface. RFC-0031 is not a hostile-code sandbox and grants no generic
operating-system capability.

The evidence classes are:

1. opt-in composition, stable Phoenix-owned identities, exact scopes, and fresh
   independent policy;
2. canonical bounded logical paths, opaque backing keys, host confinement, and
   special-object rejection;
3. explicit writes, authoritative versions/digests, atomic quota admission,
   retention, tombstones, and anti-resurrection recovery;
4. explicit independently authorized import/export and bounded provider-neutral
   transfer lifecycle;
5. bounded untrusted artifact context, content-free operations, Runtime-owned
   cleanup/recovery/shutdown, migration-by-omission, and later isolated package
   validation.

## Trust boundaries

### Untrusted

- proposed artifact bytes, names, logical paths, media types, and metadata;
- model-generated write, path, context, import, or export proposals;
- provenance input and historical approval/policy/credential-like text;
- transfer source/destination references and adapter output until validated;
- backing objects until exact type, confinement, identity association, and digest are
  validated;
- persisted records until strict schema, scope, identity, version, provenance,
  retention, and aggregate validation;
- restored snapshots, stale backing bytes, delayed transfer results, and stored prompt
  injection.

### Trusted but least-authority

- current reviewed Phoenix configuration and Runtime composition;
- Phoenix-owned `WorkspaceId`, `ArtifactId`, namespace, scope kind, and trusted scope
  derivation;
- current Policy Engine decisions and authenticated security contexts;
- authoritative workspace records after strict validation;
- Phoenix-owned canonical logical-path, version, digest, quota, retention, tombstone,
  and identity-ledger semantics;
- reviewed installed State Store, backing, transfer, policy, and other deployment
  adapters.

Files carry data, never authority. Provider or filesystem implementation details do
not become Phoenix authorization merely because they are installed.

## Threat review

| Threat | Required control | Evidence |
| --- | --- | --- |
| Enabling workspaces silently creates authority or state | Opt-in composition; no implicit grants, roots, artifacts, or workers | `test_agent_workspace_runtime_assembler.py`, `test_rfc_0031.py` |
| Model chooses a foreign workspace scope | Server-owned run/agent/principal derivation and exact resources | `test_agent_workspace_authorization.py`, `test_agent_workspace_context_integration.py` |
| Agent/model/tool/memory authority implies workspace access | Fresh independent `workspace.*` action/resource authorization | `test_agent_workspace_authorization.py` |
| Stored file text becomes policy, approval, credential, or tool authority | Artifact data remains untrusted; current policy wins | `test_agent_workspace_authorization.py`, `test_agent_workspace_context_integration.py` |
| Model-selected path escapes into the host filesystem | Canonical relative logical paths separated from opaque backing keys | `test_agent_workspace_contracts.py`, `test_agent_workspace_backing.py` |
| Link, reparse, hardlink, or special object escapes the root | Fail-closed local backing confinement and object validation | `test_agent_workspace_backing.py` |
| Concurrent writers bypass count/byte quota or path uniqueness | Atomic authoritative admission and deterministic collision checks | `test_agent_workspace_store.py` |
| Stale writer or delete overwrites newer state | Optimistic exact artifact versions | `test_agent_workspace_store.py`, `test_agent_workspace_service.py` |
| Partial/cancelled write becomes visible | Backing publication precedes authoritative visibility; failed admission cleans up | `test_agent_workspace_store.py`, `test_agent_workspace_backing.py` |
| Deleted or expired data returns after restart | Tombstones, identity anti-reuse, retention checks, bounded authoritative recovery | `test_agent_workspace_store.py`, `test_agent_workspace_recovery.py` |
| Backing corruption or substitution discloses bytes | Exact digest and authoritative metadata revalidation; sanitized fail-closed errors | `test_agent_workspace_backing.py`, `test_agent_workspace_store.py`, `test_agent_workspace_recovery.py` |
| Import or export becomes hidden network/filesystem authority | Explicit independent transfer authorization and provider-neutral bounded references | `test_agent_workspace_authorization.py`, `test_agent_workspace_transfer.py` |
| Transfer worker hangs or bypasses finite concurrency | Finite queues, workers, deadlines, settlement, cancellation, and shutdown | `test_agent_workspace_transfer_runtime.py`, `test_agent_workspace_runtime_assembler.py` |
| Binary/prompt-injection artifact is promoted to trusted model input | Bounded explicit untrusted USER context; binary decoding fails closed | `test_agent_workspace_context.py`, `test_agent_workspace_context_integration.py` |
| Cleanup/recovery/administration leaks content or hangs Runtime | Bounded Runtime ownership and content-free projections | `test_agent_workspace_cleanup_runtime.py`, `test_agent_workspace_recovery.py`, `test_agent_workspace_administration.py`, `test_agent_workspace_observer.py` |
| Upgrade changes v0.30 behavior without opt-in | Workspace composition absent by omission; no automatic reinterpretation | `test_agent_workspace_runtime_assembler.py`, `test_agent_workspace_migration_guidance.py` |
| Release docs claim security choices without executable specification | ADR, migration, RFC, and threat-review tests are part of the project suite | `test_agent_workspace_adrs.py`, `test_agent_workspace_migration_guidance.py`, `test_agent_workspace_security_review.py`, `test_rfc_0031.py` |

## Security-invariant review

### Invariants 1-9: opt-in workspace, stable identity, trusted scopes, and no host-path choice

**Result: satisfied.** Workspace composition is absent unless explicitly configured,
enabling it creates no artifact or external authority, logical workspaces and
artifacts use Phoenix-owned identities, supported scope kinds are finite, and
namespace/scope identity comes only from trusted configuration or authenticated
Phoenix context. Model content cannot widen scope or choose an arbitrary native host
path.

Evidence: `test_agent_workspace_contracts.py`,
`test_agent_workspace_authorization.py`, and
`test_agent_workspace_runtime_assembler.py`.

### Invariants 10-23: fresh exact independent authorization and files never carry authority

**Result: satisfied.** List, read, write, delete, import, export, and administration
use separate exact `workspace.*` actions. Collection resources bind exact namespace
and scope; direct artifact resources also bind `ArtifactId`. Current policy wins on
every operation. Agent, model, tool, delegation, resume, reconciliation, memory,
stored instructions, metadata, approvals, credentials, tokens, or prior grants
cannot substitute for current workspace authority. A workspace grants no generic
host-filesystem authority.

Evidence: `test_agent_workspace_authorization.py`,
`test_agent_workspace_service.py`, and
`test_agent_workspace_context_integration.py`.

### Invariants 24-32: canonical logical paths, confined backing, anti-reuse, and no implicit sharing

**Result: satisfied.** Logical paths are bounded canonical portable relative
identifiers, never native host paths. Traversal, absolute/drive/UNC/device and unsafe
forms are rejected; canonical aliases collide deterministically. Local backing uses
opaque keys beneath one configured root and rejects link/reparse/hardlink escape
objects. Artifact IDs cannot be reused to resurrect deleted state, and workspaces are
not implicitly shared across run, agent, principal, parent, or child scopes. RFC-0031
defines no global shared workspace.

Evidence: `test_agent_workspace_contracts.py`,
`test_agent_workspace_backing.py`,
`test_agent_workspace_store.py`, and
`test_agent_workspace_authorization.py`.

### Invariants 33-45: explicit writes, finite bounds, atomic mutation, retention, and bounded lifecycle

**Result: satisfied.** Phoenix has no automatic workspace capture path; writes are
explicit server-admitted operations. Artifact/path/metadata/provenance/count/byte
limits are finite. Quota and canonical-path admission are atomic under concurrency,
authoritative records carry explicit versions and canonical digests, and stale
write/delete versions fail. Backing publication does not expose partial authoritative
state. Deleted and expired artifacts are absent, retention is finite, and
Runtime-owned cleanup/recovery work has bounded records, concurrency, deadlines,
cancellation, and shutdown behavior.

Evidence: `test_agent_workspace_contracts.py`,
`test_agent_workspace_store.py`,
`test_agent_workspace_cleanup.py`,
`test_agent_workspace_cleanup_runtime.py`, and
`test_agent_workspace_recovery.py`.

### Invariants 46-57: provenance is descriptive, bytes do not execute, and transfers are explicit

**Result: satisfied.** Every admitted artifact carries bounded immutable provenance
whose origin and metadata remain descriptive rather than authoritative. Media types,
extensions, provider metadata, and external digests do not create execution
authority. Workspace storage performs no implicit script execution, archive
extraction, rendering, OCR, parsing, compilation, or remote fetch. Import and export
are explicit independently authorized server-mediated operations through
provider-neutral bounded adapters. Secrets are not automatically artifacts, and
normal prompts, memory, checkpoints, chain-of-thought, and hidden reasoning are not
automatically persisted.

Evidence: `test_agent_workspace_contracts.py`,
`test_agent_workspace_service.py`,
`test_agent_workspace_transfer.py`,
`test_agent_workspace_transfer_runtime.py`,
`test_agent_workspace_runtime_assembler.py`, and `test_rfc_0031.py`.

### Invariants 58-64: bounded untrusted context, prompt-injection resistance, and fail-closed recovery

**Result: satisfied.** Artifact context preserves reviewed provenance, has finite
item/byte/text-decoding bounds, and enters model input as explicitly untrusted USER
data rather than system policy. Binary artifacts are never silently decoded, and
stored prompt injection cannot grant model/tool/approval/delegation/memory/transfer
or operating-system authority. Unknown/corrupt/substituted/inconsistent authoritative
or backing state fails closed, and recovery does not resurrect deleted, expired,
wrong-scope, wrong-version, or digest-mismatched artifacts.

Evidence: `test_agent_workspace_context.py`,
`test_agent_workspace_context_integration.py`,
`test_agent_workspace_store.py`, and
`test_agent_workspace_recovery.py`.

### Invariants 65-71: content-free operations, provider-neutral boundaries, Runtime ownership, and compatibility

**Result: satisfied.** Observer events, recovery, public errors, and administration
use content-free bounded projections and sanitized reason/error surfaces. The local
reference backing is confined to a Phoenix-owned root, while backing and transfer
adapters remain optional and provider-neutral. Runtime owns backing, cleanup,
recovery, optional transfer workers, queues, cancellation, and reverse-order
shutdown. RFC-0031 grants no generic shell, process, browser, desktop, network,
host-filesystem, or operating-system authority. With workspace configuration omitted,
the complete workspace stack is absent and v0.30 behavior remains unchanged.

Evidence: `test_agent_workspace_backing.py`,
`test_agent_workspace_observer.py`,
`test_agent_workspace_administration.py`,
`test_agent_workspace_cleanup_runtime.py`,
`test_agent_workspace_transfer_runtime.py`, and
`test_agent_workspace_runtime_assembler.py`.

## Residual risks

- A malicious or defective installed model, tool, policy, State Store, backing,
  transfer, parser, renderer, or other deployment adapter can misuse authority
  explicitly granted to that deployment code. Process isolation and external-system
  permissions remain deployment responsibilities.
- Artifact content can still influence model behavior as untrusted context. Core
  authorization prevents authority promotion but cannot guarantee that a model
  semantically ignores every malicious instruction.
- Stable workspace/artifact IDs, scope categories, versions, counts, sizes, expiry
  categories, and timing can reveal operational traffic patterns even when artifact
  content and host paths are excluded.
- A configured external transfer adapter can send or receive data according to its
  deployment permissions. Provider privacy, data residency, remote authentication,
  and endpoint policy remain deployment responsibilities outside the provider-neutral
  core contract.
- The local reference backing protects the reviewed Phoenix-owned root but is not a
  hostile-process sandbox. Another host process with sufficient OS permissions can
  still tamper with files; Phoenix responds by validating type, confinement, metadata,
  and digest and failing closed.
- Restoring an old authoritative database together with old backing data can restore
  artifacts valid in that snapshot. Current policy, current scope configuration,
  expiry, tombstones, identity ledgers, versions, and digest validation must still win
  before disclosure.
- RFC-0031 intentionally does not provide arbitrary project-directory mounts, global
  shared workspaces, automatic artifact capture, automatic archive execution,
  transparent remote fetch, or generic OS filesystem/network authority. Adding any of
  those requires a separate RFC and security review.

## Release conclusion

The RFC-0031 threat model and all seventy-one security invariants are accepted for the
Phoenix OS v0.31.0 agent-workspace release-candidate review.

This review does not by itself publish v0.31.0. Final publication still requires
successful execution of `python scripts/check_agent_workspace_release.py`, the full
project quality gates, final RFC acceptance, release commit, tag, artifacts, and
checksums.
