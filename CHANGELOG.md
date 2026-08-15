# Changelog

## [0.31.0] - 2026-08-14

### Added
- Accepted RFC-0031 secure agent workspaces with Phoenix-owned run/agent/principal scopes and exact independent `workspace.list`, `workspace.read`, `workspace.write`, `workspace.delete`, `workspace.import`, `workspace.export`, and `workspace.admin` authority.
- Canonical bounded logical paths separated from opaque backing keys, with confined local reference backing and fail-closed traversal/link/special-object handling.
- Authoritative versioned/digested artifact records with immutable provenance, bounded count/byte quotas, atomic admission, optimistic mutation, finite retention, tombstones, and restart-safe anti-resurrection semantics.
- Explicit independently authorized bounded import/export adapters plus provenance-preserving untrusted `ArtifactContextBlock` agent integration.
- Agent-workspace migration guidance, four architecture records, formal threat review, release metadata, and isolated offline wheel/sdist validation.

### Security
- Files carry data, never authority; artifact content, names, metadata, provenance, historical approvals, credentials, grants, and policy-like text never reconstruct current authority.
- Logical paths remain Phoenix-owned relative identifiers and cannot select arbitrary native host paths; opaque backing identity remains separate from logical naming.
- Symlink, hardlink, reparse, traversal, FIFO, socket, device, and other special-object escapes fail closed in the local reference backing.
- Deleted, expired, wrong-scope, wrong-version, and digest-mismatched artifacts cannot resurrect through reads, context, transfer continuation, administration, or restart recovery.
- Workspaces expose no generic shell, process, browser, desktop, network, host-filesystem, or operating-system authority.

### Compatibility
- Phoenix OS 0.30.0 behavior is preserved when workspace configuration is omitted.
- Upgrade creates no artifact, workspace store, backing root, worker, transfer, permission, context attachment, host-directory mount, memory conversion, model call, tool call, delegation, or external access automatically.
- Release publication uses Git tag `v0.31.0`, wheel and sdist artifacts, and `SHA256SUMS`.


## [0.30.0] - 2026-08-12

### Added
- Accepted RFC-0030 secure agent memory with Phoenix-owned run/agent/principal scopes and exact independent `memory.search`, `memory.read`, `memory.write`, `memory.delete`, and `memory.admin` authority.
- Explicit bounded records with immutable provenance, optimistic versions, finite retention, expiry, tombstones, and authoritative anti-resurrection semantics.
- Deterministic bounded retrieval, source-record version/digest revalidation, and provenance-preserving untrusted `MemoryContextBlock` agent integration.
- Optional provider-neutral semantic retrieval with candidate-only derived indexes, bounded provider/recovery deadlines, and Runtime-owned cleanup/shutdown.
- Agent-memory migration guidance, four architecture records, formal threat review, release metadata, and isolated offline wheel/sdist validation.

### Security
- Memory informs work, never authority; remembered instructions, historical policy-like text, approvals, credentials, grants, and provenance never reconstruct current authority.
- Memory scope identity is Phoenix-owned, cross-scope substitution fails closed, and agents, principals, runs, parents, and children do not share memory implicitly.
- Normal conversations and hidden reasoning are not captured automatically; writes are explicit and sensitive material remains behind the secrets boundary.
- Stale, deleted, expired, wrong-version, and wrong-digest retrieval candidates are rejected against the authoritative source before disclosure.
- Memory exposes no generic shell, filesystem, network, browser, desktop, or operating-system authority.

### Compatibility
- Phoenix OS 0.29.0 behavior is preserved when memory configuration is omitted.
- Upgrade creates no record, memory store, index, provider call, worker, permission, context injection, model call, tool call, delegation, or external access automatically.
- Release publication uses Git tag `v0.30.0`, wheel and sdist artifacts, and `SHA256SUMS`.


## [0.29.0] - 2026-08-11

### Added
- Accepted RFC-0029 secure multi-agent coordination with reviewed registered-child delegation and exact `agent.delegate` authority.
- Phoenix-owned delegation lineage, stable `DelegationId` child identity, bounded result aggregation, parent cancellation, and finite Runtime lifecycle.
- Monotonic root budget, total-child, fan-out, concurrency, queue, deadline, input/result, and aggregation limits.
- Durable delegation linkage with restart-safe lifetime accounting, exclusive recovery claims, indeterminate running-child reconciliation, and SQLite reference persistence.
- Multi-agent migration guidance, four architecture records, formal threat review, release metadata, and isolated offline wheel/sdist validation.

### Security
- Delegation creates work, never authority; parent permissions, approvals, credentials, model grants, tool grants, and policy decisions are never copied to a child.
- Child admission uses current server-owned registration and current policy, while child results remain untrusted data.
- Completing children does not restore lifetime root budget or child capacity, and restart does not reset those reservations.
- One delegation binds to one child run; unknown running work becomes indeterminate and is never replayed automatically.
- Coordination exposes no generic shell, filesystem, network, browser, desktop, or operating-system authority.

### Compatibility
- Phoenix OS 0.28.0 behavior is preserved when coordination configuration is omitted.
- Upgrade creates no delegation, child, worker, store, permission, approval, credential, model call, tool call, or external access automatically.
- Release publication uses Git tag `v0.29.0`, wheel and sdist artifacts, and `SHA256SUMS`.


## [0.28.0] - 2026-08-10

### Added
- Accepted RFC-0028 durable agent runs, checkpoints, controlled recovery, and the five durable-agent architecture records.
- Canonical chained checkpoints, atomic reference stores, fenced leases, deterministic recovery, and bounded workers.
- Explicit execution-attempt and reconciliation records for indeterminate external work without transparent retry or exactly-once claims.
- Optional protected payload persistence, bounded retention, cleanup, tombstones, content-free observation, safe administration, and Runtime composition.
- Durable-agent migration guidance, threat review, release metadata, and wheel/sdist isolated offline package validation.

### Security
- Durable-agent execution remains disabled unless explicitly configured, and checkpoints remain data rather than authority.
- Resume, model, tool, approval, reconciliation, lease, fencing, and compatibility decisions are revalidated against current state.
- Stale workers cannot mutate after fencing changes; malformed, rolled-back, substituted, unsupported, or non-canonical checkpoints fail closed.
- Indeterminate model or tool attempts are never retried automatically, and Phoenix does not claim exactly-once external side effects.
- Protected payloads are absent by default and, when enabled, remain bounded, authenticated, versioned, retention-limited, and excluded from safe output.

### Compatibility
- Phoenix OS 0.27.0 behavior is preserved when durable-agent configuration is omitted.
- Ordinary RFC-0027 agent execution and RFC-0026 inference remain independently configurable.
- Release publication uses Git tag `v0.28.0`, wheel and sdist artifacts, and `SHA256SUMS`.


## [0.27.0] - 2026-07-29

### Added
- Accepted RFC-0027 and the five secure-agent architecture records.
- Immutable agent, tool proposal, invocation, result, strict schema, limit, and safe error contracts.
- Server-owned reviewed tool registration with exact resource resolvers and deterministic fake adapters.
- Independent `agent.run`, per-turn `model.infer`, and per-call `tool.invoke` authorization.
- Action-bound, actor-bound, short-lived, single-use approval evidence for sensitive effects.
- Deterministic serial agent execution with finite budgets, cancellation, shutdown, and no transparent retry.
- Optional Runtime composition, content-free observability, safe administration, migration, threat review, and isolated package gate.

### Security
- Agent execution remains disabled by default with no implicit tool, permission, approval, run, worker, listener, network, filesystem, shell, or operating-system authority.
- Model output and tool results remain untrusted data; policy resources are resolved only by trusted server-side code after strict validation.
- Approvals are bound to the exact normalized invocation and fail closed after mutation, replay, expiry, denial, cancellation, or consumption.
- Prompts, model responses, raw arguments, tool results, credentials, secret references, approval evidence, endpoint details, and raw exceptions remain absent from safe output.
- Model and tool execution are never retried transparently, and ambiguous external failures are not automatically repeated.

### Compatibility
- Phoenix OS 0.26.0 behavior is preserved when agent configuration is omitted.
- RFC-0026 inference remains independently configurable, and existing principals or service accounts gain no agent or tool authority automatically.


## [0.26.0] - 2026-07-27

### Added
- Accepted RFC-0026 and the five secure-inference architecture records.
- Provider-neutral immutable inference contracts and a reviewed provider/model registry.
- Exact `model.infer` authorization for concrete provider-model resources.
- Exact versioned credential leases and fail-closed hosted or loopback endpoint policy.
- Bounded complete execution, ordered streaming, cancellation, admission, and no-transparent-retry semantics.
- Optional Runtime composition, content-free diagnostics, safe lifecycle events, and bounded shutdown.
- Maintainer Dashboard, scoped machine administration, migration guidance, release notes, and an isolated offline packaging and security gate.

### Security
- Inference remains disabled by default with no implicit provider, model, credential, endpoint, grant, listener, or network authority.
- Model output remains untrusted data and receives no implicit capability, command, job, workflow, plugin, filesystem, shell, network, or operating-system authority.
- Credentials, prompts, responses, endpoint details, streaming frames, and raw provider failures remain excluded from safe output.
- Hosted endpoints require verified HTTPS, complete DNS admission, pinned destinations, disabled redirects and ambient proxies, and finite limits.
- Invocation, human administration, and machine administration require independent exact permissions.

### Compatibility
- Phoenix OS 0.25.0 behavior is preserved when inference configuration is omitted.
- Existing service accounts gain no inference grants, and no provider, model, endpoint, credential, request, or network permission is created automatically.


## [0.25.0] - 2026-07-25

### Added
- Accepted RFC-0025 and the five secure-inbound architecture records.
- Reviewed schema allowlisting and deterministic external-event normalization.
- Per-source versioned HMAC-SHA-256 or RFC-0023 service-account authentication.
- Atomic durable replay, source-event idempotency, accepted events, and stable receipts.
- Exact active-source ingress routes on the shared Control Plane listener.
- Bounded asynchronous publication, recovery, dead letter, and explicit redrive.
- Maintainer Dashboard, scoped machine administration, and Runtime lifecycle ownership.
- Migration guidance, release notes, and an isolated offline packaging and security gate.

### Security
- Inbound events remain disabled by default with no implicit source, route, credential, repository, worker, grant, or network authority.
- Raw request bodies never become unrestricted Event Bus payloads or the persisted trusted contract.
- Authentication modes are mutually exclusive, replay evidence survives restart, and public failures remain generic.
- Disabled and revoked sources have no active route; every request remains bounded by listener, source, and global admission controls.
- Source submission, human administration, and machine administration require independent exact permissions.

### Compatibility
- Phoenix OS 0.24.0 behavior is preserved when inbound configuration is omitted.
- Existing webhooks are not converted, service accounts gain no inbound grants, and no ingress or persistence state is created automatically.


## [0.24.0] - 2026-07-24

### Added
- Accepted RFC-0024 and the five durable-webhook architecture records.
- Reviewed event serializers, canonical envelopes, and stable deduplication.
- Versioned HMAC-SHA-256 signing through exact leased secret references.
- Durable repositories with recovery-safe retry and dead-letter history.
- Bounded dispatch, concurrency, interrupted recovery, and explicit redrive.
- Maintainer Dashboard, scoped service-account routes, and Runtime ownership.
- Migration guidance, release notes, and a wheel, sdist, isolated-install, SSRF, replay, and compatibility gate.

### Security
- Webhooks remain disabled by default with no implicit export or egress authority.
- Every attempt revalidates DNS, rejects DNS rebinding and disallowed addresses, pins the admitted address, and never follows redirects.
- Secrets, signatures, canonical bodies, endpoint paths, raw responses, and internal exceptions remain excluded from safe views.
- Machine administration requires exact scopes, a resource grant, replay protection, and deny-by-default policy.

### Compatibility
- Phoenix OS 0.23.0 behavior is preserved when webhook configuration is omitted.
- Existing subscribers, jobs, credentials, endpoints, and outbound permissions are not converted or created automatically.



## [0.23.0] - 2026-07-21

### Added
- Accepted RFC-0023 and ADR-0046/0047.
- Durable service accounts with active, disabled, revoked, and expired lifecycle states.
- One-time API-token issuance, mandatory expiration, bounded rotation overlap, and revocation.
- Protected digest persistence with strict decoding and corruption detection.
- Exact action scopes, resource restrictions, and deny-by-default Policy Engine integration.
- Optional client-CIDR and mutual-TLS identity binding with replay-resistant request evidence.
- Independent client and account throttling, protected audit facts, and safe health metrics.
- Maintainer routes, Dashboard administration, machine routes, and RuntimeAssembler ownership.


## [0.22.0] - 2026-07-19

### Added
- Accepted RFC-0022 and ADR-0044/0045.
- Opt-in loopback or remote exposure policies with exact public-origin binding.
- Native server TLS, optional mutual TLS, certificate health, and atomic reload.
- Strict Host, Origin, direct-client, trusted-proxy, and client-CIDR validation.
- Per-client connection/request bounds and independent client/operator login throttling.
- Secure HttpOnly cookies, public-origin CSRF, and HTTPS-compatible packaged Dashboard assets.
- HMAC-protected remote address audit facts without raw addresses or proxy chains.
- RuntimeAssembler lifecycle ownership and safe combined listener-health snapshots.


## [0.21.0] - 2026-07-19

### Added
- Accepted RFC-0021 and ADR-0042/0043.
- State Store-backed durable operator sessions with checksum and index corruption detection.
- Absolute/idle expiry, atomic token and CSRF rotation, replay-resistant lineage, and restart recovery.
- Authenticated session history, exact operator/status filters, and terminal-only bounded retention.
- HttpOnly SameSite=Strict Dashboard cookies with no browser-readable session bearer.
- Session-bound rotating CSRF and action-specific recent step-up authentication.
- Dashboard session inspection, individual termination, and global operator-session revocation.
- RuntimeAssembler persistence selection and lifecycle ownership for access, recovery, retention, and HTTP.


## [0.20.0] - 2026-07-19

### Added
- Accepted RFC-0020 and ADR-0040/0041.
- Identified local operators with Viewer, Operator, and Maintainer roles.
- Bounded in-memory and State Store-backed operator registries with protected digest indexes.
- Constant-time authentication, generic failures, rotation, disablement, reactivation, and revocation.
- Temporary expiring sessions, bounded login throttling, logout, and administrative session revocation.
- Strict CSRF-protected operator management HTTP routes and allowlisted serializers.
- Dashboard operator administration and operator-filtered durable command history.
- RuntimeAssembler registry selection, bootstrap maintainer, lifecycle ownership, and exact journal attribution.


## [0.19.0] - 2026-07-19

### Added
- Accepted RFC-0019 and ADR-0038/0039.
- Payload-free versioned command journal contracts and bounded repositories.
- State Store persistence with canonical checksums, strict decoding, and corruption detection.
- Restart-safe journal-backed idempotency and terminal receipts.
- Bounded interrupted-command recovery with deterministic side-effect probes.
- Authenticated paginated command history and allowlisted Dashboard presentation.
- Terminal-only age/count retention with optimistic revision fencing.
- RuntimeAssembler ownership of journal, recovery, retention, history, and HTTP lifecycle.


## [0.18.0] - 2026-07-19

### Added
- Accepted RFC-0018 and ADR-0036/0037.
- Exact per-action Dashboard command permissions and operation availability discovery.
- SHA-256-bound idempotency with safe replay, terminal-only eviction, and deterministic command IDs.
- Origin-bound HMAC CSRF tokens and one-time HMAC confirmation proofs for destructive actions.
- Safe job creation, cancellation, dead-letter retry, and workflow cancellation handlers.
- Bounded authenticated POST transport with strict JSON schemas and command concurrency limits.
- Payload-free command events, Security Journal categorization, and allowlisted receipts.
- Dashboard job creation, cancellation, retry controls, release documentation, and v0.18.0 packaging.

## [0.17.0] - 2026-07-18

### Added
- Accepted RFC-0017 and ADR-0034/0035.
- Versioned allowlisted control-plane snapshots and safe aggregate health.
- SHA-256 administrator-token authentication with constant-time comparison.
- Loopback-only bounded HTTP/1.1 read API with authenticated operational routes.
- Paginated job, workflow, capability, plugin, and audit read models.
- Bounded cursor-based Event Bus long polling with retention gaps and backpressure.
- Packaged dependency-free dashboard assets with strict browser security headers.
- RuntimeAssembler ownership, public API, executable example, migration guidance, and regression tests.

## [0.16.0] - 2026-07-18

### Added
- Accepted RFC-0016 and ADR-0032/0033.
- Immutable workflow definitions, steps, records, statuses, plans, repositories, and worker contracts.
- Deterministic DAG validation, cycle rejection, declaration-ordered topological planning, fan-out, and fan-in.
- In-memory and State Store-backed persistence with optimistic revisions and restart recovery.
- Job-backed orchestration with stable UUIDv5 step jobs, retry reconciliation, failure propagation, and cancellation.
- Runtime-owned workflow reconciliation, safe Event Bus facts, and Audit Ledger workflow categorization.
- Public API, migration guidance, executable example, validation notes, and regression tests.

## [0.15.0] - 2026-07-18

### Added
- Accepted RFC-0015 and ADR-0030/0031.
- Immutable durable-job, schedule, retry, lease, run, worker, repository, and snapshot contracts.
- Capability-only one-time and fixed-interval execution with deterministic bounded ticks.
- Atomic lease fencing, stale-result rejection, retries, cancellation, and dead-letter transitions.
- In-memory and State Store-backed repositories with restart and expired-lease recovery.
- Runtime-owned bounded worker lifecycle, safe Event Bus facts, and Audit Ledger job categorization.
- Public API, migration guidance, executable example, validation notes, and regression tests.

## [0.14.0] - 2026-07-18

### Added
- Accepted RFC-0014 and ADR-0028/0029.
- Canonical UTF-8 NDJSON audit archive segments with deterministic optional gzip.
- Dual payload/artifact SHA-256 digests and chained immutable manifests.
- Exact-range export, bounded rotation, atomic publication, and overwrite refusal.
- Individual archive and complete cross-segment verification with optional seal checks.
- Non-destructive retention plans with age, newest-count, and protected-archive constraints.
- Exact digest confirmation, current-chain validation, stale-plan checks, and prefix-only deletion.
- Audit archival example, migration guidance, validation notes, and regression tests.

## [0.13.0] - 2026-07-18

### Added
- Accepted RFC-0013 and ADR-0026/0027.
- Durable standard-library `SQLiteAuditStore` with WAL and full synchronous commits.
- Atomic append transactions that persist records and chain-head metadata together.
- Versioned schema validation and fail-closed recovery verification before append.
- SQL append-only guards for update, delete, sequence continuity, and previous-digest linkage.
- Persistent bounded audit queries, optional signature recovery, and forensic reads after close.
- Runtime lifecycle recovery integration, durable example, migration guidance, and regression tests.

## [0.12.0] - 2026-07-18

### Added
- Accepted RFC-0012 and ADR-0024/0025.
- Immutable redacted audit events, records, seals, queries, verification reports, and snapshots.
- Deterministic canonical JSON and SHA-256 previous-digest chaining with a fixed genesis digest.
- Optional provider-neutral external signatures through `AuditSigner` and `KeyRef`.
- Append-only `AuditStore` boundary and deterministic `InMemoryAuditStore`.
- Authenticated deny-by-default `audit.read` and `audit.verify` Policy Engine integration.
- Event Bus `SecurityJournal` mapping with category, outcome, severity, correlation, and recursion prevention.
- Safe audit events, logs, metrics, RuntimeAssembler ownership, Nova migration guidance, and example.

## [0.11.0] - 2026-07-18

### Added
- Accepted RFC-0011 and ADR-0022/0023.
- Immutable secret, key-reference, metadata, lease, store, and snapshot contracts.
- Identity-required, deny-by-default `SecretsManager` with Policy Engine integration.
- Immutable version creation, rotation ancestry, exact lookup, latest-active lookup, and revocation.
- Principal-bound bounded leases with expiry, explicit revocation, purge, and secret-revocation invalidation.
- Deterministic process-local `InMemorySecretStore` for tests and ephemeral deployments.
- Provider-neutral `SecretStore` and `SecretProtector` boundaries with explicit `KeyRef` metadata.
- Typed Configuration secret-reference decoder and on-demand lease resolver.
- Event Bus, Observability, and RuntimeAssembler integration without material disclosure.
- Nova 3.x secrets migration guidance and executable example.

## [0.10.0] - 2026-07-18

### Added
- Accepted RFC-0010 and ADR-0020/0021.
- Immutable redacted credential, identity, session, grant, repository, registration, and snapshot contracts.
- Explicit synchronous/asynchronous authentication provider registry with safe rejection and failure handling.
- Opaque high-entropy bearer sessions with persisted SHA-256 digests only.
- Absolute and idle expiry, touch intervals, per-identity limits, revocation, and identity-wide logout.
- In-memory and State Store-backed session repositories.
- Session-derived Security, Capability, and State contexts plus task-local propagation.
- Authenticated Kernel adapter and optional Identity lifecycle ownership in `RuntimeAssembler`.
- Correlated events, logs, metrics, and spans without credential or bearer export.
- Nova 3.x identity migration guidance and executable example.

## [0.9.0] - 2026-07-17

### Added
- Accepted RFC-0009 and ADR-0018/0019.
- Immutable security contexts, policy requests, rules, decisions, registrations, and snapshots.
- Deterministic deny-by-default Policy Engine with explicit priority and restriction precedence.
- Explainable allow, deny, and confirmation outcomes with structured enforcement errors.
- Capability permission and confirmation adapters backed by central policy.
- Policy-protected State Store operations and transactions.
- Policy-protected plugin setup and startup while preserving unconditional cleanup.
- Event Bus and Observability decision signals without exporting permissions, scopes, or request attributes.
- Optional Policy Engine service and lifecycle ownership in `RuntimeAssembler`.
- Nova 3.x security migration guidance and executable example.

## [0.8.0] - 2026-07-17

### Added
- Accepted RFC-0008 and ADR-0016/0017.
- Immutable plugin manifests, semantic versions, version ranges, dependencies, exports, and snapshots.
- Deterministic dependency resolution, lifecycle ordering, startup rollback, and aggregate shutdown.
- Least-authority Plugin SDK for declared capabilities, state stores, and plugin-owned services.
- Explicit host permission approval and exact export-name enforcement.
- Side-effect-free entry-point discovery with explicit allowlisted loading.
- Synchronous/asynchronous `HookPlugin` adapter for Nova 3.x migration.
- Event Bus and Observability lifecycle signals, spans, logs, and metrics.
- Optional Plugin Manager composition and lifecycle ownership in `RuntimeAssembler`.

## [0.7.0] - 2026-07-17

### Fixed
- Parameterized `StateKey[T]` and `StateRecord[T]` construction on Python 3.12 when using frozen slotted dataclasses.

### Added
- Accepted RFC-0007 and ADR-0014/0015.
- Typed namespaced state keys, immutable records, snapshots, contexts, and statistics.
- Deterministic safe JSON codec with explicit `SecretValue` rejection.
- In-memory State Store with optimistic versions, TTL, deterministic listing, and lifecycle hooks.
- Serializable atomic transactions with automatic rollback and competing-writer serialization.
- Replace and merge snapshot restoration with fresh live versions.
- Named State Store Registry with deterministic startup and reverse shutdown.
- Correlated Event Bus facts, structured diagnostics, spans, and operation metrics.
- Optional State service ownership in `RuntimeAssembler`.
- Nova 3.x state and persistence migration guidance and executable example.

## [0.6.0] - 2026-07-17

### Added
- Accepted RFC-0006 and ADR-0012/0013.
- Immutable structured log, metric, span, registration, export-report, and snapshot contracts.
- Deterministic synchronous and asynchronous sink delivery with explicit failure policies.
- Recursive structured redaction with conventional secret-key and `SecretValue` protection.
- Asynchronous nested span context with trace, parent, correlation, and causation propagation.
- Event Bus wildcard observer with severity mapping and redacted event attributes.
- Bounded `InMemorySink` for tests and local diagnostics.
- Optional observability ownership and event bridge in `RuntimeAssembler`.
- Nova 3.x observability migration guidance and executable example.

## [0.5.0] - 2026-07-17

### Added
- Accepted RFC-0005 and ADR-0010/0011.
- Immutable configuration schemas, fields, origins, resolved values, and secret wrappers.
- Strict decoders, validators, source precedence, provenance, and unknown-key policy.
- Mapping, JSON file, and environment configuration sources.
- Deterministic asynchronous singleton dependency composition.
- Missing-dependency and cycle detection before Runtime startup.
- Lifecycle-service adaptation and `RuntimeAssembler` integration.
- Nova 3.x configuration and service-composition migration guidance.

## [0.4.0] - 2026-07-17

### Added
- Accepted RFC-0004 and ADR-0008/0009.
- One-shot Phoenix Runtime composition root and immutable named services.
- Deterministic component startup, reverse shutdown, and startup rollback.
- Graceful request rejection and draining during shutdown.
- Retryable aggregate shutdown failures with active-component snapshots.
- Lifecycle deadlines, cancellation propagation, and async context management.
- Correlated Runtime lifecycle events and final core-service ownership.
- Nova 3.x lifecycle-component migration guidance and Runtime example.

## [0.3.0] - 2026-07-17

### Added
- Accepted RFC-0003 and ADR-0006/0007.
- Immutable capability descriptors, contexts, invocations, results, and registrations.
- Deterministic Capability Registry with discovery and safe unregistration.
- Default required-permissions and descriptor-confirmation policies.
- Synchronous and asynchronous provider support with deadlines and cancellation.
- Safe policy/provider error translation and registry lifecycle management.
- Correlated capability lifecycle events through the Event Bus.
- `CapabilityHandler` adapter for Kernel integration without Kernel coupling.
- Nova 3.x provider migration guidance and capability example.

## [0.2.0] - 2026-07-17

### Added
- Accepted RFC-0002 and ADR-0004/0005.
- Deterministic asynchronous in-process Event Bus.
- Immutable event, subscription, dispatch, and failure contracts.
- Exact and wildcard subscriptions, priorities, one-shot handlers, safe unsubscription.
- Failure collection and strict aggregate-error policy.
- Kernel lifecycle integration through the Event Bus.
- Event Bus and Kernel examples and expanded test suite.

## [0.1.0] - 2026-07-17

### Added
- Repository bootstrap, MIT license, governance, Python 3.12 tooling and CI.
- Accepted RFC-0001 and ADR-0001 through ADR-0003.
- First asynchronous headless Phoenix Kernel.
