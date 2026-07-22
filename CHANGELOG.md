# Changelog


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
