# Changelog

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
