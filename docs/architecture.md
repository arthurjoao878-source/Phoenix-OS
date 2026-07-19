# Architecture

```text
 mapping / JSON / environment
              |
              v
     ConfigLoader + Schema
 decode | validate | redact | provenance
              |
              v
      ServiceComposer graph
 explicit dependencies | cycle detection
              |
              v
         RuntimeAssembler
              |
              v
         Phoenix Runtime
 composition | lifecycle | request drain
              |
              v
          Policy Engine
 identity | rules | explainable decisions
       |          |                 |
       |          |                 +-----------------------------+
       |          v                                               v
       |     Phoenix Kernel                                  Event Bus
       | routing | authorization                  lifecycle and request facts
       |          |                                  |                  |
       |          v                                  v                  v
       |   CapabilityHandler                    EventObserver     SecurityJournal
       |          |                                  |                  |
       |          v                                  v                  v
       | Capability Registry                 Observability Hub      Audit Ledger
       | permission | confirmation       logs | metrics | spans   chain | verify
       |          |                                  |                  |
       |          v                                  v                  v
       | capability providers                 external sinks    AuditStore protocol
       |                                                     memory | SQLite | external
       |                                                            + AuditSigner
       v
 State Store Registry
 named stores | lifecycle
       |
       v
 State Store protocol
 versions | TTL | transactions | snapshots
       |
       +----> MemoryStateStore
       +----> external durable adapters
```

`ConfigLoader` resolves raw deployment values before Runtime construction. Its immutable schema
performs strict decoding and validation, records the winning source for every value, and wraps
secrets so ordinary inspection remains redacted.

`ServiceComposer` builds named singleton dependencies from explicit declarations. It detects
missing dependencies and cycles before startup. `RuntimeAssembler` exposes Kernel, Event Bus,
Capability Registry, resolved configuration, and optional Observability, Audit, Policy, State, Identity, Secrets, Jobs, Workflows, Plugins, and local Control Plane services to
factories, then creates `PhoenixRuntime` with composed services and lifecycle components.

`PhoenixRuntime` remains the lifecycle owner. It owns the Kernel, Event Bus, Capability Registry,
external lifecycle components, immutable named services, request admission, graceful draining, and
ordered shutdown. Configuration and service factories finish before the Runtime enters `STARTING`.

Commands enter through `PhoenixRuntime.handle()`, which accepts work only while the Runtime is
running and delegates admitted requests to `Kernel.handle()`. A `CapabilityHandler` is registered as
an ordinary route handler. The Kernel does not import the Capability Registry, Configuration,
Observability, Audit, Identity, Secrets, or State subsystems.

`StateStoreRegistry` resolves one or more named stores. Consumers depend on the asynchronous
`StateStore` protocol rather than a database vendor. The reference `MemoryStateStore` supplies safe
JSON serialization, typed namespaced keys, optimistic versions, TTL, serializable transactions, and
logical snapshots. Durable databases and their connection, migration, encryption, and retry policies
remain external adapters.

Events report immutable facts and lifecycle transitions; they are not a command channel.
`EventObserver` may translate those facts into structured diagnostics. `SecurityJournal` may map
non-audit facts into redacted append-only records, but it ignores `audit.*` events and never publishes
commands or alters Event Bus dispatch. State operations may emit safe key/version facts and create
spans, but never include persisted values automatically.

Lifecycle components start in resolved order and stop in reverse order. With observability and
audit, the hub and Event Observer start first, followed by the Audit Ledger and Security Journal,
before Policy, State, Identity, Secrets, custom services, and Plugins. Shutdown therefore closes State
before the observer unsubscribes and the hub closes. The Runtime then closes the Capability Registry
and Event Bus.

Remote brokers, remote or distributed database implementations, replication, cross-service
transactions, hosted job queues, distributed scheduling consensus, metric aggregation, telemetry
vendor protocols, AI, semantic memory,
credential stores, sandboxing, operating-system automation, remote configuration, hot reload, hosted administration, and remote UI delivery remain external adapters.
The package includes only a loopback, read-only dashboard and the local SQLite audit backend as
reference implementations.


## Audit Ledger and Security Journal

`AuditLedger` accepts immutable `AuditEvent` facts whose structured details are recursively redacted
before persistence. `AuditStore` implementations atomically assign positive sequences. Each
`AuditRecord` hashes deterministic UTF-8 JSON containing the complete redacted event, sequence,
recording time, and previous digest. The first record references a fixed all-zero genesis digest.

`InMemoryAuditStore` provides deterministic process-local append for tests and ephemeral services.
`SQLiteAuditStore` provides a durable local reference adapter with a versioned schema, WAL, full
synchronous commits, atomic record/head transactions, append-only SQL guards, and complete-chain
verification before resume. `AuditSigner` receives only record digests and provider-neutral `KeyRef`
metadata; raw signing keys and concrete algorithms remain external. An unsigned chain detects
mutation, reordering, and gaps when verified, but it is not independently tamper-proof and cannot
independently detect replacement with an older internally valid database.

Historical `audit.read` and `audit.verify` operations require authenticated `SecurityContext` values
and central Policy Engine authorization or exact fallback permissions. Trusted append avoids
authorization recursion and does not imply isolation from hostile code already running in-process.

`SecurityJournal` subscribes to Event Bus facts, derives stable categories, outcomes, severity,
actors, actions, and resources, preserves correlation, and appends redacted records. It ignores
`audit.*` events at the observer boundary even when a custom mapper is supplied. Runtime shutdown
keeps the journal and ledger alive while later security services stop, then closes the journal before
the ledger and Event Bus.

`AuditArchiveManager` reads exact contiguous ranges through the provider-neutral `AuditStore`
boundary. It publishes canonical NDJSON payloads and immutable manifests with payload, artifact,
record-head, and prior-manifest digests. Rotation exports not-yet-archived history in bounded
segments without mutating the live ledger. Retention is split into a non-destructive plan and a
separate exact-digest-confirmed apply step; only an oldest contiguous prefix can be selected.
Retained suffixes preserve explicit external anchors. WORM, object lock, remote replication,
encryption at rest, and independent timestamping remain deployment or external-adapter concerns.

## Durable Jobs and Workflow Scheduling

`JobScheduler` persists immutable capability-backed job records through the `JobRepository` protocol.
Due work is claimed atomically with bounded opaque fencing leases. Completion and failure require the
exact active lease, so cancelled, expired, or replaced workers cannot overwrite newer repository
state. `InMemoryJobRepository` is process-local; `StateJobRepository` uses serializable State Store
transactions and a versioned JSON-safe schema for restart recovery.

`run_due()` remains an explicit bounded tick. `JobWorker` is a separate one-shot Runtime lifecycle
adapter with explicit polling, batching, worker identity, and lease limits. Runtime assembly starts it
after plugins so exported capabilities are ready, and reverse shutdown stops jobs before plugins and
borrowed State Stores. Job Event Bus payloads exclude arguments, outputs, and exception messages; the
Security Journal maps them to the dedicated audit job category.

Lease fencing protects repository transitions, not external side effects. Capability providers should
use idempotency keys or tolerate at-least-once execution. Cron parsing, arbitrary code, shell commands,
distributed consensus, hosted queues, and exactly-once effects remain outside the core.


## Policy Engine and Security Context

`PolicyEngine` centralizes authorization questions from subsystem adapters. Immutable
`SecurityContext` values carry trusted principal, role, permission, scope, correlation, and
confirmation facts. Declarative rules match normalized actions and resources with explicit priority.
No match means deny. At equal priority, deny precedes confirmation and confirmation precedes allow.

`PolicyPermissionPolicy` and `PolicyConfirmationPolicy` protect capabilities. `PolicyStateStore`
decorates any State Store, including transactions. `PolicyProtectedPlugin` authorizes plugin setup and
startup but never blocks cleanup. The Runtime may own the engine as the named `policy` service. The
Kernel does not import or depend on policy internals.

The Policy Engine is not an identity provider, credential verifier, secret store, or sandbox. Hosts
must construct security contexts from authenticated and trusted deployment inputs.

## Plugin System and Adapter SDK

`PluginManager` is the extension composition boundary. It validates immutable manifests, Phoenix and
Plugin API compatibility, requested permissions, declared exports, and dependency graphs before any
plugin setup hook runs. Setup and startup follow deterministic dependency order; rollback and shutdown
reverse it.

Plugins receive a restricted `PluginRegistrar`, not mutable access to Runtime internals. The registrar
can contribute only manifest-declared capabilities, named state stores, and plugin-owned services for
which the host approved the corresponding permission. Plugin services remain behind
`PluginManager.service()` so Runtime's frozen service mapping does not change after assembly.

Entry-point discovery returns metadata without imports. Loading requires an explicit deployment
allowlist. Loaded Python code still executes with normal process authority; untrusted plugins require
external process isolation.

With full assembly, lifecycle order is Observability, Event Observer, Policy, State, Identity, composed
lifecycle services, and Plugins. Reverse shutdown stops plugins while host services and diagnostics remain
available, then closes state, observation, capabilities, and events through existing owners.


## Identity, Authentication, and Sessions

`AuthenticationManager` is the trusted bridge from provider-specific credentials to immutable
`Identity` and `Session` values. Providers remain external adapters; the core does not implement
password databases, OAuth, OIDC, LDAP, SAML, passkeys, or operating-system authentication.

New sessions return an opaque bearer inside `SecretValue`. Only a SHA-256 digest is retained by
`SessionRepository`. `InMemorySessionRepository` supports ephemeral execution and
`StateSessionRepository` persists JSON-safe records through the existing State Store boundary.
Absolute expiry, idle expiry, touch intervals, session limits, revocation, and identity-wide
revocation are owned by the manager.

A resolved session derives the central `SecurityContext`. `session_scope()` propagates it with
`contextvars`; adapters translate the same trusted facts to Kernel, Capability, and State boundaries.
The Policy Engine continues to decide authorization and never validates credentials itself.

Runtime assembly starts State before Identity and stops Identity before State. Plugins stop first, so
cleanup remains possible while identity and persistence services are available.

## Secrets Vault and Key Management

`SecretsManager` is the authenticated and authorized boundary for secret creation, rotation,
metadata lookup, temporary material access, and revocation. Names are carried as immutable
`SecretRef` values; external wrapping keys are identified only by `KeyRef`. Neither reference
contains sensitive material.

Every manager operation requires an authenticated `SecurityContext`. The Policy Engine evaluates
normalized `secret.*` actions and `secret:<namespace>/<name>` resources. When no engine is supplied,
explicit context permissions remain deny-by-default.

Material leaves a store only inside a bounded `SecretLease` whose `SecretValue` is redacted by
default. Leases belong to one principal, expire, may be revoked, and are invalidated when their exact
secret version is revoked. Runtime shutdown clears lease memory before the store closes.

`InMemorySecretStore` is deterministic, non-durable, and not encrypted at rest. Production vaults,
HSMs, cloud KMS, operating-system keyrings, envelope encryption, provider authentication, retries,
and disaster recovery remain behind external `SecretStore` and `SecretProtector` implementations.
Runtime assembly starts Secrets after Identity and stops it before Identity, State, Observability,
and Events close.

## Durable Workflow Graphs and Orchestration

`WorkflowDefinition` is an immutable directed acyclic graph of `WorkflowStep` values. Graph
construction rejects duplicate identifiers, missing dependencies, self-dependencies, and cycles.
`WorkflowPlanner` computes declaration-ordered topological levels, making fan-out and fan-in stable
across processes and repository implementations.

`WorkflowOrchestrator` persists one `WorkflowRecord` and delegates every runnable step to the durable
job subsystem. UUIDv5 identifiers derived from workflow and step identifiers make dispatch safe to
recover when a process stops between job creation and workflow revision replacement. Job terminal
state is reconciled into step state; successful dependencies release downstream barriers, while
failure or cancellation terminates outstanding siblings and descendants.

`InMemoryWorkflowRepository` is process-local. `StateWorkflowRepository` uses the generic State Store
with a versioned JSON-safe schema and optimistic workflow revisions. The workflow layer does not
persist callables, shell commands, or executable objects.

Runtime assembly starts `JobWorker` before `WorkflowWorker` and stops them in reverse order. The
workflow worker performs bounded reconciliation ticks and exposes counters without definitions,
arguments, outputs, or errors. Safe `workflow.*` events contain identifiers and lifecycle status;
`SecurityJournal` records them under `AuditCategory.WORKFLOW`.


## Dashboard Control Plane

`ControlPlaneService` reads immutable Runtime, job, workflow, capability, plugin, and audit snapshots
through narrow protocols. Every public model and JSON serializer is allowlisted. Internal service
objects, provider instances, arguments, outputs, metadata, Event Bus payloads, audit records, chain
digests, exception messages, credentials, and secrets are not serialized recursively.

`ControlPlaneHttpServer` is a bounded standard-library HTTP/1.1 adapter. It accepts only literal
loopback addresses, supports GET only, authenticates operational routes with an administrator token
digest, and applies fixed request, response, connection, and timeout limits. Static dashboard assets
are selected from an exact package manifest and contain no operational data.

`ControlPlaneEventStream` observes wildcard Event Bus facts but retains only event identity headers in
one bounded shared ring buffer. Long polling uses cursors, reports retention gaps, rejects excess
waiters with backpressure, and wakes readers during shutdown.

With control-plane assembly enabled, the event stream starts before job and workflow workers so their
facts can be observed. The HTTP server starts last. Reverse lifecycle order therefore closes HTTP
first, stops workers, and then unsubscribes the event stream before the Event Bus closes. The built-in
dashboard is local and read-only; remote administration, write controls, TLS, multi-user identity,
and hosted deployment remain external boundaries.

## Dashboard Command Boundary

RFC-0018 adds `ControlPlaneCommandApi` beside the read-only `ControlPlaneService`. The command API owns
short-lived browser protection, bounded idempotency, exact action authorization, safe job/workflow
handlers, and payload-free command event publication. It is not a generic dispatcher: every mutation
has a fixed contract, permission, handler method, HTTP route, serializer, and stable result-code set.

The HTTP transport accepts authenticated command POSTs only from its exact literal-loopback origin.
CSRF validation precedes idempotency reservation; job and workflow cancellation additionally consume
a one-time confirmation proof. Body size, total connections, command concurrency, idempotency entries,
confirmation entries, JSON depth, item counts, string sizes, retry policy, schedule interval, and
execution deadline are all bounded.

`RuntimeAssembler` exposes `control_plane.commands` as a lifecycle service between
`control_plane.events` and the job/workflow workers. Startup makes event observation and command state
available before the HTTP listener. Reverse shutdown stops HTTP first, then workers, then closes
command confirmation/idempotency state before the Event Bus stream unsubscribes.
