# Phoenix OS

Phoenix OS is an experimental orchestration foundation for Python 3.12+ with an optional local administrative dashboard.
Version `0.17.0` implements seventeen accepted specifications:

- **RFC-0001 — Phoenix Kernel:** asynchronous request lifecycle, routing, authorization,
  confirmation, cancellation, deadlines, safe errors, and lifecycle events.
- **RFC-0002 — Event Bus:** immutable events, deterministic asynchronous delivery, priorities,
  one-shot and wildcard subscriptions, failure isolation, and explicit shutdown.
- **RFC-0003 — Capability Registry:** immutable capability contracts, trusted contexts,
  permissions, confirmation, deadlines, safe provider execution, discovery, and Kernel adapters.
- **RFC-0004 — Phoenix Runtime:** deterministic component startup, rollback, request draining,
  reverse shutdown, lifecycle states, deadlines, and context management.
- **RFC-0005 — Configuration System:** typed immutable configuration, ordered sources, provenance,
  explicit secrets, dependency composition, and Runtime assembly.
- **RFC-0006 — Observability and Diagnostics:** structured logs and metrics, asynchronous spans,
  deterministic sinks, recursive redaction, Event Bus observation, and Runtime ownership.
- **RFC-0007 — State Store and Persistence:** typed namespaced keys, safe JSON serialization,
  optimistic versions, TTL, serializable transactions, snapshots, and named-store lifecycle.
- **RFC-0008 — Plugin System and Adapter SDK:** immutable manifests, semantic compatibility,
  dependency ordering, least-authority exports, allowlisted discovery, rollback, and Runtime lifecycle.
- **RFC-0009 — Policy Engine and Security Context:** immutable identities, declarative rules,
  default-deny decisions, confirmation, explanations, and subsystem enforcement adapters.
- **RFC-0010 — Identity, Authentication and Sessions:** redacted credentials, trusted provider
  adapters, opaque bearer sessions, hashed persistence, expiry, revocation, and context propagation.
- **RFC-0011 — Secrets Vault and Key Management:** versioned secret references, authenticated
  policy enforcement, bounded leases, rotation, revocation, and external cryptographic boundaries.
- **RFC-0012 — Audit Ledger and Security Journal:** immutable redacted security facts, canonical
  hash chaining, optional external signatures, policy-protected inspection, and Event Bus journaling.
- **RFC-0013 — Durable Audit Storage and Recovery:** SQLite WAL persistence, atomic append
  transactions, append-only SQL guards, schema validation, and verify-before-resume recovery.
- **RFC-0014 — Audit Retention, Rotation and Archival:** canonical NDJSON segments, deterministic
  compression, chained manifests, verification, and confirmed prefix-only retention.
- **RFC-0015 — Durable Jobs and Workflow Scheduling:** capability-only jobs, deterministic schedules,
  lease fencing, retries, dead-letter state, State Store recovery, and Runtime-owned bounded workers.
- **RFC-0016 — Durable Workflow Graphs and Orchestration:** immutable DAG definitions, deterministic
  fan-out/fan-in planning, durable job-backed steps, restart recovery, failure propagation, and
  Runtime-owned reconciliation.
- **RFC-0017 — Dashboard Control Plane and Read-Only API:** allowlisted snapshots, authenticated
  loopback HTTP, paginated operational views, bounded event streaming, packaged static assets, and
  Runtime-owned dashboard lifecycle.

The core intentionally contains no AI model, remote database driver, semantic-memory engine,
concrete tool, concrete identity provider, password database, cloud vault, cryptographic key, job
queue broker, audit signature provider, remote audit archive, telemetry vendor, hosted control plane, remote administration, or
operating-system automation. The
standard-library SQLite adapter is a local reference implementation; stronger storage remains behind
the State Store and Audit Store protocols. Other integrations belong behind capability providers,
lifecycle components, named services, sinks, allowlisted plugins, and external adapters.
The plugin system is an authority boundary for SDK contributions, not a sandbox for hostile code.

## Install for development

```bash
python -m pip install -e ".[dev]"
```

## Validate

```bash
ruff check .
ruff format --check .
mypy
pytest
```

On Windows:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\check.ps1
```


## Local dashboard example

```powershell
python .\examples\control_plane_dashboard.py
```

Open the printed loopback URL and enter the one-time administrator token. The dashboard serves only
packaged HTML, CSS, JavaScript, and SVG assets; it loads no external scripts or fonts. All data
requests remain authenticated with `control-plane.read`, use explicit serializers, and omit job
arguments, workflow inputs and outputs, plugin metadata, audit bodies, Event Bus payloads, and
secrets. The token is retained only in browser `sessionStorage` for the active tab.

`RuntimeAssembler` can own `ControlPlaneEventStream` and `ControlPlaneHttpServer` by receiving an
`AdminTokenAuthenticator`. The server accepts only literal loopback addresses. Static routes are
public because they contain no operational data; every `/v1/control-plane/*` route remains
authenticated and read-only.

## Durable workflow example

```python
from phoenix_os import WorkflowDefinition, WorkflowStep

definition = WorkflowDefinition(
    "release",
    (
        WorkflowStep("prepare", "release.prepare"),
        WorkflowStep("test", "release.test", dependencies=frozenset({"prepare"})),
        WorkflowStep("publish", "release.publish", dependencies=frozenset({"test"})),
    ),
)
workflow = await orchestrator.start(definition)
```

Workflow definitions are validated directed acyclic graphs. Independent steps fan out in declaration
order, dependent steps wait at fan-in barriers, and every runnable step becomes a durable Phoenix
job. `StateWorkflowRepository` persists definitions and execution state; `WorkflowWorker` reconciles
non-terminal instances under Runtime ownership without storing Python callables or shell commands.

## Durable jobs example

```python
from datetime import UTC, datetime

from phoenix_os import JobSchedule, JobSpec

job = await scheduler.schedule(
    JobSpec(
        capability="report.generate",
        schedule=JobSchedule(datetime.now(UTC)),
        arguments={"report_id": "daily"},
    )
)
runs = await scheduler.run_due()
```

Jobs store capability names rather than Python callables or shell commands. `InMemoryJobRepository` is
process-local; `StateJobRepository` persists versioned records through `StateStore`. Lease fencing
rejects stale completion, but capability providers still need idempotency for external side effects.
`JobWorker` supplies an explicit bounded Runtime lifecycle loop while `run_due()` remains directly
testable.

## Audit example

```python
from phoenix_os import AuditCategory, AuditLedger, AuditQuery

await audit.record_security(
    "policy.evaluated",
    category=AuditCategory.AUTHORIZATION,
    action="secret.read",
    resource="secret:production/database-password",
    context=security_context,
)
records = await audit.read(AuditQuery(limit=100), security_context)
verification = await audit.verify(security_context)
```

Audit details are redacted before hashing. `InMemoryAuditStore` remains ephemeral. For local durable
recovery, construct `SQLiteAuditStore("var/phoenix/audit.sqlite3")`; it verifies an existing chain
before resuming appends by default. `AuditArchiveManager` exports canonical NDJSON segments, verifies
manifest and record continuity, and requires digest-confirmed retention plans before deletion. An
unsigned SHA-256 chain remains tamper-evident rather than tamper-proof; protected storage and
independent anchoring remain deployment responsibilities.

## Secrets example

```python
from phoenix_os import KeyRef, SecretRef, SecretsManager, SecretValue

manager = SecretsManager(policy=policy)
ref = SecretRef("database-password", "production")
await manager.create(
    ref,
    SecretValue(password),
    security_context,
    protection_key=KeyRef("primary", "external-kms", 1),
)
lease = await manager.lease(ref, security_context)
```

Configuration should contain `SecretRef` values rather than raw credentials. The reference in-memory
store is not encrypted at rest; production encryption and key custody belong to reviewed external
`SecretStore` and `SecretProtector` adapters.

## Identity example

```python
from phoenix_os import (
    AuthenticationCredential,
    AuthenticationManager,
    CallableAuthenticationProvider,
    Identity,
    SecretValue,
)

provider = CallableAuthenticationProvider(authenticate_nova_user)
identity = AuthenticationManager((("nova", provider),))
grant = await identity.authenticate(
    "nova",
    AuthenticationCredential("password", SecretValue(password)),
)
session = await identity.resolve(grant.token)
```

Only a one-way digest is retained by the session repository. Password hashing, OAuth, LDAP, OIDC,
and external token verification belong inside trusted provider adapters.

## Policy example

```python
from phoenix_os import PolicyEffect, PolicyEngine, PolicyRequest, PolicyRule

policy = PolicyEngine((
    PolicyRule(
        "allow-profile",
        PolicyEffect.ALLOW,
        actions=frozenset({"state.read"}),
        resources=frozenset({"state:profile:*"}),
    ),
))
decision = await policy.evaluate(
    PolicyRequest("state.read", "state:profile:arthur"),
)
```

The engine is deny-by-default. Capability, State Store, Plugin, and Runtime adapters keep policy
centralized without coupling the Kernel to the authorization implementation.

## Plugin example

```python
from phoenix_os import HookPlugin, PluginManifest

plugin = HookPlugin(
    PluginManifest("nova.voice", "Nova Voice Adapter", "1.0.0"),
)
```

Plugins are loaded explicitly, validated before setup, and owned by `PluginManager`. See
`examples/plugin_system.py` for capability and service exports.

## State example

```python
from phoenix_os import ABSENT_VERSION, MemoryStateStore, StateKey

store = MemoryStateStore()
profile = StateKey("profile", "arthur", dict)
record = await store.put(
    profile,
    {"level": 1},
    expected_version=ABSENT_VERSION,
)
updated = await store.put(
    profile,
    {"level": 2},
    expected_version=record.version,
)
```

See `examples/` and `docs/` for complete contracts, configuration, dependency composition, Runtime
integration, the local dashboard, durable jobs, Runtime workers, authentication providers, sessions, secret references, leases, key providers, policy rules, security contexts, plugin manifests, dependency resolution, durable audit recovery, state transactions, snapshots, trace context, redaction, and architectural decisions.

## License

MIT — Copyright (c) 2026 Phoenix contributors.
