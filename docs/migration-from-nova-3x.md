# Migration from Nova 3.x

Nova 3.x remains outside the Phoenix core. Migration is incremental:

1. Declare a `ConfigSchema` for each required host setting instead of reading environment variables
   throughout Nova modules.
2. Load defaults first, optional JSON second, and environment overrides last.
3. Mark credentials and tokens as secret fields and reveal them only inside the adapter factory that
   needs them.
4. Construct one `EventBus`, `Router`, `Kernel`, `CapabilityRegistry`, and optional
   `ObservabilityHub` in the application composition root.
5. Convert each concrete Nova tool into one namespaced capability provider.
6. Describe required permissions, confirmation, risk, and timeout explicitly.
7. Build `CapabilityContext` only from trusted identity and session data.
8. Register `CapabilityHandler` instances as Kernel routes.
9. Register Nova databases, voice engines, schedulers, clients, exporters, and UI bridges as explicit
   `ServiceDefinition` objects.
10. Declare dependencies such as `voice -> ai_client` or `memory -> database`; do not resolve them
    through module globals.
11. Mark services with startup and shutdown hooks as lifecycle services.
12. Build the system through `RuntimeAssembler`, then route accepted requests through
    `PhoenixRuntime.handle()`.
13. Use `EventObserver` to convert Runtime, Kernel, and capability lifecycle facts into structured
    diagnostics.
14. Wrap important Nova operations with `observability.span(...)` and emit structured logs and
    finite metric samples from adapters.
15. Put identifiers, states, counts, and safe metadata in structured attributes. Never place API
    keys, prompts, file contents, personal data, or credentials in log messages.
16. Implement file, console, OpenTelemetry, Prometheus, or remote exporters as external
    `ObservationSink` adapters.
17. Keep legacy SQLite event or telemetry persistence in adapters subscribed to selected signals.
18. Map Nova session state, checkpoints, cache entries, and adapter metadata to typed `StateKey`
    values instead of global dictionaries or direct SQL calls.
19. Use expected versions for read-modify-write flows and `ABSENT_VERSION` for create-only writes.
20. Group related writes in `async with state.transaction()` and use TTL only for data whose
    expiration semantics are explicit.
21. Put durable SQLite, PostgreSQL, Redis, or cloud implementations behind the `StateStore`
    protocol; keep migrations, connection pools, encryption, and retries in those adapters.
22. Use a `StateStoreRegistry` when Nova needs isolated stores such as `primary`, `session`, or
    `cache`, and pass it to `RuntimeAssembler` as the `state` service.
23. Group related Nova adapters into immutable `PluginManifest` units with explicit dependencies,
    permissions, and exports.
24. Use `HookPlugin` for incremental migration of existing setup/start/stop callbacks.
25. Approve only the plugin permissions required by the deployment and keep the default permission
    set empty.
26. Discover package entry points as metadata first; load only names present in a deployment-specific
    allowlist.
27. Resolve plugin-published services through `PluginManager.service()` instead of mutating global
    registries or Runtime services.
28. Never treat the plugin system as a sandbox. Isolate untrusted packages in external processes.
29. Adapt Nova login, API-token, service-account, or operating-system verification behind an
    `AuthenticationProvider`; never verify credentials in Kernel handlers.
30. Return only trusted roles, permissions, scopes, and attributes from the provider result.
31. Resolve a bearer session before creating `SecurityContext`, `CapabilityContext`, or
    `StateOperationContext`.
32. Persist sessions through `StateSessionRepository` or another `SessionRepository`; never write raw
    bearer tokens to a database.
33. Revoke sessions on logout, credential reset, account disablement, or suspected compromise.
34. Never import Nova UI, database drivers, AI clients, password libraries, OAuth clients,
    configuration parsing, Windows automation, or telemetry vendors into Phoenix core modules.

Example mapping:

```text
Nova os.getenv("OPENAI_KEY") -> secret field ai.api_key
Nova config.json             -> JsonFileConfigSource
Nova abrir_bloco_de_notas()  -> provider system.open_application
Nova ler_arquivo()           -> provider files.read
Nova salvar_memoria()        -> authorized capability calling StateStore
Nova iniciar_banco()         -> lifecycle service database
Nova iniciar_voz()           -> lifecycle service voice
Nova cliente_ia              -> service ai_client
Nova logging.info(...)       -> observability.log(...)
Nova cronômetro manual       -> async with observability.span(...)
Nova contador global         -> observability.metric(..., kind=COUNTER)
Nova dict de sessão          -> StateKey("session", user_id, dict)
Nova UPDATE com versão       -> state.put(..., expected_version=record.version)
Nova cache temporário        -> state.put(..., ttl=timedelta(...))
Nova módulo opcional          -> HookPlugin + PluginManifest
Nova descoberta automática    -> allowlisted EntryPointPluginDiscovery
Nova validar_login()          -> CallableAuthenticationProvider
Nova token em banco           -> StateSessionRepository com digest
Nova usuário global           -> session_scope + current_security_context
```

A service definition makes dependencies and lifecycle explicit:

```python
ServiceDefinition(
    "nova.voice",
    create_voice_service,
    dependencies=("ai_client", "observability"),
    lifecycle=True,
)
```

An exporter remains an adapter:

```python
class NovaConsoleSink:
    async def emit(self, observation: Observation) -> None:
        ...
```

Legacy event names may be translated by an adapter. Legacy configuration keys may temporarily be
ignored by selecting `UnknownKeyPolicy.IGNORE`, but strict schemas and structured diagnostics are
the target state.


A state adapter keeps persistence separate from authorization:

```python
profile = StateKey("profile", user_id, dict)
current = await state.get(profile, context=operation_context)
updated = await state.put(
    profile,
    new_profile,
    expected_version=ABSENT_VERSION if current is None else current.version,
    context=operation_context,
)
```

Legacy database rows should be migrated by an external adapter or one-time migration tool. Do not
load pickle blobs or arbitrary Python objects through the Phoenix state boundary.


A Nova adapter can begin as callbacks while preserving explicit authority:

```python
plugin = HookPlugin(
    PluginManifest(
        "nova.voice",
        "Nova Voice Adapter",
        "1.0.0",
        permissions=frozenset({PluginPermission.PUBLISH_SERVICES}),
        exports=PluginExports(services=frozenset({"nova.voice"})),
    ),
    setup=register_voice_service,
    start=start_voice,
    stop=stop_voice,
)
```

Package discovery should remain separate from loading. Review manifest permissions and exports,
pin the distribution, and add only the approved entry-point name to the host allowlist.

## Security and authorization migration

Do not copy Nova 3.x authorization booleans or global permission lists into handlers. Translate
authenticated identity facts into an immutable `SecurityContext`, then ask the Policy Engine about a
normalized action and resource.

Recommended migration sequence:

1. identify every privileged Nova operation;
2. assign stable actions such as `capability.invoke`, `state.write`, or `plugin.start`;
3. define namespaced resources;
4. register explicit deny-by-default rules;
5. use Capability, State, and Plugin policy adapters;
6. preserve confirmation as a trusted context fact;
7. audit decisions through Event Bus and Observability without logging credentials or secret values.

Authentication protocols, password verification, external token validation, and process isolation
remain provider or deployment adapters. The Phoenix manager owns only provider registration and
session lifecycle. Never infer trust from caller-supplied roles, permissions, scopes, confirmation
flags, or unverified session identifiers.


## Identity and session migration

Convert one Nova authentication path at a time. A provider should reveal `AuthenticationCredential`
only inside its verification hook and return an `Identity` only after successful verification.

```python
async def verify_nova_user(request: AuthenticationRequest) -> Identity:
    password = request.credential.secret.reveal(str)
    user = await nova_accounts.verify(password)
    if user is None:
        raise AuthenticationRejectedError("invalid credentials")
    return Identity(
        user.id,
        roles=frozenset(user.roles),
        permissions=frozenset(user.permissions),
    )
```

Issue a session through `AuthenticationManager`, return the bearer only through a secure transport,
and resolve it at the trusted ingress boundary. Use `AuthenticatedKernel` for simple in-process
adoption or build a transport adapter that binds `session_scope()` before calling Runtime. Do not log
credentials, bearers, token digests, personal profile data, permissions, or scopes.

## Secrets and key-management migration

Do not migrate Nova API keys, passwords, refresh tokens, or certificates as plain configuration
values. Replace each raw value with a stable `SecretRef`, then resolve a short-lived lease only at the
trusted adapter that needs the material.

Recommended sequence:

1. inventory every secret and its current consumers;
2. assign a namespace and stable secret name;
3. replace configuration values with `namespace/name` references;
4. define `secret.create`, `secret.rotate`, `secret.read`, and `secret.revoke` policy rules;
5. authenticate the calling service or user before requesting a lease;
6. keep lease lifetimes short and do not cache revealed values globally;
7. rotate by creating a new immutable version and update consumers to use latest or an exact version;
8. revoke compromised versions and affected sessions immediately;
9. implement production storage, encryption, KMS/HSM access, backup, and recovery in external
   adapters;
10. never place secret values, wrapping keys, vault credentials, or leases in events, logs, metrics,
    exceptions, source control, or State Store records.

Example mapping:

```text
Nova os.getenv("OPENAI_KEY")       -> SecretRef("openai-key", "ai")
Nova senha em config.json          -> parse_secret_ref("database/password")
Nova variável global de token      -> bounded SecretLease
Nova atualizar credencial          -> secrets.rotate(...)
Nova invalidar chave comprometida  -> secrets.revoke(...)
Nova Azure/AWS/Vault SDK direto    -> external SecretStore/SecretProtector adapter
Nova identificador de KMS          -> KeyRef(provider, name, version)
```

`InMemorySecretStore` is only a migration and test aid. It does not encrypt process memory or provide
durable recovery. Use a reviewed provider adapter before moving production credentials.


## Audit and security-journal migration

Do not treat Nova text logs as authoritative audit history. Inventory security-relevant actions and
convert them into structured facts with stable action, resource, actor, outcome, and category fields.
Redact before append; never copy credentials, bearer tokens, secret values, full request bodies, or
personal profile data into audit details.

Recommended sequence:

1. identify authentication, authorization, secret, plugin, capability, state, and runtime events;
2. assign normalized actions and resources already used by Policy Engine rules;
3. use direct `AuditLedger.record_security()` calls for operations that must observe append failure;
4. enable `SecurityJournal` for broad Event Bus capture and inspect dispatch failures;
5. grant `audit.read` and `audit.verify` only to authenticated operational identities;
6. verify the complete chain during export, investigation, startup checks, or scheduled operations;
7. use `SQLiteAuditStore` for local durable recovery or an external `AuditStore` for stronger retention, backup, write protection, and independent clocks;
8. supply an external `AuditSigner` and protected `KeyRef` when origin authentication is required;
9. document retention, legal hold, privacy, access review, and incident-response procedures outside
   the Phoenix core.

Example mapping:

```text
Nova logger.info("login ok")       -> AuditEvent(category=AUTHENTICATION, outcome=SUCCEEDED)
Nova logger.warning("access")     -> policy Event Bus fact -> SecurityJournal
Nova arquivo audit.log            -> SQLiteAuditStore or external AuditStore adapter
Nova checksum isolado             -> previous-digest chained AuditRecord
Nova assinatura local improvisada -> reviewed external AuditSigner + KeyRef
Nova leitura irrestrita de logs   -> audit.read policy rule
```

`InMemoryAuditStore` is a test and migration aid only. Its records disappear with the process.
`SQLiteAuditStore` survives restart and verifies before resuming by default, but it is not WORM, does
not encrypt database pages, and cannot independently detect rollback to an older valid copy. An
unsigned hash chain remains tamper-evident rather than tamper-proof.

## Audit archive and retention migration

Do not rotate Nova audit logs by renaming files without a verifiable handoff. Export Phoenix records
through `AuditArchiveManager`, preserve exact sequence ranges, and verify every manifest chain before
moving bundles to long-term storage.

Recommended sequence:

1. choose a bounded segment size appropriate for investigation and transfer;
2. export only complete contiguous ranges, or explicitly include a final partial segment;
3. retain manifest and artifact files together;
4. verify payload, artifact, record, head, and manifest continuity after every transfer;
5. independently record important latest manifest digests when rollback detection is required;
6. use protected archive identifiers for incident, legal-hold, or investigation material;
7. review the retention plan and separately confirm its exact digest before deletion;
8. apply filesystem permissions, encryption, backup, object lock, privacy, and regulatory controls
   outside the Phoenix process;
9. never treat local retention deletion as proof that remote copies or backups were removed.

Example mapping:

```text
Nova rename audit.log           -> AuditArchiveManager.rotate(...)
Nova zip with current timestamp -> deterministic gzip with payload/artifact digests
Nova checksum.txt               -> chained AuditArchiveManifest
Nova delete older_than(days)    -> plan_retention + exact digest confirmation
Nova legal hold spreadsheet     -> protected_archive_ids plus external governance
Nova copied archive directory   -> verify_chain after transfer
```

Archive rotation does not truncate the live SQLite ledger. Use an external `AuditStore` or reviewed
operational procedure when active-store compaction is required.

## Durable jobs and scheduling migration

Do not persist Nova Python callables, module paths, pickles, shell commands, or full request objects as
scheduled work. Register a reviewed Phoenix capability and persist only its stable name, JSON-safe
arguments, trusted context, schedule, retry policy, and deadline.

Recommended sequence:

1. inventory delayed tasks, retry loops, timers, and startup recovery scripts;
2. map every task to a stable registered capability;
3. separate non-sensitive job metadata from potentially sensitive arguments;
4. choose one-time or fixed-interval scheduling and a bounded retry policy;
5. use `InMemoryJobRepository` only for tests or disposable process-local jobs;
6. use `StateJobRepository` or a reviewed external adapter when jobs must survive restart;
7. configure bounded worker polling, batch size, execution deadlines, and lease TTL;
8. make external side effects idempotent because execution is at least once;
9. observe safe `job.*` facts and investigate dead-letter records without logging arguments or output;
10. keep shell execution, cron/calendar parsing, hosted queues, and distributed consensus behind
    reviewed external capability or repository adapters.

Example mapping:

```text
Nova threading.Timer(callable)    -> JobSpec(capability=..., schedule=JobSchedule(...))
Nova while True + sleep           -> Runtime-owned JobWorker with bounded polling
Nova retry loop                   -> RetryPolicy with deterministic backoff
Nova pickle of function           -> registered CapabilityDescriptor + JSON-safe arguments
Nova status="processing"          -> atomic JobLease fencing token
Nova failed_tasks.json            -> StateJobRepository dead-letter records
Nova cron / Celery / cloud queue  -> external scheduling or JobRepository adapter
```

Repository fencing rejects stale completion but cannot reverse an external effect performed before a
worker loses its lease. Pass stable domain idempotency keys to capabilities whenever duplicates would
be harmful.

## Durable workflow graph migration

Do not translate Nova automation chains into serialized functions, mutable callback lists, shell
scripts stored as data, or ad hoc status files. Model each reviewed action as a Phoenix capability and
express ordering through immutable workflow dependencies.

Recommended sequence:

1. inventory multi-step automations and identify explicit inputs, outputs, dependencies, and failure policy;
2. register one stable capability for every executable step;
3. create a `WorkflowDefinition` with immutable `WorkflowStep` values;
4. use dependency sets for fan-out and fan-in rather than shared mutable counters;
5. keep credentials behind secret references and out of workflow arguments and metadata;
6. use `StateWorkflowRepository` when instances must survive restart;
7. run the existing `JobWorker` and the `WorkflowWorker` under Runtime ownership;
8. make external effects idempotent because step jobs remain at least once;
9. inspect safe `workflow.*` and `job.*` audit facts rather than logging arguments or outputs;
10. keep dynamic graphs, compensation engines, hosted queues, remote workers, and distributed locks
    behind reviewed external adapters.

Example mapping:

```text
Nova callback chain                 -> WorkflowDefinition with dependencies
Nova ThreadPool fan-out             -> independent steps in one topological level
Nova shared completed counter       -> fan-in dependency barrier
Nova workflow_state.json            -> StateWorkflowRepository
Nova retry around each callback     -> WorkflowStep RetryPolicy -> durable JobSpec
Nova resume script                  -> WorkflowWorker reconciliation
Nova cancel flag                    -> WorkflowOrchestrator.cancel(...)
Nova serialized Python function     -> registered capability name
Nova shell pipeline                 -> reviewed external capability provider
```

A stable workflow-step job identifier prevents duplicate dispatch during recovery, but it cannot undo
an external effect completed before a worker loses its lease. Providers still need domain-level
idempotency keys and transactional integration where duplication is harmful.

## Dashboard and control-plane migration

Do not expose Nova debug endpoints, unrestricted object dumps, log files, command handlers, or local
web servers directly as a Phoenix dashboard. Build the observation surface from the explicit
control-plane views and keep every operational route read-only.

Recommended sequence:

1. generate a high-entropy administrator token at startup or resolve one from a reviewed secret
   provider;
2. construct `AdminTokenAuthenticator` and pass it to `RuntimeAssembler`;
3. bind `ControlPlaneHttpConfig` only to literal `127.0.0.1` or `::1`;
4. pass the durable job repository as `control_plane_job_records` when job detail is required;
5. expose plugin, audit, jobs, and workflows through their existing managers rather than copying
   internal objects;
6. open `/dashboard/` locally and enter the token in the active browser tab;
7. keep remote access behind an external TLS, identity, authorization, and reverse-proxy boundary;
8. never add command execution, shell input, arbitrary file paths, raw exception messages, Event Bus
   payloads, credentials, secret values, or audit bodies to dashboard serializers.

Example mapping:

```text
Nova Flask debug server              -> loopback ControlPlaneHttpServer
Nova globals / __dict__ JSON dump    -> explicit ControlPlaneSnapshot serializer
Nova unrestricted logs endpoint      -> bounded safe Event Bus header feed
Nova browser token in URL/localStorage -> Authorization header + tab sessionStorage
Nova static folder from user path    -> fixed packaged DashboardAssets manifest
Nova remote admin port               -> external reviewed ingress, not built-in listener
```

The packaged dashboard is an operator view, not a trust boundary or remote management product. A
process-local administrator token does not replace deployment identity, TLS, host access controls,
incident logging, or network policy.
