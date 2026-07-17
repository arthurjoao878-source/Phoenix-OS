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
23. Never import Nova UI, database drivers, AI clients, credentials, configuration parsing, Windows
    automation, or telemetry vendors into `phoenix_os.kernel`, `phoenix_os.events`,
    `phoenix_os.capabilities`, `phoenix_os.runtime`, `phoenix_os.observability`, or
    `phoenix_os.state`.

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
