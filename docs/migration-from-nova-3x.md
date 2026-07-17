# Migration from Nova 3.x

Nova 3.x remains outside the Phoenix core. Migration is incremental:

1. Declare a `ConfigSchema` for each required host setting instead of reading environment variables
   throughout Nova modules.
2. Load defaults first, optional JSON second, and environment overrides last.
3. Mark credentials and tokens as secret fields and reveal them only inside the adapter factory that
   needs them.
4. Construct one `EventBus`, `Router`, `Kernel`, and `CapabilityRegistry` in the application
   composition root.
5. Convert each concrete Nova tool into one namespaced capability provider.
6. Describe required permissions, confirmation, risk, and timeout explicitly.
7. Build `CapabilityContext` only from trusted identity/session data.
8. Register `CapabilityHandler` instances as Kernel routes.
9. Register Nova databases, voice engines, schedulers, clients, and UI bridges as explicit
   `ServiceDefinition` objects.
10. Declare dependencies such as `voice -> ai_client` or `memory -> database`; do not resolve them
    through module globals.
11. Mark services with startup and shutdown hooks as lifecycle services.
12. Build the system through `RuntimeAssembler`, then route accepted requests through
    `PhoenixRuntime.handle()`.
13. Observe Runtime, Kernel, and capability lifecycle through Event Bus subscriptions.
14. Keep legacy SQLite event persistence in an adapter subscribed to selected events.
15. Never import Nova UI, database, AI client, credentials, configuration parsing, or Windows
    automation into `phoenix_os.kernel`, `phoenix_os.events`, `phoenix_os.capabilities`, or
    `phoenix_os.runtime`.

Example mapping:

```text
Nova os.getenv("OPENAI_KEY") -> secret field ai.api_key
Nova config.json             -> JsonFileConfigSource
Nova abrir_bloco_de_notas()  -> provider system.open_application
Nova ler_arquivo()           -> provider files.read
Nova salvar_memoria()        -> provider memory.store
Nova iniciar_banco()         -> lifecycle service database
Nova iniciar_voz()           -> lifecycle service voice
Nova cliente_ia              -> service ai_client
```

A service definition makes dependencies and lifecycle explicit:

```python
ServiceDefinition(
    "nova.voice",
    create_voice_service,
    dependencies=("ai_client",),
    lifecycle=True,
)
```

Legacy event names may be translated by an adapter. Legacy configuration keys may temporarily be
ignored by selecting `UnknownKeyPolicy.IGNORE`, but strict schemas are the target state.
