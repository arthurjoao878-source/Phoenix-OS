# Migration from Nova 3.x

Nova 3.x remains outside the Phoenix core. Migration is incremental:

1. Construct one `EventBus`, `Router`, `Kernel`, and `CapabilityRegistry` in the application
   composition root.
2. Convert each concrete Nova tool into one namespaced capability provider.
3. Describe required permissions, confirmation, risk, and timeout explicitly.
4. Build `CapabilityContext` only from trusted identity/session data.
5. Register `CapabilityHandler` instances as Kernel routes.
6. Wrap Nova databases, voice engines, schedulers, clients, and UI bridges as lifecycle components.
7. Add shared legacy objects as named Runtime services instead of importing them into Phoenix core.
8. Route accepted requests through `PhoenixRuntime.handle()` so shutdown can reject new work and
   drain in-flight work safely.
9. Observe Runtime, Kernel, and capability lifecycle through Event Bus subscriptions.
10. Keep legacy SQLite event persistence in an adapter subscribed to selected events.
11. Never import Nova UI, database, AI client, credentials, or Windows automation into
    `phoenix_os.kernel`, `phoenix_os.events`, `phoenix_os.capabilities`, or `phoenix_os.runtime`.

Example mapping:

```text
Nova abrir_bloco_de_notas() -> provider system.open_application
Nova ler_arquivo()          -> provider files.read
Nova salvar_memoria()       -> provider memory.store
Nova iniciar_banco()        -> Runtime component database
Nova iniciar_voz()          -> Runtime component voice
Nova cliente_ia             -> named Runtime service ai_client
```

A lifecycle wrapper may use `HookComponent` while the legacy module is migrated:

```python
component = ComponentSpec(
    "nova.voice",
    HookComponent(start=start_voice, stop=stop_voice),
)
```

Legacy event names may be translated by an adapter. They do not become Phoenix contracts
automatically.
