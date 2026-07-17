# Migration from Nova 3.x

Nova 3.x remains outside the Phoenix core. Migration is incremental:

1. Wrap each Nova input channel as a `Request` producer.
2. Convert each concrete Nova tool into one namespaced capability provider.
3. Describe required permissions, confirmation, risk, and timeout explicitly.
4. Build `CapabilityContext` only from trusted identity/session data.
5. Register `CapabilityHandler` instances as Kernel routes.
6. Observe Kernel and capability lifecycle through Event Bus subscriptions.
7. Keep legacy SQLite event persistence in an adapter subscribed to selected events.
8. Never import Nova UI, database, AI client, credentials, or Windows automation into
   `phoenix_os.kernel`, `phoenix_os.events`, or `phoenix_os.capabilities`.

Example mapping:

```text
Nova abrir_bloco_de_notas() -> provider system.open_application
Nova ler_arquivo()          -> provider files.read
Nova salvar_memoria()       -> provider memory.store
```

Legacy event names may be translated by an adapter. They do not become Phoenix contracts
automatically.
