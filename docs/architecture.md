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
       |          |                 |
       |          |                 +-----------------------------+
       |          v                                               v
       |     Phoenix Kernel                                  Event Bus
       | routing | authorization                  lifecycle and request facts
       |          |                                               |
       |          v                                               v
       |   CapabilityHandler                                EventObserver
       |          |                                               |
       |          v                                               v
       | Capability Registry                           Observability Hub
       | permission | confirmation              logs | metrics | completed spans
       |          |                                               |
       |          v                                               v
       | capability providers                            external sinks
       |
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
Capability Registry, resolved configuration, and optional Observability and State services to
factories, then creates `PhoenixRuntime` with composed services and lifecycle components.

`PhoenixRuntime` remains the lifecycle owner. It owns the Kernel, Event Bus, Capability Registry,
external lifecycle components, immutable named services, request admission, graceful draining, and
ordered shutdown. Configuration and service factories finish before the Runtime enters `STARTING`.

Commands enter through `PhoenixRuntime.handle()`, which accepts work only while the Runtime is
running and delegates admitted requests to `Kernel.handle()`. A `CapabilityHandler` is registered as
an ordinary route handler. The Kernel does not import the Capability Registry, Configuration,
Observability, or State subsystems.

`StateStoreRegistry` resolves one or more named stores. Consumers depend on the asynchronous
`StateStore` protocol rather than a database vendor. The reference `MemoryStateStore` supplies safe
JSON serialization, typed namespaced keys, optimistic versions, TTL, serializable transactions, and
logical snapshots. Durable databases and their connection, migration, encryption, and retry policies
remain external adapters.

Events report immutable facts and lifecycle transitions; they are not a command channel.
`EventObserver` may translate those facts into structured diagnostics, but it never publishes
commands or alters Event Bus dispatch. State operations may emit safe key/version facts and create
spans, but never include persisted values automatically.

Lifecycle components start in resolved order and stop in reverse order. With observability and
state, the hub and Event Observer start before the State service. Shutdown therefore closes State
before the observer unsubscribes and the hub closes. The Runtime then closes the Capability Registry
and Event Bus.

Remote brokers, durable database implementations, distributed transactions, replication, retries,
metric aggregation, telemetry vendor protocols, AI, semantic memory, credential stores, sandboxing,
operating-system automation, remote configuration, hot reload, and UI remain external adapters.
