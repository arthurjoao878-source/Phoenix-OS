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
          |               |
          |               +-----------------------------+
          v                                             v
     Phoenix Kernel                                  Event Bus
 routing | authorization                  lifecycle and request facts
          |                                             |
          v                                             v
   CapabilityHandler                              EventObserver
          |                                             |
          v                                             v
 Capability Registry                         Observability Hub
 permission | confirmation              logs | metrics | completed spans
          |                                             |
          v                                             v
 capability providers                          external sinks

 application spans / logs / metrics -------------------^
```

`ConfigLoader` resolves raw deployment values before Runtime construction. Its immutable schema
performs strict decoding and validation, records the winning source for every value, and wraps
secrets so ordinary inspection remains redacted.

`ServiceComposer` builds named singleton dependencies from explicit declarations. It detects
missing dependencies and cycles before startup. `RuntimeAssembler` exposes Kernel, Event Bus,
Capability Registry, resolved configuration, and optionally Observability to factories, then creates
`PhoenixRuntime` with the composed services and lifecycle components.

`PhoenixRuntime` remains the lifecycle owner. It owns the Kernel, Event Bus, Capability Registry,
external lifecycle components, immutable named services, request admission, graceful draining, and
ordered shutdown. Configuration and service factories finish before the Runtime enters `STARTING`.

Commands enter through `PhoenixRuntime.handle()`, which accepts work only while the Runtime is
running and delegates admitted requests to `Kernel.handle()`. A `CapabilityHandler` is registered as
an ordinary route handler. The Kernel does not import the Capability Registry, Configuration System,
or Observability subsystem.

Events report immutable facts and lifecycle transitions; they are not a command channel.
`EventObserver` may translate those facts into structured diagnostics, but it never publishes
commands or alters Event Bus dispatch. Application code may also emit structured logs and metric
samples or create nested asynchronous spans directly through `ObservabilityHub`.

Lifecycle components start in resolved dependency order and stop in reverse order. When assembled
with observability, the hub starts first, the event observer starts next, and application components
follow. Shutdown reverses that order so application shutdown facts are observed before the bridge
unsubscribes and the hub closes. The Runtime then closes the Capability Registry and Event Bus.

Persistence, remote brokers, retries, metric aggregation, telemetry vendor protocols, AI, memory,
databases, credential stores, sandboxing, operating-system automation, remote configuration, hot
reload, and UI remain external adapters.
