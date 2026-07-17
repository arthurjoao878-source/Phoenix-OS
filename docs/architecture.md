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
         Phoenix Kernel
    routing | authorization
              |
              v
      CapabilityHandler
              |
              v
     Capability Registry
 permission | confirmation | timeout
              |
              v
    capability providers

 lifecycle and request facts
              |
              v
          Event Bus
```

`ConfigLoader` resolves raw deployment values before Runtime construction. Its immutable schema
performs strict decoding and validation, records the winning source for every value, and wraps
secrets so ordinary inspection remains redacted.

`ServiceComposer` builds named singleton dependencies from explicit declarations. It detects
missing dependencies and cycles before startup. `RuntimeAssembler` exposes Kernel, Event Bus,
Capability Registry, and resolved configuration to factories, then creates `PhoenixRuntime` with
the composed services and lifecycle components.

`PhoenixRuntime` remains the lifecycle owner. It owns the Kernel, Event Bus, Capability Registry,
external lifecycle components, immutable named services, request admission, graceful draining, and
ordered shutdown. Configuration and service factories finish before the Runtime enters `STARTING`.

Commands enter through `PhoenixRuntime.handle()`, which accepts work only while the Runtime is
running and delegates admitted requests to `Kernel.handle()`. Events report facts and lifecycle
transitions; they are not a command channel. The Kernel does not import the Capability Registry or
Configuration System. A `CapabilityHandler` is registered as an ordinary route handler.

Lifecycle components start in resolved dependency order and stop in reverse order. The Runtime
closes the Capability Registry after external components and closes the Event Bus last. Persistence,
remote brokers, retries, metrics exporters, AI, memory, databases, credential stores, sandboxing,
operating-system automation, remote configuration, hot reload, and UI remain external adapters.
