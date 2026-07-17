# Architecture

```text
interfaces / integrations / Nova 3.x adapters
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

`PhoenixRuntime` is the composition root. It owns the Kernel, Event Bus, Capability Registry,
external lifecycle components, immutable named services, request admission, graceful draining, and
ordered shutdown. It does not move provider, database, AI, UI, or operating-system logic into the
core.

Commands enter through `PhoenixRuntime.handle()`, which accepts work only while the Runtime is
running and delegates admitted requests to `Kernel.handle()`. Events report facts and lifecycle
transitions; they are not a command channel. The Kernel does not import the Capability Registry.
Instead, a `CapabilityHandler` is registered as an ordinary route handler.

Lifecycle components start in explicit registration order and stop in reverse order. The Runtime
closes the Capability Registry after external components and closes the Event Bus last. Persistence,
remote brokers, retries, schemas, metrics exporters, AI, memory, databases, credentials,
sandboxing, operating-system automation, configuration parsing, and UI remain outside the Kernel,
Event Bus, Registry, and Runtime.
