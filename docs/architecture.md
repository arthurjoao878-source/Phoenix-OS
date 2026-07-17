# Architecture

```text
interfaces / integrations / Nova 3.x adapters
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

Kernel and capability lifecycle observations flow through the in-process Event Bus.
```

Commands enter through `Kernel.handle()`. Events report facts and lifecycle transitions; they are
not a command channel. The Kernel does not import the Capability Registry. Instead, a
`CapabilityHandler` is registered as an ordinary route handler.

The registry owns discovery and the safe invocation boundary, but not implementation details.
Persistence, remote brokers, retries, schemas, metrics exporters, AI, memory, databases,
credentials, sandboxing, operating-system automation, and UI remain outside the Kernel, Event Bus,
and Registry.
