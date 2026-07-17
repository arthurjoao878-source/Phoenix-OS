# Architecture

```text
interfaces / integrations / Nova 3.x adapters
                    |
                    v
             Phoenix Kernel
        routing | authorization
                    |
                    v
                 handlers

All lifecycle observations flow through the in-process Event Bus.
```

The Event Bus is an observer mechanism, not a command channel. Commands enter through
`Kernel.handle()`. Events report facts that already occurred or lifecycle transitions.
Persistence, remote brokers, retries, schemas, metrics exporters, AI, memory, databases,
tools, and UI remain outside both Kernel and Event Bus.
