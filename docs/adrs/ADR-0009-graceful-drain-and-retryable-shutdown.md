# ADR-0009 — Graceful request drain and retryable shutdown

- **Status:** Accepted

Shutdown transitions to `stopping` before waiting for active requests. New work is rejected while
already admitted requests finish. Components are then stopped in reverse order. Every possible
stop hook is attempted, successful components are removed from the active set, and failures remain
active so a later `stop()` can retry only unfinished cleanup.

The Capability Registry closes after application components. The Event Bus closes last so runtime,
Kernel, and capability shutdown facts remain observable.
