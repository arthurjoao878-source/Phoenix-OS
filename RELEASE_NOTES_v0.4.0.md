# Phoenix OS v0.4.0 — Phoenix Runtime

Phoenix OS 0.4.0 introduces the deterministic composition and lifecycle boundary defined by
RFC-0004.

## Highlights

- One-shot `PhoenixRuntime` composition root.
- Immutable Runtime context, metadata, and named service mapping.
- Reserved Kernel, Event Bus, Capability Registry, and Runtime services.
- Deterministic component startup and reverse-order shutdown.
- Best-effort rollback after startup failure.
- Graceful request admission shutdown and in-flight request draining.
- Retryable cleanup after component shutdown failures.
- Concurrent start/stop idempotence after successful transitions.
- Optional lifecycle deadlines and cancellation propagation.
- Async context-manager support.
- Correlated Runtime lifecycle events.
- Capability Registry closes before Event Bus; Event Bus closes last.
- 103 tests preserving RFC-0001 through RFC-0003 behavior.

Suggested commit:

```text
feat(runtime): implement RFC-0004 lifecycle composition
```

Suggested tag:

```text
v0.4.0
```
