# RFC-0004 — Phoenix Runtime

- **Status:** Accepted
- **Version:** 1.0
- **Target:** Phoenix OS 0.4.0

## Summary

Phoenix OS needs one explicit composition root for the Kernel, Event Bus, Capability Registry, and
application-owned adapters. The Phoenix Runtime owns startup, request admission, graceful draining,
reverse-order shutdown, lifecycle state, rollback, and service discovery without moving concrete
infrastructure into the core.

The Runtime is one-shot. A created instance may start once, serve requests while running, and stop
once. Failed shutdown may be retried for components that remain active, but a stopped or failed
instance is never restarted.

## Goals

1. Compose the Kernel, Event Bus, Capability Registry, and named external services.
2. Start lifecycle components deterministically in registration order.
3. Roll back successfully started components in reverse order after startup failure.
4. Reject new requests once shutdown begins and drain requests already in flight.
5. Stop active components in reverse order and attempt every possible stop hook.
6. Preserve caller cancellation and support optional startup/shutdown deadlines.
7. Expose immutable runtime context, state snapshots, and safe lifecycle errors.
8. Emit correlated lifecycle events through RFC-0002.
9. Own final shutdown of the Capability Registry and Event Bus.
10. Support incremental Nova 3.x migration through lifecycle components and named services.

## Non-goals

The Runtime does not implement dependency injection by type, automatic dependency graphs, dynamic
plugin loading, process supervision, clustering, persistence, retries, health checks, signal
handling, configuration parsing, logging backends, AI, memory, databases, operating-system
automation, or user interfaces. Deployment adapters own those concerns.

## Public contracts

- `PhoenixRuntime`: composition root and lifecycle coordinator.
- `RuntimeState`: `created`, `starting`, `running`, `stopping`, `stopped`, or `failed`.
- `RuntimeContext`: immutable runtime ID, creation time, metadata, and named service mapping.
- `LifecycleComponent`: asynchronous `start(context)` and `stop(context)` protocol.
- `ComponentSpec`: immutable name-to-component registration.
- `HookComponent`: adapter for synchronous or asynchronous lifecycle hooks.
- `RuntimeSnapshot`: immutable point-in-time state, active components, and in-flight count.
- `ComponentFailure`: component name, phase, and captured internal exception.

## Composition

The reserved services are:

- `kernel`
- `events`
- `capabilities`
- `runtime`

Applications may add other named services at construction time. Service names are normalized,
unique, and immutable after construction. Components receive the same `RuntimeContext` for startup
and shutdown. Runtime composition never grants capability permissions; trusted request adapters
remain responsible for `CapabilityContext` construction.

## Startup lifecycle

1. Transition from `created` to `starting`.
2. Emit `runtime.starting`.
3. For every component in registration order:
   1. emit `runtime.component.starting`;
   2. await `component.start(context)`;
   3. mark the component active;
   4. emit `runtime.component.started`.
4. Transition to `running`.
5. Emit `runtime.started`.

A startup exception or deadline triggers best-effort rollback of active components in reverse
order. Successful rollback removes the component from the active set. Rollback failures are
captured in `RuntimeStartError` or `RuntimeDeadlineExceededError`. The Runtime enters `failed` and
may then be stopped to retry remaining cleanup.

## Request admission and draining

`PhoenixRuntime.handle()` accepts requests only while the state is `running`. Admission and the
in-flight counter are guarded by one asynchronous condition. Shutdown changes the state to
`stopping` before waiting, so no new request can enter after draining begins.

Requests already admitted continue through `Kernel.handle()`. Shutdown waits until their count
reaches zero before stopping components. Caller cancellation of an individual request continues to
propagate through the Kernel and decrements the in-flight count in all cases.

## Shutdown lifecycle

1. Transition to `stopping` and reject new requests.
2. Emit `runtime.stopping`.
3. Drain requests already in flight.
4. For every active component in reverse startup order:
   1. emit `runtime.component.stopping`;
   2. await `component.stop(context)`;
   3. remove successful components from the active set;
   4. emit `runtime.component.stopped`.
5. If any component failed, enter `failed`, emit `runtime.stop.failed`, and raise one aggregate
   `RuntimeStopError`. Successfully stopped components are not retried.
6. Close the Capability Registry.
7. Transition to `stopped` and emit `runtime.stopped`.
8. Close the Event Bus last so all preceding lifecycle facts remain observable.

A later `stop()` call may retry only components that remained active after failure. Successful
start and stop calls are idempotent under concurrent callers.

## State model

```text
created -> starting -> running -> stopping -> stopped
              |                     |
              v                     v
            failed <--------------- failed
              |
              v
           stopping -> stopped
```

`start()` is valid only from `created` and is a no-op when already `running`. `stop()` is valid from
`created`, `running`, or `failed`, and is a no-op when already `stopped`. A one-shot instance cannot
restart after `stopped` or `failed`.

## Failure and cancellation model

- Component implementation messages are not copied into the public error message.
- Structured failure objects retain the original exception for trusted diagnostics.
- Startup failure performs reverse-order rollback before returning control.
- Normal shutdown attempts all active components even if one stop hook fails.
- Lifecycle deadlines become `RuntimeDeadlineExceededError`.
- Caller cancellation remains `asyncio.CancelledError` and leaves the Runtime in `failed` so cleanup
  can be retried.

## Event model

Lifecycle events use source `phoenix.runtime` by default. The Runtime ID is both the correlation ID
and causation ID, and is included in every payload. Component events include `component` and
`phase`. Failure events expose safe codes and counts rather than component exception text.

## Acceptance criteria

- Strict formatting, linting, typing, and tests pass.
- Core services and custom services are immutable and uniquely named.
- Components start in registration order and stop in reverse order.
- Startup failure rolls back previously started components.
- Stop failure does not prevent remaining components from being attempted.
- New requests are rejected during shutdown while in-flight work drains.
- Concurrent start and stop calls are idempotent after successful transitions.
- Deadlines and cancellation preserve retryable cleanup state.
- Capability Registry closes before Event Bus, and Event Bus closes last.
- Runtime lifecycle events are deterministic and correlated.
- RFC-0001 through RFC-0003 behavior remains unchanged.
