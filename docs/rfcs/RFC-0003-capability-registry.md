# RFC-0003 — Capability Registry

- **Status:** Accepted
- **Version:** 1.0
- **Target:** Phoenix OS 0.3.0

## Summary

Phoenix OS needs a secure boundary between orchestration and concrete effects. The Capability
Registry owns discovery, policy evaluation, invocation, time limits, safe errors, and lifecycle
observation for external or local operations. The Kernel remains unaware of provider details.

A capability is a namespaced operation such as `files.read`, `system.open_application`, or
`weather.current`. A provider implements one operation behind immutable contracts. A trusted
adapter constructs the invocation context; untrusted request payloads never grant permissions.

## Goals

1. Register and resolve uniquely named capabilities.
2. Keep descriptors, contexts, invocations, and results immutable.
3. Evaluate permission before confirmation and execution.
4. Require explicit confirmation when declared by policy.
5. Preserve cancellation and enforce optional deadlines.
6. Translate provider failures into safe domain errors.
7. Emit correlated lifecycle events through RFC-0002.
8. Integrate with RFC-0001 through a handler adapter, not Kernel imports.
9. Allow incremental Nova 3.x migration through providers.

## Non-goals

The registry does not implement operating-system automation, AI, memory, databases, remote
brokers, retries, sandboxing, credential storage, plugin installation, schemas, or user
interfaces. Providers and deployment adapters own those concerns.

## Public contracts

- `CapabilityDescriptor`: static name, version, risk, permissions, confirmation, timeout, tags.
- `CapabilityContext`: trusted principal, request/tracing data, confirmation, permissions.
- `CapabilityInvocation`: immutable capability name, arguments, context, ID, creation time.
- `CapabilityResult`: registry-normalized immutable output tied to an invocation ID.
- `CapabilityRegistration`: opaque handle used for safe unregistration.
- `CapabilityProvider`: synchronous or asynchronous callable returning a mapping.
- `PermissionPolicy` and `ConfirmationPolicy`: asynchronous policy contracts.

## Invocation lifecycle

1. Resolve a snapshot of the registered provider.
2. Create and emit `capability.invocation.received`.
3. Evaluate permission.
4. Emit `capability.permission.allowed` or `capability.permission.denied`.
5. Evaluate confirmation.
6. If needed and absent, emit `capability.confirmation.required` and reject.
7. Emit `capability.invocation.started`.
8. Execute the provider under the effective timeout.
9. Normalize the mapping into `CapabilityResult`.
10. Emit `capability.invocation.completed`.

Failures emit `capability.invocation.failed`; cancellation emits
`capability.invocation.cancelled` and propagates to the caller.

## Security model

The default permission policy requires every descriptor permission to be present in the trusted
context. The default context factory grants no permissions. Request payload fields are arguments,
not authority. The default confirmation policy honors `confirmation_required` on the descriptor.

Permission is evaluated before confirmation so an unauthorized principal cannot use confirmation
as a bypass or learn unnecessary operational detail. Providers receive no registry internals and
cannot choose their own invocation ID.

## Determinism and concurrency

Registration order is preserved by discovery. Names are unique. Registry mutation is protected by
an asynchronous lock, but provider execution occurs outside the lock. An invocation uses the
provider snapshot resolved at its start, so later registration changes do not alter an in-flight
call.

## Kernel integration

`CapabilityHandler` translates a Kernel `Request` into an invocation and maps safe capability
errors to Kernel `Response` objects. The Kernel imports no provider, policy, registry, operating
system, Nova, or tool implementation.

## Acceptance criteria

- Strict typing, formatting, linting, and tests pass.
- Duplicate and missing names are rejected deterministically.
- Default permissions deny absent authority.
- Confirmation is explicit and cannot be inferred from arguments.
- Synchronous and asynchronous providers work.
- Deadlines and cancellation behave correctly.
- Provider and policy internals do not leak through public errors.
- Event correlation and causation are preserved.
- Kernel integration requires only a handler adapter.
