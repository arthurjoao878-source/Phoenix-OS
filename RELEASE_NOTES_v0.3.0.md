# Phoenix OS v0.3.0 — Capability Registry

Phoenix OS 0.3.0 introduces the secure execution boundary defined by RFC-0003.

## Highlights

- Immutable descriptors, contexts, invocations, results, and registration handles.
- Deterministic discovery and unique namespaced capability registration.
- Default-deny required-permissions policy.
- Explicit descriptor-based confirmation policy.
- Synchronous and asynchronous provider support.
- Deadlines, cancellation propagation, and safe provider/policy errors.
- Correlated lifecycle events through the RFC-0002 Event Bus.
- `CapabilityHandler` integration without adding Registry dependencies to the Kernel.
- Nova 3.x migration path through isolated providers and trusted adapters.
- 77 tests passing under strict linting and typing.

Suggested commit:

```text
feat(capabilities): implement RFC-0003 capability registry
```

Suggested tag:

```text
v0.3.0
```
