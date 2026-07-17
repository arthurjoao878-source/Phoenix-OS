# ADR-0004 — Deterministic serial event delivery

- Status: **Accepted**

Version 0.2 invokes handlers serially from a subscription snapshot, ordered by descending
priority and then registration order. Hidden task creation and nondeterministic completion
are rejected for the foundational bus.
