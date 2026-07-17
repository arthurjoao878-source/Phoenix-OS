# ADR-0006 — Capability boundary outside the Kernel

- **Status:** Accepted

The Kernel remains a generic request orchestrator. Concrete effects are exposed through a separate
Capability Registry and reached through handlers. This prevents operating-system, AI, persistence,
or Nova implementation details from becoming Kernel dependencies.
