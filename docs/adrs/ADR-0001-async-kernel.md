# ADR-0001 — Async-first Kernel

- Status: **Accepted**

The public Kernel API is asynchronous. Blocking integrations must use adapters and must not
block the event loop.
