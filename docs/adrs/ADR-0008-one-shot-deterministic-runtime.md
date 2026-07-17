# ADR-0008 — One-shot deterministic runtime lifecycle

- **Status:** Accepted

Phoenix Runtime instances are one-shot composition roots. Components start serially in explicit
registration order and stop serially in reverse order. No implicit dependency graph or concurrent
startup is inferred. A failed or stopped instance is not restarted; applications construct a new
Runtime instead.

This keeps lifecycle order reviewable, rollback deterministic, and ownership unambiguous. Dynamic
component replacement and automatic dependency resolution remain outside the core.
