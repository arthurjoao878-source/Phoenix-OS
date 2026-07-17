# ADR-0017 — Declarative plugin authority and dependency order

- **Status:** Accepted
- **Date:** 2026-07-17

## Context

A plugin that can mutate registries freely can bypass review, collide with other integrations, and
create nondeterministic startup. Dependencies also need stable ordering and rollback semantics.

## Decision

Every privileged contribution requires three conditions: a manifest permission, host approval of that
permission, and an exact declared export name. Plugin dependencies are resolved deterministically
before setup. Setup/start follow dependency order; rollback/stop reverse it. Contributions are tracked
by a host-owned registrar and cleaned when possible.

## Consequences

- Plugin authority is visible in static metadata.
- Undeclared contributions fail immediately.
- Required dependencies and cycles fail before plugin side effects.
- Plugin-published services remain behind the Plugin Manager rather than mutating Runtime's immutable
  service mapping.
- State stores registered before startup become lifecycle-owned by `StateStoreRegistry`.
