# ADR-0069: Server-owned integrated profiles and exact capability bridges

- **Status:** Accepted
- **Date:** 2026-08-28
- **Related:** RFC-0036

## Context

Task-level orchestration needs to expose a finite capability surface without creating a
second tool registry or letting adapters choose stronger downstream profiles, resources,
scopes, or action families at runtime.

A generic bridge that can retarget itself would create a confused-deputy boundary where
an upstream `tool.invoke` decision could be laundered into unrelated downstream
authority.

## Decision

Integrated execution uses immutable positive-generation server-owned
`IntegratedExecutionProfile` configuration and reuses the RFC-0027 `ToolRegistry`.

Every model-visible integrated `ToolId` has exactly one server-owned
`IntegratedToolBinding`, classified as exactly `LOCAL_TRANSFORM` or
`DOWNSTREAM_BRIDGE`. Missing, duplicate, ambiguous, or unsupported bindings fail
profile validation.

A local transform has no ambient external authority and can mutate only its explicitly
reviewed bounded orchestration state.

A downstream bridge is pinned to its exact Phoenix subsystem boundary, binding identity,
action family, and applicable generation/freshness. It calls the canonical downstream
Phoenix service rather than an adapter directly. `tool.invoke` and downstream canonical
authorization are independent and both remain required.

## Consequences

- RFC-0036 creates no second capability registry.
- Model or caller content cannot choose a stronger downstream profile or resource.
- Bridge substitution across profile, generation, namespace, scope, host/application
  target, resource, or action family fails closed.
- Existing memory, workspace, host, network, browser, and delegation authority models
  remain authoritative.

## Alternatives considered

- **Create an integrated capability registry.** Rejected because it would duplicate the
  RFC-0027 tool inventory and create divergent admission semantics.
- **Let bridge adapters choose a compatible profile dynamically.** Rejected because
  compatibility is not authority.
- **Treat `tool.invoke` as sufficient downstream permission.** Rejected because each
  subsystem owns its canonical protected-operation boundary.

## Supersession criteria

A replacement must preserve one exact server-owned binding per exposed tool, prohibit
runtime downstream substitution, reuse the canonical Phoenix service boundaries, and
retain independent current `tool.invoke` plus downstream authorization.
