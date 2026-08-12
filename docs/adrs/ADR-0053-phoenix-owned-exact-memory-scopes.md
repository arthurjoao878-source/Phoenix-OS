# ADR-0053: Phoenix-owned exact memory scopes without implicit sharing

- **Status:** Accepted
- **Date:** 2026-08-12
- **Related:** RFC-0030

## Context

Persistent memory becomes a disclosure boundary when records survive beyond one
request. If a model can choose scope strings, if agent and principal identity are
conflated, or if parent/child delegation implicitly shares memory, one workload can
read data admitted for another.

## Decision

Every record belongs to one exact Phoenix-owned namespace and one finite scope kind.
RFC-0030 v1 supports only `run`, `agent`, and `principal`.

Run and agent scope identifiers are derived from trusted Phoenix-owned identities.
Principal scope identity is derived from the authenticated security context through a
content-free stable digest. Model content may propose query or record text but cannot
create, widen, replace, or mutate the trusted scope.

Collection authorization binds the exact namespace, scope kind, and scope ID. Direct
record authorization additionally binds the exact `MemoryId`. Cross-namespace,
cross-scope, and cross-record substitution fail closed.

There is no global shared memory in v1. Agents, principals, runs, parents, and
delegated children do not inherit or share memory implicitly. Any future copy or
promotion feature requires a new explicit server-owned operation and independent
authorization.

## Consequences

- Scope disclosure is independently testable and auditable.
- Delegation does not become a hidden memory-sharing channel.
- Applications must deliberately choose the scope kind appropriate for retained
  data.
- Future shared-memory features cannot inherit authority from this ADR implicitly.

## Alternatives considered

- **Let model output choose arbitrary scope strings.** Rejected because untrusted text
  cannot define a security boundary.
- **Use one global agent-memory pool.** Rejected because it destroys least disclosure.
- **Automatically share parent memory with children.** Rejected because delegation
  creates work, not shared authority or shared retained context.

## Supersession criteria

A replacement must preserve Phoenix-owned scope identity, exact resource binding,
fail-closed substitution handling, and no implicit cross-agent/principal/run or
parent/child sharing.
