# ADR-0025: Opt-in Runtime-owned durable lifecycle, retention, and administration

- **Status:** Accepted
- **Date:** 2026-08-10
- **Related:** RFC-0028

## Context

Durability introduces stores, codecs, key protection, leases, recovery workers,
retention workers, cleanup, observability, and administrative controls. If any of
those components start implicitly, outlive their dependencies, or expose broad
administrative authority, installing durability can change Phoenix behavior before
a deployment has opted in.

Destructive recovery administration and cleanup also need stronger boundaries than
ordinary read-only health.

## Decision

Durable composition is optional, disabled by default, and requires the RFC-0027
agent subsystem. When durable configuration is omitted, `RuntimeAssembler` creates
no durable run, checkpoint, payload, lease, recovery worker, retention worker,
cleanup pass, durable event, or durable administration service.

When explicitly configured, Runtime composition owns the durable store, checkpoint
codec, optional protector, lease manager, recovery coordinator and worker, durable
agent runtime, observer, administration boundaries, retention worker, and their
lifecycle dependencies. Complete configuration and dependency validation occurs
before durable services become visible. Partial startup rolls back
deterministically.

The recovery worker examines only existing eligible durable runs. It cannot create
new goals, schedule autonomous agents, widen tool authority, or reset accumulated
budgets and deadlines. Recovery, reconciliation, retention, and cleanup remain
bounded in pages, queues, concurrency, attempts, and duration.

Retention is finite. Cleanup is delegated to the Runtime-owned bounded retention
worker, derives authority and bounds from trusted Runtime policy and configuration,
skips actively leased runs, removes protected payloads under the reviewed retention
protocol, and preserves terminal tombstones that prevent stale resurrection.

Maintainer administration exposes only reviewed content-free durable state and
health. Destructive reconciliation and cleanup require exact actions, recent human
step-up authentication, one-time confirmation, and audit. Wildcard permissions do
not satisfy exact destructive authority. Machine administration is disabled by
default and, when enabled for reviewed read operations, requires exact
service-account scopes and resources. RFC-0028 exposes no machine cleanup endpoint.

Shutdown stops new durable admission and automatic recovery, drains admitted work
within finite grace, stops new external attempts, preserves indeterminate outcomes
when completion is unknown, closes administrative admission before destructive
protection/coordinators, and closes storage after its durable dependents.

## Consequences

- Upgrading preserves v0.27.0 behavior until durability is explicitly configured.
- Durable ownership, rollback, shutdown, retention, and cleanup ordering are
  deterministic and testable.
- Ordinary in-memory RFC-0027 agent execution and RFC-0026 inference remain
  independently usable when durability is disabled.
- Deployments must explicitly configure storage, policy, limits, retention, and
  optional protected-content keys.
- Human and machine administration remain intentionally asymmetric.

## Alternatives considered

- **Create a default durable store on install.** Rejected because package import or
  upgrade must not create persistent state.
- **Resume every stored run automatically at startup.** Rejected because recovery
  requires bounded admission, current authorization, compatibility, and fencing.
- **Expose direct store deletion to administration.** Rejected because cleanup must
  remain bounded by the retention protocol and anti-resurrection rules.
- **Reuse human destructive endpoints for service accounts.** Rejected because
  machine authority is a separate default-off security model.

## Supersession criteria

A replacement must preserve opt-in composition, deterministic rollback, bounded
worker and shutdown lifecycles, server-owned retention and cleanup authority,
anti-resurrection state, content-free administration, exact protected destructive
actions, and default-off machine administration.
