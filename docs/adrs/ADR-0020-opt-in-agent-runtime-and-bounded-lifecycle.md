# ADR-0020: Opt-in Runtime-owned agent composition and bounded lifecycle

- **Status:** Accepted
- **Date:** 2026-07-29
- **Related:** RFC-0027

## Context

An agent subsystem can accidentally acquire authority merely by being installed:
background planners, default tools, inherited inference credentials, listeners,
or long-lived workers could change existing Phoenix behavior before a maintainer
has reviewed configuration and policy.

## Decision

Agent composition is optional and disabled by default. When agent configuration
is absent, `RuntimeAssembler` creates no agent service, tool registry, adapter,
approval, run, event, state key, worker, listener, network request, credential
lease, filesystem access, shell access, or operating-system action.

When explicitly configured, `RuntimeAssembler` validates the complete closed
world before exposing services. It composes exact model and tool dependencies,
policy adapters, approval service when required, admission, executor, observer,
service, and maintainer administration. Partial startup rolls back
deterministically.

No background planner, scheduler, listener, shell, filesystem watcher, or
autonomous run is started. Runs occur only through an explicit trusted service
call.

Shutdown rejects new runs, drains or cancels active runs within finite bounds,
invalidates unused approvals, closes tool adapters in reverse composition order,
closes the model-turn adapter and agent Runtime, and preserves RFC-0026 inference
shutdown ordering.

Maintainer administration exposes only reviewed tool lifecycle and content-free
health. Machine administration is not introduced by RFC-0027.

## Consequences

- Upgrading from v0.26.0 is behavior-preserving until a deployment opts in.
- Inference can remain enabled independently while agent execution is disabled.
- Lifecycle ordering and cleanup are testable and deterministic.
- Deployments must provide every resolver and adapter explicitly; no convenience
  auto-discovery fills missing authority.
- Tool installation remains a deployment-time operation in the initial release.

## Alternatives considered

- **Enable a default assistant automatically.** Rejected because installation
  would create unreviewed execution authority.
- **Run a background planner.** Rejected because it changes lifecycle and
  resource use without an explicit invocation.
- **Share unrestricted Runtime or inference internals with tools.** Rejected
  because adapters would gain ambient authority unrelated to one invocation.

## Supersession criteria

A later autonomous, durable, or remotely administered agent design requires a
new RFC and ADRs that preserve opt-in composition, least authority, finite
lifecycle bounds, deterministic rollback, and compatibility when omitted.
