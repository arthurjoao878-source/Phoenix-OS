# ADR-0017: Independent agent, model, and tool authorization with exact approvals

- **Status:** Accepted
- **Date:** 2026-07-29
- **Related:** RFC-0027

## Context

Authorizing an agent run does not safely authorize every model turn and nested
tool call. A model can be influenced by prompt injection, stale external data,
or malicious tool output after the run begins. Human approval also becomes
unsafe when it can be replayed for a different tool, resource, argument set, or
actor.

## Decision

Phoenix OS evaluates three separate boundaries:

1. the exact `agent.run` action for the configured agent;
2. RFC-0026 `model.infer` for every individual model turn; and
3. the exact `tool.invoke` action for every individual tool call.

The concrete tool resource is resolved by trusted server-side code only after
strict argument validation. Model-provided strings are never accepted directly
as policy resources.

When a tool effect requires human approval, Phoenix creates one action-bound
record over the canonical argument digest, exact tool, resolved resource, run,
step, call, actor, and finite expiry. Approval evidence is single-use and
replay-resistant. Any mutation of those fields invalidates the approval. A model
cannot create, modify, consume, or extend approval evidence.

Authorization denial and approval denial are terminal security decisions for the
proposed call. The Runtime does not ask the model to reinterpret, weaken, or
bypass them.

## Consequences

- An admitted run cannot become a confused deputy for arbitrary nested actions.
- Policy and approval evidence remain server-owned and auditable without storing
  prompts or arguments.
- Sensitive tools incur an additional explicit human step.
- Callers and adapters must carry stable identifiers and canonical digests.
- Service-account or administrative authority does not imply `agent.run`,
  `model.infer`, or `tool.invoke` authority.

## Alternatives considered

- **Authorize only the outer run.** Rejected because later model output would
  inherit excessive ambient authority.
- **Authorize by model-supplied resource.** Rejected because prompt injection
  could fabricate or broaden the policy target.
- **Approve a tool for an entire session.** Rejected because arguments and
  resources can change between calls.

## Supersession criteria

A replacement must retain independent decisions for run, model, and tool work;
trusted resource resolution; and exact action-bound, actor-bound, short-lived,
single-use approval semantics.
