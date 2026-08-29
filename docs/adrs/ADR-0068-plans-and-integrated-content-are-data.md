# ADR-0068: Plans and integrated content are data, never authority

- **Status:** Accepted
- **Date:** 2026-08-28
- **Related:** RFC-0036

## Context

Integrated execution combines task text, model planning, tool results, memory, workspace,
browser, network, clipboard, durable metadata, and other content-bearing sources. If any
of those values could create Phoenix authority, prompt injection or persisted-content
injection could escalate from data into permissions, profiles, resources, credentials,
approvals, or protected operations.

RFC-0027 already treats model proposals and tool results as untrusted. RFC-0036 must
preserve that rule while adding task-level planning.

## Decision

Phoenix treats integrated task text, plan proposals/revisions, model output, tool
arguments/results, retrieved content, checkpoints, and resupplied recovery context as
data only.

Planning remains inside the RFC-0027 two-outcome model-turn contract. A plan update can
occur only through the reserved server-owned `integrated.plan.update` tool and normal
`tool.invoke` authorization. Accepted plan state remains bounded advisory data for the
exact task/run and never becomes an executable workflow graph or authority grant.

Task/run admission authorizes only the exact admitted run. It does not authorize later
model inference, tool invocation, delegation, or any memory, workspace, host, network, or
browser operation.

## Consequences

- Prompt injection cannot manufacture Phoenix policy resources or protected operations.
- Plan revisions can change future advisory intent but not task identity, profile
  binding, approvals, completed attempts, effect outcomes, or history.
- Existing RFC-0027 run/step identities and authority boundaries remain authoritative.
- Recovery context can inform replanning but cannot replace trusted run/profile state.

## Alternatives considered

- **Treat an accepted plan as executable authority.** Rejected because model-authored
  intent would bypass current protected-operation authorization.
- **Add a third model-native planning outcome.** Rejected because it would fork the
  RFC-0027 loop contract.
- **Restore checkpoint decisions as live permission.** Rejected because persisted state
  is data and current authority may have changed.

## Supersession criteria

A replacement must preserve the rule that task, plan, model, tool, retrieved, persisted,
and resupplied content cannot manufacture or replay Phoenix authority, and must preserve
fresh canonical authorization for every protected operation.
