# ADR-0048: Delegation creates work, never authority

- **Status:** Accepted
- **Date:** 2026-08-11
- **Related:** RFC-0029

## Context

Multi-agent coordination introduces a new relationship between an already admitted
parent run and a separately admitted child run. A naive delegation design can
accidentally treat the parent as an authority source and copy permissions,
approvals, credentials, provider grants, tool grants, or policy decisions into the
child. That would turn coordination into privilege transfer.

Phoenix already separates agent-run, model, tool, approval, secret, and durable
recovery authority. Coordination must compose with those boundaries rather than
bypass them.

## Decision

Delegation creates work, never authority.

Every child is selected from the current server-owned delegable-agent registry and
requires a fresh exact `agent.delegate` authorization for the concrete
`agent-delegation:<namespace>/parent:<parent-agent-id>/child:<child-agent-id>`
resource. The child then receives its own Phoenix-owned run identity and is admitted
under its current reviewed `AgentServiceConfiguration`.

Parent permissions, approvals, credentials, tool grants, model grants, policy
decisions, and security-context authority are never copied into the child merely
because delegation succeeded. Every child model turn and tool invocation continues
through the independent RFC-0026/RFC-0027 authorization boundaries. Child output is
untrusted data and cannot grant Phoenix authority.

Persisted delegation metadata is also data rather than authority. Recovery must
revalidate the current registry compatibility and current policy before a
recoverable child can continue.

## Consequences

- A parent may request a reviewed child but cannot manufacture a child
  implementation or widen that child's authority.
- Existing policy boundaries remain independently testable and auditable.
- Revoked or changed current configuration wins over historical delegation state.
- Deployments must explicitly grant `agent.delegate`; existing agent principals gain
  no delegation permission automatically.

## Alternatives considered

- **Copy the parent's security context to the child.** Rejected because it transfers
  authority rather than work.
- **Treat `agent.run` as sufficient delegation permission.** Rejected because
  delegation is a distinct trust edge.
- **Let model output name arbitrary executable child code.** Rejected because the
  child inventory is server-owned and reviewed.

## Supersession criteria

A replacement must preserve fresh exact delegation authorization, independent child
admission, no parent-authority transfer, current-state revalidation, and untrusted
child results.
