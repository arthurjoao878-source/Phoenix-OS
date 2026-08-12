# ADR-0052: Memory informs work, never authority

- **Status:** Accepted
- **Date:** 2026-08-12
- **Related:** RFC-0030

## Context

Persistent memory can contain historical instructions, model output, user content,
approval-like text, credentials, policy fragments, or prompt injection. Treating
remembered content as trusted merely because Phoenix stored it would create a new
authority channel around existing policy, agent, model, tool, approval, secret, and
delegation boundaries.

## Decision

Memory informs work, never authority.

Every search, direct read, write, delete, and administrative operation requires its
own fresh exact memory authorization. Remembered content, provenance, metadata,
historical grants, approval-like text, credentials, or policy fragments remain data
and cannot reconstruct current authority.

Retrieved memory may enter an agent run only as a bounded provenance-preserving
untrusted context block. It never becomes a system-policy message merely because it
came from Phoenix memory. Current Policy Engine decisions and current reviewed
configuration always win.

Phoenix does not automatically persist normal conversations, prompts, responses,
tool results, chain-of-thought, or hidden reasoning. Writes are explicit
server-admitted operations.

## Consequences

- Memory cannot bypass independent agent/model/tool/delegation/approval boundaries.
- Stored prompt injection remains a model-input risk but not an authorization
  mechanism.
- Applications may use remembered data for relevance while still resolving current
  authority independently.
- Existing principals gain no memory permission when memory is enabled.

## Alternatives considered

- **Treat Phoenix-stored content as trusted system context.** Rejected because storage
  history is not current authority.
- **Reuse the agent run authorization for all memory operations.** Rejected because
  memory disclosure and mutation are independent trust edges.
- **Automatically remember every interaction.** Rejected because it silently expands
  persistence, privacy, and poisoning risk.

## Supersession criteria

A replacement must preserve fresh independent current-policy authorization, explicit
writes, no automatic hidden-reasoning persistence, and the rule that remembered
content itself never grants Phoenix authority.
