# ADR-0056: Files carry data, never authority

- **Status:** Accepted
- **Date:** 2026-08-14
- **Related:** RFC-0031

## Context

Workspace artifacts may contain instructions, source code, scripts, documents, archives,
credentials copied as text, approval-like statements, policy fragments, tool output,
or prompt injection. A filename, extension, media type, provenance field, digest, or
the fact that Phoenix stored bytes cannot safely establish current authority.

Treating workspace content as trusted merely because it resides inside a Phoenix-owned
workspace would create an authority channel around the existing policy, agent, model,
tool, approval, secret, delegation, memory, import, export, network, and operating-
system boundaries.

## Decision

Files carry data, never authority.

Every workspace list, read, write, delete, import, export, and administrative
operation requires its own fresh exact current-policy authorization. Artifact bytes,
logical paths, filenames, media types, metadata, provenance, digests, historical
grants, approval-like text, credentials, or policy fragments remain data and cannot
reconstruct current Phoenix authority.

Artifact content may enter an agent run only through an explicit bounded context
boundary that labels it untrusted. Storage never promotes artifact content into a
system or policy message. Stored prompt injection cannot grant model, tool,
delegation, approval, memory, import, export, host-filesystem, shell, process,
browser, desktop, network, or other operating-system authority.

Phoenix does not execute bytes merely because they are artifacts. Archive extraction,
macro execution, rendering, OCR, parsing, compilation, script execution, or similar
transformations require a separate reviewed boundary; none is implicit in workspace
storage.

Phoenix does not automatically persist normal prompts, responses, tool results,
memory records, child results, conversations, checkpoints, chain-of-thought, or
hidden reasoning as workspace artifacts. Writes are explicit server-admitted
operations.

## Consequences

- Workspace persistence does not become an ambient authorization mechanism.
- Stored prompt injection remains a model-input risk but cannot bypass independent
  Phoenix authorization boundaries.
- Applications that intentionally transform or execute artifact data must do so
  through separately reviewed capabilities and policy.
- Enabling workspaces grants no existing principal, agent, model, tool, memory
  subsystem, or transfer adapter new authority by itself.
- Current reviewed configuration and current Policy Engine decisions always win over
  historical artifact content or metadata.

## Alternatives considered

- **Trust files after Phoenix stores them.** Rejected because storage history is not
  current authority.
- **Trust selected extensions or media types.** Rejected because names and descriptive
  metadata do not establish execution or policy authority.
- **Reuse agent-run or tool authorization for workspace operations.** Rejected because
  workspace disclosure, mutation, transfer, and administration are independent trust
  edges.
- **Automatically capture agent activity into artifacts.** Rejected because it
  silently expands persistence, privacy exposure, and poisoning risk.

## Supersession criteria

A replacement must preserve fresh independent current-policy authorization, explicit
writes, untrusted artifact context, no automatic hidden-reasoning persistence, and the
rule that artifact content or metadata itself never grants Phoenix authority.
