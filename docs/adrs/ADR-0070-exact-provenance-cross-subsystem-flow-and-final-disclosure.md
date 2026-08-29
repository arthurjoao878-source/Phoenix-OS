# ADR-0070: Exact provenance controls cross-subsystem flow and final disclosure

- **Status:** Accepted
- **Date:** 2026-08-28
- **Related:** RFC-0036

## Context

Independent authority checks do not alone prevent disclosure. A run may legitimately
read sensitive memory and separately possess network authority; without an explicit
information-flow boundary, compromised planning could combine those permissions to
exfiltrate the memory.

Final user-visible output is another disclosure sink and cannot be assumed safe merely
because the model produced it.

## Decision

Phoenix tracks bounded exact server-owned `IntegratedDataProvenanceAtom` values carrying
source kind, reviewed source binding, and applicable freshness.

Every model turn and reviewed integrated transformation conservatively derives
provenance as the union of all input atoms plus the Phoenix-owned source atom for the
derived output. v0.36.0 defines no declassification primitive. Provenance cannot be
removed, weakened, relabeled, silently coalesced, or truncated. Exact union overflow
fails closed.

The integrated profile owns a finite server-owned `IntegratedDataFlowPolicy`. A content
flow proceeds only when an exact route admits the exact provenance to the exact sink.
Data-flow admission occurs before approval consumption and effect admission and never
substitutes for protected-operation authority.

Final output crosses the explicit `USER_RESULT` sink. Its audience is derived from
trusted task admission and authenticated Phoenix context, and applicable source-scope
constraints must match before content is released.

## Consequences

- Separately authorized read/write capabilities cannot be combined into implicit
  cross-subsystem disclosure.
- `MEMORY -> NETWORK`, `WORKSPACE -> NETWORK`, or equivalent flows remain denied unless
  exact server-owned policy admits them.
- Provenance laundering and silent overflow are release-blocking failures.
- A final model response can be denied without releasing its content.
- Data-flow allow and authority allow remain separate decisions.

## Alternatives considered

- **Track only source-class labels.** Rejected because later scope/audience decisions
  require exact reviewed source binding and freshness.
- **Drop provenance when limits are exceeded.** Rejected because truncation would widen
  disclosure.
- **Treat final output as implicitly user-safe.** Rejected because prior access does not
  imply final disclosure authority.

## Supersession criteria

A replacement must preserve exact bounded origin binding, conservative propagation,
fail-closed overflow, explicit server-owned cross-subsystem routes, and authenticated
source-scope-aware `USER_RESULT` disclosure.
