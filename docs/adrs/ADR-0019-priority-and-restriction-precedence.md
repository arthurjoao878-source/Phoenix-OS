# ADR-0019 — Priority and restriction precedence

- Status: Accepted
- Date: 2026-07-17

## Context

Multiple matching rules require predictable conflict resolution without hidden specificity scoring or
arbitrary callback behavior.

## Decision

Rules are sorted by descending priority. At equal priority, deny precedes confirmation, which precedes
allow. Registration order breaks remaining ties. The first match decides and all matching identifiers
are retained for explanation.

## Consequences

Policy authors can create explicit overrides with priority while equal-priority restrictions remain
safe. Changing priority is a security-sensitive configuration change and should be reviewed.
