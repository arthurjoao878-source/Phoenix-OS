# ADR-0025 — Trusted append and policy-protected inspection

- Status: Accepted
- Date: 2026-07-18

## Context

Phoenix subsystems must record security facts without creating authorization recursion, while audit
history must not become a broadly readable source of identity and security metadata. Event-driven
capture is useful but cannot be represented as a durable cross-process guarantee.

## Decision

Audit append is a trusted in-process operation. Historical reads and verification require an
authenticated `SecurityContext` and central Policy Engine enforcement or exact fallback permissions.
`SecurityJournal` maps Event Bus facts into redacted records, ignores `audit.*` events, and runs
before later security services in Runtime lifecycle order.

## Consequences

Core subsystems can record facts without recursively auditing the authorization required to audit.
Inspection remains deny-by-default. Hostile code already executing in-process is outside this trust
boundary, and Event Bus capture remains subject to in-process delivery and dispatch failure
semantics.
