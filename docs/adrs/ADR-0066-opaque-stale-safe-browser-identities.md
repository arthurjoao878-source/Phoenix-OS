# ADR-0066: Opaque stale-safe browser identities

- **Status:** Accepted
- **Date:** 2026-08-26
- **Related:** RFC-0035

## Context

Browser DOM and native engine identities are mutable and attacker-influenceable. CSS
selectors, XPath, coordinates, DOM paths, titles, and native handles can retarget as a
page changes. Reusing them across revisions creates a time-of-check to time-of-use gap
and can direct an effect at a different target than the one reviewed.

A browser session also needs to remain bound to the requester that opened it rather than
acting as a shareable capability.

## Decision

Phoenix uses opaque server-owned session, page, revision, and element identities with
exact stale checks.

Each v0.35.0 session owns exactly one top-level page. Page revisions are positive
freshness identities. Element IDs are opaque and valid only for one exact page revision.
A mutation or navigation advances the visible page revision, making older element
observations stale.

Sessions are bound to the exact structural authority subject, and agent-mediated
sessions additionally bind exact agent/run scope. IDs and snapshots are descriptive
references only; possession does not grant authority.

Public effect APIs do not accept CSS selectors, XPath, pixel/coordinate targets, DOM
paths, accessibility paths, or native browser handles.

## Consequences

- Callers must reacquire page/element state after a revision change.
- Stale targets fail closed instead of being heuristically retargeted.
- Cross-principal, cross-session, cross-agent, and cross-run reuse is rejected.
- Native adapter correlations remain private implementation state.
- One-page scope prevents popup/frame identity from silently creating new targets.

## Alternatives considered

- **Expose CSS/XPath selectors.** Rejected because selector meaning can change between
  observation and effect.
- **Retarget stale elements by label or DOM similarity.** Rejected because content is
  untrusted data and not identity.
- **Treat session IDs as capabilities.** Rejected because identity and authority must
  remain separate and current.

## Supersession criteria

A replacement must preserve opaque non-bearer identities, exact session/subject binding,
revision-scoped element identity, fail-closed stale behavior, and the absence of generic
selector/coordinate/native-handle effect targeting.
