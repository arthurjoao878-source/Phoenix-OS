# ADR-0063: Immediate UI TOCTOU revalidation before host effects

- **Status:** Accepted
- **Date:** 2026-08-18
- **Related:** RFC-0032

## Context

Desktop state is inherently time-varying. A window can disappear, be recreated under
a reused native handle, change owning process, move between relevant session/desktop
conditions, or cease to be the intended target between enumeration and a later focus
or close request.

Validation performed only when the target was first listed leaves a time-of-check to
time-of-use gap at the exact point where Phoenix is about to create an operating-
system-visible effect.

## Decision

Phoenix revalidates UI target identity and relevant desktop state immediately before
the effect.

For sensitive window effects, the adapter checks the expected Phoenix host/epoch and
the current native target immediately before effect admission. It revalidates the
reviewed ownership and identity relationships and rejects vanished, reused,
substituted, unavailable, or unsafe session/desktop targets.

A mismatch or inability to establish the reviewed target fails closed rather than
retargeting another window or degrading to best effort. Historical enumeration,
window titles, labels, model text, or prior successful focus never substitute for the
immediate native check.

Focus remains narrower than generic desktop input. A successful focus result does not
promise that focus persists and grants no keyboard or mouse authority.

Application close remains graceful and targets one exact revalidated configured
application/process instance. Failure to establish that target never widens into
force-kill or arbitrary process termination.

Cancellation before effect admission prevents new effects. Once an operating-system
effect has started, later cancellation or uncertainty does not fabricate rollback.
Uncertain admitted effects are indeterminate and are not transparently retried.

## Consequences

- Enumeration is useful selection data but cannot be treated as a durable UI target.
- The adapter must keep enough private native correlation data to revalidate the exact
  target at the effect boundary.
- UI races fail closed instead of silently acting on a replacement target.
- Focus cannot be used as implicit authorization for later keyboard/mouse automation.
- Callers and recovery logic must tolerate indeterminate outcomes after an admitted
  external effect.

## Alternatives considered

- **Trust the enumeration snapshot until use.** Rejected because window identity and
  desktop state can change before the effect.
- **Retarget by title or label after a stale match.** Rejected because user-visible
  metadata is untrusted descriptive data, not identity or authority.
- **Retry focus or close after uncertainty.** Rejected because the original effect may
  already have occurred against the exact admitted target.
- **Use focus as a precursor to generic input injection.** Rejected because focus can
  change after the operation and RFC-0032 does not grant keyboard/mouse authority.

## Supersession criteria

A replacement must preserve immediate pre-effect target revalidation, fail-closed
behavior for stale or unsafe desktop state, no metadata-based retargeting, focus
without keyboard/mouse authority, exact graceful-close targeting, pre-admission
cancellation, and indeterminate/no-retry semantics after uncertain admitted effects.
