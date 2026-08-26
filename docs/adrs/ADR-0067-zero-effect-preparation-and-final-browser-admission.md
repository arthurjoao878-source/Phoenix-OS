# ADR-0067: Zero-effect preparation and final browser admission

- **Status:** Accepted
- **Date:** 2026-08-26
- **Related:** RFC-0035

## Context

Browser operations can contain attacker-influenceable waits: adapter preparation, DNS
resolution, destination setup, and tool/freshness validation. Authorizing before those
waits and then committing later would create revocation and TOCTOU gaps.

Potentially effectful navigation and click operations also cannot be safely retried once
remote request bytes or another external effect may have started.

## Decision

Concrete browser adapters separate zero-effect preparation from one-shot protected
commit.

Preparation may resolve the exact page/element/request plan but must not emit remote
request bytes or perform the protected effect. After the last attacker-controlled wait,
Phoenix revalidates the current structural subject, profile generation, session,
page/revision, exact action/intent, tool authority when applicable, destination
admission, cancellation, and deadline.

No observer, audit, health, log, metric, inspection, or other attacker-controlled
blocking wait may be inserted between that final admission sequence and commit.

Click-derived remote requests are bound to exact method, destination, request target, and
body digest when present. Redirects are finite, manually derived under reviewed
semantics, and re-admitted per hop.

Once a remote or external effect may have started, ambiguous failure is
`INDETERMINATE`. Phoenix does not transparently retry the operation.

## Consequences

- Concrete adapters must prove zero-effect preparation semantics.
- Revocation and cancellation can still stop work before final commit.
- Final tool/browser/network checks remain adjacent to the effect boundary.
- Observer failure or delay cannot change the protected operation result.
- Recovery cannot replay an indeterminate remote effect automatically.

## Alternatives considered

- **Authorize once before preparation.** Rejected because attacker-controlled waits could
  outlive the authority that admitted the operation.
- **Let the adapter auto-follow redirects.** Rejected because each new destination needs
  current admission.
- **Retry after timeout or cancellation.** Rejected because the prior effect may already
  have occurred.
- **Await telemetry before commit.** Rejected because observation would create a new
  TOCTOU window.

## Supersession criteria

A replacement must preserve zero-effect preparation, current final revalidation after
the last attacker-controlled wait, no untrusted blocking step before commit,
per-destination redirect admission, and indeterminate/no-transparent-retry semantics
after possible effect start.
