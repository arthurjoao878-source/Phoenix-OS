# ADR-0037 — Origin-bound browser commands and one-time destructive proof

- Status: Accepted
- Date: 2026-07-19

## Context

A bearer token stored in a browser tab is not by itself sufficient protection for state-changing HTTP
requests. The local dashboard must also prevent cross-site request forgery, accidental repeated
submission, and silent destructive actions while keeping secrets out of logs and persistent state.

## Decision

Every browser command requires an HMAC-SHA-256 CSRF token bound to the authenticated principal and the
exact literal-loopback HTTP origin. The server compares that origin to its bound address and port.
Tokens are short-lived, stateless, redacted from ordinary representations, and verified before any
idempotency reservation or mutation.

Job and workflow cancellation require a second one-time HMAC proof. The proof binds principal,
command UUID, action, target, fingerprint, and hashed idempotency key. The bounded confirmation store
retains only proof and binding digests, timestamps, and consumption state. Replay, mismatch,
expiration, and malformed proof share one generic rejection.

The HTTP adapter accepts only fixed POST routes, bounded JSON bodies, exact singleton protection
headers, and a configured command-concurrency limit. It emits safe Event Bus facts for completed,
rejected, and confirmation-issued operations so the Security Journal records command activity without
request bodies or credentials.

## Consequences

Same-origin browser commands remain practical without cookies, external frameworks, or persistent
CSRF sessions. Destructive requests require an explicit two-step flow and cannot reuse a consumed
proof. Non-browser clients must intentionally supply the same origin and protection headers and remain
limited to the loopback listener.
