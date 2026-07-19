# ADR-0043 — HttpOnly session cookies and step-up authentication

- Status: Accepted
- Date: 2026-07-19

## Context

A browser-readable bearer in `sessionStorage` exposes the administrative session to any script that
executes in the Dashboard origin. High-risk operator mutations also need evidence that the current
operator recently re-entered the durable credential, rather than relying only on an older session.

## Decision

The loopback Dashboard receives the session token only through a host-only, root-scoped `HttpOnly`,
`SameSite=Strict` cookie. The cookie has no `Domain` attribute; `Secure` is configurable for an
external HTTPS terminator. JavaScript receives a separate rotating CSRF token bound to the exact
loopback origin, session UUID, and generation. Token and CSRF material rotate atomically and the
previous generation becomes permanently terminal.

Maintainer creation, access changes, durable credential rotation, operator revocation, and global
session revocation require step-up authentication. The operator re-enters the durable credential and
receives a short-lived HMAC-SHA-256 proof bound to the exact action, current session generation,
operator UUID, operator revision, credential version, and recent-authentication window.

## Consequences

Dashboard JavaScript no longer stores or reads the session bearer. Cross-origin requests cannot use
the cookie for state changes without the session-bound CSRF evidence, and a stolen proof cannot be
reused for another action or after session/operator mutation. The built-in server remains
loopback-only and does not provide TLS; deployments that introduce an HTTPS boundary must enable the
`Secure` cookie policy there.
