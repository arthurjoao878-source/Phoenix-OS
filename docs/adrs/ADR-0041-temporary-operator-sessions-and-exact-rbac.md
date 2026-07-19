# ADR-0041 — Temporary operator sessions and exact RBAC

- Status: Accepted
- Date: 2026-07-19

## Context

Long-lived local operator credentials should not be sent with every Dashboard request. Administrative
commands and operator management also need exact attribution and permissions without introducing
cookies, remote identity providers, or account-enumeration responses.

## Decision

The loopback Dashboard exchanges a long-lived operator bearer for a bounded temporary session. The
session store retains only SHA-256 digests, enforces absolute expiry, total and per-operator limits,
and invalidates sessions after logout, credential rotation, disablement, revocation, or explicit
administrative revocation. Login throttling stores only authorization fingerprints and all external
login failures share one response shape.

Built-in Viewer, Operator, and Maintainer roles grant deterministic permission sets. Operator-specific
permissions are additive. HTTP management routes use exact permission checks, origin-bound CSRF
validation, optimistic record revisions, allowlisted serializers, and credential-free audit facts.
Command journal writes bind the request-local authenticated username through a context-local scope so
concurrent operators retain correct attribution.

## Consequences

The Dashboard keeps only a temporary session token in browser session storage. State-changing operator
management remains loopback-only and protected by the same browser-origin boundary as command
operations. Sessions are intentionally process-local and must be reissued after a process restart,
while operators and long-lived credential digests remain durable.
