# Phoenix OS v0.21.0 — Durable Operator Sessions and Step-Up Authentication

Phoenix OS 0.21.0 implements RFC-0021 and replaces process-local browser bearer sessions with
restart-safe, rotating, revocable operator sessions and action-specific recent authentication.

## Highlights

- bounded in-memory and State Store-backed durable session repositories;
- absolute and idle expiry with immutable initial lifetime;
- atomic token and CSRF rotation with predecessor/successor lineage;
- constant-time digest authentication and replay rejection;
- automatic invalidation after operator status, role, permission, or credential changes;
- Runtime-owned restart recovery and terminal-only retention workers;
- authenticated, operator-filtered session history;
- safe session issuance, renewal, rotation, expiry, logout, and revocation events;
- host-only `HttpOnly`, `SameSite=Strict` Dashboard session cookie;
- no browser-readable session bearer or `sessionStorage` token;
- session- and origin-bound rotating CSRF evidence;
- step-up authentication for reviewed high-risk operator mutations;
- Dashboard session inspection, individual termination, and global operator-session revocation;
- accepted RFC-0021 and ADR-0042/0043.

## Security model

Only SHA-256 digests of session tokens and CSRF secrets are persisted. HTTP responses, history,
snapshots, audit facts, and errors omit tokens, digests, authorization headers, durable credentials,
and internal exception text. Step-up proofs are HMAC protected, action-specific, short lived, and
bound to current operator and session revisions.

## Compatibility

`AdminTokenAuthenticator` remains available for transitional loopback integrations. Operator mode now
uses cookies rather than an `Authorization` bearer after login. Custom clients must retain the
`Set-Cookie` value, send it on protected requests, read `X-Phoenix-CSRF`, and replace both values when
a response rotates them. Sensitive operator mutations additionally require `X-Phoenix-Step-Up`.

## Validation

- Ruff lint and formatting passed;
- mypy strict passed;
- complete regression suite passed;
- wheel and source distribution passed Twine validation;
- durable session, cookie, step-up, history, retention, and Dashboard assets are packaged;
- package version reports 0.21.0.
