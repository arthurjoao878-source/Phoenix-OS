# RFC-0021 — Durable Operator Sessions and Step-Up Authentication

- Status: Accepted
- Target release: Phoenix OS v0.21.0
- Authors: Phoenix contributors
- Created: 2026-07-19

## Summary

RFC-0021 replaces process-local administrative sessions with durable, rotating, revocable local
operator sessions backed by the Phoenix State Store. Session cookies will become `HttpOnly` and
`SameSite=Strict`, CSRF protection will rotate with each session generation, and sensitive operator
mutations will require recent step-up authentication with the durable operator credential.

The built-in control plane remains loopback-only. This RFC does not introduce remote access,
external identity providers, passwords, TLS termination, or browser-readable session tokens.

## Security goals

- plaintext session tokens and CSRF secrets are never persisted, logged, serialized, or included in
  exceptions;
- session records are bound to one operator UUID, normalized username, operator revision, durable
  credential version, and token generation;
- absolute and idle expiry are independently enforced and persisted;
- periodic token rotation does not extend the original absolute session lifetime;
- each rotation creates explicit predecessor and successor lineage so the previous token remains
  durably terminal and cannot be replayed;
- operator role, permission, status, or durable credential changes invalidate affected sessions;
- repository mutations use optimistic revisions and deterministic lifecycle rules;
- concurrent sessions are bounded globally and per operator;
- terminal session retention never removes active sessions;
- incompatible schemas or corrupted records fail closed;
- step-up authentication is required for reviewed high-risk operator actions.

## Durable session lifecycle

```text
active -> revoked
       -> expired
       -> rotated -> active successor generation
```

`revoked`, `expired`, and `rotated` are terminal. Rotation creates a new active record with the same
operator identity, operator revision, durable credential version, and absolute expiry. The old token
digest remains associated with a terminal record until controlled retention removes it.

## Expiration model

Every active record persists three independent deadlines:

- `absolute_expires_at`: fixed at initial issuance and never extended by activity or rotation;
- `idle_expires_at`: refreshed after bounded authenticated activity but clamped to absolute expiry;
- `rotate_after`: marks when the active token should be replaced by a new generation.

Absolute timeout wins when both deadlines are reached. Expiration decisions use timezone-aware
clocks and never depend on process-local timers alone.

## Slice plan

### Slice 1 — Durable contracts and in-memory reference repository

Completed in this branch:

- redacted one-time durable session token and CSRF-secret wrappers;
- SHA-256-only token and CSRF persistence boundaries;
- schema-v1 `ControlPlaneDurableSessionRecord`;
- active, revoked, expired, and rotated states;
- explicit credential-free termination reasons;
- operator revision, credential version, and token-generation binding;
- predecessor and successor rotation lineage;
- bounded absolute TTL, idle TTL, rotation interval, terminal retention, and per-operator policy;
- deterministic expiration and rotation decisions;
- bounded page, snapshot, rotation, and repository contracts;
- exact operator and status filters;
- bounded in-memory reference repository;
- unique session UUID and token-digest indexes;
- optimistic touch, terminate, rotate, and terminal-delete mutations;
- atomic in-memory token rotation without extending absolute expiry;
- deterministic newest-first pagination and active-session listing;
- typed duplicate, not-found, conflict, capacity, and closed errors.

### Slice 2 — State Store persistence and corruption detection

Completed in this branch:

- `StateControlPlaneDurableSessionRepository` backed by the Phoenix State Store;
- canonical schema-v1 JSON record documents and SHA-256 record checksums;
- atomic record, token-index, operator-index, and lineage-index creation;
- atomic optimistic touch, termination, rotation, and terminal deletion;
- durable token lookup for active and terminal generations;
- exact session UUID, token digest, operator/session, and lineage key binding;
- strict allowlisted envelope, record, and index decoding;
- canonical UUID and timezone-aware ISO-8601 validation;
- restart recovery of active, revoked, expired, and rotated records;
- direct predecessor/successor verification and full rotation-chain validation;
- duplicate UUID, token digest, CSRF digest, cross-digest, and index detection;
- missing, orphaned, mismatched, and wrong-key index detection;
- configured global and active-per-operator capacity validation after restart;
- schema-specific, corruption, persistence, conflict, and closed errors;
- borrowed State Store lifecycle without closing the Runtime-owned store.

### Slice 3 — Durable authentication, rotation, and expiry

Completed in this branch:

- restart-safe session issuance from freshly authenticated operator evidence;
- constant-time session-token comparison for known, unknown, and malformed candidates;
- generic rejection without token, digest, or account disclosure;
- persisted idle activity refresh clamped to the original absolute expiry;
- deterministic absolute-before-idle timeout reconciliation;
- automatic one-time token and CSRF-secret rotation when the persisted deadline is due;
- atomic predecessor termination and successor generation creation;
- replay-safe rejection of rotated predecessor tokens without creating duplicate successors;
- immutable absolute expiry across every rotation generation;
- operator status, durable credential version, revision, and username binding checks;
- explicit invalidation reasons for inactive operators, credential rotation, and access changes;
- individual session logout and administrative revocation;
- bounded revocation of every active generation for one operator;
- access counters without credentials, digests, or exception text;
- `StateControlPlaneDurableSessionRepository` restart authentication coverage;
- bounded recovery passes for overdue and stale active records;
- Runtime-compatible recovery worker lifecycle and safe typed error counters.

### Slice 4 — HttpOnly cookies, CSRF rotation, and step-up authentication

Completed in this branch:

- host-only root-scoped session cookies with mandatory `HttpOnly` and `SameSite=Strict`;
- optional `Secure` policy for deployments terminating HTTPS outside the built-in loopback server;
- strict bounded cookie parsing with duplicate-session-cookie rejection;
- durable operator credential exchange into one session cookie and one browser-readable CSRF token;
- no session bearer in JSON response bodies or browser JavaScript storage contracts;
- exact loopback-origin binding for every CSRF token;
- CSRF secret digest verification against the active durable session record;
- session UUID and generation binding so predecessor CSRF evidence cannot cross rotation;
- atomic session-token and CSRF-token replacement headers after automatic rotation;
- generic login, cookie, and CSRF rejection without account or session enumeration;
- persistent logout paired with unconditional browser-cookie clearing;
- configurable recent-authentication window bounded to thirty minutes;
- durable credential reauthentication for the same current operator;
- signed step-up proofs bound to session UUID, generation, operator UUID, operator revision,
  credential version, exact sensitive action, and recent-authentication deadline;
- reviewed actions for Maintainer creation, access changes, credential rotation, operator
  revocation, and global session revocation;
- fail-closed proof invalidation after session termination, operator status changes, role or
  permission changes, and durable credential rotation;
- credential-free step-up counters and redacted proof wrappers.

### Slice 5 — History, retention, Dashboard, Runtime, and v0.21.0

Completed in this branch:

- authenticated allowlisted session history with exact operator and status filters;
- explicit `control-plane.operator-sessions.read` Maintainer permission;
- terminal-only bounded age/count retention with optimistic revision fencing;
- protection of active records and rotation-lineage records from unsafe standalone deletion;
- safe issuance, renewal, expiry, rotation, logout, and revocation Event Bus facts;
- cookie-authenticated operator, session-history, and operator-management HTTP routes;
- action-specific step-up enforcement for reviewed high-risk mutations;
- Dashboard removal of browser-readable session bearer storage;
- Dashboard session history, operator/status filters, individual termination, and global revocation;
- automatic State Store or bounded in-memory repository selection in `RuntimeAssembler`;
- Runtime lifecycle ownership of repository, access, recovery, retention, and HTTP components;
- public service lookup for durable sessions, history, recovery, retention, and step-up;
- ADR-0042 and ADR-0043;
- migration guidance, release notes, package exports, and version 0.21.0.

## Accepted architecture

The durable session repository owns all persisted authorization evidence and is closed only after the
HTTP server, access service, recovery worker, and retention worker stop. In operator mode the HTTP
server authenticates protected routes exclusively from the session cookie; the durable credential is
accepted only by login and step-up endpoints. Legacy `AdminTokenAuthenticator` mode remains a
mutually exclusive compatibility path.

The session token appears only in `Set-Cookie`; rotating CSRF evidence appears only in the dedicated
response header. Neither value is persisted in plaintext or returned in JSON. Safe history and audit
facts use explicit allowlists. Terminal retention never deletes active records and currently protects
records participating in rotation lineage rather than weakening replay evidence.

RFC-0021 is accepted with ADR-0042 and ADR-0043.

## Non-goals

RFC-0021 does not provide arbitrary remote administration, federated login, password storage,
browser-readable bearer tokens, unlimited sessions, silent privilege escalation, or recovery of a
revoked operator identity.
