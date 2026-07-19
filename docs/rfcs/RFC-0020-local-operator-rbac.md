# RFC-0020 — Local Operator Identity and Role-Based Access Control

- Status: Accepted
- Target: Phoenix OS v0.20.0

## Summary

Phoenix OS will replace the single anonymous administrator bearer with identified local operators,
role-based permissions, temporary administrative sessions, durable State Store persistence, access
audit events, and a bounded local management surface.

This RFC keeps the built-in control plane loopback-only. It does not introduce remote identity,
password authentication, external directories, hosted administration, or implicit privilege grants.

## Security goals

- every administrative principal has a stable local operator identity;
- plaintext operator tokens are never persisted, logged, serialized, or included in exceptions;
- role permissions are explicit, deterministic, and additive only through reviewed grants;
- inactive or revoked operators cannot authenticate;
- credential rotation invalidates prior credentials without changing operator identity;
- sessions are bounded, expiring, revocable, and tied to one operator;
- login, logout, access failures, credential changes, and operator changes are auditable without
  exposing credentials;
- responses avoid account-enumeration signals;
- State Store corruption and incompatible schemas fail closed.

## Built-in roles

### Viewer

May authenticate and read the local control plane.

### Operator

Includes Viewer permissions and may create jobs, retry dead-letter jobs, cancel jobs, and cancel
workflows through the RFC-0018 command protections.

### Maintainer

Includes Operator permissions and may list, create, update, disable, rotate, and revoke local
operator access and administrative sessions.

Operator-specific additional permissions are explicit immutable grants. They never remove the
permissions implied by the selected built-in role.

## Slice plan

1. **Completed in this slice:** immutable operator, role, permission, token-digest, pagination,
   snapshot, registry, and bounded in-memory reference contracts.
2. **Completed in this slice:** State Store persistence, canonical encoding, index integrity, and corruption detection.
3. **Completed in this slice:** constant-time operator authentication, credential rotation, deactivation, reactivation, and terminal revocation.
4. **Completed in this slice:** temporary administrative sessions, rate limits, generic failures, and access audit events.
5. **Completed in this slice:** Dashboard management, history filters, RuntimeAssembler integration, ADRs, and v0.20.0 release.

## Slice 1 boundaries

The first slice does not replace `AdminTokenAuthenticator` yet. It defines the new identity boundary
and a reference registry while preserving the v0.19.0 transport behavior until persistence and
session authentication are implemented in later slices.

Operator records contain only SHA-256 credential digests. The `ControlPlaneOperatorToken` wrapper is
one-time input with redacted `str` and `repr`. Registry indexes are unique by UUID, normalized
username, and token digest. Replacements use optimistic revisions and cannot rewrite creation time or
schema version.


## Slice 2 boundaries

The durable registry stores one schema-v1 operator envelope plus independent username and token-digest indexes. Record bytes use canonical JSON and a SHA-256 integrity digest. Every read validates exact allowlisted fields, supported schemas, normalized identities, state-key bindings, index cardinality, record/index agreement, optimistic revisions, and canonical permission ordering. Adds and replacements update records and both indexes atomically through the State Store transaction boundary.

The registry borrows the State Store lifecycle and therefore survives registry reconstruction and process-level Runtime restarts when backed by a durable provider. Plaintext tokens remain outside the persistence contract. Authentication, credential rotation workflows, sessions, rate limits, and management HTTP routes remain deferred to later slices.


## Slice 3 boundaries

The operator authenticator accepts only bounded, syntactically valid Bearer credentials, converts the plaintext to a SHA-256 digest immediately, performs an explicit constant-time digest comparison, and returns identified authentication evidence containing only the operator UUID, current principal, token version, and authentication time. Missing, malformed, unknown, disabled, and revoked credentials all produce the same unauthenticated result. Registry corruption and persistence failures remain visible as typed operational failures so the transport can fail closed.

The operator manager owns credential and status lifecycle mutations. Credential rotation atomically replaces the token-digest index, increments token and record versions, invalidates the previous bearer, and emits only a credential-free mutation receipt. Disabled operators may rotate credentials without becoming active. Deactivation is reversible only through an explicit reactivation transition. Revocation is terminal, prevents future authentication and rotation, and preserves prior disable metadata. Every mutation uses optimistic revisions and rejects backwards or naive clocks.

Management HTTP routes, Dashboard controls, durable Runtime ownership, and final transport replacement remain deferred to the final slice.


## Slice 4 boundaries

Temporary operator sessions are bounded by a fixed maximum lifetime, per-operator active-session limit, and total in-memory capacity. Session bearers are generated as one-time values, represented only through redacted wrappers, indexed by SHA-256 digest, and never persisted or emitted. Every session is bound to the operator UUID and credential version that created it. Expiry, logout, administrative revocation, operator deactivation or revocation, and credential rotation invalidate a session without reusing its bearer.

Login failures use one generic exception and one generic external audit shape for missing, malformed, unknown, disabled, revoked, and throttled credentials. A bounded sliding-window limiter tracks only protected authorization fingerprints and clears successful buckets. Authentication and session events contain allowlisted operator, session, outcome, action, resource, and result-code facts but never token material, digests, authorization headers, or internal exception text. The Event Bus remains best-effort so an unavailable audit subscriber cannot reopen access or leak credentials.


## Slice 5 boundaries

The final slice adds strict loopback HTTP routes for login, logout, current-session identity, operator listing and creation, role/display-name updates, credential rotation, disablement, reactivation, terminal revocation, and administrative session revocation. All state-changing management routes require exact permissions, the authenticated temporary session, and origin-bound CSRF validation. Creation and rotation return a plaintext credential exactly once with cache prevention; registry reads and audit events remain digest-free.

Command history accepts an exact normalized operator filter, and journal-backed idempotency binds the authenticated principal through a context-local scope so concurrent commands preserve correct attribution. The Dashboard exchanges the bootstrap credential for a temporary session, displays the current operator, exposes maintainer controls, and filters durable history by operator.

`RuntimeAssembler` supports automatic in-memory or State Store-backed operator registries, optional first-start maintainer bootstrap, Runtime-owned session/access lifecycle, public service lookup, and legacy `AdminTokenAuthenticator` compatibility. RFC-0020 is accepted together with ADR-0040 and ADR-0041, and the package version advances to 0.20.0.
