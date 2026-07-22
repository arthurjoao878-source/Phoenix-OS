# RFC-0023: Service Accounts and Scoped API Tokens

- Status: Accepted
- Target release: Phoenix OS v0.23.0
- Owners: Phoenix OS maintainers

## Summary

RFC-0023 introduces durable service accounts and scoped API tokens for
non-browser clients, integrations, automation processes, and external services.

Human operators continue to use durable browser sessions, cookies, CSRF
protection, and step-up authentication. Machine clients authenticate through
explicit bearer tokens with bounded authority, expiration, rotation, revocation,
network restrictions, and complete security auditing.

## Motivation

Phoenix OS v0.22.0 established a secure remote control plane with native TLS,
trusted proxy handling, client-network allowlists, remote admission limits, and
protected operator authentication.

Machine integrations must not reuse human credentials, browser cookies, or
Maintainer sessions. They require independent identities and narrowly scoped
credentials with durable lifecycle management.

## Goals

- Durable service-account identities
- API tokens displayed exactly once
- Persisted protected token digests only
- Exact action scopes
- Optional resource restrictions
- Mandatory expiration
- Bounded token rotation overlap
- Immediate durable revocation
- Optional client CIDR restrictions
- Optional mutual-TLS identity binding
- Independent client and account throttling
- Safe security auditing
- RuntimeAssembler lifecycle ownership
- Maintainer administration routes and Dashboard controls

## Non-goals

- OAuth or OIDC provider implementations
- Social login
- WebAuthn
- Browser authentication through API tokens
- Direct shell execution
- Unrestricted operating-system automation
- Plaintext token persistence
- Automatic inheritance of human operator roles

## Security invariants

1. Complete API tokens are never persisted.
2. New token material is displayed exactly once.
3. Authorization remains deny-by-default.
4. Tokens receive only explicitly configured scopes.
5. Service accounts never inherit Maintainer authority implicitly.
6. Expiration, disablement, and revocation are checked before authorization.
7. Rotation overlap is explicit, short-lived, and bounded.
8. API-token authentication does not use cookies or CSRF.
9. Tokens are excluded from logs, errors, events, metrics, audit details, and snapshots.
10. Comparisons involving token digests use constant-time operations.
11. Network and mutual-TLS restrictions fail closed.
12. Existing v0.22.0 installations remain compatible without service accounts.

## Proposed contracts

- `ServiceAccount`
- `ServiceAccountStatus`
- `ServiceAccountRepository`
- `ApiTokenMetadata`
- `ApiTokenStatus`
- `ApiTokenScope`
- `ApiTokenRestriction`
- `ApiTokenAuthenticator`
- `ServiceAccountManager`
- `ServiceAccountSnapshot`

## Slice plan

### Slice 1 — Contracts and persistence

- [x] Immutable service-account and token contracts
- [x] Active, disabled, revoked, and expired states
- [x] In-memory repository
- [x] State Store-backed durable repository
- [x] Protected digest indexes
- [x] Strict decoding and corruption detection
- [x] Safe bounded snapshots

### Slice 2 — Issuance and lifecycle

- [x] Service-account creation and update
- [x] One-time token issuance
- [x] Mandatory expiration
- [x] Atomic token rotation
- [x] Bounded overlap period
- [x] Individual token revocation
- [x] Account-wide token revocation
- [x] Terminal-only bounded history retention

### Slice 3 — Authentication and authorization

- [x] Strict `Authorization: Bearer` parsing
- [x] Generic authentication failures
- [x] Exact action scopes
- [x] Optional resource restrictions
- [x] Separation from human operator sessions
- [x] Policy Engine integration
- [x] Safe authenticated API context propagation

### Slice 4 — Remote protections and audit

- [x] Per-client authentication throttling
- [x] Per-account authentication throttling
- [x] Optional client CIDR binding
- [x] Optional mutual-TLS identity binding
- [x] Replay and enumeration resistance
- [x] Protected audit facts
- [x] Safe metrics and health snapshots

### Slice 5 — Administration and v0.23.0

- [x] Maintainer-only management routes
- [x] Dashboard service-account administration
- [x] One-time token presentation
- [x] RuntimeAssembler integration
- [x] Migration guidance
- [x] Architecture Decision Records
- [x] Regression and security tests
- [x] Release notes and version 0.23.0

## Compatibility

Service accounts are optional. When none are configured, Phoenix OS preserves
the v0.22.0 operator-session and remote-control behavior.

Browser routes continue to require operator sessions, cookies, CSRF protection,
and step-up authentication. API tokens are accepted only by explicitly
allowlisted machine API routes.

## Acceptance

RFC-0023 is accepted for Phoenix OS 0.23.0. Service accounts remain optional,
machine routes remain explicitly allowlisted, and existing v0.22.0 operator-session
and remote-control behavior is preserved when service accounts are absent.
