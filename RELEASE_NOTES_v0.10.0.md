# Phoenix OS v0.10.0 — Identity, Authentication and Sessions

Phoenix OS v0.10.0 implements RFC-0010 and introduces the trusted boundary between external
credential providers, authenticated identities, revocable sessions, and the centralized Policy
Engine.

## Highlights

- immutable redacted credential and authentication-request contracts;
- authenticated user, service, plugin, and system identities;
- explicit synchronous and asynchronous provider registration;
- opaque cryptographically random bearer sessions;
- SHA-256 digest persistence without raw token storage;
- absolute and idle expiration, touch intervals, and session limits;
- revocation by identifier, token, or identity;
- in-memory and State Store-backed repositories;
- session-derived Security, Capability, and State contexts;
- task-local context propagation through `contextvars`;
- authenticated Kernel adapter;
- Runtime composition and deterministic lifecycle ownership;
- correlated events, metrics, logs, and spans with secret-safe payloads.

## Security model

The core does not verify passwords, JWTs, OAuth, OIDC, LDAP, SAML, passkeys, or operating-system
accounts. Those protocols remain behind trusted `AuthenticationProvider` adapters. Session tokens
are bearer capabilities and still require secure transport, process memory, and deployment controls.
SHA-256 is used only for high-entropy random session tokens, not human passwords.

## Architecture records

- RFC-0010 — Identity, Authentication and Sessions;
- ADR-0020 — Opaque bearer tokens and one-way digests;
- ADR-0021 — Provider boundary and session-derived security context.

## Validation

- Ruff approved;
- Ruff Format approved;
- mypy strict approved;
- 367 tests approved;
- ten examples executed successfully;
- wheel built and installed in an isolated virtual environment;
- isolated authentication and session smoke test approved.

## Compatibility

This release preserves the public contracts introduced in RFC-0001 through RFC-0009 and requires
Python 3.12 or newer.
