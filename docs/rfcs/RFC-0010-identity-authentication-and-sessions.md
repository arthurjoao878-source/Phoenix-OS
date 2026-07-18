# RFC-0010 — Identity, Authentication and Sessions

- Status: Accepted
- Target: Phoenix OS 0.10.0
- Authors: Phoenix contributors
- Updated: 2026-07-18

## Summary

Phoenix OS requires a trusted boundary that converts provider-specific credentials into authenticated
identities, revocable sessions, and immutable `SecurityContext` values. This RFC introduces that
boundary without embedding OAuth, LDAP, password databases, operating-system accounts, token
validation libraries, or remote identity services in the core.

## Goals

- define immutable credential, identity, session, grant, registration, and snapshot contracts;
- keep raw credentials and bearer tokens redacted by default;
- support synchronous and asynchronous authentication providers;
- register providers explicitly and resolve them deterministically;
- issue cryptographically random bearer tokens and persist only SHA-256 digests;
- enforce absolute expiry, optional idle expiry, touch intervals, and per-identity session limits;
- support session lookup, revocation, identity-wide revocation, expiry, and lifecycle shutdown;
- derive `SecurityContext`, `CapabilityContext`, and `StateOperationContext` from trusted sessions;
- propagate session and security context through asynchronous tasks;
- provide in-memory and State Store-backed session repositories;
- emit correlated events, metrics, logs, and spans without exporting secret material;
- compose the authentication manager through `RuntimeAssembler`.

## Non-goals

The core does not:

- hash or verify passwords;
- validate JWT, OAuth, OIDC, SAML, Kerberos, LDAP, passkeys, or operating-system credentials;
- store user directories or password databases;
- provide account recovery, MFA enrollment, federation, or browser redirects;
- encrypt persistent State Store contents;
- replace TLS, process isolation, operating-system access control, or a secrets manager;
- treat possession of caller-provided roles or permissions as proof of authentication.

Those concerns belong to trusted provider and deployment adapters.

## Contracts

### AuthenticationCredential

A credential contains a normalized scheme, a `SecretValue`, and safe provider attributes. The secret
is excluded from representations and must be explicitly revealed inside a provider implementation.

### AuthenticationRequest

A request identifies the selected provider and carries correlation metadata. Provider diagnostics
must never include the credential or its revealed value.

### Identity

An identity contains a stable subject, principal type, provider, roles, permissions, scopes,
attributes, and authentication time. Anonymous identities are invalid because an `Identity` is the
result of successful authentication.

### Session and SessionGrant

`Session` contains public metadata only. It never contains a bearer token or token digest.
`SessionGrant` returns a newly issued session and a redacted `SecretValue` token. The token is shown
only once to the trusted caller and should be transported through an external secure channel.

### SessionRecord

Repositories store a `SessionRecord` containing the session and a one-way SHA-256 token digest. A
repository must never persist the raw bearer token.

## Provider model

Providers implement one method:

```python
class AuthenticationProvider(Protocol):
    def authenticate(
        self,
        request: AuthenticationRequest,
    ) -> Identity | Awaitable[Identity]: ...
```

Provider registration is explicit. Duplicate names are rejected. Missing providers, deliberate
credential rejection, cancellation, and unexpected provider failures have distinct errors.
`CallableAuthenticationProvider` adapts existing synchronous or asynchronous Nova callbacks.

The manager overwrites `Identity.provider` with the selected registered provider name, preventing a
provider result from spoofing provenance.

## Session lifecycle

The default policy applies:

- eight-hour absolute lifetime;
- thirty-minute idle lifetime;
- thirty-second touch interval;
- at most eight active sessions per identity.

Hosts may supply a different immutable `SessionPolicy`. A requested lifetime may shorten but never
extend the configured absolute lifetime.

Resolution hashes the supplied bearer and looks up the digest. Revoked sessions fail with
`SessionRevokedError`; expired sessions are persisted as expired and fail with
`SessionExpiredError`; unknown tokens fail with `SessionTokenInvalidError`.

Revocation is idempotent. Identity-wide revocation processes sessions in deterministic repository
order. Runtime shutdown closes the manager and its repository.

## Repositories

`InMemorySessionRepository` is the default and is intended for tests, local runs, and ephemeral
processes.

`StateSessionRepository` stores JSON-safe session records through any `StateStore`. It borrows the
store lifecycle and therefore does not close the underlying store. A deployment using
`PolicyStateStore` must explicitly allow the `phoenix.identity` system principal to access the chosen
session namespace.

External database repositories may implement `SessionRepository`; drivers, migrations, encryption,
connection pools, replication, and retries remain outside the core.

## Context propagation

`Session.security_context()` derives the central authorization context. Session identifiers and
provider provenance are added as safe attributes. Roles, permissions, and scopes come only from the
trusted provider result.

`session_scope()` binds the session and derived context with `contextvars`, so child asynchronous
operations can call `current_session()` or `current_security_context()` without global mutable state.
Nested scopes restore the previous context.

`capability_context_from_session()` and `state_context_from_session()` translate the same trusted
facts for existing subsystem adapters. `AuthenticatedKernel` validates a bearer before forwarding a
request and binds the session while the Kernel executes it.

## Security

- token generation defaults to `secrets.token_urlsafe(32)`;
- only SHA-256 token digests are retained;
- credentials and grants use `SecretValue` and hidden dataclass fields;
- events and observations contain provider, subject, session identifier, and outcome only;
- provider exception messages are not used as public authentication error messages;
- bearer tokens are capabilities and must be protected from logs, URLs, telemetry, crash reports,
  source control, and unencrypted storage;
- SHA-256 is used for high-entropy random bearer tokens, not for human passwords;
- password hashing remains a provider responsibility using a suitable password KDF.

## Events and diagnostics

The manager may emit:

- `identity.authentication.succeeded`;
- `identity.authentication.failed`;
- `identity.session.issued`;
- `identity.session.resolved`;
- `identity.session.expired`;
- `identity.session.revoked`.

It records authentication, resolution, and revocation counters and wraps provider authentication in
an asynchronous span. No signal contains raw credentials, raw bearer tokens, token digests,
permissions, or scopes.

## Runtime composition

`RuntimeAssembler(identity=manager)` exposes the manager as the reserved `identity` service. State
starts before Identity, allowing a State-backed repository to operate. Reverse shutdown closes
Identity before State. Plugins stop before Identity, so plugin cleanup can still resolve host
services.

## Compatibility

This RFC adds APIs without changing the public contracts of Kernel, Event Bus, Capability Registry,
Runtime, Configuration, Observability, State Store, Plugin System, or Policy Engine.

## Acceptance criteria

- public contracts are immutable and strictly typed;
- raw credentials and bearer tokens are absent from representations, events, and observations;
- provider registration, rejection, failure, and cancellation are covered by tests;
- issue, resolve, touch, expiry, revocation, limits, and snapshots are covered by tests;
- both repositories satisfy round-trip and lifecycle tests;
- session-derived contexts integrate with Kernel, Capability, State, Policy, and Runtime boundaries;
- Ruff, Ruff Format, mypy strict, pytest, examples, wheel build, and isolated installation pass.
