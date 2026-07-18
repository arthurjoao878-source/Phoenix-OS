# ADR-0022 — Secret references and short-lived leases

- Status: Accepted
- Date: 2026-07-18

## Context

Passing raw credentials through configuration, global variables, plugin registries, or long-lived
service objects makes disclosure difficult to audit and revoke. Phoenix requires a stable way to
name secret material without embedding it and a controlled way to grant temporary access.

## Decision

Configuration and subsystem contracts use immutable `SecretRef` values. Secret material is returned
only through principal-bound `SecretLease` objects containing a redacted `SecretValue`. Leases have a
positive bounded lifetime, are stored only in manager memory, and are invalidated when their exact
secret version is revoked.

All manager operations require authenticated `SecurityContext` and deny by default through the
Policy Engine or explicit fallback permissions.

## Consequences

- configuration and diagnostics can carry references without carrying material;
- rotation creates stable immutable versions;
- lease expiry limits accidental long-lived exposure;
- revocation can invalidate active access immediately inside the process;
- callers must request and protect a lease rather than cache raw values indefinitely;
- Python cannot guarantee zeroization of immutable objects, so process isolation remains important.
