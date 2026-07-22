# ADR-0046 - Durable service accounts and one-time API tokens

- Status: Accepted
- Date: 2026-07-21

## Context

Machine integrations must not reuse durable operator credentials, browser
session cookies, CSRF evidence, or Maintainer authority. They need independent
identities whose authority can be restricted, expired, rotated, and revoked
without changing a human operator.

Persisting a complete bearer token would turn repository or State Store
disclosure into immediate credential disclosure. Returning an existing token
again would also remove the one-time presentation guarantee.

## Decision

Phoenix OS represents each machine client as a durable service account that is
separate from human operator roles and sessions. An account has an immutable
identifier, normalized name, display name, lifecycle status, timestamps, and an
optimistic revision.

API tokens are opaque `phx_sa_` bearer credentials. Complete token material is
returned only by issuance or rotation and is never persisted. Repositories keep
protected token digests and allowlisted metadata, including account identity,
label, exact scopes, resource restrictions, transport restrictions, status,
mandatory expiration, lineage, token version, and revision.

Authentication compares protected digests in constant time and revalidates the
current account and token state before authorization. Disabled or revoked
accounts and revoked or expired tokens fail authentication.

Rotation atomically creates a successor token. Any predecessor overlap is
explicit and bounded. Revocation is durable and immediate outside an approved
overlap. Only terminal token history is eligible for bounded retention.

`RuntimeAssembler` owns the lifecycle and selects the State Store-backed
repository when durable state is available. The bounded in-memory repository
remains a reference and test implementation.

## Consequences

Operators must capture a newly issued or rotated token when it is displayed.
Phoenix OS cannot recover or display that plaintext later.

Machine credentials can be rotated or revoked independently of human
credentials. Repository snapshots, logs, metrics, audit records, errors, and
health views cannot contain complete tokens or reusable digest material.

Deployments that require restart persistence must provide a durable State
Store. Deployments using the in-memory repository lose service-account state
when the process ends.
