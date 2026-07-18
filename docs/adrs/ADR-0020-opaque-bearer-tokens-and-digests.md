# ADR-0020 — Opaque bearer tokens and one-way digests

- Status: Accepted
- Date: 2026-07-18

## Context

Phoenix sessions require a credential that can be presented repeatedly without coupling the core to
JWT or another token format. Persisting a raw bearer would turn a State Store disclosure into active
session compromise.

## Decision

The core issues opaque tokens from a cryptographically secure generator. The token is returned once
inside `SecretValue`. Repositories retain only a lowercase SHA-256 digest and public session
metadata. Resolution hashes the presented bearer and compares through repository lookup.

SHA-256 is appropriate here because tokens have high random entropy. It is not approved for password
storage; password KDF selection remains a provider responsibility.

## Consequences

- a repository cannot recover or re-display bearer tokens;
- session resolution works with in-memory and durable repositories;
- token rotation requires issuing a new session or record;
- deployments must still protect bearer transport and process memory;
- state encryption and breach response remain deployment concerns.
