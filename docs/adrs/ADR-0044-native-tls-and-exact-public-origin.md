
# ADR-0044 — Native TLS and exact public-origin runtime binding

- Status: Accepted
- Date: 2026-07-19

## Context

The original Phoenix Dashboard listener was intentionally restricted to literal loopback HTTP.
Remote administration requires transport confidentiality, certificate health, Secure cookies,
and one browser origin that agrees with socket, Host, and CSRF validation. Independent settings
could otherwise create a listener that is reachable under a different authority than the one
authenticated by the browser.

## Decision

Remote exposure uses a native hardened `ssl.SSLContext` and an immutable
`ControlPlaneNetworkPolicy`. The policy binds exposure mode, literal bind address, fixed port,
canonical public origin, TLS mode, certificate material, client networks, trusted proxies,
cookie security, and per-client connection limits as one fail-closed contract.

`RuntimeAssembler` selects the policy-aware server only when a policy is explicitly supplied.
Native TLS, optional client-certificate verification, certificate metadata, reload, network
guard, and HTTP application share one Runtime-owned lifecycle. HTTP Host, browser Origin,
session-cookie Secure policy, and CSRF evidence use the same canonical public origin.

## Consequences

Upgrades do not silently widen the listener. Remote configuration is more explicit and requires a
fixed port, but ambiguity is rejected before startup. Certificate paths and private-key material
remain absent from public snapshots. Operators must provide certificate issuance, renewal,
filesystem protection, DNS, firewall policy, and operational monitoring.
