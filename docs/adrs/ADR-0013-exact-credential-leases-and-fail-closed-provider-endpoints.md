# ADR-0013: Exact credential leases and fail-closed provider endpoints

- **Status:** Accepted
- **Date:** 2026-07-27
- **Related RFC:** [RFC-0026](../rfcs/RFC-0026-secure-model-providers-and-inference-runtime.md)

## Context

Hosted and local providers may require credentials and network destinations.
Ambient environment credentials, mutable secret names, caller-selected URLs,
redirects, proxies, or partial DNS admission could leak credentials or create an
SSRF and TLS-downgrade boundary.

## Decision

Provider authentication references an exact versioned `SecretRef`. The inference
Runtime acquires the minimum credential lease immediately before adapter
execution and revokes leases after completion, failure, timeout, cancellation,
or bounded shutdown cleanup.

Plaintext credentials never enter inference requests, responses, events, audit,
metrics, health, ordinary persistence, or administrative views.

For hosted providers, Phoenix and the reviewed adapter resolve, admit, and pin
every destination before use. Hosted endpoints require canonical HTTPS,
certificate verification, finite timeouts, admitted ports and networks, and
credential transmission only to the reviewed destination.

All DNS answers must be admitted. Redirects and ambient proxies remain disabled.
Requests cannot alter endpoint, Host, proxy, DNS, TLS, certificate, redirect, or
credential-destination policy.

Plain HTTP remains limited to explicit loopback-local configuration when every
resolved address is loopback. A local provider does not create a second Phoenix
listener.

## Consequences

Positive consequences:

- credentials are short-lived in adapter execution;
- configuration identifies one immutable secret version;
- SSRF, redirect, proxy, DNS-rebinding, and TLS downgrade fail closed;
- callers cannot redirect credentials;
- endpoint URLs and secret details remain outside safe administration.

Costs and constraints:

- operators must rotate by creating and reviewing new secret versions;
- adapters must accept pinned destination and no-ambient-proxy behavior;
- every DNS answer is evaluated, which may reject mixed public/private results;
- hosted integrations require explicit network policy and certificate
  verification.

## Alternatives considered

### Read API keys from ambient environment variables inside adapters

Rejected because credential provenance, version, lease lifetime, audit, and
revocation would be outside Phoenix control.

### Allow unversioned secret references

Rejected because execution could silently change credential material.

### Follow provider redirects automatically

Rejected because redirects may escape the reviewed destination or leak
authorization.

### Admit one safe DNS answer and ignore unsafe answers

Rejected because selection or rebinding could reach a forbidden address.

### Permit HTTP for private networks

Rejected because private does not imply authenticated, encrypted, or loopback.

## Supersession criteria

A future ADR may alter credential or endpoint plumbing only if exact secret
versioning, bounded leases, complete destination admission, verified hosted TLS,
redirect/proxy denial, and credential-destination binding remain fail-closed.
