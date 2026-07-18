# ADR-0021 — Provider boundary and session-derived security context

- Status: Accepted
- Date: 2026-07-18

## Context

Authentication protocols vary by deployment, while Policy Engine requires one trustworthy and
portable security representation. Letting request handlers accept caller-supplied roles or construct
ad hoc contexts would bypass the authorization boundary.

## Decision

Authentication protocols remain behind `AuthenticationProvider`. Successful providers return an
immutable `Identity`. `AuthenticationManager` records provider provenance, issues a session, and
sessions derive `SecurityContext` values. Context variables propagate the trusted session during
asynchronous execution. Adapters translate the same session into Kernel, Capability, and State
contexts.

## Consequences

- Policy Engine remains independent from OAuth, LDAP, password, and token libraries;
- identity facts have one trusted construction path;
- provider adapters are testable and replaceable;
- hosts must protect provider registration and session tokens;
- context propagation is convenient but not authentication by itself: a session must be resolved
  before it is bound.
