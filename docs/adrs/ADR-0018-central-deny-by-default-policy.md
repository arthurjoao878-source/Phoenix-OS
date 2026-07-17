# ADR-0018 — Central deny-by-default policy

- Status: Accepted
- Date: 2026-07-17

## Context

Capability permissions, plugin authority, and State access need one explainable decision model.
Independent ad-hoc checks create inconsistent defaults and make audits difficult.

## Decision

Phoenix OS adopts an in-process `PolicyEngine` with immutable requests, declarative rules, three
outcomes, and a default-deny result when no rule matches. Adapters translate existing subsystem
contexts into the central model; the Kernel remains unaware of the engine.

## Consequences

Authorization semantics become consistent and testable. Deployments must register explicit grants.
Authentication and credential verification remain external responsibilities.
