# Phoenix OS v0.9.0 — Policy Engine and Security Context

Phoenix OS v0.9.0 implements RFC-0009 and introduces one deterministic authorization model for
capabilities, state, plugins, Runtime services, and future adapters.

## Highlights

- Immutable `SecurityContext` with principal type, authentication state, roles, permissions, scopes,
  safe attributes, correlation, causation, and confirmation.
- Declarative policy rules with action, resource, principal, identity, scope, permission, role, and
  attribute matching.
- Deny-by-default decisions with explicit explanations.
- Deterministic priority and equal-priority restriction precedence.
- `ALLOW`, `DENY`, and `REQUIRE_CONFIRMATION` outcomes.
- Structured enforcement exceptions retaining the complete decision.
- Capability permission and confirmation policy adapters.
- State Store decorator covering ordinary operations and transactions.
- Plugin decorator protecting setup and startup without blocking cleanup.
- Event Bus, logs, metrics, and spans for safe policy diagnostics.
- Optional `RuntimeAssembler` ownership as the named `policy` service.

## Security boundary

The Policy Engine performs authorization only. It does not authenticate principals, validate tokens,
issue sessions, store credentials, or sandbox loaded Python code. Hosts must create security contexts
from trusted inputs. Policy events intentionally omit roles, permissions, scopes, request attributes,
and secrets.

## Compatibility

The release preserves the existing Kernel, Event Bus, Capability Registry, Runtime, Configuration,
Observability, State Store, and Plugin System public contracts. Integrations are additive adapters.

## Validation

The release is validated with Ruff, Ruff Format, mypy strict, pytest, executable examples, wheel
construction, isolated installation, a policy smoke test, and SHA-256 package integrity hashes.
Exact results are recorded in `VALIDATION.md`.
