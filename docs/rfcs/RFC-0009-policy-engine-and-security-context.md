# RFC-0009 — Policy Engine and Security Context

- Status: Accepted
- Version: 1.0
- Target: Phoenix OS 0.9.0

## Summary

Phoenix OS requires one deterministic authorization vocabulary shared by capabilities, plugins,
state stores, services, and future adapters. This RFC introduces an immutable `SecurityContext`,
declarative `PolicyRule` contracts, an explainable deny-by-default `PolicyEngine`, and adapters for
existing subsystem boundaries.

The engine answers authorization questions. It does not authenticate users, issue credentials,
manage secrets, or sandbox Python code.

## Goals

- represent trusted identity, roles, permissions, scopes, attributes, correlation, and confirmation;
- express portable rules without executing arbitrary predicates;
- evaluate rules deterministically with explicit priority;
- deny when no rule matches;
- distinguish `ALLOW`, `DENY`, and `REQUIRE_CONFIRMATION`;
- return a structured explanation for every decision;
- emit safe events, metrics, logs, and spans;
- integrate through adapters without coupling the Kernel to policy internals;
- preserve all existing public contracts.

## Non-goals

- user authentication, session issuance, OAuth, OIDC, or certificate validation;
- a remote policy language or vendor protocol;
- dynamic code evaluation inside rules;
- a hostile-code sandbox;
- storage of secrets or identity records;
- distributed policy replication or hot reload.

## Security context

`SecurityContext` is immutable and host-owned. Adapters must construct it only from trusted input.
It contains:

- `principal` and `principal_type`;
- authenticated state;
- roles, permissions, and scopes;
- non-secret string attributes;
- correlation and causation identifiers;
- explicit confirmation state.

Anonymous principals cannot be marked authenticated. Collections and attributes are normalized and
frozen. The context is authorization input, not proof that authentication occurred.

## Policy request

A `PolicyRequest` asks whether one normalized `action` may target one normalized `resource` under a
security context. Optional request attributes describe safe facts such as risk level, version, tenant,
or environment.

Examples:

```text
capability.invoke -> capability:files.delete
state.read        -> state:profile:arthur
plugin.start      -> plugin:nova.voice
runtime.read      -> runtime:self
```

## Declarative rules

A `PolicyRule` declares:

- stable rule identifier;
- effect;
- action, resource, and principal glob patterns;
- optional principal types;
- required roles, permissions, and scopes;
- optional authenticated-state requirement;
- exact string attributes;
- integer priority;
- safe explanation and metadata.

Rules contain no callbacks. This keeps evaluation portable, inspectable, and deterministic.

## Evaluation order

Rules are ordered by:

1. higher priority first;
2. at equal priority, `DENY` before `REQUIRE_CONFIRMATION` before `ALLOW`;
3. registration order.

The first matching rule decides. Every matching rule identifier is included in the decision for
diagnostics. A higher-priority rule may intentionally override a lower-priority rule. Equal-priority
security restrictions win over grants.

When no rule matches, the decision is `DENY` with an explicit default-deny explanation.

A confirmation rule returns `REQUIRE_CONFIRMATION` until the trusted context carries
`confirmed=True`. The same rule then resolves to `ALLOW` with `confirmation_satisfied=True`.

## Enforcement

`PolicyEngine.evaluate()` always returns a decision. `PolicyEngine.enforce()` returns an allowed
decision or raises a structured denial/confirmation exception that retains the decision.

Cancellation propagates. Event or observability exporter failures remain isolated according to the
existing Event Bus and Observability contracts.

## Integration

### Capability Registry

`PolicyPermissionPolicy` and `PolicyConfirmationPolicy` translate capability invocations into
`capability.invoke` requests. Existing Registry error translation remains unchanged.

### State Store

`PolicyStateStore` decorates any `StateStore`. It authorizes reads, writes, deletes, lists,
transactions, snapshots, restoration, maintenance, and statistics. The default context resolver uses
reserved `StateOperationContext.metadata` fields; deployments may provide a stricter resolver.

### Plugins

`PolicyProtectedPlugin` decorates a plugin and authorizes setup and startup. Stop hooks are never
blocked after resources may have been acquired. The Plugin SDK remains an authority boundary, not a
sandbox.

### Runtime

`RuntimeAssembler` can expose a Policy Engine as the named `policy` service and own its lifecycle.
The engine starts before State and Plugins and stops after them, while Observability remains active.

## Observability and privacy

The engine emits `policy.evaluated` facts and decision counters. Restricted decisions create warning
logs. Signals contain action, resource, principal, principal type, effect, rule identifier, and
confirmation state. Rule request attributes, permissions, scopes, and secrets are not exported by
default.

## Failure and lifecycle semantics

- registration is allowed only while the engine is open;
- duplicate rule identifiers are rejected;
- unregistration uses opaque handles;
- close clears all rules and rejects further evaluation;
- start is immediate and stop closes the engine;
- snapshots expose counts and rule identifiers, not request details.

## Acceptance criteria

- immutable contracts and deterministic matching;
- default deny;
- priority and equal-priority restriction precedence;
- confirmation resolution;
- structured enforcement errors;
- Capability, State, Plugin, Event Bus, Observability, and Runtime integration;
- strict typing, formatting, linting, and automated tests;
- no new runtime dependency.
