# RFC-0005 — Phoenix Configuration System

- **Status:** Accepted
- **Version:** 0.5.0
- **Date:** 2026-07-17

## Summary

Phoenix OS needs a deterministic boundary for configuration and dependency composition before Nova
3.x adapters, databases, AI clients, credentials, voice engines, and interfaces can be assembled
safely. This RFC defines immutable typed configuration, ordered sources, explicit secret handling,
and asynchronous singleton dependency composition without moving application-specific logic into
the Kernel, Event Bus, Capability Registry, or Runtime.

## Goals

- Decode raw values through an explicit schema.
- Preserve deterministic source precedence and value provenance.
- Reject missing, malformed, invalid, and unknown values safely.
- Redact secrets by default and require explicit reveal operations.
- Support in-memory, environment, and JSON file sources without third-party dependencies.
- Compose named singleton services from explicit dependency declarations.
- Detect missing dependencies and cycles before Runtime startup.
- Adapt lifecycle services into Runtime components automatically.
- Make the resolved configuration available as a named Runtime service.

## Non-goals

- Dynamic mutation or hot reload of a running Runtime.
- Arbitrary Python execution from configuration files.
- YAML, TOML, remote secret stores, service discovery, or distributed configuration.
- Global service locators or implicit constructor injection.
- Logging secret contents, raw credentials, or complete source payloads.

## Configuration keys

Keys are lowercase dotted identifiers such as `runtime.startup_deadline` or `nova.voice.enabled`.
Whitespace and case are normalized. Empty segments, punctuation, leading digits, and duplicate
normalized keys are rejected.

## Schema

A `ConfigSchema` owns unique `ConfigField` declarations. Each field defines:

- a normalized key;
- a strict decoder;
- an optional default;
- an optional validator;
- whether the value is secret;
- human-readable documentation.

Required fields have no default. Defaults are already typed and are still validated.

## Sources and precedence

`ConfigLoader` loads sources in registration order. Later sources override earlier sources. The
winning source and original key are preserved in `ConfigOrigin`.

Built-in sources are:

1. `MappingConfigSource` for defaults, tests, and host-supplied values;
2. `JsonFileConfigSource` for data-only local configuration;
3. `EnvironmentConfigSource` for deployment overrides.

The conventional environment mapping is:

```text
PHOENIX_RUNTIME__PORT -> runtime.port
PHOENIX_AUTH__TOKEN   -> auth.token
```

Unknown keys are rejected by default. Applications may explicitly select `IGNORE` while migrating
legacy configuration.

## Secrets

Secret fields resolve to `SecretValue`. Its string and representation forms are always redacted.
`Configuration.as_dict()` redacts secrets by default. Reading a secret through the ordinary value
API is rejected. Revealing a secret requires an explicit `secret(...).reveal(...)` call.

This protects ordinary inspection and diagnostics. It does not replace an operating-system or
remote secret manager, memory protection, access control, or process isolation.

## Dependency composition

`ServiceDefinition` declares one singleton service factory, its dependencies, and whether the
service participates in Runtime lifecycle management. `ServiceComposer` resolves dependencies with
a deterministic depth-first traversal, builds each service once, and rejects:

- duplicate definitions;
- missing dependencies;
- dependency cycles;
- reserved core-service names;
- invalid lifecycle services;
- factory failures.

Factories receive a read-only `DependencyResolver` and the resolved `Configuration`. Dependencies
are explicit strings; no reflection-based parameter injection is performed.

## Runtime integration

`RuntimeAssembler` exposes these base services during composition:

```text
kernel
 events
capabilities
configuration
```

It then constructs `PhoenixRuntime` with all composed services and lifecycle components. The
Runtime remains the lifecycle owner. Configuration loading and service factories run before Runtime
startup, so partial composition cannot be mistaken for a running system.

## Error and security model

Public errors identify the failing key, source, or service but do not include raw values. Decoder
and factory exceptions remain attached for trusted diagnostics through explicit attributes and
exception chaining. JSON is used as a data-only file format; configuration files never execute
code.

## Cancellation

Source loading and asynchronous service factories run in the caller's task. Cancellation is not
translated and propagates normally. Runtime lifecycle cancellation continues to follow RFC-0004.

## Compatibility

RFC-0005 adds a new module and does not change existing Kernel, Event Bus, Capability Registry, or
Runtime public contracts. Direct `PhoenixRuntime(...)` construction remains supported.

## Acceptance criteria

- All configuration contracts are immutable.
- Source precedence and provenance are deterministic.
- Secrets are redacted by default.
- Missing, unknown, decode, validation, source, cycle, and factory failures are tested.
- Synchronous and asynchronous factories are supported.
- Lifecycle services start and stop through Phoenix Runtime.
- Ruff, Ruff Format, mypy strict, and pytest pass.
