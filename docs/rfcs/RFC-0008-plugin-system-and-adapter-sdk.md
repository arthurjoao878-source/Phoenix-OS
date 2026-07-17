# RFC-0008 — Plugin System and Adapter SDK

- **Status:** Accepted
- **Version:** 0.8.0
- **Date:** 2026-07-17

## Summary

Phoenix OS needs a controlled extension boundary for Nova 3.x adapters and independently packaged
integrations without allowing plugins to mutate the Kernel or bypass existing security contracts.
This RFC defines immutable plugin manifests, semantic-version compatibility, explicit permissions,
declarative exports, dependency resolution, deterministic setup and lifecycle ordering, rollback,
entry-point discovery, an allowlisted loader, and a restricted Adapter SDK.

Plugins remain trusted Python code once loaded. The Plugin System reduces accidental coupling and
makes authority visible; it is not a process sandbox or a defense against malicious native code.

## Goals

- Define a stable manifest and lifecycle contract for Phoenix extensions.
- Reject incompatible API, Phoenix, dependency, and permission requirements before startup.
- Resolve plugin dependencies deterministically and detect cycles.
- Require contributions to be declared in the manifest before registration.
- Restrict privileged contributions to host-approved permissions.
- Register capabilities, named state stores, and plugin-owned services through one SDK.
- Roll back contributions when setup or startup fails.
- Start plugins after their host services and stop them before those services.
- Discover package entry-point metadata without importing plugin modules.
- Require an explicit allowlist before entry-point code is loaded.
- Emit lifecycle events, structured logs, metrics, and spans.
- Provide callback adapters suitable for incremental Nova 3.x migration.

## Non-goals

- Sandboxing arbitrary Python, native extensions, subprocesses, or operating-system access.
- Installing packages, resolving packages from the internet, or managing virtual environments.
- Hot reloading plugins inside a running Runtime.
- Allowing plugins to patch the Kernel, Event Bus, Runtime, or registries directly.
- Defining a remote plugin marketplace, signing authority, trust store, or update service.
- Guaranteeing binary compatibility across Python versions.
- Automatically loading every discovered entry point.
- Providing durable plugin configuration or secret storage.

## Manifest

`PluginManifest` is immutable and side-effect-free. It contains:

- a normalized stable plugin ID;
- a human-readable name and strict `major.minor.patch` version;
- the supported Plugin API version;
- a Phoenix semantic-version range;
- requested privileged permissions;
- required or optional plugin dependencies;
- declared capability, state-store, and service exports;
- descriptive metadata.

Plugin IDs use lowercase letters, digits, dots, underscores, and hyphens. IDs and dependency IDs are
normalized before use. A plugin cannot depend on itself or declare the same dependency twice.

The Plugin API version is intentionally separate from the Phoenix package version. Phoenix v0.8.0
exposes Plugin API version 1. A different API version is rejected even when the package-version range
would otherwise match.

## Compatibility

`SemanticVersion` and `VersionRange` provide strict compatibility checks without adding a packaging
library to the core. Ranges may define inclusive or exclusive minimum and maximum bounds. Pre-release,
build metadata, wildcard expressions, and arbitrary package specifier syntax are intentionally outside
this first contract.

Before any setup hook runs, `PluginManager` verifies:

1. every manifest uses the supported Plugin API version;
2. the current Phoenix version is inside the declared range;
3. every requested permission is allowed by the host;
4. every required dependency exists;
5. each dependency version is accepted;
6. the dependency graph is acyclic.

This validation is fail-fast and precedes plugin side effects.

## Permissions and exports

Privileged contributions require both a requested manifest permission and explicit host approval.
Version 1 defines:

- `capabilities.register`;
- `state_stores.register`;
- `services.publish`.

Permission approval alone is insufficient. Every contributed name must also appear in the manifest's
`PluginExports`. This prevents a plugin from silently expanding its public surface after review.
Duplicate capability, state-store, or service names are rejected by their owning registry.

The default host permission set is empty. Applications must opt in to each permission.

## Adapter SDK

Each plugin receives a host-owned `PluginContext` and restricted `PluginRegistrar`. The registrar can:

- register an explicitly declared capability provider;
- register an explicitly declared named state store before Runtime startup;
- publish an explicitly declared plugin service;
- resolve host services and services published by already-prepared dependencies.

The registrar records opaque registration handles and removes contributions in reverse order during
rollback or shutdown where the owning registry permits removal. A state store that has already entered
Runtime lifecycle remains owned by `StateStoreRegistry` and is closed during registry shutdown.

`HookPlugin` adapts synchronous or asynchronous setup, start, and stop callbacks to the plugin
contract. This is the reference migration path for existing Nova modules.

## Dependency resolution

Plugins are registered in deterministic sequence. Dependencies are visited depth-first, preserving
registration order among otherwise independent plugins. Every dependency is prepared and started
before its dependents. Shutdown reverses the resolved order.

Optional dependencies affect ordering and version validation only when present. Missing required
dependencies and incompatible versions fail before setup. Cycles report the explicit dependency path.

A dependent plugin may resolve a service published during setup by a dependency because setup follows
the resolved order.

## Lifecycle

The manager has explicit states: `created`, `preparing`, `prepared`, `starting`, `running`, `stopping`,
`stopped`, and `failed`.

`prepare()` validates manifests, resolves dependencies, creates restricted registrars, and executes
setup hooks. Setup is the only phase allowed to contribute capabilities, stores, or services. A setup
failure cleans the failing plugin and every previously prepared plugin in reverse order.

`start()` executes optional start hooks in dependency order. A startup failure stops already-started
plugins in reverse order and removes prepared contributions. `stop()` invokes optional stop hooks in
reverse dependency order, continues after ordinary failures, removes contributions, and reports an
aggregate `PluginStopError`.

Cancellation is never translated. Hooks are one-shot inside the one-shot Runtime model.

## Runtime integration

`RuntimeAssembler` accepts an optional `PluginManager`. It exposes the manager as the `plugins`
service, composes ordinary services, binds those services to the manager, and calls `prepare()` before
constructing the Runtime.

The lifecycle order is:

1. Observability and Event Observer;
2. State Store or State Store Registry;
3. ordinary composed lifecycle services;
4. Plugin Manager.

Shutdown is reversed. Plugins therefore stop while their state, custom services, Event Bus, and
Observability dependencies are still available.

Plugin-published services remain inside the Plugin Manager's service registry and are resolved through
`plugins.service(name)`. They do not mutate the Runtime's immutable service mapping after assembly.

## Discovery and loading

`EntryPointPluginDiscovery` reads the `phoenix_os.plugins` entry-point group and returns sorted
`PluginReference` metadata without importing plugin modules. Loading is a separate asynchronous action
that requires the entry-point name to be present in an explicit allowlist.

The loader accepts a plugin instance, plugin class, synchronous zero-argument factory, or asynchronous
zero-argument factory. The result must expose a `PluginManifest` and callable setup hook.

Discovery does not imply trust. Hosts should pin package versions, verify distribution provenance,
review requested permissions and exports, and maintain a deployment-specific allowlist.

## Events and observability

The manager emits safe lifecycle facts such as `plugin.prepared`, `plugin.started`, `plugin.stopped`,
and failure events. Payloads include plugin IDs and versions but never plugin configuration, secrets,
or arbitrary service objects.

When an `ObservabilityHub` is present, setup, start, and stop hooks run inside spans. Lifecycle logs and
active/prepared gauge metrics are emitted through the existing structured diagnostics boundary.
Telemetry failures do not invalidate a completed plugin transition; cancellation still propagates.

## Security model

Plugins execute in the Phoenix process and have normal Python authority granted by the operating
system. Manifest permissions govern only SDK contributions. They cannot prevent a malicious plugin
from importing Python modules or using ambient process privileges.

Production deployments should combine:

- a strict entry-point allowlist;
- pinned and verified distributions;
- least-privilege operating-system accounts;
- isolated processes for untrusted code;
- explicit capability permissions and confirmation policies;
- secret minimization and structured redaction;
- external package-signing and software-supply-chain controls.

The Plugin System must never be described as a security sandbox.

## Compatibility

RFC-0008 adds `phoenix_os.plugins`, optional `RuntimeAssembler` support, and the additive
`StateStoreRegistry.started` lifecycle property. Existing Kernel, Event Bus, Capability Registry,
Runtime, Configuration, Observability, and State Store APIs remain valid.

## Acceptance criteria

- Public manifest, version, dependency, export, registration, failure, and snapshot contracts are
  immutable.
- Incompatible API and Phoenix versions fail before setup.
- Missing, incompatible, and cyclic dependencies are explicit failures.
- Setup and startup follow dependency order; shutdown and rollback reverse it.
- Requested permissions require explicit host approval.
- Contributions must be declared and are cleaned after rollback or shutdown.
- Entry-point discovery performs no imports and loading requires an allowlist.
- Runtime assembly binds composed services before plugin preparation.
- Plugins stop before state and other host services close.
- Existing public contracts and tests remain valid.
