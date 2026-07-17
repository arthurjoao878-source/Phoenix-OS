# ADR-0016 — Explicit allowlisted plugin loading

- **Status:** Accepted
- **Date:** 2026-07-17

## Context

Python entry-point discovery is convenient, but importing every discovered package executes third-party
code before the host has reviewed compatibility, permissions, exports, or provenance. Discovery and
execution therefore cannot be the same operation.

## Decision

Phoenix exposes side-effect-free `PluginReference` metadata first. `EntryPointPluginDiscovery.load()`
requires an explicit allowlist containing the selected entry-point name before calling the package
loader. Automatic loading, package installation, and marketplace resolution are outside the core.

## Consequences

- Merely inspecting installed plugin metadata does not import plugin modules.
- Deployment configuration must maintain an allowlist.
- Plugin code remains trusted once explicitly loaded; this is not sandboxing.
- Supply-chain verification and package signing remain external responsibilities.
