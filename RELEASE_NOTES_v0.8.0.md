# Phoenix OS v0.8.0 — Plugin System and Adapter SDK

Phoenix OS v0.8.0 implements RFC-0008 and introduces a deterministic extension boundary for packaged
plugins and incremental Nova 3.x adapters.

## Highlights

- Immutable plugin manifests and strict semantic versions.
- Phoenix-version and Plugin-API compatibility checks before setup.
- Required and optional dependencies with deterministic topological ordering.
- Explicit host approval for capability, state-store, and service contributions.
- Exact manifest export declarations enforced by a restricted Plugin SDK.
- Setup and startup rollback with reverse-order cleanup.
- Reverse deterministic shutdown with aggregate failure reporting.
- Side-effect-free Python entry-point discovery and explicit allowlisted loading.
- `HookPlugin` for synchronous or asynchronous Nova adapter callbacks.
- Runtime assembly, Event Bus, Observability, Capability Registry, and State Store integration.

## Security

The Plugin System is not a sandbox. Once loaded, a plugin executes as normal Python code with ambient
process authority. Production hosts should pin and verify distributions, use a strict allowlist, grant
minimum SDK permissions, and isolate untrusted code in another process.

## Validation

The release is validated with Ruff, Ruff Format, mypy strict, pytest, executable examples, wheel
construction, isolated installation, and package integrity hashes. See `VALIDATION.md` for exact
results.
