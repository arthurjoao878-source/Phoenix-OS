# Validation — Phoenix OS v0.8.0

- **Milestone:** RFC-0008 — Plugin System and Adapter SDK
- **Date:** 2026-07-17
- **Package target:** Python 3.12+
- **Validation interpreter:** CPython 3.13.5
- **Static-analysis target:** Python 3.12

## Static validation

```text
ruff check .
All checks passed!

ruff format --check .
88 files already formatted

mypy
Success: no issues found in 88 source files
```

The strict mypy configuration keeps `python_version = "3.12"`, so the public API and all examples are
checked against the project's minimum language target even though the available validation interpreter
was CPython 3.13.5.

## Test suite

```text
pytest
288 passed
```

Coverage includes all previous Kernel, Event Bus, Capability Registry, Runtime, Configuration,
Observability, and State Store behavior plus:

- strict semantic-version parsing and range boundaries;
- immutable manifest, dependency, export, context, failure, and snapshot contracts;
- duplicate, missing, incompatible, optional, and cyclic dependency behavior;
- Plugin API and Phoenix package compatibility checks;
- default-deny host permission approval;
- exact declared capability, state-store, and service exports;
- deterministic prepare/start/stop order;
- setup and startup rollback;
- aggregate shutdown failures;
- contribution cleanup;
- dependency service resolution;
- side-effect-free entry-point discovery;
- explicit allowlisted plugin loading;
- class, factory, and asynchronous factory loading;
- Event Bus and Observability lifecycle signals;
- RuntimeAssembler lifecycle and host-service integration.

## Executable examples

All eight examples executed successfully:

- `examples/kernel.py`
- `examples/event_bus.py`
- `examples/capability_registry.py`
- `examples/runtime.py`
- `examples/configuration.py`
- `examples/observability.py`
- `examples/state_store.py`
- `examples/plugin_system.py`

## Compilation and package build

```text
python -m compileall -q src tests examples
python -m build --wheel --no-isolation
Successfully built phoenix_os-0.8.0-py3-none-any.whl
```

Wheel SHA-256:

```text
90d2ea8455118886609bc7464fdaaf684174f2c8b72102f1b671803f4b779568
```

## Isolated installation

The wheel was installed without dependencies into a new virtual environment. The isolated smoke test
confirmed:

- `phoenix_os.__version__ == "0.8.0"`;
- plugin manifest and manager imports;
- plugin preparation and startup;
- active-plugin snapshot;
- deterministic plugin shutdown.

```text
isolated plugin smoke test passed 0.8.0
```

## Archive integrity

The release ZIP was built from a clean tree without caches, bytecode, or temporary build directories.
`unzip -t` completed without errors. SHA-256 hashes for the ZIP, wheel, RFC, release notes, and
validation report are provided separately.

## Result

Phoenix OS v0.8.0 satisfies the RFC-0008 acceptance criteria while preserving all previously
validated public contracts. The Plugin System constrains SDK contributions through manifests,
permissions, exports, compatibility checks, and deterministic lifecycle ownership. It is explicitly
not represented as a sandbox for hostile Python code.
