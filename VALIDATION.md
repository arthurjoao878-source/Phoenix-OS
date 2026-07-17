# Validation — Phoenix OS v0.9.0

Validation date: 2026-07-17

## Environment

- Runtime used for release validation: CPython 3.13.5 on Linux.
- Declared and type-checked minimum runtime: Python 3.12.
- Ruff: 0.15.22.
- mypy: 2.3.0, strict mode.
- pytest: 9.1.1 in the clean development environment.

The project intentionally uses only Python 3.12 language features. Final execution of
`scripts/check.ps1` on the maintainer's Python 3.12 Windows environment remains the release-side
runtime confirmation for that exact interpreter.

## Complete quality gate

Executed from a fresh virtual environment after an editable install with development dependencies:

```text
All checks passed!
97 files already formatted
Success: no issues found in 97 source files
325 passed
```

The gate ran:

```text
python -m ruff check .
python -m ruff format --check .
python -m mypy
python -m pytest
```

## Test coverage areas

The 325 tests include the existing Kernel, Event Bus, Capability Registry, Runtime, Configuration,
Observability, State Store, and Plugin System suites plus RFC-0009 coverage for:

- immutable security contexts and normalized policy requests;
- declarative rule contracts and frozen metadata;
- default-deny evaluation;
- priority ordering and equal-priority restriction precedence;
- principal, identity type, authentication, role, permission, scope, glob, and attribute matching;
- explicit confirmation and confirmed resolution;
- explainable decisions and structured enforcement exceptions;
- rule registration, lookup, removal, snapshots, lifecycle, and closure;
- Event Bus and Observability signals;
- Capability permission and confirmation adapters;
- protected State Store operations and transactions;
- protected plugin setup and startup;
- RuntimeAssembler service and lifecycle integration.

## Compilation and examples

`compileall` completed successfully for `src`, `tests`, and `examples`.

Nine executable examples completed successfully:

- Kernel;
- Event Bus;
- Capability Registry;
- Runtime;
- Configuration;
- Observability;
- State Store;
- Plugin System;
- Policy Engine.

## Wheel

Built artifact:

```text
phoenix_os-0.9.0-py3-none-any.whl
```

SHA-256:

```text
5b822d21f03518be5e36e8441321b9986f2c6c1e69e87b4fede938bc7535cdec
```

The wheel was installed without dependencies into a clean virtual environment. The isolated smoke
test confirmed:

- `phoenix_os.__version__ == "0.9.0"`;
- `PHOENIX_VERSION == "0.9.0"`;
- public Policy Engine imports;
- system-principal matching;
- successful `PolicyEngine.enforce()`;
- clean Policy Engine shutdown.

Result:

```text
isolated policy smoke test passed 0.9.0
```

## Conclusion

Phoenix OS v0.9.0 satisfies the RFC-0009 acceptance criteria while preserving all previously
accepted public contracts. Authorization is centralized, deterministic, explainable, and deny by
default. Authentication, credential validation, secret storage, remote policy distribution, and
hostile-code isolation remain external adapter responsibilities.
