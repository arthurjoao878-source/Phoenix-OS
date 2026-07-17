# Validation — Phoenix OS v0.6.0

Validation completed on 2026-07-17.

## Environment

- Python: 3.13.5
- Supported project baseline: Python 3.12+
- Ruff: 0.15.22
- mypy: 2.3.0, strict mode
- pytest: 9.0.2

## Static validation

- `ruff check .` — passed
- `ruff format --check .` — passed, 65 files checked
- `mypy` — passed, 65 source, test, and example files checked
- `python -m compileall -q src tests examples` — passed

## Test suite

- `pytest` — 202 tests passed
- Existing Kernel, Event Bus, Capability Registry, Runtime, Configuration, dependency composition,
  Runtime assembly, and package-version tests remain green
- New observability coverage includes immutable contracts, metric validation, deterministic sink
  priority, synchronous and asynchronous sinks, failure collection, strict export errors,
  cancellation, recursive redaction, bounded memory storage, nested spans, context reset,
  correlation and causation inheritance, Event Bus observation, and Runtime ownership

## Executable examples

The following examples completed successfully:

- `examples/event_bus.py`
- `examples/kernel.py`
- `examples/capability_registry.py`
- `examples/runtime.py`
- `examples/configuration.py`
- `examples/observability.py`

The observability example confirmed:

- Runtime-owned observability and Event Bus bridging;
- structured logs, counter metrics, and completed spans;
- nested correlation context;
- recursive redaction of `api_key` and password attributes;
- lifecycle observations during startup and shutdown;
- bounded in-memory diagnostic snapshots.

## Distribution

- built artifact: `dist/phoenix_os-0.6.0-py3-none-any.whl`
- wheel installed successfully in a clean virtual environment
- isolated `phoenix_os.__version__` smoke test returned `0.6.0`
- isolated metric and span correlation smoke test passed

## Result

Phoenix OS v0.6.0 satisfies the RFC-0006 acceptance criteria and preserves the validated public
contracts from v0.5.0.
