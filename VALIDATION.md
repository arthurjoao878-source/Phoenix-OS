# Validation — Phoenix OS v0.5.0

Validation completed on 2026-07-17.

## Environment

- Python: 3.13.5
- Supported project baseline: Python 3.12+
- Ruff: 0.15.22
- mypy: 2.3.0, strict mode
- pytest: 9.x

## Static validation

- `ruff check .` — passed
- `ruff format --check .` — passed
- `mypy` — passed, 50 source files checked
- `python -m compileall -q src tests examples` — passed

## Test suite

- `pytest` — 161 tests passed
- Kernel, Event Bus, Capability Registry, Runtime, Configuration, sources, decoders,
  dependency composition, Runtime assembly, and package-version tests included

## Executable examples

The following examples completed successfully:

- `examples/event_bus.py`
- `examples/kernel.py`
- `examples/capability_registry.py`
- `examples/runtime.py`
- `examples/configuration.py`

The configuration example confirmed:

- later environment-source precedence;
- typed integer and boolean decoding;
- secret redaction in snapshots;
- explicit dependency composition;
- lifecycle startup and reverse shutdown through `PhoenixRuntime`.

## Distribution

- built artifact: `dist/phoenix_os-0.5.0-py3-none-any.whl`
- wheel installed successfully in a clean virtual environment
- isolated `phoenix_os.__version__` smoke test returned `0.5.0`
- isolated configuration decoding smoke test passed

## Result

Phoenix OS v0.5.0 satisfies the RFC-0005 acceptance criteria and preserves the validated public
contracts from v0.4.0.
