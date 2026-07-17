# Validation Report

Validated on 2026-07-17 with Python 3.13.5. The project targets Python 3.12+ and CI
covers Python 3.12 and 3.13.

## Static and automated validation

- `ruff check .` — passed
- `ruff format --check .` — passed
- `mypy` in strict mode — passed with no issues in 28 source files
- `pytest` — 77 passed
- `python -m compileall -q src tests examples` — passed

## Executable examples

- `python examples/event_bus.py` — passed
- `python examples/kernel.py` — passed
- `python examples/capability_registry.py` — passed

## Distribution validation

- wheel build — passed
- wheel contents include Kernel, Event Bus, and Capability Registry packages
- isolated virtual-environment installation — passed
- isolated `phoenix_os.__version__` smoke test — `0.3.0`
- isolated capability registration and invocation — passed

## RFC-0003 coverage

The suite validates immutable contracts, unique registration, safe unregistration, deterministic
discovery, default-deny required permissions, explicit confirmation, synchronous and asynchronous
providers, policy ordering, deadlines, cancellation, safe failure translation, correlated events,
registry shutdown, Kernel adapter integration, and preservation of RFC-0001/RFC-0002 behavior.
