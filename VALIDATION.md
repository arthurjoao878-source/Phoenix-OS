# Validation — Phoenix OS v0.7.0

Validation completed on 2026-07-17.

## Environment

- Python: 3.13.5
- Supported project baseline: Python 3.12+
- Ruff: 0.15.22
- mypy: 2.3.0, strict mode
- pytest: 9.0.2

## Static validation

- `ruff check .` — passed
- `ruff format --check .` — passed, 77 files checked
- `mypy` — passed, 77 source, test, and example files checked
- `python -m compileall -q src tests examples` — passed
- `scripts/check.sh` — passed end to end after editable development installation

## Test suite

- `pytest` — 249 tests passed
- Existing Kernel, Event Bus, Capability Registry, Runtime, Configuration, dependency composition,
  Runtime assembly, Observability, and package-version tests remain green
- New State Store coverage includes key and timestamp validation, deterministic JSON serialization,
  secret rejection, typed reads, storage isolation, optimistic conflicts, create-only writes,
  versioned deletes, deterministic namespace listing, TTL expiration, explicit purge, atomic
  transaction commit, automatic rollback, explicit rollback, competing-writer serialization,
  snapshots, replace and merge restoration, events, correlation metadata, logs, metrics, spans,
  closed diagnostic channels, lifecycle closure, named registry resolution, deterministic registry
  lifecycle, registration constraints, store isolation, and Runtime ownership

## Executable examples

The following seven examples completed successfully:

- `examples/event_bus.py`
- `examples/kernel.py`
- `examples/capability_registry.py`
- `examples/runtime.py`
- `examples/configuration.py`
- `examples/observability.py`
- `examples/state_store.py`

The State Store example confirmed:

- create-only optimistic writes;
- atomic transaction update and additional-key creation;
- typed state reads;
- logical snapshot creation and replace restoration;
- correlated Event Bus and Observability diagnostics.

## Distribution

- built artifact: `dist/phoenix_os-0.7.0-py3-none-any.whl`
- wheel installed successfully in a clean virtual environment
- isolated `phoenix_os.__version__` smoke test returned `0.7.0`
- isolated typed write, optimistic transaction update, and read smoke test passed

## Compatibility regression

- Added direct construction coverage for parameterized `StateKey[object]` and `StateRecord[object]`.
- Reserved the `__orig_class__` slot on both frozen generic contracts so Python 3.12 typing assignment is rejected through `FrozenInstanceError`/`AttributeError` rather than the slotted-dataclass `TypeError` path.
- Full local validation in this corrected package was rerun on Python 3.13.5; the original failure was reported on Python 3.12.0 and must also be confirmed by the downstream Windows validation command.

## Result

Phoenix OS v0.7.0 satisfies the RFC-0007 acceptance criteria and preserves the validated public
contracts from v0.6.0.
