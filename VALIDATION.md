# Validation Report

Validated on 2026-07-17 with Python 3.13.5. The project targets Python 3.12+ and the
GitHub Actions matrix covers Python 3.12 and 3.13.

## Static and automated validation

- `./scripts/check.sh` — passed
- `ruff check .` — passed
- `ruff format --check .` — passed
- `mypy` in strict mode — passed with no issues in 36 checked files
- `pytest` — 103 passed
- `python -m compileall -q src tests examples` — passed

## Executable examples

- `python examples/event_bus.py` — passed
- `python examples/kernel.py` — passed
- `python examples/capability_registry.py` — passed
- `python examples/runtime.py` — passed

## Distribution validation

- wheel build — passed
- built artifact: `phoenix_os-0.4.0-py3-none-any.whl`
- wheel contents include Kernel, Event Bus, Capability Registry, and Runtime packages
- isolated virtual-environment installation — passed
- isolated `phoenix_os.__version__` smoke test — `0.4.0`
- isolated Runtime start/stop smoke test — passed

## RFC-0004 coverage

The suite validates immutable Runtime contracts, reserved and custom service composition,
deterministic startup, reverse shutdown, startup rollback, rollback failure reporting, retryable
shutdown, aggregate stop failures, lifecycle events, state snapshots, concurrent idempotence,
request admission, in-flight draining, shutdown rejection of new work, lifecycle deadlines,
cancellation propagation, async context management, Capability Registry ownership, Event Bus
last-close ordering, and preservation of RFC-0001 through RFC-0003 behavior.
