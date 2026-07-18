# Validation — Phoenix OS v0.15.0

Validation date: 2026-07-18

## Environment

- Platform: Linux
- Runtime: CPython 3.13
- Declared minimum: Python 3.12
- Durable job reference backend: provider-neutral `StateStore`
- Runtime worker: standard-library `asyncio`

The Ruff and mypy targets remain Python 3.12. A Windows `check.ps1` run remains the final confirmation
on the maintainer's exact Python 3.12 installation.

## Quality pipeline

```text
All checks passed!
153 files already formatted
Success: no issues found in 153 source files
508 passed
```

Commands:

```bash
python -m ruff check .
python -m ruff format --check .
python -m mypy
python -m pytest -q
python -m compileall -q src tests examples
```

## RFC-0015 coverage

The suite includes coverage for:

- immutable validated schedules, retries, jobs, leases, runs, workers, and snapshots;
- deterministic due ordering and bounded one-time ticks;
- one-time completion and fixed-rate recurring rescheduling;
- atomic competing claims and opaque fencing tokens;
- stale and expired lease rejection and reclamation;
- deterministic bounded retry and dead-letter transitions;
- cancellation invalidating active leases;
- capability-only execution and safe failure categories;
- versioned State Store serialization and invalid-schema rejection;
- scheduled, retrying, cancelled, and expired-lease restart recovery;
- serializable claims across repository instances;
- Runtime-owned worker startup after plugins and reverse-order shutdown;
- worker tick failure isolation and one-shot lifecycle enforcement;
- safe `job.*` Event Bus payloads and dedicated Audit Ledger categorization;
- root-package API and 0.15.0 plugin compatibility metadata;
- all RFC-0001 through RFC-0014 regression suites.

## Example

Fifteen examples compile, including `durable_jobs.py`. Its representative output is:

```text
runs: 1
status: succeeded
output: {'generated': 'daily'}
```

## Result

Phoenix OS v0.15.0 satisfies RFC-0015 while preserving previously validated public contracts.
Repository lease fencing prevents stale state transitions but does not guarantee exactly-once
external effects. Production deployments remain responsible for idempotent capability design,
State Store durability, encryption, access control, retention, backup, worker sizing, and external
queue or distributed-scheduling adapters where required.
