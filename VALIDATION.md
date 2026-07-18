# Validation — Phoenix OS v0.13.0

Validation date: 2026-07-18

## Environment

- Platform: Linux
- Runtime: CPython 3.13.5
- Declared minimum: Python 3.12
- Ruff: 0.15.22
- mypy: 2.3.0
- pytest: 9.0.2
- pytest-asyncio: 1.3.0
- SQLite: Python standard-library driver

The mypy and Ruff targets remain Python 3.12. Runtime execution in this validation environment used
CPython 3.13.5. A Windows `check.ps1` run remains the final confirmation on the maintainer's exact
Python 3.12 installation.

## Quality pipeline

```text
All checks passed!
138 files already formatted
Success: no issues found in 138 source files
468 passed in 2.38s
```

Commands:

```bash
python -m ruff check .
python -m ruff format --check .
python -m mypy
PYTHONPATH=src python -m pytest -q
PYTHONPATH=src python -m compileall -q src tests examples
```

## RFC-0013 coverage

The suite includes coverage for:

- durable SQLite persistence across close and reopen;
- exact recovery of event fields, redacted details, correlation, causation, sequence, digest, and
  optional seal metadata;
- resumed appends at the next sequence with the persisted head digest;
- WAL-backed atomic record and metadata transactions;
- duplicate event rejection without sequence advancement;
- parameterized persistent filters and deterministic ascending limits;
- local competing store instances sharing one contiguous sequence;
- SQL trigger rejection of record updates, deletes, sequence gaps, and broken previous-digest links;
- detection of changed persisted content and chain-head metadata mismatch;
- fail-closed append recovery through `AuditRecoveryError`;
- explicit incompatible schema failure through `AuditSchemaError`;
- optional external signatures surviving reopen and verification;
- invalid verification when a signed record has no configured verifier;
- close blocking new appends while preserving forensic reads, verification, and snapshots;
- `AuditLedger` store lifecycle startup and RuntimeAssembler durable Security Journal integration;
- all RFC-0001 through RFC-0012 regression suites.

## Examples

Thirteen examples executed successfully in isolated process runs:

```text
audit_ledger.py
capability_registry.py
configuration.py
durable_audit_ledger.py
event_bus.py
identity_authentication.py
kernel.py
observability.py
plugin_system.py
policy_engine.py
runtime.py
secrets_vault.py
state_store.py
```

The durable audit example produced:

```text
recovered: 1 sequence: 1
redacted: ***
same head: True
valid: True
```

## Compilation

```bash
PYTHONPATH=src python -m compileall -q src tests examples
```

Completed successfully.

## Distribution artifacts

Built artifacts:

```text
phoenix_os-0.13.0-py3-none-any.whl
phoenix_os-0.13.0.tar.gz
```

The wheel was installed without dependencies into a clean virtual environment with no source-tree
`PYTHONPATH`. An isolated smoke test created a SQLite ledger, appended a redacted event, closed and
reopened the database, inspected the persisted record through an authenticated auditor context,
verified the chain, and checked the installed package version:

```text
isolated durable audit smoke test passed 0.13.0
```

## Result

Phoenix OS v0.13.0 satisfies RFC-0013 while preserving all previously validated public contracts.
`SQLiteAuditStore` provides local transactional durability and verify-before-resume recovery, but it
is not WORM, encrypted at rest, independently anchored, remotely replicated, or resistant to
privileged database replacement or rollback. Stronger evidence, retention, backup, availability, and
origin guarantees remain external `AuditStore`, `AuditSigner`, and deployment responsibilities.
