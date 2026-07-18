# Validation — Phoenix OS v0.12.0

Validation date: 2026-07-18

## Environment

- Platform: Linux
- Runtime: CPython 3.13.5
- Declared minimum: Python 3.12
- Ruff: 0.15.22
- mypy: 2.3.0
- pytest: 9.0.2
- pytest-asyncio: 1.3.0

The mypy and Ruff targets remain Python 3.12. Runtime execution in this validation environment used
CPython 3.13.5. The Windows `check.ps1` run remains the final confirmation on the maintainer's exact
Python 3.12 installation.

## Quality pipeline

```text
All checks passed!
135 files already formatted
Success: no issues found in 135 source files
452 passed in 2.23s
```

Commands:

```bash
python -m ruff check .
python -m ruff format --check .
PYTHONPATH=src python -m mypy
PYTHONPATH=src python -m pytest -q
PYTHONPATH=src python -m compileall -q src tests examples
```

## RFC-0012 coverage

The suite includes coverage for:

- immutable normalized audit events, records, queries, seals, snapshots, and verification results;
- recursive secret redaction before persistence, including nested mappings and sequences;
- deterministic canonical UTF-8 JSON encoding and SHA-256 record digests;
- genesis linkage, monotonic sequencing, and hash-chain head tracking;
- detection of modified records, broken previous-digest links, sequence gaps, and reordering;
- accurate reporting of the records checked before a verification failure;
- optional externally supplied signing and verification through provider-neutral `AuditSigner` and
  `KeyRef` contracts;
- deterministic in-memory append, bounded filtering, snapshots, concurrency, and closed-state
  behavior;
- authenticated identity requirements and deny-by-default `audit.read` and `audit.verify`
  permissions;
- Policy Engine allow, deny, and confirmation enforcement for ledger inspection;
- Security Journal Event Bus mapping for identity, authentication, authorization, capability,
  configuration, plugin, runtime, secrets, state, and system events;
- journal outcome and severity derivation, correlation propagation, redaction, and recursion
  prevention, including custom event mappers;
- Event Bus and Observability signals that expose audit metadata without secret material;
- RuntimeAssembler service exposure, automatic journal registration, reserved service names, and
  deterministic lifecycle shutdown;
- all RFC-0001 through RFC-0011 regression suites.

## Examples

Twelve examples executed successfully in isolated process runs:

```text
audit_ledger.py
capability_registry.py
configuration.py
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

## Compilation

```bash
PYTHONPATH=src python -m compileall -q src tests examples
```

Completed successfully.

## Distribution artifacts

Built artifacts:

```text
phoenix_os-0.12.0-py3-none-any.whl
phoenix_os-0.12.0.tar.gz
```

The wheel was installed without dependencies into a clean virtual environment with no source-tree
`PYTHONPATH`. An isolated smoke test appended a redacted security event, inspected it through an
authenticated auditor context, verified the hash chain and checked the installed package version:

```text
isolated audit smoke test passed 0.12.0
```

## Result

Phoenix OS v0.12.0 satisfies the RFC-0012 acceptance criteria while preserving all previously
validated public contracts. The included in-memory store is process-local and non-durable. The hash
chain is tamper-evident, not tamper-proof. The core intentionally does not claim to provide a durable
WORM backend, remote transparency log, concrete cryptographic signer, HSM/KMS integration, log
shipping, retention enforcement, regulatory certification, or complete compliance reporting.
