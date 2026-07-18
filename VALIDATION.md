# Validation — Phoenix OS v0.11.0

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
122 files already formatted
Success: no issues found in 122 source files
417 passed
```

Commands:

```bash
python -m ruff check .
python -m ruff format --check .
python -m mypy
python -m pytest
```

## RFC-0011 coverage

The suite includes coverage for:

- normalized and immutable secret and external-key references;
- metadata, material, lease, store, and diagnostic contracts;
- redacted representations for stored material and leases;
- deterministic version allocation and rotation ancestry;
- exact-version and latest-active resolution;
- deterministic listing and namespace filtering;
- version and lease revocation;
- store snapshots, material clearing, and closed-state behavior;
- authenticated identity requirements and deny-by-default local permissions;
- Policy Engine allow, deny, and confirmation enforcement;
- lease bounds, principal ownership, expiry, purge, and secret-revocation invalidation;
- Event Bus and Observability signals without material disclosure;
- typed Configuration reference decoding and lease resolution;
- provider-neutral `KeyRef`, `SecretStore`, and `SecretProtector` boundaries;
- RuntimeAssembler service exposure and lifecycle shutdown;
- all RFC-0001 through RFC-0010 regression suites.

## Examples

Eleven examples executed successfully:

```text
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
python -m compileall -q src tests examples
```

Completed successfully.

## Wheel

Built artifact:

```text
phoenix_os-0.11.0-py3-none-any.whl
```

The wheel was installed into a clean virtual environment without the source tree on `PYTHONPATH`.
An isolated smoke test created and rotated a versioned secret, issued a lease, verified the material,
revoked the active version, and closed the manager:

```text
isolated secrets smoke test passed 0.11.0
```

## Result

Phoenix OS v0.11.0 satisfies the RFC-0011 acceptance criteria while preserving all previously
validated public contracts. No claim is made that the core supplies encryption at rest, a concrete
cloud vault, HSM, KMS, TPM, keychain, transport, backup, or disaster-recovery provider.
