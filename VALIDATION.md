# Validation — Phoenix OS v0.10.0

Validation date: 2026-07-18

## Environment

- Platform: Linux
- Runtime: CPython 3.13.5
- Declared minimum: Python 3.12
- Ruff: 0.15.22
- mypy: 2.3.0
- pytest: 9.1.1
- pytest-asyncio: 1.4.0

The mypy target and Ruff target remain Python 3.12. Runtime execution in this validation environment
used CPython 3.13.5. The Windows `check.ps1` run remains the final confirmation on the maintainer's
Python 3.12 installation.

## Quality pipeline

```text
All checks passed!
110 files already formatted
Success: no issues found in 110 source files
367 passed
```

Commands:

```bash
python -m ruff check .
python -m ruff format --check .
python -m mypy
python -m pytest
```

## RFC-0010 coverage

The suite includes coverage for:

- credential redaction and immutable authentication contracts;
- identity normalization and SecurityContext derivation;
- provider registration, ordering, removal, rejection, cancellation-safe execution, and safe errors;
- bearer issuance, digest lookup, token collision handling, resolution, and session snapshots;
- absolute and idle expiration, touches, limits, revocation, identity-wide revocation, and purge;
- in-memory and State Store-backed repositories;
- persistence round trips without raw bearer storage;
- task-local session and security-context propagation;
- Capability and State context adapters;
- authenticated Kernel forwarding;
- Event Bus and Observability signals without credentials or bearer tokens;
- RuntimeAssembler identity service and lifecycle ordering;
- all RFC-0001 through RFC-0009 regression suites.

## Examples

Ten examples executed successfully:

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
phoenix_os-0.10.0-py3-none-any.whl
```

The wheel was installed into a clean virtual environment without the source tree on `PYTHONPATH`.
An isolated smoke test authenticated an identity, issued and resolved a bearer session, revoked it,
and closed the manager:

```text
isolated identity smoke test passed 0.10.0
```

## Result

Phoenix OS v0.10.0 satisfies the RFC-0010 acceptance criteria while preserving all previously
validated public contracts. No claim is made that the core implements a concrete password, OAuth,
OIDC, LDAP, SAML, passkey, or operating-system identity provider.
