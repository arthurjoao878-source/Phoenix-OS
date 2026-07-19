# Validation — Phoenix OS v0.18.0

RFC-0018 was validated against the complete Phoenix OS regression suite with strict static analysis,
loopback command integration, browser protection coverage, Runtime lifecycle tests, and packaging
checks.

## Commands

```powershell
python -m pip install -e ".[dev]"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\check.ps1
python -m build
python -m twine check .\dist\*.whl .\dist\*.tar.gz
python .\examples\control_plane_dashboard.py
```

## Results

- Ruff lint passed;
- Ruff formatting check passed;
- mypy strict passed for source, tests, and examples;
- complete regression suite passed;
- wheel and source distribution passed Twine validation;
- wheel contains the packaged Dashboard HTML, CSS, JavaScript, and SVG assets;
- package and plugin compatibility metadata report 0.18.0.

## Validated behavior

- immutable command intents, receipts, action permissions, and bounded idempotency;
- SHA-256 storage keys and command fingerprints without retained request payloads;
- replay of matching requests and conflict rejection for key reuse with another fingerprint;
- origin-bound HMAC CSRF issuance, expiry, exact-loopback validation, and constant-time verification;
- one-time destructive confirmation proofs with expiry, bounded retention, and replay rejection;
- deeply validated immutable JSON job arguments and bounded scheduling parameters;
- capability existence, permission, risk, and confirmation-policy checks before job scheduling;
- deterministic command/job UUID recovery after concurrent or partial scheduler success;
- safe job cancellation, dead-letter retry, and workflow cancellation reconciliation;
- fixed authenticated POST routes with strict media type, body, header, query, and concurrency limits;
- exact operation availability without exposing a principal's full permission set;
- safe receipts without arguments, outputs, contexts, tokens, proofs, keys, or exception text;
- payload-free command facts and Security Journal authorization categorization;
- Dashboard tab-scoped bearer/CSRF storage, fresh idempotency keys, and two-step cancellation flow;
- no inline/external scripts, `innerHTML`, `eval`, CDN assets, cookies, or arbitrary route dispatch;
- Runtime-owned command API startup and reverse shutdown between HTTP and Event Bus lifecycles;
- all previously validated kernel, events, capabilities, runtime, configuration, observability,
  state, plugins, policy, identity, secrets, audit, jobs, workflows, and read-only Dashboard behavior.

Phoenix OS v0.18.0 satisfies RFC-0018 while retaining a local, allowlisted, capability-only command
boundary. Remote administration and generic object mutation remain outside the built-in control plane.
