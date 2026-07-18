# Validation — Phoenix OS v0.14.0

Validation date: 2026-07-18

## Environment

- Platform: Linux
- Runtime: CPython 3.13
- Declared minimum: Python 3.12
- SQLite: Python standard-library driver
- Archive compression: Python standard-library gzip

The Ruff and mypy targets remain Python 3.12. A Windows `check.ps1` run remains the final confirmation
on the maintainer's exact Python 3.12 installation.

## Quality pipeline

```text
All checks passed!
140 files already formatted
Success: no issues found in 140 source files
483 passed
```

Commands:

```bash
python -m ruff check .
python -m ruff format --check .
python -m mypy
python -m pytest -q
python -m compileall -q src tests examples
```

## RFC-0014 coverage

The suite includes coverage for:

- exact contiguous archive export and recursive redaction preservation;
- canonical UTF-8 NDJSON records and deterministic gzip encoding;
- payload, artifact, manifest, record, and chain-head digest verification;
- cross-segment sequence, record-head, and prior-manifest continuity;
- bounded full-segment rotation and explicit final partial segments;
- incomplete-range and overwrite refusal;
- artifact and manifest tamper detection;
- persisted external seal verification and missing-verifier failure;
- non-destructive retention planning;
- exact confirmation-digest enforcement;
- verified prefix-only deletion and retained-suffix verification;
- protected archives stopping candidate selection;
- age and newest-count policy interaction;
- all RFC-0001 through RFC-0013 regression suites.

## Examples

Fourteen examples execute successfully, including `audit_archival.py`. Its representative output is:

```text
archives: 3 records: 5
valid: True head: <sha256>
retention candidates: 1
confirmation digest: <sha256>
```

## Result

Phoenix OS v0.14.0 satisfies RFC-0014 while preserving previously validated public contracts.
Archive bundles are portable and tamper-evident, but not encrypted, WORM, independently timestamped,
or resistant to privileged replacement or rollback. Retention deletion remains subject to external
legal, privacy, backup, access-control, and incident-response governance.
