# Validation — Phoenix OS v0.23.0

RFC-0023 uses the complete Phoenix OS regression and packaging gates. Validation must run on the
final checkout after all five slices are applied.

## Commands

```powershell
python -m pip install -e ".[dev]"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\check.ps1
python -m build
python -m twine check .\dist\*.whl .\dist\*.tar.gz
```

## Required behavior

- Ruff lint and formatting over source, tests, and examples;
- strict mypy analysis;
- complete regression suite;
- unchanged v0.22 operator-session and remote-control behavior when service accounts are absent;
- bounded in-memory and durable State Store-backed service-account repositories;
- strict state decoding, protected digest indexes, and corruption detection;
- one-time token issuance with no plaintext persistence or recovery endpoint;
- mandatory expiration, atomic rotation, bounded overlap, revocation, and terminal retention;
- exact action scopes, resource restrictions, and deny-by-default policy integration;
- generic failures, constant-time digest comparison, and enumeration resistance;
- optional client-CIDR and mutual-TLS identity restrictions that fail closed;
- fresh nonce and aware timestamp replay validation for exact machine routes;
- independent per-client and per-account authentication throttling;
- protected audit facts and safe metrics and health snapshots without token material;
- Maintainer routes, one-time Dashboard presentation, and no browser credential storage;
- RuntimeAssembler repository selection, service discovery, and reverse shutdown;
- wheel and source distribution metadata reporting 0.23.0;
- packaged Dashboard assets and service-account modules after isolated installation.
