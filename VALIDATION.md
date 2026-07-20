
# Validation — Phoenix OS v0.22.0

RFC-0022 uses the complete Phoenix OS regression and packaging gates. Validation must run on the
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
- unchanged legacy loopback HTTP behavior when no network policy is supplied;
- explicit policy-selected fixed-port listener lifecycle;
- native TLS and optional mutual-TLS handshakes;
- certificate-health and reload snapshots without key or path disclosure;
- exact Host and public-Origin binding;
- direct and trusted-proxy identity resolution;
- spoofed or ambiguous forwarding-header rejection;
- client-network allowlists and bounded connection/request admission;
- independent remote login admission by client and operator;
- Secure HttpOnly cookies and origin-bound rotating CSRF;
- protected remote-address audit facts without raw addresses or proxy chains;
- Runtime service discovery and reverse shutdown;
- wheel and source distribution metadata reporting 0.22.0.
