
# Phoenix OS v0.22.0 — Secure Remote Control Plane and TLS

Phoenix OS 0.22.0 implements RFC-0022 and introduces an opt-in, fail-closed remote
administration boundary while preserving the existing local loopback behavior by default.

## Highlights

- immutable loopback and remote exposure policies;
- native server-authenticated TLS and optional mutual TLS;
- TLS 1.2 or TLS 1.3 minimum enforcement and hardened HTTP/1.1 contexts;
- bounded certificate loading, safe certificate metadata, expiry health, and atomic reload;
- exact canonical public-origin, Host, Secure-cookie, and CSRF binding;
- direct and trusted-proxy client identity with explicit provenance;
- strict `Forwarded` or `X-Forwarded-For` selection;
- explicit client and trusted-proxy CIDR allowlists;
- per-client connection and request limits;
- independent remote login limits by client and operator;
- HMAC-protected address fingerprints and allowlisted audit payloads;
- RuntimeAssembler service discovery and reverse lifecycle ownership;
- safe combined listener, guard, TLS, throttle, and audit health snapshots;
- public API, migration guidance, RFC, ADRs, tests, and v0.22.0 packaging.

## Compatibility

No configuration change is required for existing installations. When
`control_plane_network_policy` is omitted, Phoenix keeps the v0.21.0 literal-loopback HTTP
listener and permits its existing ephemeral local port.

Remote exposure is never inferred from `ControlPlaneHttpConfig`. It requires an explicit
`ControlPlaneNetworkPolicy`, fixed port, HTTPS public origin, native TLS, Secure cookies, client
networks, and durable operator mode.

## Safety model

Remote requests pass through TLS, exact Host and Origin validation, client identity resolution,
proxy trust validation, client allowlists, request limits, connection limits, operator
authentication, client/operator login throttling, session cookies, CSRF, authorization, and
step-up checks.

Snapshots and audit facts omit private-key material, certificate paths, client and peer
addresses, proxy chains, Host and Origin values, authorization headers, credentials, cookie
values, session tokens, CSRF values, digests, and internal exception text.

## Release validation

Run the complete repository quality gate and package checks before publishing:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\check.ps1
python -m build
python -m twine check .\dist\*.whl .\dist\*.tar.gz
```
