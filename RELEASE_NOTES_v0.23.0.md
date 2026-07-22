# Phoenix OS v0.23.0 — Service Accounts and Scoped API Access

Phoenix OS 0.23.0 implements RFC-0023 and introduces durable machine identities and narrowly
scoped API credentials without reusing human operator sessions or browser security state.

## Highlights

- durable in-memory and State Store-backed service-account repositories;
- active, disabled, revoked, and expired account and token lifecycle states;
- one-time opaque API-token issuance with protected digest-only persistence;
- mandatory expiration, atomic rotation, bounded predecessor overlap, and durable revocation;
- exact action scopes, resource restrictions, and central deny-by-default policy enforcement;
- optional client-CIDR and mutual-TLS certificate identity binding;
- fresh nonce and timestamp replay evidence for every machine request;
- independent client and account authentication throttling;
- generic authentication failures, protected audit facts, and safe health snapshots;
- Maintainer management routes and Dashboard account and token administration;
- explicit machine-route allowlisting with trusted credential-free handler context;
- RuntimeAssembler repository selection, lifecycle ownership, and v0.22 compatibility;
- migration guidance, ADR-0046/0047, regression tests, and v0.23.0 packaging.

## Compatibility

Service accounts are optional and begin empty. Existing operator records, durable sessions,
network policies, TLS settings, cookies, CSRF, and step-up behavior are not rewritten. Omitting
service-account composition preserves the Phoenix OS 0.22 control-plane behavior.

API tokens are accepted only by explicitly registered machine routes. They cannot authenticate
to the Dashboard and never inherit Viewer, Operator, or Maintainer authority.

## Safety model

Complete API tokens are returned only by issuance or rotation and are never persisted. Tokens,
digests, authorization headers, request bodies, network identities, and internal exception text
remain excluded from logs, errors, events, metrics, audit details, and snapshots.

Machine requests require exact bearer parsing, current account and token state, expiration,
optional transport restrictions, independent throttles, fresh replay evidence, exact action and
resource grants, and central policy approval before a handler receives trusted context.

## Release validation

Run the complete repository quality gate and package checks before publishing:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\check.ps1
python -m build
python -m twine check .\dist\*.whl .\dist\*.tar.gz
```
