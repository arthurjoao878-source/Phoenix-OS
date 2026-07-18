# Security Policy

Do not disclose vulnerabilities in public issues. Report them privately to the
maintainers with reproduction steps, affected versions, and potential impact.
Never include real credentials or personal data in a report.

Phoenix OS is pre-alpha. Do not use it as a security boundary or grant adapters
more privileges than strictly necessary.


Runtime service objects and lifecycle components are trusted application composition.
Do not infer permissions from Runtime services or untrusted request payloads, and do not
treat graceful shutdown as process or operating-system sandboxing.


## Plugin trust boundary

Plugin manifests, permissions, exports, and allowlists constrain Phoenix SDK contributions but do not
sandbox Python code. A loaded plugin can use ambient process authority. Do not load unreviewed packages.
Pin and verify plugin distributions, grant the minimum SDK permissions, and run untrusted extensions in
separate operating-system processes or containers.

## Authentication and session tokens

Phoenix OS stores only SHA-256 digests of high-entropy opaque session tokens. Treat every raw bearer
as a credential: never place it in logs, URLs, telemetry, exceptions, source control, or unencrypted
storage. Revoke affected sessions immediately after suspected disclosure.

`AuthenticationProvider` adapters are trusted code and are responsible for password hashing,
external token validation, MFA, account status checks, and provider-specific rate limiting. Do not
use SHA-256 directly for human passwords. Use a suitable password KDF or the security controls of the
external identity provider.

## Secrets and key management

`SecretValue`, `SecretRef`, leases, and policy checks reduce accidental disclosure but do not make the
Python process a hardware-backed vault. `InMemorySecretStore` is neither durable nor encrypted at
rest. Never use it as the sole protection for production credentials.

Production deployments should use independently reviewed external `SecretStore` and
`SecretProtector` adapters, protect provider credentials, use short leases, restrict policy rules,
and revoke affected versions and sessions after suspected disclosure. Do not place secret material,
wrapping keys, lease values, vault credentials, or decrypted payloads in logs, events, metrics,
exceptions, source control, State Store, or configuration files.


## Audit ledger and security journal

Audit records may contain identity, authorization, resource, timing, and incident metadata. Restrict
`audit.read` and `audit.verify`, minimize details, and apply retention and privacy requirements in the
deployment. Redaction reduces accidental disclosure but cannot determine every domain-specific
sensitive field.

`InMemoryAuditStore` is not durable, write-once, independently clocked, or resistant to an attacker
with process-memory access. A SHA-256 chain without protected signatures detects ordinary mutation
when the complete history is available, but a privileged attacker can replace and rehash an entire
unsigned ledger. Use reviewed external storage and `AuditSigner` implementations when stronger
evidence, retention, availability, or non-repudiation properties are required.
