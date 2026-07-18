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
