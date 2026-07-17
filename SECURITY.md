# Security Policy

Do not disclose vulnerabilities in public issues. Report them privately to the
maintainers with reproduction steps, affected versions, and potential impact.
Never include real credentials or personal data in a report.

Phoenix OS is pre-alpha. Do not use it as a security boundary or grant adapters
more privileges than strictly necessary.


Runtime service objects and lifecycle components are trusted application composition.
Do not infer permissions from Runtime services or untrusted request payloads, and do not
treat graceful shutdown as process or operating-system sandboxing.
