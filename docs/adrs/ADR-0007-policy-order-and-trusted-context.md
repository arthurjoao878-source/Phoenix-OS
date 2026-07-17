# ADR-0007 — Permission before confirmation with trusted context

- **Status:** Accepted

Capability permission is evaluated before confirmation. Permissions are supplied only by a trusted
context factory and never inferred from request arguments. The conservative default grants no
permissions. This prevents confirmation from bypassing authorization and avoids privilege injection
through payload data.
