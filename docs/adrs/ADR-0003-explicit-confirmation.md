# ADR-0003 — Explicit confirmation for sensitive actions

- Status: **Accepted**

Sensitive routes and confirm authorization decisions require `Request.confirmed=True`.
The Kernel never infers consent from conversational wording.
