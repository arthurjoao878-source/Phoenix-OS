# ADR-0005 — Isolated handler failures with explicit policy

- Status: **Accepted**

Handler exceptions are data in a dispatch report. Strict callers may request an aggregate
exception after all handlers run. Cancellation is never converted into a failure report.
