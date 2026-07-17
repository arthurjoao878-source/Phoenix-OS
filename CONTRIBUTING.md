# Contributing

1. Discuss architecture changes through an RFC or ADR.
2. Keep the Kernel headless and dependency-light.
3. Add focused tests for every behavioral change.
4. Run Ruff, mypy strict, and pytest before opening a pull request.
5. Never commit credentials, tokens, personal data, or generated local state.

Use Conventional Commits. Example:

```text
feat(events): implement RFC-0002 deterministic event bus
```
