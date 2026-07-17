# Phoenix OS

Phoenix OS is an experimental, headless orchestration foundation for Python 3.12+.
Version `0.3.0` implements three accepted specifications:

- **RFC-0001 — Phoenix Kernel:** asynchronous request lifecycle, routing, authorization,
  confirmation, cancellation, deadlines, safe errors, and lifecycle events.
- **RFC-0002 — Event Bus:** immutable events, deterministic asynchronous delivery,
  priorities, one-shot and wildcard subscriptions, failure isolation, and explicit shutdown.
- **RFC-0003 — Capability Registry:** immutable capability contracts, trusted contexts,
  permissions, confirmation, deadlines, safe provider execution, discovery, and Kernel adapters.

The core intentionally contains no AI model, database, memory implementation, concrete tool,
credential store, UI, or operating-system automation. Those belong behind capability providers and
external adapters.

## Install for development

```bash
python -m pip install -e ".[dev]"
```

## Validate

```bash
ruff check .
ruff format --check .
mypy
pytest
```

On Windows:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\check.ps1
```

## Capability example

```python
from collections.abc import Mapping

from phoenix_os import CapabilityDescriptor, CapabilityInvocation, CapabilityRegistry

registry = CapabilityRegistry()

async def ping(invocation: CapabilityInvocation) -> Mapping[str, object]:
    return {"reply": "pong", "principal": invocation.context.principal}

await registry.register(CapabilityDescriptor("system.ping"), ping)
result = await registry.invoke("system.ping")
```

See `examples/` and `docs/` for complete contracts, Kernel integration, and architectural
decisions.

## License

MIT — Copyright (c) 2026 Phoenix contributors.
