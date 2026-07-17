# Phoenix OS

Phoenix OS is an experimental, headless orchestration foundation for Python 3.12+.
Version `0.4.0` implements four accepted specifications:

- **RFC-0001 — Phoenix Kernel:** asynchronous request lifecycle, routing, authorization,
  confirmation, cancellation, deadlines, safe errors, and lifecycle events.
- **RFC-0002 — Event Bus:** immutable events, deterministic asynchronous delivery,
  priorities, one-shot and wildcard subscriptions, failure isolation, and explicit shutdown.
- **RFC-0003 — Capability Registry:** immutable capability contracts, trusted contexts,
  permissions, confirmation, deadlines, safe provider execution, discovery, and Kernel adapters.
- **RFC-0004 — Phoenix Runtime:** immutable service composition, deterministic component startup,
  rollback, request draining, reverse shutdown, lifecycle states, deadlines, and context management.

The core intentionally contains no AI model, database, memory implementation, concrete tool,
credential store, UI, or operating-system automation. Those belong behind capability providers,
lifecycle components, named services, and external adapters.

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

## Runtime example

```python
from phoenix_os import (
    AllowAllAuthorizer,
    CapabilityRegistry,
    EventBus,
    Kernel,
    PhoenixRuntime,
    Router,
)

events = EventBus()
router = Router()
kernel = Kernel(router=router, authorizer=AllowAllAuthorizer(), events=events)
capabilities = CapabilityRegistry(events=events)
runtime = PhoenixRuntime(kernel=kernel, events=events, capabilities=capabilities)

async with runtime:
    ...
```

See `examples/` and `docs/` for complete contracts, request handling, lifecycle components, Kernel
integration, and architectural decisions.

## License

MIT — Copyright (c) 2026 Phoenix contributors.
