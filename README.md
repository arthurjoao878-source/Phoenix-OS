# Phoenix OS

Phoenix OS is an experimental, headless orchestration foundation for Python 3.12+.
Version `0.6.0` implements six accepted specifications:

- **RFC-0001 — Phoenix Kernel:** asynchronous request lifecycle, routing, authorization,
  confirmation, cancellation, deadlines, safe errors, and lifecycle events.
- **RFC-0002 — Event Bus:** immutable events, deterministic asynchronous delivery, priorities,
  one-shot and wildcard subscriptions, failure isolation, and explicit shutdown.
- **RFC-0003 — Capability Registry:** immutable capability contracts, trusted contexts,
  permissions, confirmation, deadlines, safe provider execution, discovery, and Kernel adapters.
- **RFC-0004 — Phoenix Runtime:** deterministic component startup, rollback, request draining,
  reverse shutdown, lifecycle states, deadlines, and context management.
- **RFC-0005 — Configuration System:** typed immutable configuration, ordered sources, provenance,
  explicit secrets, dependency composition, and Runtime assembly.
- **RFC-0006 — Observability and Diagnostics:** structured logs and metrics, asynchronous spans,
  deterministic sinks, recursive redaction, Event Bus observation, and Runtime ownership.

The core intentionally contains no AI model, database, memory implementation, concrete tool,
credential store, telemetry vendor, persistence backend, UI, or operating-system automation. Those
belong behind capability providers, lifecycle components, named services, sinks, and external
adapters.

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

## Observability example

```python
from phoenix_os import InMemorySink, MetricKind, ObservabilityHub

sink = InMemorySink(capacity=1000)
observability = ObservabilityHub((sink,))

async with observability.span("request", source="application"):
    await observability.log(
        "request.started",
        source="application",
        message="request accepted",
    )
    await observability.metric(
        "requests.total",
        1,
        source="application",
        kind=MetricKind.COUNTER,
    )
```

See `examples/` and `docs/` for complete contracts, configuration, dependency composition, Runtime
integration, trace context, redaction, and architectural decisions.

## License

MIT — Copyright (c) 2026 Phoenix contributors.
