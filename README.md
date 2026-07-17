# Phoenix OS

Phoenix OS is an experimental, headless orchestration foundation for Python 3.12+.
Version `0.5.0` implements five accepted specifications:

- **RFC-0001 — Phoenix Kernel:** asynchronous request lifecycle, routing, authorization,
  confirmation, cancellation, deadlines, safe errors, and lifecycle events.
- **RFC-0002 — Event Bus:** immutable events, deterministic asynchronous delivery,
  priorities, one-shot and wildcard subscriptions, failure isolation, and explicit shutdown.
- **RFC-0003 — Capability Registry:** immutable capability contracts, trusted contexts,
  permissions, confirmation, deadlines, safe provider execution, discovery, and Kernel adapters.
- **RFC-0004 — Phoenix Runtime:** immutable service composition, deterministic component startup,
  rollback, request draining, reverse shutdown, lifecycle states, deadlines, and context management.
- **RFC-0005 — Configuration System:** typed immutable configuration, ordered mapping/JSON/
  environment sources, provenance, secret redaction, dependency graphs, and Runtime assembly.

The core intentionally contains no AI model, database, memory implementation, concrete tool,
credential store, UI, or operating-system automation. Those belong behind capability providers,
lifecycle services, named dependencies, and external adapters.

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

## Configuration and Runtime assembly

```python
from phoenix_os import (
    ConfigField,
    ConfigLoader,
    ConfigSchema,
    EnvironmentConfigSource,
    MappingConfigSource,
    RuntimeAssembler,
    as_boolean,
    as_integer,
)

schema = ConfigSchema(
    (
        ConfigField("runtime.port", as_integer, default=8080),
        ConfigField("runtime.debug", as_boolean, default=False),
    )
)
configuration = await ConfigLoader(
    schema,
    (
        MappingConfigSource({"runtime.port": 8000}, name="defaults"),
        EnvironmentConfigSource(),
    ),
).load()

runtime = await RuntimeAssembler(
    kernel=kernel,
    events=events,
    capabilities=capabilities,
    configuration=configuration,
).assemble()

async with runtime:
    ...
```

See `examples/` and `docs/` for complete contracts, source precedence, secret handling, dependency
composition, request handling, lifecycle components, and architectural decisions.

## License

MIT — Copyright (c) 2026 Phoenix contributors.
