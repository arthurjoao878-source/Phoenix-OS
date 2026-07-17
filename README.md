# Phoenix OS

Phoenix OS is an experimental, headless orchestration foundation written for Python 3.12+.
Version `0.2.0` implements two accepted specifications:

- **RFC-0001 — Phoenix Kernel:** asynchronous request lifecycle, routing, authorization,
  confirmation, cancellation, deadlines, safe errors, and lifecycle events.
- **RFC-0002 — Event Bus:** immutable events, deterministic asynchronous delivery,
  priorities, one-shot and wildcard subscriptions, failure isolation, and explicit shutdown.

The Kernel intentionally contains no AI model, database, memory, tool implementation, UI,
or operating-system automation. Those capabilities belong behind adapters.

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

## Minimal example

```python
from phoenix_os import AllowAllAuthorizer, Kernel, Request, Response, Router

router = Router()

async def ping(request: Request) -> Response:
    return Response(status=200, body={"reply": "pong"})

router.add("system.ping", ping)
kernel = Kernel(router=router, authorizer=AllowAllAuthorizer())
response = await kernel.handle(Request(action="system.ping"))
```

See `examples/` and `docs/` for complete contracts and decisions.

## License

MIT — Copyright (c) 2026 Phoenix contributors.
